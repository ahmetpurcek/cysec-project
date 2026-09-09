/*
 * network_ids.c — Kural Tabanlı Ağ Saldırı Tespit Sistemi (IDS)
 *
 * full_monitor'ın yakaladığı paketlerden ham veriyi (raw_data) parse
 * eder ve eşik tabanlı kurallarla saldırı/şüphe tespiti yapar.
 * Tüm durum sabit boyutlu statik dizilerde tutulur (malloc yok),
 * tek mutex ile thread-safe çalışır.
 */

#include "network_ids.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

/* ==================================================================
 *   PAKET PARSE — raw_data üzerinden bağımsız minimal parser
 *   (dissector'a bağımlılık yok, hızlı ve güvenilir)
 * ================================================================== */

typedef struct {
    int      is_ipv4;
    int      is_arp;
    int      is_icmp;
    int      is_tcp;
    int      is_udp;
    int      is_dns;
    int      is_broadcast;
    int      is_multicast;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  tcp_flags;
    int      arp_opcode;
    uint8_t  arp_sender_mac[6];
    uint32_t arp_sender_ip;
    uint8_t  src_mac[6];
    uint8_t  dst_mac[6];
    uint32_t arp_target_ip;   /* ARP hedef IP (cerceve byte 38-41) */
    const uint8_t *payload;   /* TCP/UDP L4 yuku (raw_data icinde) */
    int      payload_len;

    /* SOC v3: DNS/metadata ayristirma */
    int      dns_is_response;   /* DNS QR bayragi (yanit mi) */
    uint16_t dns_qdcount;       /* soru sayisi */
    char     dns_qname[256];    /* ilk sorunun adi */
    int      dns_qname_len;     /* qname'in tukettigi bayt */
    uint32_t mdns_ans_ip;       /* mDNS yaniti A-kaydi IP'si */
    char     nbns_name[64];     /* NetBIOS adi (NBNS sorgusu) */
    int      dhcp_op;           /* 1=REQUEST 2=REPLY */
    uint32_t dhcp_yiaddr;       /* kiralanan IP */
    uint8_t  dhcp_chaddr[6];    /* istemci MAC */
    char     dhcp_hostname[64]; /* istemci adi (opsiyon 12) */
} IdsPktInfo;

static int ids_dns_name(const uint8_t *d, int dlen, int off, char *out, int outlen);
static void ids_decode_nbns(const uint8_t *in, int inlen, char *out, int outlen);

static void ids_parse_pkt(const PacketRecord *pkt, IdsPktInfo *pi) {
    memset(pi, 0, sizeof(*pi));

    const uint8_t *r = pkt->raw_data;
    int len = pkt->raw_len;
    if (len < 14) return;

    /* Ethernet */
    memcpy(pi->dst_mac, r, 6);
    memcpy(pi->src_mac, r + 6, 6);
    uint16_t etype = (r[12] << 8) | r[13];

    int all_ff = 1;
    for (int i = 0; i < 6; i++) if (r[i] != 0xFF) { all_ff = 0; break; }
    pi->is_broadcast = all_ff;
    pi->is_multicast = (r[0] & 1) && !all_ff;

    if (etype == 0x0806) {
        /* ARP */
        pi->is_arp = 1;
        if (len < 42) return;
        pi->arp_opcode = (r[20] << 8) | r[21];
        memcpy(pi->arp_sender_mac, r + 22, 6);
        pi->arp_sender_ip = (uint32_t)r[28] << 24 | (uint32_t)r[29] << 16 |
                            (uint32_t)r[30] << 8 | r[31];
        pi->arp_target_ip = (uint32_t)r[38] << 24 | (uint32_t)r[39] << 16 |
                            (uint32_t)r[40] << 8 | r[41];
        return;
    }

    if (etype != 0x0800) return; /* IPv6 ve diğerleri şimdilik atlanır */
    pi->is_ipv4 = 1;
    if (len < 34) return;

    int ihl = (r[14] & 0x0F) * 4;
    if (ihl < 20 || 14 + ihl + 4 > len) return;

    pi->src_ip = (uint32_t)r[26] << 24 | (uint32_t)r[27] << 16 |
                 (uint32_t)r[28] << 8 | r[29];
    pi->dst_ip = (uint32_t)r[30] << 24 | (uint32_t)r[31] << 16 |
                 (uint32_t)r[32] << 8 | r[33];

    uint8_t proto = r[23];
    const uint8_t *l4 = r + 14 + ihl;
    int l4len = len - (14 + ihl);

    if (proto == 6 && l4len >= 20) {
        pi->is_tcp = 1;
        pi->src_port = (l4[0] << 8) | l4[1];
        pi->dst_port = (l4[2] << 8) | l4[3];
        pi->tcp_flags = l4[13] & 0x3F;
        int doff = (l4[12] >> 4) * 4;
        if (doff >= 20 && l4len > doff) {
            pi->payload = l4 + doff;
            pi->payload_len = l4len - doff;
        }
    } else if (proto == 17 && l4len >= 8) {
        pi->is_udp = 1;
        pi->src_port = (l4[0] << 8) | l4[1];
        pi->dst_port = (l4[2] << 8) | l4[3];
        const uint8_t *pay = l4 + 8;
        int paylen = l4len - 8;

        /* DNS (53): 12 baytlık başlık — QR bayrağı + soru sayısı + ilk ad */
        if (pi->dst_port == 53 && paylen >= 12) {
            pi->dns_qdcount = (uint16_t)((pay[4] << 8) | pay[5]);
            pi->dns_is_response = (pay[2] & 0x80) != 0;
            pi->is_dns = (pi->dns_qdcount > 0);
            int q = ids_dns_name(pay, paylen, 12, pi->dns_qname,
                                 (int)sizeof(pi->dns_qname));
            if (q > 0) pi->dns_qname_len = q;
        }
        /* mDNS (5353): yanıt A-kaydı — soruları atla, C0 işaretçili yanıtı çöz */
        if (pi->dst_port == 5353 && paylen >= 12) {
            pi->dns_qdcount = (uint16_t)((pay[4] << 8) | pay[5]);
            pi->dns_is_response = (pay[2] & 0x80) != 0;
            pi->is_dns = (pi->dns_qdcount > 0);
            int off = 12;
            for (int q = 0; q < pi->dns_qdcount && off < paylen; q++) {
                int n = ids_dns_name(pay, paylen, off,
                                     q == 0 ? pi->dns_qname : NULL,
                                     q == 0 ? (int)sizeof(pi->dns_qname) : 0);
                if (n < 0) { off = paylen; break; }
                off += n + 4;   /* soru: isim + QTYPE + QCLASS */
            }
            if (off + 12 <= paylen && pay[off] == 0xC0) {
                uint16_t rtype = (uint16_t)((pay[off + 2] << 8) | pay[off + 3]);
                uint16_t rdlen = (uint16_t)((pay[off + 10] << 8) | pay[off + 11]);
                if (rtype == 1 && rdlen == 4 && off + 16 <= paylen) {
                    pi->mdns_ans_ip = ((uint32_t)pay[off + 12] << 24) |
                                      ((uint32_t)pay[off + 13] << 16) |
                                      ((uint32_t)pay[off + 14] << 8) | pay[off + 15];
                }
            }
        }
        /* DHCP (67/68): sihirli cookie 0x63825363, opsiyon 12 = hostname */
        if ((pi->dst_port == 67 || pi->dst_port == 68) && paylen >= 240) {
            if (pay[236] == 0x63 && pay[237] == 0x82 &&
                pay[238] == 0x53 && pay[239] == 0x63) {
                pi->dhcp_op = pay[0];
                pi->dhcp_yiaddr = ((uint32_t)pay[16] << 24) |
                                  ((uint32_t)pay[17] << 16) |
                                  ((uint32_t)pay[18] << 8) | pay[19];
                memcpy(pi->dhcp_chaddr, pay + 28, 6);
                int o = 240;
                while (o + 1 < paylen) {
                    uint8_t opt = pay[o];
                    if (opt == 255) break;
                    if (opt == 0) { o++; continue; }
                    uint8_t ol = pay[o + 1];
                    if (o + 2 + ol > paylen) break;
                    if (opt == 12 && ol > 0 && ol < (int)sizeof(pi->dhcp_hostname)) {
                        memcpy(pi->dhcp_hostname, pay + o + 2, ol);
                        pi->dhcp_hostname[ol] = '\0';
                    }
                    o += 2 + ol;
                }
            }
        }
        /* NBNS (137): ad sorgusu (0x20), 32 bayt kodlanmış ad @pay[13] */
        if (pi->dst_port == 137 && paylen >= 45) {
            if (pay[12] == 0x20) {
                ids_decode_nbns(pay + 13, 32, pi->nbns_name,
                                (int)sizeof(pi->nbns_name));
            }
        }
        if (paylen > 0) {
            pi->payload = pay;
            pi->payload_len = paylen;
        }
    } else if (proto == 1 && l4len >= 4) {
        pi->is_icmp = 1;
    }
}

static void ids_ip_to_str(uint32_t ip, char *buf, int len) {
    snprintf(buf, len, "%u.%u.%u.%u",
             (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
             (ip >> 8) & 0xFF, ip & 0xFF);
}

/* DNS isim cozucu: label uzunlugu + dize. C0 isaretcisi -1 dondurur;
 * NULL out ile yalnizca tuketilen bayt sayisi hesaplanir. */
static int ids_dns_name(const uint8_t *d, int dlen, int off, char *out, int outlen) {
    int o = off, w = 0;
    while (o < dlen) {
        uint8_t l = d[o];
        if (l == 0) { o++; break; }
        if (l & 0xC0) return -1;              /* sikistirma isaretcisi */
        o++;
        if (o + l > dlen) return -1;
        for (int i = 0; i < l; i++) {
            if (out && w + 1 < outlen) out[w++] = (char)d[o + i];
        }
        o += l;
        if (o < dlen && d[o] != 0) {
            if (out && w + 1 < outlen) out[w++] = '.';
        }
    }
    if (out && w < outlen) out[w] = '\0';
    return o - off;
}

/* NetBIOS 'A' kodlu ad cozucu: her karakter 2 bayt (nibble+'A').
 * Cozulen bosluk (dolgu) adi keser. */
static void ids_decode_nbns(const uint8_t *in, int inlen, char *out, int outlen) {
    int w = 0;
    for (int i = 0; i + 1 < inlen && w + 1 < outlen; i += 2) {
        char c = (char)(((in[i] - 'A') & 0x0F) << 4) |
                 (char)((in[i + 1] - 'A') & 0x0F);
        if (c == ' ') break;
        out[w++] = c;
    }
    out[w] = '\0';
}

/* ==================================================================
 *   IDS STATE
 * ================================================================== */

IdsAgent g_ids;

static platform_mutex_t g_ids_lock;
static int g_ids_initialized = 0;

/* MAC/IP bağlamı (ARP zehirlenmesi + self-origin bastırma için) */
static uint8_t g_local_mac[6];
static uint8_t g_gateway_mac[6];
static int     g_gateway_mac_valid = 0;
static uint32_t g_gateway_ip = 0;
static uint32_t g_local_ip = 0;

/* ==================================================================
 *   SELF-ORIGINATION SUPPRESSION
 *   Uygulamanin kendi urettigi trafik (otomatik ARP/ping taramasi,
 *   fallback sentetik cerceveler) uyari gurultusu yaratmasin. Yabanci
 *   MAC'ten gelen (kaynak IP yerel olsa bile) cerceveler bastirilmaz:
 *   spoof'lu IP saldirgan olabilir.
 * ================================================================== */

static int ids_mac_zero(const uint8_t mac[6]) {
    for (int i = 0; i < 6; i++)
        if (mac[i] != 0) return 0;
    return 1;
}

static int ids_is_self_originated(const IdsPktInfo *pi) {
    if (!ids_mac_zero(pi->src_mac)) {
        /* pcap modu: gercek cerceve — kendi NIC MAC'imiz mi? */
        if (memcmp(pi->src_mac, g_local_mac, 6) == 0) return 1;
        /* Yabanci MAC: bastirma yok (ARP poisoning/spoof tespiti korunur) */
        return 0;
    }
    /* Fallback modu: sentetik cerceve (MAC yok) — IP eslesmesine bak */
    if (g_local_ip && pi->src_ip == g_local_ip) return 1;
    return 0;
}

/* Alert ring buffer (kronolojik, en yeni sonda) */
static IdsGuiAlert g_alert_buf[IDS_MAX_ALERTS];
static int g_alert_count = 0;

/* ==================================================================
 *   TRACKER — eşik analizi için akış sayaçları
 * ================================================================== */

typedef struct {
    char     key[96];
    uint32_t count;
    uint32_t unique[64];       /* farklı hedef/port hash'leri */
    int      unique_len;
    time_t   window_start;
    time_t   last_alert;
    int      active;
} IdsTracker;

static IdsTracker g_trackers[IDS_MAX_TRACKERS];
static int g_tracker_count = 0;

static uint32_t ids_hash_unique(uint32_t a, uint32_t b) {
    return a ^ (b * 2654435761u);
}

static IdsTracker *ids_tracker_get(const char *key) {
    for (int i = 0; i < g_tracker_count; i++) {
        if (g_trackers[i].active && strcmp(g_trackers[i].key, key) == 0)
            return &g_trackers[i];
    }
    if (g_tracker_count >= IDS_MAX_TRACKERS) {
        /* Kap dolu: once pasif kayit, yoksa en eski kayit geri donusturulur */
        IdsTracker *victim = NULL;
        for (int i = 0; i < g_tracker_count; i++) {
            if (!g_trackers[i].active) { victim = &g_trackers[i]; break; }
        }
        if (!victim) {
            victim = &g_trackers[0];
            for (int i = 1; i < g_tracker_count; i++)
                if (g_trackers[i].window_start < victim->window_start)
                    victim = &g_trackers[i];
        }
        memset(victim, 0, sizeof(*victim));
        strncpy(victim->key, key, sizeof(victim->key) - 1);
        victim->active = 1;
        victim->window_start = time(NULL);
        return victim;
    }
    IdsTracker *t = &g_trackers[g_tracker_count++];
    memset(t, 0, sizeof(*t));
    strncpy(t->key, key, sizeof(t->key) - 1);
    t->active = 1;
    t->window_start = time(NULL);
    return t;
}

static void ids_tracker_reset_if_expired(IdsTracker *t) {
    time_t now = time(NULL);
    if (now - t->window_start > IDS_WINDOW_SEC) {
        t->count = 0;
        t->unique_len = 0;
        t->window_start = now;
    }
}

static void ids_tracker_bump(IdsTracker *t, uint32_t unique_val) {
    ids_tracker_reset_if_expired(t);
    t->count++;
    if (unique_val != 0 && t->unique_len < 64) {
        int found = 0;
        for (int i = 0; i < t->unique_len; i++) {
            if (t->unique[i] == unique_val) { found = 1; break; }
        }
        if (!found) t->unique[t->unique_len++] = unique_val;
    }
}

static int ids_tracker_can_alert(IdsTracker *t) {
    time_t now = time(NULL);
    if (now - t->last_alert < IDS_ALERT_COOLDOWN) return 0;
    t->last_alert = now;
    return 1;
}

/* ==================================================================
 *   ALERT ÜRETİMİ
 * ================================================================== */

#define SCORE_KRITIK 0.95
#define SCORE_YUKSEK 0.75
#define SCORE_ORTA   0.50
#define SCORE_DUSUK  0.25

/* SOC v3: olay korelasyonu (ids_raise_alert icinden cagrilir) */
static void ids_incident_update(uint32_t att, uint32_t vic, const char *sig,
                                const char *sev, double score);

/* LAN katmanı öne bildirimleri (uygulamaları ids_raise_alert'ten
 * sonraki bölümde) — uyarı üretimi host skorlarını besler. */
static uint32_t ids_sev_points(const char *sev);
static uint32_t ids_sig_flags(const char *sig);
static void ids_host_credit(uint32_t ip, uint32_t points, uint32_t flag);
static void ids_host_victim(uint32_t ip, uint32_t points, uint32_t flag);

static void ids_raise_alert(const char *sig, const char *sev, double score,
                            const IdsPktInfo *pi, const char *desc) {
    if (!g_ids.running) return;
    platform_mutex_lock(&g_ids_lock);

    IdsGuiAlert *a;
    if (g_alert_count >= IDS_MAX_ALERTS) {
        /* En eskiyi düşür (sondan kopyala) */
        memmove(&g_alert_buf[0], &g_alert_buf[1],
                sizeof(IdsGuiAlert) * (IDS_MAX_ALERTS - 1));
        g_alert_count = IDS_MAX_ALERTS - 1;
        a = &g_alert_buf[g_alert_count];
    } else {
        a = &g_alert_buf[g_alert_count++];
    }

    memset(a, 0, sizeof(*a));
    strncpy(a->sig_name, sig, sizeof(a->sig_name) - 1);
    ids_ip_to_str(pi->src_ip, a->src_ip, sizeof(a->src_ip));
    ids_ip_to_str(pi->dst_ip, a->dst_ip, sizeof(a->dst_ip));
    a->src_port = pi->src_port;
    a->dst_port = pi->dst_port;
    a->score = score;
    strncpy(a->severity, sev, sizeof(a->severity) - 1);
    strncpy(a->description, desc, sizeof(a->description) - 1);
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    if (tm) {
        strftime(a->timestamp, sizeof(a->timestamp), "%H:%M:%S", tm);
    } else {
        strncpy(a->timestamp, "--:--:--", sizeof(a->timestamp) - 1);
    }

    g_ids.total_alerts++;

    /* LAN katmanı: uyarı kaynak/hedef host skorlarına işlenir.
     * ARP uyarılarında src/dst IP alanları boştur; ham çerçevedeki
     * sender/target IP'leri kullanılır. */
    {
        uint32_t att = pi->src_ip, vic = pi->dst_ip;
        if (pi->is_arp) {
            att = pi->arp_sender_ip;
            vic = pi->arp_target_ip;
        }
        uint32_t pts = ids_sev_points(sev);
        uint32_t fl  = ids_sig_flags(sig);
        ids_host_credit(att, pts, fl);
        ids_host_victim(vic, pts, fl);
        ids_incident_update(att, vic, sig, sev, score);
    }

    platform_mutex_unlock(&g_ids_lock);
}

/* ==================================================================
 *   LAN KATMANI — ağ geneli akış tablosu + host tehdit skorlaması
 *
 *   ARP MITM / promiscuous pcap sayesinde tüm ağ trafiği bu makineden
 *   geçtiğinde her cihaz için: hangi IP'lere/portlara dokunduğu, kime
 *   saldırdığı, kimin saldırısına uğradığı ve toplam tehdit skoru
 *   (0-100) hesaplanır. Skorlar uyarı üretimi (ids_raise_alert) ve
 *   akış analizi (ids_flow_analysis) tarafından beslenir.
 * ================================================================== */

/* Uyarı önem derecesi -> host skor katkısı */
static uint32_t ids_sev_points(const char *sev) {
    if (!sev) return 2;
    if (strcmp(sev, "KRITIK") == 0) return 40;
    if (strcmp(sev, "YUKSEK") == 0) return 20;
    if (strcmp(sev, "ORTA") == 0)   return 8;
    return 2;
}

/* İmza adı -> host tehdit bayrağı (IDS_F_*) */
static uint32_t ids_sig_flags(const char *sig) {
    if (!sig) return IDS_F_SCAN;
    if (strstr(sig, "Brute")) return IDS_F_BRUTEFORCE;
    if (strstr(sig, "Tarama") || strstr(sig, "Sweep")) return IDS_F_SCAN;
    if (strstr(sig, "Flood") || strstr(sig, "DDoS") ||
        strstr(sig, "Storm"))
        return IDS_F_FLOOD;
    if (strstr(sig, "Meterpreter") || strstr(sig, "Shellcode") ||
        strstr(sig, "Backdoor") || strstr(sig, "BackOrifice") ||
        strstr(sig, "RAT") || strstr(sig, "botnet") ||
        strstr(sig, "SQL") || strstr(sig, "XSS") ||
        strstr(sig, "Enjeksiyon") || strstr(sig, "Erisim") ||
        strstr(sig, "Calistirma") || strstr(sig, "Indirme") ||
        strstr(sig, "PowerShell") || strstr(sig, "Log4Shell") ||
        strstr(sig, "JNDI"))
        return IDS_F_MALWARE;
    if (strstr(sig, "ARP") || strstr(sig, "Cakismasi") ||
        strstr(sig, "Eslesme"))
        return IDS_F_ARPSPOOF;
    if (strstr(sig, "DNS") || strstr(sig, "DGA") || strstr(sig, "Tunel"))
        return IDS_F_DNS;
    return IDS_F_SCAN;
}

/* ---- Akış tablosu (5-tuple) ---- */
typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto;          /* 6=TCP, 17=UDP, 1=ICMP */
    uint64_t pkt_count;
    uint64_t byte_count;
    uint32_t syn_count;      /* ACK'sız SYN (tarama işareti) */
    uint32_t rst_count;
    time_t   first_seen;
    time_t   last_seen;
    int      active;
} IdsFlow;

static IdsFlow g_flows[IDS_MAX_FLOWS];
static int g_flow_count = 0;

/* ---- Host tehdit kaydı (dahili, GUI snapshot'ına kopyalanır) ---- */
typedef struct {
    uint32_t ip;
    uint64_t sent_pkts;
    uint64_t recv_pkts;
    uint32_t flows_as_src;
    uint32_t flows_as_dst;
    uint32_t unique_target_ips;    /* analizde hesaplanır */
    uint32_t unique_target_ports;
    uint32_t attack_score;         /* 0-100 */
    uint32_t victim_score;         /* 0-100 */
    uint32_t flags;                /* IDS_F_* */
    char     hostname[64];         /* DHCP/mDNS/NetBIOS'tan ogrenilen ad */
    uint32_t dns_qcount;           /* gonderilen DNS sorgusu sayisi */
    uint32_t dns_dcount;           /* farkli alan adi sayisi */
    char     dns_domains[40][128]; /* gorulen alan adlari (dedupe) */
    int      dns_pending_alert;    /* DGA uyarisi bekliyor */
    int      dns_pending_tunnel;   /* tunel sezgiseli tuttu */
    time_t   last_seen;
    int      active;
} IdsHost;

static IdsHost g_hosts[IDS_MAX_HOSTS];
static int g_host_count = 0;

/* ---- SOC v3: korelasyonlu olay kayitlari (saldirgan->kurban cifti) ---- */
#define IDS_MAX_INCIDENTS 32
typedef struct {
    uint32_t attacker;
    uint32_t victim;
    uint32_t alert_count;
    uint32_t flags;
    int      killchain;
    char     worst_severity[16];
    double   max_score;
    char     last_sig[64];
    time_t   first_seen;
    time_t   last_seen;
} IdsIncidentInt;

static IdsIncidentInt g_incidents[IDS_MAX_INCIDENTS];
static int g_incident_count = 0;

/* Kapsam (CIDR) — verilmezse özel ağ aralıkları fallback */
static uint32_t g_net_base = 0;
static uint32_t g_net_mask = 0;
static int g_net_range_set = 0;

static time_t g_last_flow_analysis = 0;

void ids_set_network_range(const char *cidr) {
    if (!cidr || !cidr[0]) {
        g_net_range_set = 0;
        return;
    }
    unsigned int a, b, c, d, pp;
    if (sscanf(cidr, "%u.%u.%u.%u/%u", &a, &b, &c, &d, &pp) == 5 &&
        pp <= 32) {
        g_net_base = ((uint32_t)a << 24) | ((uint32_t)b << 16) |
                     ((uint32_t)c << 8) | (uint32_t)d;
        g_net_mask = (pp == 0) ? 0 : (0xFFFFFFFFu << (32 - pp));
        g_net_range_set = 1;
    } else {
        g_net_range_set = 0;
    }
}

/* IP, izlenen ağ kapsamında mı? (CIDR yoksa özel ağ fallback) */
static int ids_ip_in_scope(uint32_t ip) {
    if (g_net_range_set)
        return (ip & g_net_mask) == (g_net_base & g_net_mask);
    uint8_t a = (uint8_t)(ip >> 24);
    if (a == 10) return 1;
    if (a == 172) {
        uint8_t b = (uint8_t)(ip >> 16);
        return (b >= 16 && b <= 31);
    }
    if (a == 192) return (uint8_t)(ip >> 16) == 168;
    if (a == 169) return (uint8_t)(ip >> 16) == 254;
    if (a == 127) return 1;
    return 0;
}

/* Akış bul / yoksa pasif veya en eski slotu geri dönüştür */
static IdsFlow *ids_flow_get(uint32_t src, uint32_t dst, uint16_t sp,
                              uint16_t dp, uint8_t proto, int *created) {
    *created = 0;
    for (int i = 0; i < IDS_MAX_FLOWS; i++) {
        IdsFlow *f = &g_flows[i];
        if (f->active && f->src_ip == src && f->dst_ip == dst &&
            f->src_port == sp && f->dst_port == dp && f->proto == proto)
            return f;
    }
    IdsFlow *victim = NULL;
    if (g_flow_count < IDS_MAX_FLOWS) {
        victim = &g_flows[g_flow_count++];
    } else {
        for (int i = 0; i < IDS_MAX_FLOWS; i++) {
            if (!g_flows[i].active) { victim = &g_flows[i]; break; }
        }
        if (!victim) {
            victim = &g_flows[0];
            for (int i = 1; i < IDS_MAX_FLOWS; i++)
                if (g_flows[i].last_seen < victim->last_seen)
                    victim = &g_flows[i];
        }
    }
    time_t now = time(NULL);
    memset(victim, 0, sizeof(*victim));
    victim->src_ip = src;
    victim->dst_ip = dst;
    victim->src_port = sp;
    victim->dst_port = dp;
    victim->proto = proto;
    victim->first_seen = now;
    victim->last_seen = now;
    victim->active = 1;
    *created = 1;
    return victim;
}

/* Host bul / yoksa pasif veya en eski slotu geri dönüştür */
static IdsHost *ids_host_get_or_create(uint32_t ip) {
    if (!ip) return NULL;
    for (int i = 0; i < IDS_MAX_HOSTS; i++) {
        IdsHost *h = &g_hosts[i];
        if (h->active && h->ip == ip) {
            h->last_seen = time(NULL);
            return h;
        }
    }
    IdsHost *victim = NULL;
    if (g_host_count < IDS_MAX_HOSTS) {
        victim = &g_hosts[g_host_count++];
    } else {
        for (int i = 0; i < IDS_MAX_HOSTS; i++) {
            if (!g_hosts[i].active) { victim = &g_hosts[i]; break; }
        }
        if (!victim) {
            victim = &g_hosts[0];
            for (int i = 1; i < IDS_MAX_HOSTS; i++)
                if (g_hosts[i].last_seen < victim->last_seen)
                    victim = &g_hosts[i];
        }
    }
    memset(victim, 0, sizeof(*victim));
    victim->ip = ip;
    victim->last_seen = time(NULL);
    victim->active = 1;
    return victim;
}

/* Uyarıdan gelen saldırı/kurban skoru (kapsamdaki hostlara) */
static void ids_host_credit(uint32_t ip, uint32_t points, uint32_t flag) {
    if (!ip || !points || !ids_ip_in_scope(ip)) return;
    IdsHost *h = ids_host_get_or_create(ip);
    if (!h) return;
    h->attack_score += points;
    if (h->attack_score > 100) h->attack_score = 100;
    h->flags |= flag;
}

static void ids_host_victim(uint32_t ip, uint32_t points, uint32_t flag) {
    if (!ip || !points || !ids_ip_in_scope(ip)) return;
    IdsHost *h = ids_host_get_or_create(ip);
    if (!h) return;
    h->victim_score += points;
    if (h->victim_score > 100) h->victim_score = 100;
    h->flags |= flag;
}

/* ---- SOC v3: host adi ogrenme ----
 * DHCP REQUEST'ta MAC -> bekleyen ad; DHCP ACK'ta MAC + yiaddr eslesir;
 * mDNS A-kaydi ve NBNS sorgulari dogrudan IP -> ad ogretir.
 * Ilk ogrenilen ad kazanir (ad degisimi yanlis pozitif uretmesin). */
typedef struct {
    uint8_t  mac[6];
    char     name[64];
    time_t   ts;
} IdsNamePending;

static IdsNamePending g_name_pending[64];
static int g_name_pending_count = 0;

static void ids_name_pending_set(const uint8_t mac[6], const char *name) {
    for (int i = 0; i < g_name_pending_count; i++) {
        if (memcmp(g_name_pending[i].mac, mac, 6) == 0) {
            strncpy(g_name_pending[i].name, name,
                    sizeof(g_name_pending[i].name) - 1);
            g_name_pending[i].ts = time(NULL);
            return;
        }
    }
    if (g_name_pending_count < 64) {
        memcpy(g_name_pending[g_name_pending_count].mac, mac, 6);
        strncpy(g_name_pending[g_name_pending_count].name, name,
                sizeof(g_name_pending[g_name_pending_count].name) - 1);
        g_name_pending[g_name_pending_count].ts = time(NULL);
        g_name_pending_count++;
    }
}

static const char *ids_name_pending_get(const uint8_t mac[6]) {
    for (int i = 0; i < g_name_pending_count; i++)
        if (memcmp(g_name_pending[i].mac, mac, 6) == 0)
            return g_name_pending[i].name;
    return NULL;
}

/* MAC/IP -> ad ogret; ilk ogrenilen kazanir */
static void ids_hostname_learn(uint32_t ip, const char *name) {
    if (!ip || !name || !name[0]) return;
    IdsHost *h = ids_host_get_or_create(ip);
    if (!h) return;
    if (!h->hostname[0])
        strncpy(h->hostname, name, sizeof(h->hostname) - 1);
}

/* mDNS yanitindaki A-kaydi IP'sine yanit adini bagla */
static void ids_hostname_from_mdns(const IdsPktInfo *pi) {
    if (!pi->mdns_ans_ip) return;
    if (!pi->dns_qname[0]) return;
    ids_hostname_learn(pi->mdns_ans_ip, pi->dns_qname);
}

/* Her pakette çağrılır: akış sayacını ve host istatistiklerini günceller */
static void ids_flow_update(const IdsPktInfo *pi, const PacketRecord *pkt) {
    if (pi->is_arp) {
        /* ARP: akış yok; yalnızca host görünürlüğü (last_seen) */
        if (pi->arp_sender_ip && ids_ip_in_scope(pi->arp_sender_ip)) {
            IdsHost *h = ids_host_get_or_create(pi->arp_sender_ip);
            if (h) h->last_seen = time(NULL);
        }
        return;
    }
    if (!pi->is_ipv4) return;

    uint8_t proto = pi->is_tcp ? 6 : (pi->is_udp ? 17 : (pi->is_icmp ? 1 : 0));
    if (!proto) return;

    int created = 0;
    IdsFlow *f = ids_flow_get(pi->src_ip, pi->dst_ip, pi->src_port,
                              pi->dst_port, proto, &created);
    if (!f) return;
    f->pkt_count++;
    if (pkt && pkt->length > 0) f->byte_count += (uint32_t)pkt->length;
    if (pi->is_tcp) {
        int is_syn = (pi->tcp_flags & 0x02) && !(pi->tcp_flags & 0x10);
        if (is_syn) f->syn_count++;
        if (pi->tcp_flags & 0x04) f->rst_count++;
    }
    f->last_seen = time(NULL);

    /* Host sayaçları — yalnızca kapsamdaki IP'ler için host açılır */
    if (ids_ip_in_scope(pi->src_ip)) {
        IdsHost *h = ids_host_get_or_create(pi->src_ip);
        if (h) {
            h->sent_pkts++;
            h->last_seen = f->last_seen;
            if (created) h->flows_as_src++;
        }
    }
    if (pi->src_ip != pi->dst_ip && ids_ip_in_scope(pi->dst_ip)) {
        IdsHost *h = ids_host_get_or_create(pi->dst_ip);
        if (h) {
            h->recv_pkts++;
            h->last_seen = f->last_seen;
            if (created) h->flows_as_dst++;
        }
    }

    /* ---- SOC v3: DNS/metadata ogrenme (yalnizca UDP) ---- */
    if (pi->is_udp) {
        IdsHost *sh = ids_ip_in_scope(pi->src_ip)
                          ? ids_host_get_or_create(pi->src_ip) : NULL;

        /* DHCP REQUEST: MAC -> ad bekle; DHCP ACK: MAC -> IP ad ogren */
        if ((pi->dst_port == 67 || pi->dst_port == 68) && pi->dhcp_op == 1 &&
            !ids_mac_zero(pi->dhcp_chaddr) && pi->dhcp_hostname[0]) {
            ids_name_pending_set(pi->dhcp_chaddr, pi->dhcp_hostname);
        }
        if ((pi->dst_port == 67 || pi->dst_port == 68) && pi->dhcp_op == 2 &&
            pi->dhcp_yiaddr && !ids_mac_zero(pi->dhcp_chaddr)) {
            const char *nm = ids_name_pending_get(pi->dhcp_chaddr);
            if (nm) ids_hostname_learn(pi->dhcp_yiaddr, nm);
        }
        /* mDNS yaniti: A-kaydi IP'sine ad bagla */
        if (pi->dst_port == 5353 && pi->dns_is_response && pi->mdns_ans_ip)
            ids_hostname_from_mdns(pi);
        /* NBNS sorgusu: kaynak IP'ye NetBIOS adi bagla */
        if (pi->dst_port == 137 && pi->nbns_name[0] && sh)
            ids_hostname_learn(pi->src_ip, pi->nbns_name);

        /* DNS sorgusu (kapsamdaki kaynak): alan adini say, tunel sezgiseli */
        if (pi->dst_port == 53 && !pi->dns_is_response && pi->dns_qdcount > 0 &&
            pi->dns_qname[0] && sh) {
            int dup = 0;
            for (int i = 0; i < (int)sh->dns_dcount && i < 40; i++) {
                if (strcmp(sh->dns_domains[i], pi->dns_qname) == 0) { dup = 1; break; }
            }
            if (!dup && sh->dns_dcount < 40) {
                strncpy(sh->dns_domains[sh->dns_dcount], pi->dns_qname,
                        sizeof(sh->dns_domains[0]) - 1);
                sh->dns_dcount++;
            }
            sh->dns_qcount++;

            /* Tunel sezgiseli (tek seferlik): ilk label >= 12 karakter,
             * hem rakam hem harf, tire yok -> DGA/tunel adayı */
            if (!sh->dns_pending_tunnel) {
                const char *p = pi->dns_qname;
                int l = 0;
                while (*p && *p != '.') { l++; p++; }
                int digits = 0, letters = 0, hyph = 0;
                for (int k = 0; k < l; k++) {
                    char c = pi->dns_qname[k];
                    if (c >= '0' && c <= '9') digits++;
                    else if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) letters++;
                    else if (c == '-') hyph++;
                }
                if (l >= 12 && digits > 0 && letters > 0 && hyph == 0)
                    sh->dns_pending_tunnel = 1;
            }
        }
    }
}

/* Saniyede bir: zaman aşımı, per-host analiz, skor bozunumu */
static void ids_flow_analysis(void) {
    time_t now = time(NULL);
    if (now - g_last_flow_analysis < 1) return;
    g_last_flow_analysis = now;

    /* Zaman aşımı */
    for (int i = 0; i < IDS_MAX_FLOWS; i++) {
        if (g_flows[i].active && now - g_flows[i].last_seen > IDS_FLOW_TIMEOUT)
            g_flows[i].active = 0;
    }
    for (int i = 0; i < IDS_MAX_HOSTS; i++) {
        if (g_hosts[i].active && now - g_hosts[i].last_seen > IDS_HOST_TIMEOUT)
            g_hosts[i].active = 0;
    }

    for (int hi = 0; hi < IDS_MAX_HOSTS; hi++) {
        IdsHost *h = &g_hosts[hi];
        if (!h->active || !h->ip) continue;

        /* Benzersiz hedef IP / port (kaynak olduğu akışlardan) */
        uint32_t uips[128];
        uint32_t uports[128];
        int un_ips = 0, un_ports = 0;
        for (int fi = 0; fi < IDS_MAX_FLOWS; fi++) {
            IdsFlow *f = &g_flows[fi];
            if (!f->active || f->src_ip != h->ip) continue;
            if (un_ips < 128) {
                int k;
                for (k = 0; k < un_ips; k++) if (uips[k] == f->dst_ip) break;
                if (k == un_ips) uips[un_ips++] = f->dst_ip;
            }
            if (un_ports < 128 && f->dst_port) {
                int k;
                for (k = 0; k < un_ports; k++)
                    if (uports[k] == f->dst_port) break;
                if (k == un_ports) uports[un_ports++] = f->dst_port;
            }
        }
        h->unique_target_ips = (uint32_t)un_ips;
        h->unique_target_ports = (uint32_t)un_ports;

        /* Port taraması: >= 8 farklı hedef port */
        if (un_ports >= 8 && !(h->flags & IDS_F_SCAN)) {
            h->flags |= IDS_F_SCAN;
            h->attack_score += 10;
            if (h->attack_score > 100) h->attack_score = 100;
        }
        /* Ağ taraması: >= 6 farklı hedef IP */
        if (un_ips >= 6 && !(h->flags & IDS_F_SWEEP)) {
            h->flags |= IDS_F_SWEEP;
            h->attack_score += 15;
            if (h->attack_score > 100) h->attack_score = 100;
        }
        /* Flood: 60+ akış hedef olarak */
        if (h->flows_as_dst >= 60 && !(h->flags & IDS_F_FLOOD)) {
            h->flags |= IDS_F_FLOOD;
            h->victim_score += 20;
            if (h->victim_score > 100) h->victim_score = 100;
        }
        /* Brute force: aynı port grubunda >= 6 akış ve >= 4 farklı kaynak port */
        if (h->flows_as_dst >= 6 && !(h->flags & IDS_F_BRUTEFORCE)) {
            typedef struct {
                uint16_t port;
                uint32_t count;
                uint16_t src_ports[32];
                int spn;
            } BruteBucket;
            BruteBucket bb[16];
            int bn = 0;
            for (int fi = 0; fi < IDS_MAX_FLOWS; fi++) {
                IdsFlow *f = &g_flows[fi];
                if (!f->active || f->dst_ip != h->ip || !f->dst_port) continue;
                int b = -1;
                for (int j = 0; j < bn; j++)
                    if (bb[j].port == f->dst_port) { b = j; break; }
                if (b < 0 && bn < 16) {
                    b = bn++;
                    bb[b].port = f->dst_port;
                    bb[b].count = 0;
                    bb[b].spn = 0;
                }
                if (b < 0) continue;
                bb[b].count++;
                if (bb[b].spn < 32) {
                    int k;
                    for (k = 0; k < bb[b].spn; k++)
                        if (bb[b].src_ports[k] == f->src_port) break;
                    if (k == bb[b].spn)
                        bb[b].src_ports[bb[b].spn++] = f->src_port;
                }
            }
            for (int b = 0; b < bn; b++) {
                if (bb[b].count >= 6 && bb[b].spn >= 4) {
                    h->flags |= IDS_F_BRUTEFORCE;
                    h->victim_score += 25;
                    if (h->victim_score > 100) h->victim_score = 100;
                    break;
                }
            }
        }

        /* ---- SOC v3: DNS DGA / tunel analizi (saniyede bir) ---- */
        if (h->dns_qcount >= 25 && h->dns_dcount >= 10 && !(h->flags & IDS_F_DNS)) {
            h->flags |= IDS_F_DNS;
            h->dns_pending_alert = 1;
            h->attack_score += 10;
            if (h->attack_score > 100) h->attack_score = 100;
        }
        if (h->dns_pending_alert) {
            h->dns_pending_alert = 0;
            IdsPktInfo pi;
            memset(&pi, 0, sizeof(pi));
            pi.src_ip = h->ip;
            pi.is_udp = 1;
            ids_raise_alert("DGA Suphesi (C2)", "KRITIK", SCORE_KRITIK, &pi,
                            "Cok sayida benzersiz alan adi sorgusu (olasi DGA)");
        }
        if (h->dns_pending_tunnel && !(h->flags & IDS_F_TUNNEL)) {
            h->flags |= IDS_F_TUNNEL;
            h->attack_score += 15;
            if (h->attack_score > 100) h->attack_score = 100;
            IdsPktInfo pi;
            memset(&pi, 0, sizeof(pi));
            pi.src_ip = h->ip;
            pi.is_udp = 1;
            ids_raise_alert("DNS Tuneli (C2)", "KRITIK", SCORE_KRITIK, &pi,
                            "Alfa-sayisal uzun label (olasi DNS tunelleme)");
        }

        /* Skor bozunumu: saniyede 1 puan (saldırı bitince geriler) */
        if (h->attack_score > 0) h->attack_score--;
        if (h->victim_score > 0) h->victim_score--;
    }

    int ac = 0, hc = 0;
    for (int i = 0; i < IDS_MAX_FLOWS; i++)
        if (g_flows[i].active) ac++;
    for (int i = 0; i < IDS_MAX_HOSTS; i++)
        if (g_hosts[i].active && g_hosts[i].ip) hc++;
    g_ids.active_flows = (uint32_t)ac;
    g_ids.host_count = (uint32_t)hc;
}

/* Saldırı skoruna göre azalan sıralama (snapshot için) */
static int ids_host_cmp_desc(const void *a, const void *b) {
    const IdsHostThreat *ha = (const IdsHostThreat *)a;
    const IdsHostThreat *hb = (const IdsHostThreat *)b;
    if (ha->attack_score != hb->attack_score)
        return ha->attack_score > hb->attack_score ? -1 : 1;
    if (ha->victim_score != hb->victim_score)
        return ha->victim_score > hb->victim_score ? -1 : 1;
    return strcmp(ha->ip, hb->ip);
}

int ids_get_host_threat_snapshot(IdsHostThreatSnapshot *out) {
    if (!out) return 0;
    platform_mutex_lock(&g_ids_lock);
    memset(out, 0, sizeof(*out));
    out->window_start = time(NULL);

    int n = 0;
    for (int i = 0; i < IDS_MAX_HOSTS && n < IDS_MAX_HOSTS; i++) {
        IdsHost *h = &g_hosts[i];
        if (!h->active || !h->ip) continue;

        IdsHostThreat *t = &out->hosts[n];
        memset(t, 0, sizeof(*t));
        ids_ip_to_str(h->ip, t->ip, sizeof(t->ip));
        t->ip_raw = h->ip;
        t->is_gateway = (g_gateway_ip && h->ip == g_gateway_ip);
        t->is_local = (g_local_ip && h->ip == g_local_ip);
        t->attack_score = h->attack_score;
        t->victim_score = h->victim_score;
        t->total_sent = h->sent_pkts;
        t->total_recv = h->recv_pkts;
        t->flows_as_src = h->flows_as_src;
        t->flows_as_dst = h->flows_as_dst;
        t->unique_target_ips = h->unique_target_ips;
        t->unique_target_ports = h->unique_target_ports;
        t->flags = h->flags;
        t->last_seen = h->last_seen;
        strncpy(t->hostname, h->hostname, sizeof(t->hostname) - 1);

        /* En çok paket gidilen hedef / gelinen kaynak (64 kayıtlık özet) */
        typedef struct { uint32_t ip; uint64_t pkts; } PeerAgg;
        PeerAgg vp[64];
        PeerAgg ap[64];
        int vn = 0, an = 0;
        for (int fi = 0; fi < IDS_MAX_FLOWS; fi++) {
            IdsFlow *f = &g_flows[fi];
            if (!f->active) continue;
            if (f->src_ip == h->ip && f->dst_ip != h->ip) {
                int k = -1;
                for (int j = 0; j < vn; j++)
                    if (vp[j].ip == f->dst_ip) { k = j; break; }
                if (k < 0 && vn < 64) {
                    k = vn++;
                    vp[k].ip = f->dst_ip;
                    vp[k].pkts = 0;
                }
                if (k >= 0) vp[k].pkts += f->pkt_count;
            } else if (f->dst_ip == h->ip && f->src_ip != h->ip) {
                int k = -1;
                for (int j = 0; j < an; j++)
                    if (ap[j].ip == f->src_ip) { k = j; break; }
                if (k < 0 && an < 64) {
                    k = an++;
                    ap[k].ip = f->src_ip;
                    ap[k].pkts = 0;
                }
                if (k >= 0) ap[k].pkts += f->pkt_count;
            }
        }
        uint64_t maxp = 0;
        for (int j = 0; j < vn; j++) {
            if (vp[j].pkts > maxp) {
                maxp = vp[j].pkts;
                ids_ip_to_str(vp[j].ip, t->top_victim_ip, sizeof(t->top_victim_ip));
            }
        }
        maxp = 0;
        for (int j = 0; j < an; j++) {
            if (ap[j].pkts > maxp) {
                maxp = ap[j].pkts;
                ids_ip_to_str(ap[j].ip, t->top_attacker_ip,
                              sizeof(t->top_attacker_ip));
            }
        }

        if (h->attack_score >= 80)
            strncpy(t->status, "KRITIK SALDIRGAN", sizeof(t->status) - 1);
        else if (h->attack_score >= 40)
            strncpy(t->status, "SALDIRGAN", sizeof(t->status) - 1);
        else if (h->attack_score >= 15)
            strncpy(t->status, "SUPHELI", sizeof(t->status) - 1);
        else
            strncpy(t->status, "TEMIZ", sizeof(t->status) - 1);
        n++;
    }

    qsort(out->hosts, n, sizeof(IdsHostThreat), ids_host_cmp_desc);
    out->count = n;

    int ac = 0;
    for (int i = 0; i < IDS_MAX_FLOWS; i++)
        if (g_flows[i].active) ac++;
    out->total_flows = ac;

    platform_mutex_unlock(&g_ids_lock);
    return n;
}

void ids_clear_host_data(void) {
    platform_mutex_lock(&g_ids_lock);
    memset(g_flows, 0, sizeof(g_flows));
    g_flow_count = 0;
    memset(g_hosts, 0, sizeof(g_hosts));
    g_host_count = 0;
    memset(g_name_pending, 0, sizeof(g_name_pending));
    g_name_pending_count = 0;
    memset(g_incidents, 0, sizeof(g_incidents));
    g_incident_count = 0;
    g_last_flow_analysis = 0;
    g_ids.active_flows = 0;
    g_ids.host_count = 0;
    g_ids.incident_count = 0;
    platform_mutex_unlock(&g_ids_lock);
}

/* ==================================================================
 *   KURAL EŞİKLERİ
 * ================================================================== */

static const char *brute_force_name(uint16_t dport) {
    switch (dport) {
        case 22:   return "SSH Brute Force";
        case 21:   return "FTP Brute Force";
        case 3389: return "RDP Brute Force";
        case 3306: return "MySQL Brute Force";
        case 5432: return "PostgreSQL Brute Force";
        case 6379: return "Redis Brute Force";
        case 23:   return "Telnet Brute Force";
        case 80:
        case 443:
        case 8080: return "Web Brute Force";
        default:   return "Brute Force";
    }
}

static const char *brute_force_sev(uint16_t dport) {
    switch (dport) {
        case 80:
        case 443:
        case 8080: return "ORTA";
        default:   return "KRITIK";
    }
}

/* ==================================================================
 *   BINDING MAP — IP↔MAC esleme takibi (MAC degisimi / spoof icin)
 * ================================================================== */

#define IDS_BIND_MAX     256
#define IDS_BIND_STABLE  2   /* degisiklik uyarisi icin gereken kararli gozlem */

typedef struct {
    uint32_t ip;
    uint8_t  mac[6];
    int      seen;          /* bu MAC ile gozlenme sayisi */
    time_t   last_seen;
    time_t   last_alert;
    int      valid;
} IdsBinding;

static IdsBinding g_bindings[IDS_BIND_MAX];
static int g_binding_count = 0;

static int ids_binding_find(uint32_t ip) {
    for (int i = 0; i < g_binding_count; i++)
        if (g_bindings[i].valid && g_bindings[i].ip == ip) return i;
    return -1;
}

static int ids_binding_new(void) {
    int i;
    if (g_binding_count < IDS_BIND_MAX) {
        i = g_binding_count++;
    } else {
        /* Kap dolu: en eski kullanilan kayit geri donustur (LRU) */
        i = 0;
        for (int k = 1; k < IDS_BIND_MAX; k++)
            if (g_bindings[k].last_seen < g_bindings[i].last_seen) i = k;
    }
    memset(&g_bindings[i], 0, sizeof(g_bindings[i]));
    return i;
}

/* Guvenilir taban kayitlari (kendi MAC / gateway) icin binding baslat */
static void ids_binding_seed(uint32_t ip, const uint8_t mac[6]) {
    if (!ip || ids_mac_zero(mac)) return;
    int i = ids_binding_find(ip);
    if (i < 0) i = ids_binding_new();
    g_bindings[i].ip = ip;
    memcpy(g_bindings[i].mac, mac, 6);
    g_bindings[i].seen = IDS_BIND_STABLE;
    g_bindings[i].valid = 1;
    g_bindings[i].last_seen = time(NULL);
}

/* Paketlerden IP->MAC eslesmesini ogren; kararli eslesme degisirse uyar */
static void ids_learn_binding(const IdsPktInfo *pi) {
    uint32_t claim_ip;
    if (ids_mac_zero(pi->src_mac)) return;   /* sentetik cerceve: MAC yok */
    claim_ip = pi->is_arp ? pi->arp_sender_ip : pi->src_ip;
    if (!claim_ip) return;
    if (claim_ip == g_gateway_ip || claim_ip == g_local_ip) return;

    int i = ids_binding_find(claim_ip);
    if (i < 0) {
        i = ids_binding_new();
        g_bindings[i].ip = claim_ip;
        memcpy(g_bindings[i].mac, pi->src_mac, 6);
        g_bindings[i].seen = 1;
        g_bindings[i].valid = 1;
        g_bindings[i].last_seen = time(NULL);
        return;
    }
    IdsBinding *b = &g_bindings[i];
    if (memcmp(b->mac, pi->src_mac, 6) != 0) {
        if (b->seen >= IDS_BIND_STABLE) {
            time_t now = time(NULL);
            if (now - b->last_alert >= IDS_ALERT_COOLDOWN) {
                char desc[128];
                char ip[46];
                ids_ip_to_str(claim_ip, ip, sizeof(ip));
                b->last_alert = now;
                snprintf(desc, sizeof(desc),
                         "%s icin MAC %02x:%02x:%02x:%02x:%02x:%02x -> "
                         "%02x:%02x:%02x:%02x:%02x:%02x degisti (spoof/roam?)",
                         ip,
                         b->mac[0], b->mac[1], b->mac[2],
                         b->mac[3], b->mac[4], b->mac[5],
                         pi->src_mac[0], pi->src_mac[1], pi->src_mac[2],
                         pi->src_mac[3], pi->src_mac[4], pi->src_mac[5]);
                ids_raise_alert("IP-MAC Eslesme Degisikligi", "YUKSEK",
                                SCORE_YUKSEK, pi, desc);
            }
        }
        memcpy(b->mac, pi->src_mac, 6);
        b->seen = 1;
    } else if (b->seen < IDS_BIND_STABLE) {
        b->seen++;
    }
    b->last_seen = time(NULL);
}

/* ==================================================================
 *   PAYLOAD IMZA MOTORU — L7 iceriginde saldiri deseni arama
 * ================================================================== */

#define IDS_PAYLOAD_SCAN 96  /* imza aramasinda incelenen on yuk (byte) */

typedef struct {
    const char *needle;
    const char *sig;
    const char *sev;
    double      score;
    int         request_only;   /* yalnizca istek yonunde (cevap degil) ara */
} IdsSig;

static const IdsSig g_sigs[] = {
    /* Web / SQLi / XSS — istek yonu */
    { "sqlmap",        "SQLMap (SQLi taramasi)",       "YUKSEK", SCORE_YUKSEK, 1 },
    { "UNION SELECT",  "SQL Injection (UNION SELECT)", "YUKSEK", SCORE_YUKSEK, 1 },
    { "OR 1=1",        "SQL Injection (OR 1=1)",       "YUKSEK", SCORE_YUKSEK, 1 },
    { "<script",       "XSS (script etiketi)",         "YUKSEK", SCORE_YUKSEK, 1 },
    { "onerror=",      "XSS (onerror)",                "ORTA",   SCORE_ORTA,   1 },
    { "javascript:",   "XSS (javascript)",             "ORTA",   SCORE_ORTA,   1 },
    /* Dosya erisimi / komut calistirma */
    { "/etc/passwd",   "Dosya Erisim (/etc/passwd)",   "YUKSEK", SCORE_YUKSEK, 1 },
    { "/etc/shadow",   "Dosya Erisim (/etc/shadow)",   "KRITIK", SCORE_KRITIK, 1 },
    { "cmd.exe",       "Windows Komut (cmd.exe)",      "KRITIK", SCORE_KRITIK, 1 },
    { "/bin/sh",       "Shell Erisim (/bin/sh)",       "KRITIK", SCORE_KRITIK, 1 },
    { "whoami",        "Komut Calistirma (whoami)",    "YUKSEK", SCORE_YUKSEK, 1 },
    { "<?php",         "PHP Kodu Enjeksiyonu",         "YUKSEK", SCORE_YUKSEK, 1 },
    { "eval(",         "Kod Enjeksiyonu (eval)",       "YUKSEK", SCORE_YUKSEK, 1 },
    /* Powershell / yuk indirme — her iki yon */
    { "powershell",    "PowerShell Komutu",            "YUKSEK", SCORE_YUKSEK, 0 },
    { "-enc",          "PowerShell EncodedCommand",    "KRITIK", SCORE_KRITIK, 1 },
    { "IEX(",          "PowerShell IEX",               "KRITIK", SCORE_KRITIK, 1 },
    { "wget ",         "Yuk Indirme (wget)",           "ORTA",   SCORE_ORTA,   0 },
    { "curl ",         "Yuk Indirme (curl)",           "ORTA",   SCORE_ORTA,   0 },
    { "base64",        "Base64 Kodlanmis Yuk",         "ORTA",   SCORE_ORTA,   0 },
    /* Log4Shell (JNDI) */
    { "jndi:",         "Log4Shell (JNDI)",             "KRITIK", SCORE_KRITIK, 0 },
    { "${jndi:",       "Log4Shell (JNDI ekspr.)",      "KRITIK", SCORE_KRITIK, 0 },
};
#define IDS_SIG_COUNT (int)(sizeof(g_sigs) / sizeof(g_sigs[0]))

static int ids_mem_ci_find(const uint8_t *hay, int hlen, const char *needle) {
    int nlen = (int)strlen(needle);
    if (nlen == 0 || nlen > hlen) return 0;
    for (int i = 0; i + nlen <= hlen; i++) {
        int j = 0;
        for (; j < nlen; j++) {
            char a = (char)hay[i + j];
            char b = needle[j];
            if (a >= 'A' && a <= 'Z') a = (char)(a + 32);
            if (b >= 'A' && b <= 'Z') b = (char)(b + 32);
            if (a != b) break;
        }
        if (j == nlen) return 1;
    }
    return 0;
}

static int ids_mem_has_run(const uint8_t *p, int n, uint8_t byte, int min_run) {
    int run = 0;
    for (int i = 0; i < n; i++) {
        if (p[i] == byte) {
            if (++run >= min_run) return 1;
        } else {
            run = 0;
        }
    }
    return 0;
}

/* Payload'i alintiya cevir: basilabilir karakterler aynen, digerleri "..." */
static void ids_excerpt(const uint8_t *p, int n, char *out, int outlen) {
    int k = 0, i = 0;
    while (i < n && k + 1 < outlen) {
        unsigned char c = p[i];
        if (c >= 0x20 && c < 0x7F) {
            out[k++] = (char)c;
            i++;
        } else {
            if (outlen - k < 4) break;
            out[k++] = '.';
            out[k++] = '.';
            out[k++] = '.';
            while (i < n && !(p[i] >= 0x20 && p[i] < 0x7F)) i++;
        }
    }
    if (i < n && k + 3 < outlen) {
        out[k++] = '.';
        out[k++] = '.';
        out[k++] = '.';
    }
    out[k] = '\0';
}

static void ids_check_payload(const IdsPktInfo *pi) {
    const uint8_t *p = pi->payload;
    int n = pi->payload_len;
    int scan, is_request, i;
    char k2[96];
    char desc[160];
    char ex[64];
    IdsTracker *tr;

    if (!p || n <= 0) return;
    scan = n < IDS_PAYLOAD_SCAN ? n : IDS_PAYLOAD_SCAN;

    /* IsteK yonu: kaynak port >= 1024 ise istemci istegi kabul et.
     * Servis yanitlarinda (sport < 1024, orn. 80/443/53) yalnizca
     * request_only olmayan imzalar aranir. */
    is_request = (pi->src_port >= 1024);

    for (i = 0; i < IDS_SIG_COUNT; i++) {
        const IdsSig *sg = &g_sigs[i];
        if (sg->request_only && !is_request) continue;
        if (!ids_mem_ci_find(p, scan, sg->needle)) continue;

        snprintf(k2, sizeof(k2), "G|%d|%u", i, pi->src_ip);
        tr = ids_tracker_get(k2);
        if (!tr) continue;
        ids_tracker_bump(tr, 0);
        if (!ids_tracker_can_alert(tr)) continue;

        ids_excerpt(p, scan < 48 ? scan : 48, ex, sizeof(ex));
        snprintf(desc, sizeof(desc), "L7 yukunde imza: %s | ilk veri: %s",
                 sg->sig, ex);
        ids_raise_alert(sg->sig, sg->sev, sg->score, pi, desc);
    }

    /* Shellcode sled'leri: NOP (0x90) / INT3 (0xCC) serileri */
    if (ids_mem_has_run(p, n, 0x90, 8)) {
        snprintf(k2, sizeof(k2), "G|NOP|%u", pi->src_ip);
        tr = ids_tracker_get(k2);
        if (tr) {
            ids_tracker_bump(tr, 0);
            if (ids_tracker_can_alert(tr)) {
                ids_excerpt(p, scan < 48 ? scan : 48, ex, sizeof(ex));
                snprintf(desc, sizeof(desc),
                         ">=8 ardIsIk NOP (0x90) | ilk veri: %s", ex);
                ids_raise_alert("Shellcode (NOP-sled)", "KRITIK", SCORE_KRITIK,
                                pi, desc);
            }
        }
    }
    if (ids_mem_has_run(p, n, 0xCC, 8)) {
        snprintf(k2, sizeof(k2), "G|INT3|%u", pi->src_ip);
        tr = ids_tracker_get(k2);
        if (tr) {
            ids_tracker_bump(tr, 0);
            if (ids_tracker_can_alert(tr)) {
                ids_excerpt(p, scan < 48 ? scan : 48, ex, sizeof(ex));
                snprintf(desc, sizeof(desc),
                         ">=8 ardIsIk INT3 (0xCC) | ilk veri: %s", ex);
                ids_raise_alert("Shellcode (INT3-sled)", "KRITIK", SCORE_KRITIK,
                                pi, desc);
            }
        }
    }
}

static void ids_check_rules(const IdsPktInfo *pi) {
    char key[96];
    IdsTracker *t;

    /* ---------- 1. ARP Zehirlenmesi (sahte gateway) ---------- */
    if (pi->is_arp && pi->arp_opcode == 2 && g_gateway_mac_valid &&
        pi->arp_sender_ip == g_gateway_ip) {
        int is_ours = (memcmp(pi->arp_sender_mac, g_local_mac, 6) == 0);
        int is_real = (memcmp(pi->arp_sender_mac, g_gateway_mac, 6) == 0);
        if (!is_ours && !is_real) {
            char desc[128];
            char att_ip[46];
            ids_ip_to_str(pi->arp_sender_ip, att_ip, sizeof(att_ip));
            snprintf(desc, sizeof(desc),
                     "Gateway (%s) icin sahte ARP Reply: MAC %02x:%02x:%02x:%02x:%02x:%02x",
                     att_ip,
                     pi->arp_sender_mac[0], pi->arp_sender_mac[1],
                     pi->arp_sender_mac[2], pi->arp_sender_mac[3],
                     pi->arp_sender_mac[4], pi->arp_sender_mac[5]);
            ids_raise_alert("ARP Zehirlenmesi (MITM)", "KRITIK",
                            SCORE_KRITIK, pi, desc);
        }
    }

    /* ---------- 1b. ARP IP cakismasi: yabanci MAC yerel IP'yi sahipleniyor ---------- */
    if (pi->is_arp && g_local_ip && pi->arp_sender_ip == g_local_ip) {
        int is_ours = (memcmp(pi->arp_sender_mac, g_local_mac, 6) == 0);
        if (!is_ours) {
            char desc[160];
            char att_ip[46];
            ids_ip_to_str(pi->arp_sender_ip, att_ip, sizeof(att_ip));
            snprintf(desc, sizeof(desc),
                     "Yabanci MAC (%02x:%02x:%02x:%02x:%02x:%02x) yerel IP %s icin ARP gonderiyor",
                     pi->arp_sender_mac[0], pi->arp_sender_mac[1],
                     pi->arp_sender_mac[2], pi->arp_sender_mac[3],
                     pi->arp_sender_mac[4], pi->arp_sender_mac[5], att_ip);
            ids_raise_alert("ARP IP Cakismasi (Spoof)", "KRITIK",
                            SCORE_KRITIK, pi, desc);
        }
    }

    /* ---------- 1c. ARP taramasi: tek MAC'ten cok hedefe ARP istegi ---------- */
    if (pi->is_arp && pi->arp_opcode == 1) {
        snprintf(key, sizeof(key), "A|%02x%02x%02x%02x%02x%02x",
                 pi->arp_sender_mac[0], pi->arp_sender_mac[1],
                 pi->arp_sender_mac[2], pi->arp_sender_mac[3],
                 pi->arp_sender_mac[4], pi->arp_sender_mac[5]);
        t = ids_tracker_get(key);
        if (t) {
            ids_tracker_bump(t, pi->arp_target_ip);
            if (t->count >= 20 && t->unique_len >= 8 && ids_tracker_can_alert(t)) {
                char desc[160];
                char m[32];
                snprintf(m, sizeof(m), "%02x:%02x:%02x:%02x:%02x:%02x",
                         pi->arp_sender_mac[0], pi->arp_sender_mac[1],
                         pi->arp_sender_mac[2], pi->arp_sender_mac[3],
                         pi->arp_sender_mac[4], pi->arp_sender_mac[5]);
                snprintf(desc, sizeof(desc),
                         "%s -> %u farkli IP'ye ARP istegi (%u paket) - ag kesfi",
                         m, t->unique_len, t->count);
                ids_raise_alert("ARP Taramasi (Ag Kesfi)", "ORTA",
                                SCORE_ORTA, pi, desc);
            }
        }
    }

    /* ---------- 2. Kötü amaçlı portlara bağlantı ---------- */
    if (pi->is_tcp) {
        static const struct MalPortDef { int port; const char *name; } mal_ports[] = {
            { 4444,  "Meterpreter" },
            { 31337, "BackOrifice" },
            { 5555,  "Android ADB" },
            { 6667,  "IRC (botnet?)" },
            { 4445,  "Metasploit" },
            { 1090,  "X-KeyStroke (RAT)" },
            { 1099,  "Java RMI Registry" },
            { 1524,  "Metasploit Backdoor (ingreslock)" },
            { 6666,  "IRC Alt (botnet?)" },
            { 54320, "BackOrifice 2000" },
            { 54321, "BackOrifice 2000 (alt)" },
            { 31338, "BackOrifice (UDP)" },
        };
        const char *mal = NULL;
        for (size_t mi = 0; mi < sizeof(mal_ports) / sizeof(mal_ports[0]); mi++) {
            if (pi->dst_port == mal_ports[mi].port) {
                mal = mal_ports[mi].name;
                break;
            }
        }
        if (mal) {
            /* Akis bazli tekrar bastirma: ayni kaynak->hedef->port akisi icin
             * IDS_ALERT_COOLDOWN (60 sn) surece yalnizca TEK uyari uret.
             * /proc/net fallback modu her 2 sn'de bir ayni SYN baglantisini
             * yeniden sentezleyip IDS'e besledigi icin bu kural olmasaydi
             * ayni uyaridan yuzlercesi aninda yigilirdi. */
            snprintf(key, sizeof(key), "M|%u|%u|%u",
                     pi->src_ip, pi->dst_ip, pi->dst_port);
            t = ids_tracker_get(key);
            if (t) {
                ids_tracker_bump(t, 0);
                if (ids_tracker_can_alert(t)) {
                    char desc[128];
                    snprintf(desc, sizeof(desc),
                             "Kotu amacli port %d (%s) baglantisi",
                             pi->dst_port, mal);
                    ids_raise_alert(mal, "KRITIK", SCORE_KRITIK, pi, desc);
                }
            }
        }
    }

    /* ---------- 3. TCP tabanlı tarama / saldırılar ---------- */
    if (pi->is_tcp) {
        int is_syn = (pi->tcp_flags & 0x02) && !(pi->tcp_flags & 0x10);
        int is_fin_only = (pi->tcp_flags == 0x01);
        int is_null = (pi->tcp_flags == 0x00);
        int is_xmas = (pi->tcp_flags == 0x29);

        /* SYN kaynak taraması: tek kaynaktan çok farklı port */
        if (is_syn) {
            snprintf(key, sizeof(key), "S|%u", pi->src_ip);
            t = ids_tracker_get(key);
            if (t) {
                ids_tracker_bump(t, pi->dst_port);
                if (t->count >= 20 && t->unique_len >= 8 && ids_tracker_can_alert(t)) {
                    char desc[128];
                    char s[46];
                    ids_ip_to_str(pi->src_ip, s, sizeof(s));
                    snprintf(desc, sizeof(desc),
                             "%s -> %d farkli porta SYN taramasi (%u paket)",
                             s, t->unique_len, t->count);
                    ids_raise_alert("Port Taramasi (SYN)", "YUKSEK",
                                    SCORE_YUKSEK, pi, desc);
                }
            }

            /* SYN flood: tek hedefe çok farklı kaynaktan SYN */
            snprintf(key, sizeof(key), "F|%u|%u", pi->dst_ip, pi->dst_port);
            t = ids_tracker_get(key);
            if (t) {
                ids_tracker_bump(t, pi->src_ip);
                if (t->count >= 100 && t->unique_len >= 20 && ids_tracker_can_alert(t)) {
                    char desc[128];
                    char d[46];
                    ids_ip_to_str(pi->dst_ip, d, sizeof(d));
                    snprintf(desc, sizeof(desc),
                             "%s:%u hedefine %u farkli kaynaktan SYN flood",
                             d, pi->dst_port, t->unique_len);
                    ids_raise_alert("SYN Flood (DDoS)", "KRITIK",
                                    SCORE_KRITIK, pi, desc);
                }
            }

            /* Brute force: aynı kaynak→hedef→port arası çok bağlantı */
            snprintf(key, sizeof(key), "C|%u|%u|%u", pi->src_ip, pi->dst_ip,
                     pi->dst_port);
            t = ids_tracker_get(key);
            if (t) {
                /* Farkli kaynak portlari say: fallback modunun her 2 sn'de
                 * ayni SYN baglantisini yeniden sentezlemesi tek bir kaynak
                 * portu tekrar tekrar sayip yanlis "brute force" uyarisi
                 * uretiyordu. Gercek brute force her baglanti denemesinde
                 * yeni bir ephemeral kaynak port kullanir. */
                ids_tracker_bump(t, pi->src_port);
                if (t->count >= 8 && t->unique_len >= 5 && ids_tracker_can_alert(t)) {
                    char desc[192];
                    char s[46], d[46];
                    ids_ip_to_str(pi->src_ip, s, sizeof(s));
                    ids_ip_to_str(pi->dst_ip, d, sizeof(d));
                    snprintf(desc, sizeof(desc),
                             "%s -> %s:%u arasi %u farkli kaynak porttan %u baglanti denemesi",
                             s, d, pi->dst_port, t->unique_len, t->count);
                    ids_raise_alert(brute_force_name(pi->dst_port),
                                    brute_force_sev(pi->dst_port),
                                    SCORE_KRITIK, pi, desc);
                }
            }

            /* Yatay tarama: ayni porta cok farkli hedefe SYN (tek kaynak) */
            snprintf(key, sizeof(key), "Y|%u|%u", pi->src_ip, pi->dst_port);
            t = ids_tracker_get(key);
            if (t) {
                ids_tracker_bump(t, pi->dst_ip);
                if (t->count >= 8 && t->unique_len >= 6 && ids_tracker_can_alert(t)) {
                    char desc[128];
                    char s[46];
                    ids_ip_to_str(pi->src_ip, s, sizeof(s));
                    snprintf(desc, sizeof(desc),
                             "%s -> %u farkli hedefe port %u SYN (yatay tarama)",
                             s, t->unique_len, pi->dst_port);
                    ids_raise_alert("Yatay Tarama (Ayni Port)", "YUKSEK",
                                    SCORE_YUKSEK, pi, desc);
                }
            }
        }

        /* Stealth tarama tipleri */
        if (is_fin_only) {
            snprintf(key, sizeof(key), "T|FIN|%u", pi->src_ip);
            t = ids_tracker_get(key);
            if (t) {
                ids_tracker_bump(t, pi->dst_port);
                if (t->count >= 15 && t->unique_len >= 5 && ids_tracker_can_alert(t))
                    ids_raise_alert("Port Taramasi (FIN)", "YUKSEK",
                                    SCORE_YUKSEK, pi, "FIN-only paketlerle stealth tarama");
            }
        } else if (is_null) {
            snprintf(key, sizeof(key), "T|NULL|%u", pi->src_ip);
            t = ids_tracker_get(key);
            if (t) {
                ids_tracker_bump(t, pi->dst_port);
                if (t->count >= 15 && t->unique_len >= 5 && ids_tracker_can_alert(t))
                    ids_raise_alert("Port Taramasi (NULL)", "YUKSEK",
                                    SCORE_YUKSEK, pi, "Flagsiz (NULL) paketlerle stealth tarama");
            }
        } else if (is_xmas) {
            snprintf(key, sizeof(key), "T|XMAS|%u", pi->src_ip);
            t = ids_tracker_get(key);
            if (t) {
                ids_tracker_bump(t, pi->dst_port);
                if (t->count >= 15 && t->unique_len >= 5 && ids_tracker_can_alert(t))
                    ids_raise_alert("Port Taramasi (Xmas)", "YUKSEK",
                                    SCORE_YUKSEK, pi, "FIN+PSH+URG (Xmas) paketlerle stealth tarama");
            }
        }

        /* Bogus bayrak kombinasyonlari (TCP yiginlari kabul etmez) */
        if (pi->tcp_flags == 0x03 || pi->tcp_flags == 0x05 ||
            pi->tcp_flags == 0x06) {
            const char *bogus = "SYN+FIN";
            if (pi->tcp_flags == 0x05)      bogus = "FIN+RST";
            else if (pi->tcp_flags == 0x06) bogus = "SYN+RST";
            snprintf(key, sizeof(key), "W|%02x|%u", pi->tcp_flags, pi->src_ip);
            t = ids_tracker_get(key);
            if (t) {
                ids_tracker_bump(t, ids_hash_unique(pi->dst_ip, pi->dst_port));
                if (t->count >= 4 && t->unique_len >= 2 && ids_tracker_can_alert(t)) {
                    char desc[128];
                    char sig[64];
                    char s[46];
                    ids_ip_to_str(pi->src_ip, s, sizeof(s));
                    snprintf(sig, sizeof(sig), "Bogus Bayrak (%s)", bogus);
                    snprintf(desc, sizeof(desc),
                             "%s tarafindan %u farkli hedef/porta %s bayrakli %u paket",
                             s, t->unique_len, bogus, t->count);
                    ids_raise_alert(sig, "ORTA", SCORE_ORTA, pi, desc);
                }
            }
        }
    }

    /* ---------- 4. UDP tarama / flood ---------- */
    if (pi->is_udp) {
        /* DNS cevaplari (kaynak port 53 -> yuksek hedef port) tarama gibi
         * gorunup yanlis pozitif uretiyordu; sayac yalnizca dusuk hedef
         * porta giden ve DNS kaynagi olmayan paketlerle beslenir. */
        if (pi->dst_port < 1024 && pi->src_port != 53) {
            snprintf(key, sizeof(key), "U|%u", pi->src_ip);
            t = ids_tracker_get(key);
            if (t) {
                ids_tracker_bump(t, pi->dst_port);
                if (t->count >= 15 && t->unique_len >= 8 && ids_tracker_can_alert(t))
                    ids_raise_alert("UDP Port Taramasi", "ORTA", SCORE_ORTA, pi,
                                    "Tek kaynaktan cok sayida farkli UDP portuna paket");
                if (t->count >= 200 && t->unique_len >= 10 && ids_tracker_can_alert(t))
                    ids_raise_alert("UDP Flood", "ORTA", SCORE_ORTA, pi,
                                    "Tek kaynaktan asiri UDP trafigi");
            }
        }

        /* DNS anomali: tek kaynaktan aşırı sorgu */
        if (pi->is_dns) {
            snprintf(key, sizeof(key), "D|%u", pi->src_ip);
            t = ids_tracker_get(key);
            if (t) {
                ids_tracker_bump(t, 0);
                if (t->count >= 50 && ids_tracker_can_alert(t))
                    ids_raise_alert("DNS Anomali", "ORTA", SCORE_ORTA, pi,
                                    "Tek kaynaktan asiri DNS sorgusu (tunneling/flood?)");
            }
        }
    }

    /* ---------- 5. ICMP flood / ping sweep ---------- */
    if (pi->is_icmp) {
        snprintf(key, sizeof(key), "I|%u", pi->src_ip);
        t = ids_tracker_get(key);
        if (t) {
            ids_tracker_bump(t, pi->dst_ip);
            if (t->unique_len >= 10 && ids_tracker_can_alert(t))
                ids_raise_alert("Ping Sweep", "ORTA", SCORE_ORTA, pi,
                                "Tek kaynaktan cok sayida farkli hedefe ICMP (ag kesfi)");
            if (t->count >= 100 && ids_tracker_can_alert(t))
                ids_raise_alert("ICMP Flood", "ORTA", SCORE_ORTA, pi,
                                "Tek kaynaktan asiri ICMP trafigi");
        }
    }

    /* ---------- 6. Broadcast / multicast storm ---------- */
    if (pi->is_broadcast || pi->is_multicast) {
        t = ids_tracker_get("B");
        if (t) {
            ids_tracker_bump(t, 0);
            if (t->count >= 150 && ids_tracker_can_alert(t))
                ids_raise_alert("Broadcast Storm", "ORTA", SCORE_ORTA, pi,
                                "Asiri broadcast/multicast trafigi (ag yavaslamasi)");
        }
    }

    /* ---------- 7. L7 payload imza taramasi ---------- */
    ids_check_payload(pi);
}

/* ==================================================================
 *   PUBLIC API
 * ================================================================== */

void ids_init(void) {
    if (g_ids_initialized) return;
    platform_mutex_init(&g_ids_lock);
    memset(&g_ids, 0, sizeof(g_ids));
    memset(g_alert_buf, 0, sizeof(g_alert_buf));
    g_alert_count = 0;
    memset(g_trackers, 0, sizeof(g_trackers));
    g_tracker_count = 0;
    memset(g_bindings, 0, sizeof(g_bindings));
    g_binding_count = 0;
    memset(g_local_mac, 0, sizeof(g_local_mac));
    memset(g_gateway_mac, 0, sizeof(g_gateway_mac));
    g_gateway_mac_valid = 0;
    g_gateway_ip = 0;
    g_local_ip = 0;
    /* LAN katmanı */
    memset(g_flows, 0, sizeof(g_flows));
    g_flow_count = 0;
    memset(g_hosts, 0, sizeof(g_hosts));
    g_host_count = 0;
    memset(g_name_pending, 0, sizeof(g_name_pending));
    g_name_pending_count = 0;
    memset(g_incidents, 0, sizeof(g_incidents));
    g_incident_count = 0;
    g_ids.incident_count = 0;
    g_net_base = 0;
    g_net_mask = 0;
    g_net_range_set = 0;
    g_last_flow_analysis = 0;
    g_ids.active_flows = 0;
    g_ids.host_count = 0;
    g_ids.running = 1;
    g_ids.rule_count = 20;
    g_ids_initialized = 1;
}

void ids_cleanup(void) {
    if (!g_ids_initialized) return;
    g_ids.running = 0;
    platform_mutex_destroy(&g_ids_lock);
    g_ids_initialized = 0;
}

/* Lokal kaynakli (self) SYN taramasi: kendi makinenizden disariya yapilan
 * port taramalari (ornek nmap) genel kurallara takilmaz cunku self trafik
 * yanlis pozitifleri onlemek icin bastirilir. Bu kural yalnizca TCP SYN
 * paketlerini sayar; ayni kaynaktan cok sayida FARKLI hedef porta SYN
 * gidince uyari verir. Normal tarayici trafigi 2-3 porta dokunur,
 * cok sayida farkli porta dokunmadigi surece tetiklenmez. */
static void ids_check_local_scan(const IdsPktInfo *pi) {
    char key[64];
    IdsTracker *t;
    if (!pi->is_tcp) return;
    int is_syn = (pi->tcp_flags & 0x02) && !(pi->tcp_flags & 0x10);
    if (!is_syn) return;
    snprintf(key, sizeof(key), "L|%u", pi->src_ip);
    t = ids_tracker_get(key);
    if (t) {
        ids_tracker_bump(t, pi->dst_port);
        if (t->count >= 16 && t->unique_len >= 8 && ids_tracker_can_alert(t)) {
            char desc[128];
            char s[46];
            ids_ip_to_str(pi->src_ip, s, sizeof(s));
            snprintf(desc, sizeof(desc),
                     "%s -> %u farkli porta disari SYN taramasi (%u paket)",
                     s, t->unique_len, t->count);
            ids_raise_alert("Yerel Kaynakli Port Taramasi", "YUKSEK",
                            SCORE_YUKSEK, pi, desc);
        }
    }
}

void ids_process_packet(const PacketRecord *pkt) {
    if (!g_ids.running || !pkt) return;

    IdsPktInfo pi;
    ids_parse_pkt(pkt, &pi);
    if (!pi.is_ipv4 && !pi.is_arp) return;

    /* LAN katmanı: kendi ürettiğimiz trafik dahil TÜM trafiği akış
     * tablosuna işle — Tehdit Haritası ağ geneli görüşe dayanır. */
    ids_flow_update(&pi, pkt);
    ids_flow_analysis();

    /* Kendi urettigimiz trafik genel kurallari tetiklemesin: otomatik
     * ARP/ping taramasi (pcap kendi cercevelerini de gorur) ve fallback
     * modun sentetik cerceveleri Broadcast Storm / Ping Sweep / SYN tarama
     * kurallarini tetikleyip Uyarilar sekmesini dolduruyordu. Ancak
     * disariya yaptigimiz port taramalari da tespit edilsin istiyoruz;
     * bu yuzden self trafikte yalnizca ids_check_local_scan() calisir. */
    if (ids_is_self_originated(&pi)) {
        ids_check_local_scan(&pi);
        return;
    }

    g_ids.total_pkts_processed++;
    ids_learn_binding(&pi);
    ids_check_rules(&pi);
    g_ids.active_trackers = g_tracker_count;
}

int ids_get_alerts_snapshot(IdsGuiAlert *out, int max_count) {
    if (!out || max_count <= 0) return 0;
    platform_mutex_lock(&g_ids_lock);
    int n = (g_alert_count < max_count) ? g_alert_count : max_count;
    for (int i = 0; i < n; i++) out[i] = g_alert_buf[i];
    platform_mutex_unlock(&g_ids_lock);
    return n;
}

void ids_clear_alerts(void) {
    platform_mutex_lock(&g_ids_lock);
    memset(g_alert_buf, 0, sizeof(g_alert_buf));
    g_alert_count = 0;
    platform_mutex_unlock(&g_ids_lock);
}

/* ---- SOC v3: kill chain asamasi (imza adindan) ---- */
static int ids_killchain_for_sig(const char *sig) {
    if (!sig) return 2;
    if (strstr(sig, "Tarama") || strstr(sig, "Sweep") || strstr(sig, "Scan"))
        return 1;   /* kesif */
    if (strstr(sig, "DGA") || strstr(sig, "Tunel") || strstr(sig, "C2") ||
        strstr(sig, "Komut") || strstr(sig, "Botnet"))
        return 3;   /* C2 / etki */
    return 2;       /* sizma */
}

/* Ayni saldirgan->kurban ciftini 600 sn pencerede birlestir (32 kayit) */
static void ids_incident_update(uint32_t att, uint32_t vic, const char *sig,
                                const char *sev, double score) {
    if (!att || !vic) return;
    time_t now = time(NULL);
    for (int i = 0; i < g_incident_count; i++) {
        IdsIncidentInt *ic = &g_incidents[i];
        if (ic->attacker == att && ic->victim == vic) {
            if (now - ic->last_seen > 600) continue;   /* yeni pencere */
            ic->alert_count++;
            ic->flags |= ids_sig_flags(sig);
            if (score > ic->max_score) ic->max_score = score;
            if (sev) strncpy(ic->worst_severity, sev,
                             sizeof(ic->worst_severity) - 1);
            strncpy(ic->last_sig, sig, sizeof(ic->last_sig) - 1);
            int kc = ids_killchain_for_sig(sig);
            if (kc > ic->killchain) ic->killchain = kc;
            ic->last_seen = now;
            return;
        }
    }
    if (g_incident_count < IDS_MAX_INCIDENTS) {
        IdsIncidentInt *ic = &g_incidents[g_incident_count++];
        memset(ic, 0, sizeof(*ic));
        ic->attacker = att;
        ic->victim = vic;
        ic->alert_count = 1;
        ic->flags = ids_sig_flags(sig);
        ic->killchain = ids_killchain_for_sig(sig);
        ic->max_score = score;
        if (sev) strncpy(ic->worst_severity, sev,
                         sizeof(ic->worst_severity) - 1);
        strncpy(ic->last_sig, sig, sizeof(ic->last_sig) - 1);
        ic->first_seen = ic->last_seen = now;
    }
}

/* En son gorulen once (snapshot siralama) */
static int ids_incident_cmp_last(const void *a, const void *b) {
    const IdsIncident *ia = (const IdsIncident *)a;
    const IdsIncident *ib = (const IdsIncident *)b;
    if (ia->last_seen != ib->last_seen)
        return ia->last_seen > ib->last_seen ? -1 : 1;
    return 0;
}

int ids_get_incidents_snapshot(IdsIncident *out, int max_count) {
    if (!out || max_count <= 0) return 0;
    platform_mutex_lock(&g_ids_lock);
    int n = (g_incident_count < max_count) ? g_incident_count : max_count;
    for (int i = 0; i < n; i++) {
        IdsIncidentInt *ic = &g_incidents[i];
        ids_ip_to_str(ic->attacker, out[i].attacker_ip,
                      sizeof(out[i].attacker_ip));
        ids_ip_to_str(ic->victim, out[i].victim_ip,
                      sizeof(out[i].victim_ip));
        out[i].alert_count = ic->alert_count;
        out[i].flags = ic->flags;
        out[i].killchain = ic->killchain;
        strncpy(out[i].worst_severity, ic->worst_severity,
                sizeof(out[i].worst_severity) - 1);
        out[i].max_score = ic->max_score;
        strncpy(out[i].last_sig, ic->last_sig, sizeof(out[i].last_sig) - 1);
        out[i].first_seen = ic->first_seen;
        out[i].last_seen = ic->last_seen;
    }
    qsort(out, n, sizeof(IdsIncident), ids_incident_cmp_last);
    g_ids.incident_count = (uint32_t)n;
    platform_mutex_unlock(&g_ids_lock);
    return n;
}

/* Uyari triyaji: durum guncelle (index/durum gecersizse 0) */
int ids_set_alert_status(int index, int status) {
    if (index < 0 || index >= g_alert_count) return 0;
    if (status < IDS_ALERT_STATUS_NEW || status > IDS_ALERT_STATUS_FALSEPOS)
        return 0;
    platform_mutex_lock(&g_ids_lock);
    g_alert_buf[index].status = status;
    platform_mutex_unlock(&g_ids_lock);
    return 1;
}

/* Uyari triyaji: analist notu yaz */
int ids_set_alert_note(int index, const char *note) {
    if (index < 0 || index >= g_alert_count) return 0;
    if (!note) return 0;
    platform_mutex_lock(&g_ids_lock);
    strncpy(g_alert_buf[index].note, note,
            sizeof(g_alert_buf[index].note) - 1);
    platform_mutex_unlock(&g_ids_lock);
    return 1;
}

void ids_set_mac_context(const char *local_mac, const char *gateway_mac,
                         const char *gateway_ip, const char *local_ip) {
    unsigned int b[6];
    if (gateway_mac && sscanf(gateway_mac, "%x:%x:%x:%x:%x:%x",
                              &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) == 6) {
        for (int i = 0; i < 6; i++) g_gateway_mac[i] = (uint8_t)b[i];
        g_gateway_mac_valid = 1;
    }
    if (local_mac && sscanf(local_mac, "%x:%x:%x:%x:%x:%x",
                            &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) == 6) {
        for (int i = 0; i < 6; i++) g_local_mac[i] = (uint8_t)b[i];
    }
    if (gateway_ip) {
        unsigned int a, c, d, e;
        if (sscanf(gateway_ip, "%u.%u.%u.%u", &a, &c, &d, &e) == 4)
            g_gateway_ip = (a << 24) | (c << 16) | (d << 8) | e;
    }
    if (local_ip) {
        unsigned int a, c, d, e;
        if (sscanf(local_ip, "%u.%u.%u.%u", &a, &c, &d, &e) == 4)
            g_local_ip = (a << 24) | (c << 16) | (d << 8) | e;
    }

    /* Kapsam: acikca CIDR verilmediyse yerel IP'den sinifli agi turet.
     * Boylece LAN tespiti 'Aga Tara' sonucuna bagimli kalmaz; izleme
     * baslar baslamaz dogru alt ag kapsami hazirdir. */
    if (!g_net_range_set && g_local_ip) {
        uint8_t a = (uint8_t)(g_local_ip >> 24);
        uint8_t b = (uint8_t)(g_local_ip >> 16);
        uint32_t bits = 24;
        if (a == 10) bits = 8;
        else if (a == 172 && b >= 16 && b <= 31) bits = 12;
        else if (a == 192 && b == 168) bits = 16;
        g_net_mask = (bits == 32) ? 0xFFFFFFFFu : (0xFFFFFFFFu << (32 - bits));
        g_net_base = g_local_ip & g_net_mask;
        g_net_range_set = 1;
    }

    /* Binding map'ine guvenilir taban kayitlarini ekle */
    if (g_gateway_ip && g_gateway_mac_valid)
        ids_binding_seed(g_gateway_ip, g_gateway_mac);
    if (g_local_ip && !ids_mac_zero(g_local_mac))
        ids_binding_seed(g_local_ip, g_local_mac);
}





