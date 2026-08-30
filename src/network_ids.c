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
} IdsPktInfo;

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
    } else if (proto == 17 && l4len >= 8) {
        pi->is_udp = 1;
        pi->src_port = (l4[0] << 8) | l4[1];
        pi->dst_port = (l4[2] << 8) | l4[3];
        if (pi->dst_port == 53 && l4len >= 12) {
            uint16_t qd = (l4[8] << 8) | l4[9];
            pi->is_dns = (qd > 0);
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

/* ==================================================================
 *   IDS STATE
 * ================================================================== */

IdsAgent g_ids;

static platform_mutex_t g_ids_lock;
static int g_ids_initialized = 0;

/* MAC bağlamı (ARP zehirlenmesi için) */
static uint8_t g_local_mac[6];
static uint8_t g_gateway_mac[6];
static int     g_gateway_mac_valid = 0;
static uint32_t g_gateway_ip = 0;

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
    platform_mutex_unlock(&g_ids_lock);
}

/* ==================================================================
 *   KURAL EŞİKLERİ
 * ================================================================== */

#define SCORE_KRITIK 0.95
#define SCORE_YUKSEK 0.75
#define SCORE_ORTA   0.50
#define SCORE_DUSUK  0.25

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

    /* ---------- 2. Kötü amaçlı portlara bağlantı ---------- */
    if (pi->is_tcp) {
        const char *mal = NULL;
        if (pi->dst_port == 4444)      mal = "Meterpreter";
        else if (pi->dst_port == 31337) mal = "BackOrifice";
        else if (pi->dst_port == 5555)  mal = "Android ADB";
        else if (pi->dst_port == 6667)  mal = "IRC (botnet?)";
        else if (pi->dst_port == 4445)  mal = "Metasploit";
        if (mal) {
            char desc[128];
            snprintf(desc, sizeof(desc), "Kotu amacli port %d (%s) baglantisi",
                     pi->dst_port, mal);
            ids_raise_alert(mal, "KRITIK", SCORE_KRITIK, pi, desc);
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
                ids_tracker_bump(t, 0);
                if (t->count >= 8 && ids_tracker_can_alert(t)) {
                    char desc[128];
                    char s[46], d[46];
                    ids_ip_to_str(pi->src_ip, s, sizeof(s));
                    ids_ip_to_str(pi->dst_ip, d, sizeof(d));
                    snprintf(desc, sizeof(desc),
                             "%s -> %s:%u arasi %u baglanti denemesi",
                             s, d, pi->dst_port, t->count);
                    ids_raise_alert(brute_force_name(pi->dst_port),
                                    brute_force_sev(pi->dst_port),
                                    SCORE_KRITIK, pi, desc);
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
    }

    /* ---------- 4. UDP tarama / flood ---------- */
    if (pi->is_udp) {
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
    memset(g_local_mac, 0, sizeof(g_local_mac));
    memset(g_gateway_mac, 0, sizeof(g_gateway_mac));
    g_gateway_mac_valid = 0;
    g_gateway_ip = 0;
    g_ids.running = 1;
    g_ids.rule_count = 14;
    g_ids_initialized = 1;
}

void ids_cleanup(void) {
    if (!g_ids_initialized) return;
    g_ids.running = 0;
    platform_mutex_destroy(&g_ids_lock);
    g_ids_initialized = 0;
}

void ids_process_packet(const PacketRecord *pkt) {
    if (!g_ids.running || !pkt) return;

    IdsPktInfo pi;
    ids_parse_pkt(pkt, &pi);
    if (!pi.is_ipv4 && !pi.is_arp) return;

    g_ids.total_pkts_processed++;
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

void ids_set_mac_context(const char *local_mac, const char *gateway_mac,
                         const char *gateway_ip) {
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
}


