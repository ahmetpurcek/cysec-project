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
        if (pi->dst_port == 53 && l4len >= 12) {
            uint16_t qd = (l4[8] << 8) | l4[9];
            pi->is_dns = (qd > 0);
        }
        if (l4len > 8) {
            pi->payload = l4 + 8;
            pi->payload_len = l4len - 8;
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

    /* Binding map'ine guvenilir taban kayitlarini ekle */
    if (g_gateway_ip && g_gateway_mac_valid)
        ids_binding_seed(g_gateway_ip, g_gateway_mac);
    if (g_local_ip && !ids_mac_zero(g_local_mac))
        ids_binding_seed(g_local_ip, g_local_mac);
}


