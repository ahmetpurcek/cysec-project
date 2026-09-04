/*
 * network_ids.h — Kural Tabanlı Ağ Saldırı Tespit Sistemi (IDS)
 *
 * full_monitor tarafından yakalanan paketleri analiz eder:
 * port taraması, brute force, flood, ARP zehirlenmesi, kötü amaçlı
 * port bağlantıları ve DNS/broadcast anomalilerini tespit eder.
 *
 * Ağır ML/imza sistemleri yerine hafif, hızlı, kural tabanlı eşik
 * analizi kullanır (Snort mantığı, C ile).
 */
#ifndef NETWORK_IDS_H
#define NETWORK_IDS_H

#include "platform.h"
#include "network_monitor.h"
#include <stdint.h>

/* ========== Sabitler ========== */
#define IDS_MAX_ALERTS         512     /* dahili alert ring buffer */
#define IDS_MAX_GUI_ALERTS     256     /* GUI snapshot limiti */
#define IDS_MAX_TRACKERS       2048    /* akış/izleme kaydı */
#define IDS_WINDOW_SEC         10      /* eşik penceresi (saniye) */
#define IDS_ALERT_COOLDOWN     60      /* aynı uyarının tekrarı arası (sn) */

/* ========== GUI için düz alert yapısı ========== */
typedef struct {
    char        sig_name[64];
    char        src_ip[46];
    char        dst_ip[46];
    uint16_t    src_port;
    uint16_t    dst_port;
    char        timestamp[32];
    double      score;
    char        severity[16];   /* KRITIK, YUKSEK, ORTA, DUSUK */
    char        description[128];
} IdsGuiAlert;

/* ========== IDS durumu (GUI erişimi için global) ========== */
typedef struct {
    int         running;
    int         rule_count;         /* aktif kural sayısı */
    uint64_t    total_pkts_processed;
    uint64_t    total_alerts;
    int         active_trackers;    /* anlık takip edilen akış sayısı */
} IdsAgent;

extern IdsAgent g_ids;

/* ========== API ========== */
void ids_init(void);
void ids_cleanup(void);

/* Yakalanan her paket için çağrılır (full_monitor callback'inden) */
void ids_process_packet(const PacketRecord *pkt);

/* GUI snapshot: son IDS_MAX_GUI_ALERTS uyarıyı düz diziye kopyalar */
int  ids_get_alerts_snapshot(IdsGuiAlert *out, int max_count);
void ids_clear_alerts(void);

/* MAC/IP bağlamı: ARP zehirlenmesi tespiti ve self-origin uyari
 * bastirmasi icin gateway/kendi MAC ve yerel IP bilgisi */
void ids_set_mac_context(const char *local_mac, const char *gateway_mac,
                         const char *gateway_ip, const char *local_ip);

#endif /* NETWORK_IDS_H */


