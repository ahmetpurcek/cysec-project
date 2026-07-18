/*
 * arp_scanner.h — ARP Ağ Tarayıcı
 * Ağdaki cihazları keşfeder, sınıflandırır ve izler.
 */
#ifndef ARP_SCANNER_H
#define ARP_SCANNER_H

#include "platform.h"
#include "utils.h"

/* ========== Sabitler ========== */
#define MAX_DEVICES     256
#define MAX_VENDOR_DB   50000
#define SCAN_INTERVAL   15       /* saniye */
#define DEVICE_TIMEOUT  120      /* saniye — bu süre sonra kaybolur */

/* ========== Cihaz Risk Seviyeleri ========== */
typedef enum {
    RISK_NONE = 0,
    RISK_LOW,
    RISK_MEDIUM,
    RISK_HIGH,
    RISK_CRITICAL
} RiskLevel;

/* ========== Cihaz Yapısı ========== */
typedef struct {
    char ip[MAX_IP_LEN];
    char mac[MAX_MAC_LEN];
    char vendor[MAX_VENDOR_LEN];
    char hostname[MAX_HOSTNAME_LEN];
    char type[64];              /* "Router/Gateway", "Bilgisayar", vs. */
    char icon[8];               /* Emoji UTF-8 */
    RiskLevel risk;
    int  is_gateway;
    int  is_local;
    int  is_random_mac;
    time_t discovered_at;
    time_t last_seen;
} Device;

/* ========== Tarama Sonuçları ========== */
typedef struct {
    Device devices[MAX_DEVICES];
    int    device_count;
    
    /* Gateway bilgisi */
    char gateway_ip[MAX_IP_LEN];
    char gateway_mac[MAX_MAC_LEN];
    
    /* Yerel cihaz bilgisi */
    char local_ip[MAX_IP_LEN];
    char local_mac[MAX_MAC_LEN];
    char local_iface[MAX_IFACE_LEN];
    
    /* Ağ aralığı */
    char network_range[32];
    
    /* Durum */
    int  is_scanning;
    int  scan_count;
    time_t last_scan_time;
    
    /* Özet */
    int total;
    int routers;
    int computers;
    int mobile;
    int iot;
    int unknown;
    int high_risk;
    int medium_risk;
} ScanResults;

/* ========== MAC Vendor Veritabanı ========== */
void scanner_load_mac_vendors(const char *filepath);
const char *scanner_get_vendor(const char *mac);

/* ========== Tarama Fonksiyonları ========== */
void scanner_init(void);
void scanner_cleanup(void);

/* Tam ağ taraması (senkron) */
int  scanner_full_scan(void);

/* Tarama sonuçlarını al (thread-safe) */
void scanner_get_results(ScanResults *out);

/* Arka plan otonom tarama başlat */
void scanner_start_auto_scan(int interval_sec);

/* Cihaz sınıflandırma */
void scanner_classify_device(Device *dev, const char *gateway_ip, const char *local_ip);

/* ========== Log Mesajları ========== */
#define MAX_SCAN_LOG_LINES 100
typedef struct {
    char lines[MAX_SCAN_LOG_LINES][256];
    int  count;
    int  write_idx;
} ScanLog;

void scanner_log(const char *fmt, ...);
void scanner_get_log(ScanLog *out);

#endif /* ARP_SCANNER_H */
