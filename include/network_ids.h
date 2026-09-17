/*
 * network_ids.h — Kural Tabanlı Ağ Saldırı Tespit Sistemi (IDS)
 * Port taraması, brute force, flood, ARP zehirlenmesi, kötü amaçlı port
 * ve DNS/broadcast anomalilerini hafif eşik analiziyle tespit eder (Snort
 * mantığı, C ile). v2 (LAN katmanı): akış tablosundan her cihaz için
 * saldırı/kurban skoru ve tehdit durumu üretir (Tehdit Haritası).
 */
#ifndef NETWORK_IDS_H
#define NETWORK_IDS_H

#include "platform.h"
#include "network_monitor.h"
#include <stdint.h>
#include <time.h>

/* ========== Sabitler ========== */
#define IDS_MAX_ALERTS         512     /* dahili alert ring buffer */
#define IDS_MAX_GUI_ALERTS     256     /* GUI snapshot limiti */
#define IDS_MAX_TRACKERS       2048    /* akış/izleme kaydı */
#define IDS_WINDOW_SEC         10      /* eşik penceresi (saniye) */
#define IDS_ALERT_COOLDOWN     60      /* aynı uyarının tekrarı arası (sn) */

/* ===== YAVAŞ (HIZ SINIRLAMALI) TARAMA — UZUN UFUK ======
 * Sorun: 10 sn'lik tumbling pencere yalnız PATLAMA taramayı görür; hız
 * sınırlı tarama (nmap --scan-delay 2s) pencereye 5-6 farklı port bırakıp
 * hiçbir eşiği dolduramaz. Çözüm: kısa pencere korunur, yanına aktivite
 * boşluğu ile kapanan bağımsız UZUN UFUK eklenir (Zeek flow timeout / Snort
 * sfPortscan / Suricata threshold+timeout yaklaşımı).
 * Çift raporlama yok: kısa pencere aynı ufukta tetiklendiyse uzun ufuk susar;
 * gözlem süresi IDS_SCAN_MIN_SPAN_SEC'i geçmelidir. Eşik LONG_UNIQUE=24
 * (8 port/10 sn'lik hızın 300 sn'ye yayılmış karşılığı). */
#define IDS_SCAN_IDLE_GAP_SEC    30    /* son paketten sonra ufuk kapanışı (sn) */
#define IDS_SCAN_LONG_WINDOW_SEC 300   /* uzun ufuk azami ömrü (sn) */
#define IDS_SCAN_MIN_SPAN_SEC    15    /* "yavaş" sayılmak için min gözlem (sn) */
#define IDS_SCAN_LONG_UNIQUE     24    /* uzun ufukta farklı değer eşiği */

/* ========== LAN katmanı sabitleri ========== */
#define IDS_MAX_HOSTS          128     /* Tehdit Haritası host kapasitesi */
#define IDS_MAX_FLOWS          1024    /* akış tablosu kapasitesi */
#define IDS_FLOW_TIMEOUT       120     /* akış pasif kalınca düşme süresi (sn) */
#define IDS_HOST_TIMEOUT       600     /* host son görülmeden düşme süresi (sn) */

/* Host tehdit bayrakları (IDS_F_*) */
#define IDS_F_SCAN       (1u << 0)     /* port taraması */
#define IDS_F_SWEEP      (1u << 1)     /* ağ taraması / ping sweep */
#define IDS_F_BRUTEFORCE (1u << 2)     /* brute force */
#define IDS_F_FLOOD      (1u << 3)     /* flood / DDoS */
#define IDS_F_MALWARE    (1u << 4)     /* kötü amaçlı yazılım / exploit */
#define IDS_F_ARPSPOOF   (1u << 5)     /* ARP zehirlenmesi / spoof */
#define IDS_F_DNS        (1u << 6)     /* DNS anomalisi */
#define IDS_F_TUNNEL     (1u << 7)     /* DNS tunel / DGA (C2) */

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
    int         status;         /* IDS_ALERT_STATUS_* (SOC v3 triyaj) */
    char        note[256];      /* analist notu (SOC v3 triyaj) */
    int         port_owner_attacker; /* port sahibi saldirgandir (Meterpreter vb.) */
    /* ---  Risk skoru sistemi --- */
    uint8_t     confidence;     /* 0-100: çok düşük kanıt (0) -> kesinleşmiş tehdit (100) */
    uint8_t     evidence_bits;  /* IDS_EV_* bitleri: hangi kanıtlar birikti */
    char        fp_reason[64];  /* muhtemel false positive ise nedeni */
} IdsGuiAlert;

/* ---  Kanıt bitleri (IDS_EV_*) --- */
#define IDS_EV_THRESHOLD_MET   (1u << 0)  /* eşik aşıldı */
#define IDS_EV_HANDSHAKE_SEEN  (1u << 1)  /* TCP handshake tamamlandı */
#define IDS_EV_REPEATED        (1u << 2)  /* birden fazla kez görüldü */
#define IDS_EV_MULTI_PORT      (1u << 3)  /* çok porta yayıldı */
#define IDS_EV_PAYLOAD_MATCH   (1u << 4)  /* payload imzası eşleşti */
#define IDS_EV_EXTERNAL_SRC    (1u << 5)  /* kaynak internet'ten (daha ciddi) */
#define IDS_EV_KNOWN_BAD_PORT  (1u << 6)  /* bilinen kötü amaçlı port */

/* SOC v3 triyaj durumlari */
#define IDS_ALERT_STATUS_NEW       0   /* yeni, incelenmedi */
#define IDS_ALERT_STATUS_REVIEWING 1   /* analist incelemesinde */
#define IDS_ALERT_STATUS_ACK       2   /* kabul edildi / mudahale edildi */
#define IDS_ALERT_STATUS_FALSEPOS  3   /* yanlis pozitif */

/* ========== LAN katmanı: host tehdit kaydı ========== */
typedef struct {
    char        ip[46];             /* okunabilir IP */
    char        hostname[64];       /* DHCP/mDNS/NetBIOS'tan ogrenilen ad */
    uint32_t    ip_raw;             /* ham IP (karşılaştırma için) */
    int         is_gateway;         /* ağ geçidi mi */
    int         is_local;           /* bu makine mi */
    uint32_t    attack_score;       /* 0-100 saldırı skoru */
    uint32_t    victim_score;       /* 0-100 kurban skoru */
    uint64_t    total_sent;         /* gönderilen paket */
    uint64_t    total_recv;         /* alınan paket */
    uint32_t    flows_as_src;       /* kaynak olduğu akış sayısı */
    uint32_t    flows_as_dst;       /* hedef olduğu akış sayısı */
    uint32_t    unique_target_ips;  /* dokunduğu farklı hedef IP */
    uint32_t    unique_target_ports;/* dokunduğu farklı hedef port */
    uint32_t    flags;              /* IDS_F_* bitleri */
    char        top_victim_ip[46];  /* en çok paket gönderdiği hedef */
    char        top_attacker_ip[46];/* en çok paket aldığı kaynak */
    time_t      last_seen;
    char        status[24];         /* TEMIZ / SUPHELI / SALDIRGAN / KRITIK SALDIRGAN */
} IdsHostThreat;

/* GUI için host tehdit anlık görüntüsü (skora göre sıralı) */
typedef struct {
    int         count;              /* aktif host sayısı */
    int         total_flows;        /* aktif akış sayısı */
    time_t      window_start;
    IdsHostThreat hosts[IDS_MAX_HOSTS];
} IdsHostThreatSnapshot;

/* ========== IDS durumu (GUI erişimi için global) ========== */
typedef struct {
    int         running;
    int         rule_count;         /* aktif kural sayısı */
    uint64_t    total_pkts_processed;
    uint64_t    total_alerts;
    int         active_trackers;    /* anlık takip edilen akış sayısı */
    uint32_t    active_flows;       /* LAN katmanı: aktif akış sayısı */
    uint32_t    host_count;         /* LAN katmanı: izlenen host sayısı */
    uint32_t    incident_count;     /* SOC v3: korelasyonlu olay sayısı */
    /* ---  Adaptif cooldown & dedup --- */
    uint64_t    suppressed_fps;     /* bastırılan false positive uyarı sayısı */
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

/* Tek bir uyariyi dizinden sil (GUI satir bazli silme; 1=basarili) */
int  ids_remove_alert(int index);

/* MAC/IP bağlamı: ARP zehirlenmesi tespiti ve self-origin uyari
 * bastirmasi icin gateway/kendi MAC ve yerel IP bilgisi */
void ids_set_mac_context(const char *local_mac, const char *gateway_mac,
                         const char *gateway_ip, const char *local_ip);

/* ========== LAN katmanı API ========== */
/* Tehdit Haritası: aktif hostları saldırı skoruna göre sıralı kopyalar */
int  ids_get_host_threat_snapshot(IdsHostThreatSnapshot *out);
/* Akış tablosu + host skorlarını sıfırlar */
void ids_clear_host_data(void);
/* Kapsam CIDR'i: "192.168.1.0/24" — verilmezse özel ağ aralıkları kullanılır */
void ids_set_network_range(const char *cidr);

/* ========== İzleme kapsamı API ==========
 * GUI'deki izleme listesinin motor kopyası. Boş = hiçbir paket işlenmez;
 * dolu = yalnız listedeki IP'lere ait paketler işlenir. */
#define IDS_SCOPE_MAX 128
void ids_scope_set(const char *ips[], int n);
void ids_scope_clear(void);

/* ===== Uzun ufuk (yavaş tarama) kalibrasyon kancası ======
 * Yalnızca testlerin boşluk-sıfırlama ve min gözlem süresini gerçek zamanda
 * beklemeden kanıtlaması içindir; üretimde header sabitleri kullanılır.
 * 0/negatif verilen alan DEĞİŞTİRİLMEZ (kısmi güncelleme güvenli). */
void ids_set_scan_window_params(int idle_gap_sec, int max_window_sec,
                                int min_span_sec, int long_unique_thr);
void ids_get_scan_window_params(int *idle_gap_sec, int *max_window_sec,
                                int *min_span_sec, int *long_unique_thr);

/* ========== SOC v3: korelasyonlu olay + triyaj API ========== */
typedef struct {
    char        attacker_ip[46];
    char        victim_ip[46];
    uint32_t    alert_count;        /* çiftteki toplam uyarı */
    uint32_t    flags;              /* IDS_F_* birleşimi */
    int         killchain;          /* 1=keşif 2=sızma 3=C2/etki */
    char        worst_severity[16];
    double      max_score;
    char        last_sig[64];
    time_t      first_seen;
    time_t      last_seen;
} IdsIncident;

int  ids_get_incidents_snapshot(IdsIncident *out, int max_count);
int  ids_set_alert_status(int index, int status);
int  ids_set_alert_note(int index, const char *note);

#endif /* NETWORK_IDS_H */






