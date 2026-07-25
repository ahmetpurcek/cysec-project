/*
 * pcap_agent.h — PCAP Tabanlı Ağ Tehdit Algılama Ajanı
 * 
 * pcap_files/ dizinindeki pcap dosyalarından saldırı imzaları çıkarır,
 * canlı ağ trafiğini dinleyip eşleşme ve anomali tespiti yapar.
 * 
 * Linux + Windows desteği.
 */
#ifndef PCAP_AGENT_H
#define PCAP_AGENT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <math.h>
#include <dirent.h>
#include <signal.h>

#ifdef _WIN32
    #include <winsock2.h>
    #include <windows.h>
    #include <pcap.h>
    #include <iphlpapi.h>
    #pragma comment(lib, "wpcap.lib")
    #pragma comment(lib, "ws2_32.lib")
    #pragma comment(lib, "iphlpapi.lib")
#else
    #include <pcap/pcap.h>
    #include <unistd.h>
    #include <arpa/inet.h>
    #include <net/ethernet.h>
    #include <netinet/ip.h>
    #include <netinet/tcp.h>
    #include <netinet/udp.h>
    #include <netinet/ip_icmp.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <errno.h>
#endif

/* ---------- sabitler ---------- */
#define PA_MAX_SIGNATURES       4096
#define PA_MAX_FLOWS            131072
#define PA_BURST_LEN            100000
#define PA_FEATURE_DIM          16
#define PA_PCAP_DIR             "pcap_files"
#define PA_SIG_FILE             "agent_signatures.dat"
#define PA_ETH_ALEN             6

/* ---------- feature vektörü (16 boyut) ---------- */
typedef struct {
    double      src_port_entropy;       /* kaynak port çeşitliliği        */
    double      dst_port_entropy;       /* hedef port çeşitliliği         */
    double      syn_rate;               /* saniyedeki SYN sayısı          */
    double      rst_rate;               /* saniyedeki RST sayısı          */
    double      pkt_size_mean;          /* ortalama paket boyutu          */
    double      pkt_size_std;           /* standart sapma                 */
    double      flow_count;             /* eşsiz akım sayısı              */
    double      byte_rate;              /* saniyedeki bayt sayısı         */
    double      unique_dst_ports;       /* eşsiz hedef port               */
    double      unique_src_ips;         /* eşsiz kaynak IP                */
    double      dns_query_len_mean;     /* DNS sorgu uzunluk ortalaması   */
    double      dns_query_count;        /* DNS sorgu sayısı               */
    double      icmp_ratio;             /* ICMP paket oranı               */
    double      tcp_window_mean;        /* TCP window ortalaması          */
    double      ttl_mean;               /* TTL ortalaması                 */
    double      payload_entropy;        /* payload entropisi              */
} pa_feature_t;

/* ---------- imza ---------- */
typedef struct {
    char            name[64];
    pa_feature_t    feat;
    double          threshold;
    uint32_t        match_count;
    time_t          first_seen;
    time_t          last_seen;
} pa_signature_t;

/* ---------- akım (flow) ---------- */
typedef struct {
    uint32_t    src_ip;
    uint32_t    dst_ip;
    uint16_t    src_port;
    uint16_t    dst_port;
    uint8_t     proto;
    uint64_t    packets;
    uint64_t    bytes;
    time_t      start;
    time_t      last;
    uint8_t     syn_seen;
    uint8_t     rst_seen;
} pa_flow_t;

/* ---------- olay (alert) ---------- */
typedef struct pa_alert_node {
    char        sig_name[64];
    char        src_ip_str[46];
    char        dst_ip_str[46];
    uint16_t    src_port;
    uint16_t    dst_port;
    time_t      ts;
    double      score;
    struct pa_alert_node *next;
} pa_alert_t;

/* ---------- GUI için flat alert snapshot ---------- */
#define PA_MAX_GUI_ALERTS   256

typedef struct {
    char        sig_name[64];
    char        src_ip[46];
    char        dst_ip[46];
    uint16_t    src_port;
    uint16_t    dst_port;
    char        timestamp[32];
    double      score;
    char        severity[16];       /* KRITIK, YUKSEK, ORTA, DUSUK */
} pa_gui_alert_t;

/* ---------- agent yapısı ---------- */
typedef struct {
    pa_signature_t  sigs[PA_MAX_SIGNATURES];
    int             sig_count;

    pa_flow_t      *flows;                  /* heap-allocated, MAX_FLOWS */
    int             flow_count;

    pa_alert_t     *alert_head;
    pa_alert_t     *alert_tail;
    int             alert_count;

    double        (*burst_features)[PA_FEATURE_DIM]; /* heap, BURST_LEN rows */
    int             burst_idx;
    int             burst_full;

    char            iface[64];
    int             running;
    pcap_t         *pcap_handle;

    /* istatistik */
    uint64_t        total_pkts_processed;
    uint64_t        total_bytes_processed;
    time_t          start_time;
} pa_agent_t;

/* ---------- API ---------- */
int  pa_agent_init          (pa_agent_t *a, const char *iface);
void pa_agent_destroy       (pa_agent_t *a);

int  pa_agent_load_pcaps    (pa_agent_t *a, const char *dir);
void pa_agent_train         (pa_agent_t *a);
void pa_agent_rescan_pcaps  (pa_agent_t *a, const char *dir);

int  pa_agent_save_sigs     (pa_agent_t *a, const char *path);
int  pa_agent_load_sigs     (pa_agent_t *a, const char *path);

void pa_agent_start_capture (pa_agent_t *a);
void pa_agent_stop_capture  (pa_agent_t *a);

void pa_agent_process_pkt   (pa_agent_t *a, const uint8_t *pkt,
                             int len, struct timeval *ts);
void pa_agent_classify      (pa_agent_t *a, pa_feature_t *fv,
                             const char *sip, const char *dip,
                             uint16_t sp, uint16_t dp, time_t ts);

void pa_agent_print_alerts  (pa_agent_t *a);
void pa_agent_free_alerts   (pa_agent_t *a);

/* ---------- GUI erişim ---------- */
/* Son PA_MAX_GUI_ALERTS alarmı flat array'e kopyalar, GUI'den güvenle okunabilir */
int  pa_agent_get_alerts_snapshot(pa_agent_t *a, pa_gui_alert_t *out, int max_count);

/* ---------- imza yönetimi ---------- */
void pa_add_signature       (pa_agent_t *a, pa_feature_t *fv, const char *name);

/* ---------- yardımcı ---------- */
void     pa_ip_to_str   (uint32_t ip, char *buf);
uint32_t pa_str_to_ip   (const char *str);
double   pa_calc_entropy (const uint8_t *data, int len);

/* Windows'ta usleep */
#ifdef _WIN32
    #define usleep(x) Sleep((x)/1000)
#endif

#endif /* PCAP_AGENT_H */