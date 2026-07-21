/*
 * full_monitor.h — Full Packet Capture Engine (Wireshark-style)
 */
#ifndef NETWORK_MONITOR_H
#define NETWORK_MONITOR_H

#include "platform.h"

#define MAX_RAW_SIZE    256
#define MAX_LAYERS      10



typedef enum {
    LAYER_ETHERNET, LAYER_ARP, LAYER_IPV4, LAYER_IPV6,
    LAYER_TCP, LAYER_UDP, LAYER_ICMP,
    LAYER_DNS, LAYER_HTTP, LAYER_TLS, LAYER_DHCP,
    LAYER_MDNS, LAYER_LLMNR, LAYER_NETBIOS, LAYER_SSDP,
    LAYER_NTP, LAYER_SNMP, LAYER_SYSLOG, LAYER_TFTP,
    LAYER_STUN, LAYER_MYSQL, LAYER_POSTGRES, LAYER_REDIS,
    LAYER_MONGODB, LAYER_SSH, LAYER_FTP, LAYER_SMTP,
    LAYER_POP3, LAYER_IMAP, LAYER_RDP, LAYER_VNC,
    LAYER_DATA, LAYER_UNKNOWN
} PduLayerType;

typedef struct {
    PduLayerType type;
    char name[32];
    char summary[256];
    int offset;
    int length;
    char fields[1024];
} PduLayer;

typedef struct {
    double timestamp;
    int packet_number;
    char src_ip[MAX_IP_LEN];
    char dst_ip[MAX_IP_LEN];
    char src_mac[MAX_MAC_LEN];
    char dst_mac[MAX_MAC_LEN];
    char src_port[8];
    char dst_port[8];
    char protocol[32];
    char flags[32];
    char info[512];
    int length;
    int ttl;
    PduLayer layers[MAX_LAYERS];
    int layer_count;
    unsigned char raw_data[MAX_RAW_SIZE];
    int raw_len;
} PacketRecord;

typedef struct {
    int total;
    int tcp;
    int udp;
    int icmp;
    int arp;
    int dns;
    int http;
    int tls;
    int dhcp;
    int mdns;
} FullStats;

void full_monitor_init(void);
void full_monitor_cleanup(void);
void full_monitor_start(const char *iface);
void full_monitor_stop(void);
int  full_monitor_get_packets(PacketRecord *out, int max_count, int offset);
int  full_monitor_get_filtered(PacketRecord *out, int max_count, const char *filter_proto);
void full_monitor_get_stats(FullStats *s);

/* Yardımcı */
const char *svc_name(int port);
const char *ip_proto_name(int proto);

/* ===== ARP Spoof (MITM trafik yakalama) ===== */
void arp_spoof_start(const char *target_ip, const char *gateway_ip, const char *iface);
void arp_spoof_stop(void);
int  arp_spoof_is_running(void);
const char *arp_spoof_get_target(void);
void enable_ip_forward(void);
void disable_ip_forward(void);

#endif /* NETWORK_MONITOR_H */