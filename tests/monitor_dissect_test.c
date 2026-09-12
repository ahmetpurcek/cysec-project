/*
 * monitor_dissect_test.c — network_monitor.c çerçeve çözümleme (dissect)
 * birim testleri: Ethernet/ARP/IPv4/UDP/TCP/IPv6/SLL ve yeni API korumaları.
 *
 * Derle & çalıştır (repo kökünden):
 *   gcc -std=gnu11 -Wall -Wextra -Iinclude tests/monitor_dissect_test.c \
 *       src/network_monitor.c src/platform.c src/network_ids.c \
 *       -lpthread -lpcap -o /tmp/mon_test && /tmp/mon_test
 */
#include "network_monitor.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

/* network_monitor.h pcap.h içermiyor: DLT sabitlerini güvenle tanımla */
#ifndef DLT_EN10MB
#define DLT_EN10MB 1
#endif
#ifndef DLT_LINUX_SLL
#define DLT_LINUX_SLL 113
#endif

static int g_total = 0;
static int g_failed = 0;

#define CHECK(cond, ...)                                                     \
    do {                                                                     \
        g_total++;                                                           \
        if (cond) {                                                          \
            printf("  PASS  %s:%d\n", __FILE__, __LINE__);                   \
        } else {                                                             \
            g_failed++;                                                      \
            printf("  FAIL  %s:%d  ", __FILE__, __LINE__);                   \
            printf(__VA_ARGS__);                                             \
            printf("\n");                                                    \
        }                                                                    \
    } while (0)

#define CHECK_STR(actual, expected)                                          \
    CHECK(strcmp((actual), (expected)) == 0,                                 \
          "beklenen \"%s\" alinan \"%s\"", (expected), (actual))

/* ---------------- Çerçeve kurucular ---------------- */

static void mac_set(uint8_t *d, int a, int b, int c, int e, int f, int g) {
    d[0] = (uint8_t)a; d[1] = (uint8_t)b; d[2] = (uint8_t)c;
    d[3] = (uint8_t)e; d[4] = (uint8_t)f; d[5] = (uint8_t)g;
}

static void ip4_set(uint8_t *d, int a, int b, int c, int e) {
    d[0] = (uint8_t)a; d[1] = (uint8_t)b; d[2] = (uint8_t)c; d[3] = (uint8_t)e;
}

/* Ethernet + ARP reply: 42 bayt (14 + 28) */
static size_t build_eth_arp(uint8_t *f) {
    mac_set(f + 0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66); /* dst */
    mac_set(f + 6, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF); /* src */
    f[12] = 0x08; f[13] = 0x06;                          /* ARP */
    uint8_t *a = f + 14;
    a[0] = 0x00; a[1] = 0x01;                            /* htype ethernet */
    a[2] = 0x08; a[3] = 0x00;                            /* ptype IPv4 */
    a[4] = 0x06; a[5] = 0x04;                            /* hlen/plen */
    a[6] = 0x00; a[7] = 0x02;                            /* op: reply */
    mac_set(a + 8, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF);  /* sha */
    ip4_set(a + 14, 192, 168, 1, 50);                    /* spa */
    mac_set(a + 18, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66); /* tha */
    ip4_set(a + 24, 192, 168, 1, 1);                     /* tpa */
    return 42;
}

/* Ethernet + IPv4 + UDP (binary güdümlü yük, "UDP" protokolü korunmalı): 82 bayt */
static size_t build_eth_udp_bait(uint8_t *f) {
    mac_set(f + 0, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
    mac_set(f + 6, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF);
    f[12] = 0x08; f[13] = 0x00;                          /* IPv4 */
    uint8_t *ip = f + 14;
    ip[0] = 0x45;
    ip[2] = 0x00; ip[3] = 0x44;                          /* total_len 68 */
    ip[8] = 64;                                          /* ttl */
    ip[9] = 17;                                          /* UDP */
    ip4_set(ip + 12, 192, 168, 1, 50);
    ip4_set(ip + 16, 8, 8, 8, 8);
    uint8_t *u = f + 34;
    u[0] = 0x75; u[1] = 0x30;                            /* sport 30000 */
    u[2] = 0x27; u[3] = 0x0F;                            /* dport 9999 */
    u[4] = 0x00; u[5] = 0x30;                            /* ulen 48 */
    uint8_t *p = f + 42;                                 /* 40 bayt yük */
    memset(p, 0, 40);
    p[12] = 0x08; p[13] = 0x00; p[14] = 0x45;            /* iç IPv4 başlık taklidi */
    p[23] = 99;                                          /* 'c' */
    p[30] = 9; p[31] = 9; p[32] = 9; p[33] = 9;          /* 9.9.9.9 */
    return 82;
}

/* Ethernet + IPv4 + TCP SYN: 54 bayt (yüksüz) */
static size_t build_eth_tcp_syn(uint8_t *f) {
    mac_set(f + 0, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
    mac_set(f + 6, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF);
    f[12] = 0x08; f[13] = 0x00;
    uint8_t *ip = f + 14;
    ip[0] = 0x45;
    ip[2] = 0x00; ip[3] = 0x28;                          /* total_len 40 */
    ip[8] = 64;
    ip[9] = 6;                                           /* TCP */
    ip4_set(ip + 12, 192, 168, 1, 50);
    ip4_set(ip + 16, 192, 168, 1, 1);
    uint8_t *t = f + 34;
    t[0] = 0x9C; t[1] = 0x40;                            /* sport 40000 */
    t[2] = 0x27; t[3] = 0x0F;                            /* dport 9999 */
    t[4] = 0x00; t[5] = 0x00; t[6] = 0x00; t[7] = 0x01;  /* seq 1 */
    t[8] = 0; t[9] = 0; t[10] = 0; t[11] = 0;            /* ack 0 */
    t[12] = 0x50; t[13] = 0x02;                          /* doff=5, SYN */
    return 54;
}

/* Ethernet + IPv6 + UDP: 74 bayt (14 + 40 + 8 + 12) */
static size_t build_eth_ipv6_udp(uint8_t *f) {
    mac_set(f + 0, 0x33, 0x33, 0x00, 0x00, 0x00, 0x02);
    mac_set(f + 6, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF);
    f[12] = 0x86; f[13] = 0xDD;                          /* IPv6 */
    uint8_t *ip = f + 14;
    ip[0] = 0x60;                                        /* ver 6 */
    ip[4] = 0x00; ip[5] = 0x14;                          /* payload_len 20 */
    ip[6] = 17;                                          /* next hdr UDP */
    ip[7] = 64;                                          /* hop limit */
    ip[8]  = 0xFE; ip[9]  = 0x80;                        /* src fe80::1 */
    ip[24] = 0xFE; ip[25] = 0x80;                        /* dst fe80::2 */
    ip[39] = 0x02;
    uint8_t *u = f + 54;
    u[0] = 0x15; u[1] = 0xB3;                            /* sport 5555 */
    u[2] = 0x1A; u[3] = 0x0A;                            /* dport 6666 */
    u[4] = 0x00; u[5] = 0x14;                            /* ulen 20 */
    memset(f + 62, 0, 12);                               /* 12 bayt yük */
    return 74;
}

/* Linux SLL + ARP reply: 44 bayt (16 + 28) — 'any' arayüzü biçimi */
static size_t build_sll_arp(uint8_t *f) {
    f[0] = 0x00; f[1] = 0x00;                            /* pkttype: bize unicast */
    f[2] = 0x00; f[3] = 0x01;                            /* hatype ethernet */
    f[4] = 0x00; f[5] = 0x06;                            /* addrlen 6 */
    mac_set(f + 6, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF);  /* addr */
    f[12] = 0x00; f[13] = 0x00;
    f[14] = 0x08; f[15] = 0x06;                          /* ethertype ARP */
    uint8_t *a = f + 16;
    a[0] = 0x00; a[1] = 0x01;
    a[2] = 0x08; a[3] = 0x00;
    a[4] = 0x06; a[5] = 0x04;
    a[6] = 0x00; a[7] = 0x02;                            /* reply */
    mac_set(a + 8, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF);
    ip4_set(a + 14, 192, 168, 1, 50);
    mac_set(a + 18, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66);
    ip4_set(a + 24, 192, 168, 1, 1);
    return 44;
}

/* ---------------- Testler ---------------- */

static void test_ethernet_arp(void) {
    printf("== Ethernet ARP reply ==\n");
    uint8_t f[128];
    size_t n = build_eth_arp(f);
    PacketRecord pr;
    CHECK(full_monitor_dissect_frame(DLT_EN10MB, f, (int)n, &pr) == 1,
          "dissect_frame ret");
    CHECK_STR(pr.protocol, "ARP");
    CHECK_STR(pr.src_ip, "192.168.1.50");
    CHECK_STR(pr.dst_ip, "192.168.1.1");
    CHECK_STR(pr.src_mac, "aa:bb:cc:dd:ee:ff");
    CHECK_STR(pr.dst_mac, "11:22:33:44:55:66");
    CHECK(strstr(pr.info, "192.168.1.50 is at aa:bb:cc:dd:ee:ff") != NULL,
          "ARP info beklenen dize yok: \"%s\"", pr.info);
    CHECK(strstr(pr.layers[1].fields, "Opcode: Reply (2)") != NULL,
          "ARP fields opcode yok");
    CHECK(pr.layer_count == 2, "layer_count=%d beklenen 2", pr.layer_count);
    CHECK(pr.length == (int)n, "length=%d beklenen %d", pr.length, (int)n);
    CHECK(pr.raw_len == (int)n, "raw_len=%d beklenen %d", pr.raw_len, (int)n);
    CHECK(pr.timestamp > 0, "timestamp=%f", pr.timestamp);
}

static void test_ethernet_udp_binary_payload(void) {
    printf("== Ethernet IPv4 UDP (binary yük) ==\n");
    uint8_t f[128];
    size_t n = build_eth_udp_bait(f);
    PacketRecord pr;
    CHECK(full_monitor_dissect_frame(DLT_EN10MB, f, (int)n, &pr) == 1,
          "dissect_frame ret");
    CHECK_STR(pr.protocol, "UDP");          /* raw_text binary'i atlamalı */
    CHECK_STR(pr.src_ip, "192.168.1.50");
    CHECK_STR(pr.dst_ip, "8.8.8.8");
    CHECK_STR(pr.src_port, "30000");
    CHECK_STR(pr.dst_port, "9999");
    CHECK(strstr(pr.info, "30000 → 9999 Len=48") != NULL,
          "UDP info beklenen dize yok: \"%s\"", pr.info);
    CHECK(pr.ttl == 64, "ttl=%d", pr.ttl);
    CHECK(pr.layer_count == 3, "layer_count=%d beklenen 3 (ETH/IPv4/UDP)",
          pr.layer_count);
    CHECK(pr.layers[1].type == LAYER_IPV4, "2. katman IPv4 olmalı");
    CHECK(pr.layers[2].type == LAYER_UDP, "3. katman UDP olmalı");
    CHECK(pr.length == (int)n, "length=%d beklenen %d", pr.length, (int)n);
    CHECK(pr.raw_len == (int)n, "raw_len=%d beklenen %d", pr.raw_len, (int)n);
    CHECK(memcmp(pr.raw_data, f, n) == 0, "raw_data kopyası bozuk");
}

static void test_ethernet_tcp_syn(void) {
    printf("== Ethernet IPv4 TCP SYN ==\n");
    uint8_t f[128];
    size_t n = build_eth_tcp_syn(f);
    PacketRecord pr;
    CHECK(full_monitor_dissect_frame(DLT_EN10MB, f, (int)n, &pr) == 1,
          "dissect_frame ret");
    CHECK_STR(pr.protocol, "TCP");
    CHECK_STR(pr.src_port, "40000");
    CHECK_STR(pr.dst_port, "9999");
    CHECK(strstr(pr.flags, "SYN") != NULL, "flags SYN içermiyor: \"%s\"", pr.flags);
    CHECK(strstr(pr.info, "40000 → 9999") != NULL, "TCP info yok: \"%s\"", pr.info);
    CHECK(pr.layer_count == 3, "layer_count=%d beklenen 3", pr.layer_count);
    CHECK(pr.layers[2].type == LAYER_TCP, "3. katman TCP olmalı");
}

static void test_ethernet_ipv6_udp(void) {
    printf("== Ethernet IPv6 UDP ==\n");
    uint8_t f[128];
    size_t n = build_eth_ipv6_udp(f);
    PacketRecord pr;
    CHECK(full_monitor_dissect_frame(DLT_EN10MB, f, (int)n, &pr) == 1,
          "dissect_frame ret");
    CHECK_STR(pr.protocol, "UDP");
    CHECK(strncmp(pr.src_ip, "fe80", 4) == 0, "src_ip IPv6 değil: \"%s\"", pr.src_ip);
    CHECK(strncmp(pr.dst_ip, "fe80", 4) == 0, "dst_ip IPv6 değil: \"%s\"", pr.dst_ip);
    CHECK_STR(pr.src_port, "5555");
    CHECK_STR(pr.dst_port, "6666");
    CHECK(pr.ttl == 64, "hop limit=%d", pr.ttl);
    CHECK(pr.layer_count == 3, "layer_count=%d beklenen 3 (ETH/IPv6/UDP)",
          pr.layer_count);
    CHECK(pr.layers[1].type == LAYER_IPV6, "2. katman IPv6 olmalı");
}

static void test_sll_arp(void) {
    printf("== Linux SLL + ARP reply ==\n");
    uint8_t f[128];
    size_t n = build_sll_arp(f);
    PacketRecord pr;
    CHECK(full_monitor_dissect_frame(DLT_LINUX_SLL, f, (int)n, &pr) == 1,
          "dissect_frame ret");
    CHECK_STR(pr.protocol, "ARP");          /* çifte dissect hatasını regresyondan koru */
    CHECK_STR(pr.src_mac, "aa:bb:cc:dd:ee:ff");
    CHECK_STR(pr.dst_mac, "(us)");
    CHECK_STR(pr.layers[0].name, "Linux Cooked Capture");
    CHECK(pr.layer_count == 2, "layer_count=%d beklenen 2 (SLL/ARP)", pr.layer_count);
    CHECK(pr.length == (int)n, "length=%d beklenen %d", pr.length, (int)n);
    CHECK(pr.raw_len == (int)n, "raw_len=%d beklenen %d", pr.raw_len, (int)n);
}

static void test_guards(void) {
    printf("== Girdi korumaları ==\n");
    uint8_t f[128];
    size_t n = build_eth_arp(f);
    PacketRecord pr;
    int ret;

    ret = full_monitor_dissect_frame(DLT_EN10MB, NULL, (int)n, &pr);
    CHECK(ret == 0, "NULL data ret=%d", ret);
    ret = full_monitor_dissect_frame(DLT_EN10MB, f, 0, &pr);
    CHECK(ret == 0, "caplen=0 ret=%d", ret);
    ret = full_monitor_dissect_frame(DLT_EN10MB, f, (int)n, NULL);
    CHECK(ret == 0, "NULL out ret=%d", ret);

    /* Kısa çerçeve: dissect edilemez ama varsayılan ETH etiketi konmalı */
    ret = full_monitor_dissect_frame(DLT_EN10MB, f, 13, &pr);
    CHECK(ret == 1, "13B çerçeve ret=%d", ret);
    CHECK_STR(pr.protocol, "ETH");
    CHECK(pr.length == 13, "length=%d", pr.length);
    CHECK(pr.raw_len == 13, "raw_len=%d", pr.raw_len);
}

static void test_api_guards(void) {
    printf("== Yeni API korumaları (init sonrası, handle yok) ==\n");
    char buf[64];

    int r = full_monitor_pcap_record_start("/tmp/x.pcap");
    CHECK(r == -1, "record_start handle yokken -1 olmali, alinan %d", r);
    CHECK(full_monitor_pcap_record_is_active() == 0, "is_active=0 olmali");
    buf[0] = 'X';
    full_monitor_pcap_record_path(buf, sizeof(buf));
    CHECK(buf[0] == '\0', "path bos olmali");
    CHECK(full_monitor_pcap_record_bytes() == 0, "bytes=0 olmali");
    full_monitor_pcap_record_stop();        /* guvenli no-op olmali */
    CHECK(full_monitor_pcap_record_is_active() == 0, "stop sonrasi is_active=0");

    r = full_monitor_own_mac(NULL, 0);
    CHECK(r == -1, "own_mac(NULL,0) -> -1, alinan %d", r);
    buf[0] = 'X';
    r = full_monitor_own_mac(buf, sizeof(buf));
    CHECK(r == -1, "own_mac bilinmiyorken -1 olmali, alinan %d", r);
    CHECK(buf[0] == '\0', "own_mac cikisi bos olmali");

    CHECK(full_monitor_get_foreign_frame_count() == 0, "foreign=0");
    CHECK(full_monitor_mirror_suspected() == 0, "mirror=0");

    char slots[512];
    r = full_monitor_activity_slots(slots, sizeof(slots));
    CHECK(r == 0, "activity_slots=0, alinan %d", r);
    CHECK(slots[0] == '\0', "slots bos olmali");
    r = full_monitor_activity_slots(NULL, 0);
    CHECK(r == 0, "activity_slots(NULL,0)=0, alinan %d", r);

    CHECK(full_monitor_device_active("192.168.1.50", NULL, 10.0) == 0,
          "device_active=0 olmali");

    double seen = arp_spoof_target_last_seen("192.168.1.50");
    CHECK(seen == -1.0, "last_seen=-1.0 olmali, alinan %f", seen);
}

int main(void) {
    printf("== monitor_dissect_test.c ==\n");
    full_monitor_init();

    test_guards();
    test_ethernet_arp();
    test_ethernet_udp_binary_payload();
    test_ethernet_tcp_syn();
    test_ethernet_ipv6_udp();
    test_sll_arp();
    test_api_guards();

    full_monitor_cleanup();

    printf("\nTOPLAM: %d, BAŞARISIZ: %d\n", g_total, g_failed);
    return g_failed ? 1 : 0;
}
