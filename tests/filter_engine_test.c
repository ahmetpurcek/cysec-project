/*
 * filter_engine_test.c — filter_engine.c birim testleri.
 *
 * Derle & çalıştır (repo kökünden):
 *   gcc -std=c11 -Wall -Wextra -Iinclude tests/filter_engine_test.c \
 *       src/filter_engine.c -o /tmp/filter_test && /tmp/filter_test
 */
#include "filter_engine.h"

#include <stdio.h>
#include <string.h>

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

/* ---------------- Test paketleri ---------------- */

static void pkt_zero(PacketRecord *p) {
    memset(p, 0, sizeof(*p));
    p->src_ip[0] = '\0';
    p->dst_ip[0] = '\0';
    p->src_mac[0] = '\0';
    p->dst_mac[0] = '\0';
    p->src_port[0] = '\0';
    p->dst_port[0] = '\0';
    p->protocol[0] = '\0';
    p->info[0] = '\0';
}

static void set_str(char *dst, size_t cap, const char *s) {
    snprintf(dst, cap, "%s", s);
}

static void add_layer(PacketRecord *p, PduLayerType t, const char *name) {
    if (p->layer_count >= MAX_LAYERS) return;
    p->layers[p->layer_count].type = t;
    set_str(p->layers[p->layer_count].name,
            sizeof(p->layers[p->layer_count].name), name);
    p->layer_count++;
}

/* TCP/TLS paketi: 192.168.1.10 -> 8.8.8.8:443, MAC'ler dolu. */
static PacketRecord pkt_tcp(void) {
    PacketRecord p;
    pkt_zero(&p);
    p.packet_number = 1;
    set_str(p.src_ip, sizeof(p.src_ip), "192.168.1.10");
    set_str(p.dst_ip, sizeof(p.dst_ip), "8.8.8.8");
    set_str(p.src_mac, sizeof(p.src_mac), "AA:BB:CC:DD:EE:01");
    set_str(p.dst_mac, sizeof(p.dst_mac), "00:11:22:33:44:55");
    set_str(p.src_port, sizeof(p.src_port), "54321");
    set_str(p.dst_port, sizeof(p.dst_port), "443");
    set_str(p.protocol, sizeof(p.protocol), "TCP");
    set_str(p.info, sizeof(p.info),
            "Client Hello SNI=alpha.example.com TLSv1.3");
    add_layer(&p, LAYER_ETHERNET, "Ethernet");
    add_layer(&p, LAYER_IPV4, "IPv4");
    add_layer(&p, LAYER_TCP, "TCP");
    add_layer(&p, LAYER_TLS, "TLS");
    return p;
}

/* UDP/DNS paketi: 10.0.0.5:5353 -> 192.168.1.1:53. */
static PacketRecord pkt_udp(void) {
    PacketRecord p;
    pkt_zero(&p);
    p.packet_number = 2;
    set_str(p.src_ip, sizeof(p.src_ip), "10.0.0.5");
    set_str(p.dst_ip, sizeof(p.dst_ip), "192.168.1.1");
    set_str(p.src_mac, sizeof(p.src_mac), "AA:BB:CC:DD:EE:02");
    set_str(p.dst_mac, sizeof(p.dst_mac), "00:11:22:33:44:55");
    set_str(p.src_port, sizeof(p.src_port), "5353");
    set_str(p.dst_port, sizeof(p.dst_port), "53");
    set_str(p.protocol, sizeof(p.protocol), "UDP");
    set_str(p.info, sizeof(p.info), "Standard query A beta.example.com");
    add_layer(&p, LAYER_ETHERNET, "Ethernet");
    add_layer(&p, LAYER_IPV4, "IPv4");
    add_layer(&p, LAYER_UDP, "UDP");
    add_layer(&p, LAYER_DNS, "DNS");
    return p;
}

/* ARP paketi: IP'siz/portsuz. */
static PacketRecord pkt_arp(void) {
    PacketRecord p;
    pkt_zero(&p);
    p.packet_number = 3;
    set_str(p.src_mac, sizeof(p.src_mac), "AA:BB:CC:DD:EE:03");
    set_str(p.dst_mac, sizeof(p.dst_mac), "FF:FF:FF:FF:FF:FF");
    set_str(p.protocol, sizeof(p.protocol), "ARP");
    set_str(p.info, sizeof(p.info), "Who has 192.168.1.1? Tell 192.168.1.10");
    add_layer(&p, LAYER_ETHERNET, "Ethernet");
    add_layer(&p, LAYER_ARP, "ARP");
    return p;
}

/* ICMP paketi: bilgisi "and"/"or" sözcükleri içerir. */
static PacketRecord pkt_icmp(void) {
    PacketRecord p;
    pkt_zero(&p);
    p.packet_number = 4;
    set_str(p.src_ip, sizeof(p.src_ip), "192.168.1.10");
    set_str(p.dst_ip, sizeof(p.dst_ip), "192.168.1.1");
    set_str(p.src_mac, sizeof(p.src_mac), "AA:BB:CC:DD:EE:01");
    set_str(p.dst_mac, sizeof(p.dst_mac), "00:11:22:33:44:55");
    set_str(p.protocol, sizeof(p.protocol), "ICMP");
    set_str(p.info, sizeof(p.info), "Echo reply: send and receive ok");
    add_layer(&p, LAYER_ETHERNET, "Ethernet");
    add_layer(&p, LAYER_IPV4, "IPv4");
    add_layer(&p, LAYER_ICMP, "ICMP");
    return p;
}

/* Bir paketin bir listede tek başına eşleşip eşleşmediği */
static int one_match(const PacketRecord *p, const char *expr) {
    return filter_engine_packet_matches(p, expr);
}

/* ---------------- Testler ---------------- */

static void test_validity(void) {
    printf("[1] filter_engine_expr_valid\n");
    CHECK(filter_engine_expr_valid(NULL) == 1,
          "NULL ifade filtre yok sayilir (bos gibi)");
    CHECK(filter_engine_expr_valid("") == 1, "bos ifade gecerli");
    CHECK(filter_engine_expr_valid("   ") == 1, "bosluk ifade gecerli");
    CHECK(filter_engine_expr_valid("ip.src == 1.2.3.4") == 1, "basit esitlik");
    CHECK(filter_engine_expr_valid("IP.SRC == 1.2.3.4") == 1, "buyuk harf");
    CHECK(filter_engine_expr_valid("ip.src == 1.2.3.4 and tcp.port == 80") == 1,
          "and ayraci");
    CHECK(filter_engine_expr_valid("tcp.port == 80 or udp.port == 53") == 1,
          "or ayraci");
    CHECK(filter_engine_expr_valid("tcp.port == 80 || udp.port == 53") == 1,
          "|| ayraci");
    CHECK(filter_engine_expr_valid("tcp.port == 80 && udp.port == 53") == 1,
          "&& ayraci");
    CHECK(filter_engine_expr_valid("info contains \"send and receive\"") == 1,
          "tirnakli contains");
    CHECK(filter_engine_expr_valid("info contains send and receive") == 1,
          "tirnaksiz contains");
    CHECK(filter_engine_expr_valid("dns") == 1, "ciblak sozcuk");
    CHECK(filter_engine_expr_valid("443") == 1, "ciblak port");
    CHECK(filter_engine_expr_valid("192.168.1.10") == 1, "ciblak ip");
    CHECK(filter_engine_expr_valid("proto == TLS") == 1, "proto TLS");
    CHECK(filter_engine_expr_valid("eth.addr == aa:bb:cc:dd:ee:01") == 1,
          "mac esitligi");

    CHECK(filter_engine_expr_valid("bogus.field == 1") == 0,
          "bilinmeyen alan");
    CHECK(filter_engine_expr_valid("ip.src ==") == 0, "deger yok");
    CHECK(filter_engine_expr_valid("== 1.2.3.4") == 0, "alan yok");
    CHECK(filter_engine_expr_valid("and ip.src == 1.2.3.4") == 0,
          "basta ayrac");
    CHECK(filter_engine_expr_valid("ip.src == 1.2.3.4 and") == 0,
          "sonda ayrac");
    CHECK(filter_engine_expr_valid("ip.src == 1.2.3.4 and and tcp.port == 80") == 0,
          "art arda ayrac");
    CHECK(filter_engine_expr_valid("ip.src == 1.2.3.4 tcp.port") == 1,
          "bilesik deger (tasarim)");
    CHECK(filter_engine_expr_valid("ip.src == \"1.2.3.4") == 0,
          "dengesiz tirnak");
    CHECK(filter_engine_expr_valid("info == \"\"") == 0, "bos tirnakli deger");
    CHECK(filter_engine_expr_valid("tcp.port == abc") == 0,
          "port sayisal degil");
    CHECK(filter_engine_expr_valid("tcp.port == 65536") == 0,
          "port sinir disi");
    CHECK(filter_engine_expr_valid("udp.port == 53") == 1, "udp port gecerli");
    CHECK(filter_engine_expr_valid("ip.src < 1.2.3.4") == 0, "< desteklenmez");
    CHECK(filter_engine_expr_valid("(ip.src == 1.2.3.4)") == 0,
          "parantez desteklenmez");
    CHECK(filter_engine_expr_valid("!ip.src") == 0, "'!' on-eki desteklenmez");
}

static void test_empty_and_invalid_match(void) {
    printf("[2] bos/gecersiz ifade ile eslestirme\n");
    PacketRecord t = pkt_tcp();
    PacketRecord a = pkt_arp();

    CHECK(one_match(&t, "") == 1, "bos ifade her seyi eslestirir");
    CHECK(one_match(&a, "") == 1, "bos ifade her seyi eslestirir (arp)");
    CHECK(one_match(&t, "    ") == 1, "bosluk ifade filtrelemez");
    CHECK(one_match(&t, "ip.src ==") == 1,
          "gecersiz ifade listeyi bosaltmaz");
    CHECK(one_match(&t, "bogus.field == x") == 1,
          "gecersiz alan listeyi bosaltmaz");
    CHECK(one_match(&a, "and") == 1, "tek 'and' listeyi bosaltmaz");
    CHECK(filter_engine_packet_matches(NULL, "ip.src == 1.2.3.4") == 1,
          "NULL paket elemez");
    CHECK(filter_engine_packet_matches(NULL, NULL) == 1,
          "NULL paket + NULL ifade");
}

static void test_ip_fields(void) {
    printf("[3] ip alanlari\n");
    PacketRecord t = pkt_tcp();
    PacketRecord u = pkt_udp();
    PacketRecord a = pkt_arp();

    CHECK(one_match(&t, "ip.src == 192.168.1.10") == 1, "tcp ip.src");
    CHECK(one_match(&u, "ip.src == 192.168.1.10") == 0, "udp ip.src yanlis");
    CHECK(one_match(&a, "ip.src == 192.168.1.10") == 0, "arp ip.src yok");
    CHECK(one_match(&t, "ip.dst == 8.8.8.8") == 1, "tcp ip.dst");
    CHECK(one_match(&u, "ip.dst == 8.8.8.8") == 0, "udp ip.dst yanlis");
    CHECK(one_match(&t, "ip.addr == 192.168.1.10") == 1, "ip.addr kaynak");
    CHECK(one_match(&t, "ip.addr == 8.8.8.8") == 1, "ip.addr hedef");
    CHECK(one_match(&u, "ip.addr == 10.0.0.5") == 1, "ip.addr udp kaynak");
    CHECK(one_match(&t, "ip == 8.8.8.8") == 1, "ip kisa adi");
    CHECK(one_match(&u, "ip == 192.168.1.1") == 1, "ip udp hedef");

    CHECK(one_match(&t, "ip.src != 192.168.1.10") == 0,
          "ip.src != kaynak esitse ele");
    CHECK(one_match(&u, "ip.src != 192.168.1.10") == 1,
          "ip.src != farkliysa goster");
    CHECK(one_match(&a, "ip.src != 192.168.1.10") == 1,
          "ip.src != ip'siz paket goster (degilleme semantigi)");

    CHECK(one_match(&t, "ip.src contains 192.168") == 1, "ip.src contains");
    CHECK(one_match(&u, "ip.src contains 192.168") == 0, "ip.src contains yok");
    CHECK(one_match(&t, "IP.SRC == 192.168.1.10") == 1,
          "alan adi buyuk/kucuk harf duyarsiz");
}

static void test_mac_fields(void) {
    printf("[4] mac alanlari\n");
    PacketRecord t = pkt_tcp();
    PacketRecord a = pkt_arp();

    CHECK(one_match(&t, "eth.addr == AA:BB:CC:DD:EE:01") == 1,
          "eth.addr kaynak");
    CHECK(one_match(&t, "mac == 00:11:22:33:44:55") == 1, "mac hedef");
    CHECK(one_match(&t, "eth.src == aa:bb:cc:dd:ee:01") == 1,
          "eth.src kucuk harf deger");
    CHECK(one_match(&t, "mac.dst == 00:11:22:33:44:55") == 1, "mac.dst");
    CHECK(one_match(&t, "eth.dst == 00:11:22:33:44:55") == 1, "eth.dst");
    CHECK(one_match(&t, "mac.src == 00:11:22:33:44:55") == 0,
          "mac.src yanlis adres");
    CHECK(one_match(&a, "eth.addr == FF:FF:FF:FF:FF:FF") == 1,
          "arp broadcast hedef mac");
    CHECK(one_match(&t, "mac.addr == 00:11:22:33:44:55") == 1, "mac.addr");
    CHECK(one_match(&t, "eth.addr != AA:BB:CC:DD:EE:01") == 0,
          "eth.addr != esitse ele");
    CHECK(one_match(&t, "eth.addr contains BB:CC") == 1, "mac contains");
}

static void test_port_fields(void) {
    printf("[5] port alanlari\n");
    PacketRecord t = pkt_tcp();
    PacketRecord u = pkt_udp();
    PacketRecord a = pkt_arp();

    CHECK(one_match(&t, "tcp.port == 443") == 1, "tcp.port hedef");
    CHECK(one_match(&u, "tcp.port == 443") == 0,
          "udp paketinde tcp.port yok");
    CHECK(one_match(&u, "udp.port == 53") == 1, "udp.port hedef");
    CHECK(one_match(&t, "udp.port == 53") == 0,
          "tcp paketinde udp.port yok");
    CHECK(one_match(&u, "udp.srcport == 5353") == 1, "udp.srcport");
    CHECK(one_match(&u, "udp.sport == 5353") == 1, "udp.sport alias");
    CHECK(one_match(&t, "tcp.dstport == 443") == 1, "tcp.dstport");
    CHECK(one_match(&t, "tcp.dport == 443") == 1, "tcp.dport alias");
    CHECK(one_match(&t, "tcp.sport == 443") == 0, "tcp.sport yanlis port");
    CHECK(one_match(&t, "tcp.srcport == 54321") == 1, "tcp.srcport");

    CHECK(one_match(&t, "port == 443") == 1, "port hedef");
    CHECK(one_match(&u, "port == 53") == 1, "port udp hedef");
    CHECK(one_match(&u, "port == 5353") == 1, "port udp kaynak");
    CHECK(one_match(&a, "port == 443") == 0, "arp port yok");
    CHECK(one_match(&t, "port != 443") == 0,
          "port != hedef esitse ele (tcp)");
    CHECK(one_match(&u, "port != 443") == 1,
          "port != farkli port goster (udp)");

    /* degilleme: tasima katmani olmayan pakette "tcp.port != x" dogrudur
       (pozitif eslesmenin degili). */
    CHECK(one_match(&u, "tcp.port != 443") == 1,
          "tcp.port != udp paketinde goster (tasarim)");
    CHECK(one_match(&u, "tcp.port == 443") == 0, "tcp.port == udp yok");
}

static void test_proto_fields(void) {
    printf("[6] proto/protocol\n");
    PacketRecord t = pkt_tcp();
    PacketRecord u = pkt_udp();
    PacketRecord a = pkt_arp();

    CHECK(one_match(&t, "proto == tcp") == 1, "proto tcp (protocol alani)");
    CHECK(one_match(&u, "proto == tcp") == 0, "proto tcp udp'de yok");
    CHECK(one_match(&t, "proto == tls") == 1, "proto tls (layer)");
    CHECK(one_match(&u, "proto == dns") == 1, "proto dns (layer)");
    CHECK(one_match(&t, "proto == dns") == 0, "proto dns tcp'de yok");
    CHECK(one_match(&a, "proto == arp") == 1, "proto arp");
    CHECK(one_match(&a, "proto == tcp") == 0, "proto tcp arp'de yok");
    CHECK(one_match(&t, "protocol == TCP") == 1,
          "protocol buyuk harf deger");
    CHECK(one_match(&t, "proto contains tcp") == 1, "proto contains");

    /* Ciblak sozcuk once protokol olarak denenir */
    CHECK(one_match(&t, "tls") == 1, "ciblak tls");
    CHECK(one_match(&u, "dns") == 1, "ciblak dns");
    CHECK(one_match(&a, "arp") == 1, "ciblak arp");
    CHECK(one_match(&u, "tcp") == 0, "ciblak tcp udp'de yok");
}

static void test_info_fields(void) {
    printf("[7] info alanlari\n");
    PacketRecord t = pkt_tcp();
    PacketRecord u = pkt_udp();
    PacketRecord c = pkt_icmp();

    CHECK(one_match(&t, "info contains \"Client Hello\"") == 1,
          "tirnakli contains");
    CHECK(one_match(&u, "info contains \"Client Hello\"") == 0,
          "udp info'da yok");
    CHECK(one_match(&u, "info contains \"beta.example.com\"") == 1,
          "udp tirnakli contains");
    CHECK(one_match(&t, "info contains Client Hello") == 1,
          "tirnaksiz cok sozcuk");
    CHECK(one_match(&t, "info contains client hello") == 1,
          "contains kucuk harf duyarsiz");
    CHECK(one_match(&t, "info == \"Client Hello SNI=alpha.example.com TLSv1.3\"") == 1,
          "info == tam deger");
    CHECK(one_match(&u, "info == \"Client Hello SNI=alpha.example.com TLSv1.3\"") == 0,
          "info == yanlis paket");
    CHECK(one_match(&t, "frame contains alpha.example.com") == 1,
          "frame alias");
    CHECK(one_match(&t, "frame.info contains TLSv1.3") == 1,
          "frame.info alias");

    /* and/or sozcukleri tirnak icinde ayrac sayilmaz */
    CHECK(one_match(&c, "info contains \"send and receive\"") == 1,
          "tirnak icinde and bolunmez");
    CHECK(one_match(&c, "info contains \"send and receive\" and ip.src == 192.168.1.10") == 1,
          "tirnak + gercek and");
    CHECK(one_match(&t, "info contains \"send and receive\"") == 0,
          "send and receive tcp'de yok");
    CHECK(filter_engine_expr_valid("info contains \"a or b\"") == 1,
          "tirnak icinde or gecerli");
}

static void test_bool_combo(void) {
    printf("[8] and/or bilesikleri\n");
    PacketRecord t = pkt_tcp();
    PacketRecord u = pkt_udp();
    PacketRecord a = pkt_arp();

    CHECK(one_match(&t, "ip.src == 192.168.1.10 and tcp.port == 443") == 1,
          "and dogru");
    CHECK(one_match(&u, "ip.src == 192.168.1.10 and tcp.port == 443") == 0,
          "and yanlis kosul");
    CHECK(one_match(&t, "tcp.port == 443 and ip.src == 1.1.1.1") == 0,
          "and ikinci kosul yanlis");

    CHECK(one_match(&t, "udp.port == 53 or tcp.port == 443") == 1,
          "or tcp kolu");
    CHECK(one_match(&u, "udp.port == 53 or tcp.port == 443") == 1,
          "or udp kolu");
    CHECK(one_match(&a, "udp.port == 53 or tcp.port == 443") == 0,
          "or arp'de yok");

    CHECK(one_match(&u, "ip.addr == 10.0.0.5 && udp.port == 53") == 1,
          "&& ayraci");
    CHECK(one_match(&t, "tcp.port == 80 || udp.port == 53") == 0,
          "|| ayraci tcp'de yok");
    CHECK(one_match(&u, "tcp.port == 80 || udp.port == 53") == 1,
          "|| ayraci udp'de var");

    CHECK(one_match(&t, "dns or tls") == 1, "ciblak or tls");
    CHECK(one_match(&u, "dns or tls") == 1, "ciblak or dns");
    CHECK(one_match(&a, "dns or tls") == 0, "ciblak or arp'de yok");

    /* and/or soldan saga AND gruplari halinde islenir */
    CHECK(one_match(&t, "tcp.port == 443 or tcp.port == 80 and ip.src == 10.0.0.1") == 1,
          "onceliksiz grup (tcp)");
    CHECK(one_match(&u, "tcp.port == 443 or tcp.port == 80 and ip.src == 10.0.0.1") == 0,
          "onceliksiz grup (udp yok)");
}

static void test_bare_words(void) {
    printf("[9] ciblak sozcukler\n");
    PacketRecord t = pkt_tcp();
    PacketRecord u = pkt_udp();
    PacketRecord a = pkt_arp();
    PacketRecord c = pkt_icmp();

    CHECK(one_match(&t, "192.168.1.10") == 1, "ciblak ip kaynak");
    CHECK(one_match(&u, "192.168.1.10") == 0, "ciblak ip udp'de yok");
    CHECK(one_match(&t, "443") == 1, "ciblak 443 port");
    CHECK(one_match(&u, "443") == 0, "ciblak 443 udp'de yok");
    CHECK(one_match(&u, "5353") == 1, "ciblak 5353 udp kaynak port");
    CHECK(one_match(&u, "example.com") == 1,
          "ciblak metin alanlarinda icerik");
    CHECK(one_match(&c, "echo") == 1, "ciblak info metni");
    CHECK(one_match(&a, "who has 192.168.1.1") == 1,
          "ciblak arp info (bulanik)");
}

static void test_edge_cases(void) {
    printf("[10] sinir durumlar\n");
    PacketRecord t = pkt_tcp();

    /* Cok uzun ifade siniri (FX_MAX_EXPR=512) */
    char long_expr[600];
    memset(long_expr, 'a', sizeof(long_expr) - 1);
    long_expr[sizeof(long_expr) - 1] = '\0';
    CHECK(filter_engine_expr_valid(long_expr) == 0,
          "513+ karakter ifade gecersiz");

    /* Ayni alan iki farkli deger icin OR */
    CHECK(one_match(&t, "tcp.port == 80 or tcp.port == 443") == 1,
          "ayni alan or");
    CHECK(one_match(&t, "tcp.port == 80 or tcp.port == 22") == 0,
          "ayni alan or yok");

    /* contains port alaninda: sayisal degil ama contains ile olur */
    CHECK(filter_engine_expr_valid("tcp.port contains 44") == 1,
          "port contains gecerli");
    CHECK(one_match(&t, "tcp.port contains 44") == 1, "port contains eslesir");

    /* Deger kucuk harfe cevrilir, karsilastirma duyarsiz */
    CHECK(one_match(&t, "ip.dst == 8.8.8.8") == 1, "ip.dst normal");
    CHECK(filter_engine_expr_valid("  ip.src == 1.2.3.4  ") == 1,
          "bastaki/sondaki bosluk tolere");
}

int main(void) {
    test_validity();
    test_empty_and_invalid_match();
    test_ip_fields();
    test_mac_fields();
    test_port_fields();
    test_proto_fields();
    test_info_fields();
    test_bool_combo();
    test_bare_words();
    test_edge_cases();

    printf("\n%d testten %d basarisiz.\n", g_total, g_failed);
    return g_failed ? 1 : 0;
}


