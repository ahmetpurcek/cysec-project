/*
 * lan_flow_test.c — network_ids.c LAN katmanı birim testleri
 * (akış tablosu, host kapsamı, tehdit skorlaması, snapshot).
 *
 * Derle & çalıştır (repo kökünden):
 *   gcc -std=gnu11 -Wall -Wextra -Iinclude tests/lan_flow_test.c \
 *       src/network_ids.c src/platform.c -lpthread -o /tmp/lan_test \
 *       && /tmp/lan_test
 */
#include "network_ids.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

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

/* ---------------- Çerçeve kurucular ---------------- */

static void mac_set(uint8_t *d, int a, int b, int c, int e, int f, int g) {
    d[0] = (uint8_t)a; d[1] = (uint8_t)b; d[2] = (uint8_t)c;
    d[3] = (uint8_t)e; d[4] = (uint8_t)f; d[5] = (uint8_t)g;
}

/* Ethernet + IPv4 + TCP (SYN varsayılan) çerçevesi */
static PacketRecord pkt_tcp(uint32_t src, uint32_t dst, uint16_t sp,
                            uint16_t dp, int syn) {
    PacketRecord p;
    memset(&p, 0, sizeof(p));
    uint8_t *r = p.raw_data;
    mac_set(r + 0, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55); /* dst mac */
    mac_set(r + 6, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01); /* src mac */
    r[12] = 0x08; r[13] = 0x00;                          /* IPv4 */
    r[14] = 0x45;                                        /* v4, ihl=5 */
    r[23] = 6;                                           /* TCP */
    r[26] = (uint8_t)(src >> 24); r[27] = (uint8_t)(src >> 16);
    r[28] = (uint8_t)(src >> 8);  r[29] = (uint8_t)src;
    r[30] = (uint8_t)(dst >> 24); r[31] = (uint8_t)(dst >> 16);
    r[32] = (uint8_t)(dst >> 8);  r[33] = (uint8_t)dst;
    uint8_t *l4 = r + 34;
    l4[0] = (uint8_t)(sp >> 8); l4[1] = (uint8_t)sp;
    l4[2] = (uint8_t)(dp >> 8); l4[3] = (uint8_t)dp;
    l4[12] = 0x50;                                      /* doff=5 */
    l4[13] = syn ? 0x02 : 0x10;                         /* SYN / ACK */
    p.raw_len = 54;
    p.length = 54;
    return p;
}

/* pkt_tcp ile ayni, ama self olmayan attacker src MAC'i (DE:AD:BE:EF:00:07)
 * kullanir: ids_is_self_originated filtresini baypas eder ve paketi normal
 * kural islemcisinden (C| dahil) gecirir. */
static PacketRecord pkt_tcp_att(uint32_t src, uint32_t dst, uint16_t sp,
                                uint16_t dp, int syn) {
    PacketRecord p = pkt_tcp(src, dst, sp, dp, syn);
    mac_set(p.raw_data + 6, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x07);
    return p;
}

/* Ethernet + IPv4 + UDP çerçevesi */
static PacketRecord pkt_udp(uint32_t src, uint32_t dst, uint16_t sp,
                            uint16_t dp) {
    PacketRecord p;
    memset(&p, 0, sizeof(p));
    uint8_t *r = p.raw_data;
    mac_set(r + 0, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
    mac_set(r + 6, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02);
    r[12] = 0x08; r[13] = 0x00;
    r[14] = 0x45;
    r[23] = 17;                                          /* UDP */
    r[26] = (uint8_t)(src >> 24); r[27] = (uint8_t)(src >> 16);
    r[28] = (uint8_t)(src >> 8);  r[29] = (uint8_t)src;
    r[30] = (uint8_t)(dst >> 24); r[31] = (uint8_t)(dst >> 16);
    r[32] = (uint8_t)(dst >> 8);  r[33] = (uint8_t)dst;
    uint8_t *l4 = r + 34;
    l4[0] = (uint8_t)(sp >> 8); l4[1] = (uint8_t)sp;
    l4[2] = (uint8_t)(dp >> 8); l4[3] = (uint8_t)dp;
    l4[4] = 0; l4[5] = 8;                                /* uzunluk */
    l4[8] = 0; l4[9] = 1;                                /* DNS qdcount=1 */
    p.raw_len = 46;
    p.length = 46;
    return p;
}

/* Ethernet + ARP çerçevesi */
static PacketRecord pkt_arp(int opcode, const uint8_t *smac, uint32_t sip,
                            uint32_t tip) {
    PacketRecord p;
    memset(&p, 0, sizeof(p));
    uint8_t *r = p.raw_data;
    for (int i = 0; i < 6; i++) r[i] = 0xFF;             /* broadcast */
    mac_set(r + 6, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x03);
    r[12] = 0x08; r[13] = 0x06;                          /* ARP */
    r[14] = 0x00; r[15] = 0x01;                          /* Ethernet */
    r[16] = 0x08; r[17] = 0x00;                          /* IPv4 */
    r[18] = 0x06; r[19] = 0x04;
    r[20] = (uint8_t)(opcode >> 8); r[21] = (uint8_t)opcode;
    memcpy(r + 22, smac, 6);
    r[28] = (uint8_t)(sip >> 24); r[29] = (uint8_t)(sip >> 16);
    r[30] = (uint8_t)(sip >> 8);  r[31] = (uint8_t)sip;
    mac_set(r + 32, 0, 0, 0, 0, 0, 0);
    r[38] = (uint8_t)(tip >> 24); r[39] = (uint8_t)(tip >> 16);
    r[40] = (uint8_t)(tip >> 8);  r[41] = (uint8_t)tip;
    p.raw_len = 42;
    p.length = 42;
    return p;
}

/* Ethernet + IPv4 + UDP DNS cercevesi: 12B baslik + soru (+ yanit) */
static PacketRecord pkt_dns(uint32_t src, uint32_t dst, uint16_t sp,
                            uint16_t dp, const char *qname,
                            int is_response, uint32_t ans_ip) {
    PacketRecord p;
    memset(&p, 0, sizeof(p));
    uint8_t *r = p.raw_data;
    mac_set(r + 0, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
    mac_set(r + 6, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02);
    r[12] = 0x08; r[13] = 0x00;
    r[14] = 0x45;
    r[23] = 17;
    r[26] = (uint8_t)(src >> 24); r[27] = (uint8_t)(src >> 16);
    r[28] = (uint8_t)(src >> 8);  r[29] = (uint8_t)src;
    r[30] = (uint8_t)(dst >> 24); r[31] = (uint8_t)(dst >> 16);
    r[32] = (uint8_t)(dst >> 8);  r[33] = (uint8_t)dst;
    uint8_t *l4 = r + 34;
    l4[0] = (uint8_t)(sp >> 8); l4[1] = (uint8_t)sp;
    l4[2] = (uint8_t)(dp >> 8); l4[3] = (uint8_t)dp;
    l4[4] = 0; l4[5] = 0;                        /* uzunluk sonra */
    l4[6] = 0; l4[7] = 0;                        /* checksum yok */
    l4[8] = 0x12; l4[9] = 0x34;                  /* txid */
    l4[10] = is_response ? 0x80 : 0x01;          /* QR + RD */
    l4[11] = 0;
    l4[12] = 0; l4[13] = 1;                      /* qdcount=1 */
    l4[14] = 0; l4[15] = 0; l4[16] = 0; l4[17] = 0;
    l4[18] = 0; l4[19] = 0;
    int o = 20;                                  /* soru: 12B basliktan hemen sonra */
    const char *q = qname ? qname : "example.com";
    while (*q) {
        const char *dot = strchr(q, '.');
        int l = dot ? (int)(dot - q) : (int)strlen(q);
        l4[o++] = (uint8_t)l;
        memcpy(l4 + o, q, (size_t)l); o += l;
        if (!dot) break;
        q = dot + 1;
    }
    l4[o++] = 0;
    l4[o++] = 0; l4[o++] = 1;                    /* QTYPE A */
    l4[o++] = 0; l4[o++] = 1;                    /* QCLASS IN */
    if (is_response && ans_ip) {
        l4[o++] = 0xC0; l4[o++] = 0x0C;          /* isaretci: baslik */
        l4[o++] = 0; l4[o++] = 1;                /* TYPE A */
        l4[o++] = 0; l4[o++] = 1;                /* CLASS IN */
        l4[o++] = 0; l4[o++] = 0; l4[o++] = 0; l4[o++] = 0x3C;
        l4[o++] = 0; l4[o++] = 4;                /* RDLENGTH 4 */
        l4[o++] = (uint8_t)(ans_ip >> 24); l4[o++] = (uint8_t)(ans_ip >> 16);
        l4[o++] = (uint8_t)(ans_ip >> 8);  l4[o++] = (uint8_t)ans_ip;
        l4[10] = 0x84;                           /* QR + AA + RD */
    }
    l4[4] = (uint8_t)(o >> 8); l4[5] = (uint8_t)o;
    p.raw_len = 34 + o;
    p.length = p.raw_len;
    return p;
}

/* Ethernet + IPv4 + UDP NBNS ad sorgusu (port 137) */
static PacketRecord pkt_nbns(uint32_t src, uint32_t dst, const char *name) {
    PacketRecord p;
    memset(&p, 0, sizeof(p));
    uint8_t *r = p.raw_data;
    mac_set(r + 0, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
    mac_set(r + 6, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02);
    r[12] = 0x08; r[13] = 0x00;
    r[14] = 0x45;
    r[23] = 17;
    r[26] = (uint8_t)(src >> 24); r[27] = (uint8_t)(src >> 16);
    r[28] = (uint8_t)(src >> 8);  r[29] = (uint8_t)src;
    r[30] = (uint8_t)(dst >> 24); r[31] = (uint8_t)(dst >> 16);
    r[32] = (uint8_t)(dst >> 8);  r[33] = (uint8_t)dst;
    uint8_t *l4 = r + 34;
    l4[0] = 0x00; l4[1] = 0x89;                  /* sp=137 */
    l4[2] = 0x00; l4[3] = 0x89;                  /* dp=137 */
    l4[4] = 0; l4[5] = 0;
    l4[6] = 0; l4[7] = 0;
    l4[8] = 0xAA; l4[9] = 0xAA;                  /* txid */
    l4[10] = 0x00; l4[11] = 0x00;                /* sorgu */
    l4[12] = 0x00; l4[13] = 0x01;                /* qdcount=1 */
    l4[14] = 0; l4[15] = 0; l4[16] = 0; l4[17] = 0;
    l4[18] = 0; l4[19] = 0; l4[20] = 0; l4[21] = 0;
    l4[20] = 0x20;                               /* pay[12]: NB ad tipi */
    int o = 21;                                  /* pay[13]: kodlu ad */
    char enc[32];
    int nlen = (int)strlen(name);
    for (int i = 0; i < 16; i++) {
        char c = (i < nlen) ? name[i] : ' ';
        enc[i * 2] = (char)(((c >> 4) & 0x0F) + 'A');
        enc[i * 2 + 1] = (char)((c & 0x0F) + 'A');
    }
    memcpy(l4 + o, enc, 32); o += 32;
    l4[o++] = 0; l4[o++] = 0x20;                 /* TYPE NB */
    l4[o++] = 0; l4[o++] = 0x01;                 /* CLASS IN */
    l4[4] = (uint8_t)(o >> 8); l4[5] = (uint8_t)o;
    p.raw_len = 34 + o;
    p.length = p.raw_len;
    return p;
}

/* Ethernet + IPv4 + UDP DHCP cercevesi (240B + opsiyon 12 + END) */
static PacketRecord pkt_dhcp(uint32_t src, uint32_t dst, uint16_t sp,
                             uint16_t dp, int op, uint32_t yiaddr,
                             const uint8_t *chaddr, const char *hostname) {
    PacketRecord p;
    memset(&p, 0, sizeof(p));
    uint8_t *r = p.raw_data;
    mac_set(r + 0, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
    mac_set(r + 6, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x02);
    r[12] = 0x08; r[13] = 0x00;
    r[14] = 0x45;
    r[23] = 17;
    r[26] = (uint8_t)(src >> 24); r[27] = (uint8_t)(src >> 16);
    r[28] = (uint8_t)(src >> 8);  r[29] = (uint8_t)src;
    r[30] = (uint8_t)(dst >> 24); r[31] = (uint8_t)(dst >> 16);
    r[32] = (uint8_t)(dst >> 8);  r[33] = (uint8_t)dst;
    uint8_t *l4 = r + 34;
    l4[0] = (uint8_t)(sp >> 8); l4[1] = (uint8_t)sp;
    l4[2] = (uint8_t)(dp >> 8); l4[3] = (uint8_t)dp;
    l4[4] = 0; l4[5] = 0;
    l4[6] = 0; l4[7] = 0;
    uint8_t *dh = l4 + 8;                        /* DHCP mesaji */
    memset(dh, 0, 240);
    dh[0] = (uint8_t)op;
    dh[1] = 1; dh[2] = 6;                        /* htype, hlen */
    dh[16] = (uint8_t)(yiaddr >> 24); dh[17] = (uint8_t)(yiaddr >> 16);
    dh[18] = (uint8_t)(yiaddr >> 8);  dh[19] = (uint8_t)yiaddr;
    if (chaddr) memcpy(dh + 28, chaddr, 6);
    dh[236] = 0x63; dh[237] = 0x82; dh[238] = 0x53; dh[239] = 0x63;
    int o = 240;
    if (hostname && hostname[0]) {
        int nl = (int)strlen(hostname);
        if (nl > 63) nl = 63;
        dh[o++] = 12;
        dh[o++] = (uint8_t)nl;
        memcpy(dh + o, hostname, (size_t)nl); o += nl;
    }
    dh[o++] = 255;                               /* END */
    l4[4] = (uint8_t)((8 + o) >> 8); l4[5] = (uint8_t)(8 + o);
    p.raw_len = 34 + 8 + o;
    p.length = p.raw_len;
    return p;
}

static uint32_t ip4(const char *s) {
    unsigned int a, b, c, d;
    if (sscanf(s, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return 0;
    return ((uint32_t)a << 24) | ((uint32_t)b << 16) |
           ((uint32_t)c << 8) | d;
}

/* Snapshot'ta IP bul (yoksa NULL) */
static IdsHostThreat *find_host(IdsHostThreatSnapshot *sn, const char *ip) {
    for (int i = 0; i < sn->count; i++)
        if (strcmp(sn->hosts[i].ip, ip) == 0) return &sn->hosts[i];
    return NULL;
}

/* Bir saniye bekle, ardından analiz kenesini tetikleyen sıradan bir paket gönder */
static void tick_analysis(void) {
    sleep(1);
    PacketRecord b = pkt_tcp(ip4("192.168.1.10"), ip4("192.168.1.20"),
                             50000, 443, 0);
    ids_process_packet(&b);
}

int main(void) {
    ids_init();
    ids_set_network_range("192.168.1.0/24");
    ids_set_mac_context("AA:BB:CC:DD:EE:01", "00:11:22:33:44:55",
                        "192.168.1.1", "192.168.1.10");

    /* Izleme kapsami: test boyunca kullanilan IP'leri kapsayan liste
     * (bos kapsam = hicbir sey izlenmez; kapsam testleri dosya sonunda). */
    {
        static const char *scope[] = {
            "0.0.0.0",
            "192.168.1.1", "192.168.1.10", "192.168.1.12", "192.168.1.13",
            "192.168.1.14", "192.168.1.15", "192.168.1.17", "192.168.1.18",
            "192.168.1.19", "192.168.1.20", "192.168.1.23", "192.168.1.30",
            "192.168.1.31", "192.168.1.32", "192.168.1.40", "192.168.1.41",
            "192.168.1.42", "192.168.1.43", "192.168.1.44", "192.168.1.77",
            "192.168.1.78", "192.168.1.101", "192.168.1.255",
            /* uzun ufuk (yavas tarama) test kaynaklari */
            "192.168.1.150", "192.168.1.151",
        };
        ids_scope_set(scope, (int)(sizeof(scope) / sizeof(scope[0])));
    }

    IdsHostThreatSnapshot sn;

    printf("== Kapsam + host olusumu ==\n");
    {
        PacketRecord p = pkt_tcp(ip4("192.168.1.10"), ip4("192.168.1.20"),
                                 50000, 443, 1);
        ids_process_packet(&p);
        int n = ids_get_host_threat_snapshot(&sn);
        CHECK(n == 2, "snapshot host sayisi 2 bekleniyor, %d", n);
        CHECK(sn.total_flows == 1, "aktif akis 1 bekleniyor, %d",
              sn.total_flows);
        CHECK(g_ids.host_count == 2, "g_ids.host_count 2, %u",
              g_ids.host_count);
        CHECK(find_host(&sn, "192.168.1.10") != NULL, "host 10 yok");
        CHECK(find_host(&sn, "192.168.1.20") != NULL, "host 20 yok");
    }

    printf("== Kapsam disi IP: akis var, host yok ==\n");
    {
        PacketRecord p = pkt_udp(ip4("10.0.0.5"), ip4("192.168.1.1"),
                                 5353, 53);
        ids_process_packet(&p);
        int n = ids_get_host_threat_snapshot(&sn);
        CHECK(n == 3, "snapshot host sayisi 3 bekleniyor, %d", n);
        CHECK(sn.total_flows == 2, "aktif akis 2 bekleniyor, %d",
              sn.total_flows);
        CHECK(find_host(&sn, "10.0.0.5") == NULL,
              "kapsam disi 10.0.0.5 host olarak gorunmemeli");
        CHECK(find_host(&sn, "192.168.1.1") != NULL, "host 1 yok");
    }

    printf("== ARP: yalnizca last_seen (akis yok) ==\n");
    {
        uint8_t mac30[6];
        mac_set(mac30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30);
        PacketRecord p = pkt_arp(2, mac30, ip4("192.168.1.30"),
                                 ip4("192.168.1.1"));
        ids_process_packet(&p);
        int n = ids_get_host_threat_snapshot(&sn);
        CHECK(n == 4, "ARP sender host olarak eklenmeli, %d", n);
        CHECK(sn.total_flows == 2, "ARP akis olusturmamali, %d",
              sn.total_flows);
        CHECK(find_host(&sn, "192.168.1.30") != NULL, "host 30 yok");

        /* sender IP 0 (DHCP tarzi) — host acilmamali, cokme olmamali */
        uint8_t mac0[6];
        mac_set(mac0, 0, 0, 0, 0, 0, 0);
        PacketRecord q = pkt_arp(1, mac0, 0, ip4("192.168.1.1"));
        ids_process_packet(&q);
        n = ids_get_host_threat_snapshot(&sn);
        CHECK(n == 4, "sender IP 0 host olusturmamali, %d", n);
    }

    printf("== Akis analizi: tarama + sweep skorlari ==\n");
    {
        /* 6 hedef IP x 2 port = 12 akis -> SCAN(8+ port) + SWEEP(6+ IP) */
        for (int j = 0; j < 6; j++) {
            uint32_t d = ip4("192.168.1.101") + j;
            PacketRecord a = pkt_tcp(ip4("192.168.1.10"), d,
                                     (uint16_t)(50000 + j), (uint16_t)(100 + j * 2), 1);
            PacketRecord b = pkt_tcp(ip4("192.168.1.10"), d,
                                     (uint16_t)(51000 + j), (uint16_t)(101 + j * 2), 1);
            ids_process_packet(&a);
            ids_process_packet(&b);
        }
        tick_analysis();
        int n = ids_get_host_threat_snapshot(&sn);
        IdsHostThreat *h = find_host(&sn, "192.168.1.10");
        CHECK(h != NULL, "host 10 yok");
        if (h) {
            /* L| (yerel kaynakli tarama) esigi duzeltildiginden ayni trafik
             * artik uyari uretip skora islenir: +20 L| YUKSEK -> IDS_F_SCAN,
             * +15 akis SWEEP bonusu, -1 bozunum = 34. 24 beklemek gercegi
             * eksik gosteriyordu. */
            CHECK(h->attack_score == 34,
                  "L|(+20)+sweep(+15)-bozunum(1)=34 bekleniyor, %u",
                  h->attack_score);
            CHECK((h->flags & IDS_F_SWEEP) != 0, "SWEEP bayragi yok");
            CHECK((h->flags & IDS_F_SCAN) != 0, "SCAN bayragi yok");
            CHECK(strcmp(h->status, "SUPHELI") == 0,
                  "durum SUPHELI bekleniyor, %s", h->status);
            /* tick_analysis() paketi (10->20:443) da bir akis olusturur;
             * benzersiz hedef kumesine 20:443 eklenir -> 7 IP / 13 port. */
            CHECK(h->unique_target_ips == 7, "6 tarama + tick hedefi = 7 IP, %u",
                  h->unique_target_ips);
            CHECK(h->unique_target_ports == 13, "12 tarama + 443 = 13 port, %u",
                  h->unique_target_ports);
        }
        /* skor siralamasi: ilk kayit en yuksek saldirgan olmali.
         * Sabit bir esik yerine host'un KENDI skoruyla karsilastirilir;
         * esik degeri testin geri kalanindan bagimsiz kalsin. */
        IdsHostThreat *top10 = find_host(&sn, "192.168.1.10");
        CHECK(sn.count > 0 && top10 != NULL &&
                  sn.hosts[0].attack_score == top10->attack_score,
              "snapshot saldiri skoruna gore sirali (en yuksek ilk "
              "sirada), %u",
              sn.count > 0 ? sn.hosts[0].attack_score : 0);
        (void)n;
    }

    printf("== L| taramasi: hedef degisince TEK satir\n");
    printf("==                         guncellenir (agregasyon) ==\n");
    {
        /* Eski kod yalniz (imza + src + dst) tam eslesmesine bakiyordu; hedef
         * degisince satir bulunamiyor, dedup da bastirdigi icin uyari metni
         * donuyordu. Yeni iki gecisli mantik: 1. gecis ayni hedef, 2. gecis
         * ayni kaynak + hedef DEGISTI (hedef alani guncellenir). */
        IdsGuiAlert al[16];
        static const char *sig = "Yerel Kaynakli Port Taramasi";

        int n0 = ids_get_alerts_snapshot(al, 16);
        int lscan0 = 0;
        for (int i = 0; i < n0; i++)
            if (strcmp(al[i].sig_name, sig) == 0) lscan0++;
        CHECK(lscan0 >= 1,
              "onceki tarama blogu L| uyarisi uretmis olmali, %d", lscan0);

        uint64_t t_a = g_ids.total_alerts;

        /* 1) Ayni kaynak + AYNI hedef, 8 yeni benzersiz port (kural esigi):
         *    mevcut satir guncellenmeli, yeni satir acilmamali. */
        for (int i = 0; i < 8; i++) {
            PacketRecord p = pkt_tcp(ip4("192.168.1.10"), ip4("192.168.1.20"),
                                     (uint16_t)(52000 + i),
                                     (uint16_t)(200 + i), 1);
            ids_process_packet(&p);
        }
        int n1 = ids_get_alerts_snapshot(al, 16);
        int lscan1 = 0, u1 = -1, p1 = -1;
        for (int i = 0; i < n1; i++) {
            if (strcmp(al[i].sig_name, sig) != 0) continue;
            lscan1++;
            if (sscanf(al[i].description,
                       "%*s -> %d farkli porta disari SYN taramasi (%d paket)",
                       &u1, &p1) != 2) {
                u1 = p1 = -1;
            }
        }
        CHECK(lscan1 == lscan0,
              "ayni hedefte satir sayisi degismemeli: %d -> %d",
              lscan0, lscan1);
        CHECK(u1 >= 8 && p1 >= 8,
              "L| aciklamasi guncel sayilari tasimali: %d/%d", u1, p1);
        CHECK(g_ids.total_alerts == t_a,
              "soguma (cooldown) icinde yeni satir yayinlanmamali "
              "(%llu -> %llu)", (unsigned long long)t_a,
              (unsigned long long)g_ids.total_alerts);

        /* 2) AYNI kaynak, FARKLI hedef (.23). Eski kod burada uyariyi
         *    guncelleyemezdi (sahte yanlis negatif); yeni 2. gecis ayni
         *    satiri bulur ve hedef + sayilari tazeler. */
        for (int i = 0; i < 8; i++) {
            PacketRecord p = pkt_tcp(ip4("192.168.1.10"), ip4("192.168.1.23"),
                                     (uint16_t)(52100 + i),
                                     (uint16_t)(300 + i), 1);
            ids_process_packet(&p);
        }
        int n2 = ids_get_alerts_snapshot(al, 16);
        int lscan2 = 0, last = -1, u2 = -1, p2 = -1;
        for (int i = 0; i < n2; i++) {
            if (strcmp(al[i].sig_name, sig) != 0) continue;
            lscan2++;
            last = i;
        }
        CHECK(lscan2 == lscan0,
              "hedef degisince YENI satir acilmamali: %d -> %d",
              lscan0, lscan2);
        CHECK(last >= 0, "L| satiri bulunamadi");
        if (last >= 0) {
            CHECK(sscanf(al[last].description,
                         "%*s -> %d farkli porta disari SYN taramasi (%d paket)",
                         &u2, &p2) == 2,
                  "aciklama ayristirilamadi: %s", al[last].description);
            CHECK(u2 > u1 && p2 > p1,
                  "aciklama metni TAZELENMELI (eski hata: donuk kaliyordu) "
                  "%d/%d -> %d/%d", u1, p1, u2, p2);
            CHECK(strcmp(al[last].dst_ip, "192.168.1.23") == 0,
                  "hedef alani 2. gecisle guncellenmeli: %s",
                  al[last].dst_ip);
        }
        CHECK(g_ids.total_alerts == t_a,
              "guncelleme yayin degil olmali (uyari sayisi sismemeli) "
              "(%llu -> %llu)", (unsigned long long)t_a,
              (unsigned long long)g_ids.total_alerts);
    }

    printf("== ids_clear_alerts sonrasi uyari SESSIZCE\n");
    printf("==                         kaybolmaz (dedup serbest) ==\n");
    {
        /* Kullanici listeyi temizler ama dedup (TTL 120 sn) temizlenmez:
         * cooldown yeni yayini engeller, satir yok, dedup bastirir -> uyari
         * TAMAMEN kaybolurdu. Yama: boyle durumda dedup serbest birakilip
         * olay yeniden yayinlanir. */
        static const char *sig = "Yerel Kaynakli Port Taramasi";
        IdsGuiAlert al[16];

        /* Temiz bir kaynak: .12 (kapsamda). Ayni hedefe 8 benzersiz port ->
         * kural tetiklenir ve dedup (imza|.12|.20) silahlanir. */
        for (int i = 0; i < 8; i++) {
            PacketRecord p = pkt_tcp(ip4("192.168.1.12"), ip4("192.168.1.20"),
                                     (uint16_t)(53000 + i),
                                     (uint16_t)(400 + i), 1);
            ids_process_packet(&p);
        }
        int nb = ids_get_alerts_snapshot(al, 16);
        int l12 = 0;
        for (int i = 0; i < nb; i++)
            if (strcmp(al[i].sig_name, sig) == 0) l12++;
        CHECK(l12 >= 1, ".12 taramasi icin L| satiri olusmali, %d", l12);

        /* Analist listedeki kayitlari siler (dedup tablosu kalir). */
        ids_clear_alerts();
        CHECK(ids_get_alerts_snapshot(al, 16) == 0,
              "ids_clear_alerts sonrasi liste bos olmali");

        /* Olay DEVAM EDIYOR: ayni kaynak/hedef, soguma aktif + dedup aktif.
         * Eski kod: hicbir cikti yok. Yeni kod: dedup serbest -> yeniden
         * yayin. */
        uint64_t t_b = g_ids.total_alerts;
        PacketRecord again = pkt_tcp(ip4("192.168.1.12"), ip4("192.168.1.20"),
                                     53100, 401, 1);
        ids_process_packet(&again);
        CHECK(g_ids.total_alerts == t_b + 1,
              "silme + dedup sonrasi uyari YENIDEN yayinlanmali "
              "(%llu -> %llu)", (unsigned long long)t_b,
              (unsigned long long)g_ids.total_alerts);
        int rn = ids_get_alerts_snapshot(al, 16);
        CHECK(rn == 1 && strcmp(al[rn - 1].sig_name, sig) == 0,
              "yeniden yayinlanan satir L| olmali (n=%d, %s)", rn,
              rn >= 1 ? al[rn - 1].sig_name : "-");

        /* Uyari geri geldikten sonra ayni olay tekrar tekrar uyari
         * uretmemeli: satir yerinde oldugu icin agregasyon yolu calisir. */
        uint64_t t_c = g_ids.total_alerts;
        PacketRecord again2 = pkt_tcp(ip4("192.168.1.12"), ip4("192.168.1.20"),
                                      53101, 402, 1);
        ids_process_packet(&again2);
        CHECK(g_ids.total_alerts == t_c,
              "olay surerken uyari sayisi sismemeli (%llu -> %llu)",
              (unsigned long long)t_c,
              (unsigned long long)g_ids.total_alerts);
    }

    printf("== Brute force kurban skoru ==\n");
    {
        uint32_t v = ip4("192.168.1.40");
        uint32_t s41 = ip4("192.168.1.41"), s42 = ip4("192.168.1.42");
        uint32_t s43 = ip4("192.168.1.43"), s44 = ip4("192.168.1.44");
        PacketRecord f1 = pkt_tcp(s41, v, 51000, 2222, 1);
        PacketRecord f2 = pkt_tcp(s41, v, 51001, 2222, 1);
        PacketRecord f3 = pkt_tcp(s42, v, 52000, 2222, 1);
        PacketRecord f4 = pkt_tcp(s42, v, 52001, 2222, 1);
        PacketRecord f5 = pkt_tcp(s43, v, 53000, 2222, 1);
        PacketRecord f6 = pkt_tcp(s44, v, 54000, 2222, 1);
        ids_process_packet(&f1);
        ids_process_packet(&f2);
        ids_process_packet(&f3);
        ids_process_packet(&f4);
        ids_process_packet(&f5);
        ids_process_packet(&f6);
        tick_analysis();
        int n = ids_get_host_threat_snapshot(&sn);
        IdsHostThreat *h = find_host(&sn, "192.168.1.40");
        CHECK(h != NULL, "kurban host 40 yok");
        if (h) {
            CHECK(h->victim_score == 24,
                  "brute(+25)-bozunum(1)=24 bekleniyor, %u",
                  h->victim_score);
            CHECK((h->flags & IDS_F_BRUTEFORCE) != 0,
                  "BRUTEFORCE bayragi yok");
            CHECK(strcmp(h->status, "TEMIZ") == 0,
                  "kurbanin statusu saldiri degil TEMIZ olmali, %s",
                  h->status);
        }
        CHECK(sn.total_flows >= 12, "brute akislari tabloda, %d",
              sn.total_flows);
        (void)n;
    }

    printf("== ARP zehirlenmesi uyarisi -> host skoru ==\n");
    {
        uint8_t evil[6];
        mac_set(evil, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01);
        PacketRecord p = pkt_arp(2, evil, ip4("192.168.1.1"),
                                 ip4("192.168.1.10"));
        ids_process_packet(&p);
        CHECK(g_ids.total_alerts >= 1, "ARP zehirlenmesi uyarisi yok");
        int n = ids_get_host_threat_snapshot(&sn);
        IdsHostThreat *gw = find_host(&sn, "192.168.1.1");
        IdsHostThreat *vic = find_host(&sn, "192.168.1.10");
        CHECK(gw != NULL && gw->attack_score >= 40,
              "gateway host saldiri skoru >=40, %u",
              gw ? gw->attack_score : 0);
        CHECK(gw != NULL && (gw->flags & IDS_F_ARPSPOOF) != 0,
              "ARPSPOOF bayragi yok");
        CHECK(vic != NULL && vic->victim_score >= 40,
              "hedef kurban skoru >=40, %u",
              vic ? vic->victim_score : 0);
        CHECK(gw != NULL && strcmp(gw->status, "SALDIRGAN") == 0,
              "gateway durumu SALDIRGAN, %s", gw ? gw->status : "-");
        (void)n;
    }

    printf("== Otomatik kapsam: yerel IP'den /24 turetimi ==\n");
    {
        ids_set_network_range("");            /* kapsami sifirla */
        ids_set_mac_context("AA:BB:CC:DD:EE:01", "00:11:22:33:44:55",
                            "192.168.1.1", "192.168.1.10");
        PacketRecord p = pkt_udp(ip4("192.168.1.77"), ip4("192.168.1.78"),
                                 1000, 2000);
        ids_process_packet(&p);
        int n = ids_get_host_threat_snapshot(&sn);
        CHECK(find_host(&sn, "192.168.1.77") != NULL,
              "otomatik /24 kapsaminda host 77 olusmali, %d", n);
        CHECK(find_host(&sn, "192.168.1.78") != NULL,
              "otomatik /24 kapsaminda host 78 olusmali, %d", n);
        ids_set_network_range("192.168.1.0/24");  /* sonraki testler icin */
    }

    printf("== SOC v3: DNS DGA algilama ==\n");
    {
        uint64_t before = g_ids.total_alerts;
        /* [D5] yeni esik DGA_MIN_QCOUNT=60 -> 65 sorgu */
        for (int i = 0; i < 65; i++) {
            char q[64];
            snprintf(q, sizeof(q), "dga%02dx7wq8k.com", i);
            PacketRecord p = pkt_dns(ip4("192.168.1.14"), ip4("192.168.1.1"),
                                     10000 + i, 53, q, 0, 0);
            ids_process_packet(&p);
        }
        tick_analysis();
        int n = ids_get_host_threat_snapshot(&sn);
        IdsHostThreat *h14 = find_host(&sn, "192.168.1.14");
        CHECK(h14 != NULL, "DGA: host 14 olusmali, %d", n);
        CHECK(h14 && (h14->flags & IDS_F_DNS) != 0,
              "DGA: IDS_F_DNS bayragi yok, %u", h14 ? h14->flags : 0);
        CHECK(g_ids.total_alerts > before, "DGA: uyari uretilmedi");
        IdsGuiAlert al[8];
        int an = ids_get_alerts_snapshot(al, 8);
        CHECK(an >= 1 && strstr(al[an - 1].sig_name, "DGA") != NULL,
              "DGA: son imza 'DGA Suphesi (C2)', %s",
              an >= 1 ? al[an - 1].sig_name : "-");
        (void)n;
    }

    printf("== SOC v3: DNS tunel sezgiseli ==\n");
    {
        uint64_t before = g_ids.total_alerts;
        PacketRecord p = pkt_dns(ip4("192.168.1.15"), ip4("192.168.1.1"),
                                 20000, 53, "a1b2c3d4e5f6g7h8.example.com", 0, 0);
        ids_process_packet(&p);
        tick_analysis();
        int n = ids_get_host_threat_snapshot(&sn);
        IdsHostThreat *h15 = find_host(&sn, "192.168.1.15");
        CHECK(h15 != NULL, "TUNEL: host 15 olusmali, %d", n);
        CHECK(h15 && (h15->flags & IDS_F_TUNNEL) != 0,
              "TUNEL: IDS_F_TUNNEL bayragi yok, %u", h15 ? h15->flags : 0);
        CHECK(g_ids.total_alerts > before, "TUNEL: uyari uretilmedi");
        (void)n;
    }

    printf("== SOC v3: host adi ogrenme (mDNS/NBNS/DHCP) ==\n");
    {
        PacketRecord m = pkt_dns(ip4("192.168.1.10"), ip4("224.0.0.251"),
                                 5353, 5353, "printer.local", 1,
                                 ip4("192.168.1.12"));
        ids_process_packet(&m);
        PacketRecord nb = pkt_nbns(ip4("192.168.1.13"),
                                   ip4("192.168.1.255"), "AHMEDPC");
        ids_process_packet(&nb);
        uint8_t cli_mac[6];
        mac_set(cli_mac, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60);
        PacketRecord d1 = pkt_dhcp(ip4("0.0.0.0"), ip4("255.255.255.255"),
                                   68, 67, 1, 0, cli_mac, "ROBOT-PC");
        ids_process_packet(&d1);
        PacketRecord d2 = pkt_dhcp(ip4("192.168.1.1"), ip4("255.255.255.255"),
                                   67, 68, 2, ip4("192.168.1.10"), cli_mac, NULL);
        ids_process_packet(&d2);
        int n = ids_get_host_threat_snapshot(&sn);
        IdsHostThreat *h12 = find_host(&sn, "192.168.1.12");
        IdsHostThreat *h13 = find_host(&sn, "192.168.1.13");
        IdsHostThreat *h10 = find_host(&sn, "192.168.1.10");
        CHECK(h12 != NULL && strcmp(h12->hostname, "printer.local") == 0,
              "mDNS: host 12 adi 'printer.local', %s",
              h12 ? h12->hostname : "-");
        CHECK(h13 != NULL && strcmp(h13->hostname, "AHMEDPC") == 0,
              "NBNS: host 13 adi 'AHMEDPC', %s", h13 ? h13->hostname : "-");
        CHECK(h10 != NULL && strcmp(h10->hostname, "ROBOT-PC") == 0,
              "DHCP: host 10 adi 'ROBOT-PC', %s", h10 ? h10->hostname : "-");
        (void)n;
    }

    printf("== SOC v3: olay korelasyonu ==\n");
    {
        uint8_t evil[6];
        mac_set(evil, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01);
        PacketRecord p1 = pkt_arp(2, evil, ip4("192.168.1.1"),
                                  ip4("192.168.1.10"));
        ids_process_packet(&p1);
        PacketRecord p2 = pkt_arp(2, evil, ip4("192.168.1.1"),
                                  ip4("192.168.1.10"));
        ids_process_packet(&p2);
        IdsIncident inc[8];
        int n = ids_get_incidents_snapshot(inc, 8);
        CHECK(n >= 1, "olay kaydi yok, %d", n);
        if (n >= 1) {
            CHECK(strcmp(inc[0].attacker_ip, "192.168.1.1") == 0,
                  "olay saldirgani 192.168.1.1, %s", inc[0].attacker_ip);
            CHECK(strcmp(inc[0].victim_ip, "192.168.1.10") == 0,
                  "olay kurbani 192.168.1.10, %s", inc[0].victim_ip);
            CHECK(inc[0].alert_count >= 1, "olay uyari sayisi, %u",
                  inc[0].alert_count);
            CHECK(inc[0].killchain == 2, "killchain 2 (sizma), %d",
                  inc[0].killchain);
            CHECK(strcmp(inc[0].worst_severity, "KRITIK") == 0,
                  "olay en kotu seviye KRITIK, %s", inc[0].worst_severity);
            CHECK(inc[0].max_score >= 0.9, "olay max skor >=0.9, %.2f",
                  inc[0].max_score);
        }
        (void)n;
    }

    printf("== SOC v3: uyari triyaji ==\n");
    {
        IdsGuiAlert gal[8];
        int n = ids_get_alerts_snapshot(gal, 8);
        CHECK(n >= 1 && gal[0].status == IDS_ALERT_STATUS_NEW,
              "varsayilan durum NEW, %d", n >= 1 ? gal[0].status : -1);
        if (n >= 1) {
            CHECK(ids_set_alert_status(0, IDS_ALERT_STATUS_REVIEWING) == 1,
                  "REVIEWING guncellenemedi");
            CHECK(ids_set_alert_note(0, "Analist incelemesinde") == 1,
                  "not yazilamadi");
            CHECK(ids_set_alert_status(0, IDS_ALERT_STATUS_FALSEPOS) == 1,
                  "FALSEPOS guncellenemedi");
            CHECK(ids_set_alert_status(999, IDS_ALERT_STATUS_ACK) == 0,
                  "gecersiz index kabul edildi!");
            CHECK(ids_set_alert_status(0, 99) == 0,
                  "gecersiz durum kabul edildi!");
            IdsGuiAlert al2[8];
            int n2 = ids_get_alerts_snapshot(al2, 8);
            CHECK(n2 >= 1 && al2[0].status == IDS_ALERT_STATUS_FALSEPOS &&
                  strstr(al2[0].note, "Analist") != NULL,
                  "triyaj durum/not yansimadi");
        }
        (void)n;
    }

    printf("== ids_clear_host_data ==\n");
    {
        IdsIncident inc2[8];
        ids_clear_host_data();
        int n = ids_get_host_threat_snapshot(&sn);
        CHECK(n == 0, "temizlik sonrasi host 0, %d", n);
        CHECK(ids_get_incidents_snapshot(inc2, 8) == 0,
              "temizlik sonrasi olay 0");
        CHECK(sn.total_flows == 0, "temizlik sonrasi akis 0, %d",
              sn.total_flows);
    }

    printf("== ids_remove_alert (satir bazli silme) ==\n");
    {
        ids_clear_alerts();
        /* 3 hosttan deterministik uyari uret: DGA(.17), DGA(.18), Tunel(.19);
         * onceki testlerin uyarilari global dedup'ta (TTL 120 sn) bastirildigi
         * icin henuz uyari uretmemis hostlar secildi. 70 sorgu -> qcount>=60
         * && dcount(40 cap)>=20. */
        for (int i = 0; i < 70; i++) {
            char q[64];
            snprintf(q, sizeof(q), "dga%02dx7wq8k.com", i);
            PacketRecord p = pkt_dns(ip4("192.168.1.17"), ip4("192.168.1.1"),
                                     40000 + i, 53, q, 0, 0);
            ids_process_packet(&p);
            PacketRecord p2 = pkt_dns(ip4("192.168.1.18"), ip4("192.168.1.1"),
                                      41000 + i, 53, q, 0, 0);
            ids_process_packet(&p2);
        }
        PacketRecord t = pkt_dns(ip4("192.168.1.19"), ip4("192.168.1.1"),
                                 42000, 53, "aabbccddeeff0011.example.com",
                                 0, 0);
        ids_process_packet(&t);
        tick_analysis();

        IdsGuiAlert before[8];
        int nb = ids_get_alerts_snapshot(before, 8);
        CHECK(nb >= 3, "remove testi: en az 3 uyari gerekli, %d", nb);

        /* Ortadaki kaydi (indeks 1) sil: sonraki kayitlar sola kaymali */
        CHECK(ids_remove_alert(1) == 1, "orta kayit silinemedi");
        IdsGuiAlert after[8];
        int na = ids_get_alerts_snapshot(after, 8);
        CHECK(na == nb - 1, "silme sonrasi sayi %d, beklenen %d", na, nb - 1);
        if (na >= 1)
            CHECK(strcmp(after[0].sig_name, before[0].sig_name) == 0,
                  "ilk kayit degismemeli: %s vs %s",
                  after[0].sig_name, before[0].sig_name);
        if (na >= 2)
            CHECK(strcmp(after[1].sig_name, before[2].sig_name) == 0,
                  "kaydirma bozuk: %s vs %s",
                  after[1].sig_name, before[2].sig_name);

        /* Gecersiz indeksler reddedilmeli */
        CHECK(ids_remove_alert(-1) == 0, "negatif indeks kabul edildi!");
        CHECK(ids_remove_alert(na) == 0, "sinir disi indeks kabul edildi!");
        CHECK(ids_remove_alert(9999) == 0, "cok buyuk indeks kabul edildi!");

        /* Sondan teker teker sil: bos dizide silme reddedilmeli */
        while (na > 0) {
            CHECK(ids_remove_alert(na - 1) == 1,
                  "sondan silme basarisiz (%d)", na);
            na = ids_get_alerts_snapshot(after, 8);
        }
        CHECK(na == 0, "tum kayitlar silinmeli, %d", na);
        CHECK(ids_remove_alert(0) == 0, "bos diziden silme kabul edildi!");
    }

    printf("== kotu amacli port: dinleme kaniti (port sahibi saldirgan) ==\n");
    {
        /* [D1] 4444'te dinleyen saldirgan (.15), istemci .23. Tek SYN uyari
         * uretmez (sahte tarama olabilir); SYN-ACK ile tamamlanan 2 baglanti
         * kaniti -> “Dinleme Servisi (Kritik Port)”. Port sahibi saldirgandir. */
        PacketRecord m = pkt_tcp(ip4("192.168.1.23"), ip4("192.168.1.15"),
                                 52000, 4444, 1);
        /* Yabanci MAC: yerel trafik bastirmasini atla (kural motoru calissin) */
        m.raw_data[6] = 0xDE; m.raw_data[7] = 0xAD;
        m.raw_data[8] = 0xBE; m.raw_data[9] = 0xEF;
        m.raw_data[10] = 0x00; m.raw_data[11] = 0x01;
        ids_process_packet(&m);

        /* SYN-ACK (0x12): dinleyici .15:4444 -> istemci .23:52000 */
        PacketRecord sa = pkt_tcp(ip4("192.168.1.15"), ip4("192.168.1.23"),
                                  4444, 52000, 0);
        sa.raw_data[6] = 0xDE; sa.raw_data[7] = 0xAD;
        sa.raw_data[8] = 0xBE; sa.raw_data[9] = 0xEF;
        sa.raw_data[10] = 0x00; sa.raw_data[11] = 0x01;
        sa.raw_data[47] |= 0x02;   /* ACK(0x10) -> SYN-ACK (0x12) */
        ids_process_packet(&sa);   /* connection_count = 1 */
        ids_process_packet(&sa);   /* connection_count = 2 -> kapidan gecer */

        IdsGuiAlert snaps[4];
        int n = ids_get_alerts_snapshot(snaps, 4);
        CHECK(n == 1, "dinleme uyarisi sayisi 1, %d", n);
        if (n >= 1) {
            IdsGuiAlert *a = &snaps[n - 1];
            CHECK(strstr(a->sig_name, "Dinleme Servisi") != NULL,
                  "imza: %s", a->sig_name);
            CHECK(a->src_port == 4444 && a->dst_port == 52000,
                  "portlar src=%u dst=%u", a->src_port, a->dst_port);
            CHECK(strcmp(a->src_ip, "192.168.1.15") == 0,
                  "src_ip: %s", a->src_ip);
            CHECK(strcmp(a->dst_ip, "192.168.1.23") == 0,
                  "dst_ip: %s", a->dst_ip);
            CHECK(a->port_owner_attacker == 1,
                  "port_owner_attacker bayragi set edilmedi");
        }
        /* Cooldown (IDS_MP_ALERT_CD=120) + dedup: ayni akis bir daha
         * uyari uretmemeli (ekstra SYN ve 3. tamamlanan baglanti). */
        uint64_t before = g_ids.total_alerts;
        ids_process_packet(&m);
        ids_process_packet(&m);
        ids_process_packet(&sa);
        CHECK(g_ids.total_alerts == before,
              "cooldown calismadi: %llu -> %llu",
              (unsigned long long)before,
              (unsigned long long)g_ids.total_alerts);
    }

    printf("== DGA yanlis pozitif korumasi (gurultu sayilmaz) ==\n");
    {
        uint64_t base = g_ids.total_alerts;

        /* 1) Normal gezinme trafiği: ayni sitenin alt alanlari + PTR +
         *    mDNS + yerel adlar. 30 sorgu -> DGA UYARISI OLMAMALI. */
        const char *benign[] = {
            "mirror0.pkgbuild.com", "mirror1.pkgbuild.com",
            "mirror2.pkgbuild.com", "geo.mirror.pkgbuild.com",
            "update.googleapis.com", "fonts.googleapis.com",
            "clients4.google.com", "www.gstatic.com",
            "0.arch.pool.ntp.org", "1.arch.pool.ntp.org",
            "ntp.ubuntu.com", "deb.debian.org",
            "ping.archlinux.org", "archlinux.org",
            "github.com", "api.github.com",
            "cloudflare.com", "www.cloudflare.com",
            "cdn.jsdelivr.net", "registry.npmjs.org",
            "15.0.168.192.in-addr.arpa", "16.0.168.192.in-addr.arpa",
            "9.4.233.178.in-addr.arpa",
            "kodi-abc123._tcp.local", "spotify-connect-01._tcp.local",
            "printer.home", "nas.internal", "router.lan",
            "localhost", "wpad",
        };
        for (size_t i = 0; i < sizeof(benign) / sizeof(benign[0]); i++) {
            PacketRecord p = pkt_dns(ip4("192.168.1.31"), ip4("192.168.1.1"),
                                     (uint16_t)(40000 + i), 53, benign[i],
                                     0, 0);
            ids_process_packet(&p);
        }
        tick_analysis();
        CHECK(g_ids.total_alerts == base,
              "benign DNS trafiği DGA uyari uretti (%llu -> %llu)",
              (unsigned long long)base,
              (unsigned long long)g_ids.total_alerts);
        int n31 = ids_get_host_threat_snapshot(&sn);
        IdsHostThreat *h31 = find_host(&sn, "192.168.1.31");
        CHECK(n31 > 0 && h31 != NULL, "benign host 31 olusmali");
        CHECK(h31 != NULL && (h31->flags & IDS_F_DNS) == 0,
              "benign host DGA bayragi aldi: %u",
              h31 ? h31->flags : 0);

        /* 2) Gercek DGA kalibi: 65+ benzersiz rastgele alan -> TAM 1
         *    uyari (yeni esik DGA_MIN_QCOUNT=60) */
        for (int i = 0; i < 65; i++) {
            char q[64];
            snprintf(q, sizeof(q), "vqkzxmtdqplx%c%c.com", (char)('a' + i / 26), (char)('a' + i % 26));
            PacketRecord p = pkt_dns(ip4("192.168.1.32"), ip4("192.168.1.1"),
                                     (uint16_t)(41000 + i), 53, q, 0, 0);
            ids_process_packet(&p);
        }
        tick_analysis();
        CHECK(g_ids.total_alerts == base + 1,
              "DGA kalibi tam 1 uyari uretmeli: %llu -> %llu",
              (unsigned long long)base,
              (unsigned long long)g_ids.total_alerts);
        IdsGuiAlert da[4];
        int dn = ids_get_alerts_snapshot(da, 4);
        CHECK(dn >= 1 && strstr(da[dn - 1].sig_name, "DGA") != NULL,
              "son uyari DGA olmali: %s",
              dn >= 1 ? da[dn - 1].sig_name : "?");

        /* Sticky: fazladan sorgu yeni uyari uretmez */
        for (int i = 65; i < 70; i++) {
            char q[64];
            snprintf(q, sizeof(q), "vqkzxmtdqplx%c%c.com", (char)('a' + i / 26), (char)('a' + i % 26));
            PacketRecord p = pkt_dns(ip4("192.168.1.32"), ip4("192.168.1.1"),
                                     (uint16_t)(41000 + i), 53, q, 0, 0);
            ids_process_packet(&p);
        }
        tick_analysis();
        CHECK(g_ids.total_alerts == base + 1,
              "DGA tekrar uyari uretti: %llu",
              (unsigned long long)g_ids.total_alerts);
    }

    printf("== izleme kapsami: bos liste = pasif, dolu = yalnizca listedekiler ==\n");
    {
        uint64_t base = g_ids.total_pkts_processed;

        /* Bos kapsam: hicbir paket islenmemeli */
        ids_scope_clear();
        PacketRecord p1 = pkt_tcp(ip4("192.168.1.15"), ip4("192.168.1.23"),
                                  52000, 4444, 1);
        p1.raw_data[6] = 0xDE; p1.raw_data[7] = 0xAD;
        p1.raw_data[8] = 0xBE; p1.raw_data[9] = 0xEF;
        p1.raw_data[10] = 0x00; p1.raw_data[11] = 0x01;
        ids_process_packet(&p1);
        CHECK(g_ids.total_pkts_processed == base,
              "bos kapsamda paket islenmemeli (%llu -> %llu)",
              (unsigned long long)base,
              (unsigned long long)g_ids.total_pkts_processed);

        /* Kapsam dolu: listedeki IP'lere ait paket islenir */
        const char *sc2[] = {"192.168.1.15"};
        ids_scope_set(sc2, 1);
        ids_process_packet(&p1);
        CHECK(g_ids.total_pkts_processed == base + 1,
              "kapsamdaki paket islenmeli (%llu)",
              (unsigned long long)g_ids.total_pkts_processed);

        /* Kapsam disi: iki ucu da listede olmayan paket islenmez */
        PacketRecord p2 = pkt_tcp(ip4("192.168.1.99"), ip4("192.168.1.23"),
                                  52000, 4444, 1);
        p2.raw_data[6] = 0xDE; p2.raw_data[7] = 0xAD;
        p2.raw_data[8] = 0xBE; p2.raw_data[9] = 0xEF;
        p2.raw_data[10] = 0x00; p2.raw_data[11] = 0x01;
        ids_process_packet(&p2);
        CHECK(g_ids.total_pkts_processed == base + 1,
              "kapsam disi paket islenmemeli (%llu)",
              (unsigned long long)g_ids.total_pkts_processed);

        /* Tekrar bosalt: yine pasif */
        ids_scope_clear();
        ids_process_packet(&p1);
        CHECK(g_ids.total_pkts_processed == base + 1,
              "tekrar bosalan kapsamda paket islenmemeli (%llu)",
              (unsigned long long)g_ids.total_pkts_processed);
    }

    printf("== Brute force yanlis pozitif duzeltmesi ==\n");
    {
        /* Izleme kapsami: oncesi scope testi kapsami bosaltti; yeniden kur. */
        static const char *sc_bf[] = {
            "192.168.1.14", "192.168.1.19", "192.168.1.30",
            "192.168.1.44", "192.168.1.77", "192.168.1.78",
        };
        ids_scope_set(sc_bf, (int)(sizeof(sc_bf) / sizeof(sc_bf[0])));
        ids_set_network_range("192.168.1.0/24");

        uint32_t browser = ip4("192.168.1.30");
        uint32_t cloudflare = ip4("104.18.41.41");
        uint64_t before = g_ids.total_alerts;

        /* (1) Normal tarayici davranisi: LAN -> genel web (443). 12 paralel
         * baglanti yanlis pozitif kaynagiydi; artik ASLA uyari yok. */
        for (int i = 0; i < 12; i++) {
            PacketRecord p = pkt_tcp_att(browser, cloudflare,
                                         (uint16_t)(43000 + i), 443, 1);
            ids_process_packet(&p);
        }
        CHECK(g_ids.total_alerts == before,
              "FP: genel web (443) tarayici trafigi uyari uretmemeli "
              "(%llu -> %llu)",
              (unsigned long long)before,
              (unsigned long long)g_ids.total_alerts);

        /* (2) Yerel web sunucusuna tek kaynaktan 62 SYN = firtina. */
        uint32_t web_vic = ip4("192.168.1.77");
        uint32_t web_att = ip4("192.168.1.78");
        for (int i = 0; i < 62; i++) {
            PacketRecord p = pkt_tcp_att(web_att, web_vic,
                                         (uint16_t)(44000 + i), 443, 1);
            ids_process_packet(&p);
        }
        {
            IdsGuiAlert al[8];
            int n = ids_get_alerts_snapshot(al, 8);
            int found = 0;
            for (int i = 0; i < n; i++) {
                if (strstr(al[i].sig_name, "Web Brute Force") != NULL) {
                    found = 1;
                    CHECK(strcmp(al[i].severity, "ORTA") == 0,
                          "web brute sev ORTA olmali, %s", al[i].severity);
                }
            }
            CHECK(found, "yerel web firtinasi 'Web Brute Force' uyarmali");
        }

        /* (3) Yerel SSH brute force: 26 SYN. */
        uint32_t ssh_vic = ip4("192.168.1.14");
        uint32_t ssh_att = ip4("192.168.1.19");
        for (int i = 0; i < 26; i++) {
            PacketRecord p = pkt_tcp_att(ssh_att, ssh_vic,
                                         (uint16_t)(45000 + i), 22, 1);
            ids_process_packet(&p);
        }
        {
            IdsGuiAlert al[8];
            int n = ids_get_alerts_snapshot(al, 8);
            int found = 0;
            for (int i = 0; i < n; i++) {
                if (strstr(al[i].sig_name, "SSH Brute Force") != NULL) {
                    found = 1;
                    CHECK(strcmp(al[i].severity, "KRITIK") == 0,
                          "SSH brute sev KRITIK olmali, %s", al[i].severity);
                }
            }
            CHECK(found, "yerel SSH brute force uyarmali");
        }

        /* (4) Dis hedefe (internet SSH sunucusu) brute force: 26 SYN;
         * aciklamada '(dis hedef)' ibaresi olmali. */
        uint32_t ext_ssh = ip4("203.0.113.9");
        uint32_t ext_att = ip4("192.168.1.44");
        for (int i = 0; i < 26; i++) {
            PacketRecord p = pkt_tcp_att(ext_att, ext_ssh,
                                         (uint16_t)(46000 + i), 22, 1);
            ids_process_packet(&p);
        }
        {
            IdsGuiAlert al[8];
            int n = ids_get_alerts_snapshot(al, 8);
            int found = 0;
            for (int i = 0; i < n; i++) {
                if (strstr(al[i].sig_name, "SSH Brute Force") != NULL &&
                    al[i].description[0] &&
                    strstr(al[i].description, "(dis hedef)") != NULL) {
                    found = 1;
                }
            }
            CHECK(found, "dis hedef SSH brute '(dis hedef)' ibaresi icermeli");
        }
    }

    printf("== [14] malport yanlis pozitif duzeltmeleri ==\n");

    /* (1) Yetim SYN-ACK (self nmap senaryosu): kendi SYN'lerimiz
     * (.15 -> .22:1099) self filtresiyle bastiriliyor, hedefin SYN-ACK'leri
     * yetim kalip YANLIS “Dinleme Servisi (Kritik Port)” uretiyordu —
     * eslesen SYN kaniti olmayan SYN-ACK artik hicbir sey uretmemeli. */
    {
        uint64_t before = g_ids.total_alerts;
        for (int i = 0; i < 3; i++) {
            PacketRecord p = pkt_tcp_att(ip4("192.168.1.77"),
                                         ip4("192.168.1.78"),
                                         1099, (uint16_t)(47000 + i), 0);
            p.raw_data[47] |= 0x02;   /* ACK(0x10) -> SYN-ACK (0x12) */
            ids_process_packet(&p);
        }
        CHECK(g_ids.total_alerts == before,
              "[14] yetim SYN-ACK (1099) yanlis dinleme alarmi uretmemeli "
              "(%llu -> %llu)",
              (unsigned long long)before,
              (unsigned long long)g_ids.total_alerts);
    }

    /* (2) Gercek yerel dinleyici: dis istemci (.78) -> .15:5555 SYN atar;
     * kendi dinleyicimiz SYN-ACK ile cevaplar (self). Self SYN-ACK artik
     * filtrelenmiyor; ilk SYN-ACK'te aninda KRITIK “Dinleme Servisi”
     * alarmi beklenir. */
    {
        uint64_t before = g_ids.total_alerts;

        /* Tek SYN tek basina dinleme kaniti degil: uyari yok */
        PacketRecord syn = pkt_tcp_att(ip4("192.168.1.78"),
                                       ip4("192.168.1.15"),
                                       55218, 5555, 1);
        ids_process_packet(&syn);
        CHECK(g_ids.total_alerts == before,
              "[14] tek SYN dinleme alarmi uretmemeli (%llu -> %llu)",
              (unsigned long long)before,
              (unsigned long long)g_ids.total_alerts);

        /* Self SYN-ACK: dinleme kaniti -> aninda 1 alarm */
        PacketRecord sa = pkt_tcp(ip4("192.168.1.15"), ip4("192.168.1.78"),
                                  5555, 55218, 0);
        sa.raw_data[47] |= 0x02;   /* ACK(0x10) -> SYN-ACK (0x12) */
        ids_process_packet(&sa);

        CHECK(g_ids.total_alerts == before + 1,
              "[14] ilk SYN-ACK'te aninda 1 dinleme alarmi beklenir "
              "(%llu -> %llu)",
              (unsigned long long)before,
              (unsigned long long)g_ids.total_alerts);

        IdsGuiAlert al[8];
        int n = ids_get_alerts_snapshot(al, 8);
        int found = 0;
        for (int i = 0; i < n; i++) {
            if (strstr(al[i].sig_name, "Dinleme Servisi") != NULL &&
                al[i].src_port == 5555) {
                found = 1;
                CHECK(strcmp(al[i].severity, "KRITIK") == 0,
                      "[14] gercek dinleyici sev KRITIK olmali, %s",
                      al[i].severity);
                CHECK(al[i].src_port == 5555 && al[i].dst_port == 55218,
                      "[14] portlar src=%u dst=%u",
                      al[i].src_port, al[i].dst_port);
                CHECK(strstr(al[i].description,
                             "1 tamamlanan baglanti") != NULL,
                      "[14] aciklama aninda dogrulamali: %s",
                      al[i].description);
            }
        }
        CHECK(found,
              "[14] gercek dinleyici (.15:5555) 'Dinleme Servisi' uyarmali");
    }

    printf("== 500 portluk taramada farkli-port sayaci\n");
    printf("==                         64'te DOYUMA UGRAMAZ ==\n");
    {
        /* IdsTracker.unique[64] doyuma ugrayinca nmap taramasi hep “64 farkli
         * port” raporluyordu. Yama: port alani (0..65535) icin 8192 baytlık
         * bitmap; ilk 64 ornek rapor icin korunur, 65. portta bitmap gecer. */
        static const char *sig = "Yerel Kaynakli Port Taramasi";
        /* Tarayan kaynak: bu ana kadar HIC trafik uretmemis taze bir LAN
         * adresi secildi — onceki bloklarin .10'dan biraktigi paketler ayni
         * 10 sn'lik pencereye dusup “N paket” olcumunu bozmasin. Bitmap
         * mantigi kaynaktan bagimsizdir (anahtar: “L|<src_ip>”). */
        static const char *src = "192.168.1.60";   /* LAN kokenli kaynak */
        IdsGuiAlert al[16];
        int n, last, u, pk;

        /* Onceki bloklar kapsami degistirdi (sc_bf); hedefler (.101, .23) o
         * kapsamda olmadigi icin paketler kapsam suzgecinde dusuyordu. Kapsam
         * bu blokta yeniden kurulur, temiz sayfayla baslanir (bos listede
         * motor bastirmayi serbest birakip yayinlar). */
        static const char *sc17[] = {"192.168.1.60", "192.168.1.101",
                                     "192.168.1.23"};
        ids_scope_set(sc17, 3);
        ids_clear_alerts();

        for (int port = 1; port <= 500; port++) {
            PacketRecord p = pkt_tcp(ip4(src), ip4("192.168.1.101"),
                                     40000, (uint16_t)port, 1);
            ids_process_packet(&p);
        }
        n = ids_get_alerts_snapshot(al, 16);
        last = -1;
        for (int i = 0; i < n; i++)
            if (strcmp(al[i].sig_name, sig) == 0 &&
                strcmp(al[i].src_ip, src) == 0) {
                last = i;
            }
        CHECK(last >= 0, "500 portluk tarama L| uyarisi uretmeli (n=%d)", n);
        if (last >= 0) {
            u = pk = -1;
            CHECK(sscanf(al[last].description,
                         "%*s -> %d farkli porta disari SYN taramasi (%d paket)",
                         &u, &pk) == 2,
                  "aciklama ayristirilamadi: %s", al[last].description);
            CHECK(u == 500,
                  "500 farkli port TAM sayilmali (doyum hatasi), %d", u);
            CHECK(pk == 500, "paket sayaci 500 olmali, %d", pk);
        }

        /* 2) Pencere sonunda (IDS_WINDOW_SEC) bitmap sifirlanmazsa onceki
         * pencerenin portlari da sayilir (500 + 20 = 520 gibi gorunurdu).
         * Beklenti: tam 20. */
        sleep(IDS_WINDOW_SEC + 1);
        for (int i = 0; i < 20; i++) {
            PacketRecord p = pkt_tcp(ip4(src), ip4("192.168.1.23"),
                                     (uint16_t)(41000 + i),
                                     (uint16_t)(6000 + i), 1);
            ids_process_packet(&p);
        }
        n = ids_get_alerts_snapshot(al, 16);
        last = -1;
        for (int i = 0; i < n; i++)
            if (strcmp(al[i].sig_name, sig) == 0 &&
                strcmp(al[i].src_ip, src) == 0) {
                last = i;
            }
        CHECK(last >= 0, "pencere sonrasi L| satiri bulunamadi (n=%d)", n);
        if (last >= 0) {
            u = pk = -1;
            CHECK(sscanf(al[last].description,
                         "%*s -> %d farkli porta disari SYN taramasi (%d paket)",
                         &u, &pk) == 2,
                  "aciklama ayristirilamadi: %s", al[last].description);
            CHECK(u == 20,
                  "pencere kapaninca farkli-port sayaci SIFIRLANMALI "
                  "(eski pencerenin portlari sizmamali), %d", u);
            CHECK(pk == 20, "yeni pencerede paket sayaci 20 olmali, %d", pk);
        }
    }


    /* ==============================================================
     * UZUN UFUK — YAVAS (HIZ SINIRLAMALI) TARAMA
     * ==============================================================
     * nmap --scan-delay 1.5s kisa pencereye en fazla 5-7 farkli port
     * birakir; “8 farkli port” esikli S|/L| kurallari bu yuzden hic
     * tetiklenmezdi (yavaslatmak = kacmak). Ikinci ufuk: kisa pencere
     * iskalarsa ve gozlem suresi min_span'i gecerse uyarir; patlamalar
     * cift raporlanmaz (long_short_hit). Test esikleri kucultur (idle_gap=3,
     * max_window=60, min_span=2, thr=6); mantik uretimle birebir aynidir.
     */
    printf("== yavas (hiz sinirlamali) tarama uzun ufukta ==\n");
    {
        IdsGuiAlert al[16];
        static const char *short_sig = "Yerel Kaynakli Port Taramasi";
        static const char *long_sig  = "Yavas Port Taramasi (Yerel Kaynakli)";
        const char *slow_src = "192.168.1.150";   /* yavas tarayan kaynak */
        const char *fast_src = "192.168.1.151";   /* hizli patlama kaynagi */

        /* Onceki bloklar kapsami degistirdi (sc17); kapsam disi paketler
         * daha ids_process_packet icinde dusup hicbir kural calistirmaz
         * (gercek trafikte de ayni tuzak). Kapsam blok icinde kurulur ve
         * temiz sayfayla baslanir. */
        static const char *sc18[] = { "192.168.1.20",
                                      "192.168.1.150", "192.168.1.151" };
        ids_scope_set(sc18, 3);
        ids_clear_alerts();

        /* --- FAZ 0: uretim varsayilanlari beklenen degerlerde mi ------- */
        int di = -1, dm = -1, dsn = -1, dt = -1;
        ids_get_scan_window_params(&di, &dm, &dsn, &dt);
        CHECK(di == IDS_SCAN_IDLE_GAP_SEC && dm == IDS_SCAN_LONG_WINDOW_SEC &&
              dsn == IDS_SCAN_MIN_SPAN_SEC && dt == IDS_SCAN_LONG_UNIQUE,
              "uretim varsayilanlari korunmali: %d/%d/%d/%d (beklenen %d/%d/%d/%d)",
              di, dm, dsn, dt, IDS_SCAN_IDLE_GAP_SEC, IDS_SCAN_LONG_WINDOW_SEC,
              IDS_SCAN_MIN_SPAN_SEC, IDS_SCAN_LONG_UNIQUE);

        ids_set_scan_window_params(3, 60, 2, 6);
        ids_get_scan_window_params(&di, &dm, &dsn, &dt);
        CHECK(di == 3 && dm == 60 && dsn == 2 && dt == 6,
              "test parametreleri uygulanmali: %d/%d/%d/%d", di, dm, dsn, dt);

        /* --- FAZ A: kisa pencereyi ISKALAYAN yavas tarama yakalanmali --- */
        int n = ids_get_alerts_snapshot(al, 16);
        int long_before = 0, short_before = 0;
        for (int i = 0; i < n; i++) {
            if (strcmp(al[i].sig_name, long_sig) == 0) long_before++;
            if (strcmp(al[i].sig_name, short_sig) == 0 &&
                strcmp(al[i].src_ip, slow_src) == 0) short_before++;
        }
        CHECK(n == 0, "temiz sayfa ile baslanmali (ids_clear_alerts), n=%d", n);
        CHECK(long_before == 0,
              "uzun ufuk satiri onceden bulunmamali, %d", long_before);
        CHECK(short_before == 0,
              "%s icin kisa pencere satiri onceden olmamali, %d",
              slow_src, short_before);

        uint64_t t_a = g_ids.total_alerts;
        /* 7 FARKLI hedef port, ~0.7 sn aralikla (toplam ~4 sn gozlem).
         * Kisa pencerede yalnizca 7 farkli port -> S|/L| (8) SESSIZ kalir;
         * uzun ufuk (thr=6, min_span=2) YAKALAMALI. */
        for (int i = 0; i < 7; i++) {
            PacketRecord p = pkt_tcp(ip4(slow_src), ip4("192.168.1.20"),
                                     (uint16_t)(55000 + i),
                                     (uint16_t)(700 + i), 1);
            ids_process_packet(&p);
            usleep(700000);
        }

        n = ids_get_alerts_snapshot(al, 16);
        int lrow = -1, short_rows = 0;
        for (int i = 0; i < n; i++) {
            if (strcmp(al[i].sig_name, long_sig) == 0) lrow = i;
            if (strcmp(al[i].sig_name, short_sig) == 0 &&
                strcmp(al[i].src_ip, slow_src) == 0) short_rows++;
        }
        CHECK(short_rows == 0,
              "7 farkli port kisa esigi (8) ASMAMALI -> kisa kural sessiz, %d",
              short_rows);
        CHECK(lrow >= 0,
              "YAVAS tarama uzun ufukta YAKALANMALI (sessiz yanlis negatif!)");
        CHECK(g_ids.total_alerts > t_a,
              "uzun ufuk bir uyari YAYINLAMALI (%llu -> %llu)",
              (unsigned long long)t_a, (unsigned long long)g_ids.total_alerts);

        char descA[128] = "";
        int lu = -1, lp = -1, lsec = -1;
        if (lrow >= 0) {
            CHECK(strcmp(al[lrow].severity, "YUKSEK") == 0,
                  "uzun ufuk uyarisi YUKSEK olmali: %s", al[lrow].severity);
            CHECK(strstr(al[lrow].description, "YAVAS") != NULL,
                  "aciklama 'yavas' ayrimini tasimali: %s",
                  al[lrow].description);
            CHECK(sscanf(al[lrow].description,
                         "%*s -> %d farkli porta YAVAS disari SYN taramasi "
                         "(%d paket, %d sn)", &lu, &lp, &lsec) == 3,
                  "aciklama ayristirilamadi: %s", al[lrow].description);
            CHECK(lu >= 6, "uzun ufuk esigi (6) asilmali: %d", lu);
            CHECK(lsec >= 2, "gozlem suresi min_span'i gecmeli: %d sn", lsec);
            CHECK(strcmp(al[lrow].dst_ip, "192.168.1.20") == 0,
                  "hedef alani dogru olmali: %s", al[lrow].dst_ip);
            snprintf(descA, sizeof(descA), "%s", al[lrow].description);
        }

        /* --- FAZ B: BOSLUK (idle gap) ufku SIFIRLAMALI -----------------
         * IDS_WINDOW_SEC+1 beklenir: kisa pencere kapanir, uzun ufuk bosluga
         * duser; yeni ufukta 6 farkli port gorunmeli (sifirlama calismazsa
         * 7+6=13 olurdu). */
        sleep(IDS_WINDOW_SEC + 1);
        for (int i = 0; i < 6; i++) {
            PacketRecord p = pkt_tcp(ip4(slow_src), ip4("192.168.1.20"),
                                     (uint16_t)(55100 + i),
                                     (uint16_t)(800 + i), 1);
            ids_process_packet(&p);
            usleep(600000);
        }
        n = ids_get_alerts_snapshot(al, 16);
        int l2 = -1;
        for (int i = 0; i < n; i++)
            if (strcmp(al[i].sig_name, long_sig) == 0) l2 = i;
        CHECK(l2 >= 0, "uzun ufuk satiri kaybolmamali (n=%d)", n);
        if (l2 >= 0) {
            int u2 = -1, p2 = -1, s2 = -1;
            CHECK(sscanf(al[l2].description,
                         "%*s -> %d farkli porta YAVAS disari SYN taramasi "
                         "(%d paket, %d sn)", &u2, &p2, &s2) == 3,
                  "aciklama ayristirilamadi: %s", al[l2].description);
            CHECK(u2 == 6,
                  "BOSLUK ufku SIFIRLAMALI: yeni ufukta TAM 6 farkli port "
                  "olmali (eski sayac sizsaydi 13 olurdu), %d", u2);
            CHECK(s2 <= 4,
                  "yeni ufkun gozlem suresi kucuk olmali (eski ufkun basi "
                  "tasindiysa buyuk cikar): %d sn", s2);
            if (strlen(descA) > 0)
                CHECK(strcmp(al[l2].description, descA) != 0,
                      "metin yeni ufkun sayilariyla TAZELENMELI, %s",
                      al[l2].description);
        }

        /* --- FAZ C: Kisa kuralin yakaladigi patlama CIFT raporlanmaz ----
         * 8 farkli port ANINDA L| kisa kuralini tetikler; ufuk canli tutulup
         * min_span asilirsa uzun ufkun tum kosullari saglansa da long_short_hit
         * kilidi yuzunden susmali (aksi halde cift satir olusur). */
        int burst = 0;
        for (int i = 0; i < 8; i++) {
            PacketRecord p = pkt_tcp(ip4(fast_src), ip4("192.168.1.20"),
                                     (uint16_t)(56000 + i),
                                     (uint16_t)(900 + i), 1);
            ids_process_packet(&p);
        }
        for (int i = 0; i < 4; i++) {
            sleep(1);
            PacketRecord p = pkt_tcp(ip4(fast_src), ip4("192.168.1.20"),
                                     (uint16_t)(56100 + i),
                                     (uint16_t)(950 + i), 1);
            ids_process_packet(&p);
            burst++;
        }
        n = ids_get_alerts_snapshot(al, 16);
        int fast_short = 0, fast_long = 0, all_long = 0;
        for (int i = 0; i < n; i++) {
            if (strcmp(al[i].sig_name, long_sig) == 0) {
                all_long++;
                if (strcmp(al[i].src_ip, fast_src) == 0) fast_long++;
            }
            if (strcmp(al[i].sig_name, short_sig) == 0 &&
                strcmp(al[i].src_ip, fast_src) == 0) fast_short++;
        }
        CHECK(burst == 4, "canli tutma paketleri gonderildi, %d", burst);
        CHECK(fast_short >= 1,
              "HIZLI patlama kisa kural tarafindan raporlanmali, %d",
              fast_short);
        CHECK(fast_long == 0,
              "kisa kuralin yakaladigi patlama uzun ufukta CIFT "
              "raporlanmamali, %d", fast_long);
        CHECK(all_long == 1,
              "listede yalnizca %s kaynakli uzun ufuk satiri olmali, %d",
              slow_src, all_long);

        /* Test degerleri uretim varsayilanlarina geri alinir (sonraki
         * bloklar ve gercek calisma etkilenmesin). */
        ids_set_scan_window_params(IDS_SCAN_IDLE_GAP_SEC,
                                   IDS_SCAN_LONG_WINDOW_SEC,
                                   IDS_SCAN_MIN_SPAN_SEC,
                                   IDS_SCAN_LONG_UNIQUE);
        ids_get_scan_window_params(&di, &dm, &dsn, &dt);
        CHECK(di == IDS_SCAN_IDLE_GAP_SEC && dm == IDS_SCAN_LONG_WINDOW_SEC &&
              dsn == IDS_SCAN_MIN_SPAN_SEC && dt == IDS_SCAN_LONG_UNIQUE,
              "uretim varsayilanlari geri yuklenmeli: %d/%d/%d/%d",
              di, dm, dsn, dt);
    }

    ids_cleanup();

    printf("\n%d test, %d basarisiz\n", g_total, g_failed);
    return g_failed ? 1 : 0;
}















