/*
 * pcap_agent_network.c — Ağ İşleme Katmanı
 * 
 * IP dönüşüm, entropi hesabı, akım (flow) yönetimi,
 * paket parsing ve feature vektörü çıkarımı.
 * 
 * IPv4 + IPv6 desteği.
 */
#include "pcap_agent.h"
#include <math.h>

/* ================================================================
 * IP / Entropi Yardımcıları
 * ================================================================ */
void pa_ip_to_str(uint32_t ip, char *buf) {
    unsigned char *p = (unsigned char *)&ip;
    snprintf(buf, 16, "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
}

uint32_t pa_str_to_ip(const char *str) {
    uint32_t ip = 0;
    unsigned char b[4] = {0};
    if (sscanf(str, "%hhu.%hhu.%hhu.%hhu", &b[0], &b[1], &b[2], &b[3]) == 4)
        memcpy(&ip, b, 4);
    return ip;
}

double pa_calc_entropy(const uint8_t *data, int len) {
    if (len <= 0) return 0.0;
    double freq[256] = {0};
    for (int i = 0; i < len; i++) freq[data[i]]++;
    double ent = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = freq[i] / (double)len;
            ent -= p * log2(p);
        }
    }
    return ent;
}

/* ================================================================
 * Akım (flow) bul / ekle
 * ================================================================ */
static pa_flow_t *get_flow(pa_agent_t *a, uint32_t sip, uint32_t dip,
                           uint16_t sp, uint16_t dp, uint8_t proto)
{
    /* Mevcut flow'u bul */
    for (int i = 0; i < a->flow_count; i++) {
        pa_flow_t *f = &a->flows[i];
        if (f->src_ip == sip && f->dst_ip == dip &&
            f->src_port == sp && f->dst_port == dp &&
            f->proto == proto)
            return f;
    }
    if (a->flow_count >= PA_MAX_FLOWS) return NULL;

    pa_flow_t *f = &a->flows[a->flow_count++];
    memset(f, 0, sizeof(pa_flow_t));
    f->src_ip   = sip;  f->dst_ip   = dip;
    f->src_port = sp;   f->dst_port = dp;
    f->proto    = proto;
    f->start    = time(NULL);
    f->last     = f->start;
    return f;
}

/* ================================================================
 * Burst ring buffer'a feature satırı ekle
 * ================================================================ */
static void push_burst_row(pa_agent_t *a, pa_feature_t *fv) {
    if (a->burst_idx >= PA_BURST_LEN) {
        a->burst_idx = 0;
        a->burst_full = 1;
    }
    memcpy(a->burst_features[a->burst_idx], fv, sizeof(pa_feature_t));
    a->burst_idx++;
}

/* ================================================================
 * Dahili paket header yapıları (portable)
 * ================================================================ */
#ifdef _WIN32
  #pragma pack(push, 1)
#endif

typedef struct {
    uint8_t  dst[PA_ETH_ALEN];
    uint8_t  src[PA_ETH_ALEN];
    uint16_t type;
}
#ifdef __GNUC__
  __attribute__((packed))
#endif
pa_eth_hdr_t;

typedef struct {
    uint8_t  ver_ihl;
    uint8_t  dscp_ecn;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  proto;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
}
#ifdef __GNUC__
  __attribute__((packed))
#endif
pa_ip_hdr_t;

/* IPv6 header (40 byte sabit) */
typedef struct {
    uint32_t ver_tc_flow;    /* version(4) + traffic class(8) + flow label(20) */
    uint16_t payload_len;
    uint8_t  next_header;    /* L4 protokol (6=TCP, 17=UDP, 58=ICMPv6) */
    uint8_t  hop_limit;
    uint8_t  src_addr[16];
    uint8_t  dst_addr[16];
}
#ifdef __GNUC__
  __attribute__((packed))
#endif
pa_ipv6_hdr_t;

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t  offset;
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urg_ptr;
}
#ifdef __GNUC__
  __attribute__((packed))
#endif
pa_tcp_hdr_t;

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len;
    uint16_t checksum;
}
#ifdef __GNUC__
  __attribute__((packed))
#endif
pa_udp_hdr_t;

#ifdef _WIN32
  #pragma pack(pop)
#endif

/* TCP bayrakları */
#define PA_TH_SYN  0x02
#define PA_TH_RST  0x04
#define PA_TH_ACK  0x10

/* IPv6 next header değerleri */
#define PA_NH_TCP     6
#define PA_NH_UDP     17
#define PA_NH_ICMPV6  58

/* IPv6 adresinden basit bir 32-bit hash üret (flow tablosu için) */
static uint32_t ipv6_hash(const uint8_t *addr) {
    uint32_t h = 0;
    for (int i = 0; i < 16; i += 4) {
        uint32_t w;
        memcpy(&w, addr + i, 4);
        h ^= w;
    }
    return h;
}

/* IPv6 adresini string'e çevir (kısaltılmış) */
static void ipv6_to_str(const uint8_t *addr, char *buf, int buflen) {
    snprintf(buf, buflen, "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
             addr[0], addr[1], addr[2], addr[3],
             addr[12], addr[13], addr[14], addr[15]);
}

/* ================================================================
 * L4 işleme (TCP/UDP/ICMP) — hem IPv4 hem IPv6'dan çağrılır
 * ================================================================ */
static void process_l4(pa_agent_t *a, const uint8_t *pkt, int pkt_len,
                       int l4_offset, int l4_len, uint8_t proto,
                       uint32_t src_ip_hash, uint32_t dst_ip_hash,
                       const char *sip_str, const char *dip_str,
                       uint8_t ttl_or_hop, struct timeval *ts)
{
    pa_feature_t fv;
    memset(&fv, 0, sizeof(fv));

    uint16_t src_port = 0, dst_port = 0;
    uint8_t tcp_flags = 0;

    if (proto == 6) { /* TCP */
        if (l4_len < (int)sizeof(pa_tcp_hdr_t)) return;
        pa_tcp_hdr_t *tcp = (pa_tcp_hdr_t *)(pkt + l4_offset);
        src_port  = ntohs(tcp->src_port);
        dst_port  = ntohs(tcp->dst_port);
        tcp_flags = tcp->flags;
        fv.tcp_window_mean = ntohs(tcp->window);
        fv.ttl_mean = ttl_or_hop;

        int tcp_hdr_len = ((tcp->offset >> 4) & 0x0F) * 4;
        if (tcp_hdr_len < 20) tcp_hdr_len = 20;
        int payload_len = l4_len - tcp_hdr_len;
        if (payload_len < 0) payload_len = 0;

        if (tcp_flags & PA_TH_SYN) fv.syn_rate = 1.0;
        if (tcp_flags & PA_TH_RST) fv.rst_rate = 1.0;

        if (payload_len > 0) {
            uint8_t *payload = (uint8_t *)tcp + tcp_hdr_len;
            fv.payload_entropy = pa_calc_entropy(payload,
                                    payload_len > 128 ? 128 : payload_len);
        }

    } else if (proto == 17) { /* UDP */
        if (l4_len < (int)sizeof(pa_udp_hdr_t)) return;
        pa_udp_hdr_t *udp = (pa_udp_hdr_t *)(pkt + l4_offset);
        src_port = ntohs(udp->src_port);
        dst_port = ntohs(udp->dst_port);
        fv.ttl_mean = ttl_or_hop;

        uint8_t *payload = (uint8_t *)udp + sizeof(pa_udp_hdr_t);
        int payload_len = l4_len - (int)sizeof(pa_udp_hdr_t);
        if (payload_len < 0) payload_len = 0;

        /* DNS tespiti */
        if (src_port == 53 || dst_port == 53) {
            if (payload_len > 12) {
                fv.dns_query_len_mean = payload_len;
                fv.dns_query_count = 1;
                int qname_len = payload_len > 40 ? 40 : payload_len;
                int ent_len = qname_len - 12;
                if (ent_len > 0)
                    fv.payload_entropy = pa_calc_entropy(payload + 12, ent_len);
            }
        } else {
            fv.payload_entropy = pa_calc_entropy(payload,
                                    payload_len > 128 ? 128 : payload_len);
        }

    } else if (proto == 1 || proto == PA_NH_ICMPV6) { /* ICMP / ICMPv6 */
        fv.icmp_ratio = 1.0;
        fv.ttl_mean = ttl_or_hop;
        if (l4_len > 0) {
            uint8_t *payload = (uint8_t *)(pkt + l4_offset);
            fv.payload_entropy = pa_calc_entropy(payload,
                                    l4_len > 64 ? 64 : l4_len);
        }
    } else {
        /* Bilinmeyen protokol — yine de feature çıkar */
        fv.ttl_mean = ttl_or_hop;
        if (l4_len > 0) {
            uint8_t *payload = (uint8_t *)(pkt + l4_offset);
            fv.payload_entropy = pa_calc_entropy(payload,
                                    l4_len > 64 ? 64 : l4_len);
        }
    }

    fv.pkt_size_mean = pkt_len;
    fv.byte_rate     = pkt_len;

    /* Akım güncelle */
    pa_flow_t *fl = get_flow(a, src_ip_hash, dst_ip_hash,
                             src_port, dst_port, proto);
    if (fl) {
        fl->packets++;
        fl->bytes += (uint64_t)pkt_len;
        fl->last   = ts ? ts->tv_sec : time(NULL);
        if (tcp_flags & PA_TH_SYN) fl->syn_seen = 1;
        if (tcp_flags & PA_TH_RST) fl->rst_seen = 1;

        fv.flow_count       = 1;
        fv.unique_dst_ports = 1;
        fv.unique_src_ips   = 1;
    }

    /* Burst ring buffer'a ekle */
    push_burst_row(a, &fv);

    /* Flow temizliği: %90 dolunca eski flow'ları at */
    if (a->flow_count > (int)(PA_MAX_FLOWS * 0.9)) {
        time_t now = ts ? ts->tv_sec : time(NULL);
        int keep = 0;
        for (int i = 0; i < a->flow_count; i++) {
            if (now - a->flows[i].last < 60) {
                if (keep != i)
                    memcpy(&a->flows[keep], &a->flows[i], sizeof(pa_flow_t));
                keep++;
            }
        }
        a->flow_count = keep;
    }
}

/* ================================================================
 * Paket İşleme — hem offline hem canlı trafikte kullanılır
 * IPv4 + IPv6 desteği
 * ================================================================ */
void pa_agent_process_pkt(pa_agent_t *a, const uint8_t *pkt,
                          int len, struct timeval *ts)
{
    if (len < (int)sizeof(pa_eth_hdr_t)) return;

    /* İstatistik: her paketi say (IP olsun olmasın) */
    a->total_pkts_processed++;
    a->total_bytes_processed += (uint64_t)len;

    pa_eth_hdr_t *eth = (pa_eth_hdr_t *)pkt;
    uint16_t eth_type = ntohs(eth->type);

    /* ---- IPv4 ---- */
    if (eth_type == 0x0800) {
        if (len < (int)(sizeof(pa_eth_hdr_t) + sizeof(pa_ip_hdr_t))) return;

        pa_ip_hdr_t *ip = (pa_ip_hdr_t *)(pkt + sizeof(pa_eth_hdr_t));
        int ip_hdr_len = (ip->ver_ihl & 0x0F) * 4;
        if (ip_hdr_len < 20) return;

        int ip_total_len = ntohs(ip->tot_len);
        if (ip_total_len > len - (int)sizeof(pa_eth_hdr_t)) return;

        int l4_offset = (int)sizeof(pa_eth_hdr_t) + ip_hdr_len;
        int l4_len    = ip_total_len - ip_hdr_len;

        char sip_str[16], dip_str[16];
        pa_ip_to_str(ip->src_ip, sip_str);
        pa_ip_to_str(ip->dst_ip, dip_str);

        process_l4(a, pkt, len, l4_offset, l4_len, ip->proto,
                   ip->src_ip, ip->dst_ip, sip_str, dip_str,
                   ip->ttl, ts);
    }
    /* ---- IPv6 ---- */
    else if (eth_type == 0x86DD) {
        int ipv6_offset = (int)sizeof(pa_eth_hdr_t);
        if (len < ipv6_offset + (int)sizeof(pa_ipv6_hdr_t)) return;

        pa_ipv6_hdr_t *ip6 = (pa_ipv6_hdr_t *)(pkt + ipv6_offset);
        int payload_len = ntohs(ip6->payload_len);
        uint8_t next_hdr = ip6->next_header;

        int l4_offset = ipv6_offset + 40;  /* IPv6 header sabit 40 byte */
        int l4_len    = payload_len;
        if (l4_offset + l4_len > len)
            l4_len = len - l4_offset;
        if (l4_len < 0) return;

        /* Extension header'ları atla (basit: sadece bilinen olanlar) */
        /* 0=Hop-by-Hop, 43=Routing, 44=Fragment, 60=Destination */
        while (next_hdr == 0 || next_hdr == 43 || next_hdr == 60) {
            if (l4_len < 8) return;
            uint8_t ext_next = pkt[l4_offset];
            int ext_len = (pkt[l4_offset + 1] + 1) * 8;
            l4_offset += ext_len;
            l4_len    -= ext_len;
            next_hdr   = ext_next;
            if (l4_len < 0) return;
        }
        /* Fragment header (44) — 8 byte sabit */
        if (next_hdr == 44) {
            if (l4_len < 8) return;
            next_hdr   = pkt[l4_offset];
            l4_offset += 8;
            l4_len    -= 8;
            if (l4_len < 0) return;
        }

        uint32_t src_hash = ipv6_hash(ip6->src_addr);
        uint32_t dst_hash = ipv6_hash(ip6->dst_addr);

        char sip_str[40], dip_str[40];
        ipv6_to_str(ip6->src_addr, sip_str, sizeof(sip_str));
        ipv6_to_str(ip6->dst_addr, dip_str, sizeof(dip_str));

        process_l4(a, pkt, len, l4_offset, l4_len, next_hdr,
                   src_hash, dst_hash, sip_str, dip_str,
                   ip6->hop_limit, ts);
    }
    /* ARP veya diğer eth_type'lar — yine de feature çıkar */
    else {
        pa_feature_t fv;
        memset(&fv, 0, sizeof(fv));
        fv.pkt_size_mean = len;
        fv.byte_rate     = len;
        if (eth_type == 0x0806) {
            fv.icmp_ratio = 0.5;
        }
        push_burst_row(a, &fv);
    }

    /* Her 1000 pakette bir sınıflandırma yap (tüm paket tipleri için) */
    if (a->sig_count > 0 && a->total_pkts_processed % 1000 == 0 &&
        a->total_pkts_processed > 0) {
        pa_feature_t burst_fv;
        memset(&burst_fv, 0, sizeof(burst_fv));

        int n = a->burst_full ? PA_BURST_LEN : a->burst_idx;
        if (n > 50) {
            for (int i = 0; i < PA_FEATURE_DIM; i++) {
                double sum = 0.0;
                for (int j = 0; j < n; j++)
                    sum += a->burst_features[j][i];
                ((double *)&burst_fv)[i] = sum / n;
            }

            /* Son paketin IP bilgisini kullan (veya fallback) */
            char sip[46] = "0.0.0.0", dip[46] = "0.0.0.0";
            if (eth_type == 0x0800 &&
                len >= (int)(sizeof(pa_eth_hdr_t) + sizeof(pa_ip_hdr_t))) {
                pa_ip_hdr_t *ip = (pa_ip_hdr_t *)(pkt + sizeof(pa_eth_hdr_t));
                pa_ip_to_str(ip->src_ip, sip);
                pa_ip_to_str(ip->dst_ip, dip);
            }

            fprintf(stderr, "[DBG] CLASSIFY CALLED sig_count=%d burst_n=%d\n", a->sig_count, n); pa_agent_classify(a, &burst_fv, sip, dip, 0, 0,
                              ts ? ts->tv_sec : time(NULL));
        }
    }
}
