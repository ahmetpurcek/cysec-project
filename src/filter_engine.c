/*
 * filter_engine.c — Wireshark-tarzı display filtre motoru.
 *
 * Bellek ayırmaz (malloc yok); tüm işlem yığın (stack) üzerinde yürür.
 * İfade küçük harfe çevrilip parçalanır; karşılaştırmalar büyük/küçük
 * harf duyarsızdır. Ayrıntılı sözdizimi: include/filter_engine.h
 */
#include "filter_engine.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#define FX_MAX_EXPR    512    /* en uzun ifade */
#define FX_MAX_TERMS   24     /* en fazla terim (and/or ayrımı) */
#define FX_MAX_VALUE   96     /* tek bir değerin en uzun hali */
#define FX_MAX_FIELD   48     /* alan adı uzunluğu */

typedef enum {
    FX_F_IP, FX_F_IP_SRC, FX_F_IP_DST,
    FX_F_MAC, FX_F_MAC_SRC, FX_F_MAC_DST,
    FX_F_PORT,
    FX_F_TCP_PORT, FX_F_TCP_SPORT, FX_F_TCP_DPORT,
    FX_F_UDP_PORT, FX_F_UDP_SPORT, FX_F_UDP_DPORT,
    FX_F_PROTO, FX_F_INFO,
    FX_F_NONE
} FxField;

typedef enum { FX_OP_EQ = 0, FX_OP_NEQ, FX_OP_CONTAINS } FxOp;

typedef struct {
    FxField field;                 /* FX_F_NONE => çıplak sözcük */
    FxOp op;
    char value[FX_MAX_VALUE + 1];  /* küçük harfe çevrilmiş */
} FxTerm;

/* AND/OR ayraç tipleri */
#define FX_SEP_AND 1
#define FX_SEP_OR  2

/* ---------------- basit string yardımcıları ---------------- */

static char fx_lc(char c) {
    return (c >= 'A' && c <= 'Z') ? (char)(c + ('a' - 'A')) : c;
}

static int fx_ieq(const char *a, const char *b) {
    while (*a && *b) {
        if (fx_lc(*a) != fx_lc(*b)) return 0;
        a++;
        b++;
    }
    return *a == *b;
}

static int fx_icontains(const char *hay, const char *needle) {
    const char *h, *a, *b;
    if (!*needle) return 1;
    for (h = hay; *h; h++) {
        a = h;
        b = needle;
        while (*a && *b && fx_lc(*a) == fx_lc(*b)) { a++; b++; }
        if (!*b) return 1;
    }
    return 0;
}

static const char *fx_skip_sp(const char *s) {
    while (*s == ' ' || *s == '\t') s++;
    return s;
}

/* ---------------- alan eşleme ---------------- */

static FxField fx_resolve_field(const char *f) {
    if (!strcmp(f, "ip") || !strcmp(f, "ip.addr"))  return FX_F_IP;
    if (!strcmp(f, "ip.src")) return FX_F_IP_SRC;
    if (!strcmp(f, "ip.dst")) return FX_F_IP_DST;

    if (!strcmp(f, "eth") || !strcmp(f, "eth.addr") ||
        !strcmp(f, "mac") || !strcmp(f, "mac.addr"))  return FX_F_MAC;
    if (!strcmp(f, "eth.src") || !strcmp(f, "mac.src")) return FX_F_MAC_SRC;
    if (!strcmp(f, "eth.dst") || !strcmp(f, "mac.dst")) return FX_F_MAC_DST;

    if (!strcmp(f, "port")) return FX_F_PORT;

    if (!strcmp(f, "tcp.port"))  return FX_F_TCP_PORT;
    if (!strcmp(f, "tcp.srcport") || !strcmp(f, "tcp.sport")) return FX_F_TCP_SPORT;
    if (!strcmp(f, "tcp.dstport") || !strcmp(f, "tcp.dport")) return FX_F_TCP_DPORT;

    if (!strcmp(f, "udp.port"))  return FX_F_UDP_PORT;
    if (!strcmp(f, "udp.srcport") || !strcmp(f, "udp.sport")) return FX_F_UDP_SPORT;
    if (!strcmp(f, "udp.dstport") || !strcmp(f, "udp.dport")) return FX_F_UDP_DPORT;

    if (!strcmp(f, "proto") || !strcmp(f, "protocol")) return FX_F_PROTO;
    if (!strcmp(f, "info") || !strcmp(f, "frame") ||
        !strcmp(f, "frame.info")) return FX_F_INFO;

    return FX_F_NONE;
}

static int fx_field_is_port(FxField f) {
    return f == FX_F_PORT || f == FX_F_TCP_PORT || f == FX_F_TCP_SPORT ||
           f == FX_F_TCP_DPORT || f == FX_F_UDP_PORT ||
           f == FX_F_UDP_SPORT || f == FX_F_UDP_DPORT;
}

static int fx_val_is_uport(const char *v) {
    unsigned long n = 0;
    if (!v[0]) return 0;
    for (; *v; v++) {
        if (*v < '0' || *v > '9') return 0;
        n = n * 10 + (unsigned long)(*v - '0');
        if (n > 65535) return 0;
    }
    return 1;
}

/* ---------------- paket bilgisi ---------------- */

/* Layer tipi için küçük harfli protokol anahtar sözcükleri.
 * LAYER_IPV4 hem "ip" hem "ipv4" olarak eşleşir. */
static const char *fx_layer_tok(int idx, PduLayerType t) {
    switch (t) {
        case LAYER_ETHERNET: return (idx == 0) ? "ethernet" : NULL;
        case LAYER_ARP:      return (idx == 0) ? "arp" : NULL;
        case LAYER_IPV4:     return (idx == 0) ? "ip" : (idx == 1) ? "ipv4" : NULL;
        case LAYER_IPV6:     return (idx == 0) ? "ipv6" : NULL;
        case LAYER_TCP:      return (idx == 0) ? "tcp" : NULL;
        case LAYER_UDP:      return (idx == 0) ? "udp" : NULL;
        case LAYER_ICMP:     return (idx == 0) ? "icmp" : NULL;
        case LAYER_DNS:      return (idx == 0) ? "dns" : NULL;
        case LAYER_HTTP:     return (idx == 0) ? "http" : NULL;
        case LAYER_TLS:      return (idx == 0) ? "tls" : NULL;
        case LAYER_DHCP:     return (idx == 0) ? "dhcp" : NULL;
        case LAYER_MDNS:     return (idx == 0) ? "mdns" : NULL;
        case LAYER_LLMNR:    return (idx == 0) ? "llmnr" : NULL;
        case LAYER_NETBIOS:  return (idx == 0) ? "netbios" : NULL;
        case LAYER_SSDP:     return (idx == 0) ? "ssdp" : NULL;
        case LAYER_NTP:      return (idx == 0) ? "ntp" : NULL;
        case LAYER_SNMP:     return (idx == 0) ? "snmp" : NULL;
        case LAYER_SYSLOG:   return (idx == 0) ? "syslog" : NULL;
        case LAYER_TFTP:     return (idx == 0) ? "tftp" : NULL;
        case LAYER_STUN:     return (idx == 0) ? "stun" : NULL;
        case LAYER_MYSQL:    return (idx == 0) ? "mysql" : NULL;
        case LAYER_POSTGRES: return (idx == 0) ? "postgresql" : NULL;
        case LAYER_REDIS:    return (idx == 0) ? "redis" : NULL;
        case LAYER_MONGODB:  return (idx == 0) ? "mongodb" : NULL;
        case LAYER_SSH:      return (idx == 0) ? "ssh" : NULL;
        case LAYER_FTP:      return (idx == 0) ? "ftp" : NULL;
        case LAYER_SMTP:     return (idx == 0) ? "smtp" : NULL;
        case LAYER_POP3:     return (idx == 0) ? "pop3" : NULL;
        case LAYER_IMAP:     return (idx == 0) ? "imap" : NULL;
        case LAYER_RDP:      return (idx == 0) ? "rdp" : NULL;
        case LAYER_VNC:      return (idx == 0) ? "vnc" : NULL;
        case LAYER_DATA:     return (idx == 0) ? "data" : NULL;
        default:             return (idx == 0) ? "unknown" : NULL;
    }
}

/* Paketin protokol adıyla mı yoksa layer anahtar sözcükleriyle mi
 * eşleştiğini söyler. (contains=1 => alt dize araması) */
static int fx_proto_hit(const PacketRecord *p, const char *v, int contains) {
    int i, k;
    const char *tok;

    if (contains) {
        if (fx_icontains(p->protocol, v)) return 1;
    } else {
        if (fx_ieq(p->protocol, v)) return 1;
    }
    for (i = 0; i < p->layer_count && i < MAX_LAYERS; i++) {
        for (k = 0; k < 2; k++) {
            tok = fx_layer_tok(k, p->layers[i].type);
            if (!tok) break;
            if (contains ? fx_icontains(tok, v) : fx_ieq(tok, v)) return 1;
        }
    }
    return 0;
}

/* Paketin taşıma katmanını belirler. Layer'larda TCP/UDP yoksa (ör. eski
 * kayıtlar) protokol adı listelerine bakar. */
static void fx_transport(const PacketRecord *p, int *is_tcp, int *is_udp) {
    static const char *const tcp_names[] = {
        "tcp", "tls", "http", "ssh", "ftp", "smtp", "pop3", "imap",
        "rdp", "vnc", "mysql", "postgresql", "redis", "mongodb"
    };
    static const char *const udp_names[] = {
        "udp", "dns", "dhcp", "mdns", "llmnr", "ssdp", "ntp",
        "snmp", "syslog", "tftp", "stun", "quic"
    };
    int i;

    *is_tcp = 0;
    *is_udp = 0;
    for (i = 0; i < p->layer_count && i < MAX_LAYERS; i++) {
        if (p->layers[i].type == LAYER_TCP) *is_tcp = 1;
        else if (p->layers[i].type == LAYER_UDP) *is_udp = 1;
    }
    if (*is_tcp || *is_udp) return;

    for (i = 0; i < (int)(sizeof(tcp_names) / sizeof(tcp_names[0])); i++)
        if (fx_ieq(p->protocol, tcp_names[i])) { *is_tcp = 1; return; }
    for (i = 0; i < (int)(sizeof(udp_names) / sizeof(udp_names[0])); i++)
        if (fx_ieq(p->protocol, udp_names[i])) { *is_udp = 1; return; }
}

/* contains/eşitlik için tek bir metin alanını sına */
static int fx_sm(const char *s, const char *v, int contains) {
    return contains ? fx_icontains(s, v) : fx_ieq(s, v);
}

/* Alan bazlı OLUMLU eşleşme (NEQ burada değil, üstte terslenir). */
static int fx_field_hit(FxField field, const char *v, const PacketRecord *p,
                        int contains) {
    int tcp = 0, udp = 0, need_tcp = 0, need_udp = 0;
    int lo, hi, k;
    const char *ports[2];

    switch (field) {
        case FX_F_IP:       return fx_sm(p->src_ip, v, contains) ||
                                    fx_sm(p->dst_ip, v, contains);
        case FX_F_IP_SRC:   return fx_sm(p->src_ip, v, contains);
        case FX_F_IP_DST:   return fx_sm(p->dst_ip, v, contains);
        case FX_F_MAC:      return fx_sm(p->src_mac, v, contains) ||
                                    fx_sm(p->dst_mac, v, contains);
        case FX_F_MAC_SRC:  return fx_sm(p->src_mac, v, contains);
        case FX_F_MAC_DST:  return fx_sm(p->dst_mac, v, contains);
        case FX_F_INFO:     return fx_sm(p->info, v, contains);
        case FX_F_PROTO:    return fx_proto_hit(p, v, contains);
        case FX_F_TCP_PORT:
        case FX_F_TCP_SPORT:
        case FX_F_TCP_DPORT: need_tcp = 1; break;
        case FX_F_UDP_PORT:
        case FX_F_UDP_SPORT:
        case FX_F_UDP_DPORT: need_udp = 1; break;
        default: break; /* FX_F_PORT */
    }

    fx_transport(p, &tcp, &udp);
    if (need_tcp && !tcp) return 0;
    if (need_udp && !udp) return 0;

    switch (field) {
        case FX_F_TCP_SPORT:
        case FX_F_UDP_SPORT: lo = 0; hi = 1; break;
        case FX_F_TCP_DPORT:
        case FX_F_UDP_DPORT: lo = 1; hi = 2; break;
        default:             lo = 0; hi = 2; break; /* port / *.port */
    }
    ports[0] = p->src_port;
    ports[1] = p->dst_port;

    if (!contains) {
        long want = strtol(v, NULL, 10);
        for (k = lo; k < hi; k++) {
            if (ports[k][0] && strtol(ports[k], NULL, 10) == want) return 1;
        }
        return 0;
    }
    for (k = lo; k < hi; k++)
        if (fx_icontains(ports[k], v)) return 1;
    return 0;
}

/* Çıplak sözcük: önce protokol adı, sonra metin alanlarında geçerlilik. */
static int fx_bare_hit(const PacketRecord *p, const char *v) {
    int i;
    if (fx_proto_hit(p, v, 0)) return 1;

    if (fx_icontains(p->protocol, v)) return 1;
    if (fx_icontains(p->src_ip, v) || fx_icontains(p->dst_ip, v)) return 1;
    if (fx_icontains(p->src_mac, v) || fx_icontains(p->dst_mac, v)) return 1;
    if (fx_icontains(p->src_port, v) || fx_icontains(p->dst_port, v)) return 1;
    if (fx_icontains(p->info, v)) return 1;
    for (i = 0; i < p->layer_count && i < MAX_LAYERS; i++)
        if (fx_icontains(p->layers[i].name, v)) return 1;
    return 0;
}

/* ---------------- ifade parçalama ---------------- */

/* İfadeyi wb içine kopyalar, küçük harfe çevirir ve AND/OR ayraçlarından
 * böler. Ayraç konumlarına '\0' yazar; terms[] ayrık parçaları gösterir,
 * seps[i] = terms[i] ile terms[i+1] arasındaki ayraçtır. */
static int fx_split(const char *s0, size_t len, char wb[FX_MAX_EXPR + 1],
                    char **terms, int *seps, int *n_out) {
    size_t i;
    int n = 1;
    int in_quote = 0;

    if (len == 0) return 0;
    if (len > FX_MAX_EXPR) return 0;

    memcpy(wb, s0, len);
    wb[len] = '\0';
    for (i = 0; i < len; i++) {
        if (wb[i] < 32 || wb[i] > 126) return 0;  /* yazdırılabilir ASCII */
        wb[i] = fx_lc(wb[i]);
    }

    terms[0] = wb;
    for (i = 0; i < len; i++) {
        int sep = 0;
        size_t slen = 0;

        if (wb[i] == '"') { in_quote = !in_quote; continue; }
        if (in_quote) continue;

        if (wb[i] == '&' && i + 1 < len && wb[i + 1] == '&') {
            sep = FX_SEP_AND; slen = 2;
        } else if (wb[i] == '|' && i + 1 < len && wb[i + 1] == '|') {
            sep = FX_SEP_OR; slen = 2;
        } else if (i + 2 < len && wb[i] == 'a' && wb[i + 1] == 'n' &&
                   wb[i + 2] == 'd' &&
                   (i == 0 || !isalnum((unsigned char)wb[i - 1])) &&
                   (i + 3 >= len || !isalnum((unsigned char)wb[i + 3]))) {
            sep = FX_SEP_AND; slen = 3;
        } else if (i + 1 < len && wb[i] == 'o' && wb[i + 1] == 'r' &&
                   (i == 0 || !isalnum((unsigned char)wb[i - 1])) &&
                   (i + 2 >= len || !isalnum((unsigned char)wb[i + 2]))) {
            sep = FX_SEP_OR; slen = 2;
        }

        if (sep) {
            if (n >= FX_MAX_TERMS) return 0;
            wb[i] = '\0';
            seps[n - 1] = sep;
            terms[n] = wb + i + slen;
            n++;
            i += slen - 1;
        }
    }
    *n_out = n;
    return 1;
}

/* ---------------- terim çözümleme ---------------- */

static int fx_parse_term(const char *raw, FxTerm *out) {
    char tbuf[FX_MAX_EXPR + 1];
    char valbuf[FX_MAX_VALUE + 1];
    char fname[FX_MAX_FIELD];
    const char *contains_at = NULL, *eq_at = NULL, *vstart;
    const char *fend;
    char *p, *r;
    int inq = 0, q = 0, is_contains = 0, is_neg = 0;
    size_t tl, flen, vlen;
    FxField fld;

    tl = strlen(raw);
    if (tl == 0 || tl >= sizeof(tbuf)) return 0;
    memcpy(tbuf, raw, tl + 1);

    while (tl && (tbuf[tl - 1] == ' ' || tbuf[tl - 1] == '\t'))
        tbuf[--tl] = '\0';
    p = (char *)fx_skip_sp(tbuf);
    if (!*p) return 0;

    for (r = p; *r; r++) if (*r == '"') q++;
    if (q & 1) return 0;               /* dengesiz tırnak */

    /* Operatörü bul (tırnak içini atla) */
    for (r = p; *r; r++) {
        if (*r == '"') { inq = !inq; continue; }
        if (inq) continue;
        if (*r == ' ' && !contains_at && strncmp(r, " contains ", 10) == 0)
            contains_at = r;
        if (!eq_at && r[0] == '=' && r[1] == '=') eq_at = r;
        if (!eq_at && r[0] == '!' && r[1] == '=') eq_at = r;
    }

    if (contains_at && (!eq_at || contains_at < eq_at)) {
        is_contains = 1;
        fend = contains_at;
        vstart = contains_at + 10;
    } else if (eq_at) {
        is_neg = (eq_at[0] == '!');
        fend = eq_at;
        vstart = eq_at + 2;
    } else {
        /* Çıplak sözcük: operatör karakteri içeremez */
        for (r = p; *r; r++) {
            char c = *r;
            if (c == '=' || c == '!' || c == '<' || c == '>' ||
                c == '&' || c == '|' || c == '(' || c == ')' ||
                c == '"' || c == '\'')
                return 0;
        }
        if (strlen(p) > FX_MAX_VALUE) return 0;
        out->field = FX_F_NONE;
        out->op = FX_OP_EQ;
        memcpy(out->value, p, strlen(p) + 1);
        return 1;
    }

    /* Alan adı: [p, fend) */
    flen = (size_t)(fend - p);
    while (flen && (p[flen - 1] == ' ' || p[flen - 1] == '\t')) flen--;
    if (flen == 0 || flen >= FX_MAX_FIELD) return 0;
    for (r = p; r < p + (long)flen; r++) {
        if (!(isalnum((unsigned char)*r) || *r == '.' || *r == '-' ||
              *r == '_' || *r == ':'))
            return 0;
    }
    memcpy(fname, p, flen);
    fname[flen] = '\0';
    fld = fx_resolve_field(fname);
    if (fld == FX_F_NONE) return 0;    /* bilinmeyen alan => geçersiz */

    /* Değer */
    vstart = fx_skip_sp(vstart);
    vlen = strlen(vstart);
    while (vlen && (vstart[vlen - 1] == ' ' || vstart[vlen - 1] == '\t'))
        vlen--;
    if (vlen == 0) return 0;

    if (vstart[0] == '"') {
        if (vlen < 2 || vstart[vlen - 1] != '"') return 0;
        vstart++;
        vlen -= 2;
        for (r = (char *)vstart; r < vstart + (long)vlen; r++)
            if (*r == '"') return 0;
        if (vlen == 0) return 0;
    } else {
        for (r = (char *)vstart; r < vstart + (long)vlen; r++)
            if (*r == '"') return 0;
    }
    if (vlen > FX_MAX_VALUE) return 0;
    memcpy(valbuf, vstart, vlen);
    valbuf[vlen] = '\0';

    out->field = fld;
    out->op = is_contains ? FX_OP_CONTAINS : (is_neg ? FX_OP_NEQ : FX_OP_EQ);
    memcpy(out->value, valbuf, vlen + 1);

    /* Port alanlarında ==/!= sayısal port ister */
    if (out->op != FX_OP_CONTAINS && fx_field_is_port(fld)) {
        if (!fx_val_is_uport(out->value)) return 0;
    }
    return 1;
}

/* ---------------- değerlendirme ---------------- */

static int fx_term_hit(const FxTerm *t, const PacketRecord *p) {
    int pos;
    if (t->field == FX_F_NONE) return fx_bare_hit(p, t->value);
    pos = fx_field_hit(t->field, t->value, p, t->op == FX_OP_CONTAINS);
    return (t->op == FX_OP_NEQ) ? !pos : pos;
}

static int fx_eval_terms(char **terms, int n, const int *seps,
                         const PacketRecord *p) {
    FxTerm t;
    int res = 0, i = 0, g;

    while (i < n) {
        if (!fx_parse_term(terms[i], &t)) return 1; /* savunma: eleme yok */
        g = fx_term_hit(&t, p);
        while (i + 1 < n && seps[i] == FX_SEP_AND) {
            i++;
            if (!fx_parse_term(terms[i], &t)) return 1;
            g = g && fx_term_hit(&t, p);
        }
        res = res || g;
        i++;
    }
    return res;
}

static int fx_validate_terms(char **terms, int n, const int *seps) {
    FxTerm t;
    (void)seps;
    for (int i = 0; i < n; i++)
        if (!fx_parse_term(terms[i], &t)) return 0;
    return 1;
}

/* ---------------- genel API ---------------- */

/* Boş/yalnızca boşluk içeren ifadeler geçerlidir (filtre yok anlamında). */
static int fx_prepare(const char *expr, char wb[FX_MAX_EXPR + 1],
                      char **terms, int *seps, int *n) {
    const char *s;
    size_t len;

    if (!expr) return 0;
    s = fx_skip_sp(expr);
    len = strlen(s);
    while (len && (s[len - 1] == ' ' || s[len - 1] == '\t')) len--;
    if (len == 0) return 0;                     /* boş => "filtre yok" */
    if (!fx_split(s, len, wb, terms, seps, n)) return -1;  /* yapısal hata */
    if (!fx_validate_terms(terms, *n, seps)) return -1;    /* terim hatası */
    return 1;
}

int filter_engine_expr_valid(const char *expr) {
    char wb[FX_MAX_EXPR + 1];
    char *terms[FX_MAX_TERMS];
    int seps[FX_MAX_TERMS];
    int n = 0, rc;

    rc = fx_prepare(expr, wb, terms, seps, &n);
    return (rc == 0) ? 1 : (rc == 1);
}

int filter_engine_packet_matches(const PacketRecord *pkt, const char *expr) {
    char wb[FX_MAX_EXPR + 1];
    char *terms[FX_MAX_TERMS];
    int seps[FX_MAX_TERMS];
    int n = 0, rc;

    if (!pkt) return 1;
    rc = fx_prepare(expr, wb, terms, seps, &n);
    if (rc == 0) return 1;       /* boş ifade: her şey eşleşir */
    if (rc < 0) return 1;        /* geçersiz ifade: listeyi boşaltma */
    return fx_eval_terms(terms, n, seps, pkt);
}

