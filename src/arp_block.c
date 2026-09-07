/*
 * arp_block.c — Ağdan IP Engelleme (ARP Kara Delik) Motoru
 *
 * Engellenen her IP için iki yönlü sahte ARP Reply enjekte edilir:
 *   - Hedefe:  "Gateway IP → ölü (bogus) MAC"   → cihaz gateway'e ulaşamaz
 *   - Gateway'e: "Hedef IP → ölü (bogus) MAC"   → dönen yanıtlar karartılır
 *
 * Bogus MAC her cihaz için tekil, locally-administered bir adrestir
 * (02:BA:AD:BE:EF:xx). Ethernet kaynağı her zaman bizim gerçek MAC'imizdir;
 * bu sayede IDS'in ids_is_self_originated süzgeci (Ethernet src = g_local_mac)
 * bu çerçeveleri kendi trafiğimiz sanıp muaf tutar.
 *
 * Geri alma: gerçek eşleşmeleri bildiren ARP Reply'lar gönderilir. ARP
 * zaten 30-60 sn içinde kendiliğinden düzelir, restore paketleri anında
 * toparlar. MAC'i hiç çözülememiş hedeflerde kendiliğinden düzelme beklenir.
 */
#include "arp_block.h"
#include "platform.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef PLATFORM_LINUX
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#endif
#ifdef PLATFORM_WINDOWS
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#ifndef WINVER
#define WINVER 0x0601
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#ifdef HAVE_NPCAP
#include <pcap.h>
#endif
#endif /* PLATFORM_WINDOWS */

/* ================= İç durum ================= */

#define BLOCK_POISON_MS        1500    /* zehirleme periyodu */
#define BLOCK_TICK_MS          150     /* işçi döngü adımı */
#define BLOCK_RESTORE_COUNT    3       /* geri alırken gönderilecek paket sayısı */

#ifdef PLATFORM_LINUX

typedef struct {
    char            ip[MAX_IP_LEN];
    unsigned char   ip_bytes[4];
    unsigned char   target_mac[6];
    int             mac_valid;         /* hedefin gerçek MAC'i biliniyor mu */
    int             active;            /* şu an engelli (UI'da görünür) */
    int             restore_pending;   /* geri alındı, restore paketleri beklemede */
    long long       last_poison_ms;
    long long       next_resolve_ms;
    char            blocked_at[32];
} BlockEntry;

static BlockEntry        g_entries[ARP_BLOCK_MAX_BLOCKED];
static platform_mutex_t  g_lock;
static int               g_lock_init = 0;

static int  g_running = 0;
static platform_thread_t g_thread;
static volatile int g_raw_fd = -1;
static volatile int g_engine_ok = 0;

/* Bağlam (GUI her karede günceller) */
static char            g_iface[MAX_IFACE_LEN];
static unsigned char   g_local_mac[6];
static int             g_local_mac_valid = 0;
static char            g_gateway_ip[MAX_IP_LEN];
static char            g_gateway_mac_str[MAX_MAC_LEN];
static unsigned char   g_gateway_mac[6];
static int             g_gateway_mac_valid = 0;

/* ================= Yardımcılar ================= */

static long long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void block_lock_ensure(void) {
    if (!g_lock_init) {
        platform_mutex_init(&g_lock);
        g_lock_init = 1;
    }
}

static int block_parse_mac(const char *s, unsigned char mac[6]) {
    unsigned int b[6];
    if (!s || sscanf(s, "%x:%x:%x:%x:%x:%x",
                     &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6)
        return -1;
    for (int i = 0; i < 6; i++) mac[i] = (unsigned char)b[i];
    return 0;
}

static void block_mac_to_str(const unsigned char mac[6], char *out, int len) {
    snprintf(out, len, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* Ethernet src = bizim MAC; ARP sender MAC = istenen (sahte veya gerçek) MAC */
static void block_send_arp(int raw_fd, const char *iface,
                           const unsigned char *eth_src,
                           const unsigned char *arp_sender_mac, const char *sender_ip,
                           const unsigned char *dst_mac, const char *dst_ip) {
    unsigned char buf[42];
    memset(buf, 0, sizeof(buf));

    memcpy(buf, dst_mac, 6);                 /* Ethernet dst */
    memcpy(buf + 6, eth_src, 6);             /* Ethernet src = bizim MAC */
    buf[12] = 0x08; buf[13] = 0x06;         /* EtherType: ARP */

    buf[14] = 0x00; buf[15] = 0x01;         /* HW: Ethernet */
    buf[16] = 0x08; buf[17] = 0x00;         /* Proto: IPv4 */
    buf[18] = 0x06; buf[19] = 0x04;
    buf[20] = 0x00; buf[21] = 0x02;         /* Opcode: Reply */

    memcpy(buf + 22, arp_sender_mac, 6);     /* ARP sender MAC */
    struct in_addr sin;
    if (inet_pton(AF_INET, sender_ip, &sin) != 1) return;
    memcpy(buf + 28, &sin, 4);               /* ARP sender IP */

    memcpy(buf + 32, dst_mac, 6);            /* ARP target MAC */
    if (inet_pton(AF_INET, dst_ip, &sin) != 1) return;
    memcpy(buf + 38, &sin, 4);               /* ARP target IP */

    struct sockaddr_ll addr;
    memset(&addr, 0, sizeof(addr));
    addr.sll_family   = AF_PACKET;
    addr.sll_ifindex  = if_nametoindex(iface);
    addr.sll_protocol = htons(ETH_P_ARP);
    memcpy(addr.sll_addr, dst_mac, 6);
    addr.sll_halen    = 6;

    sendto(raw_fd, buf, 42, 0, (struct sockaddr *)&addr, sizeof(addr));
}

static int block_get_own_mac(const char *iface, unsigned char mac[6]) {
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

static int block_get_own_ip(const char *iface, char *ip_out, int ip_len) {
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

/* Bir IP'nin MAC'ini ARP Request ile çöz (2 sn timeout) */
static int block_resolve_mac(const char *ip, unsigned char *mac_out, const char *iface) {
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (fd < 0) return -1;

    unsigned int ifindex = if_nametoindex(iface);
    if (ifindex == 0) { close(fd); return -1; }

    unsigned char own_mac[6];
    char own_ip[16] = {0};
    if (block_get_own_mac(iface, own_mac) < 0) { close(fd); return -1; }
    if (block_get_own_ip(iface, own_ip, sizeof(own_ip)) < 0) { close(fd); return -1; }

    struct sockaddr_ll addr;
    memset(&addr, 0, sizeof(addr));
    addr.sll_family   = AF_PACKET;
    addr.sll_ifindex  = ifindex;
    addr.sll_protocol = htons(ETH_P_ARP);

    unsigned char buf[64];
    memset(buf, 0, sizeof(buf));
    memset(buf, 0xff, 6);                   /* dst: broadcast */
    memcpy(buf + 6, own_mac, 6);            /* src */
    buf[12] = 0x08; buf[13] = 0x06;

    buf[14] = 0x00; buf[15] = 0x01;
    buf[16] = 0x08; buf[17] = 0x00;
    buf[18] = 0x06; buf[19] = 0x04;
    buf[20] = 0x00; buf[21] = 0x01;         /* Opcode: Request */

    memcpy(buf + 22, own_mac, 6);
    struct in_addr sin;
    inet_pton(AF_INET, own_ip, &sin);
    memcpy(buf + 28, &sin, 4);

    memset(buf + 32, 0x00, 6);              /* hedef MAC bilinmiyor */
    inet_pton(AF_INET, ip, &sin);
    memcpy(buf + 38, &sin, 4);

    if (sendto(fd, buf, 42, 0, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    struct timeval tv = {2, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    unsigned char resp[128];
    int result = -1;
    for (int attempt = 0; attempt < 80; attempt++) {
        int n = recvfrom(fd, resp, sizeof(resp), 0, NULL, NULL);
        if (n <= 0) break;
        if (n < 42) continue;
        int op = (resp[20] << 8) | resp[21];
        if (op != 2) continue;
        char rip[16];
        snprintf(rip, sizeof(rip), "%d.%d.%d.%d",
                 resp[28], resp[29], resp[30], resp[31]);
        if (strcmp(rip, ip) == 0) {
            memcpy(mac_out, resp + 22, 6);
            result = 0;
            break;
        }
    }
    close(fd);
    return result;
}

/* Slot indeksine göre tekil bogus (ölü) MAC üret */
static void block_bogus_mac(int slot, unsigned char mac[6]) {
    mac[0] = 0x02;
    mac[1] = 0xBA;
    mac[2] = 0xAD;
    mac[3] = 0xBE;
    mac[4] = 0xEF;
    mac[5] = (unsigned char)(0x10 + (slot & 0x0F));
}

/* ================= Zehirleme / restore ================= */

/* Hedefe "gateway → bogus" ve gateway'e "hedef → bogus" gönder */
static void block_poison(int raw_fd, int slot, const BlockEntry *e,
                         const char *iface, const unsigned char *eth_src,
                         const unsigned char *gw_mac, int gw_mac_valid,
                         const char *gw_ip) {
    unsigned char bogus[6];
    block_bogus_mac(slot, bogus);

    /* Hedefe: "Gateway = bogus" */
    if (e->mac_valid && gw_ip[0]) {
        block_send_arp(raw_fd, iface, eth_src, bogus, gw_ip,
                       e->target_mac, e->ip);
    }
    /* Gateway'e: "Hedef = bogus" */
    if (gw_mac_valid && e->mac_valid) {
        block_send_arp(raw_fd, iface, eth_src, bogus, e->ip,
                       gw_mac, gw_ip);
    }
}

/* Gerçek eşleşmeleri geri yükle */
static void block_restore(int raw_fd, const BlockEntry *e,
                          const char *iface, const unsigned char *eth_src,
                          const unsigned char *gw_mac, int gw_mac_valid,
                          const char *gw_ip) {
    if (!e->mac_valid) return;   /* MAC bilinmiyor → ARP 30-60 sn'de kendiliğinden düzelir */
    if (!gw_mac_valid) return;
    /* Hedefe: "Gateway = gerçek gw MAC" */
    if (gw_ip[0]) {
        block_send_arp(raw_fd, iface, eth_src, gw_mac, gw_ip,
                       e->target_mac, e->ip);
    }
    /* Gateway'e: "Hedef = gerçek hedef MAC" */
    block_send_arp(raw_fd, iface, eth_src, e->target_mac, e->ip,
                   gw_mac, gw_ip);
}

/* ================= İşçi thread ================= */

static void *arp_block_worker(void *arg) {
    (void)arg;

    while (g_running) {
        int raw_fd = g_raw_fd;

        /* Raw socket yoksa açmayı dene */
        if (raw_fd < 0) {
            int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
            if (fd >= 0) {
                g_raw_fd = fd;
                g_engine_ok = 1;
                raw_fd = fd;
                fprintf(stderr, "[ARP_BLOCK] Raw socket acildi.\n");
            } else {
                g_engine_ok = 0;
                fprintf(stderr, "[ARP_BLOCK] Raw socket acilamadi (root/cap_net_raw gerekli)\n");
                platform_sleep_ms(1000);
                continue;
            }
        }

        long long now = now_ms();

        platform_mutex_lock(&g_lock);

        /* Kendi MAC'i bağlamdan gelmediyse ioctl ile al */
        if (!g_local_mac_valid && g_iface[0]) {
            unsigned char m[6];
            if (block_get_own_mac(g_iface, m) == 0) {
                memcpy(g_local_mac, m, 6);
                g_local_mac_valid = 1;
            }
        }

        /* Aktif engel varsa ve gateway MAC'i bilinmiyorsa çöz */
        int need_gw = 0;
        for (int i = 0; i < ARP_BLOCK_MAX_BLOCKED; i++) {
            if (g_entries[i].active) { need_gw = 1; break; }
        }
        if (need_gw && !g_gateway_mac_valid && g_gateway_ip[0] && g_iface[0]) {
            platform_mutex_unlock(&g_lock);   /* çözme uzun sürebilir, kilidi bırak */
            unsigned char m[6];
            int r = block_resolve_mac(g_gateway_ip, m, g_iface);
            platform_mutex_lock(&g_lock);
            if (r == 0) {
                memcpy(g_gateway_mac, m, 6);
                block_mac_to_str(m, g_gateway_mac_str, sizeof(g_gateway_mac_str));
                g_gateway_mac_valid = 1;
            }
        }

        /* --- Restore beklemede olan slotları gerçek eşleşmelerle onar --- */
        for (int i = 0; i < ARP_BLOCK_MAX_BLOCKED; i++) {
            BlockEntry *e = &g_entries[i];
            if (!e->restore_pending || !e->ip[0]) continue;
            for (int r = 0; r < BLOCK_RESTORE_COUNT && raw_fd >= 0; r++)
                block_restore(raw_fd, e, g_iface, g_local_mac,
                              g_gateway_mac, g_gateway_mac_valid, g_gateway_ip);
            memset(e, 0, sizeof(*e));
        }

        /* --- Zehirleme (her hedef kendi periyodunda) --- */
        if (g_local_mac_valid) {
            for (int i = 0; i < ARP_BLOCK_MAX_BLOCKED; i++) {
                BlockEntry *e = &g_entries[i];
                if (!e->active || !e->ip[0] || !e->mac_valid) continue;
                if (now - e->last_poison_ms < BLOCK_POISON_MS) continue;
                block_poison(raw_fd, i, e, g_iface, g_local_mac,
                             g_gateway_mac, g_gateway_mac_valid, g_gateway_ip);
                e->last_poison_ms = now;
            }
        }

        /* --- MAC'i bilinmeyen aktif hedefleri not et (kilidi bırakıp çözeceğiz) --- */
        char resolve_ip[ARP_BLOCK_MAX_BLOCKED][MAX_IP_LEN];
        int  resolve_slot[ARP_BLOCK_MAX_BLOCKED];
        int  resolve_n = 0;
        for (int i = 0; i < ARP_BLOCK_MAX_BLOCKED; i++) {
            BlockEntry *e = &g_entries[i];
            if (!e->active || !e->ip[0] || e->mac_valid) continue;
            if (now < e->next_resolve_ms) continue;
            strncpy(resolve_ip[resolve_n], e->ip, MAX_IP_LEN - 1);
            resolve_slot[resolve_n] = i;
            resolve_n++;
        }
        platform_mutex_unlock(&g_lock);

        /* --- MAC çözme (kilit dışında; 2 sn timeout) --- */
        for (int r = 0; r < resolve_n; r++) {
            unsigned char m[6];
            if (block_resolve_mac(resolve_ip[r], m, g_iface) == 0) {
                platform_mutex_lock(&g_lock);
                BlockEntry *e = &g_entries[resolve_slot[r]];
                if (e->active && e->ip[0]) {
                    memcpy(e->target_mac, m, 6);
                    e->mac_valid = 1;
                }
                platform_mutex_unlock(&g_lock);
            }
        }
        /* Çözülemeyenlerin bir sonraki denemesini ~5 sn sonraya al */
        if (resolve_n > 0) {
            long long next = now_ms() + 5000;
            platform_mutex_lock(&g_lock);
            for (int i = 0; i < ARP_BLOCK_MAX_BLOCKED; i++) {
                BlockEntry *e = &g_entries[i];
                if (!e->active || !e->ip[0] || e->mac_valid) continue;
                if (e->next_resolve_ms == 0) e->next_resolve_ms = next;
            }
            platform_mutex_unlock(&g_lock);
        }

        platform_sleep_ms(BLOCK_TICK_MS);
    }

    /* ===== Temizlik: hâlâ aktif olanları geri yükle ve socket'i kapat ===== */
    int raw_fd = g_raw_fd;
    if (raw_fd >= 0) {
        platform_mutex_lock(&g_lock);
        for (int i = 0; i < ARP_BLOCK_MAX_BLOCKED; i++) {
            BlockEntry *e = &g_entries[i];
            if (!e->active || !e->ip[0]) continue;
            for (int r = 0; r < BLOCK_RESTORE_COUNT; r++)
                block_restore(raw_fd, e, g_iface, g_local_mac,
                              g_gateway_mac, g_gateway_mac_valid, g_gateway_ip);
            memset(e, 0, sizeof(*e));
        }
        platform_mutex_unlock(&g_lock);
        close(raw_fd);
        g_raw_fd = -1;
    }
    g_engine_ok = 0;
    fprintf(stderr, "[ARP_BLOCK] Durduruldu, engeller geri alindi.\n");
    return NULL;
}

/* ================= Public API ================= */

void arp_block_init(void) {
    block_lock_ensure();
    if (g_running) return;
    g_running = 1;
    platform_thread_create(&g_thread, arp_block_worker, NULL);
    platform_thread_detach(g_thread);
    fprintf(stderr, "[ARP_BLOCK] Motor baslatildi.\n");
}

void arp_block_cleanup(void) {
    if (!g_running) return;
    g_running = 0;
    platform_sleep_ms(1500);   /* işçi restore paketlerini göndersin */
}

int arp_block_set_context(const char *iface, const char *local_mac,
                          const char *gateway_ip, const char *gateway_mac,
                          const char *local_ip) {
    (void)local_ip;   /* Linux probe'ları sender IP gerektirmez; Windows Npcap motoru kullanır */
    if (!iface || !iface[0] || !local_mac || !local_mac[0] || !gateway_ip) return -1;
    block_lock_ensure();

    platform_mutex_lock(&g_lock);
    strncpy(g_iface, iface, sizeof(g_iface) - 1);
    strncpy(g_gateway_ip, gateway_ip, sizeof(g_gateway_ip) - 1);

    if (block_parse_mac(local_mac, g_local_mac) == 0)
        g_local_mac_valid = 1;

    g_gateway_mac_valid = 0;
    g_gateway_mac_str[0] = '\0';
    if (gateway_mac && gateway_mac[0] && block_parse_mac(gateway_mac, g_gateway_mac) == 0) {
        g_gateway_mac_valid = 1;
        strncpy(g_gateway_mac_str, gateway_mac, sizeof(g_gateway_mac_str) - 1);
    }
    platform_mutex_unlock(&g_lock);
    return 0;
}

static BlockEntry *block_find(const char *ip) {
    for (int i = 0; i < ARP_BLOCK_MAX_BLOCKED; i++) {
        if (g_entries[i].ip[0] && strcmp(g_entries[i].ip, ip) == 0)
            return &g_entries[i];
    }
    return NULL;
}

int arp_block_set(const char *ip, const char *target_mac, int block) {
    if (!ip || !ip[0]) return -1;
    struct in_addr check;
    if (inet_pton(AF_INET, ip, &check) != 1) return -1;

    block_lock_ensure();
    platform_mutex_lock(&g_lock);

    /* Gateway'in kendisini engellemeye izin verme */
    if (g_gateway_ip[0] && strcmp(ip, g_gateway_ip) == 0) {
        platform_mutex_unlock(&g_lock);
        return -1;
    }

    if (block) {
        BlockEntry *found = block_find(ip);
        if (found) {   /* zaten engelli — MAC bilgisini tazele */
            if (target_mac && target_mac[0] && block_parse_mac(target_mac, found->target_mac) == 0)
                found->mac_valid = 1;
            found->restore_pending = 0;
            found->active = 1;
            platform_mutex_unlock(&g_lock);
            return 1;
        }
        for (int i = 0; i < ARP_BLOCK_MAX_BLOCKED; i++) {
            BlockEntry *e = &g_entries[i];
            if (e->ip[0]) continue;   /* dolu slot */
            memset(e, 0, sizeof(*e));
            strncpy(e->ip, ip, sizeof(e->ip) - 1);
            memcpy(e->ip_bytes, &check, 4);
            e->mac_valid = 0;
            if (target_mac && target_mac[0] && block_parse_mac(target_mac, e->target_mac) == 0)
                e->mac_valid = 1;
            e->active = 1;
            e->last_poison_ms = 0;          /* ilk zehirleme hemen */
            e->next_resolve_ms = 0;
            time_t t = time(NULL);
            struct tm tmv;
            localtime_r(&t, &tmv);
            strftime(e->blocked_at, sizeof(e->blocked_at), "%H:%M:%S", &tmv);
            platform_mutex_unlock(&g_lock);
            return 1;
        }
        platform_mutex_unlock(&g_lock);
        return 0;   /* kapasite dolu */
    }

    /* Geri al */
    BlockEntry *e = block_find(ip);
    if (e) {
        e->active = 0;
        e->restore_pending = 1;   /* işçi gerçek eşleşmeleri bildirsin */
    }
    platform_mutex_unlock(&g_lock);
    return (e != NULL) ? 1 : 0;
}

int arp_block_is_blocked(const char *ip) {
    if (!ip) return 0;
    int blocked = 0;
    block_lock_ensure();
    platform_mutex_lock(&g_lock);
    BlockEntry *e = block_find(ip);
    if (e) blocked = e->active;
    platform_mutex_unlock(&g_lock);
    return blocked;
}

void arp_block_get_snapshot(ArpBlockSnapshot *out) {
    if (!out) return;
    block_lock_ensure();
    memset(out, 0, sizeof(*out));

    platform_mutex_lock(&g_lock);
    out->engine_ok = g_engine_ok;
    strncpy(out->iface, g_iface, sizeof(out->iface) - 1);
    strncpy(out->gateway_ip, g_gateway_ip, sizeof(out->gateway_ip) - 1);
    strncpy(out->gateway_mac, g_gateway_mac_str, sizeof(out->gateway_mac) - 1);

    int n = 0;
    for (int i = 0; i < ARP_BLOCK_MAX_BLOCKED; i++) {
        BlockEntry *e = &g_entries[i];
        if (!e->active || !e->ip[0]) continue;
        ArpBlockEntry *dst = &out->entries[n];
        strncpy(dst->ip, e->ip, sizeof(dst->ip) - 1);
        if (e->mac_valid)
            block_mac_to_str(e->target_mac, dst->mac, sizeof(dst->mac));
        strncpy(dst->blocked_at, e->blocked_at, sizeof(dst->blocked_at) - 1);
        n++;
        if (n >= ARP_BLOCK_MAX_BLOCKED) break;
    }
    out->count = n;
    platform_mutex_unlock(&g_lock);
}

int arp_block_engine_ok(void) {
    return g_engine_ok;
}

#else /* PLATFORM_WINDOWS */

/* =====================================================================
 * Windows — Npcap tabanlı ARP kara-delik motoru.
 *
 * Linux dalından farklar:
 *   - Çerçeveler raw AF_PACKET socket yerine açık Npcap aygıtına
 *     pcap_inject ile gönderilir (60 bayt: 14 eth + 28 ARP + 18 pad).
 *   - Arayüz adı (FriendlyName, ör. "Wi-Fi") önce GetAdaptersAddresses ile
 *     GUID'e, oradan Npcap aygıt adına (\Device\NPF_{GUID}) eşlenir.
 *   - MAC çözümü önce işletim sistemi ARP tablosundan (GetIpNetTable),
 *     olmazsa canlı ARP Request/Reply probu ile yapılır.
 *   - Probların kendi zehirleme çerçevelerimizle yanıltılmasını önlemek için
 *     Ethernet src = g_local_mac olan yanıtlar atlanır (IDS muafiyetiyle
 *     aynı mantık: çerçeve kaynağı her zaman gerçek lokal MAC'tir).
 *
 * Npcap SDK (HAVE_NPCAP) olmadan derlenirse sessiz bir stub devreye girer:
 * tüm API no-op'tur, engine_ok=0 döner; GUI buradan "motor kapalı" gösterir
 * ve proje yine derlenir.
 * ===================================================================== */

#ifdef HAVE_NPCAP

/* ================= İç durum ================= */

typedef struct {
    char            ip[MAX_IP_LEN];
    unsigned char   ip_bytes[4];
    unsigned char   target_mac[6];
    int             mac_valid;         /* hedefin gerçek MAC'i biliniyor mu */
    int             active;            /* şu an engelli (UI'da görünür) */
    int             restore_pending;   /* geri alındı, restore paketleri beklemede */
    long long       last_poison_ms;
    long long       next_resolve_ms;
    char            blocked_at[32];
} BlockEntry;

static BlockEntry        g_entries[ARP_BLOCK_MAX_BLOCKED];
static platform_mutex_t  g_lock;
static int               g_lock_init = 0;

static int               g_running = 0;
static platform_thread_t g_thread;

static pcap_t           *g_pcap = NULL;          /* açık Npcap aygıtı */
static volatile int      g_engine_ok = 0;
static char              g_iface_open[MAX_IFACE_LEN]; /* handle'ın açıldığı FriendlyName */
static char              g_npf_open[256];             /* açık aygıt (\Device\NPF_...) */
static long long         g_open_retry_ms = 0;         /* başarısız açılış 3 sn'de bir denenir */
static int               g_open_fail_logged = 0;      /* açılış hatası tek sefer loglanır */
static long long         g_last_send_fail_ms = 0;     /* pcap_inject hata logu (5 sn throttle) */

/* Bağlam (GUI her karede günceller) */
static char            g_iface[MAX_IFACE_LEN];
static unsigned char   g_local_mac[6];
static int             g_local_mac_valid = 0;
static char            g_local_ip[MAX_IP_LEN];        /* probe isteklerinde sender IP */
static long long       g_local_mac_next_ms = 0;       /* platform fallback deneme aralığı */
static char            g_gateway_ip[MAX_IP_LEN];
static char            g_gateway_mac_str[MAX_MAC_LEN];
static unsigned char   g_gateway_mac[6];
static int             g_gateway_mac_valid = 0;
static long long       g_gw_next_ms = 0;              /* ağ geçidi çözüm/refresh periyodu */

/* PCAP_IF_LOOPBACK eski pcap başlıklarında olmayabilir */
#ifndef PCAP_IF_LOOPBACK
#define PCAP_IF_LOOPBACK 0
#endif

/* ================= Yardımcılar ================= */

static long long now_ms(void) {
    return (long long)GetTickCount64();
}

static void block_lock_ensure(void) {
    if (!g_lock_init) {
        platform_mutex_init(&g_lock);
        g_lock_init = 1;
    }
}

static int block_tolower_ascii(int c) {
    return (c >= 'A' && c <= 'Z') ? c + ('a' - 'A') : c;
}

/* Büyük/küçük harf duyarsız substring araması */
static const char *block_stristr(const char *haystack, const char *needle) {
    if (!haystack || !needle) return NULL;
    if (!*needle) return haystack;
    for (; *haystack; haystack++) {
        const char *h = haystack;
        const char *n = needle;
        while (*h && *n &&
               block_tolower_ascii((unsigned char)*h) ==
               block_tolower_ascii((unsigned char)*n)) {
            h++;
            n++;
        }
        if (!*n) return haystack;
    }
    return NULL;
}

static int block_strieq(const char *a, const char *b) {
    if (!a || !b) return 0;
    while (*a && *b) {
        if (block_tolower_ascii((unsigned char)*a) !=
            block_tolower_ascii((unsigned char)*b))
            return 0;
        a++;
        b++;
    }
    return *a == *b;
}

static int block_parse_mac(const char *s, unsigned char mac[6]) {
    unsigned int b[6];
    if (!s || sscanf(s, "%x:%x:%x:%x:%x:%x",
                     &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6)
        return -1;
    for (int i = 0; i < 6; i++) mac[i] = (unsigned char)b[i];
    return 0;
}

static void block_mac_to_str(const unsigned char mac[6], char *out, int len) {
    snprintf(out, len, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static int block_parse_ip4(const char *s, unsigned char ip[4]) {
    unsigned int b[4];
    if (!s || sscanf(s, "%u.%u.%u.%u", &b[0], &b[1], &b[2], &b[3]) != 4)
        return -1;
    for (int i = 0; i < 4; i++) {
        if (b[i] > 255) return -1;
        ip[i] = (unsigned char)b[i];
    }
    return 0;
}

/* ================= Çerçeve gönderme ================= */

/* Ethernet src = bizim MAC; ARP sender MAC = istenen (sahte veya gerçek) MAC.
 * 60 baytlık minimum Ethernet çerçevesi (14 eth + 28 ARP + 18 pad): bazı
 * NIC sürücüleri kısa çerçeveleri enjekte etmez. */
static void block_send_arp(pcap_t *p, const unsigned char *eth_src,
                           const unsigned char *arp_sender_mac,
                           const char *sender_ip,
                           const unsigned char *dst_mac, const char *dst_ip) {
    unsigned char buf[60];
    unsigned char sip[4], dip[4];
    if (block_parse_ip4(sender_ip, sip) != 0) return;
    if (block_parse_ip4(dst_ip, dip) != 0) return;

    memset(buf, 0, sizeof(buf));
    memcpy(buf, dst_mac, 6);             /* Ethernet dst */
    memcpy(buf + 6, eth_src, 6);         /* Ethernet src = bizim MAC */
    buf[12] = 0x08; buf[13] = 0x06;      /* EtherType: ARP */

    buf[14] = 0x00; buf[15] = 0x01;      /* HW: Ethernet */
    buf[16] = 0x08; buf[17] = 0x00;      /* Proto: IPv4 */
    buf[18] = 0x06; buf[19] = 0x04;
    buf[20] = 0x00; buf[21] = 0x02;      /* Opcode: Reply */

    memcpy(buf + 22, arp_sender_mac, 6); /* ARP sender MAC */
    memcpy(buf + 28, sip, 4);            /* ARP sender IP */
    memcpy(buf + 32, dst_mac, 6);        /* ARP target MAC */
    memcpy(buf + 38, dip, 4);            /* ARP target IP */

    if (!p) return;
    if (pcap_inject(p, buf, sizeof(buf)) < 0) {
        long long now = now_ms();
        if (now - g_last_send_fail_ms > 5000) {
            fprintf(stderr, "[ARP_BLOCK] Paket gonderilemedi: %s\n",
                    pcap_geterr(p));
            g_last_send_fail_ms = now;
        }
    }
}

/* ================= MAC çözümü (Windows) ================= */

/* GetIpNetTable'dan IP -> MAC (hızlı yol). dwAddr ağ sıralıdır; inet_addr
 * çıktısıyla aynı bellek düzeninde olduğundan doğrudan karşılaştırılır. */
static int win_arp_table_lookup(const char *ip, unsigned char mac_out[6]) {
    DWORD need = 0;
    if (GetIpNetTable(NULL, &need, FALSE) != ERROR_INSUFFICIENT_BUFFER || need == 0)
        return -1;
    PMIB_IPNETTABLE tbl = (PMIB_IPNETTABLE)malloc(need);
    if (!tbl) return -1;
    int rc = -1;
    if (GetIpNetTable(tbl, &need, FALSE) == NO_ERROR) {
        DWORD want = inet_addr(ip);
        for (DWORD i = 0; i < tbl->dwNumEntries; i++) {
            MIB_IPNETROW *row = &tbl->table[i];
            if (row->dwType == MIB_IPNET_TYPE_INVALID) continue;
            if (row->dwAddr != want) continue;
            if (row->dwPhysAddrLen < 6) continue;
            const unsigned char *m = row->bPhysAddr;
            if (m[0] == 0 && m[1] == 0 && m[2] == 0 &&
                m[3] == 0 && m[4] == 0 && m[5] == 0) continue;
            memcpy(mac_out, m, 6);
            rc = 0;
            break;
        }
    }
    free(tbl);
    return rc;
}

/* ARP Request gönderip cevabı dinler (en fazla 2 sn). Kendi zehirleme
 * çerçevelerimizin (Ethernet src = g_local_mac) geri dönüp bizi kandırması
 * engellenir; sadece opcode=Reply ve sender IP eşleşen yanıtlar kabul edilir. */
static int win_arp_probe(const char *ip, unsigned char mac_out[6]) {
    pcap_t *p = g_pcap;
    unsigned char sip[4], tip[4];
    if (!p) return -1;
    if (!g_local_mac_valid) return -1;          /* kendi sender MAC'imiz yok */
    if (!g_local_ip[0]) return -1;              /* sender IP yok */
    if (block_parse_ip4(g_local_ip, sip) != 0) return -1;
    if (block_parse_ip4(ip, tip) != 0) return -1;

    unsigned char buf[60];
    memset(buf, 0, sizeof(buf));
    memset(buf, 0xff, 6);                    /* dst: broadcast */
    memcpy(buf + 6, g_local_mac, 6);         /* src: bizim MAC */
    buf[12] = 0x08; buf[13] = 0x06;          /* ARP */

    buf[14] = 0x00; buf[15] = 0x01;
    buf[16] = 0x08; buf[17] = 0x00;
    buf[18] = 0x06; buf[19] = 0x04;
    buf[20] = 0x00; buf[21] = 0x01;          /* Opcode: Request */

    memcpy(buf + 22, g_local_mac, 6);
    memcpy(buf + 28, sip, 4);
    memset(buf + 32, 0, 6);                  /* hedef MAC bilinmiyor */
    memcpy(buf + 38, tip, 4);

    if (pcap_inject(p, buf, sizeof(buf)) < 0) return -1;

    long long deadline = now_ms() + 2000;
    int result = -1;
    while (now_ms() < deadline) {
        struct pcap_pkthdr *hdr = NULL;
        const unsigned char *data = NULL;
        int ret = pcap_next_ex(p, &hdr, &data);
        if (ret == 0) continue;              /* okuma zaman aşımı (100 ms) */
        if (ret < 0) break;                  /* hata / PCAP_ERROR_BREAK */
        if (!hdr || hdr->caplen < 42) continue;
        if (data[12] != 0x08 || data[13] != 0x06) continue;  /* ARP değil */
        int op = (data[20] << 8) | data[21];
        if (op != 2) continue;               /* sadece Reply */
        if (memcmp(data + 6, g_local_mac, 6) == 0) continue; /* kendi çerçevemiz */
        if (memcmp(data + 28, tip, 4) != 0) continue;        /* sender IP eşleşmesi */
        const unsigned char *sha = data + 22;
        if (sha[0] == 0 && sha[1] == 0 && sha[2] == 0 &&
            sha[3] == 0 && sha[4] == 0 && sha[5] == 0) continue;
        memcpy(mac_out, sha, 6);
        result = 0;
        break;
    }
    return result;
}

/* IP -> MAC: önce OS ARP tablosu, olmazsa canlı prob */
static int win_resolve_mac(const char *ip, unsigned char mac_out[6]) {
    if (!ip || !ip[0]) return -1;
    if (win_arp_table_lookup(ip, mac_out) == 0) return 0;
    return win_arp_probe(ip, mac_out);
}

/* ================= Arayüz -> Npcap aygıt adı ================= */

static int win_dev_is_loopback(const pcap_if_t *d) {
    if (!d) return 0;
    if (d->flags & PCAP_IF_LOOPBACK) return 1;
    if (d->name && block_stristr(d->name, "loopback")) return 1;
    if (d->description && block_stristr(d->description, "loopback")) return 1;
    return 0;
}

/* FriendlyName ("Wi-Fi") -> Npcap aygıt adı ("\Device\NPF_{GUID}").
 * 1) GetAdaptersAddresses: FriendlyName -> AdapterName(GUID) eşleşmesi
 *    (önce tam, sonra substring; büyük/küçük harf duyarsız).
 * 2) pcap_findalldevs ile doğrulama/önceliklendirme:
 *    tam NPF adı > GUID içeren ad > açıklaması FriendlyName içeren aygıt.
 * 3) Hiçbiri yoksa ilk loopback olmayan aygıt (best-effort). */
static int win_iface_to_npf(const char *friendly, char *npf_out, int len) {
    if (!friendly || !friendly[0]) return -1;
    if (npf_out && len > 0) npf_out[0] = '\0';

    /* Aşama 1: FriendlyName -> GUID */
    char guid[128] = {0};
    ULONG buflen = 0;
    ULONG rc = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, NULL, &buflen);
    if (rc == ERROR_BUFFER_OVERFLOW && buflen > 0) {
        IP_ADAPTER_ADDRESSES *aa = (IP_ADAPTER_ADDRESSES *)malloc(buflen);
        if (aa) {
            if (GetAdaptersAddresses(AF_UNSPEC, 0, NULL, aa, &buflen) == ERROR_SUCCESS) {
                /* Pass 1: tam eşleşme */
                for (IP_ADAPTER_ADDRESSES *cur = aa; cur && !guid[0]; cur = cur->Next) {
                    char fn[256] = {0};
                    if (!cur->FriendlyName || !cur->AdapterName) continue;
                    WideCharToMultiByte(CP_UTF8, 0, cur->FriendlyName, -1,
                                        fn, sizeof(fn) - 1, NULL, NULL);
                    if (block_strieq(fn, friendly))
                        strncpy(guid, cur->AdapterName, sizeof(guid) - 1);
                }
                /* Pass 2: substring (kısaltılmış ad verilmiş olabilir) */
                for (IP_ADAPTER_ADDRESSES *cur = aa; cur && !guid[0]; cur = cur->Next) {
                    char fn[256] = {0};
                    if (!cur->FriendlyName || !cur->AdapterName) continue;
                    WideCharToMultiByte(CP_UTF8, 0, cur->FriendlyName, -1,
                                        fn, sizeof(fn) - 1, NULL, NULL);
                    if (block_stristr(fn, friendly) || block_stristr(friendly, fn))
                        strncpy(guid, cur->AdapterName, sizeof(guid) - 1);
                }
            }
            free(aa);
        }
    }

    char exact_npf[256] = {0};
    if (guid[0])
        snprintf(exact_npf, sizeof(exact_npf), "\\Device\\NPF_%s", guid);

    /* Aşama 2: pcap listesinde doğrula / en iyi adayı seç */
    pcap_if_t *devs = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&devs, errbuf) < 0)
        return -1;

    pcap_if_t *best = NULL;
    int best_rank = 0;
    for (pcap_if_t *d = devs; d; d = d->next) {
        if (win_dev_is_loopback(d)) continue;
        int rank = 0;
        if (exact_npf[0]) {
            if (block_strieq(d->name, exact_npf))
                rank = 3;                    /* tam NPF adı */
            else if (d->name && strstr(d->name, guid))
                rank = 2;                    /* GUID içeren ad */
        }
        if (rank < 2 && d->description && block_stristr(d->description, friendly))
            rank = 2;                        /* açıklamada FriendlyName */
        if (rank > best_rank) {
            best_rank = rank;
            best = d;
        }
    }
    if (!best) {                             /* fallback: ilk fiziksel aygıt */
        for (pcap_if_t *d = devs; d; d = d->next) {
            if (win_dev_is_loopback(d)) continue;
            best = d;
            break;
        }
    }
    if (best && npf_out) {
        strncpy(npf_out, best->name, len - 1);
        pcap_freealldevs(devs);
        return 0;
    }
    pcap_freealldevs(devs);
    return -1;
}

/* ================= Motor aç/kapa ================= */

static int win_engine_open(void) {
    char npf[256] = {0};
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    char reason[256] = {0};

    if (win_iface_to_npf(g_iface, npf, sizeof(npf)) < 0) {
        snprintf(reason, sizeof(reason),
                 "arayuz Npcap aygitina eslenemedi (%s)", g_iface);
    } else {
        pcap_t *p = pcap_open_live(npf, 65535, 1, 100, errbuf);
        if (!p) {
            snprintf(reason, sizeof(reason), "pcap_open_live(%s): %s", npf, errbuf);
        } else if (pcap_datalink(p) != DLT_EN10MB) {
            snprintf(reason, sizeof(reason), "%s Ethernet degil (dlt=%d)",
                     npf, pcap_datalink(p));
            pcap_close(p);
        } else {
            /* BPF: yalnız ARP — başarısızlık ölümcül değil, prob paketleri
             * zaten elle süzülüyor. */
            struct bpf_program fp;
            if (pcap_compile(p, &fp, "arp", 1, PCAP_NETMASK_UNKNOWN) == 0) {
                if (pcap_setfilter(p, &fp) < 0) {
                    /* filtre kurulamadı — yoksay */
                }
                pcap_freecode(&fp);
            }
            g_pcap = p;
            strncpy(g_npf_open, npf, sizeof(g_npf_open) - 1);
            strncpy(g_iface_open, g_iface, sizeof(g_iface_open) - 1);
            g_engine_ok = 1;
            g_open_fail_logged = 0;
            g_last_send_fail_ms = 0;
            fprintf(stderr, "[ARP_BLOCK] Npcap motoru acildi: %s (%s)\n",
                    npf, g_iface);
            return 0;
        }
    }
    if (!g_open_fail_logged) {
        fprintf(stderr,
                "[ARP_BLOCK] Motor acilamadi: %s. Npcap kurulu mu, yonetici "
                "yetkisi var mi?\n", reason);
        g_open_fail_logged = 1;
    }
    return -1;
}

/* İşçi thread dışından çağrılmaz (kilit gerekmez) */
static void win_engine_close(void) {
    if (g_pcap) {
        pcap_close(g_pcap);
        g_pcap = NULL;
    }
    g_engine_ok = 0;
    g_npf_open[0] = '\0';
    g_iface_open[0] = '\0';
    g_open_fail_logged = 0;
}

/* ================= Zehirleme / restore ================= */

/* Slot indeksine göre tekil bogus (ölü) MAC üret */
static void block_bogus_mac(int slot, unsigned char mac[6]) {
    mac[0] = 0x02;
    mac[1] = 0xBA;
    mac[2] = 0xAD;
    mac[3] = 0xBE;
    mac[4] = 0xEF;
    mac[5] = (unsigned char)(0x10 + (slot & 0x0F));
}

/* Hedefe "gateway → bogus" ve gateway'e "hedef → bogus" gönder */
static void block_poison(pcap_t *p, int slot, const BlockEntry *e,
                         const unsigned char *eth_src,
                         const unsigned char *gw_mac, int gw_mac_valid,
                         const char *gw_ip) {
    unsigned char bogus[6];
    block_bogus_mac(slot, bogus);

    /* Hedefe: "Gateway = bogus" */
    if (e->mac_valid && gw_ip[0])
        block_send_arp(p, eth_src, bogus, gw_ip, e->target_mac, e->ip);
    /* Gateway'e: "Hedef = bogus" */
    if (gw_mac_valid && e->mac_valid)
        block_send_arp(p, eth_src, bogus, e->ip, gw_mac, gw_ip);
}

/* Gerçek eşleşmeleri geri yükle */
static void block_restore(pcap_t *p, const BlockEntry *e,
                          const unsigned char *eth_src,
                          const unsigned char *gw_mac, int gw_mac_valid,
                          const char *gw_ip) {
    if (!p) return;
    if (!e->mac_valid) return;   /* MAC bilinmiyor → ARP 30-60 sn'de kendiliğinden düzelir */
    if (!gw_mac_valid) return;
    /* Hedefe: "Gateway = gerçek gw MAC" */
    if (gw_ip[0])
        block_send_arp(p, eth_src, gw_mac, gw_ip, e->target_mac, e->ip);
    /* Gateway'e: "Hedef = gerçek hedef MAC" */
    block_send_arp(p, eth_src, e->target_mac, e->ip, gw_mac, gw_ip);
}

/* ================= İşçi thread ================= */

static void *arp_block_worker(void *arg) {
    (void)arg;

    while (g_running) {
        long long now = now_ms();

        /* --- Npcap handle yoksa açmayı dene (kilit dışında) --- */
        if (!g_pcap && g_iface[0] && now >= g_open_retry_ms) {
            if (win_engine_open() != 0)
                g_open_retry_ms = now_ms() + 3000;
        }

        platform_mutex_lock(&g_lock);

        /* --- Arayüz değiştiyse eski handle'ı kapat, çözümleri sıfırla --- */
        if (g_pcap && g_iface[0] && strcmp(g_iface_open, g_iface) != 0) {
            fprintf(stderr, "[ARP_BLOCK] Arayuz degisti: %s -> %s, motor "
                    "yeniden aciliyor.\n", g_iface_open, g_iface);
            win_engine_close();
            for (int i = 0; i < ARP_BLOCK_MAX_BLOCKED; i++) {
                g_entries[i].mac_valid = 0;
                g_entries[i].next_resolve_ms = 0;
            }
        }

        /* --- İhtiyaç analizi: lokal MAC fallback + ağ geçidi çözümü --- */
        int has_active = 0;
        for (int i = 0; i < ARP_BLOCK_MAX_BLOCKED; i++) {
            if (g_entries[i].active && g_entries[i].ip[0]) {
                has_active = 1;
                break;
            }
        }
        int need_local = 0;
        if (!g_local_mac_valid && g_iface[0] && now >= g_local_mac_next_ms)
            need_local = 1;
        int need_gw = 0;
        if (has_active && g_gateway_ip[0] &&
            (!g_gateway_mac_valid || now >= g_gw_next_ms))
            need_gw = 1;

        /* Lokal MAC eksikse platform'dan al (arayüz adı Windows'ta platform
         * katmanında yok sayılır — ilk UP adaptör döner) */
        if (need_local) {
            char iface_c[MAX_IFACE_LEN];
            char macbuf[MAX_MAC_LEN] = {0};
            strncpy(iface_c, g_iface, sizeof(iface_c) - 1);
            platform_mutex_unlock(&g_lock);
            unsigned char m[6];
            int ok = (platform_get_local_mac(iface_c, macbuf, sizeof(macbuf)) == 0 &&
                      block_parse_mac(macbuf, m) == 0);
            platform_mutex_lock(&g_lock);
            if (ok && !g_local_mac_valid) {
                memcpy(g_local_mac, m, 6);
                g_local_mac_valid = 1;
                fprintf(stderr, "[ARP_BLOCK] Lokal MAC (fallback): %s\n", macbuf);
            }
            if (!g_local_mac_valid)
                g_local_mac_next_ms = now_ms() + 2000;
        }

        /* Ağ geçidi MAC'ini çöz (kilit dışında; önce ARP tablosu, sonra prob) */
        if (need_gw) {
            char gw_c[MAX_IP_LEN];
            strncpy(gw_c, g_gateway_ip, sizeof(gw_c) - 1);
            platform_mutex_unlock(&g_lock);
            unsigned char m[6];
            int r = win_resolve_mac(gw_c, m);
            platform_mutex_lock(&g_lock);
            if (r == 0 && strcmp(g_gateway_ip, gw_c) == 0) {
                memcpy(g_gateway_mac, m, 6);
                block_mac_to_str(m, g_gateway_mac_str, sizeof(g_gateway_mac_str));
                g_gateway_mac_valid = 1;
                fprintf(stderr, "[ARP_BLOCK] Gateway MAC cozuldu: %s (%s)\n",
                        gw_c, g_gateway_mac_str);
            }
            g_gw_next_ms = now_ms() + ((r == 0) ? 30000 : 2000);
        }

        /* --- Restore beklemede olan slotları gerçek eşleşmelerle onar --- */
        for (int i = 0; i < ARP_BLOCK_MAX_BLOCKED; i++) {
            BlockEntry *e = &g_entries[i];
            if (!e->restore_pending || !e->ip[0]) continue;
            if (g_pcap && g_local_mac_valid) {
                for (int r = 0; r < BLOCK_RESTORE_COUNT; r++)
                    block_restore(g_pcap, e, g_local_mac, g_gateway_mac,
                                  g_gateway_mac_valid, g_gateway_ip);
            }
            memset(e, 0, sizeof(*e));
        }

        /* --- Zehirleme (her hedef kendi periyodunda) --- */
        if (g_pcap && g_local_mac_valid) {
            for (int i = 0; i < ARP_BLOCK_MAX_BLOCKED; i++) {
                BlockEntry *e = &g_entries[i];
                if (!e->active || !e->ip[0] || !e->mac_valid) continue;
                if (now - e->last_poison_ms < BLOCK_POISON_MS) continue;
                block_poison(g_pcap, i, e, g_local_mac,
                             g_gateway_mac, g_gateway_mac_valid, g_gateway_ip);
                e->last_poison_ms = now;
            }
        }

        /* --- MAC'i bilinmeyen aktif hedefleri not et (kilidi bırakıp çözeceğiz) --- */
        char resolve_ip[ARP_BLOCK_MAX_BLOCKED][MAX_IP_LEN];
        int  resolve_slot[ARP_BLOCK_MAX_BLOCKED];
        int  resolve_n = 0;
        for (int i = 0; i < ARP_BLOCK_MAX_BLOCKED; i++) {
            BlockEntry *e = &g_entries[i];
            if (!e->active || !e->ip[0] || e->mac_valid) continue;
            if (now < e->next_resolve_ms) continue;
            strncpy(resolve_ip[resolve_n], e->ip, MAX_IP_LEN - 1);
            resolve_slot[resolve_n] = i;
            resolve_n++;
        }
        platform_mutex_unlock(&g_lock);

        /* --- MAC çözme (kilit dışında; ≤2 sn prob olabilir) --- */
        for (int r = 0; r < resolve_n; r++) {
            unsigned char m[6];
            if (win_resolve_mac(resolve_ip[r], m) == 0) {
                platform_mutex_lock(&g_lock);
                BlockEntry *e = &g_entries[resolve_slot[r]];
                if (e->active && e->ip[0] &&
                    strcmp(e->ip, resolve_ip[r]) == 0) {
                    memcpy(e->target_mac, m, 6);
                    e->mac_valid = 1;
                }
                platform_mutex_unlock(&g_lock);
            }
        }
        /* Çözülemeyenlerin bir sonraki denemesini ~5 sn sonraya al */
        if (resolve_n > 0) {
            long long next = now_ms() + 5000;
            platform_mutex_lock(&g_lock);
            for (int i = 0; i < ARP_BLOCK_MAX_BLOCKED; i++) {
                BlockEntry *e = &g_entries[i];
                if (!e->active || !e->ip[0] || e->mac_valid) continue;
                if (e->next_resolve_ms == 0) e->next_resolve_ms = next;
            }
            platform_mutex_unlock(&g_lock);
        }

        platform_sleep_ms(BLOCK_TICK_MS);
    }

    /* ===== Temizlik: hâlâ aktif olanları geri yükle, Npcap aygıtını kapat ===== */
    platform_mutex_lock(&g_lock);
    for (int i = 0; i < ARP_BLOCK_MAX_BLOCKED; i++) {
        BlockEntry *e = &g_entries[i];
        if (!e->active || !e->ip[0]) continue;
        if (g_pcap && g_local_mac_valid) {
            for (int r = 0; r < BLOCK_RESTORE_COUNT; r++)
                block_restore(g_pcap, e, g_local_mac, g_gateway_mac,
                              g_gateway_mac_valid, g_gateway_ip);
        }
        memset(e, 0, sizeof(*e));
    }
    platform_mutex_unlock(&g_lock);
    win_engine_close();
    fprintf(stderr, "[ARP_BLOCK] Durduruldu, engeller geri alindi.\n");
    return NULL;
}

/* ================= Public API ================= */

void arp_block_init(void) {
    block_lock_ensure();
    if (g_running) return;
    g_running = 1;
    platform_thread_create(&g_thread, arp_block_worker, NULL);
    platform_thread_detach(g_thread);
    fprintf(stderr, "[ARP_BLOCK] Motor baslatildi (Npcap).\n");
}

void arp_block_cleanup(void) {
    if (!g_running) return;
    g_running = 0;
    /* İşçi, sürmekte olan 2 sn'lik probunu bitirip restore paketlerini
     * gönderebilsin diye Linux'takinden biraz daha uzun beklenir. */
    platform_sleep_ms(2200);
}

int arp_block_set_context(const char *iface, const char *local_mac,
                          const char *gateway_ip, const char *gateway_mac,
                          const char *local_ip) {
    if (!iface || !iface[0] || !local_mac || !local_mac[0] || !gateway_ip) return -1;
    block_lock_ensure();

    platform_mutex_lock(&g_lock);
    int gw_changed = (strcmp(g_gateway_ip, gateway_ip) != 0);
    strncpy(g_iface, iface, sizeof(g_iface) - 1);
    strncpy(g_gateway_ip, gateway_ip, sizeof(g_gateway_ip) - 1);

    if (block_parse_mac(local_mac, g_local_mac) == 0)
        g_local_mac_valid = 1;

    /* Probe isteklerinde sender IP olarak kullanılır */
    if (local_ip && local_ip[0])
        strncpy(g_local_ip, local_ip, sizeof(g_local_ip) - 1);
    else
        g_local_ip[0] = '\0';

    if (gw_changed) {
        /* Ağ geçidi değişti: eski çözümü sıfırla */
        g_gateway_mac_valid = 0;
        g_gateway_mac_str[0] = '\0';
    }
    /* Windows'ta platform_get_gateway MAC olarak "N/A" döner ve GUI bunu her
     * karede gönderir; bu yüzden "N/A"/boş gelirse mevcut çözüm KORUNUR.
     * Gerçek bir MAC parse edilebiliyorsa o kullanılır. */
    if (gateway_mac && gateway_mac[0] &&
        block_strieq(gateway_mac, "N/A") == 0 &&
        block_parse_mac(gateway_mac, g_gateway_mac) == 0) {
        g_gateway_mac_valid = 1;
        strncpy(g_gateway_mac_str, gateway_mac, sizeof(g_gateway_mac_str) - 1);
    }
    platform_mutex_unlock(&g_lock);
    return 0;
}

static BlockEntry *block_find(const char *ip) {
    for (int i = 0; i < ARP_BLOCK_MAX_BLOCKED; i++) {
        if (g_entries[i].ip[0] && strcmp(g_entries[i].ip, ip) == 0)
            return &g_entries[i];
    }
    return NULL;
}

int arp_block_set(const char *ip, const char *target_mac, int block) {
    if (!ip || !ip[0]) return -1;
    struct in_addr check;
    if (inet_pton(AF_INET, ip, &check) != 1) return -1;

    block_lock_ensure();
    platform_mutex_lock(&g_lock);

    /* Gateway'in kendisini engellemeye izin verme */
    if (g_gateway_ip[0] && strcmp(ip, g_gateway_ip) == 0) {
        platform_mutex_unlock(&g_lock);
        return -1;
    }

    if (block) {
        BlockEntry *found = block_find(ip);
        if (found) {   /* zaten engelli — MAC bilgisini tazele */
            if (target_mac && target_mac[0] && block_parse_mac(target_mac, found->target_mac) == 0)
                found->mac_valid = 1;
            found->restore_pending = 0;
            found->active = 1;
            platform_mutex_unlock(&g_lock);
            return 1;
        }
        for (int i = 0; i < ARP_BLOCK_MAX_BLOCKED; i++) {
            BlockEntry *e = &g_entries[i];
            if (e->ip[0]) continue;   /* dolu slot */
            memset(e, 0, sizeof(*e));
            strncpy(e->ip, ip, sizeof(e->ip) - 1);
            memcpy(e->ip_bytes, &check, 4);
            e->mac_valid = 0;
            if (target_mac && target_mac[0] && block_parse_mac(target_mac, e->target_mac) == 0)
                e->mac_valid = 1;
            e->active = 1;
            e->last_poison_ms = 0;          /* ilk zehirleme hemen */
            e->next_resolve_ms = 0;
            time_t t = time(NULL);
            struct tm tmv;
#if defined(_WIN32)
            localtime_s(&tmv, &t);
#else
            localtime_r(&t, &tmv);
#endif
            strftime(e->blocked_at, sizeof(e->blocked_at), "%H:%M:%S", &tmv);
            platform_mutex_unlock(&g_lock);
            return 1;
        }
        platform_mutex_unlock(&g_lock);
        return 0;   /* kapasite dolu */
    }

    /* Geri al */
    BlockEntry *e = block_find(ip);
    if (e) {
        e->active = 0;
        e->restore_pending = 1;   /* işçi gerçek eşleşmeleri bildirsin */
    }
    platform_mutex_unlock(&g_lock);
    return (e != NULL) ? 1 : 0;
}

int arp_block_is_blocked(const char *ip) {
    if (!ip) return 0;
    int blocked = 0;
    block_lock_ensure();
    platform_mutex_lock(&g_lock);
    BlockEntry *e = block_find(ip);
    if (e) blocked = e->active;
    platform_mutex_unlock(&g_lock);
    return blocked;
}

void arp_block_get_snapshot(ArpBlockSnapshot *out) {
    if (!out) return;
    block_lock_ensure();
    memset(out, 0, sizeof(*out));

    platform_mutex_lock(&g_lock);
    out->engine_ok = g_engine_ok;
    strncpy(out->iface, g_iface, sizeof(out->iface) - 1);
    strncpy(out->gateway_ip, g_gateway_ip, sizeof(out->gateway_ip) - 1);
    strncpy(out->gateway_mac, g_gateway_mac_str, sizeof(out->gateway_mac) - 1);

    int n = 0;
    for (int i = 0; i < ARP_BLOCK_MAX_BLOCKED; i++) {
        BlockEntry *e = &g_entries[i];
        if (!e->active || !e->ip[0]) continue;
        ArpBlockEntry *dst = &out->entries[n];
        strncpy(dst->ip, e->ip, sizeof(dst->ip) - 1);
        if (e->mac_valid)
            block_mac_to_str(e->target_mac, dst->mac, sizeof(dst->mac));
        strncpy(dst->blocked_at, e->blocked_at, sizeof(dst->blocked_at) - 1);
        n++;
        if (n >= ARP_BLOCK_MAX_BLOCKED) break;
    }
    out->count = n;
    platform_mutex_unlock(&g_lock);
}

int arp_block_engine_ok(void) {
    return g_engine_ok;
}

#else /* !HAVE_NPCAP — sessiz stub: Npcap SDK'sız derleme */

/* Motor yok: API no-op, engine_ok=0. GUI, snapshot üzerinden "motor kapalı"
 * durumunu gösterir; proje Npcap olmadan da derlenir ve diğer özellikler
 * (GUI, ARP tarama, port tarama) çalışır. */
void arp_block_init(void) {}
void arp_block_cleanup(void) {}
int  arp_block_set_context(const char *iface, const char *local_mac,
                           const char *gateway_ip, const char *gateway_mac,
                           const char *local_ip) {
    (void)iface; (void)local_mac; (void)gateway_ip;
    (void)gateway_mac; (void)local_ip;
    return -1;
}
int  arp_block_set(const char *ip, const char *target_mac, int block) {
    (void)ip; (void)target_mac; (void)block;
    return -1;
}
int  arp_block_is_blocked(const char *ip) { (void)ip; return 0; }
void arp_block_get_snapshot(ArpBlockSnapshot *out) {
    if (!out) return;
    memset(out, 0, sizeof(*out));
    out->engine_ok = 0;
}
int  arp_block_engine_ok(void) { return 0; }

#endif /* HAVE_NPCAP */


#endif /* PLATFORM_LINUX / WINDOWS */
