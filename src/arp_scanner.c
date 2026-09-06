/*
 * arp_scanner.c — ARP Ağ Tarayıcı Uygulaması
 * Ağdaki cihazları keşfeder, MAC vendor tanır, sınıflandırır.
 * Linux'ta /proc/net/arp + ping sweep + ip neigh kullanır.
 * Windows'ta arp -a komutu ile çalışır.
 */
#include "arp_scanner.h"
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <time.h>

#ifdef PLATFORM_WINDOWS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#endif

/* ========== Global State ========== */
static ScanResults  g_results;
static platform_mutex_t g_results_lock;
static ScanLog      g_log;
static platform_mutex_t g_log_lock;
static int          g_initialized = 0;
static int          g_auto_scan_running = 0;

/* ========== Log ========== */
void scanner_log(const char *fmt, ...) {
    platform_mutex_lock(&g_log_lock);
    
    char buf[256];
    char time_str[16];
    time_now_hms(time_str, sizeof(time_str));
    
    va_list args;
    va_start(args, fmt);
    int prefix_len = snprintf(buf, sizeof(buf), "[%s] ", time_str);
    vsnprintf(buf + prefix_len, sizeof(buf) - prefix_len, fmt, args);
    va_end(args);
    
    int idx = g_log.write_idx % MAX_SCAN_LOG_LINES;
    strncpy(g_log.lines[idx], buf, 255);
    g_log.lines[idx][255] = '\0';
    g_log.write_idx++;
    if (g_log.count < MAX_SCAN_LOG_LINES) g_log.count++;
    
    platform_mutex_unlock(&g_log_lock);
}

void scanner_get_log(ScanLog *out) {
    platform_mutex_lock(&g_log_lock);
    memcpy(out, &g_log, sizeof(ScanLog));
    platform_mutex_unlock(&g_log_lock);
}

#ifdef PLATFORM_WINDOWS

/* Windows: 'start /B ping' komutu yerine native ICMP ping sweep.
 * Hedeflere tek tek IcmpSendEcho gonderilir; yanit alinan her IP icin
 * ARP tablosuna girdi dusmesi icin kisa bir bekleme yapilir. */
#define WIN_PING_TIMEOUT_MS  700
#define WIN_PING_THREADS     8
#define WIN_PING_SLICE       32

typedef struct {
    unsigned int a, b, c;   /* ag adresinin ilk 3 okteti */
    int start, end;         /* taranacak son oktet araligi [start, end] */
} WinPingSlice;

static void *_win_ping_worker(void *arg) {
    WinPingSlice *s = (WinPingSlice *)arg;
    HANDLE icmp = IcmpCreateFile();
    if (icmp == INVALID_HANDLE_VALUE) return NULL;

    unsigned char payload[8] = {0};
    unsigned char reply[sizeof(ICMP_ECHO_REPLY) + 32];

    for (int i = s->start; i <= s->end; i++) {
        char ip[32];
        IPAddr dest = 0;
        snprintf(ip, sizeof(ip), "%u.%u.%u.%u", s->a, s->b, s->c, (unsigned)i);
        inet_pton(AF_INET, ip, &dest);
        if (dest == 0) continue;
        if (IcmpSendEcho(icmp, dest, payload, sizeof(payload), NULL,
                         reply, sizeof(reply), WIN_PING_TIMEOUT_MS) != 0) {
            Sleep(5); /* ARP girdisinin yazilmasi icin kisa nefes */
        }
    }
    IcmpCloseHandle(icmp);
    return NULL;
}

static void _win_ping_sweep(unsigned int a, unsigned int b, unsigned int c) {
    static WinPingSlice slices[WIN_PING_THREADS];
    platform_thread_t th[WIN_PING_THREADS];
    int started = 0;

    int base = 1;
    for (int n = 0; n < WIN_PING_THREADS && base <= 254; n++) {
        int e = base + WIN_PING_SLICE - 1;
        if (e > 254) e = 254;
        slices[n].a = a; slices[n].b = b; slices[n].c = c;
        slices[n].start = base;
        slices[n].end   = e;
        base = e + 1;

        if (platform_thread_create(&th[started], _win_ping_worker, &slices[n]) == 0)
            started++;
    }
    for (int i = 0; i < started; i++) {
        WaitForSingleObject(th[i], INFINITE);
        CloseHandle(th[i]);
    }
}
#endif /* PLATFORM_WINDOWS */

/* ========== ARP Tarama (Fallback: ping + arp tablosu) ========== */
static int _scan_with_arp_table(Device *devices, int max_devices, const char *network_range) {
    int count = 0;
    
    /* 1. Ping sweep ile ARP cache'i doldur */
    scanner_log("Ping sweep baslatiliyor: %s", network_range);
    
    int base_parts[4];
    if (sscanf(network_range, "%d.%d.%d.%d", &base_parts[0], &base_parts[1], &base_parts[2], &base_parts[3]) < 3) {
        return 0;
    }
    
#ifdef PLATFORM_LINUX
    /* Her 20 IP'yi paralel olarak pingle */
    for (int batch_start = 1; batch_start <= 254; batch_start += 20) {
        char cmd[2048] = {0};
        int cmd_len = 0;
        for (int i = batch_start; i < batch_start + 20 && i <= 254; i++) {
            cmd_len += snprintf(cmd + cmd_len, sizeof(cmd) - cmd_len,
                "ping -c 1 -W 1 %d.%d.%d.%d >/dev/null 2>&1 & ",
                base_parts[0], base_parts[1], base_parts[2], i);
        }
        strcat(cmd, "wait 2>/dev/null");
        platform_run_command(cmd, NULL, 0);
    }
#else
    /* Windows: cmd 'start /B ping' yerine native ICMP sweep (IcmpSendEcho) */
    _win_ping_sweep(base_parts[0], base_parts[1], base_parts[2]);
#endif
    
    scanner_log("Ping sweep tamamlandi, ARP tablosu okunuyor...");
    platform_sleep_ms(500);
    
    /* 2. ARP tablosunu oku */
    /* IP -> MAC mapping (tekillik için) */
    char seen_ips[MAX_DEVICES][MAX_IP_LEN];
    int seen_count = 0;
    
#ifdef PLATFORM_LINUX
    /* /proc/net/arp'den oku */
    FILE *fp = fopen("/proc/net/arp", "r");
    if (fp) {
        char line[256];
        fgets(line, sizeof(line), fp); /* başlık */
        while (fgets(line, sizeof(line), fp) && count < max_devices) {
            char ip[64], hw_type[16], flags[16], mac[32], mask[16], iface[32];
            if (sscanf(line, "%s %s %s %s %s %s", ip, hw_type, flags, mac, mask, iface) >= 4) {
                if (strcmp(mac, "00:00:00:00:00:00") == 0) continue;
                
                /* Tekil kontrol */
                int duplicate = 0;
                for (int i = 0; i < seen_count; i++) {
                    if (strcmp(seen_ips[i], ip) == 0) { duplicate = 1; break; }
                }
                if (duplicate) continue;
                strncpy(seen_ips[seen_count++], ip, MAX_IP_LEN);
                
                Device *dev = &devices[count];
                memset(dev, 0, sizeof(Device));
                strncpy(dev->ip, ip, MAX_IP_LEN);
                strncpy(dev->mac, mac, MAX_MAC_LEN);
                str_upper(dev->mac);
                dev->vendor[0] = '\0';
                platform_get_hostname(ip, dev->hostname, MAX_HOSTNAME_LEN);
                dev->discovered_at = time(NULL);
                dev->last_seen = time(NULL);
                
                count++;
            }
        }
        fclose(fp);
    }
    
    /* ip neigh ile de dene */
    {
        char output[MAX_CMD_OUTPUT];
        if (platform_run_command("ip neigh show 2>/dev/null", output, sizeof(output)) == 0) {
            char *line = strtok(output, "\n");
            while (line && count < max_devices) {
                char ip[64], mac[32];
                /* Format: "192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE" */
                char *lladdr = strstr(line, "lladdr ");
                if (lladdr) {
                    if (sscanf(line, "%s", ip) == 1) {
                        sscanf(lladdr + 7, "%s", mac);
                        
                        /* Tekil kontrol */
                        int duplicate = 0;
                        for (int i = 0; i < seen_count; i++) {
                            if (strcmp(seen_ips[i], ip) == 0) { duplicate = 1; break; }
                        }
                        if (!duplicate && strcmp(mac, "00:00:00:00:00:00") != 0) {
                            strncpy(seen_ips[seen_count++], ip, MAX_IP_LEN);
                            
                            Device *d = &devices[count];
                            memset(d, 0, sizeof(Device));
                            strncpy(d->ip, ip, MAX_IP_LEN);
                            strncpy(d->mac, mac, MAX_MAC_LEN);
                            str_upper(d->mac);
                            d->vendor[0] = '\0';
                            platform_get_hostname(ip, d->hostname, MAX_HOSTNAME_LEN);
                            d->discovered_at = time(NULL);
                            d->last_seen = time(NULL);
                            count++;
                        }
                    }
                }
                line = strtok(NULL, "\n");
            }
        }
    }
#else
    /* Windows: GetIpNetTable ile ARP tablosunu dogrudan oku;
     * basarisiz olursa eski 'arp -a' parse yolu fallback olarak kalir. */
    {
        int win_arp_ok = 0;
        DWORD tbl_size = 0;
        if (GetIpNetTable(NULL, &tbl_size, FALSE) == ERROR_INSUFFICIENT_BUFFER &&
            tbl_size > 0) {
            PMIB_IPNETTABLE tbl = (PMIB_IPNETTABLE)malloc((size_t)tbl_size);
            if (tbl) {
                if (GetIpNetTable(tbl, &tbl_size, FALSE) == NO_ERROR) {
                    win_arp_ok = 1;
                    for (DWORD ri = 0; ri < tbl->dwNumEntries && count < max_devices; ri++) {
                        MIB_IPNETROW *row = &tbl->table[ri];
                        const unsigned char *m;
                        char ip[64], mac[32];

                        if (row->dwType == MIB_IPNET_TYPE_INVALID) continue;
                        if (row->dwAddr == 0 ||
                            (row->dwAddr & 0xFF) == 0 || (row->dwAddr & 0xFF) == 0xFF)
                            continue;
                        if (row->dwPhysAddrLen < 6) continue;
                        m = row->bPhysAddr;
                        if (m[0] == 0 && m[1] == 0 && m[2] == 0 &&
                            m[3] == 0 && m[4] == 0 && m[5] == 0)
                            continue;

                        snprintf(ip, sizeof(ip), "%u.%u.%u.%u",
                                 (unsigned)(row->dwAddr & 0xFF),
                                 (unsigned)((row->dwAddr >> 8) & 0xFF),
                                 (unsigned)((row->dwAddr >> 16) & 0xFF),
                                 (unsigned)((row->dwAddr >> 24) & 0xFF));
                        snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                                 m[0], m[1], m[2], m[3], m[4], m[5]);

                        int duplicate = 0;
                        for (int i = 0; i < seen_count; i++) {
                            if (strcmp(seen_ips[i], ip) == 0) { duplicate = 1; break; }
                        }
                        if (duplicate) continue;
                        strncpy(seen_ips[seen_count++], ip, MAX_IP_LEN);

                        Device *d = &devices[count];
                        memset(d, 0, sizeof(Device));
                        strncpy(d->ip, ip, MAX_IP_LEN);
                        strncpy(d->mac, mac, MAX_MAC_LEN);
                        str_upper(d->mac);
                        d->vendor[0] = '\0';
                        platform_get_hostname(ip, d->hostname, MAX_HOSTNAME_LEN);
                        d->discovered_at = time(NULL);
                        d->last_seen = time(NULL);
                        count++;
                    }
                    scanner_log("GetIpNetTable: %d girdi okundu", count);
                }
                free(tbl);
            }
        }
        if (!win_arp_ok) {
        /* fallback: 'arp -a' komutu (GetIpNetTable yoksa/basarisizsa) */
        char output[MAX_CMD_OUTPUT];
        if (platform_run_command("arp -a", output, sizeof(output)) == 0) {
            char *line = strtok(output, "\n");
            while (line && count < max_devices) {
                char ip[64], mac[32], type[16];
                /* Format: "  192.168.1.1          aa-bb-cc-dd-ee-ff     dynamic" */
                if (sscanf(line, " %s %s %s", ip, mac, type) == 3) {
                    if (strchr(ip, '.') && strlen(mac) >= 11) {
                        /* MAC formatini normalize et (- -> :) */
                        for (char *p = mac; *p; p++) if (*p == '-') *p = ':';

                        int duplicate = 0;
                        for (int i = 0; i < seen_count; i++) {
                            if (strcmp(seen_ips[i], ip) == 0) { duplicate = 1; break; }
                        }
                        if (!duplicate) {
                            strncpy(seen_ips[seen_count++], ip, MAX_IP_LEN);
                            Device *d = &devices[count];
                            memset(d, 0, sizeof(Device));
                            strncpy(d->ip, ip, MAX_IP_LEN);
                            strncpy(d->mac, mac, MAX_MAC_LEN);
                            str_upper(d->mac);
                            d->vendor[0] = '\0';
                            platform_get_hostname(ip, d->hostname, MAX_HOSTNAME_LEN);
                            d->discovered_at = time(NULL);
                            d->last_seen = time(NULL);
                            count++;
                        }
                    }
                }
                line = strtok(NULL, "\n");
            }
        }
        }
    }
#endif

    
    scanner_log("ARP tablosundan %d cihaz bulundu", count);
    return count;
}

/* IP sıralama karşılaştırıcı */
static int _compare_devices(const void *a, const void *b) {
    const Device *da = (const Device *)a;
    const Device *db = (const Device *)b;
    return ip_to_int(da->ip) - ip_to_int(db->ip);
}

/* ========== Tam Ağ Taraması ========== */
int scanner_full_scan(void) {
    platform_mutex_lock(&g_results_lock);
    if (g_results.is_scanning) {
        platform_mutex_unlock(&g_results_lock);
        return -1;
    }
    g_results.is_scanning = 1;
    platform_mutex_unlock(&g_results_lock);
    
    scanner_log("Otonom ag taramasi baslatiliyor...");
    
    /* Ağ bilgilerini topla */
    char iface[MAX_IFACE_LEN] = {0};
    char local_ip[MAX_IP_LEN] = {0};
    char local_mac[MAX_MAC_LEN] = {0};
    char gateway_ip[MAX_IP_LEN] = {0};
    char gateway_mac[MAX_MAC_LEN] = {0};
    char network_range[32] = {0};
    
    platform_get_default_interface(iface, sizeof(iface));
    platform_get_local_ip(iface, local_ip, sizeof(local_ip));
    platform_get_local_mac(iface, local_mac, sizeof(local_mac));
    platform_get_gateway(gateway_ip, sizeof(gateway_ip), gateway_mac, sizeof(gateway_mac));
    platform_get_network_range(iface, local_ip, network_range, sizeof(network_range));
    
    scanner_log("Arayuz: %s | IP: %s | Ag: %s", iface, local_ip, network_range);
    scanner_log("Gateway: %s (%s)", gateway_ip, gateway_mac);
    
    /* ARP taraması */
    Device new_devices[MAX_DEVICES];
    int new_count = _scan_with_arp_table(new_devices, MAX_DEVICES, network_range);
    
    /* Yerel cihazı ekle */
    int local_found = 0;
    for (int i = 0; i < new_count; i++) {
        if (strcmp(new_devices[i].ip, local_ip) == 0) { local_found = 1; break; }
    }
    if (!local_found && new_count < MAX_DEVICES) {
        Device *d = &new_devices[new_count];
        memset(d, 0, sizeof(Device));
        strncpy(d->ip, local_ip, MAX_IP_LEN);
        strncpy(d->mac, local_mac, MAX_MAC_LEN);
        str_upper(d->mac);
        d->vendor[0] = '\0';
        platform_get_hostname(local_ip, d->hostname, MAX_HOSTNAME_LEN);
        d->discovered_at = time(NULL);
        d->last_seen = time(NULL);
        new_count++;
    }
    
    /* Cihazları sınıflandır */
    for (int i = 0; i < new_count; i++) {
        Device *d = &new_devices[i];
        d->is_gateway = (strcmp(d->ip, gateway_ip) == 0);
        d->is_local = (strcmp(d->ip, local_ip) == 0);
        // scanner_classify_device(d, gateway_ip, local_ip);
    }
    
    /* Sonuçları birleştir (mevcut + yeni) */
    platform_mutex_lock(&g_results_lock);
    
    time_t now = time(NULL);
    
    /* Yeni bulunanları mevcut listeye birleştir */
    for (int i = 0; i < new_count; i++) {
        new_devices[i].last_seen = now;
        
        int found = 0;
        for (int j = 0; j < g_results.device_count; j++) {
            if (strcmp(g_results.devices[j].ip, new_devices[i].ip) == 0) {
                /* Mevcut cihazı güncelle */
                g_results.devices[j] = new_devices[i];
                found = 1;
                break;
            }
        }
        if (!found && g_results.device_count < MAX_DEVICES) {
            g_results.devices[g_results.device_count++] = new_devices[i];
        }
    }
    
    /* Eski cihazları temizle (DEVICE_TIMEOUT saniyeden eski) */
    int write_idx = 0;
    for (int i = 0; i < g_results.device_count; i++) {
        if (difftime(now, g_results.devices[i].last_seen) <= DEVICE_TIMEOUT) {
            if (write_idx != i)
                g_results.devices[write_idx] = g_results.devices[i];
            write_idx++;
        }
    }
    g_results.device_count = write_idx;
    
    /* IP'ye göre sırala */
    qsort(g_results.devices, g_results.device_count, sizeof(Device), _compare_devices);
    
    /* Meta bilgileri güncelle */
    strncpy(g_results.gateway_ip, gateway_ip, MAX_IP_LEN);
    strncpy(g_results.gateway_mac, gateway_mac, MAX_MAC_LEN);
    strncpy(g_results.local_ip, local_ip, MAX_IP_LEN);
    strncpy(g_results.local_mac, local_mac, MAX_MAC_LEN);
    strncpy(g_results.local_iface, iface, MAX_IFACE_LEN);
    strncpy(g_results.network_range, network_range, sizeof(g_results.network_range));
    g_results.last_scan_time = now;
    g_results.scan_count++;
    g_results.is_scanning = 0;
    
    /* Özet istatistikler */
    g_results.total = g_results.device_count;
    g_results.routers = 0;
    g_results.computers = 0;
    g_results.mobile = 0;
    g_results.iot = 0;
    g_results.unknown = 0;
    g_results.high_risk = 0;
    g_results.medium_risk = 0;
    
    for (int i = 0; i < g_results.device_count; i++) {
        Device *d = &g_results.devices[i];
        if (d->is_gateway) g_results.routers++;
        else if (str_contains(d->type, "Bilgisayar") || str_contains(d->type, "Sanal")) g_results.computers++;
        else if (str_contains(d->type, "Mobil") || str_contains(d->type, "Apple") || 
                 str_contains(d->type, "Samsung")) g_results.mobile++;
        else if (str_contains(d->type, "IoT") || str_contains(d->type, "Kamera")) g_results.iot++;
        else if (str_contains(d->type, "Bilinmeyen")) g_results.unknown++;
        
        if (d->risk == RISK_HIGH || d->risk == RISK_CRITICAL) g_results.high_risk++;
        if (d->risk == RISK_MEDIUM) g_results.medium_risk++;
    }
    
    platform_mutex_unlock(&g_results_lock);
    
    scanner_log("Tarama tamamlandi: %d cihaz bulundu", g_results.device_count);
    return g_results.device_count;
}

void scanner_get_results(ScanResults *out) {
    platform_mutex_lock(&g_results_lock);
    memcpy(out, &g_results, sizeof(ScanResults));
    platform_mutex_unlock(&g_results_lock);
}

/* ========== Otonom Tarama Thread ========== */
static void *_auto_scan_thread(void *arg) {
    int interval = *(int *)arg;
    platform_sleep_ms(2000); /* İlk başta 2 saniye bekle */
    
    while (g_auto_scan_running) {
        scanner_full_scan();
        for (int i = 0; i < interval * 10 && g_auto_scan_running; i++) {
            platform_sleep_ms(100);
        }
    }
    return NULL;
}

static int g_scan_interval = SCAN_INTERVAL;

void scanner_start_auto_scan(int interval_sec) {
    if (g_auto_scan_running) return;
    g_auto_scan_running = 1;
    g_scan_interval = interval_sec;
    
    platform_thread_t thread;
    platform_thread_create(&thread, _auto_scan_thread, &g_scan_interval);
    platform_thread_detach(thread);
    
    scanner_log("Otonom tarama baslatildi (her %d saniyede bir)", interval_sec);
}

/* ========== Başlatma / Temizlik ========== */
void scanner_init(void) {
    if (g_initialized) return;
    
    memset(&g_results, 0, sizeof(g_results));
    memset(&g_log, 0, sizeof(g_log));
    platform_mutex_init(&g_results_lock);
    platform_mutex_init(&g_log_lock);
    
    g_initialized = 1;
    scanner_log("ARP tarayici baslatildi");
}

void scanner_cleanup(void) {
    g_auto_scan_running = 0;
    platform_sleep_ms(200);
    platform_mutex_destroy(&g_results_lock);
    platform_mutex_destroy(&g_log_lock);
    g_initialized = 0;
}


