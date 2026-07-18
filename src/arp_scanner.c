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

/* ========== Global State ========== */
static ScanResults  g_results;
static platform_mutex_t g_results_lock;
static ScanLog      g_log;
static platform_mutex_t g_log_lock;
static HashMap      g_mac_vendors;
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

/* ========== ARP Tarama (Fallback: ping + arp tablosu) ========== */
static int _scan_with_arp_table(Device *devices, int max_devices, const char *network_range) {
    int count = 0;
    
    /* 1. Ping sweep ile ARP cache'i doldur */
    scanner_log("Ping sweep baslatiliyor: %s", network_range);
    
    int base_parts[4];
    if (sscanf(network_range, "%d.%d.%d.%d", &base_parts[0], &base_parts[1], &base_parts[2], &base_parts[3]) < 3) {
        return 0;
    }
    
    /* Her 10 IP'yi paralel olarak pingle */
    for (int batch_start = 1; batch_start <= 254; batch_start += 20) {
        char cmd[2048] = {0};
        int cmd_len = 0;
        for (int i = batch_start; i < batch_start + 20 && i <= 254; i++) {
#ifdef PLATFORM_LINUX
            cmd_len += snprintf(cmd + cmd_len, sizeof(cmd) - cmd_len,
                "ping -c 1 -W 1 %d.%d.%d.%d >/dev/null 2>&1 & ",
                base_parts[0], base_parts[1], base_parts[2], i);
#else
            cmd_len += snprintf(cmd + cmd_len, sizeof(cmd) - cmd_len,
                "start /B ping -n 1 -w 500 %d.%d.%d.%d >NUL 2>&1 & ",
                base_parts[0], base_parts[1], base_parts[2], i);
#endif
        }
#ifdef PLATFORM_LINUX
        strcat(cmd, "wait 2>/dev/null");
#endif
        platform_run_command(cmd, NULL, 0);
    }
    
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
                
                /* Rastgele MAC kontrolü */
                if (strlen(dev->mac) >= 2) {
                    char c = dev->mac[1];
                    if (c == '2' || c == '6' || c == 'A' || c == 'E' ||
                        c == 'a' || c == 'e') {
                        dev->is_random_mac = 1;
                    }
                }
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
    /* Windows: arp -a komutu */
    {
        char output[MAX_CMD_OUTPUT];
        if (platform_run_command("arp -a", output, sizeof(output)) == 0) {
            char *line = strtok(output, "\n");
            while (line && count < max_devices) {
                char ip[64], mac[32], type[16];
                /* Format: "  192.168.1.1          aa-bb-cc-dd-ee-ff     dynamic" */
                if (sscanf(line, " %s %s %s", ip, mac, type) == 3) {
                    if (strchr(ip, '.') && strlen(mac) >= 11) {
                        /* MAC formatını normalize et (- → :) */
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
    hashmap_init(&g_mac_vendors);
    
    g_initialized = 1;
    scanner_log("ARP tarayici baslatildi");
}

void scanner_cleanup(void) {
    g_auto_scan_running = 0;
    platform_sleep_ms(200);
    platform_mutex_destroy(&g_results_lock);
    platform_mutex_destroy(&g_log_lock);
    hashmap_free(&g_mac_vendors);
    g_initialized = 0;
}
