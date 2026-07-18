/*
 * platform.c — Platform Soyutlama Katmanı Uygulaması
 * Windows ve Linux için ortak arayüz implementasyonu.
 */
#include "platform.h"
#include <stdio.h>
#include <string.h>

#ifdef PLATFORM_LINUX
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netdb.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#endif

#ifdef PLATFORM_WINDOWS
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#endif

/* ========== Başlatma / Temizlik ========== */
int platform_init(void) {
#ifdef PLATFORM_WINDOWS
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "[Platform] Winsock başlatılamadı\n");
        return -1;
    }
#endif
    return 0;
}

void platform_cleanup(void) {
#ifdef PLATFORM_WINDOWS
    WSACleanup();
#endif
}

/* ========== Ağ Bilgisi — Linux ========== */
#ifdef PLATFORM_LINUX

int platform_get_default_interface(char *iface, int len) {
    FILE *fp = popen("ip route show default 2>/dev/null", "r");
    if (!fp) { strncpy(iface, "eth0", len); return -1; }
    
    char line[512];
    if (fgets(line, sizeof(line), fp)) {
        /* "default via X.X.X.X dev ethX ..." */
        char *dev = strstr(line, "dev ");
        if (dev) {
            dev += 4;
            char *end = strchr(dev, ' ');
            if (end) *end = '\0';
            char *nl = strchr(dev, '\n');
            if (nl) *nl = '\0';
            strncpy(iface, dev, len);
            iface[len - 1] = '\0';
            pclose(fp);
            return 0;
        }
    }
    pclose(fp);
    strncpy(iface, "eth0", len);
    return -1;
}

int platform_get_local_ip(const char *iface, char *ip, int len) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        close(fd);
        /* Fallback: UDP trick */
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(80);
        inet_pton(AF_INET, "8.8.8.8", &addr.sin_addr);
        
        int s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s < 0) return -1;
        connect(s, (struct sockaddr *)&addr, sizeof(addr));
        
        struct sockaddr_in local;
        socklen_t local_len = sizeof(local);
        getsockname(s, (struct sockaddr *)&local, &local_len);
        inet_ntop(AF_INET, &local.sin_addr, ip, len);
        close(s);
        return 0;
    }
    
    struct sockaddr_in *sa = (struct sockaddr_in *)&ifr.ifr_addr;
    inet_ntop(AF_INET, &sa->sin_addr, ip, len);
    close(fd);
    return 0;
}

int platform_get_local_mac(const char *iface, char *mac, int len) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        close(fd);
        strncpy(mac, "00:00:00:00:00:00", len);
        return -1;
    }
    
    unsigned char *m = (unsigned char *)ifr.ifr_hwaddr.sa_data;
    snprintf(mac, len, "%02X:%02X:%02X:%02X:%02X:%02X",
             m[0], m[1], m[2], m[3], m[4], m[5]);
    close(fd);
    return 0;
}

int platform_get_gateway(char *ip, int len, char *mac, int mac_len) {
    /* /proc/net/route'dan gateway IP'yi bul */
    FILE *fp = fopen("/proc/net/route", "r");
    if (!fp) return -1;
    
    char line[512];
    fgets(line, sizeof(line), fp); /* başlık satırını atla */
    
    while (fgets(line, sizeof(line), fp)) {
        char iface[32];
        unsigned int dest, gw;
        if (sscanf(line, "%s %x %x", iface, &dest, &gw) == 3) {
            if (dest == 0) { /* default route */
                struct in_addr addr;
                addr.s_addr = gw;
                strncpy(ip, inet_ntoa(addr), len);
                ip[len - 1] = '\0';
                fclose(fp);
                
                /* Gateway MAC'ini ARP tablosundan bul */
                if (mac && mac_len > 0) {
                    char cmd[128];
                    snprintf(cmd, sizeof(cmd), "arp -n %s 2>/dev/null | tail -1", ip);
                    FILE *arp_fp = popen(cmd, "r");
                    if (arp_fp) {
                        char arp_line[256];
                        while (fgets(arp_line, sizeof(arp_line), arp_fp)) {
                            char arp_ip[64], arp_mac[32];
                            if (sscanf(arp_line, "%s %*s %s", arp_ip, arp_mac) >= 2) {
                                if (strcmp(arp_ip, ip) == 0 && strlen(arp_mac) >= 11) {
                                    strncpy(mac, arp_mac, mac_len);
                                    mac[mac_len - 1] = '\0';
                                    break;
                                }
                            }
                        }
                        pclose(arp_fp);
                    }
                }
                return 0;
            }
        }
    }
    fclose(fp);
    return -1;
}

int platform_get_network_range(const char *iface, const char *local_ip, char *range, int len) {
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "ip -o addr show %s 2>/dev/null", iface);
    FILE *fp = popen(cmd, "r");
    if (!fp) goto fallback;
    
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "inet ") && strstr(line, local_ip)) {
            char *inet_start = strstr(line, "inet ") + 5;
            char *space = strchr(inet_start, ' ');
            if (space) *space = '\0';
            /* inet_start = "192.168.1.100/24" */
            char *slash = strchr(inet_start, '/');
            if (slash) {
                int cidr = atoi(slash + 1);
                unsigned int ip_int = 0;
                int parts[4];
                if (sscanf(inet_start, "%d.%d.%d.%d", &parts[0], &parts[1], &parts[2], &parts[3]) == 4) {
                    ip_int = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
                    unsigned int mask = (0xFFFFFFFF << (32 - cidr)) & 0xFFFFFFFF;
                    unsigned int net = ip_int & mask;
                    snprintf(range, len, "%d.%d.%d.%d/%d",
                             (net >> 24) & 0xFF, (net >> 16) & 0xFF,
                             (net >> 8) & 0xFF, net & 0xFF, cidr);
                    pclose(fp);
                    return 0;
                }
            }
        }
    }
    pclose(fp);
    
fallback:
    /* /24 varsay */
    {
        int a, b, c, d;
        if (sscanf(local_ip, "%d.%d.%d.%d", &a, &b, &c, &d) == 4) {
            snprintf(range, len, "%d.%d.%d.0/24", a, b, c);
            return 0;
        }
    }
    return -1;
}

int platform_get_hostname(const char *ip, char *hostname, int len) {
    struct sockaddr_in sa;
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, ip, &sa.sin_addr);
    
    char host[NI_MAXHOST];
    if (getnameinfo((struct sockaddr *)&sa, sizeof(sa), host, sizeof(host), NULL, 0, 0) == 0) {
        /* IP'nin kendisini hostname olarak döndürmeyi engelle */
        if (strcmp(host, ip) != 0) {
            strncpy(hostname, host, len);
            hostname[len - 1] = '\0';
            return 0;
        }
    }
    hostname[0] = '\0';
    return -1;
}

/* ========== Thread — Linux ========== */
int platform_thread_create(platform_thread_t *thread, void *(*func)(void*), void *arg) {
    return pthread_create(thread, NULL, func, arg);
}

void platform_thread_detach(platform_thread_t thread) {
    pthread_detach(thread);
}

/* ========== Mutex — Linux ========== */
int platform_mutex_init(platform_mutex_t *mutex) {
    return pthread_mutex_init(mutex, NULL);
}

void platform_mutex_lock(platform_mutex_t *mutex) {
    pthread_mutex_lock(mutex);
}

void platform_mutex_unlock(platform_mutex_t *mutex) {
    pthread_mutex_unlock(mutex);
}

void platform_mutex_destroy(platform_mutex_t *mutex) {
    pthread_mutex_destroy(mutex);
}

#endif /* PLATFORM_LINUX */

/* ========== Ağ Bilgisi — Windows ========== */
#ifdef PLATFORM_WINDOWS

int platform_get_default_interface(char *iface, int len) {
    /* Windows'ta arayüz ismi yerine adaptör index'i kullanılır */
    strncpy(iface, "default", len);
    return 0;
}

int platform_get_local_ip(const char *iface, char *ip, int len) {
    (void)iface;
    char hostname[256];
    gethostname(hostname, sizeof(hostname));
    
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    
    if (getaddrinfo(hostname, NULL, &hints, &res) == 0) {
        struct sockaddr_in *addr = (struct sockaddr_in *)res->ai_addr;
        inet_ntop(AF_INET, &addr->sin_addr, ip, len);
        freeaddrinfo(res);
        return 0;
    }
    strncpy(ip, "127.0.0.1", len);
    return -1;
}

int platform_get_local_mac(const char *iface, char *mac, int len) {
    (void)iface;
    IP_ADAPTER_ADDRESSES *addrs = NULL;
    ULONG buflen = 15000;
    addrs = (IP_ADAPTER_ADDRESSES *)malloc(buflen);
    
    if (GetAdaptersAddresses(AF_INET, 0, NULL, addrs, &buflen) == ERROR_SUCCESS) {
        IP_ADAPTER_ADDRESSES *cur = addrs;
        while (cur) {
            if (cur->PhysicalAddressLength == 6 && cur->OperStatus == IfOperStatusUp) {
                unsigned char *m = cur->PhysicalAddress;
                snprintf(mac, len, "%02X:%02X:%02X:%02X:%02X:%02X",
                         m[0], m[1], m[2], m[3], m[4], m[5]);
                free(addrs);
                return 0;
            }
            cur = cur->Next;
        }
    }
    free(addrs);
    strncpy(mac, "00:00:00:00:00:00", len);
    return -1;
}

int platform_get_gateway(char *ip, int len, char *mac, int mac_len) {
    IP_ADAPTER_ADDRESSES *addrs = NULL;
    ULONG buflen = 15000;
    addrs = (IP_ADAPTER_ADDRESSES *)malloc(buflen);
    
    if (GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_GATEWAYS, NULL, addrs, &buflen) == ERROR_SUCCESS) {
        IP_ADAPTER_ADDRESSES *cur = addrs;
        while (cur) {
            IP_ADAPTER_GATEWAY_ADDRESS_LH *gw = cur->FirstGatewayAddress;
            if (gw && cur->OperStatus == IfOperStatusUp) {
                struct sockaddr_in *sa = (struct sockaddr_in *)gw->Address.lpSockaddr;
                inet_ntop(AF_INET, &sa->sin_addr, ip, len);
                if (mac) strncpy(mac, "N/A", mac_len);
                free(addrs);
                return 0;
            }
            cur = cur->Next;
        }
    }
    free(addrs);
    return -1;
}

int platform_get_network_range(const char *iface, const char *local_ip, char *range, int len) {
    (void)iface;
    int a, b, c, d;
    if (sscanf(local_ip, "%d.%d.%d.%d", &a, &b, &c, &d) == 4) {
        snprintf(range, len, "%d.%d.%d.0/24", a, b, c);
        return 0;
    }
    return -1;
}

int platform_get_hostname(const char *ip, char *hostname, int len) {
    struct sockaddr_in sa;
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, ip, &sa.sin_addr);
    
    char host[NI_MAXHOST];
    if (getnameinfo((struct sockaddr *)&sa, sizeof(sa), host, sizeof(host), NULL, 0, 0) == 0) {
        if (strcmp(host, ip) != 0) {
            strncpy(hostname, host, len);
            hostname[len - 1] = '\0';
            return 0;
        }
    }
    hostname[0] = '\0';
    return -1;
}

/* ========== Thread — Windows ========== */
int platform_thread_create(platform_thread_t *thread, void *(*func)(void*), void *arg) {
    *thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)func, arg, 0, NULL);
    return (*thread == NULL) ? -1 : 0;
}

void platform_thread_detach(platform_thread_t thread) {
    CloseHandle(thread);
}

/* ========== Mutex — Windows ========== */
int platform_mutex_init(platform_mutex_t *mutex) {
    *mutex = malloc(sizeof(CRITICAL_SECTION));
    if (*mutex == NULL) return -1;
    InitializeCriticalSection((CRITICAL_SECTION *)*mutex);
    return 0;
}

void platform_mutex_lock(platform_mutex_t *mutex) {
    EnterCriticalSection((CRITICAL_SECTION *)*mutex);
}

void platform_mutex_unlock(platform_mutex_t *mutex) {
    LeaveCriticalSection((CRITICAL_SECTION *)*mutex);
}

void platform_mutex_destroy(platform_mutex_t *mutex) {
    if (*mutex) {
        DeleteCriticalSection((CRITICAL_SECTION *)*mutex);
        free(*mutex);
        *mutex = NULL;
    }
}

#endif /* PLATFORM_WINDOWS */

/* ========== Ortak Fonksiyonlar ========== */
void platform_sleep_ms(unsigned int ms) {
#ifdef PLATFORM_WINDOWS
    Sleep(ms);
#else
    usleep(ms * 1000);
#endif
}

int platform_run_command(const char *cmd, char *output, int output_len) {
    if (output && output_len > 0) output[0] = '\0';
    
    FILE *fp = popen(cmd, "r");
    if (!fp) return -1;
    
    int total = 0;
    char buf[512];
    while (fgets(buf, sizeof(buf), fp)) {
        int line_len = strlen(buf);
        if (output && total + line_len < output_len - 1) {
            memcpy(output + total, buf, line_len);
            total += line_len;
            output[total] = '\0';
        }
    }
    
    int ret = pclose(fp);
    return ret;
}

const char *platform_path_separator(void) {
#ifdef PLATFORM_WINDOWS
    return "\\";
#else
    return "/";
#endif
}
