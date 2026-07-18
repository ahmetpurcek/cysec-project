/*
 * platform.h — Platform Soyutlama Katmanı
 * Windows ve Linux arası taşınabilirlik için ortak arayüz.
 */
#ifndef PLATFORM_H
#define PLATFORM_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ========== Platform Tanımlayıcıları ========== */
#ifdef _WIN32
    #define PLATFORM_WINDOWS 1
    #define PLATFORM_NAME "Windows"
    typedef void* platform_thread_t;
    typedef void* platform_mutex_t;
#elif defined(__linux__)
    #define PLATFORM_LINUX 1
    #define PLATFORM_NAME "Linux"
    #include <unistd.h>
    #include <sys/socket.h>
    #include <sys/ioctl.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <net/if.h>
    #include <netdb.h>
    #include <pthread.h>
    typedef pthread_t platform_thread_t;
    typedef pthread_mutex_t platform_mutex_t;
#endif

/* ========== Sabitler ========== */
#define MAX_IP_LEN 46
#define MAX_MAC_LEN 18
#define MAX_IFACE_LEN 32
#define MAX_HOSTNAME_LEN 256
#define MAX_PATH_LEN 512
#define MAX_CMD_OUTPUT 8192
#define MAX_VENDOR_LEN 128

/* ========== Yapılar ========== */
typedef struct {
    char ip[MAX_IP_LEN];
    char mac[MAX_MAC_LEN];
    char iface[MAX_IFACE_LEN];
} NetworkInfo;

/* ========== Platform Fonksiyonları ========== */
/* Başlatma ve temizlik */
int  platform_init(void);
void platform_cleanup(void);

/* Ağ bilgisi */
int  platform_get_default_interface(char *iface, int len);
int  platform_get_local_ip(const char *iface, char *ip, int len);
int  platform_get_local_mac(const char *iface, char *mac, int len);
int  platform_get_gateway(char *ip, int len, char *mac, int mac_len);
int  platform_get_network_range(const char *iface, const char *local_ip, char *range, int len);
int  platform_get_hostname(const char *ip, char *hostname, int len);

/* Thread */
int  platform_thread_create(platform_thread_t *thread, void *(*func)(void*), void *arg);
void platform_thread_detach(platform_thread_t thread);

/* Mutex */
int  platform_mutex_init(platform_mutex_t *mutex);
void platform_mutex_lock(platform_mutex_t *mutex);
void platform_mutex_unlock(platform_mutex_t *mutex);
void platform_mutex_destroy(platform_mutex_t *mutex);

/* Zamanlama */
void platform_sleep_ms(unsigned int ms);

/* Komut çalıştırma */
int  platform_run_command(const char *cmd, char *output, int output_len);

/* Dosya yolu */
const char *platform_path_separator(void);

#endif /* PLATFORM_H */
