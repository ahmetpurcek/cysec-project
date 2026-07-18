/*
 * brute_force.h — Otonom Brute Force Modülü (Cross-Platform)
 * Çoklu protokol brute-force motoru. SSH, FTP, HTTP, MySQL, Telnet, vs.
 * Platform soyutlama katmanı üzerinden çalışır (Linux + Windows).
 */
#ifndef BRUTE_FORCE_H
#define BRUTE_FORCE_H

#include "platform.h"

/* ========== Sabitler ========== */
#define BF_MAX_USERS         128
#define BF_MAX_PASSWORDS     256
#define BF_MAX_RESULTS       128
#define BF_MAX_THREADS       32
#define BF_MAX_CRED_LEN      64
#define BF_BUF_SIZE          4096
#define BF_CONNECT_TIMEOUT   3000   /* ms */
#define BF_MAX_HTTP_PATH     256
#define BF_MAX_HTTP_PARAMS   512

/* ========== Protokol Tipleri ========== */
typedef enum {
    BF_PROTO_FTP = 0,
    BF_PROTO_HTTP_POST,
    BF_PROTO_HTTP_GET,
    BF_PROTO_MYSQL,
    BF_PROTO_TELNET,
    BF_PROTO_SSH,
    BF_PROTO_SMB,
    BF_PROTO_RDP,
    BF_PROTO_COUNT
} BfProtocol;

/* ========== Sonuç Kaydı ========== */
typedef struct {
    char     username[BF_MAX_CRED_LEN];
    char     password[BF_MAX_CRED_LEN];
    int      success;       /* 1 = basarili giris */
    double   time_ms;       /* deneme suresi */
} BfCredResult;

/* ========== Tarama Durumu ========== */
typedef struct {
    /* Hedef */
    char          target_ip[MAX_IP_LEN];
    int           port;
    BfProtocol    protocol;

    /* HTTP spesifik */
    char          http_path[BF_MAX_HTTP_PATH];
    char          http_params[BF_MAX_HTTP_PARAMS];

    /* Credential listeleri */
    char          usernames[BF_MAX_USERS][BF_MAX_CRED_LEN];
    int           user_count;
    char          passwords[BF_MAX_PASSWORDS][BF_MAX_CRED_LEN];
    int           pass_count;

    /* Sonuçlar */
    BfCredResult  results[BF_MAX_RESULTS];
    int           result_count;

    /* İlerleme */
    int           total_combos;     /* user_count * pass_count */
    int           tested_combos;    /* şu ana kadar denenen */
    int           is_running;
    int           is_complete;
    double        elapsed_sec;
    int           thread_count;

    /* Thread-safety */
    platform_mutex_t lock;
} BfState;

/* ========== Fonksiyonlar ========== */
void bf_init(void);
void bf_cleanup(void);

/* Protokol adı */
const char *bf_proto_name(BfProtocol proto);

/* Protokol varsayılan portu */
int bf_default_port(BfProtocol proto);

/* Yerleşik user/pass listesi yükle (dahili wordlist) */
void bf_load_builtin_users(void);
void bf_load_builtin_passwords(void);

/* Dosyadan user/pass listesi yükle */
int bf_load_users_file(const char *filepath);
int bf_load_passwords_file(const char *filepath);

/* Manuel user/pass ekleme */
void bf_add_user(const char *user);
void bf_add_password(const char *pass);

/* Listeleri temizle */
void bf_clear_users(void);
void bf_clear_passwords(void);

/* Brute force başlat (non-blocking, arka plan thread) */
void bf_start(const char *target_ip, int port, BfProtocol proto, int threads);

/* HTTP spesifik ayarlar (bf_start'tan ÖNCE çağır) */
void bf_set_http_params(const char *path, const char *params);

/* Sonuçları al (thread-safe kopya) */
void bf_get_state(BfState *out);

/* Durdur */
void bf_stop(void);

#endif /* BRUTE_FORCE_H */
