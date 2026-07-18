/*
 * log_analyzer.c — Sistem Log Analiz Motoru
 * dmesg, giriş geçmişi, HTTP flood, zamanlayıcılı baskılama eklendi.
 */
#include "log_analyzer.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <stdlib.h>

/* ========== Global State ========== */
static double g_suppress_until = 0.0; /* epoch sn cinsinden */
static int    g_analyzer_initialized = 0;

/* ========== Dahili Yardımcılar ========== */
static void _add_alert(AnalysisResult *r, const char *type, const char *severity,
                        int score, const char *title, const char *desc, const char *rec) {
    if (r->alert_count >= MAX_ALERTS) return;
    Alert *a = &r->alerts[r->alert_count++];
    strncpy(a->type,           type,     sizeof(a->type)           - 1);
    strncpy(a->severity,       severity, sizeof(a->severity)       - 1);
    a->severity_score = score;
    strncpy(a->title,          title,    sizeof(a->title)          - 1);
    strncpy(a->description,    desc,     sizeof(a->description)    - 1);
    strncpy(a->recommendation, rec,      sizeof(a->recommendation) - 1);
}

/* ========== Log Okuma ========== */
static int _read_journal(char lines[][256], int max_lines, const char *unit, const char *since) {
    char cmd[512];
    if (unit && since)
        snprintf(cmd, sizeof(cmd),
                 "journalctl --no-pager -n %d -o short-iso -u %s --since '%s' 2>/dev/null",
                 max_lines, unit, since);
    else if (since)
        snprintf(cmd, sizeof(cmd),
                 "journalctl --no-pager -n %d -o short-iso --since '%s' 2>/dev/null",
                 max_lines, since);
    else
        snprintf(cmd, sizeof(cmd),
                 "journalctl --no-pager -n %d -o short-iso 2>/dev/null", max_lines);

    char output[MAX_CMD_OUTPUT * 4];
    platform_run_command(cmd, output, sizeof(output));

    int count = 0;
    char *line = strtok(output, "\n");
    while (line && count < max_lines) {
        str_trim(line);
        if (strlen(line) > 0) {
            strncpy(lines[count], line, 255);
            lines[count][255] = '\0';
            count++;
        }
        line = strtok(NULL, "\n");
    }
    return count;
}

static int _read_file_log(const char *filepath, char lines[][256], int max_lines) {
    FILE *fp = fopen(filepath, "r");
    if (!fp) {
        char cmd[512];
        snprintf(cmd, sizeof(cmd), "tail -n %d %s 2>/dev/null", max_lines, filepath);
        char output[MAX_CMD_OUTPUT * 4];
        if (platform_run_command(cmd, output, sizeof(output)) != 0) return 0;
        int count = 0;
        char *line = strtok(output, "\n");
        while (line && count < max_lines) {
            str_trim(line);
            if (strlen(line) > 0) {
                strncpy(lines[count], line, 255);
                lines[count][255] = '\0';
                count++;
            }
            line = strtok(NULL, "\n");
        }
        return count;
    }
    char all_lines[2000][256];
    int total = 0;
    char buf[512];
    while (fgets(buf, sizeof(buf), fp) && total < 2000) {
        str_trim(buf);
        if (strlen(buf) > 0) {
            strncpy(all_lines[total], buf, 255);
            all_lines[total][255] = '\0';
            total++;
        }
    }
    fclose(fp);
    int start = (total > max_lines) ? total - max_lines : 0;
    int count = 0;
    for (int i = start; i < total; i++) {
        strncpy(lines[count], all_lines[i], 255);
        count++;
    }
    return count;
}

/* ========== HTTP Access Log Analizi ========== */
static void _analyze_httpd_access(AnalysisResult *r) {
    const char *paths[] = {
        "/var/log/httpd/access_log",
        "/var/log/apache2/access.log",
        "/var/log/httpd/access.log",
        NULL
    };
    char lines[500][256];
    int count = 0;
    for (int i = 0; paths[i]; i++) {
        count = _read_file_log(paths[i], lines, 500);
        if (count > 0) break;
    }
    r->http_stats.total_requests = count;
    r->log_stats.httpd_access_lines = count;
    if (count == 0) return;

    /* Saldırı desenleri */
    const char *attack_patterns[] = {
        "union select", "or 1=1", "drop table", "; --",
        "<script", "javascript:", "onerror=",
        "../../../", "/etc/passwd", "/etc/shadow",
        "cmd.exe", "powershell", "/bin/sh",
        "wp-admin", "wp-login", "xmlrpc.php",
        "phpmyadmin", "adminer", ".env", ".git",
        "nikto", "sqlmap", "nmap", "gobuster",
        "shell", "webshell", "c99", "r57",
        NULL
    };

    int suspicious_count = 0, error_404 = 0;

    /* IP başına istek sayacı (basit array) */
    char ip_list[200][20];
    int  ip_cnt[200];
    int  ip_count = 0;

    for (int i = 0; i < count; i++) {
        if (strstr(lines[i], " 404 ")) error_404++;

        for (int p = 0; attack_patterns[p]; p++) {
            if (str_contains_ci(lines[i], attack_patterns[p])) {
                suspicious_count++;
                break;
            }
        }

        /* IP çıkar (ilk token) */
        char ip[20] = {0};
        sscanf(lines[i], "%19s", ip);
        if (strchr(ip, '.')) {
            int found = 0;
            for (int k = 0; k < ip_count; k++) {
                if (strcmp(ip_list[k], ip) == 0) { ip_cnt[k]++; found = 1; break; }
            }
            if (!found && ip_count < 200) {
                strncpy(ip_list[ip_count], ip, 19);
                ip_cnt[ip_count] = 1;
                ip_count++;
            }
        }
    }

    r->http_stats.suspicious_count = suspicious_count;
    r->http_stats.error_404_count  = error_404;

    if (suspicious_count > 0) {
        char desc[512];
        snprintf(desc, sizeof(desc), "%d adet supheli HTTP istegi tespit edildi.", suspicious_count);
        _add_alert(r, "HTTP_ATTACK", "ORTA", 55,
                   "Supheli HTTP Trafigi Tespit Edildi", desc,
                   "WAF kurali ekle. Kaynak IP'leri engelle.");
    }
    if (error_404 > 20) {
        char desc[512];
        snprintf(desc, sizeof(desc), "%d adet 404 hatasi. Dizin taramasi olabilir.", error_404);
        _add_alert(r, "DIR_SCAN", "ORTA", 55,
                   "Dizin/Dosya Taramasi Tespit Edildi", desc,
                   "Rate limiting uygula. fail2ban HTTP kurali ekle.");
    }

    /* IP flood tespiti */
    for (int k = 0; k < ip_count; k++) {
        if (ip_cnt[k] > 100 &&
            strcmp(ip_list[k], "127.0.0.1") != 0 &&
            strcmp(ip_list[k], "::1") != 0) {
            char title[128], desc[256];
            snprintf(title, sizeof(title), "Yogun HTTP Trafigi: %s", ip_list[k]);
            snprintf(desc,  sizeof(desc),
                     "%s adresinden %d HTTP istegi. Olasilikla brute force veya DDoS.",
                     ip_list[k], ip_cnt[k]);
            _add_alert(r, "HTTP_FLOOD", "DUSUK", 25, title, desc,
                       "IP icin rate limiting uygula. Gerekirse engelle.");
        }
    }

    /* Son satırları kaydet */
    int start = (count > MAX_RAW_LOG_LINES) ? count - MAX_RAW_LOG_LINES : 0;
    r->raw_httpd_count = 0;
    for (int i = start; i < count && r->raw_httpd_count < MAX_RAW_LOG_LINES; i++)
        strncpy(r->raw_httpd[r->raw_httpd_count++], lines[i], 255);
}

/* ========== Sistem Journal Analizi ========== */
static void _analyze_journal(AnalysisResult *r) {
    char since[32];
    snprintf(since, sizeof(since), "%d minutes ago", LOG_FRESHNESS_MIN);
    char lines[500][256];
    int count = _read_journal(lines, 500, NULL, since);
    r->log_stats.journal_lines = count;

    /* IP başına SSH başarısız sayacı */
    char ssh_ips[64][20];
    int  ssh_cnt[64];
    int  ssh_ip_count = 0;

    for (int i = 0; i < count; i++) {
        if (str_contains_ci(lines[i], "Failed password") ||
            str_contains_ci(lines[i], "authentication failure")) {
            /* IP çıkarmaya çalış */
            char *from = strstr(lines[i], "from ");
            char ip[20] = "unknown";
            if (from) sscanf(from + 5, "%19s", ip);

            int found = 0;
            for (int k = 0; k < ssh_ip_count; k++) {
                if (strcmp(ssh_ips[k], ip) == 0) { ssh_cnt[k]++; found = 1; break; }
            }
            if (!found && ssh_ip_count < 64) {
                strncpy(ssh_ips[ssh_ip_count], ip, 19);
                ssh_cnt[ssh_ip_count] = 1;
                ssh_ip_count++;
            }
        }

        if (str_contains(lines[i], "Started") &&
            (str_contains_ci(lines[i], "reverse") || str_contains_ci(lines[i], "tunnel") ||
             str_contains_ci(lines[i], "tor"))) {
            _add_alert(r, "SUSPICIOUS_SERVICE", "YUKSEK", 75,
                       "Supheli Servis Baslatildi",
                       lines[i],
                       "Servisi incele. Yetkisiz ise durdur.");
        }
    }

    for (int k = 0; k < ssh_ip_count; k++) {
        if (ssh_cnt[k] >= 3) {
            char title[128], desc[256];
            int critical = (ssh_cnt[k] > 10);
            snprintf(title, sizeof(title), "SSH Brute Force: %s", ssh_ips[k]);
            snprintf(desc,  sizeof(desc),
                     "%s adresinden %d basarisiz SSH giris denemesi.", ssh_ips[k], ssh_cnt[k]);
            _add_alert(r, "SSH_BRUTE_FORCE",
                       critical ? "KRITIK" : "YUKSEK",
                       critical ? 90 : 70,
                       title, desc,
                       "fail2ban ile IP engelle. SSH key-only auth kullan.");
        }
    }

    int start = (count > MAX_RAW_LOG_LINES) ? count - MAX_RAW_LOG_LINES : 0;
    r->raw_journal_count = 0;
    for (int i = start; i < count && r->raw_journal_count < MAX_RAW_LOG_LINES; i++)
        strncpy(r->raw_journal[r->raw_journal_count++], lines[i], 255);
}

/* ========== MariaDB Log Analizi ========== */
static void _analyze_mariadb(AnalysisResult *r) {
    char since[32];
    snprintf(since, sizeof(since), "%d minutes ago", LOG_FRESHNESS_MIN);
    char lines[300][256];
    int count = _read_journal(lines, 300, "mariadbd", since);
    r->log_stats.mariadb_lines = count;

    r->db_stats.aborted_connections = 0;
    r->db_stats.auth_failures       = 0;
    r->db_stats.warnings            = 0;
    r->db_stats.errors              = 0;

    for (int i = 0; i < count; i++) {
        if (str_contains(lines[i], "Aborted connection")) r->db_stats.aborted_connections++;
        if (str_contains(lines[i], "Access denied"))     r->db_stats.auth_failures++;
        if (str_contains(lines[i], "[Warning]"))         r->db_stats.warnings++;
        if (str_contains(lines[i], "[Error]"))           r->db_stats.errors++;
    }

    if (r->db_stats.aborted_connections > 10) {
        char desc[256];
        snprintf(desc, sizeof(desc), "%d adet iptal edilen veritabani baglantisi.",
                 r->db_stats.aborted_connections);
        _add_alert(r, "DB_ABORTED_CONN", "ORTA", 55,
                   "Veritabani Baglanti Sorunlari", desc,
                   "Veritabani baglanti havuzunu kontrol et.");
    }
    if (r->db_stats.auth_failures > 5) {
        char desc[256];
        snprintf(desc, sizeof(desc), "%d adet basarisiz veritabani giris denemesi.",
                 r->db_stats.auth_failures);
        _add_alert(r, "DB_BRUTE_FORCE", "KRITIK", 90,
                   "Veritabani Brute Force Tespiti", desc,
                   "Veritabani portunu disa kapat. Guclu sifre kullan.");
    }
}

/* ========== dmesg Analizi ========== */
static void _analyze_dmesg(AnalysisResult *r) {
    char output[MAX_CMD_OUTPUT * 2];
    if (platform_run_command("dmesg --time-format=iso -l warn,err,crit 2>/dev/null | tail -100",
                             output, sizeof(output)) != 0) return;

    int count = 0;
    char *line = strtok(output, "\n");
    while (line && count < 100) {
        str_trim(line);
        if (strlen(line) > 0) {
            r->log_stats.dmesg_lines++;
            /* Kritik kernel hataları */
            if (str_contains_ci(line, "oom") || str_contains_ci(line, "out of memory")) {
                _add_alert(r, "KERNEL_OOM", "YUKSEK", 70,
                           "Bellek Yetersizligi (OOM) Kernel Hatasi",
                           line,
                           "RAM kullanimi izle. Gereksiz servisleri durdur.");
            } else if (str_contains_ci(line, "segfault") || str_contains_ci(line, "general protection")) {
                _add_alert(r, "KERNEL_SEGFAULT", "ORTA", 50,
                           "Kernel Segfault Tespiti",
                           line,
                           "Ilgili sureci incele. Sistem guncellemesi yap.");
            } else if (str_contains_ci(line, "usb") && str_contains_ci(line, "new")) {
                _add_alert(r, "USB_DEVICE", "DUSUK", 20,
                           "Yeni USB Cihaz Baglantisi",
                           line,
                           "Yetkilendirilmemis USB cihazlarini incele.");
            }
            count++;
        }
        line = strtok(NULL, "\n");
    }
}

/* ========== Giris Gecmisi Analizi ========== */
static void _analyze_login_history(AnalysisResult *r) {
    char output[MAX_CMD_OUTPUT];
    /* Son 24 saatin girişlerini al, reboot hariç */
    if (platform_run_command(
        "last -n 50 -F 2>/dev/null | grep -v reboot | grep -v 'still logged' | "
        "grep -v 'wtmp begins' | head -20",
        output, sizeof(output)) != 0) return;

    char *line = strtok(output, "\n");
    while (line) {
        str_trim(line);
        if (strlen(line) == 0) { line = strtok(NULL, "\n"); continue; }

        /* Saat çıkar: "HH:MM" formatı */
        int hour = -1;
        char *colon = strchr(line, ':');
        if (colon && colon > line + 1) {
            char h2[3] = { *(colon-2), *(colon-1), '\0' };
            hour = atoi(h2);
        }

        if (hour >= 2 && hour <= 5) {
            char desc[512];
            snprintf(desc, sizeof(desc),
                     "Gece saatlerinde sistem girisi tespit edildi: %.150s", line);
            _add_alert(r, "ODD_LOGIN_TIME", "DUSUK", 30,
                       "Olagan Disi Saatte Giris",
                       desc,
                       "Girisi dogrula. Yetkisiz ise hesabi incele.");
            break;
        }
        line = strtok(NULL, "\n");
    }
}

/* ========== Aktif Saldırı Dosyası ========== */
static void _check_active_attacks(AnalysisResult *r) {
    FILE *fp = fopen("/tmp/detected_attacks.log", "r");
    if (!fp) return;
    char line[512];
    int attack_count = 0;
    while (fgets(line, sizeof(line), fp) && attack_count < 5) {
        str_trim(line);
        if (strlen(line) == 0) continue;
        char *sep1 = strchr(line, '|');
        if (!sep1) continue;
        *sep1 = '\0';
        char *attack_name = sep1 + 1;
        char *sep2 = strchr(attack_name, '|');
        char *raw_line = "";
        if (sep2) { *sep2 = '\0'; raw_line = sep2 + 1; }
        int is_exploit = str_contains_ci(attack_name, "meterpreter") ||
                         str_contains_ci(attack_name, "session")     ||
                         str_contains_ci(attack_name, "exploit");
        char title[256], desc[512];
        snprintf(title, sizeof(title), "Aktif Tehdit: %s", attack_name);
        snprintf(desc,  sizeof(desc),  "Hedef tespit edildi. Detay: %.100s", raw_line);
        _add_alert(r, "ACTIVE_SCAN",
                   is_exploit ? "KRITIK" : "YUKSEK",
                   is_exploit ? 95 : 75,
                   title, desc,
                   "Saldiriyi durdurun veya guvенlik duvari kurali ekleyin.");
        attack_count++;
    }
    fclose(fp);
}

/* ========== Saldırı Süreci İzleme ========== */
static void _check_attack_processes(AnalysisResult *r) {
#ifdef PLATFORM_LINUX
    char output[MAX_CMD_OUTPUT * 2];
    if (platform_run_command("ps aux 2>/dev/null", output, sizeof(output)) != 0) return;
    const char *tools[]  = { "nmap","sqlmap","dirb","gobuster","ffuf",
                             "nikto","hydra","medusa","msfconsole","metasploit", NULL };
    const char *labels[] = { "Nmap Ag/Port Taramasi","SQLMap Veritabani Taramasi",
                             "Web Dizin Taramasi","Web Dizin Taramasi","Web Dizin Taramasi",
                             "Nikto Web Zafiyet Taramasi","Brute Force Saldirisi",
                             "Brute Force Saldirisi","Metasploit Framework",
                             "Metasploit Framework", NULL };
    char *line = strtok(output, "\n");
    while (line) {
        if (!str_contains_ci(line, "grep")) {
            for (int i = 0; tools[i]; i++) {
                if (str_contains_ci(line, tools[i])) {
                    if (str_contains(line, "scan_results")) break;
                    char desc[512];
                    snprintf(desc, sizeof(desc), "Tespit edilen islem: %.200s", line);
                    _add_alert(r, "ACTIVE_SCAN",
                               (i >= 6) ? "KRITIK" : "YUKSEK",
                               (i >= 6) ? 95 : 75,
                               labels[i], desc,
                               "Saldiriyi durdurun veya guvенlik duvari engelleme kurali ekleyin.");
                    break;
                }
            }
        }
        line = strtok(NULL, "\n");
    }
#endif
}

/* ========== Ana Analiz ========== */
void analyzer_run(AnalysisResult *r) {
    memset(r, 0, sizeof(AnalysisResult));

    _analyze_httpd_access(r);
    _analyze_journal(r);
    _analyze_mariadb(r);
    _analyze_dmesg(r);
    _analyze_login_history(r);
    _check_active_attacks(r);
    _check_attack_processes(r);

    r->log_stats.total_lines = r->log_stats.journal_lines +
                               r->log_stats.httpd_access_lines +
                               r->log_stats.mariadb_lines +
                               r->log_stats.dmesg_lines;

    r->critical = 0; r->high = 0; r->medium = 0; r->low = 0; r->info = 0;
    for (int i = 0; i < r->alert_count; i++) {
        if      (str_contains(r->alerts[i].severity, "KRITIK")) r->critical++;
        else if (str_contains(r->alerts[i].severity, "YUKSEK")) r->high++;
        else if (str_contains(r->alerts[i].severity, "ORTA"))   r->medium++;
        else if (str_contains(r->alerts[i].severity, "DUSUK"))  r->low++;
        else r->info++;
    }

    /* Zamanlayıcılı baskılama */
    double now = (double)time(NULL);
    if (g_suppress_until > 0.0 && now < g_suppress_until) {
        r->alert_count = 0;
        r->critical = 0; r->high = 0; r->medium = 0; r->low = 0; r->info = 0;
    } else if (now >= g_suppress_until) {
        g_suppress_until = 0.0; /* süre doldu, sıfırla */
    }
}

int analyzer_read_raw_log(const char *source, char lines[][256], int max_lines) {
    if (strcmp(source, "journal") == 0)
        return _read_journal(lines, max_lines, NULL, "60 minutes ago");
    if (strcmp(source, "httpd_access") == 0) {
        const char *paths[] = { "/var/log/httpd/access_log", "/var/log/apache2/access.log", NULL };
        for (int i = 0; paths[i]; i++) { int c = _read_file_log(paths[i], lines, max_lines); if (c > 0) return c; }
    }
    if (strcmp(source, "httpd_error") == 0) {
        const char *paths[] = { "/var/log/httpd/error_log", "/var/log/apache2/error.log", NULL };
        for (int i = 0; paths[i]; i++) { int c = _read_file_log(paths[i], lines, max_lines); if (c > 0) return c; }
    }
    if (strcmp(source, "mariadb") == 0)
        return _read_journal(lines, max_lines, "mariadbd", "60 minutes ago");
    if (strcmp(source, "dmesg") == 0) {
        char output[MAX_CMD_OUTPUT * 2];
        platform_run_command("dmesg --time-format=iso 2>/dev/null | tail -200", output, sizeof(output));
        int count = 0;
        char *line = strtok(output, "\n");
        while (line && count < max_lines) {
            str_trim(line);
            if (strlen(line) > 0) {
                strncpy(lines[count], line, 255);
                lines[count][255] = '\0';
                count++;
            }
            line = strtok(NULL, "\n");
        }
        return count;
    }
    return 0;
}

void analyzer_clear_alerts(void) {
    /* 10 dakika süreyle baskıla */
    g_suppress_until = (double)time(NULL) + 600.0;
    remove("/tmp/detected_attacks.log");
}

void analyzer_init(void)    { g_analyzer_initialized = 1; }
void analyzer_cleanup(void) { g_analyzer_initialized = 0; }
