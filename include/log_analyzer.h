/*
 * log_analyzer.h — Sistem Log Analiz Motoru
 * Sistem loglarını okur, anomali ve sızma girişimlerini tespit eder.
 */
#ifndef LOG_ANALYZER_H
#define LOG_ANALYZER_H

#include "platform.h"
#include "utils.h"

/* ========== Sabitler ========== */
#define MAX_ALERTS          100
#define MAX_LOG_LINES       500
#define MAX_RAW_LOG_LINES   50
#define LOG_FRESHNESS_MIN   60   /* dakika */

/* ========== Alert Yapısı ========== */
typedef struct {
    char type[32];
    char severity[16];        /* KRİTİK, YÜKSEK, ORTA, DÜŞÜK, BİLGİ */
    int  severity_score;      /* 0-100 */
    char title[256];
    char description[512];
    char recommendation[256];
} Alert;

/* ========== Log İstatistikleri ========== */
typedef struct {
    int total_lines;
    int journal_lines;
    int httpd_access_lines;
    int httpd_error_lines;
    int mariadb_lines;
    int dmesg_lines;
} LogStats;

/* ========== HTTP İstatistikleri ========== */
typedef struct {
    int total_requests;
    int suspicious_count;
    int error_404_count;
} HttpStats;

/* ========== DB İstatistikleri ========== */
typedef struct {
    int aborted_connections;
    int auth_failures;
    int warnings;
    int errors;
} DbStats;

/* ========== Analiz Sonucu ========== */
typedef struct {
    Alert   alerts[MAX_ALERTS];
    int     alert_count;
    
    /* Özet */
    int     critical;
    int     high;
    int     medium;
    int     low;
    int     info;
    
    /* İstatistikler */
    LogStats  log_stats;
    HttpStats http_stats;
    DbStats   db_stats;
    
    /* Son log satırları */
    char raw_journal[MAX_RAW_LOG_LINES][256];
    int  raw_journal_count;
    char raw_httpd[MAX_RAW_LOG_LINES][256];
    int  raw_httpd_count;
} AnalysisResult;

/* ========== Fonksiyonlar ========== */
void analyzer_init(void);
void analyzer_cleanup(void);

/* Tüm logları analiz et */
void analyzer_run(AnalysisResult *result);

/* Belirli log kaynağını ham olarak oku */
int  analyzer_read_raw_log(const char *source, char lines[][256], int max_lines);

/* Uyarıları temizle */
void analyzer_clear_alerts(void);

#endif /* LOG_ANALYZER_H */
