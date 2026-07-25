/*
 * pcap_agent_main.c — PCAP Agent Bağımsız Çalıştırıcı
 *
 * Kullanım:
 *   ./pcap_agent            (otomatik arayüz bulur)
 *   ./pcap_agent eth0       (belirtilen arayüzde dinler)
 *   ./pcap_agent --offline  (canlı yakalama yapmaz, sadece pcap analiz)
 *
 * Akış:
 *   1. pcap_files/ dizinindeki tüm .pcap dosyalarını tara
 *   2. Feature vektörlerinden imza çıkar
 *   3. İmzaları agent_signatures.dat'a kaydet
 *   4. Canlı ağ trafiğini dinle + alarm üret
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include "pcap_agent.h"

static pa_agent_t g_agent;

static void sigint_handler(int sig) {
    (void)sig;
    fprintf(stderr, "\n[!] Kapatiliyor...\n");
    g_agent.running = 0;
    pa_agent_stop_capture(&g_agent);

    /* Çıkışta rapor */
    printf("\n--- Oturum Ozeti ---\n");
    printf("Toplam paket  : %lu\n", (unsigned long)g_agent.total_pkts_processed);
    printf("Toplam bayt   : %lu\n", (unsigned long)g_agent.total_bytes_processed);
    printf("Aktif flow    : %d\n",  g_agent.flow_count);
    printf("Imza sayisi   : %d\n",  g_agent.sig_count);
    printf("Alarm sayisi  : %d\n",  g_agent.alert_count);

    pa_agent_print_alerts(&g_agent);
    pa_agent_destroy(&g_agent);
    exit(0);
}

static void print_banner(void) {
    printf("\n");
    printf("  +========================================+\n");
    printf("  |     PCAP Agent v1.0                    |\n");
    printf("  |  Ogren + Tespit + Raporla              |\n");
    printf("  |  CySec Project - Tehdit Algilama       |\n");
    printf("  +========================================+\n");
    printf("\n");
}

int main(int argc, char **argv) {
    const char *iface = NULL;
    int offline_only = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--offline") == 0) {
            offline_only = 1;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printf("Kullanim: %s [arayuz | --offline | --help]\n", argv[0]);
            printf("  arayuz    : Canli dinlenecek ag arayuzu (orn: eth0)\n");
            printf("  --offline : Sadece pcap dosyalarini analiz et\n");
            printf("  --help    : Bu mesaj\n");
            return 0;
        } else {
            iface = argv[i];
        }
    }

    signal(SIGINT, sigint_handler);
#ifndef _WIN32
    signal(SIGTERM, sigint_handler);
#endif

    print_banner();

    /* Agent başlat */
    if (pa_agent_init(&g_agent, iface) != 0) {
        fprintf(stderr, "[-] Agent baslatilamadi.\n");
        return 1;
    }

    printf("[*] Ag arayuzu: %s\n", g_agent.iface);

    /* 1. Eğitim: pcap_files/ dizinindeki tüm pcap'leri tara */
    printf("[*] Pcap dosyalari taraniyor: %s/\n", PA_PCAP_DIR);
    if (pa_agent_load_pcaps(&g_agent, PA_PCAP_DIR) > 0) {
        printf("[*] Ogrenme baslatiliyor (%d imza)...\n",
               g_agent.sig_count);
        pa_agent_train(&g_agent);
        pa_agent_save_sigs(&g_agent, PA_SIG_FILE);
        printf("[+] Imzalar kaydedildi: %s\n", PA_SIG_FILE);

        /* Re-scan: pcap dosyalarını imzalara karşı tekrar tara */
        pa_agent_rescan_pcaps(&g_agent, PA_PCAP_DIR);
    } else {
        /* Kayıtlı imza var mı? */
        if (pa_agent_load_sigs(&g_agent, PA_SIG_FILE) > 0) {
            printf("[*] Kayitli imzalar yuklendi: %s (%d imza)\n",
                   PA_SIG_FILE, g_agent.sig_count);
        } else {
            printf("[!] Hic imza yok. Sadece anomali modunda calisacak.\n");
        }
    }

    /* 2. Offline mod mu? */
    if (offline_only) {
        printf("\n[*] Offline mod: Canli yakalama atlanıyor.\n");
        pa_agent_print_alerts(&g_agent);
        printf("\n--- Analiz Ozeti ---\n");
        printf("Toplam paket  : %lu\n",
               (unsigned long)g_agent.total_pkts_processed);
        printf("Toplam bayt   : %lu\n",
               (unsigned long)g_agent.total_bytes_processed);
        printf("Aktif flow    : %d\n",  g_agent.flow_count);
        printf("Imza sayisi   : %d\n",  g_agent.sig_count);
        printf("Alarm sayisi  : %d\n",  g_agent.alert_count);
        pa_agent_destroy(&g_agent);
        return 0;
    }

    /* 3. Canlı yakalama başlat */
    printf("[*] Canli trafik dinleniyor... (Ctrl+C durdurur)\n\n");
    pa_agent_start_capture(&g_agent);

    /* Buraya pcap_loop bitince gelir (Ctrl+C veya hata) */
    pa_agent_print_alerts(&g_agent);
    pa_agent_destroy(&g_agent);

    return 0;
}
