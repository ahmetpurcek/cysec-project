/*
 * main.c — Ana Giriş Noktası
 * Akıllı Şehir Güvenlik Merkezi — C Native Desktop Uygulaması
 */
#include "platform.h"
#include "utils.h"
#include "arp_scanner.h"
#include "pcap_agent.h"
#include "network_monitor.h"
#include "port_scanner.h"
#include "gui.h"
#include <stdio.h>
#include <string.h>

/* Global PCAP Agent — GUI'den erişilebilir */
pa_agent_t g_pcap_agent;

/* Agent'ı arka planda çalıştıran thread */
static void *pcap_agent_thread(void *arg) {
    (void)arg;
    pa_agent_start_capture(&g_pcap_agent);
    return NULL;
}

int main(int argc, char *argv[]) {
    printf("=== Akilli Sehir Guvenlik Merkezi ===\n");
    printf("Platform: %s\n", PLATFORM_NAME);

    /* Platform başlat */
    if (platform_init() != 0) {
        fprintf(stderr, "Platform baslatilamadi!\n");
        return 1;
    }

    /* Modüller başlat */
    scanner_init();
    full_monitor_init();
    portscan_init();

    /* PCAP Agent başlat */
    {
        const char *iface = (argc > 1) ? argv[1] : NULL;
        if (pa_agent_init(&g_pcap_agent, iface) != 0) {
            fprintf(stderr, "[-] PCAP Agent baslatilamadi.\n");
        } else {
            printf("[*] PCAP Agent: arayuz=%s\n", g_pcap_agent.iface);

            /* pcap_files/ dizinindeki dosyalardan imza çıkar */
            if (pa_agent_load_pcaps(&g_pcap_agent, PA_PCAP_DIR) > 0) {
                pa_agent_train(&g_pcap_agent);
                pa_agent_save_sigs(&g_pcap_agent, PA_SIG_FILE);
                printf("[+] %d imza olusturuldu ve kaydedildi.\n",
                       g_pcap_agent.sig_count);

                /* Pcap dosyalarını imzalara karşı tekrar tara → alarm üret */
                pa_agent_rescan_pcaps(&g_pcap_agent, PA_PCAP_DIR);
            } else {
                if (pa_agent_load_sigs(&g_pcap_agent, PA_SIG_FILE) > 0) {
                    printf("[*] Kayitli %d imza yuklendi.\n",
                           g_pcap_agent.sig_count);
                } else {
                    printf("[!] Imza yok, anomali modunda calisacak.\n");
                }
            }

            /* Canlı yakalamayı arka plan thread'inde başlat */
            platform_thread_t capture_thread;
            if (platform_thread_create(&capture_thread,
                                       pcap_agent_thread, NULL) == 0) {
                platform_thread_detach(capture_thread);
                printf("[+] PCAP Agent canli yakalama basladi.\n");
            } else {
                fprintf(stderr, "[-] Agent thread olusturulamadi.\n");
            }
        }
    }

    /* Otonom ağ taramasını başlat */
    scanner_start_auto_scan(15);

    /* GUI başlat */
    gui_init(1280, 720);

    /* Ana döngü */
    while (!gui_should_close()) {
        gui_draw();
    }

    /* Temizlik */
    gui_cleanup();
    pa_agent_stop_capture(&g_pcap_agent);
    pa_agent_destroy(&g_pcap_agent);
    arp_spoof_stop();
    portscan_cleanup();
    full_monitor_cleanup();
    scanner_cleanup();
    platform_cleanup();

    printf("Guvenlik Merkezi kapatildi.\n");
    return 0;
}
