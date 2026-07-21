/*
 * main.c — Ana Giriş Noktası
 * Akıllı Şehir Güvenlik Merkezi — C Native Desktop Uygulaması
 */
#include "platform.h"
#include "utils.h"
#include "arp_scanner.h"
#include "log_analyzer.h"
#include "network_monitor.h"
#include "port_scanner.h"
#include "brute_force.h"
#include "gui.h"
#include <stdio.h>
#include <string.h>

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
    analyzer_init();
    full_monitor_init();
    portscan_init();
    bf_init();

    /* Otonom ağ taramasını başlat */
    scanner_start_auto_scan(15);

    /* Ağ izleme: GUI'den cihaz bazında başlatılacak (Trafik Yakala butonu) */

    /* GUI başlat */
    gui_init(1280, 720);

    /* Ana döngü */
    while (!gui_should_close()) {
        gui_draw();
    }

    /* Temizlik */
    gui_cleanup();
    arp_spoof_stop();  /* ARP cache'i geri yükle */
    bf_cleanup();
    portscan_cleanup();
    full_monitor_cleanup();
    scanner_cleanup();
    analyzer_cleanup();
    platform_cleanup();

    printf("Guvenlik Merkezi kapatildi.\n");
    return 0;
}
