/*
 * main.c — Ana Giriş Noktası
 * Akıllı Şehir Güvenlik Merkezi — C Native Desktop Uygulaması
 */
#include "platform.h"
#include "utils.h"
#include "arp_scanner.h"
#include "network_monitor.h"
#include "network_ids.h"
#include "port_scanner.h"
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
    full_monitor_init();
    ids_init();
    portscan_init();

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
    arp_spoof_stop();
    portscan_cleanup();
    full_monitor_cleanup();
    ids_cleanup();
    scanner_cleanup();
    platform_cleanup();

    printf("Guvenlik Merkezi kapatildi.\n");
    return 0;
}

