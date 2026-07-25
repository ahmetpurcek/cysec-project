/*
 * pcap_agent_loader.c — PCAP Dosya Yükleyici + Agent Yaşam Döngüsü
 *
 * - pcap_files/ dizinindeki tüm .pcap/.pcapng dosyalarını tarar
 * - Agent başlatma (init) ve yıkım (destroy) fonksiyonları
 * - Canlı ağ yakalama (start/stop capture)
 * - Otomatik imza çıkarımı
 */
#include "pcap_agent.h"
#include <string.h>

/* ================================================================
 * Canlı yakalama callback
 * ================================================================ */
static void pcap_live_callback(u_char *user,
                               const struct pcap_pkthdr *h,
                               const u_char *pkt)
{
    pa_agent_t *a = (pa_agent_t *)user;
    if (!a->running) {
        pcap_breakloop(a->pcap_handle);
        return;
    }
    pa_agent_process_pkt(a, pkt, (int)h->caplen, (struct timeval *)&h->ts);
}

/* ================================================================
 * Tek bir pcap dosyasını oku ve işle
 * ================================================================ */
static int load_single_pcap(pa_agent_t *a, const char *filepath) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *p = pcap_open_offline(filepath, errbuf);
    if (!p) {
        fprintf(stderr, "    [!] %s acilamadi: %s\n", filepath, errbuf);
        return -1;
    }

    printf("    [*] Isleniyor: %s\n", filepath);

    struct pcap_pkthdr *hdr;
    const u_char *pkt;
    int cnt = 0;

    while (pcap_next_ex(p, &hdr, &pkt) > 0) {
        pa_agent_process_pkt(a, pkt, (int)hdr->caplen, &hdr->ts);
        cnt++;
    }

    printf("    [*] %d paket okundu.\n", cnt);
    pcap_close(p);
    return cnt;
}

/* ================================================================
 * Dizindeki tüm pcap dosyalarını yükle
 * ================================================================ */
int pa_agent_load_pcaps(pa_agent_t *a, const char *dir) {
    DIR *d = opendir(dir);
    if (!d) {
        fprintf(stderr, "[-] Dizin acilamadi: %s\n", dir);
        return -1;
    }

    int total = 0;
    struct dirent *entry;
    while ((entry = readdir(d)) != NULL) {
        const char *name = entry->d_name;
        int len = (int)strlen(name);
        if (len < 5) continue;

        /* .pcap veya .pcapng uzantısı kontrol */
        int is_pcap   = (len >= 5  && strcasecmp(name + len - 5,  ".pcap") == 0);
        int is_pcapng = (len >= 7  && strcasecmp(name + len - 7, ".pcapng") == 0);
        if (!is_pcap && !is_pcapng) continue;

        char fullpath[512];
        snprintf(fullpath, sizeof(fullpath), "%s/%s", dir, name);

        int n = load_single_pcap(a, fullpath);
        if (n > 0) total += n;
    }
    closedir(d);

    printf("[*] Toplam %d paket islendi.\n", total);

    /* Hiç imza yoksa burst buffer'dan otomatik imza çıkar */
    if (a->sig_count == 0 && total > 0) {
        int n = a->burst_full ? PA_BURST_LEN : a->burst_idx;
        int step = n / 10;
        if (step < 100) step = 100;

        for (int i = 0; i < n; i += step) {
            pa_feature_t fv;
            memset(&fv, 0, sizeof(fv));

            int end   = i + step;
            if (end > n) end = n;
            int count = end - i;
            if (count < 50) continue;

            /* Segment ortalaması */
            for (int j = i; j < end; j++) {
                for (int k = 0; k < PA_FEATURE_DIM; k++)
                    ((double *)&fv)[k] += a->burst_features[j][k];
            }
            for (int k = 0; k < PA_FEATURE_DIM; k++)
                ((double *)&fv)[k] /= count;

            char sig_name[64];
            snprintf(sig_name, sizeof(sig_name), "pcap_imza_%d",
                     a->sig_count + 1);
            pa_add_signature(a, &fv, sig_name);
        }
    }

    return total;
}

/* ================================================================
 * Re-scan: Eğitim sonrası pcap dosyalarını imzalara karşı tekrar tara
 * Bu sayede pcap'lerdeki tehditler alarm olarak üretilir.
 * ================================================================ */
static int rescan_single_pcap(pa_agent_t *a, const char *filepath) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *p = pcap_open_offline(filepath, errbuf);
    if (!p) return -1;

    struct pcap_pkthdr *hdr;
    const u_char *pkt;
    int cnt = 0;

    while (pcap_next_ex(p, &hdr, &pkt) > 0) {
        pa_agent_process_pkt(a, pkt, (int)hdr->caplen, &hdr->ts);
        cnt++;
    }

    pcap_close(p);
    return cnt;
}

void pa_agent_rescan_pcaps(pa_agent_t *a, const char *dir) {
    if (a->sig_count == 0) return;

    DIR *d = opendir(dir);
    if (!d) return;

    printf("[*] Pcap dosyalari imzalara karsi yeniden taraniyor...\n");

    /* Burst buffer'ı sıfırla (temiz rescan) */
    a->burst_idx  = 0;
    a->burst_full = 0;

    struct dirent *entry;
    while ((entry = readdir(d)) != NULL) {
        const char *name = entry->d_name;
        int len = (int)strlen(name);
        if (len < 5) continue;
        int is_pcap   = (len >= 5  && strcasecmp(name + len - 5,  ".pcap") == 0);
        int is_pcapng = (len >= 7  && strcasecmp(name + len - 7, ".pcapng") == 0);
        if (!is_pcap && !is_pcapng) continue;

        char fullpath[512];
        snprintf(fullpath, sizeof(fullpath), "%s/%s", dir, name);
        rescan_single_pcap(a, fullpath);
    }
    closedir(d);

    printf("[+] Re-scan tamamlandi. %d alarm uretildi.\n", a->alert_count);
}

/* ================================================================
 * Agent başlat
 * ================================================================ */
int pa_agent_init(pa_agent_t *a, const char *iface) {
    memset(a, 0, sizeof(pa_agent_t));
    a->running     = 0;
    a->pcap_handle = NULL;
    a->start_time  = time(NULL);

    /* Heap allocation: flow tablosu */
    a->flows = (pa_flow_t *)calloc(PA_MAX_FLOWS, sizeof(pa_flow_t));
    if (!a->flows) {
        fprintf(stderr, "[-] Flow tablosu icin bellek ayrılamadı.\n");
        return -1;
    }

    /* Heap allocation: burst ring buffer */
    a->burst_features = (double (*)[PA_FEATURE_DIM])calloc(
        PA_BURST_LEN, sizeof(double) * PA_FEATURE_DIM);
    if (!a->burst_features) {
        fprintf(stderr, "[-] Burst buffer icin bellek ayrılamadı.\n");
        free(a->flows);
        a->flows = NULL;
        return -1;
    }

    /* Ağ arayüzü */
    if (iface && strlen(iface) > 0) {
        strncpy(a->iface, iface, 63);
        a->iface[63] = '\0';
    } else {
#ifdef _WIN32
        pcap_if_t *alldevs;
        char errbuf[PCAP_ERRBUF_SIZE];
        if (pcap_findalldevs(&alldevs, errbuf) == -1 || !alldevs) {
            fprintf(stderr, "[-] Arayuz bulunamadi: %s\n", errbuf);
            strcpy(a->iface, "\\Device\\NPF_Loopback");
        } else {
            strncpy(a->iface, alldevs->name, 63);
            a->iface[63] = '\0';
            pcap_freealldevs(alldevs);
        }
#else
        FILE *fp = popen(
            "ip route get 1 2>/dev/null | head -1 | awk '{print $5}'", "r");
        if (fp) {
            char buf[64] = {0};
            if (fgets(buf, 63, fp)) {
                buf[strcspn(buf, "\n")] = '\0';
                if (strlen(buf) > 0)
                    strncpy(a->iface, buf, 63);
            }
            pclose(fp);
        }
        if (strlen(a->iface) == 0)
            strcpy(a->iface, "eth0");
#endif
    }

    return 0;
}

/* ================================================================
 * Agent yıkım — tüm heap belleği serbest bırak
 * ================================================================ */
void pa_agent_destroy(pa_agent_t *a) {
    pa_agent_stop_capture(a);
    pa_agent_free_alerts(a);

    if (a->flows) {
        free(a->flows);
        a->flows = NULL;
    }
    if (a->burst_features) {
        free(a->burst_features);
        a->burst_features = NULL;
    }
}

/* ================================================================
 * Canlı yakalama başlat
 * ================================================================ */
void pa_agent_start_capture(pa_agent_t *a) {
    char errbuf[PCAP_ERRBUF_SIZE];

    a->pcap_handle = pcap_open_live(a->iface, 65535, 1, 500, errbuf);
    if (!a->pcap_handle) {
        fprintf(stderr, "[-] Arayuz acilamadi: %s\n  Hata: %s\n",
                a->iface, errbuf);
        fprintf(stderr,
                "  Not: Root/Administrator yetkisi gerekebilir.\n");
        return;
    }

    /* BPF filtresi: sadece IP trafiği */
    struct bpf_program fp;
    if (pcap_compile(a->pcap_handle, &fp, "ip", 0,
                     PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "[-] BPF derlenemedi: %s\n",
                pcap_geterr(a->pcap_handle));
    } else {
        pcap_setfilter(a->pcap_handle, &fp);
        pcap_freecode(&fp);
    }

    a->running = 1;
    printf("[+] Canli yakalama basladi: %s\n", a->iface);

    /* pcap_loop — callback ile paketleri işler */
    int ret = pcap_loop(a->pcap_handle, -1, pcap_live_callback,
                        (u_char *)a);
    if (ret == -1) {
        fprintf(stderr, "[-] pcap_loop hatasi: %s\n",
                pcap_geterr(a->pcap_handle));
    }

    a->running = 0;
    pcap_close(a->pcap_handle);
    a->pcap_handle = NULL;
}

/* ================================================================
 * Canlı yakalamayı durdur
 * ================================================================ */
void pa_agent_stop_capture(pa_agent_t *a) {
    if (a->pcap_handle && a->running) {
        pcap_breakloop(a->pcap_handle);
        a->running = 0;
    }
}
