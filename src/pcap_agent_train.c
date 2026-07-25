/*
 * pcap_agent_train.c — Eğitim / İmza Çıkarımı
 *
 * Burst ring buffer'daki feature vektörlerinden istatistiksel
 * imzalar oluşturur. Her imza, 16 boyutlu bir ortalama vektör
 * ve L2-norm bazlı eşik değerinden oluşur.
 */
#include "pcap_agent.h"
#include <math.h>

/* ================================================================
 * İmza ekle
 * ================================================================ */
void pa_add_signature(pa_agent_t *a, pa_feature_t *fv, const char *name) {
    if (a->sig_count >= PA_MAX_SIGNATURES) {
        fprintf(stderr, "[-] Maksimum imza sayısına ulaşıldı (%d).\n",
                PA_MAX_SIGNATURES);
        return;
    }

    pa_signature_t *s = &a->sigs[a->sig_count];
    strncpy(s->name, name, 63);
    s->name[63] = '\0';
    memcpy(&s->feat, fv, sizeof(pa_feature_t));

    /* threshold = feature vektörünün L2 normunun %80'i */
    double norm = 0.0;
    double *d = (double *)fv;
    for (int i = 0; i < PA_FEATURE_DIM; i++)
        norm += d[i] * d[i];
    s->threshold = sqrt(norm) * 0.80;
    if (s->threshold < 0.01) s->threshold = 0.01;

    s->match_count = 0;
    s->first_seen  = time(NULL);
    s->last_seen   = s->first_seen;

    a->sig_count++;
    printf("    [+] Imza #%d: %-24s (esik=%.4f)\n",
           a->sig_count, name, s->threshold);
}

/* ================================================================
 * Burst buffer'dan ortalama feature vektörü çıkar
 * ================================================================ */
static void extract_features(pa_agent_t *a, pa_feature_t *fv) {
    memset(fv, 0, sizeof(pa_feature_t));

    if (a->burst_idx == 0 && !a->burst_full) return;

    int n = a->burst_full ? PA_BURST_LEN : a->burst_idx;
    if (n < 10) return;

    /* Ortalama */
    for (int i = 0; i < PA_FEATURE_DIM; i++) {
        double sum = 0.0;
        for (int j = 0; j < n; j++)
            sum += a->burst_features[j][i];
        ((double *)fv)[i] = sum / n;
    }

    /* Standart sapma (pkt_size_std alanına yazılır) */
    double mean_size = fv->pkt_size_mean;
    double var_sum = 0.0;
    /* pkt_size_mean burst_features'taki index 4 */
    for (int j = 0; j < n; j++) {
        double d = a->burst_features[j][4] - mean_size;
        var_sum += d * d;
    }
    fv->pkt_size_std = sqrt(var_sum / n);
}

/* ================================================================
 * Eğitim: mevcut imzaları burst verisiyle güncelle
 * ================================================================ */
void pa_agent_train(pa_agent_t *a) {
    if (a->sig_count == 0) {
        printf("[!] Egitim icin imza yok. Atlanıyor.\n");
        return;
    }

    for (int i = 0; i < a->sig_count; i++) {
        pa_feature_t fv;
        extract_features(a, &fv);
        memcpy(&a->sigs[i].feat, &fv, sizeof(pa_feature_t));

        double norm = 0.0;
        double *d = (double *)&fv;
        for (int j = 0; j < PA_FEATURE_DIM; j++)
            norm += d[j] * d[j];
        a->sigs[i].threshold = sqrt(norm) * 0.85;
        if (a->sigs[i].threshold < 0.01) a->sigs[i].threshold = 0.01;
    }

    printf("[+] Egitim tamamlandi. %d imza olusturuldu.\n", a->sig_count);
}

/* ================================================================
 * İmza kaydet (binary)
 * ================================================================ */
int pa_agent_save_sigs(pa_agent_t *a, const char *path) {
    FILE *fp = fopen(path, "wb");
    if (!fp) {
        fprintf(stderr, "[-] Imza dosyasi yazilamadi: %s\n", path);
        return -1;
    }

    fwrite(&a->sig_count, sizeof(int), 1, fp);
    fwrite(a->sigs, sizeof(pa_signature_t), (size_t)a->sig_count, fp);
    fclose(fp);
    return a->sig_count;
}

/* ================================================================
 * İmza yükle (binary)
 * ================================================================ */
int pa_agent_load_sigs(pa_agent_t *a, const char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;

    int cnt;
    if (fread(&cnt, sizeof(int), 1, fp) != 1) { fclose(fp); return -1; }
    if (cnt > PA_MAX_SIGNATURES) cnt = PA_MAX_SIGNATURES;
    if ((int)fread(a->sigs, sizeof(pa_signature_t), (size_t)cnt, fp) != cnt) {
        fclose(fp);
        return -1;
    }
    a->sig_count = cnt;
    fclose(fp);
    return cnt;
}
