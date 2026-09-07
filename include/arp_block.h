/*
 * arp_block.h — Ağdan IP Engelleme (ARP Kara Delik / Black-Hole) Motoru
 *
 * Bir cihazı ağdan kesmek için iki yönlü sahte ARP enjekte eder:
 *   - Hedefe: "Gateway IP → ölü MAC"  (cihazın internete giden paketleri kaybolur)
 *   - Gateway'e: "Hedef IP → ölü MAC" (dönen yanıtlar karartılır)
 *
 * MITM değildir: trafik yönlendirilmez (IP forwarding açılmaz), sadece
 * hedefin ARP tablosu zehirlenir. Aynı gerekçeyle kendi gönderdiğimiz
 * çerçevelerin Ethernet kaynak MAC'i = yerel MAC olduğundan IDS'in
 * "kendi trafiği" süzgeci (ids_is_self_originated) bunları otomatik
 * muaf tutar.
 *
 * Kaldırma: gerçek MAC eşleşmelerini bildiren ARP Reply'lar gönderilir;
 * ARP zaten 30-60 sn içinde kendiliğinden düzelir ama restore paketleri
 * anında toparlar.
 */
#ifndef ARP_BLOCK_H
#define ARP_BLOCK_H

#include "platform.h"

#define ARP_BLOCK_MAX_BLOCKED 32

/* ========== GUI için düz snapshot ========== */
typedef struct {
    char  ip[MAX_IP_LEN];
    char  mac[MAX_MAC_LEN];         /* hedefin çözülen MAC'i */
    char  blocked_at[32];           /* engelleme zamanı */
} ArpBlockEntry;

typedef struct {
    int            count;           /* engelli cihaz sayısı */
    int            engine_ok;       /* raw socket açılabildi mi (root/cap) */
    char           iface[MAX_IFACE_LEN];
    char           gateway_ip[MAX_IP_LEN];
    char           gateway_mac[MAX_MAC_LEN];
    ArpBlockEntry  entries[ARP_BLOCK_MAX_BLOCKED];
} ArpBlockSnapshot;

/* ========== API ========== */
void arp_block_init(void);
void arp_block_cleanup(void);

/* Bağlamı ayarla (iface, yerel MAC, gateway IP/MAC, yerel IP) — GUI her karede günceller */
int  arp_block_set_context(const char *iface, const char *local_mac,
                           const char *gateway_ip, const char *gateway_mac,
                           const char *local_ip);

/* Engelle / geri al. block=1 engelle, 0 geri al.
 * target_mac: hedefin MAC'i ("" ise motor ARP ile çözmeye çalışır).
 * Döner: 1=başarılı, 0=kuyruğa alındı/işlendi, -1=geçersiz/engine yok */
int  arp_block_set(const char *ip, const char *target_mac, int block);

int  arp_block_is_blocked(const char *ip);

/* Thread-safe snapshot (GUI listesi için) */
void arp_block_get_snapshot(ArpBlockSnapshot *out);

int  arp_block_engine_ok(void);

#endif /* ARP_BLOCK_H */
