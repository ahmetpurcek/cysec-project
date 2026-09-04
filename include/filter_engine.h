/*
 * filter_engine.h — Wireshark-tarzı Display Filtre Motoru
 *
 * Paket Izleme sekmesindeki paket listesini filtrelemek için
 * Wireshark sözdiziminin küçük bir alt kümesini uygular.
 *
 * ===================== Desteklenen Sözdizimi =====================
 *
 *   Mantıksal operatörler:  and / && ,  or / ||   (küçük/büyük harf duyarsız)
 *   Karşılaştırma:          ==   !=   contains
 *   Parantez DESTEKLENMEZ;  "!" (değil) öneki DESTEKLENMEZ.
 *
 *   Alanlar:
 *     ip / ip.addr            Kaynak veya hedef IP
 *     ip.src / ip.dst         Kaynak / hedef IP
 *     eth.addr / eth / mac            Kaynak veya hedef MAC
 *     mac.src / mac.dst / eth.src / eth.dst
 *     tcp.port, tcp.srcport/sport, tcp.dstport/dport   (yalnız TCP paketleri)
 *     udp.port, udp.srcport/sport, udp.dstport/dport   (yalnız UDP paketleri)
 *     port                     Herhangi bir kaynak veya hedef port
 *     proto / protocol         Protokol adı (tcp, udp, http, dns, tls, arp...)
 *     info / frame             Paket özet (info) metni
 *
 *   contains değeri boşluk içerebilir; çift tırnakla yazılabilir:
 *     info contains "GET /"    info contains GET /
 *
 *   Çıplak (operatorsüz) sözcük: önce protokol adı olarak denenir,
 *   bulunamazsa paketin metin alanlarında geçerli mi diye bakılır:
 *     dns        tcp         http         443         192.168.1.5
 *
 *   Örnekler:
 *     ip.addr == 192.168.1.5
 *     tcp.port == 443 or udp.port == 53
 *     ip.src == 10.0.0.1 and tcp.port == 80
 *     dns or mdns
 *     info contains GET
 *
 * Boş ifade = filtre yok (tüm paketler eşleşir). Bilinmeyen alan adı veya
 * hatalı sözdizimi => ifade GEÇERSİZ sayılır (filter_engine_expr_valid == 0).
 */
#ifndef FILTER_ENGINE_H
#define FILTER_ENGINE_H

#include "network_monitor.h"

#ifdef __cplusplus
extern "C" {
#endif

/* İfade geçerli mi? 1 = geçerli, 0 = geçersiz. Boş ifade geçerlidir. */
int filter_engine_expr_valid(const char *expr);

/* Paket ifadeyle eşleşiyor mu? 1 = eşleşti, 0 = eşleşmedi.
 * Boş ifade her paketle eşleşir; GEÇERSİZ ifade hiçbir paketi elemez
 * (1 döner) — böylece kullanıcı sözdizimini düzeltirken liste kaybolmaz. */
int filter_engine_packet_matches(const PacketRecord *pkt, const char *expr);

#ifdef __cplusplus
}
#endif

#endif /* FILTER_ENGINE_H */

