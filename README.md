# Siber Güvenlik Merkezi (AkilliSehirGuvenlik)

Raylib tabanlı, tek pencereden ağ keşfi, port taraması, canlı trafik izleme ve saldırı tespiti (IDS) sunan C11 güvenlik aracı. **Linux** üzerinde çalışır.

## 📋 Özellikler

- **Modern GUI** — Raylib + Raygui ile geliştirilmiş, çözünürlükten bağımsız ölçeklenen arayüz.
- **Ağ Keşfi (ARP Scanner)** — Ağdaki cihazları tarar ve sınıflandırır. Raw ARP soketleri ile sweep, `/proc/net/arp` ve `ip neigh` ile ARP tablosu okuma.
- **Ağdan Kesme (ARP Black-Hole)** — Seçilen cihazın ağ erişimini anında keser/geri verir.
  - Raw `AF_PACKET` soketleri ile hedefe sürekli sahte ARP yanıtı göndererek (black-hole) cihazın trafiğini karartır.
  - Cihaz listesi satırlarındaki hızlı **KES/AC** düğmeleri, cihaz detayındaki **Ağdan Kes/Geri Ver** butonu ve sol alttaki **ENGELLENEN CİHAZLAR** paneli (Geri Al) üzerinden kullanılır.
  - Ağ geçidi (gateway) ve yerel cihaz (bu cihaz) motor tarafından engellenemez.
- **Otonom Port Tarayıcı (AutoPort)** — Nmap bağımsız, çok kanallı (thread pool) port/servis analizi; TTL tabanlı OS tahmini.
  - TCP Connect taraması (tüm kullanıcılar)
  - Root yetkisiyle: SYN, FIN, NULL, Xmas, ACK, Window, Maimon raw taramaları
- **Canlı Trafik İzleme (PCAP)** — libpcap ile gerçek zamanlı paket yakalama.
- **Ağ IDS** — Yakalanan trafik üzerinde 20 kural çalıştırır: ARP spoofing, IP-MAC bağlama değişimi, ARP MITM, sahte TCP bayrak kombinasyonları, yatay/dikey port taraması, SSH brute-force denemesi, L7 payload imzaları (SQLi, XSS, JNDI, PowerShell, NOP-sled, Meterpreter vb.). 60 sn cooldown ile uyarı üretir.
- **Display Filtre Motoru** — Wireshark tarzı filtre ifadeleri (`ip.addr == 10.0.0.5 && tcp.port == 443` gibi) ile paket listesi filtreleme; 138 birim testle doğrulanmış ayrıştırıcı.

## 🛠️ Gereksinimler

- CMake 3.16+, GCC veya Clang
- `libpcap-dev` (canlı trafik + IDS için)
- Raylib bağımlılıkları (X11/Wayland, OpenGL) — dağıtım paketinden `raylib` kurun

## 🚀 Kurulum ve Derleme

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j4
./build/guvenlik_merkezi
```

> Derleme çıktıları `build/` klasöründe tutulur ve `.gitignore`'dadır.

## 🏁 Çalıştırma Notları

SYN gibi raw tarama türleri ve libpcap yakalaması root ister:

```bash
xhost +
sudo ./build/guvenlik_merkezi
```

## 🧪 Testler

```bash
# Display filtre motoru regresyon testi
gcc -std=c11 -D_GNU_SOURCE -Iinclude tests/filter_engine_test.c src/filter_engine.c src/utils.c -o fetest && ./fetest
```

## 📁 Proje Yapısı

```
├── CMakeLists.txt          # Bağımlılıklar ve derleme bayrakları
├── include/                # Başlıklar (platform soyutlaması: platform.h)
├── lib/raygui.h            # Raygui (tek dosya)
├── src/
│   ├── main.c              # Giriş noktası
│   ├── gui.c               # Raylib/raygui arayüzü
│   ├── platform.c/h        # Platform soyutlaması (thread, iface shims)
│   ├── arp_scanner.c       # Ağ keşfi (raw ARP / /proc/net/arp)
│   ├── arp_block.c         # Ağdan Kesme (ARP black-hole) motoru
│   ├── port_scanner.c      # Port tarama motoru
│   ├── network_monitor.c   # libpcap canlı yakalama
│   ├── network_ids.c       # IDS kuralları ve alert motoru
│   ├── filter_engine.c     # Display filtre ayrıştırıcı
│   └── utils.c             # Yardımcılar (hashmap, str, log)
└── tests/                  # Birim/regresyon testleri
```
