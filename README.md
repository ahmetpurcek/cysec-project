# 🏛️ Akıllı Şehir Siber Güvenlik Merkezi

Belediye Public Wi-Fi, Akıllı Kamera ve IoT Altyapısı için gerçek zamanlı siber güvenlik izleme ve tehdit tespit platformu.

Eski Python tabanlı sürümden **tamamen yerel C diline** geçirilmiştir. Artık daha yüksek performanslı, düşük kaynak tüketen ve gelişmiş güvenlik araçlarına (otonom port tarayıcı, canlı ağ izleyici) sahip standalone bir masaüstü uygulamasıdır.

## 📋 Özellikler

- **Yerel ve Modern GUI** — Raylib kullanılarak geliştirilmiş, her çözünürlüğe ölçeklenebilen akıcı kullanıcı arayüzü.
- **Ağ Keşfi (ARP Scanner)** — Ağdaki cihazları dinamik olarak bulur. Detaylı MAC Vendor sınıflandırması (Cisco, Apple, Akıllı Ev Aletleri, Kameralar vb.) ve rastgele MAC tespiti yapar.
- **Gelişmiş Log Analizi** — `journalctl`, `dmesg`, `httpd` ve `mariadb` loglarını sürekli izleyerek SSH brute-force, web dizin taramaları, IP flood, kernel oom/segfault hatalarını tespit eder.
- **Canlı Trafik (PCAP)** — `libpcap` tabanlı canlı ağ trafiği izleme, şüpheli ağ akışlarının gerçek zamanlı tespiti.
- **Otonom Port Tarayıcı (AutoPort)** — Nmap'ten tamamen bağımsız, çok kanallı (thread pool) çalışan; TCP Connect, SYN, FIN, NULL, Xmas ve UDP tarama özellikli gelişmiş port/servis analizi ve TTL tabanlı OS tahmini.

## 🛠️ Gereksinimler (Linux)

Derleme ve çalıştırma için gereken bağımlılıklar:

- CMake 3.16+
- GCC veya Clang
- `libpcap` geliştirme paketleri (`sudo apt install libpcap-dev`)
- Raylib bağımlılıkları (X11, Wayland, OpenGL)

## 🚀 Kurulum ve Derleme

```bash
# Repoyu klonladıktan veya dizine girdikten sonra:
mkdir build
cd build

# Projeyi yapılandır
cmake .. -DCMAKE_BUILD_TYPE=Release

# Derle (Çoklu çekirdek desteği ile)
make -j$(nproc)
```

## 🏁 Çalıştırma

Bazı gelişmiş tarama türleri (örn. SYN Scan) ve libpcap ile canlı trafik izleme özellikleri root yetkisi gerektirir.

```bash
sudo ./guvenlik_merkezi
```

**Not:** MAC adres çözümlemeleri için `mac-addresses.txt` dosyasının derlenen `guvenlik_merkezi` çalıştırılabilir dosyası ile aynı dizinde yer aldığından emin olun.
