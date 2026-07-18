# Siber Güvenlik Merkezi

## 📋 Özellikler

- **Yerel ve Modern GUI** — Raylib kullanılarak geliştirilmiş, her çözünürlüğe ölçeklenebilen akıcı kullanıcı arayüzü.
- **Cross-Platform Desteği** — Artık hem **Linux** hem de **Windows** sistemlerde sorunsuz çalışabilen altyapı.
- **Ağ Keşfi (ARP Scanner)** — Ağdaki cihazları dinamik olarak bulur. Detaylı MAC Vendor sınıflandırması (Cisco, Apple, Akıllı Ev Aletleri, Kameralar vb.) ve rastgele MAC tespiti yapar.
- **Gelişmiş Log Analizi** — `journalctl`, `dmesg`, `httpd` ve `mariadb` loglarını sürekli izleyerek SSH brute-force, web dizin taramaları, IP flood, kernel oom/segfault hatalarını tespit eder.
- **Canlı Trafik (PCAP)** — `libpcap` tabanlı canlı ağ trafiği izleme, şüpheli ağ akışlarının gerçek zamanlı tespiti.
- **Otonom Port Tarayıcı (AutoPort)** — Nmap'ten tamamen bağımsız, çok kanallı (thread pool) çalışan; TCP Connect, SYN, FIN, NULL, Xmas ve UDP tarama özellikli gelişmiş port/servis analizi ve TTL tabanlı OS tahmini.
- **Brute Force Motoru** — FTP, HTTP, MySQL ve Telnet servisleri için çoklu-iş parçacığı (multi-thread) destekli otonom kaba kuvvet (brute-force) zaafiyet testi.

## 🛠️ Gereksinimler

### Linux
- CMake 3.16+
- GCC veya Clang
- `libpcap` geliştirme paketleri (`sudo apt install libpcap-dev`)
- Raylib bağımlılıkları (X11, Wayland, OpenGL)

### Windows
- CMake 3.16+
- MinGW-w64 (GCC) veya MSVC (Visual Studio Build Tools)
- *(Raylib, Windows üzerinde CMake ile projeyi yapılandırırken internet üzerinden otomatik olarak indirilip derlenir)*

## 🚀 Kurulum ve Derleme

```bash
# Repoyu klonladıktan veya dizine girdikten sonra:
mkdir build
cd build

# Projeyi yapılandır
cmake .. -DCMAKE_BUILD_TYPE=Release

# Derle (Çoklu çekirdek desteği ile cross-platform komut)
cmake --build . --config Release -j 4
```
*(Windows ve Linux'ta yukarıdaki komutlarla derleme yapabilirsiniz.)*

## 🏁 Çalıştırma

### Linux
Bazı gelişmiş tarama türleri (örn. SYN Scan) ve libpcap ile canlı trafik izleme özellikleri root yetkisi gerektirir.
```bash
sudo ./guvenlik_merkezi
```

### Windows
Ağ tarama işlemlerinin doğru çalışması için uygulamanın **Yönetici Olarak (Run as Administrator)** çalıştırılması tavsiye edilir.
```cmd
.\Release\guvenlik_merkezi.exe
# veya (kullandığınız derleyiciye göre dizin değişebilir)
.\guvenlik_merkezi.exe
```
