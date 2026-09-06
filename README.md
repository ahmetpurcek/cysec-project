# Siber Güvenlik Merkezi (AkilliSehirGuvenlik)

Raylib tabanlı, tek pencereden ağ keşfi, port taraması, canlı trafik izleme ve saldırı tespiti (IDS) sunan C11 güvenlik aracı. Hem **Linux** hem de **Windows** üzerinde çalışır.

## 📋 Özellikler

- **Modern GUI** — Raylib + Raygui ile geliştirilmiş, çözünürlükten bağımsız ölçeklenen arayüz.
- **Ağ Keşfi (ARP Scanner)** — Ağdaki cihazları tarar ve sınıflandırır.
  - Linux: raw ARP soketleri ile sweep
  - Windows: native ICMP ping sweep (IcmpSendEcho) + `GetIpNetTable` ile ARP tablosu okuma
- **Otonom Port Tarayıcı (AutoPort)** — Nmap bağımsız, çok kanallı (thread pool) port/servis analizi; TTL tabanlı OS tahmini.
  - Tüm platformlar: TCP Connect taraması
  - Yalnızca Linux (root): SYN, FIN, NULL, Xmas, ACK, Window, Maimon raw taramaları
  - Windows'ta raw/stealth türleri otomatik TCP Connect'e düşer (tek seferlik uyarı verir)
- **Canlı Trafik İzleme (PCAP)** — libpcap (Linux) / Npcap (Windows) ile gerçek zamanlı paket yakalama.
- **Ağ IDS** — Yakalanan trafik üzerinde 20 kural çalıştırır: ARP spoofing, IP-MAC bağlama değişimi, ARP MITM, sahte TCP bayrak kombinasyonları, yatay/dikey port taraması, SSH brute-force denemesi, L7 payload imzaları (SQLi, XSS, JNDI, PowerShell, NOP-sled, Meterpreter vb.). 60 sn cooldown ile uyarı üretir.
- **Display Filtre Motoru** — Wireshark tarzı filtre ifadeleri (`ip.addr == 10.0.0.5 && tcp.port == 443` gibi) ile paket listesi filtreleme; 138 birim testle doğrulanmış ayrıştırıcı.

## 🛠️ Gereksinimler

### Linux
- CMake 3.16+, GCC veya Clang
- `libpcap-dev` (canlı trafik + IDS için)
- Raylib bağımlılıkları (X11/Wayland, OpenGL) — dağıtım paketinden `raylib` kurun

### Windows
- CMake 3.16+
- Derleyici: **MinGW-w64 (GCC)** veya **MSVC (Visual Studio 2019/2022 Build Tools)**
- *(Raylib, CMake yapılandırması sırasında internetten otomatik indirilip derlenir)*
- **Npcap (çalışma zamanı)** — canlı trafik izleme ve IDS için: https://npcap.com/#download
  - Kurulum sırasında **"WinPcap API-compatible Mode"** seçili kalmalı.
- **Npcap SDK** — canlı trafik desteğiyle derlemek için: https://npcap.com/#download

> SDK'sız da derleme **başarılı olur**; bu durumda GUI, ARP taraması ve port taraması çalışır, yalnızca canlı trafik izleme ve IDS kapalı (stub) gelir.

## 🚀 Kurulum ve Derleme

### Linux
```bash
cmake -S . -B build-linux -DCMAKE_BUILD_TYPE=Release
cmake --build build-linux -j4
./build-linux/guvenlik_merkezi
```

> Derleme çıktıları platforma göre ayrı klasörlerde tutulur: **`build-linux/`** (Linux) ve **`build-win/`** (Windows). Her ikisi de `.gitignore`'dadır, git'e girmez.

### Windows

**1) Npcap SDK'yı hazırlayın** (canlı trafik + IDS istiyorsanız):
```bat
:: SDK'yı zip'ten çıkardıktan sonra ortam değişkeni verin (örnek yol):
setx NPCAP_SDK "C:\npcap-sdk-1.15"
:: alternatif: SDK'yı C:\Program Files\Npcap altına kurarsanız otomatik bulunur
:: yeni bir terminal açın (setx kalıcıdır, mevcut oturuma etki etmez)
```

**2) Derleyin** — MinGW için (PowerShell veya cmd):
```bat
cmake -S . -B build-win -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build build-win -j4
```
MSVC için "x64 Native Tools Command Prompt for VS 2022" açın:
```bat
cmake -S . -B build-win -DCMAKE_BUILD_TYPE=Release
cmake --build build-win --config Release -j4
```

**3) Çalıştırın:**
```bat
.\build-win\guvenlik_merkezi.exe
```

CMake, Npcap SDK'yı sırayla şuralarda arar: `NPCAP_SDK` ortam değişkeni → `C:\Program Files\Npcap` → `C:\Program Files (x86)\Npcap`. Bulamazsa `WARNING` basar ve **stub modda** derler (uygulama açılır, canlı trafik/IDS paneli devre dışı olur).

## 🏁 Çalıştırma Notları

### Linux
SYN gibi raw tarama türleri ve libpcap yakalaması root ister:
```bash
xhost +
sudo ./build-linux/guvenlik_merkezi
```

### Windows
- Ağ taramalarının (ICMP sweep, port taraması, paket yakalama) doğru çalışması için uygulamayı **Yönetici Olarak Çalıştırın**.
- Canlı trafik + IDS için **Npcap** kurulu olmalı (WinPcap API-compatible Mode). SDK yalnızca derleme sırasında gerekir.
- Stealth tarama türleri (SYN/FIN/NULL/Xmas/ACK/Window/Maimon) Windows'ta desteklenmez; seçildiğinde **TCP Connect** taramasına otomatik düşer ve arayüzde uyarı görürsünüz.
- ARP taraması Windows'ta native ICMP ping sweep + `GetIpNetTable` ile çalışır; harici `ping`/`arp` komutlarına bağımlı değildir.

### Sorun Giderme (Windows)
| Belirti | Sebep | Çözüm |
|---|---|---|
| CMake'te `Npcap SDK bulunamadı` uyarısı | SDK yolu tanımsız | `NPCAP_SDK` ortam değişkenini ayarlayıp CMake cache'ini silip yeniden yapılandırın |
| `wpcap.dll bulunamadı` | Npcap runtime yok | npcap.com'dan Npcap installer'ı kurun (WinPcap API mode) |
| Canlı trafik paneli boş / cihaz listesi yok | Yönetici yetkisi yok | Exe'yi sağ tık → "Yönetici olarak çalıştır" |
| Ping sweep sonucu eksik | Hedef güvenlik duvarı ICMP'yi engelliyor | Hedefte ICMP echo'ya izin verin (davranışsal kısıt, hata değil) |

## 🧪 Testler

```bash
# Display filtre motoru regresyon testi (Linux)
gcc -std=c11 -D_GNU_SOURCE -Iinclude tests/filter_engine_test.c src/filter_engine.c src/utils.c -o fetest && ./fetest
```

## 📁 Proje Yapısı

```
├── CMakeLists.txt          # Npcap SDK keşfi + platform bayrakları
├── include/                # Başlıklar (platform soyutlaması: platform.h)
├── lib/raygui.h            # Raygui (tek dosya)
├── src/
│   ├── main.c              # Giriş noktası
│   ├── gui.c               # Raylib/raygui arayüzü
│   ├── platform.c/h        # Platform soyutlaması (thread, iface, GUID, shims)
│   ├── arp_scanner.c       # Ağ keşfi (raw ARP / ICMP+GetIpNetTable)
│   ├── port_scanner.c      # Port tarama motoru
│   ├── network_monitor.c   # libpcap/Npcap canlı yakalama
│   ├── network_ids.c       # IDS kuralları ve alert motoru
│   ├── filter_engine.c     # Display filtre ayrıştırıcı
│   └── utils.c             # Yardımcılar (hashmap, str, log)
└── tests/                  # Birim/regresyon testleri
```



