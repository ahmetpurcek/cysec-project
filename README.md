# Siber Güvenlik Merkezi

> Raylib tabanlı, tek pencereden ağ keşfi, port taraması, canlı trafik izleme ve saldırı tespiti (IDS) sunan C11 güvenlik aracı.  
> **Sadece Linux üzerinde çalışır.** (Arch, BlackArch, Kali, Parrot, Ubuntu/Debian, Fedora)

---

## 📋 Özellikler

| Modül | Açıklama |
|---|---|
| **Modern GUI** | Raylib + Raygui ile geliştirilmiş, çözünürlükten bağımsız ölçeklenen arayüz |
| **Ağ Keşfi (ARP Scanner)** | Raw ARP soketleri ile sweep, `/proc/net/arp` ve `ip neigh` ile cihaz tespiti |
| **Ağdan Kesme (ARP Black-Hole)** | Raw `AF_PACKET` soketleri ile hedef cihaza sürekli sahte ARP yanıtı göndererek internet erişimini keser/geri verir |
| **Otonom Port Tarayıcı (AutoPort)** | Nmap bağımsız, çok kanallı (thread pool) TCP/raw port ve servis analizi; TTL tabanlı OS tahmini |
| **Canlı Trafik İzleme** | `libpcap` ile gerçek zamanlı paket yakalama ve L3/L4 ayrıştırma |
| **Ağ IDS** | 20 kural: ARP spoofing, MITM, sahte TCP bayrakları, yatay/dikey port taraması, SSH brute-force, SQLi/XSS/JNDI/Meterpreter imzaları |
| **Display Filtre Motoru** | Wireshark tarzı filtre ifadeleri (`ip.addr == 10.0.0.5 && tcp.port == 443`) — 138 birim testle doğrulanmış |

---

## 🖥️ Sistem Gereksinimleri

- **İşletim Sistemi:** Linux (kernel 5.4+)
- **Mimari:** x86\_64
- **Root yetkisi:** Bazı tarama modları ve libpcap yakalama için zorunlu
- **Ekran:** OpenGL 2.1+ destekli GPU / X11 veya Wayland oturumu

### Yazılım Gereksinimleri

| Bileşen | Minimum Sürüm |
|---|---|
| GCC veya Clang | GCC 9+ / Clang 10+ |
| CMake | 3.16+ |
| pkg-config | Herhangi |
| raylib | 4.5+ |
| libpcap | 1.9+ |
| OpenGL geliştirme başlıkları | — |
| X11 geliştirme başlıkları | — |

---

## 📦 Dağıtıma Göre Bağımlılık Kurulumu

> ⚠️ **Önemli:** `raylib` paket adı ve sürümü dağıtımlar arasında önemli farklılıklar gösterebilir.  
> Hangi dağıtımı kullandığınızı aşağıdan bulun ve sırasıyla uygulayın.

---

### 🔷 Arch Linux / BlackArch / Manjaro

BlackArch ve Arch aynı `pacman` paket yöneticisini kullanır.

```bash
# 1. Paket listesini güncelle
sudo pacman -Syu

# 2. Derleme araçları + bağımlılıklar
sudo pacman -S --needed \
    base-devel \
    cmake \
    pkgconf \
    raylib \
    libpcap \
    mesa \
    libx11 \
    libxrandr \
    libxinerama \
    libxcursor \
    libxi \
    glfw-x11
```

> 💡 Wayland kullanıyorsanız `glfw-x11` yerine `glfw-wayland` kurun:
> ```bash
> sudo pacman -S glfw-wayland
> ```

---

### 🔷 Kali Linux / Parrot OS (Debian tabanlı)

```bash
# 1. Paket listesini güncelle
sudo apt update && sudo apt upgrade -y

# 2. Derleme araçları
sudo apt install -y \
    build-essential \
    cmake \
    pkg-config \
    git

# 3. libpcap
sudo apt install -y libpcap-dev

# 4. OpenGL ve X11 başlıkları (Raylib için zorunlu)
sudo apt install -y \
    libgl1-mesa-dev \
    libgles2-mesa-dev \
    libx11-dev \
    libxrandr-dev \
    libxinerama-dev \
    libxcursor-dev \
    libxi-dev \
    libxext-dev \
    libwayland-dev \
    libxkbcommon-dev

# 5. Raylib
#    Kali/Parrot depolarında raylib olmayabilir. Önce deneyin:
sudo apt install -y libraylib-dev 2>/dev/null || \
    echo "libraylib-dev bulunamadı — aşağıdaki 'Raylib Kaynak Koddan Derleme' bölümüne geçin"
```

---

### 🔷 Ubuntu 22.04 / 24.04 / Linux Mint

```bash
sudo apt update && sudo apt upgrade -y

sudo apt install -y \
    build-essential \
    cmake \
    pkg-config \
    libpcap-dev \
    libgl1-mesa-dev \
    libgles2-mesa-dev \
    libx11-dev \
    libxrandr-dev \
    libxinerama-dev \
    libxcursor-dev \
    libxi-dev \
    libxext-dev \
    libwayland-dev \
    libxkbcommon-dev

# Ubuntu 24.04+: raylib resmi depoda mevcut
sudo apt install -y libraylib-dev

# Ubuntu 22.04 / Linux Mint: raylib paketi yoksa kaynak koddan derleyin
# (Aşağıdaki bölüme bakın)
```

---

### 🔷 Fedora / RHEL / Rocky Linux

```bash
# 1. Güncelle
sudo dnf upgrade -y

# 2. Geliştirme araçları grubu
sudo dnf groupinstall -y "Development Tools"

# 3. Bağımlılıklar
sudo dnf install -y \
    cmake \
    pkgconf-pkg-config \
    libpcap-devel \
    mesa-libGL-devel \
    mesa-libGLES-devel \
    libX11-devel \
    libXrandr-devel \
    libXinerama-devel \
    libXcursor-devel \
    libXi-devel \
    libXext-devel \
    wayland-devel \
    libxkbcommon-devel

# 4. Raylib Fedora depolarında bulunmaz → kaynak koddan derleme gerekir
# (Aşağıdaki bölüme bakın)
```

---

### 🔧 Raylib Kaynak Koddan Derleme (Evrensel Yöntem)

Paket deposunda raylib yoksa veya sürüm çok eskiyse bu yöntemi kullanın.  
**Her dağıtımda çalışır.**

```bash
# 1. Kaynak kodu indir
git clone --depth 1 --branch 5.0 https://github.com/raysan5/raylib.git /tmp/raylib-src
cd /tmp/raylib-src

# 2. Derle ve sisteme kur
mkdir build && cd build
cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=ON \
    -DWITH_PIC=ON
make -j$(nproc)
sudo make install

# 3. Kütüphane önbelleğini güncelle
sudo ldconfig

# 4. Kurulumu doğrula
pkg-config --modversion raylib
# Beklenen çıktı: 5.0.0
```

> Eğer `pkg-config` raylib'i hâlâ bulamazsa:
> ```bash
> export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH
> # Kalıcı yapmak için:
> echo 'export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH' >> ~/.bashrc
> source ~/.bashrc
> ```

---

## 🚀 Derleme

Tüm bağımlılıklar kurulduktan sonra proje kökünden:

```bash
# 1. Build dizinini oluştur ve yapılandır
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release

# 2. Derle (tüm CPU çekirdeklerini kullan)
cmake --build build -j$(nproc)
```

Başarılı derleme çıktısı:
```
[100%] Linking C executable guvenlik_merkezi
[100%] Built target guvenlik_merkezi
```

Çalıştırılabilir dosya: `build/guvenlik_merkezi`

---

## 🏁 Çalıştırma

### Normal mod

```bash
./build/guvenlik_merkezi
```

### Root modu — tam özellik seti (önerilen)

SYN/FIN/Xmas raw taramaları, ARP black-hole ve libpcap yakalama **root yetkisi gerektirir**.

```bash
# X11 display iznini ver (sudo ile GUI açmak için zorunlu)
xhost +local:root

# Root olarak çalıştır
sudo ./build/guvenlik_merkezi

# İşlem bitince izni geri al (güvenlik)
xhost -local:root
```

### Wayland oturumunda root modu

```bash
# Oturum tipini kontrol et
echo $XDG_SESSION_TYPE   # "wayland" çıktısı veriyorsa:

sudo WAYLAND_DISPLAY=$WAYLAND_DISPLAY \
     XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR \
     ./build/guvenlik_merkezi
```

---

## 🧪 Testler

### Display Filtre Motoru Birim Testi (138 test)

```bash
gcc -std=c11 -D_GNU_SOURCE \
    -Iinclude \
    tests/filter_engine_test.c \
    src/filter_engine.c \
    src/utils.c \
    -o /tmp/fetest && /tmp/fetest
```

### LAN Akış Testi

```bash
gcc -std=c11 -D_GNU_SOURCE \
    -Iinclude \
    tests/lan_flow_test.c \
    src/filter_engine.c \
    src/utils.c \
    -o /tmp/lantest && /tmp/lantest
```

### Monitor/Ayrıştırma Testi

```bash
gcc -std=c11 -D_GNU_SOURCE \
    -Iinclude \
    tests/monitor_dissect_test.c \
    src/filter_engine.c \
    src/utils.c \
    -o /tmp/montest && /tmp/montest
```

---

## 🛠️ Sık Karşılaşılan Hatalar ve Çözümleri

### ❌ `Could not find raylib` (CMake hatası)

```
-- Could NOT find raylib (missing: RAYLIB_LIBRARIES)
```

**Çözüm:**
```bash
pkg-config --modversion raylib          # sürümü kontrol et
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH
sudo ldconfig
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release   # tekrar dene
```

---

### ❌ `pcap.h: No such file or directory`

| Dağıtım | Komut |
|---|---|
| Arch/BlackArch | `sudo pacman -S libpcap` |
| Debian/Kali/Ubuntu | `sudo apt install libpcap-dev` |
| Fedora | `sudo dnf install libpcap-devel` |

---

### ❌ `GL/gl.h: No such file or directory`

| Dağıtım | Komut |
|---|---|
| Arch/BlackArch | `sudo pacman -S mesa` |
| Debian/Kali/Ubuntu | `sudo apt install libgl1-mesa-dev libgles2-mesa-dev` |
| Fedora | `sudo dnf install mesa-libGL-devel` |

---

### ❌ `X11/Xlib.h: No such file or directory`

| Dağıtım | Komut |
|---|---|
| Arch/BlackArch | `sudo pacman -S libx11 libxrandr libxinerama libxcursor libxi` |
| Debian/Kali/Ubuntu | `sudo apt install libx11-dev libxrandr-dev libxinerama-dev libxcursor-dev libxi-dev` |
| Fedora | `sudo dnf install libX11-devel libXrandr-devel libXinerama-devel libXcursor-devel libXi-devel` |

---

### ❌ GUI açılmıyor / `cannot open display`

```bash
xhost +local:root
sudo ./build/guvenlik_merkezi
```

---

### ❌ `error while loading shared libraries: libraylib.so`

```bash
sudo ldconfig
# Hâlâ hata alıyorsanız:
echo "/usr/local/lib" | sudo tee /etc/ld.so.conf.d/raylib.conf
sudo ldconfig
```

---

### ❌ CMake sürümü çok eski (3.16 altı)

```bash
# Arch
sudo pacman -S cmake

# Debian/Kali/Ubuntu — Kitware resmi deposu
wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc | sudo apt-key add -
sudo apt-add-repository 'deb https://apt.kitware.com/ubuntu/ focal main'
sudo apt install cmake

# pip ile (herhangi bir dağıtım)
pip3 install cmake --user
export PATH="$HOME/.local/bin:$PATH"
```

---

## 📁 Proje Yapısı

```
cysec-project/
├── CMakeLists.txt              # Bağımlılıklar ve derleme yapılandırması
├── README.md                   # Bu dosya
├── include/                    # Başlık dosyaları
│   ├── platform.h              # Platform soyutlaması (thread, iface shims)
│   ├── arp_scanner.h           # Ağ keşfi arayüzü
│   ├── arp_block.h             # ARP black-hole motoru arayüzü
│   ├── port_scanner.h          # Port tarayıcı arayüzü
│   ├── network_monitor.h       # PCAP izleme arayüzü
│   ├── network_ids.h           # IDS kural motoru arayüzü
│   ├── filter_engine.h         # Display filtre ayrıştırıcı arayüzü
│   ├── gui.h                   # GUI modülü arayüzü
│   └── utils.h                 # Yardımcı araçlar (hashmap, str, log)
├── lib/
│   └── raygui.h                # Raygui (header-only, tek dosya)
├── src/
│   ├── main.c                  # Giriş noktası
│   ├── platform.c              # Thread ve platform soyutlaması
│   ├── utils.c                 # Yardımcılar
│   ├── arp_scanner.c           # Ağ keşfi (raw ARP / /proc/net/arp)
│   ├── arp_block.c             # ARP black-hole motoru (AF_PACKET raw)
│   ├── port_scanner.c          # Port tarama (TCP connect + raw soket)
│   ├── network_monitor.c       # libpcap canlı yakalama ve ayrıştırma
│   ├── network_ids.c           # IDS kuralları ve alert motoru
│   ├── filter_engine.c         # Display filtre ayrıştırıcı
│   └── gui.c                   # Raylib/Raygui grafik arayüzü
├── assets/fonts/               # GUI yazı tipleri
├── tests/
│   ├── filter_engine_test.c    # Display filtre birim testleri (138 test)
│   ├── lan_flow_test.c         # LAN akış testleri
│   └── monitor_dissect_test.c  # Paket ayrıştırma testleri
└── build/                      # Derleme çıktısı (.gitignore'da)
```

---

## ⚠️ Yasal Uyarı

Bu araç **yalnızca eğitim ve yetkili güvenlik testleri** amacıyla geliştirilmiştir.  
Sahip olmadığınız veya test etme izniniz bulunmayan ağ ve sistemlere karşı kullanmak yasaldır.  
Kullanım sorumluluğu tamamen kullanıcıya aittir.


