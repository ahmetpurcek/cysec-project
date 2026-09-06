cmake_minimum_required(VERSION 3.16)
project(AkilliSehirGuvenlik C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Kaynak dosyaları
set(SOURCES
    src/main.c
    src/platform.c
    src/utils.c
    src/arp_scanner.c
    src/network_monitor.c
    src/network_ids.c
    src/port_scanner.c
    src/gui.c
    src/filter_engine.c
)

# Header dizinleri
include_directories(include)
include_directories(lib)

# Hedef
add_executable(guvenlik_merkezi ${SOURCES})

# Platform bağımlılıkları
if(UNIX AND NOT APPLE)
    # Linux
    find_package(PkgConfig REQUIRED)
    
    # raylib
    pkg_check_modules(RAYLIB REQUIRED raylib)
    target_include_directories(guvenlik_merkezi PRIVATE ${RAYLIB_INCLUDE_DIRS})
    target_link_directories(guvenlik_merkezi PRIVATE ${RAYLIB_LIBRARY_DIRS})
    
    target_link_libraries(guvenlik_merkezi
        ${RAYLIB_LIBRARIES}
        m           # math
        pthread     # threads
        dl          # dynamic loading
        pcap        # packet capture
    )
    
    # OpenGL ve X11 bağımlılıkları (raylib için)
    find_package(OpenGL)
    if(OPENGL_FOUND)
        target_link_libraries(guvenlik_merkezi ${OPENGL_LIBRARIES})
    endif()
    
elseif(WIN32)
    # Windows — raylib'i otomatik indir ve derle
    include(FetchContent)
    FetchContent_Declare(
        raylib
        URL https://github.com/raysan5/raylib/archive/refs/tags/5.5.zip
    )
    set(BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
    set(BUILD_GAMES OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(raylib)

    target_link_libraries(guvenlik_merkezi
        raylib
        ws2_32      # Winsock
        iphlpapi    # IP Helper (GetAdaptersAddresses, GetIpNetTable, IcmpSendEcho)
        winmm       # Multimedia (raylib)
        opengl32    # OpenGL
        gdi32       # GDI
    )

    # --- Npcap SDK bul (canli paket izleme + IDS icin) ---
    # once NPCAP_SDK ortam degiskeni, sonra standart kurulum dizinleri denenir.
    # SDK bulunamazsa HAVE_NPCAP tanimsiz derlenir: proje stub pcap ile calisir
    # (GUI, ARP tarama ve port tarama acik; canli trafik izleme/IDS kapali).
    set(NPCAP_SDK_PATH "")
    if(DEFINED ENV{NPCAP_SDK} AND EXISTS "$ENV{NPCAP_SDK}")
        set(NPCAP_SDK_PATH "$ENV{NPCAP_SDK}")
    else()
        foreach(_npcap_dir
            "C:/Program Files/Npcap"
            "C:/Program Files (x86)/Npcap"
        )
            if(EXISTS "${_npcap_dir}/Lib/x64/wpcap.lib")
                set(NPCAP_SDK_PATH "${_npcap_dir}")
                break()
            endif()
        endforeach()
    endif()

    if(NPCAP_SDK_PATH)
        message(STATUS "Npcap SDK bulundu: ${NPCAP_SDK_PATH}")
        target_compile_definitions(guvenlik_merkezi PRIVATE HAVE_NPCAP)
        target_include_directories(guvenlik_merkezi PRIVATE "${NPCAP_SDK_PATH}/Include")
        target_link_directories(guvenlik_merkezi PRIVATE "${NPCAP_SDK_PATH}/Lib/x64")
        target_link_libraries(guvenlik_merkezi wpcap Packet)
    else()
        message(WARNING
            "Npcap SDK bulunamadi (NPCAP_SDK ortam degiskeni veya C:/Program Files/Npcap).\n"
            "Canli paket izleme / IDS ozellikleri kapali (stub pcap) derlenecek.\n"
            "SDK indirme: https://npcap.com/#download  ->  NPCAP_SDK ortam degiskenini SDK dizinine ayarlayin."
        )
    endif()
endif()

# Derleme bayrakları
if(MSVC)
    target_compile_options(guvenlik_merkezi PRIVATE /W4)
else()
    target_compile_options(guvenlik_merkezi PRIVATE
        -Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers
    )
endif()
message(STATUS "Platform: ${CMAKE_SYSTEM_NAME}")
message(STATUS "Derleyici: ${CMAKE_C_COMPILER}")




