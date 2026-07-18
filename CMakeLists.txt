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
    src/log_analyzer.c
    src/network_monitor.c
    src/port_scanner.c
    src/brute_force.c
    src/gui.c
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
        pcap        # libpcap (ileride kullanılacak)
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
        iphlpapi    # IP Helper
        winmm       # Multimedia (raylib)
        opengl32    # OpenGL
        gdi32       # GDI
    )
endif()

# Derleme bayrakları
target_compile_options(guvenlik_merkezi PRIVATE
    -Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers
)

# mac-addresses.txt'yi build dizinine kopyala
if(EXISTS "${CMAKE_SOURCE_DIR}/mac-addresses.txt")
    configure_file("${CMAKE_SOURCE_DIR}/mac-addresses.txt" 
                   "${CMAKE_BINARY_DIR}/mac-addresses.txt" COPYONLY)
endif()

message(STATUS "Platform: ${CMAKE_SYSTEM_NAME}")
message(STATUS "Derleyici: ${CMAKE_C_COMPILER}")
