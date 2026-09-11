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
    src/arp_block.c
    src/port_scanner.c
    src/gui.c
    src/filter_engine.c
)

# Header dizinleri
include_directories(include)
include_directories(lib)

# Hedef
add_executable(guvenlik_merkezi ${SOURCES})

# Linux bağımlılıkları
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

# Derleme bayrakları
target_compile_options(guvenlik_merkezi PRIVATE
    -Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers
)

message(STATUS "Platform: ${CMAKE_SYSTEM_NAME}")
message(STATUS "Derleyici: ${CMAKE_C_COMPILER}")
