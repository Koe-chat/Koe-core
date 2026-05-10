cmake_minimum_required(VERSION 3.18)
project(koe-core VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# --------------------------------------------------------------------------
# Compiler options
# --------------------------------------------------------------------------

add_compile_options(
    -Wall -Wextra -Wpedantic
    -Wstrict-aliasing=2
    -fstack-protector-strong
    -fno-strict-aliasing
)

# Termux/Android: no PIE flag needed (linker handles it).
if(NOT ANDROID)
    add_compile_options(-fPIC)
endif()

# --------------------------------------------------------------------------
# Optional feature flags
# --------------------------------------------------------------------------

option(KOE_NO_MRUBY "Disable mruby plugin system" OFF)
option(KOE_NO_CURL  "Disable libcurl (disables Matrix and server backup)" OFF)
option(KOE_ASAN     "Enable AddressSanitizer + UBSan (Debug only)" OFF)
option(KOE_BUILD_TESTS "Build unit tests" ON)
option(KOE_BUILD_EXAMPLES "Build examples" OFF)

if(KOE_NO_MRUBY)
    add_compile_definitions(KOE_NO_MRUBY)
endif()

if(KOE_NO_CURL)
    add_compile_definitions(KOE_NO_CURL)
endif()

# --------------------------------------------------------------------------
# Build configurations
# --------------------------------------------------------------------------

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_compile_options(-O2)
elseif(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_options(-O0 -g)
    if(KOE_ASAN)
        add_compile_options(-fsanitize=address,undefined)
        add_link_options(-fsanitize=address,undefined)
    endif()
endif()

# --------------------------------------------------------------------------
# Find required libraries
# --------------------------------------------------------------------------

# libsodium
find_library(SODIUM_LIB sodium REQUIRED)
find_path(SODIUM_INCLUDE sodium.h PATH_SUFFIXES sodium)
if(NOT SODIUM_LIB OR NOT SODIUM_INCLUDE)
    message(FATAL_ERROR
        "libsodium not found.\n"
        "  Termux: pkg install libsodium-dev\n"
        "  Debian:  apt install libsodium-dev\n"
        "  Arch:    pacman -S libsodium")
endif()

# libopus
find_library(OPUS_LIB opus REQUIRED)
find_path(OPUS_INCLUDE opus/opus.h)
if(NOT OPUS_LIB OR NOT OPUS_INCLUDE)
    message(FATAL_ERROR
        "libopus not found.\n"
        "  Termux: pkg install opus-dev\n"
        "  Debian:  apt install libopus-dev\n"
        "  Arch:    pacman -S opus")
endif()

# SQLite3
find_library(SQLITE3_LIB sqlite3 REQUIRED)
find_path(SQLITE3_INCLUDE sqlite3.h)
if(NOT SQLITE3_LIB OR NOT SQLITE3_INCLUDE)
    message(FATAL_ERROR
        "libsqlite3 not found.\n"
        "  Termux: pkg install sqlite-dev\n"
        "  Debian:  apt install libsqlite3-dev")
endif()

# libcurl (optional)
if(NOT KOE_NO_CURL)
    find_library(CURL_LIB curl)
    find_path(CURL_INCLUDE curl/curl.h)
    if(NOT CURL_LIB)
        message(WARNING
            "libcurl not found — Matrix and server backup disabled.\n"
            "  Termux: pkg install libcurl-dev\n"
            "  Debian:  apt install libcurl4-openssl-dev\n"
            "  Or reconfigure with -DKOE_NO_CURL=ON to suppress this warning.")
        set(KOE_NO_CURL ON)
        add_compile_definitions(KOE_NO_CURL)
    endif()
endif()

# mruby (optional)
if(NOT KOE_NO_MRUBY)
    find_library(MRUBY_LIB mruby)
    find_path(MRUBY_INCLUDE mruby.h)
    if(NOT MRUBY_LIB)
        message(WARNING
            "mruby not found — plugin system disabled.\n"
            "  Termux: pkg install mruby-dev\n"
            "  Or build mruby from source: https://github.com/mruby/mruby\n"
            "  Or reconfigure with -DKOE_NO_MRUBY=ON to suppress this warning.")
        set(KOE_NO_MRUBY ON)
        add_compile_definitions(KOE_NO_MRUBY)
    endif()
endif()

# --------------------------------------------------------------------------
# Library source files
# --------------------------------------------------------------------------

set(KOE_SOURCES
    src/koe_version.c
    src/koe_packet.c
    src/koe_crypto.c
    src/koe_identity.c
    src/koe_account.c
    src/koe_handshake.c
    src/koe_transport.c
    src/koe_presence.c
    src/koe_session.c
    src/koe_message.c
    src/koe_queue.c
    src/koe_audio.c
    src/koe_media.c
    src/koe_matrix.c
    src/koe_channel.c
    src/koe_ghost.c
    src/koe_revoke.c
    src/koe_store.c
    src/koe_db.c
    src/koe_plugin.c
    src/koe_event.c
    src/koe_backup.c
    src/koe_core.c
)

# --------------------------------------------------------------------------
# Static library target
# --------------------------------------------------------------------------

add_library(koe-core STATIC ${KOE_SOURCES})

target_include_directories(koe-core PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include/koe>
    ${SODIUM_INCLUDE}
    ${OPUS_INCLUDE}
    ${SQLITE3_INCLUDE}
)

if(NOT KOE_NO_CURL AND CURL_INCLUDE)
    target_include_directories(koe-core PRIVATE ${CURL_INCLUDE})
endif()

if(NOT KOE_NO_MRUBY AND MRUBY_INCLUDE)
    target_include_directories(koe-core PRIVATE ${MRUBY_INCLUDE})
endif()

# --------------------------------------------------------------------------
# Shared library target (for Go cgo and Swift)
# --------------------------------------------------------------------------

add_library(koe-core-shared SHARED ${KOE_SOURCES})

target_include_directories(koe-core-shared PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include/koe>
    ${SODIUM_INCLUDE}
    ${OPUS_INCLUDE}
    ${SQLITE3_INCLUDE}
)

set_target_properties(koe-core-shared PROPERTIES
    OUTPUT_NAME koe-core
    SOVERSION 0
    VERSION 0.1.0
)

# --------------------------------------------------------------------------
# Link libraries
# --------------------------------------------------------------------------

set(KOE_LINK_LIBS ${SODIUM_LIB} ${OPUS_LIB} ${SQLITE3_LIB})

if(NOT KOE_NO_CURL AND CURL_LIB)
    list(APPEND KOE_LINK_LIBS ${CURL_LIB})
endif()

if(NOT KOE_NO_MRUBY AND MRUBY_LIB)
    list(APPEND KOE_LINK_LIBS ${MRUBY_LIB})
endif()

target_link_libraries(koe-core         PUBLIC ${KOE_LINK_LIBS})
target_link_libraries(koe-core-shared  PUBLIC ${KOE_LINK_LIBS})

# --------------------------------------------------------------------------
# Unit tests
# --------------------------------------------------------------------------

if(KOE_BUILD_TESTS)
    enable_testing()
    add_executable(koe-test tests/test_koe_core.c)
    target_link_libraries(koe-test koe-core)
    target_include_directories(koe-test PRIVATE include ${SODIUM_INCLUDE})
    add_test(NAME koe-core-tests COMMAND koe-test)
endif()

# --------------------------------------------------------------------------
# Install rules
# --------------------------------------------------------------------------

install(TARGETS koe-core koe-core-shared
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
)

install(DIRECTORY include/
    DESTINATION include/koe
    FILES_MATCHING PATTERN "*.h"
)

# --------------------------------------------------------------------------
# Summary
# --------------------------------------------------------------------------

message(STATUS "")
message(STATUS "koe-core ${PROJECT_VERSION} configuration:")
message(STATUS "  Build type:  ${CMAKE_BUILD_TYPE}")
message(STATUS "  libsodium:   ${SODIUM_LIB}")
message(STATUS "  libopus:     ${OPUS_LIB}")
message(STATUS "  sqlite3:     ${SQLITE3_LIB}")
message(STATUS "  libcurl:     ${KOE_NO_CURL} (disabled=${KOE_NO_CURL})")
message(STATUS "  mruby:       (disabled=${KOE_NO_MRUBY})")
message(STATUS "  Tests:       ${KOE_BUILD_TESTS}")
message(STATUS "")
