cmake_minimum_required(VERSION 3.18)
project(koe-core VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# ---------------------------------------------------------------------------
# Compiler flags
# ---------------------------------------------------------------------------

add_compile_options(
    -Wall
    -Wextra
    -Wpedantic
    -Wshadow
    -Wconversion
    -Wstrict-prototypes
    -fstack-protector-strong
    -D_FORTIFY_SOURCE=2
)

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_compile_options(-O2 -DNDEBUG)
else()
    add_compile_options(-O0 -g -fsanitize=address,undefined)
    add_link_options(-fsanitize=address,undefined)
endif()

# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------

# libsodium — required
find_library(SODIUM_LIB sodium REQUIRED)
find_path(SODIUM_INCLUDE sodium.h PATH_SUFFIXES sodium)

# libopus — required for voice calls
find_library(OPUS_LIB opus REQUIRED)
find_path(OPUS_INCLUDE opus/opus.h)

# ---------------------------------------------------------------------------
# Library target
# ---------------------------------------------------------------------------

add_library(koe-core STATIC
    src/koe_core.c
    src/koe_crypto.c
    src/koe_identity.c
    src/koe_handshake.c
    src/koe_packet.c
    src/koe_message.c
    src/koe_queue.c
    src/koe_transport.c
    src/koe_audio.c
    src/koe_backup.c
    src/koe_channel.c
    src/koe_revoke.c
    src/koe_ghost.c
    src/koe_store.c
    src/koe_event.c
)

target_include_directories(koe-core
    PUBLIC  include
    PRIVATE ${SODIUM_INCLUDE}
            ${OPUS_INCLUDE}
)

target_link_libraries(koe-core
    PUBLIC  ${SODIUM_LIB}
            ${OPUS_LIB}
)

# ---------------------------------------------------------------------------
# Install rules (for use as a dependency by koe-chat and koe-server)
# ---------------------------------------------------------------------------

install(TARGETS koe-core ARCHIVE DESTINATION lib)
install(DIRECTORY include/ DESTINATION include/koe)
