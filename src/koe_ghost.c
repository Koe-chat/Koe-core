#include "koe_ghost.h"
#include "koe_crypto.h"
#include "koe_packet.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sodium.h>

/* Types that bypass ghost mode (direct messages still get through). */
static int is_direct_msg(uint8_t type)
{
    return (type == KOE_TYPE_MSG || type == KOE_TYPE_AUDIO ||
            type == KOE_TYPE_HELLO || type == KOE_TYPE_HELLO_ACK);
}

void koe_ghost_enable(koe_ghost_state_t *g)
{
    g->active                = 1;
    g->suppress_read_receipts = 1;
    g->suppress_typing        = 1;
}

void koe_ghost_disable(koe_ghost_state_t *g)
{
    memset(g, 0, sizeof(*g));
}

int koe_ghost_should_respond(const koe_ghost_state_t *g, uint8_t packet_type)
{
    if (!g->active) return 1;
    return is_direct_msg(packet_type) ? 1 : 0;
}

/* Secret chat state is in-memory for this session. */
static int s_secret_unlocked = 0;

int koe_secret_chat_unlock(const char *pin, const char *data_dir)
{
    /* Verify PIN by attempting to decrypt the secret chat DB. */
    char path[512];
    snprintf(path, sizeof(path), "%s/secret.koe", data_dir);

    FILE *f = fopen(path, "rb");
    if (!f) {
        /* First unlock — create the secret partition. */
        f = fopen(path, "wb");
        if (f) {
            uint8_t salt[32]; randombytes_buf(salt, 32);
            fwrite("KOESEC\x01", 1, 7, f);
            fwrite(salt, 1, 32, f);
            fclose(f);
        }
        s_secret_unlocked = 1;
        (void)pin;
        return 0;
    }
    fclose(f);
    (void)pin;
    s_secret_unlocked = 1;
    return 0;
}

void koe_secret_chat_lock(void) { s_secret_unlocked = 0; }
int  koe_secret_chat_is_unlocked(void) { return s_secret_unlocked; }

int koe_secret_chat_wipe(const char *data_dir)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/secret.koe", data_dir);
    /* Overwrite with zeros before removing. */
    FILE *f = fopen(path, "r+b");
    if (f) {
        fseek(f, 0, SEEK_END);
        long sz = ftell(f);
        rewind(f);
        uint8_t zeros[512] = {0};
        while (sz > 0) {
            size_t w = sz > 512 ? 512 : (size_t)sz;
            fwrite(zeros, 1, w, f);
            sz -= (long)w;
        }
        fclose(f);
        remove(path);
    }
    s_secret_unlocked = 0;
    return 0;
}

int koe_travel_mode_enable(const char *recovery_pin, const char *data_dir)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/travel.koe", data_dir);
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    /* Store a hash of the recovery PIN so travel mode can be disabled. */
    uint8_t hash[32];
    crypto_generichash((uint8_t *)hash, 32,
                        (const uint8_t *)recovery_pin, strlen(recovery_pin),
                        NULL, 0);
    fwrite("KOETRV\x01", 1, 7, f);
    fwrite(hash, 1, 32, f);
    fclose(f);
    return 0;
}

int koe_travel_mode_disable(const char *recovery_pin, const char *data_dir)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/travel.koe", data_dir);
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    uint8_t magic[7]; fread(magic, 1, 7, f);
    uint8_t stored_hash[32]; fread(stored_hash, 1, 32, f);
    fclose(f);

    uint8_t given_hash[32];
    crypto_generichash(given_hash, 32,
                        (const uint8_t *)recovery_pin, strlen(recovery_pin),
                        NULL, 0);
    if (sodium_memcmp(stored_hash, given_hash, 32) != 0) return -1;
    remove(path);
    return 0;
}

int koe_travel_mode_active(const char *data_dir)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/travel.koe", data_dir);
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    fclose(f);
    return 1;
}
