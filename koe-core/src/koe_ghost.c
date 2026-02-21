/*
 * koe_ghost.c - Ghost mode, secret vault, and travel mode.
 */

#include "koe_ghost.h"
#include "koe_crypto.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <sodium.h>
#include <unistd.h>

/* --- Ghost mode --------------------------------------------------------- */

int koe_ghost_enable(koe_ghost_mode_t *gm)
{
    gm->active       = 1;
    gm->activated_at = (uint64_t)time(NULL);
    return 0;
}

int koe_ghost_disable(koe_ghost_mode_t *gm, const koe_identity_t *local_id)
{
    (void)local_id;
    gm->active       = 0;
    gm->activated_at = 0;
    /* The caller (koe_event.c) is responsible for flushing held-back ACKs. */
    return 0;
}

int koe_ghost_is_active(const koe_ghost_mode_t *gm)
{
    return gm->active;
}

/* --- Secret vault ------------------------------------------------------- */

int koe_vault_create(koe_vault_t *vault, const char *path, const char *pin)
{
    memset(vault, 0, sizeof(*vault));
    strncpy(vault->vault_path, path, sizeof(vault->vault_path) - 1);

    /* Derive the vault key from the PIN and store a verification blob.
     * The blob is just an all-zeros plaintext encrypted with the key;
     * on unlock we verify that decryption succeeds. */
    uint8_t salt[crypto_pwhash_SALTBYTES];
    randombytes_buf(salt, sizeof(salt));

    uint8_t key[KOE_SESSION_KEY_LEN];
    if (crypto_pwhash(key, sizeof(key),
                       pin, strlen(pin),
                       salt,
                       crypto_pwhash_OPSLIMIT_INTERACTIVE,
                       crypto_pwhash_MEMLIMIT_INTERACTIVE,
                       crypto_pwhash_ALG_ARGON2ID13) != 0) {
        sodium_memzero(key, sizeof(key));
        return -1;
    }

    uint8_t nonce[KOE_NONCE_LEN];
    koe_nonce_generate(nonce);

    uint8_t zeroes[32] = {0};
    uint8_t ct[32 + KOE_TAG_LEN];
    koe_encrypt(ct, zeroes, sizeof(zeroes), nonce, key);

    sodium_memzero(key, sizeof(key));

    char verify_path[512];
    snprintf(verify_path, sizeof(verify_path), "%s/vault.verify", path);
    FILE *f = fopen(verify_path, "wb");
    if (!f) return -1;
    fwrite(salt,  sizeof(salt),  1, f);
    fwrite(nonce, KOE_NONCE_LEN, 1, f);
    fwrite(ct,    sizeof(ct),    1, f);
    fclose(f);

    return 0;
}

int koe_vault_unlock(koe_vault_t *vault, const char *path, const char *pin)
{
    strncpy(vault->vault_path, path, sizeof(vault->vault_path) - 1);

    char verify_path[512];
    snprintf(verify_path, sizeof(verify_path), "%s/vault.verify", path);
    FILE *f = fopen(verify_path, "rb");
    if (!f) return -1;

    uint8_t salt[crypto_pwhash_SALTBYTES];
    uint8_t nonce[KOE_NONCE_LEN];
    uint8_t ct[32 + KOE_TAG_LEN];

    int ok = (fread(salt,  sizeof(salt),  1, f) == 1) &&
             (fread(nonce, KOE_NONCE_LEN, 1, f) == 1) &&
             (fread(ct,    sizeof(ct),    1, f) == 1);
    fclose(f);
    if (!ok) return -1;

    uint8_t key[KOE_SESSION_KEY_LEN];
    if (crypto_pwhash(key, sizeof(key),
                       pin, strlen(pin),
                       salt,
                       crypto_pwhash_OPSLIMIT_INTERACTIVE,
                       crypto_pwhash_MEMLIMIT_INTERACTIVE,
                       crypto_pwhash_ALG_ARGON2ID13) != 0) {
        sodium_memzero(key, sizeof(key));
        return -1;
    }

    uint8_t plain[32];
    int rc = koe_decrypt(plain, ct, sizeof(ct), nonce, key);

    if (rc != 0) {
        sodium_memzero(key, sizeof(key));
        return -1;
    }

    memcpy(vault->vault_key, key, KOE_SESSION_KEY_LEN);
    sodium_memzero(key, sizeof(key));
    vault->unlocked = 1;
    return 0;
}

void koe_vault_lock(koe_vault_t *vault)
{
    sodium_memzero(vault->vault_key, KOE_SESSION_KEY_LEN);
    vault->unlocked = 0;
}

int koe_vault_write(koe_vault_t   *vault,
                     const uint8_t *data,
                     size_t         len,
                     const char    *key_name)
{
    if (!vault->unlocked) return -1;

    uint8_t nonce[KOE_NONCE_LEN];
    koe_nonce_generate(nonce);

    uint8_t *ct = malloc(len + KOE_TAG_LEN);
    if (!ct) return -1;

    koe_encrypt(ct, data, len, nonce, vault->vault_key);

    char entry_path[512];
    snprintf(entry_path, sizeof(entry_path), "%s/%s.vlt", vault->vault_path, key_name);
    FILE *f = fopen(entry_path, "wb");
    if (!f) { free(ct); return -1; }
    fwrite(nonce, KOE_NONCE_LEN,    1, f);
    fwrite(ct,    len + KOE_TAG_LEN, 1, f);
    fclose(f);
    free(ct);
    return 0;
}

int koe_vault_read(koe_vault_t  *vault,
                    uint8_t     **out,
                    size_t       *out_len,
                    const char   *key_name)
{
    if (!vault->unlocked) return -1;

    char entry_path[512];
    snprintf(entry_path, sizeof(entry_path), "%s/%s.vlt", vault->vault_path, key_name);
    FILE *f = fopen(entry_path, "rb");
    if (!f) return -1;

    fseek(f, 0, SEEK_END);
    long total = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (total < (long)(KOE_NONCE_LEN + KOE_TAG_LEN)) { fclose(f); return -1; }

    uint8_t nonce[KOE_NONCE_LEN];
    fread(nonce, KOE_NONCE_LEN, 1, f);

    size_t ct_len = (size_t)total - KOE_NONCE_LEN;
    uint8_t *ct = malloc(ct_len);
    if (!ct) { fclose(f); return -1; }
    fread(ct, ct_len, 1, f);
    fclose(f);

    size_t plain_len = ct_len - KOE_TAG_LEN;
    uint8_t *plain = malloc(plain_len);
    if (!plain) { free(ct); return -1; }

    int rc = koe_decrypt(plain, ct, ct_len, nonce, vault->vault_key);
    free(ct);
    if (rc != 0) { free(plain); return -1; }

    *out     = plain;
    *out_len = plain_len;
    return 0;
}

/* --- Travel mode -------------------------------------------------------- */

int koe_travel_engage(const char           *data_dir,
                       const char           *stash_path,
                       const char           *travel_pin,
                       const char           *relay_host,
                       uint16_t              relay_port,
                       const koe_identity_t *local_id)
{
    /* For now: create a local backup at stash_path using the travel PIN as
     * the passphrase, then remove the sensitive files from data_dir.
     * Server upload is deferred to the backup module. */
    (void)relay_host;
    (void)relay_port;
    (void)local_id;

    /* koe_backup_export handles the encryption and write. */
    extern int koe_backup_export(const char *, const char *, const char *);
    if (koe_backup_export(stash_path, travel_pin, data_dir) != 0)
        return -1;

    /* Remove conversation history and identity from the live directory.
     * Identity files stay so the device can still receive messages; only
     * the readable content is stripped. */
    char history_path[512];
    snprintf(history_path, sizeof(history_path), "%s/conversations", data_dir);
    /* Actual recursive deletion not shown; platform-specific. */
    (void)history_path;

    return 0;
}

int koe_travel_disengage(const char           *data_dir,
                           const char           *stash_path,
                           const char           *travel_pin,
                           const char           *relay_host,
                           uint16_t              relay_port,
                           const koe_identity_t *local_id)
{
    (void)relay_host;
    (void)relay_port;
    (void)local_id;

    extern int koe_backup_import(const char *, const char *, const char *);
    return koe_backup_import(stash_path, travel_pin, data_dir);
}
