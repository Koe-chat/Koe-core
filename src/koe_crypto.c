/*
 * koe_crypto.c - Cryptographic operations via libsodium.
 */

#include "koe_crypto.h"
#include <sodium.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/* Argon2id parameters (libsodium interactive preset: ~64 MB, ~1 s on ARM). */
#define KDF_MEMLIMIT  crypto_pwhash_MEMLIMIT_INTERACTIVE
#define KDF_OPSLIMIT  crypto_pwhash_OPSLIMIT_INTERACTIVE

/* base58 alphabet (Bitcoin). */
static const char B58_ALPHA[] =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/* ---------------------------------------------------------------------- */

int koe_crypto_init(void)
{
    return sodium_init() < 0 ? -1 : 0;
}

/* ---------------------------------------------------------------------- */
/* Identity                                                                  */
/* ---------------------------------------------------------------------- */

int koe_identity_generate(koe_identity_t *id)
{
    return crypto_sign_keypair(id->pk, id->sk) == 0 ? 0 : -1;
}

int koe_identity_save(const koe_identity_t *id,
                       const char           *path,
                       const char           *passphrase)
{
    uint8_t salt[crypto_pwhash_SALTBYTES];
    randombytes_buf(salt, sizeof(salt));

    uint8_t enc_key[KOE_SESSION_KEY_LEN];
    if (crypto_pwhash(enc_key, sizeof(enc_key),
                       passphrase, strlen(passphrase),
                       salt, KDF_OPSLIMIT, KDF_MEMLIMIT,
                       crypto_pwhash_ALG_ARGON2ID13) != 0) {
        sodium_memzero(enc_key, sizeof(enc_key));
        return -1;
    }

    /* Plaintext: pk (32) || sk (64) = 96 bytes. */
    uint8_t plain[96];
    memcpy(plain,      id->pk, KOE_ED25519_PK_LEN);
    memcpy(plain + 32, id->sk, KOE_ED25519_SK_LEN);

    uint8_t nonce[KOE_NONCE_LEN];
    koe_nonce_generate(nonce);

    uint8_t ct[96 + KOE_TAG_LEN];
    if (koe_encrypt(ct, plain, sizeof(plain), nonce, enc_key) != 0) {
        sodium_memzero(enc_key, sizeof(enc_key));
        sodium_memzero(plain, sizeof(plain));
        return -1;
    }
    sodium_memzero(enc_key, sizeof(enc_key));
    sodium_memzero(plain, sizeof(plain));

    FILE *f = fopen(path, "wb");
    if (!f) return -1;

    /* File layout: magic(4) + version(1) + salt(32) + nonce(24) + ct(112). */
    uint8_t magic[5] = { 'K','O','E','I','D' };
    fwrite(magic, 1, sizeof(magic), f);
    fwrite(salt,  1, sizeof(salt),  f);
    fwrite(nonce, 1, sizeof(nonce), f);
    fwrite(ct,    1, sizeof(ct),    f);
    fclose(f);
    return 0;
}

int koe_identity_load(koe_identity_t *id,
                       const char     *path,
                       const char     *passphrase)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    uint8_t magic[5];
    if (fread(magic, 1, sizeof(magic), f) != sizeof(magic)) { fclose(f); return -1; }
    if (memcmp(magic, "KOEID", 5) != 0) { fclose(f); return -1; }

    uint8_t salt[crypto_pwhash_SALTBYTES];
    uint8_t nonce[KOE_NONCE_LEN];
    uint8_t ct[96 + KOE_TAG_LEN];

    if (fread(salt,  1, sizeof(salt),  f) != sizeof(salt)  ||
        fread(nonce, 1, sizeof(nonce), f) != sizeof(nonce) ||
        fread(ct,    1, sizeof(ct),    f) != sizeof(ct)) {
        fclose(f);
        return -1;
    }
    fclose(f);

    uint8_t enc_key[KOE_SESSION_KEY_LEN];
    if (crypto_pwhash(enc_key, sizeof(enc_key),
                       passphrase, strlen(passphrase),
                       salt, KDF_OPSLIMIT, KDF_MEMLIMIT,
                       crypto_pwhash_ALG_ARGON2ID13) != 0) {
        sodium_memzero(enc_key, sizeof(enc_key));
        return -1;
    }

    uint8_t plain[96];
    int rc = koe_decrypt(plain, ct, sizeof(ct), nonce, enc_key);
    sodium_memzero(enc_key, sizeof(enc_key));
    if (rc != 0) return -1;

    memcpy(id->pk, plain,      KOE_ED25519_PK_LEN);
    memcpy(id->sk, plain + 32, KOE_ED25519_SK_LEN);
    sodium_memzero(plain, sizeof(plain));
    return 0;
}

/* base58 encode the first 8 bytes of pk into out[0..KOE_SHORT_ID_LEN-1]. */
void koe_identity_short_id(koe_short_id_t *out, const uint8_t pk[KOE_ED25519_PK_LEN])
{
    uint64_t val = 0;
    for (int i = 0; i < 8; i++)
        val = (val << 8) | pk[i];

    char tmp[KOE_SHORT_ID_LEN];
    int  pos = sizeof(tmp) - 1;
    tmp[pos] = '\0';

    do {
        pos--;
        tmp[pos] = B58_ALPHA[val % 58];
        val /= 58;
    } while (val && pos > 0);

    /* Pad with leading '1's (base58 zero). */
    while (pos > 0) {
        pos--;
        tmp[pos] = '1';
    }

    strncpy(out->value, tmp + pos, KOE_SHORT_ID_LEN - 1);
    out->value[KOE_SHORT_ID_LEN - 1] = '\0';
}

/* ---------------------------------------------------------------------- */
/* Ephemeral keypair                                                         */
/* ---------------------------------------------------------------------- */

int koe_ephemeral_generate(koe_ephemeral_t *eph)
{
    return crypto_box_keypair(eph->pk, eph->sk) == 0 ? 0 : -1;
}

/* ---------------------------------------------------------------------- */
/* Session key derivation                                                    */
/* ---------------------------------------------------------------------- */

int koe_session_derive(koe_session_t         *sess,
                        koe_ephemeral_t        *local_eph,
                        const uint8_t           remote_eph[KOE_X25519_PK_LEN],
                        const koe_identity_t   *local_id,
                        const uint8_t           remote_pk[KOE_ED25519_PK_LEN],
                        int                     initiator)
{
    /* X25519 shared secret. */
    uint8_t dh[crypto_scalarmult_BYTES];
    if (crypto_scalarmult(dh, local_eph->sk, remote_eph) != 0) {
        sodium_memzero(dh, sizeof(dh));
        return -1;
    }

    /* Erase ephemeral secret immediately. */
    sodium_memzero(local_eph->sk, sizeof(local_eph->sk));

    /* BLAKE2b-256 over: dh || local_pk || remote_pk (ordered by initiator flag). */
    crypto_generichash_state state;
    crypto_generichash_init(&state, NULL, 0, KOE_SESSION_KEY_LEN);
    crypto_generichash_update(&state, dh, sizeof(dh));

    if (initiator) {
        crypto_generichash_update(&state, local_id->pk, KOE_ED25519_PK_LEN);
        crypto_generichash_update(&state, remote_pk,    KOE_ED25519_PK_LEN);
    } else {
        crypto_generichash_update(&state, remote_pk,    KOE_ED25519_PK_LEN);
        crypto_generichash_update(&state, local_id->pk, KOE_ED25519_PK_LEN);
    }

    uint8_t combined[KOE_SESSION_KEY_LEN * 2];
    crypto_generichash_final(&state, combined, sizeof(combined));

    /* First 32 bytes = initiator's tx key; second 32 = initiator's rx key. */
    if (initiator) {
        memcpy(sess->tx_key, combined,                       KOE_SESSION_KEY_LEN);
        memcpy(sess->rx_key, combined + KOE_SESSION_KEY_LEN, KOE_SESSION_KEY_LEN);
    } else {
        memcpy(sess->rx_key, combined,                       KOE_SESSION_KEY_LEN);
        memcpy(sess->tx_key, combined + KOE_SESSION_KEY_LEN, KOE_SESSION_KEY_LEN);
    }

    sodium_memzero(dh,       sizeof(dh));
    sodium_memzero(combined, sizeof(combined));
    return 0;
}

/* ---------------------------------------------------------------------- */
/* Encryption                                                               */
/* ---------------------------------------------------------------------- */

int koe_encrypt(uint8_t       *ct,
                 const uint8_t *plain,
                 size_t         plain_len,
                 const uint8_t  nonce[KOE_NONCE_LEN],
                 const uint8_t  key[KOE_SESSION_KEY_LEN])
{
    return crypto_aead_xchacha20poly1305_ietf_encrypt(
               ct, NULL, plain, (unsigned long long)plain_len,
               NULL, 0, NULL, nonce, key) == 0 ? 0 : -1;
}

int koe_decrypt(uint8_t       *plain,
                 const uint8_t *ct,
                 size_t         ct_len,
                 const uint8_t  nonce[KOE_NONCE_LEN],
                 const uint8_t  key[KOE_SESSION_KEY_LEN])
{
    if (ct_len < KOE_TAG_LEN) return -1;
    unsigned long long plain_len;
    return crypto_aead_xchacha20poly1305_ietf_decrypt(
               plain, &plain_len, NULL,
               ct, (unsigned long long)ct_len,
               NULL, 0, nonce, key) == 0 ? 0 : -1;
}

/* ---------------------------------------------------------------------- */
/* Signatures                                                               */
/* ---------------------------------------------------------------------- */

int koe_sign(uint8_t              sig[KOE_ED25519_SIG_LEN],
              const uint8_t       *msg,
              size_t               msg_len,
              const koe_identity_t *id)
{
    unsigned long long siglen;
    return crypto_sign_detached(sig, &siglen, msg, (unsigned long long)msg_len, id->sk) == 0 ? 0 : -1;
}

int koe_verify(const uint8_t sig[KOE_ED25519_SIG_LEN],
                const uint8_t *msg,
                size_t         msg_len,
                const uint8_t  pk[KOE_ED25519_PK_LEN])
{
    return crypto_sign_verify_detached(sig, msg, (unsigned long long)msg_len, pk) == 0 ? 0 : -1;
}

/* ---------------------------------------------------------------------- */
/* Nonce                                                                    */
/* ---------------------------------------------------------------------- */

void koe_nonce_generate(uint8_t buf[KOE_NONCE_LEN])
{
    randombytes_buf(buf, KOE_NONCE_LEN);
}

/* ---------------------------------------------------------------------- */
/* Verification tokens                                                      */
/* ---------------------------------------------------------------------- */

int koe_verify_token_generate(char          *token_out,
                                uint8_t       *nonce_out,
                                const uint8_t  pk[KOE_ED25519_PK_LEN])
{
    randombytes_buf(nonce_out, 16);

    /* BLAKE2b(nonce || pk) mod 1,000,000 = 6-digit token. */
    uint8_t hash[32];
    crypto_generichash_state state;
    crypto_generichash_init(&state, NULL, 0, sizeof(hash));
    crypto_generichash_update(&state, nonce_out, 16);
    crypto_generichash_update(&state, pk, KOE_ED25519_PK_LEN);
    crypto_generichash_final(&state, hash, sizeof(hash));

    uint32_t val;
    memcpy(&val, hash, sizeof(val));
    val = val % 1000000;

    snprintf(token_out, 7, "%06u", val);
    return 0;
}

int koe_verify_token_check(const char    *token,
                             const uint8_t  nonce[16],
                             const uint8_t  pk[KOE_ED25519_PK_LEN],
                             int64_t        issued_at_unix)
{
    int64_t now = (int64_t)time(NULL);
    if (now - issued_at_unix > KOE_VERIFY_TOKEN_TTL) return -1;

    char expected[7];
    uint8_t nonce_copy[16];
    memcpy(nonce_copy, nonce, 16);

    uint8_t hash[32];
    crypto_generichash_state state;
    crypto_generichash_init(&state, NULL, 0, sizeof(hash));
    crypto_generichash_update(&state, nonce_copy, 16);
    crypto_generichash_update(&state, pk, KOE_ED25519_PK_LEN);
    crypto_generichash_final(&state, hash, sizeof(hash));

    uint32_t val;
    memcpy(&val, hash, sizeof(val));
    val = val % 1000000;
    snprintf(expected, 7, "%06u", val);

    return sodium_memcmp(token, expected, 6) == 0 ? 0 : -1;
}

/* ---------------------------------------------------------------------- */
/* Secure memory                                                            */
/* ---------------------------------------------------------------------- */

void koe_memzero(void *ptr, size_t len)
{
    sodium_memzero(ptr, len);
}
