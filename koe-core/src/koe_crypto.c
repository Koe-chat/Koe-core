/*
 * koe_crypto.c - Cryptographic operations backed by libsodium.
 *
 * Every function that touches key material zeroes the relevant stack
 * variables before returning, regardless of success or failure.
 */

#include "koe_crypto.h"
#include <sodium.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/* Argon2id parameters for passphrase-based key derivation.
 * These are libsodium's "interactive" presets: ~64 MB of memory, ~1 second
 * on a mobile CPU. Chosen to be slow enough to resist offline brute-force
 * while still being usable on a Snapdragon. */
#define KDF_MEMLIMIT  crypto_pwhash_MEMLIMIT_INTERACTIVE
#define KDF_OPSLIMIT  crypto_pwhash_OPSLIMIT_INTERACTIVE

int koe_crypto_init(void)
{
    return sodium_init() < 0 ? -1 : 0;
}

/* --- Identity ----------------------------------------------------------- */

int koe_identity_generate(koe_identity_t *id)
{
    return crypto_sign_keypair(id->pk, id->sk) == 0 ? 0 : -1;
}

int koe_identity_save(const koe_identity_t *id,
                       const char           *path,
                       const char           *passphrase)
{
    /* Derive a 32-byte encryption key from the passphrase. */
    uint8_t kdf_salt[crypto_pwhash_SALTBYTES];
    randombytes_buf(kdf_salt, sizeof(kdf_salt));

    uint8_t enc_key[KOE_SESSION_KEY_LEN];
    int rc = crypto_pwhash(enc_key, sizeof(enc_key),
                            passphrase, strlen(passphrase),
                            kdf_salt,
                            KDF_OPSLIMIT, KDF_MEMLIMIT,
                            crypto_pwhash_ALG_ARGON2ID13);
    if (rc != 0) {
        sodium_memzero(enc_key, sizeof(enc_key));
        return -1;
    }

    /* Encrypt the secret key. */
    uint8_t nonce[KOE_NONCE_LEN];
    randombytes_buf(nonce, sizeof(nonce));

    uint8_t ciphertext[KOE_ED25519_SK_LEN + KOE_TAG_LEN];
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        ciphertext, NULL,
        id->sk, KOE_ED25519_SK_LEN,
        NULL, 0,
        NULL,
        nonce, enc_key);

    sodium_memzero(enc_key, sizeof(enc_key));

    /* Write public key file. */
    char pub_path[512];
    snprintf(pub_path, sizeof(pub_path), "%s/identity.pub", path);
    FILE *f = fopen(pub_path, "wb");
    if (!f) return -1;
    fwrite(id->pk, 1, KOE_ED25519_PK_LEN, f);
    fclose(f);

    /* Write encrypted secret key file: salt || nonce || ciphertext. */
    char sec_path[512];
    snprintf(sec_path, sizeof(sec_path), "%s/identity.sec", path);
    f = fopen(sec_path, "wb");
    if (!f) return -1;
    fwrite(kdf_salt,   1, sizeof(kdf_salt),   f);
    fwrite(nonce,      1, sizeof(nonce),       f);
    fwrite(ciphertext, 1, sizeof(ciphertext),  f);
    fclose(f);

    return 0;
}

int koe_identity_load(koe_identity_t *id,
                       const char     *path,
                       const char     *passphrase)
{
    /* Read public key. */
    char pub_path[512];
    snprintf(pub_path, sizeof(pub_path), "%s/identity.pub", path);
    FILE *f = fopen(pub_path, "rb");
    if (!f) return -1;
    if (fread(id->pk, 1, KOE_ED25519_PK_LEN, f) != KOE_ED25519_PK_LEN) {
        fclose(f);
        return -1;
    }
    fclose(f);

    /* Read salt + nonce + ciphertext. */
    char sec_path[512];
    snprintf(sec_path, sizeof(sec_path), "%s/identity.sec", path);
    f = fopen(sec_path, "rb");
    if (!f) return -1;

    uint8_t kdf_salt[crypto_pwhash_SALTBYTES];
    uint8_t nonce[KOE_NONCE_LEN];
    uint8_t ciphertext[KOE_ED25519_SK_LEN + KOE_TAG_LEN];

    int ok = (fread(kdf_salt,   1, sizeof(kdf_salt),   f) == sizeof(kdf_salt))
          && (fread(nonce,      1, sizeof(nonce),       f) == sizeof(nonce))
          && (fread(ciphertext, 1, sizeof(ciphertext),  f) == sizeof(ciphertext));
    fclose(f);
    if (!ok) return -1;

    /* Derive decryption key. */
    uint8_t enc_key[KOE_SESSION_KEY_LEN];
    int rc = crypto_pwhash(enc_key, sizeof(enc_key),
                            passphrase, strlen(passphrase),
                            kdf_salt,
                            KDF_OPSLIMIT, KDF_MEMLIMIT,
                            crypto_pwhash_ALG_ARGON2ID13);
    if (rc != 0) {
        sodium_memzero(enc_key, sizeof(enc_key));
        return -1;
    }

    rc = crypto_aead_xchacha20poly1305_ietf_decrypt(
        id->sk, NULL,
        NULL,
        ciphertext, sizeof(ciphertext),
        NULL, 0,
        nonce, enc_key);

    sodium_memzero(enc_key, sizeof(enc_key));
    return rc == 0 ? 0 : -1;
}

/* --- Ephemeral keypair -------------------------------------------------- */

int koe_ephemeral_generate(koe_ephemeral_t *eph)
{
    return crypto_box_keypair(eph->pk, eph->sk) == 0 ? 0 : -1;
}

int koe_session_derive(koe_session_t         *sess,
                        const koe_ephemeral_t *local_eph,
                        const uint8_t          remote_eph_pk[KOE_X25519_PK_LEN],
                        const koe_identity_t  *local_id,
                        const uint8_t          remote_id_pk[KOE_ED25519_PK_LEN],
                        int                    initiator)
{
    /* X25519 scalar multiplication to get the shared point. */
    uint8_t shared[crypto_scalarmult_BYTES];
    if (crypto_scalarmult(shared, local_eph->sk, remote_eph_pk) != 0) {
        sodium_memzero(shared, sizeof(shared));
        return -1;
    }

    /* Mix in both long-term public keys as domain separation context.
     * Order is (initiator_pk || responder_pk) regardless of who we are,
     * so both parties produce identical context bytes. */
    uint8_t context[KOE_ED25519_PK_LEN * 2];
    if (initiator) {
        memcpy(context,                    local_id->pk,  KOE_ED25519_PK_LEN);
        memcpy(context + KOE_ED25519_PK_LEN, remote_id_pk, KOE_ED25519_PK_LEN);
    } else {
        memcpy(context,                    remote_id_pk,  KOE_ED25519_PK_LEN);
        memcpy(context + KOE_ED25519_PK_LEN, local_id->pk, KOE_ED25519_PK_LEN);
    }

    /* BLAKE2b-512 over (shared || context) produces 64 bytes:
     * first 32 are the initiator's tx key, last 32 are the rx key. */
    uint8_t material[64];
    uint8_t input[sizeof(shared) + sizeof(context)];
    memcpy(input, shared, sizeof(shared));
    memcpy(input + sizeof(shared), context, sizeof(context));

    crypto_generichash(material, sizeof(material), input, sizeof(input), NULL, 0);

    sodium_memzero(shared,  sizeof(shared));
    sodium_memzero(input,   sizeof(input));
    sodium_memzero(context, sizeof(context));

    if (initiator) {
        memcpy(sess->tx_key, material,      KOE_SESSION_KEY_LEN);
        memcpy(sess->rx_key, material + 32, KOE_SESSION_KEY_LEN);
    } else {
        memcpy(sess->rx_key, material,      KOE_SESSION_KEY_LEN);
        memcpy(sess->tx_key, material + 32, KOE_SESSION_KEY_LEN);
    }

    sodium_memzero(material, sizeof(material));

    memcpy(sess->remote_pk, remote_id_pk, KOE_ED25519_PK_LEN);
    sess->established = 1;
    return 0;
}

/* --- Encryption --------------------------------------------------------- */

int koe_encrypt(uint8_t       *ciphertext,
                 const uint8_t *plaintext,
                 size_t         plaintext_len,
                 const uint8_t  nonce[KOE_NONCE_LEN],
                 const uint8_t  key[KOE_SESSION_KEY_LEN])
{
    unsigned long long ct_len;
    int rc = crypto_aead_xchacha20poly1305_ietf_encrypt(
        ciphertext, &ct_len,
        plaintext, plaintext_len,
        NULL, 0,
        NULL,
        nonce, key);
    return rc == 0 ? 0 : -1;
}

int koe_decrypt(uint8_t       *plaintext,
                 const uint8_t *ciphertext,
                 size_t         ciphertext_len,
                 const uint8_t  nonce[KOE_NONCE_LEN],
                 const uint8_t  key[KOE_SESSION_KEY_LEN])
{
    unsigned long long pt_len;
    int rc = crypto_aead_xchacha20poly1305_ietf_decrypt(
        plaintext, &pt_len,
        NULL,
        ciphertext, ciphertext_len,
        NULL, 0,
        nonce, key);
    return rc == 0 ? 0 : -1;
}

/* --- Signatures --------------------------------------------------------- */

int koe_sign(uint8_t              sig[KOE_ED25519_SIG_LEN],
              const uint8_t       *msg,
              size_t               msg_len,
              const koe_identity_t *id)
{
    unsigned long long siglen;
    return crypto_sign_detached(sig, &siglen, msg, msg_len, id->sk) == 0 ? 0 : -1;
}

int koe_verify(const uint8_t sig[KOE_ED25519_SIG_LEN],
                const uint8_t *msg,
                size_t         msg_len,
                const uint8_t  pk[KOE_ED25519_PK_LEN])
{
    return crypto_sign_verify_detached(sig, msg, msg_len, pk) == 0 ? 0 : -1;
}

/* --- Nonce -------------------------------------------------------------- */

void koe_nonce_generate(uint8_t nonce[KOE_NONCE_LEN])
{
    randombytes_buf(nonce, KOE_NONCE_LEN);
}

/* --- Hashing ------------------------------------------------------------ */

int koe_hash(uint8_t out[KOE_HASH_LEN], const uint8_t *data, size_t len)
{
    return crypto_generichash(out, KOE_HASH_LEN, data, len, NULL, 0) == 0 ? 0 : -1;
}

/* --- Verification token ------------------------------------------------- */

int koe_verify_token_generate(char          out[7],
                                const uint8_t local_pk[KOE_ED25519_PK_LEN],
                                const uint8_t remote_pk[KOE_ED25519_PK_LEN],
                                uint32_t      ttl_seconds)
{
    (void)ttl_seconds;   /* TTL is informational; callers enforce it */

    uint8_t salt[16];
    randombytes_buf(salt, sizeof(salt));

    uint8_t input[KOE_ED25519_PK_LEN * 2 + sizeof(salt)];
    memcpy(input,                              local_pk,  KOE_ED25519_PK_LEN);
    memcpy(input + KOE_ED25519_PK_LEN,         remote_pk, KOE_ED25519_PK_LEN);
    memcpy(input + KOE_ED25519_PK_LEN * 2,     salt,      sizeof(salt));

    uint8_t hash[KOE_HASH_LEN];
    if (koe_hash(hash, input, sizeof(input)) != 0)
        return -1;

    /* Take the first 3 bytes (24 bits) and reduce modulo 1,000,000 to get
     * a 6-digit decimal number. */
    uint32_t raw = ((uint32_t)hash[0] << 16)
                 | ((uint32_t)hash[1] <<  8)
                 |  (uint32_t)hash[2];
    uint32_t token = raw % 1000000;

    snprintf(out, 7, "%06u", token);
    return 0;
}
