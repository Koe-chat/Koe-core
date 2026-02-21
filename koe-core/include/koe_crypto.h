/*
 * koe_crypto.h - Cryptographic primitives for the Koe protocol.
 *
 * All crypto is implemented via libsodium. No other crypto library is used.
 *
 * Key lifecycle:
 *   Ed25519 keypair  - Long-term identity. Generated once, stored on disk
 *                      with the secret key encrypted via Argon2id + XChaCha20.
 *   X25519 keypair   - Ephemeral, one per handshake session. Derived from
 *                      the Ed25519 keys via the libsodium conversion helpers.
 *                      Discarded immediately after the session key is derived.
 *   Session keys     - Produced by BLAKE2b-256 over the X25519 shared secret
 *                      and both parties' long-term public keys. Never written
 *                      to disk or transmitted in any form.
 *
 * Forward secrecy is provided by the ephemeral X25519 exchange: compromising
 * the long-term Ed25519 secret key does not allow decryption of past sessions.
 */

#ifndef KOE_CRYPTO_H
#define KOE_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#define KOE_ED25519_PK_LEN   32
#define KOE_ED25519_SK_LEN   64
#define KOE_ED25519_SIG_LEN  64
#define KOE_X25519_PK_LEN    32
#define KOE_X25519_SK_LEN    32
#define KOE_SESSION_KEY_LEN  32
#define KOE_NONCE_LEN        24
#define KOE_TAG_LEN          16
#define KOE_HASH_LEN         32

/* Long-term Ed25519 identity keypair */
typedef struct {
    uint8_t pk[KOE_ED25519_PK_LEN];
    uint8_t sk[KOE_ED25519_SK_LEN];
} koe_identity_t;

/* Ephemeral X25519 keypair, one per handshake */
typedef struct {
    uint8_t pk[KOE_X25519_PK_LEN];
    uint8_t sk[KOE_X25519_SK_LEN];
} koe_ephemeral_t;

/* Session keys produced after a completed handshake.
 * tx_key is used to encrypt outgoing traffic; rx_key decrypts incoming.
 * On the other end tx and rx are flipped, so both parties share the same
 * two keys but use them in opposite directions. */
typedef struct {
    uint8_t tx_key[KOE_SESSION_KEY_LEN];
    uint8_t rx_key[KOE_SESSION_KEY_LEN];
    uint8_t remote_pk[KOE_ED25519_PK_LEN];
    int     established;
} koe_session_t;

/* --- Initialisation ----------------------------------------------------- */

/* Must be called once before any other koe_crypto_* function.
 * Returns 0 on success, -1 if libsodium initialisation fails. */
int koe_crypto_init(void);

/* --- Identity management ----------------------------------------------- */

/* Generate a fresh Ed25519 keypair into *id. */
int koe_identity_generate(koe_identity_t *id);

/* Write an identity to disk. The secret key is encrypted with XChaCha20 using
 * a key derived from `passphrase` via Argon2id (interactive parameters).
 * Writes "identity.pub" (plaintext) and "identity.sec" (encrypted) to `path`. */
int koe_identity_save(const koe_identity_t *id,
                       const char           *path,
                       const char           *passphrase);

/* Load and decrypt an identity from disk. */
int koe_identity_load(koe_identity_t *id,
                       const char     *path,
                       const char     *passphrase);

/* --- Ephemeral key exchange -------------------------------------------- */

/* Generate a throwaway X25519 keypair for a single handshake. */
int koe_ephemeral_generate(koe_ephemeral_t *eph);

/* Derive session keys after the X25519 exchange is complete.
 *
 * Both parties call this with mirrored arguments. The `initiator` flag
 * determines which direction gets which key; the initiator's tx equals
 * the responder's rx, and vice versa.
 *
 * The derivation is:
 *   shared  = X25519(local_eph.sk, remote_eph_pk)
 *   context = local_id_pk || remote_id_pk  (or reversed if !initiator)
 *   keys    = BLAKE2b-512(shared || context), split into tx + rx
 */
int koe_session_derive(koe_session_t         *sess,
                        const koe_ephemeral_t *local_eph,
                        const uint8_t          remote_eph_pk[KOE_X25519_PK_LEN],
                        const koe_identity_t  *local_id,
                        const uint8_t          remote_id_pk[KOE_ED25519_PK_LEN],
                        int                    initiator);

/* --- Symmetric encryption (XChaCha20-Poly1305) ------------------------- */

/* Encrypt `plaintext_len` bytes and write the result to `ciphertext`.
 * `ciphertext` must be at least (plaintext_len + KOE_TAG_LEN) bytes; the
 * Poly1305 MAC tag is prepended.
 * Each (key, nonce) pair must be unique; use koe_nonce_generate() and never
 * reuse a nonce under the same key.
 * Returns 0 on success, -1 on error. */
int koe_encrypt(uint8_t       *ciphertext,
                 const uint8_t *plaintext,
                 size_t         plaintext_len,
                 const uint8_t  nonce[KOE_NONCE_LEN],
                 const uint8_t  key[KOE_SESSION_KEY_LEN]);

/* Verify and decrypt. `ciphertext_len` includes the KOE_TAG_LEN byte MAC
 * prefix. `plaintext` must be at least (ciphertext_len - KOE_TAG_LEN) bytes.
 * Returns 0 on success, -1 if the MAC check fails or on any other error.
 * On failure the plaintext buffer contents are undefined. */
int koe_decrypt(uint8_t       *plaintext,
                 const uint8_t *ciphertext,
                 size_t         ciphertext_len,
                 const uint8_t  nonce[KOE_NONCE_LEN],
                 const uint8_t  key[KOE_SESSION_KEY_LEN]);

/* --- Signatures (Ed25519) ----------------------------------------------- */

/* Sign `msg_len` bytes of `msg` with the identity secret key.
 * `sig` must be KOE_ED25519_SIG_LEN bytes. */
int koe_sign(uint8_t              sig[KOE_ED25519_SIG_LEN],
              const uint8_t       *msg,
              size_t               msg_len,
              const koe_identity_t *id);

/* Verify a signature. Returns 0 if valid, -1 otherwise. */
int koe_verify(const uint8_t sig[KOE_ED25519_SIG_LEN],
                const uint8_t *msg,
                size_t         msg_len,
                const uint8_t  pk[KOE_ED25519_PK_LEN]);

/* --- Nonce management --------------------------------------------------- */

/* Fill `nonce` with 24 cryptographically random bytes.
 * The XChaCha20 nonce space is 192 bits; with random nonces the probability
 * of collision within a single session lifetime is negligible. */
void koe_nonce_generate(uint8_t nonce[KOE_NONCE_LEN]);

/* --- Hashing ------------------------------------------------------------ */

/* BLAKE2b-256 over `len` bytes of `data`. Output written to `out` (32 bytes). */
int koe_hash(uint8_t out[KOE_HASH_LEN], const uint8_t *data, size_t len);

/* --- Identity verification token --------------------------------------- */

/* Generate a short numeric verification token for out-of-band identity
 * confirmation. The token is a 6-digit decimal string (7 bytes with NUL)
 * derived from BLAKE2b over both parties' public keys and a random salt.
 *
 * The token is unique to each (local_pk, remote_pk) pair and each call.
 * `ttl_seconds` is informational only; callers enforce expiry. */
int koe_verify_token_generate(char          out[7],
                                const uint8_t local_pk[KOE_ED25519_PK_LEN],
                                const uint8_t remote_pk[KOE_ED25519_PK_LEN],
                                uint32_t      ttl_seconds);

#endif /* KOE_CRYPTO_H */
