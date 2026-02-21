/*
 * koe_crypto.h - Cryptographic primitives backed by libsodium.
 *
 * All operations that touch secret key material zero their stack variables
 * before returning, whether or not the call succeeded.
 *
 * Algorithm choices:
 *   Symmetric encryption  XChaCha20-Poly1305  — no hardware AES needed on ARM
 *   Key exchange          X25519 (ECDH)       — ephemeral, forward secrecy
 *   Identity / signing    Ed25519             — compact, fast on Cortex-A53
 *   KDF (session keys)    BLAKE2b-256         — keyed hash over shared secret
 *   Password hashing      Argon2id            — identity file + backup passphrases
 *   Nonces                randombytes_buf     — always random, never counter
 *
 * Bindgen notes:
 *   - Opaque types (encoder handles etc.) are forward-declared only.
 *   - All sizes are #define constants so bindgen sees them as integer literals.
 *   - No variadic functions are exported.
 */

#ifndef KOE_CRYPTO_H
#define KOE_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

/* Field sizes (bytes). */
#define KOE_ED25519_PK_LEN    32
#define KOE_ED25519_SK_LEN    64
#define KOE_ED25519_SIG_LEN   64
#define KOE_X25519_PK_LEN     32
#define KOE_X25519_SK_LEN     32
#define KOE_SESSION_KEY_LEN   32
#define KOE_NONCE_LEN         24
#define KOE_TAG_LEN           16
#define KOE_SHORT_ID_LEN      16   /* base58 of first 8 bytes of pk */

/* ---------------------------------------------------------------------- */
/* Key types                                                                 */
/* ---------------------------------------------------------------------- */

/* Long-term Ed25519 identity keypair. */
typedef struct {
    uint8_t pk[KOE_ED25519_PK_LEN];
    uint8_t sk[KOE_ED25519_SK_LEN];
} koe_identity_t;

/* Ephemeral X25519 keypair for a single handshake. */
typedef struct {
    uint8_t pk[KOE_X25519_PK_LEN];
    uint8_t sk[KOE_X25519_SK_LEN];
} koe_ephemeral_t;

/* Symmetric session keys derived after a completed handshake.
 * tx_key is used for outbound; rx_key for inbound.
 * Matches the remote side with tx <-> rx swapped. */
typedef struct {
    uint8_t tx_key[KOE_SESSION_KEY_LEN];
    uint8_t rx_key[KOE_SESSION_KEY_LEN];
} koe_session_t;

/* Short human-readable identity (e.g. "water#a3f7b2c9"). */
typedef struct {
    char value[KOE_SHORT_ID_LEN];
} koe_short_id_t;

/* ---------------------------------------------------------------------- */
/* Initialisation                                                            */
/* ---------------------------------------------------------------------- */

/*
 * koe_crypto_init - Initialise libsodium.
 *
 * Must be called once before any other koe_* function.
 * Thread-safe; safe to call multiple times.
 * Returns 0 on success, -1 on failure.
 */
int koe_crypto_init(void);

/* ---------------------------------------------------------------------- */
/* Identity keypair                                                          */
/* ---------------------------------------------------------------------- */

/*
 * koe_identity_generate - Create a fresh Ed25519 keypair.
 */
int koe_identity_generate(koe_identity_t *id);

/*
 * koe_identity_save - Encrypt and persist the identity to a file.
 *
 * The file contains an Argon2id-derived key wrapping the raw keypair.
 * path: destination file path.
 * passphrase: user-chosen passphrase; may be empty string but not NULL.
 */
int koe_identity_save(const koe_identity_t *id,
                       const char           *path,
                       const char           *passphrase);

/*
 * koe_identity_load - Decrypt and load an identity from a file.
 *
 * Returns 0 on success, -1 if the file is missing, corrupted, or the
 * passphrase is wrong.
 */
int koe_identity_load(koe_identity_t *id,
                       const char     *path,
                       const char     *passphrase);

/*
 * koe_identity_short_id - Derive the short ID string for a public key.
 *
 * The short ID is the base58 encoding of the first 8 bytes of pk, zero-
 * terminated.  out must point to at least KOE_SHORT_ID_LEN bytes.
 */
void koe_identity_short_id(koe_short_id_t *out, const uint8_t pk[KOE_ED25519_PK_LEN]);

/* ---------------------------------------------------------------------- */
/* Ephemeral keypair                                                         */
/* ---------------------------------------------------------------------- */

/*
 * koe_ephemeral_generate - Create a fresh X25519 keypair for one handshake.
 *
 * Discard the ephemeral keypair immediately after session key derivation.
 */
int koe_ephemeral_generate(koe_ephemeral_t *eph);

/* ---------------------------------------------------------------------- */
/* Session key derivation                                                    */
/* ---------------------------------------------------------------------- */

/*
 * koe_session_derive - Derive symmetric session keys from a completed X25519
 *                      exchange.
 *
 * local_eph:  our ephemeral keypair.
 * remote_eph: the remote peer's ephemeral public key.
 * local_id:   our long-term identity keypair.
 * remote_pk:  the remote peer's long-term public key.
 * initiator:  1 if we sent the HELLO, 0 if we responded.
 *
 * The derivation mixes the ephemeral DH output with the two long-term public
 * keys using BLAKE2b-256 to bind the session to the authenticated identities.
 *
 * Zeroes local_eph.sk before returning (ephemeral key erasure).
 */
int koe_session_derive(koe_session_t         *sess,
                        koe_ephemeral_t        *local_eph,
                        const uint8_t           remote_eph[KOE_X25519_PK_LEN],
                        const koe_identity_t   *local_id,
                        const uint8_t           remote_pk[KOE_ED25519_PK_LEN],
                        int                     initiator);

/* ---------------------------------------------------------------------- */
/* Authenticated encryption                                                  */
/* ---------------------------------------------------------------------- */

/*
 * koe_encrypt - Encrypt plaintext with XChaCha20-Poly1305.
 *
 * ct must be at least plain_len + KOE_TAG_LEN bytes.
 * nonce must be KOE_NONCE_LEN bytes; generate with koe_nonce_generate().
 * key must be KOE_SESSION_KEY_LEN bytes.
 *
 * Returns 0 on success, -1 on failure.
 */
int koe_encrypt(uint8_t       *ct,
                 const uint8_t *plain,
                 size_t         plain_len,
                 const uint8_t  nonce[KOE_NONCE_LEN],
                 const uint8_t  key[KOE_SESSION_KEY_LEN]);

/*
 * koe_decrypt - Decrypt and authenticate XChaCha20-Poly1305 ciphertext.
 *
 * plain must be at least ct_len - KOE_TAG_LEN bytes.
 * Returns 0 on success, -1 if authentication fails (reject the packet).
 */
int koe_decrypt(uint8_t       *plain,
                 const uint8_t *ct,
                 size_t         ct_len,
                 const uint8_t  nonce[KOE_NONCE_LEN],
                 const uint8_t  key[KOE_SESSION_KEY_LEN]);

/* ---------------------------------------------------------------------- */
/* Signatures                                                                */
/* ---------------------------------------------------------------------- */

/*
 * koe_sign - Produce an Ed25519 signature over msg.
 *
 * sig must be KOE_ED25519_SIG_LEN bytes.
 */
int koe_sign(uint8_t              sig[KOE_ED25519_SIG_LEN],
              const uint8_t       *msg,
              size_t               msg_len,
              const koe_identity_t *id);

/*
 * koe_verify - Verify an Ed25519 signature.
 *
 * Returns 0 if valid, -1 if invalid.
 */
int koe_verify(const uint8_t sig[KOE_ED25519_SIG_LEN],
                const uint8_t *msg,
                size_t         msg_len,
                const uint8_t  pk[KOE_ED25519_PK_LEN]);

/* ---------------------------------------------------------------------- */
/* Nonce generation                                                          */
/* ---------------------------------------------------------------------- */

/*
 * koe_nonce_generate - Fill buf with KOE_NONCE_LEN cryptographically random bytes.
 *
 * Always use a fresh random nonce. Never reuse nonces with the same key.
 */
void koe_nonce_generate(uint8_t buf[KOE_NONCE_LEN]);

/* ---------------------------------------------------------------------- */
/* Identity verification tokens                                              */
/* ---------------------------------------------------------------------- */

/*
 * koe_verify_token_generate - Generate a 6-digit out-of-band verification code.
 *
 * The token is valid for KOE_VERIFY_TOKEN_TTL seconds and is single-use.
 * token_out must be 7 bytes (6 digits + null terminator).
 * nonce_out must be 16 bytes; kept secret until the peer's token is verified.
 */
#define KOE_VERIFY_TOKEN_TTL  30  /* seconds */

int koe_verify_token_generate(char          *token_out,
                                uint8_t       *nonce_out,
                                const uint8_t  pk[KOE_ED25519_PK_LEN]);

/*
 * koe_verify_token_check - Verify a token received from a peer.
 *
 * Returns 0 if valid and within TTL, -1 otherwise.
 */
int koe_verify_token_check(const char    *token,
                             const uint8_t  nonce[16],
                             const uint8_t  pk[KOE_ED25519_PK_LEN],
                             int64_t        issued_at_unix);

/* ---------------------------------------------------------------------- */
/* Secure memory                                                             */
/* ---------------------------------------------------------------------- */

/*
 * koe_memzero - Zero a buffer in a way the compiler cannot optimise away.
 *
 * Thin wrapper around sodium_memzero.
 */
void koe_memzero(void *ptr, size_t len);

#endif /* KOE_CRYPTO_H */
