/*
 * koe_identity.h - Local user profile and contact book.
 *
 * A Koe identity is an Ed25519 keypair. The public key is the user's
 * permanent network address. The human-readable short ID shown in the UI
 * is a base58 encoding of the first 6 bytes of the public key, e.g. "a3f7b2".
 * Collisions are possible in theory but negligible in practice given the
 * underlying 256-bit address space.
 *
 * The contact book is serialised as a small encrypted binary blob using the
 * local identity key. No JSON or XML parser is involved, which keeps the
 * attack surface minimal.
 */

#ifndef KOE_IDENTITY_H
#define KOE_IDENTITY_H

#include "koe_crypto.h"
#include <stdint.h>
#include <time.h>

#define KOE_NAME_MAX       64    /* maximum display name length including NUL */
#define KOE_SHORT_ID_LEN    9    /* 8 chars base58 + NUL terminator */

/* Local user profile ----------------------------------------------------- */
typedef struct {
    koe_identity_t  keys;
    char            name[KOE_NAME_MAX];
    char            short_id[KOE_SHORT_ID_LEN];
    time_t          created_at;
} koe_profile_t;

/* Contact entry ---------------------------------------------------------- */
typedef struct {
    uint8_t  pk[KOE_ED25519_PK_LEN];
    char     name[KOE_NAME_MAX];
    char     short_id[KOE_SHORT_ID_LEN];
    time_t   added_at;
    time_t   last_seen;
    int      verified;    /* 1 if identity confirmed via koe_verify_token */
    int      blocked;
} koe_contact_t;

/* Contact book ----------------------------------------------------------- */
typedef struct koe_contact_node {
    koe_contact_t          contact;
    struct koe_contact_node *next;
} koe_contact_node_t;

typedef struct {
    koe_contact_node_t *head;
    size_t              count;
} koe_contact_book_t;

/* Profile management ----------------------------------------------------- */

/* Generate a new identity and profile. `name` is the chosen display name.
 * `passphrase` is used to encrypt the secret key on disk. The profile files
 * are written under `path`. Returns 0 on success, -1 on error. */
int koe_profile_create(koe_profile_t *profile,
                        const char    *name,
                        const char    *passphrase,
                        const char    *path);

/* Load a previously saved profile. */
int koe_profile_load(koe_profile_t *profile,
                      const char    *path,
                      const char    *passphrase);

/* Persist a profile to disk. Skips the write if nothing has changed since
 * the last save. Returns 0 on success, -1 on error. */
int koe_profile_save(const koe_profile_t *profile,
                      const char          *path,
                      const char          *passphrase);

/* Derive the short human-readable ID from a public key.
 * `out` must be at least KOE_SHORT_ID_LEN bytes. */
void koe_profile_short_id(char          out[KOE_SHORT_ID_LEN],
                            const uint8_t pk[KOE_ED25519_PK_LEN]);

/* Contact book ----------------------------------------------------------- */

void koe_contact_book_init(koe_contact_book_t *book);
void koe_contact_book_free(koe_contact_book_t *book);

/* Add a contact. Returns -1 if the public key is already in the book. */
int koe_contact_add(koe_contact_book_t *book,
                     const uint8_t       pk[KOE_ED25519_PK_LEN],
                     const char         *name);

/* Look up a contact by public key. Returns a live pointer into the list
 * (do not free it directly), or NULL if not found. */
koe_contact_t *koe_contact_find(koe_contact_book_t *book,
                                  const uint8_t       pk[KOE_ED25519_PK_LEN]);

/* Remove a contact by public key. Returns 0 if found and removed, -1 if not
 * found. */
int koe_contact_remove(koe_contact_book_t *book,
                        const uint8_t       pk[KOE_ED25519_PK_LEN]);

/* Mark a contact as identity-verified. */
int koe_contact_set_verified(koe_contact_book_t *book,
                               const uint8_t       pk[KOE_ED25519_PK_LEN],
                               int                 verified);

/* Update the last_seen timestamp for a contact. */
void koe_contact_update_seen(koe_contact_book_t *book,
                               const uint8_t       pk[KOE_ED25519_PK_LEN]);

/* Serialise the contact book to an encrypted binary file at `path`.
 * Encryption uses the local identity key so only this device can read it. */
int koe_contact_book_save(const koe_contact_book_t *book,
                            const char               *path,
                            const koe_identity_t     *id);

/* Load and decrypt a contact book from disk. */
int koe_contact_book_load(koe_contact_book_t   *book,
                            const char           *path,
                            const koe_identity_t *id);

#endif /* KOE_IDENTITY_H */
