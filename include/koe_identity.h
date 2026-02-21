/*
 * koe_identity.h - Local identity profile and contact book.
 *
 * The profile wraps the Ed25519 keypair with display metadata and a
 * short human-readable identifier.  The contact book is stored in the
 * SQLite database (koe_db.h) but cached in memory as a linked list.
 *
 * Short IDs:
 *   The short ID is the base58-encoded first 8 bytes of the Ed25519
 *   public key, e.g. "a3f7b2c9".  It is appended to the display name
 *   with a # separator: "water#a3f7b2c9".  Short IDs are for human
 *   use only; the full 32-byte public key is always used on the wire.
 */

#ifndef KOE_IDENTITY_H
#define KOE_IDENTITY_H

#include "koe_crypto.h"
#include "koe_db.h"
#include <stdint.h>
#include <time.h>

#define KOE_DISPLAY_NAME_MAX  64

/* A fully loaded local profile. */
typedef struct {
    koe_identity_t keys;
    char           display_name[KOE_DISPLAY_NAME_MAX];
    koe_short_id_t short_id;
    time_t         created_at;
} koe_profile_t;

/* An entry in the in-memory contact book. */
typedef struct koe_contact {
    uint8_t          pk[KOE_ED25519_PK_LEN];
    char             display_name[KOE_DISPLAY_NAME_MAX];
    koe_short_id_t   short_id;
    time_t           added_at;
    time_t           last_seen;
    int              verified;
    int              blocked;
    struct koe_contact *next;
} koe_contact_t;

typedef struct {
    koe_contact_t *head;
    int            count;
} koe_contact_book_t;

/* Profile operations. */
int  koe_profile_create(koe_profile_t *p, const char *display_name,
                         const char *passphrase, const char *dir);
int  koe_profile_load(koe_profile_t *p, const char *dir, const char *passphrase);
int  koe_profile_save(const koe_profile_t *p, const char *dir, const char *passphrase);
void koe_profile_short_id(char *out, const uint8_t pk[KOE_ED25519_PK_LEN]);

/* Contact book operations (in-memory cache; persist via koe_db). */
void          koe_contact_book_init(koe_contact_book_t *book);
void          koe_contact_book_free(koe_contact_book_t *book);
int           koe_contact_book_load(koe_contact_book_t *book, koe_db_conn_t *db);
int           koe_contact_book_save(const koe_contact_book_t *book, koe_db_conn_t *db);
int           koe_contact_add(koe_contact_book_t *book, const uint8_t pk[KOE_ED25519_PK_LEN],
                               const char *display_name);
int           koe_contact_remove(koe_contact_book_t *book, const uint8_t pk[KOE_ED25519_PK_LEN]);
koe_contact_t *koe_contact_find(const koe_contact_book_t *book, const uint8_t pk[KOE_ED25519_PK_LEN]);
koe_contact_t *koe_contact_find_by_short_id(const koe_contact_book_t *book, const char *short_id);
int           koe_contact_set_verified(koe_contact_book_t *book, const uint8_t pk[KOE_ED25519_PK_LEN], int v);
int           koe_contact_set_blocked(koe_contact_book_t *book, const uint8_t pk[KOE_ED25519_PK_LEN], int b);

#endif /* KOE_IDENTITY_H */
