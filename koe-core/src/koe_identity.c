/*
 * koe_identity.c - Profile and contact book management.
 */

#include "koe_identity.h"
#include "koe_crypto.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <sodium.h>

/* Base58 alphabet (Bitcoin ordering, avoids visually ambiguous characters). */
static const char BASE58[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

void koe_profile_short_id(char out[KOE_SHORT_ID_LEN], const uint8_t pk[KOE_ED25519_PK_LEN])
{
    /* Encode the first 6 bytes of the public key in base58.
     * Six bytes give us 8 base-58 characters with a tiny bit of padding room. */
    uint64_t n = 0;
    for (int i = 0; i < 6; i++)
        n = (n << 8) | pk[i];

    char tmp[8];
    for (int i = 7; i >= 0; i--) {
        tmp[i] = BASE58[n % 58];
        n /= 58;
    }
    memcpy(out, tmp, 8);
    out[8] = '\0';
}

int koe_profile_create(koe_profile_t *profile,
                        const char    *name,
                        const char    *passphrase,
                        const char    *path)
{
    memset(profile, 0, sizeof(*profile));

    if (koe_identity_generate(&profile->keys) != 0)
        return -1;

    strncpy(profile->name, name, KOE_NAME_MAX - 1);
    koe_profile_short_id(profile->short_id, profile->keys.pk);
    profile->created_at = time(NULL);

    return koe_identity_save(&profile->keys, path, passphrase);
}

int koe_profile_load(koe_profile_t *profile,
                      const char    *path,
                      const char    *passphrase)
{
    memset(profile, 0, sizeof(*profile));

    if (koe_identity_load(&profile->keys, path, passphrase) != 0)
        return -1;

    koe_profile_short_id(profile->short_id, profile->keys.pk);

    /* Load display name from a plain text sidecar file. */
    char name_path[512];
    snprintf(name_path, sizeof(name_path), "%s/identity.name", path);
    FILE *f = fopen(name_path, "r");
    if (f) {
        fgets(profile->name, KOE_NAME_MAX, f);
        fclose(f);
        /* Strip trailing newline if present. */
        size_t len = strlen(profile->name);
        if (len > 0 && profile->name[len - 1] == '\n')
            profile->name[len - 1] = '\0';
    }

    return 0;
}

int koe_profile_save(const koe_profile_t *profile,
                      const char          *path,
                      const char          *passphrase)
{
    if (koe_identity_save(&profile->keys, path, passphrase) != 0)
        return -1;

    char name_path[512];
    snprintf(name_path, sizeof(name_path), "%s/identity.name", path);
    FILE *f = fopen(name_path, "w");
    if (!f) return -1;
    fprintf(f, "%s\n", profile->name);
    fclose(f);

    return 0;
}

/* --- Contact book ------------------------------------------------------- */

void koe_contact_book_init(koe_contact_book_t *book)
{
    book->head  = NULL;
    book->count = 0;
}

void koe_contact_book_free(koe_contact_book_t *book)
{
    koe_contact_node_t *n = book->head;
    while (n) {
        koe_contact_node_t *next = n->next;
        sodium_memzero(n, sizeof(*n));
        free(n);
        n = next;
    }
    book->head  = NULL;
    book->count = 0;
}

int koe_contact_add(koe_contact_book_t *book,
                     const uint8_t       pk[KOE_ED25519_PK_LEN],
                     const char         *name)
{
    /* Reject duplicates. */
    if (koe_contact_find(book, pk))
        return -1;

    koe_contact_node_t *node = calloc(1, sizeof(*node));
    if (!node) return -1;

    memcpy(node->contact.pk, pk, KOE_ED25519_PK_LEN);
    strncpy(node->contact.name, name, KOE_NAME_MAX - 1);
    koe_profile_short_id(node->contact.short_id, pk);
    node->contact.added_at = time(NULL);

    node->next  = book->head;
    book->head  = node;
    book->count++;

    return 0;
}

koe_contact_t *koe_contact_find(koe_contact_book_t *book,
                                  const uint8_t       pk[KOE_ED25519_PK_LEN])
{
    for (koe_contact_node_t *n = book->head; n; n = n->next) {
        if (memcmp(n->contact.pk, pk, KOE_ED25519_PK_LEN) == 0)
            return &n->contact;
    }
    return NULL;
}

int koe_contact_remove(koe_contact_book_t *book,
                        const uint8_t       pk[KOE_ED25519_PK_LEN])
{
    koe_contact_node_t **pp = &book->head;
    while (*pp) {
        if (memcmp((*pp)->contact.pk, pk, KOE_ED25519_PK_LEN) == 0) {
            koe_contact_node_t *dead = *pp;
            *pp = dead->next;
            sodium_memzero(dead, sizeof(*dead));
            free(dead);
            book->count--;
            return 0;
        }
        pp = &(*pp)->next;
    }
    return -1;
}

int koe_contact_set_verified(koe_contact_book_t *book,
                               const uint8_t       pk[KOE_ED25519_PK_LEN],
                               int                 verified)
{
    koe_contact_t *c = koe_contact_find(book, pk);
    if (!c) return -1;
    c->verified = verified;
    return 0;
}

void koe_contact_update_seen(koe_contact_book_t *book,
                               const uint8_t       pk[KOE_ED25519_PK_LEN])
{
    koe_contact_t *c = koe_contact_find(book, pk);
    if (c) c->last_seen = time(NULL);
}

/* Contact book serialisation: write a flat array of koe_contact_t structs,
 * encrypt the whole thing with the local identity key, prepend a nonce. */
int koe_contact_book_save(const koe_contact_book_t *book,
                            const char               *path,
                            const koe_identity_t     *id)
{
    size_t n     = book->count;
    size_t plain_len = n * sizeof(koe_contact_t);

    uint8_t *plain = calloc(1, plain_len + 1);
    if (!plain && plain_len) return -1;

    size_t i = 0;
    for (koe_contact_node_t *node = book->head; node; node = node->next, i++)
        memcpy(plain + i * sizeof(koe_contact_t), &node->contact, sizeof(koe_contact_t));

    /* Derive an encryption key from the identity public key (not the secret
     * key — we don't need confidentiality here, just integrity and binding). */
    uint8_t key[KOE_SESSION_KEY_LEN];
    koe_hash(key, id->pk, KOE_ED25519_PK_LEN);

    uint8_t nonce[KOE_NONCE_LEN];
    koe_nonce_generate(nonce);

    uint8_t *ct = malloc(plain_len + KOE_TAG_LEN);
    if (!ct) { free(plain); return -1; }

    koe_encrypt(ct, plain, plain_len, nonce, key);

    sodium_memzero(plain, plain_len);
    free(plain);
    sodium_memzero(key, sizeof(key));

    FILE *f = fopen(path, "wb");
    if (!f) { free(ct); return -1; }
    fwrite(&n,     sizeof(n),               1, f);
    fwrite(nonce,  KOE_NONCE_LEN,           1, f);
    fwrite(ct,     plain_len + KOE_TAG_LEN, 1, f);
    fclose(f);
    free(ct);
    return 0;
}

int koe_contact_book_load(koe_contact_book_t   *book,
                            const char           *path,
                            const koe_identity_t *id)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    size_t n;
    if (fread(&n, sizeof(n), 1, f) != 1) { fclose(f); return -1; }

    uint8_t nonce[KOE_NONCE_LEN];
    if (fread(nonce, KOE_NONCE_LEN, 1, f) != 1) { fclose(f); return -1; }

    size_t ct_len = n * sizeof(koe_contact_t) + KOE_TAG_LEN;
    uint8_t *ct = malloc(ct_len);
    if (!ct) { fclose(f); return -1; }

    if (fread(ct, ct_len, 1, f) != 1) { free(ct); fclose(f); return -1; }
    fclose(f);

    uint8_t key[KOE_SESSION_KEY_LEN];
    koe_hash(key, id->pk, KOE_ED25519_PK_LEN);

    uint8_t *plain = malloc(n * sizeof(koe_contact_t));
    if (!plain) { free(ct); return -1; }

    int rc = koe_decrypt(plain, ct, ct_len, nonce, key);
    free(ct);
    sodium_memzero(key, sizeof(key));

    if (rc != 0) { free(plain); return -1; }

    koe_contact_book_init(book);
    for (size_t i = 0; i < n; i++) {
        koe_contact_t *c = (koe_contact_t *)(plain + i * sizeof(koe_contact_t));
        koe_contact_add(book, c->pk, c->name);
        koe_contact_t *stored = koe_contact_find(book, c->pk);
        if (stored) {
            stored->added_at  = c->added_at;
            stored->last_seen = c->last_seen;
            stored->verified  = c->verified;
            stored->blocked   = c->blocked;
        }
    }

    sodium_memzero(plain, n * sizeof(koe_contact_t));
    free(plain);
    return 0;
}
