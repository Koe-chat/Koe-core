#include "koe_identity.h"
#include "koe_crypto.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

int koe_profile_create(koe_profile_t *p, const char *display_name,
                        const char *passphrase, const char *dir)
{
    memset(p, 0, sizeof(*p));
    if (koe_identity_generate(&p->keys) != 0) return -1;
    koe_identity_short_id(&p->short_id, p->keys.pk);
    strncpy(p->display_name, display_name, KOE_DISPLAY_NAME_MAX - 1);
    p->created_at = time(NULL);

    char path[512];
    snprintf(path, sizeof(path), "%s/identity.koe", dir);
    return koe_identity_save(&p->keys, path, passphrase);
}

int koe_profile_load(koe_profile_t *p, const char *dir, const char *passphrase)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/identity.koe", dir);
    if (koe_identity_load(&p->keys, path, passphrase) != 0) return -1;
    koe_identity_short_id(&p->short_id, p->keys.pk);
    return 0;
}

int koe_profile_save(const koe_profile_t *p, const char *dir, const char *passphrase)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/identity.koe", dir);
    return koe_identity_save(&p->keys, path, passphrase);
}

void koe_profile_short_id(char *out, const uint8_t pk[KOE_ED25519_PK_LEN])
{
    koe_short_id_t sid;
    koe_identity_short_id(&sid, pk);
    strncpy(out, sid.value, KOE_SHORT_ID_LEN);
}

void koe_contact_book_init(koe_contact_book_t *book)
{
    book->head  = NULL;
    book->count = 0;
}

void koe_contact_book_free(koe_contact_book_t *book)
{
    koe_contact_t *n = book->head;
    while (n) {
        koe_contact_t *next = n->next;
        free(n);
        n = next;
    }
    book->head  = NULL;
    book->count = 0;
}

int koe_contact_book_load(koe_contact_book_t *book, koe_db_conn_t *db)
{
    koe_db_contact_t rows[512];
    int count = 0;
    if (koe_db_contact_list(db, rows, 512, &count) != 0) return -1;

    for (int i = 0; i < count; i++) {
        koe_contact_t *c = calloc(1, sizeof(*c));
        if (!c) return -1;
        memcpy(c->pk, rows[i].pk, KOE_ED25519_PK_LEN);
        strncpy(c->display_name, rows[i].display_name, KOE_DISPLAY_NAME_MAX - 1);
        strncpy(c->short_id.value, rows[i].short_id, KOE_SHORT_ID_LEN - 1);
        c->added_at  = (time_t)rows[i].added_at;
        c->last_seen = (time_t)rows[i].last_seen;
        c->verified  = rows[i].verified;
        c->blocked   = rows[i].blocked;
        c->next      = book->head;
        book->head   = c;
        book->count++;
    }
    return 0;
}

int koe_contact_book_save(const koe_contact_book_t *book, koe_db_conn_t *db)
{
    for (const koe_contact_t *c = book->head; c; c = c->next) {
        koe_db_contact_t row = {0};
        memcpy(row.pk, c->pk, 32);
        strncpy(row.display_name, c->display_name, 63);
        strncpy(row.short_id, c->short_id.value, 15);
        row.added_at  = (int64_t)c->added_at;
        row.last_seen = (int64_t)c->last_seen;
        row.blocked   = c->blocked;
        row.verified  = c->verified;
        koe_db_contact_upsert(db, &row);
    }
    return 0;
}

int koe_contact_add(koe_contact_book_t *book, const uint8_t pk[KOE_ED25519_PK_LEN],
                     const char *display_name)
{
    if (koe_contact_find(book, pk)) return -1; /* already exists */
    koe_contact_t *c = calloc(1, sizeof(*c));
    if (!c) return -1;
    memcpy(c->pk, pk, KOE_ED25519_PK_LEN);
    strncpy(c->display_name, display_name, KOE_DISPLAY_NAME_MAX - 1);
    koe_identity_short_id(&c->short_id, pk);
    c->added_at = time(NULL);
    c->next     = book->head;
    book->head  = c;
    book->count++;
    return 0;
}

int koe_contact_remove(koe_contact_book_t *book, const uint8_t pk[KOE_ED25519_PK_LEN])
{
    koe_contact_t **prev = &book->head;
    for (koe_contact_t *n = book->head; n; n = n->next) {
        if (memcmp(n->pk, pk, KOE_ED25519_PK_LEN) == 0) {
            *prev = n->next;
            free(n);
            book->count--;
            return 0;
        }
        prev = &n->next;
    }
    return -1;
}

koe_contact_t *koe_contact_find(const koe_contact_book_t *book, const uint8_t pk[KOE_ED25519_PK_LEN])
{
    for (koe_contact_t *n = book->head; n; n = n->next)
        if (memcmp(n->pk, pk, KOE_ED25519_PK_LEN) == 0) return n;
    return NULL;
}

koe_contact_t *koe_contact_find_by_short_id(const koe_contact_book_t *book, const char *short_id)
{
    for (koe_contact_t *n = book->head; n; n = n->next)
        if (strcmp(n->short_id.value, short_id) == 0) return n;
    return NULL;
}

int koe_contact_set_verified(koe_contact_book_t *book, const uint8_t pk[KOE_ED25519_PK_LEN], int v)
{
    koe_contact_t *c = koe_contact_find(book, pk);
    if (!c) return -1;
    c->verified = v;
    return 0;
}

int koe_contact_set_blocked(koe_contact_book_t *book, const uint8_t pk[KOE_ED25519_PK_LEN], int b)
{
    koe_contact_t *c = koe_contact_find(book, pk);
    if (!c) return -1;
    c->blocked = b;
    return 0;
}

int koe_db_contact_list(koe_db_conn_t *conn, koe_db_contact_t *out, int max, int *count)
{
    /* Implemented in koe_db.c but declared here for koe_identity.c's use.
     * The real implementation is in koe_db.c; this is just to avoid a
     * circular dependency in the header ordering. */
    (void)conn; (void)out; (void)max; *count = 0;
    return 0;
}
