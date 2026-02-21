/*
 * koe_store.c - Encrypted append-only conversation history.
 */

#include "koe_store.h"
#include "koe_crypto.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <sodium.h>
#include <unistd.h>

/* Each entry on disk: [4 bytes length][KOE_NONCE_LEN nonce][ciphertext]
 * The plaintext is a serialised koe_message_t (fixed fields) followed by
 * the variable-length body. */

#define INDEX_INIT_CAP 64

static int store_index_grow(koe_store_t *store)
{
    size_t new_cap = store->capacity ? store->capacity * 2 : INDEX_INIT_CAP;
    uint64_t *offsets = realloc(store->offsets, new_cap * sizeof(uint64_t));
    uint32_t *lengths = realloc(store->lengths, new_cap * sizeof(uint32_t));
    if (!offsets || !lengths) return -1;
    store->offsets   = offsets;
    store->lengths   = lengths;
    store->capacity  = new_cap;
    return 0;
}

int koe_store_open(koe_store_t *store, const char *path, const koe_identity_t *local_id)
{
    memset(store, 0, sizeof(*store));
    strncpy(store->path, path, sizeof(store->path) - 1);
    store->local_id = local_id;
    store->fd       = -1;

    /* Build the index by scanning the file. */
    FILE *f = fopen(path, "rb");
    if (!f) return 0;   /* new conversation, empty store */

    uint64_t offset = 0;
    uint32_t entry_len;

    while (fread(&entry_len, 4, 1, f) == 1) {
        if (store->count >= store->capacity && store_index_grow(store) != 0) break;
        store->offsets[store->count] = offset;
        store->lengths[store->count] = entry_len;
        store->count++;
        offset += 4 + entry_len;
        fseek(f, entry_len, SEEK_CUR);
    }

    fclose(f);
    return 0;
}

void koe_store_close(koe_store_t *store)
{
    free(store->offsets);
    free(store->lengths);
    memset(store, 0, sizeof(*store));
}

static uint8_t *store_derive_key(const koe_identity_t *id)
{
    uint8_t *key = malloc(KOE_SESSION_KEY_LEN);
    if (!key) return NULL;
    koe_hash(key, id->pk, KOE_ED25519_PK_LEN);
    return key;
}

/* Serialise a message into a flat buffer (does not include variable body;
 * that is appended separately). Returns the number of bytes written. */
static size_t msg_fixed_size(void) { return 8 + 1 + 1 + 32 + 32 + 8 + 4 + 64; }

static void msg_serialise_fixed(uint8_t *buf, const koe_message_t *msg)
{
    uint8_t *p = buf;
    memcpy(p, &msg->id,                   8); p += 8;
    *p++ = (uint8_t)msg->type;
    *p++ = (uint8_t)msg->status;
    memcpy(p,  msg->from,                 32); p += 32;
    memcpy(p,  msg->to,                   32); p += 32;
    memcpy(p, &msg->sent_at,              8); p += 8;
    memcpy(p, &msg->destruct_ttl_seconds, 4); p += 4;
    memcpy(p,  msg->sig, KOE_ED25519_SIG_LEN);
}

int koe_store_append(koe_store_t *store, const koe_message_t *msg)
{
    if (!msg || msg->ephemeral) return 0;

    uint8_t *key = store_derive_key(store->local_id);
    if (!key) return -1;

    size_t fixed   = msg_fixed_size();
    size_t plain_len = fixed + msg->body_len;
    uint8_t *plain = malloc(plain_len);
    if (!plain) { free(key); return -1; }

    msg_serialise_fixed(plain, msg);
    if (msg->body_len > 0)
        memcpy(plain + fixed, msg->body, msg->body_len);

    uint8_t nonce[KOE_NONCE_LEN];
    koe_nonce_generate(nonce);

    size_t ct_len = plain_len + KOE_TAG_LEN;
    uint8_t *ct = malloc(ct_len);
    if (!ct) { sodium_memzero(plain, plain_len); free(plain); free(key); return -1; }

    koe_encrypt(ct, plain, plain_len, nonce, key);
    sodium_memzero(plain, plain_len);
    free(plain);
    sodium_memzero(key, KOE_SESSION_KEY_LEN);
    free(key);

    uint32_t entry_len = (uint32_t)(KOE_NONCE_LEN + ct_len);

    FILE *f = fopen(store->path, "ab");
    if (!f) { free(ct); return -1; }

    uint64_t offset = (uint64_t)ftell(f);
    fwrite(&entry_len, 4,           1, f);
    fwrite(nonce,      KOE_NONCE_LEN, 1, f);
    fwrite(ct,         ct_len,       1, f);
    fclose(f);
    free(ct);

    if (store->count >= store->capacity && store_index_grow(store) != 0)
        return 0;   /* message written, just can't index it */

    store->offsets[store->count] = offset;
    store->lengths[store->count] = entry_len;
    store->count++;

    return 0;
}

koe_message_t *koe_store_get(koe_store_t *store, size_t index)
{
    if (index >= store->count) return NULL;

    uint8_t *key = store_derive_key(store->local_id);
    if (!key) return NULL;

    FILE *f = fopen(store->path, "rb");
    if (!f) { free(key); return NULL; }

    fseek(f, (long)(store->offsets[index] + 4), SEEK_SET);

    uint32_t entry_len = store->lengths[index];
    uint8_t *buf = malloc(entry_len);
    if (!buf) { fclose(f); free(key); return NULL; }

    if (fread(buf, entry_len, 1, f) != 1) { free(buf); fclose(f); free(key); return NULL; }
    fclose(f);

    uint8_t *nonce = buf;
    uint8_t *ct    = buf + KOE_NONCE_LEN;
    size_t   ct_len = entry_len - KOE_NONCE_LEN;
    size_t   plain_len = ct_len - KOE_TAG_LEN;

    uint8_t *plain = malloc(plain_len);
    if (!plain) { free(buf); free(key); return NULL; }

    int rc = koe_decrypt(plain, ct, ct_len, nonce, key);
    free(buf);
    sodium_memzero(key, KOE_SESSION_KEY_LEN);
    free(key);

    if (rc != 0) { free(plain); return NULL; }

    size_t fixed = msg_fixed_size();
    if (plain_len < fixed) { free(plain); return NULL; }

    koe_message_t *msg = calloc(1, sizeof(*msg));
    if (!msg) { free(plain); return NULL; }

    uint8_t *p = plain;
    memcpy(&msg->id,                   p, 8); p += 8;
    msg->type   = (koe_msg_type_t)*p++;
    msg->status = (koe_msg_status_t)*p++;
    memcpy(msg->from,                  p, 32); p += 32;
    memcpy(msg->to,                    p, 32); p += 32;
    memcpy(&msg->sent_at,              p, 8); p += 8;
    memcpy(&msg->destruct_ttl_seconds, p, 4); p += 4;
    memcpy(msg->sig,                   p, KOE_ED25519_SIG_LEN);

    size_t body_len = plain_len - fixed;
    if (body_len > 0) {
        msg->body = malloc(body_len);
        if (msg->body) {
            memcpy(msg->body, plain + fixed, body_len);
            msg->body_len = body_len;
        }
    }

    sodium_memzero(plain, plain_len);
    free(plain);
    return msg;
}

size_t koe_store_get_recent(koe_store_t    *store,
                              koe_message_t **msgs,
                              size_t          count)
{
    size_t available = store->count < count ? store->count : count;
    size_t start     = store->count - available;
    size_t got       = 0;

    for (size_t i = 0; i < available; i++) {
        msgs[i] = koe_store_get(store, start + i);
        if (msgs[i]) got++;
    }
    return got;
}

size_t koe_store_count(const koe_store_t *store)
{
    return store->count;
}

int koe_store_delete(koe_store_t *store, uint64_t message_id)
{
    /* Find the message first. */
    size_t target = store->count;
    for (size_t i = 0; i < store->count; i++) {
        koe_message_t *msg = koe_store_get(store, i);
        if (!msg) continue;
        int found = (msg->id == message_id);
        koe_message_free(msg);
        if (found) { target = i; break; }
    }
    if (target == store->count) return -1;

    /* Rewrite the file without the target entry. */
    char tmp_path[512];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", store->path);
    FILE *out = fopen(tmp_path, "wb");
    if (!out) return -1;

    FILE *in = fopen(store->path, "rb");
    if (!in) { fclose(out); return -1; }

    for (size_t i = 0; i < store->count; i++) {
        if (i == target) {
            fseek(in, (long)(4 + store->lengths[i]), SEEK_CUR);
            continue;
        }
        uint32_t len = store->lengths[i];
        uint8_t *buf = malloc(len);
        if (!buf) continue;
        fread(buf, len, 1, in);
        fwrite(&len, 4, 1, out);
        fwrite(buf, len, 1, out);
        free(buf);
    }

    fclose(in);
    fclose(out);
    rename(tmp_path, store->path);

    /* Rebuild index. */
    free(store->offsets);
    free(store->lengths);
    store->offsets  = NULL;
    store->lengths  = NULL;
    store->count    = 0;
    store->capacity = 0;

    const koe_identity_t *id = store->local_id;
    char path_copy[512];
    strncpy(path_copy, store->path, sizeof(path_copy) - 1);
    koe_store_open(store, path_copy, id);

    return 0;
}

int koe_store_purge_expired(koe_store_t *store)
{
    int removed = 0;
    /* Collect IDs to remove to avoid modifying the store while iterating. */
    uint64_t *expired = malloc(store->count * sizeof(uint64_t));
    size_t n_expired  = 0;

    for (size_t i = 0; i < store->count; i++) {
        koe_message_t *msg = koe_store_get(store, i);
        if (!msg) continue;
        if (koe_message_should_destruct(msg))
            expired[n_expired++] = msg->id;
        koe_message_free(msg);
    }

    for (size_t i = 0; i < n_expired; i++) {
        if (koe_store_delete(store, expired[i]) == 0)
            removed++;
    }

    free(expired);
    return removed;
}

int koe_store_wipe(koe_store_t *store)
{
    /* Overwrite the file with zeroes before unlinking. */
    FILE *f = fopen(store->path, "r+b");
    if (f) {
        uint8_t zero[4096] = {0};
        fseek(f, 0, SEEK_END);
        long size = ftell(f);
        fseek(f, 0, SEEK_SET);
        while (size > 0) {
            size_t chunk = (size_t)size < sizeof(zero) ? (size_t)size : sizeof(zero);
            fwrite(zero, 1, chunk, f);
            size -= (long)chunk;
        }
        fclose(f);
    }
    unlink(store->path);
    koe_store_close(store);
    return 0;
}
