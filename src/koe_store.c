#include "koe_store.h"
#include "koe_crypto.h"
#include "koe_db.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

int koe_store_open(koe_store_t *store, koe_db_conn_t *db)
{
    memset(store, 0, sizeof(*store));
    store->db = db;
    return koe_db_migrate(db);
}

void koe_store_close(koe_store_t *store) { store->db = NULL; }

int koe_store_put(koe_store_t *store, const koe_message_t *msg,
                   const koe_identity_t *local_id)
{
    /* Encrypt body with a key derived from the local identity's SK. */
    uint8_t store_key[KOE_SESSION_KEY_LEN];
    crypto_generichash_state state;
    crypto_generichash_init(&state, NULL, 0, KOE_SESSION_KEY_LEN);
    crypto_generichash_update(&state, local_id->sk, KOE_ED25519_SK_LEN);
    crypto_generichash_update(&state, (const uint8_t *)"koe-store", 9);
    crypto_generichash_final(&state, store_key, KOE_SESSION_KEY_LEN);

    size_t  ct_len = msg->body_len + KOE_TAG_LEN;
    uint8_t *ct    = malloc(ct_len);
    if (!ct) { koe_memzero(store_key, sizeof(store_key)); return -1; }

    uint8_t nonce[KOE_NONCE_LEN];
    koe_nonce_generate(nonce);
    int rc = koe_encrypt(ct, msg->body, msg->body_len, nonce, store_key);
    koe_memzero(store_key, sizeof(store_key));
    if (rc != 0) { free(ct); return -1; }

    koe_db_message_t row = {0};
    row.id              = (int64_t)msg->id;
    memcpy(row.from_pk, msg->from, 32);
    memcpy(row.to_pk,   msg->to,   32);
    row.body_encrypted  = ct;
    row.body_len        = ct_len;
    row.sent_at         = msg->sent_at;
    row.delivered_at    = msg->delivered_at;
    row.read_at         = msg->read_at;
    row.destruct_at     = msg->destruct_at;
    row.status          = msg->status;
    row.is_secret       = msg->is_secret;

    rc = koe_db_message_insert(store->db, &row);
    free(ct);
    return rc;
}

int koe_store_get(koe_store_t *store, uint64_t id, koe_message_t *out,
                   const koe_identity_t *local_id)
{
    /* Query by ID using a peer PK scan — simplified for now. */
    /* TODO: add a get-by-id method to koe_db. */
    (void)store; (void)id; (void)out; (void)local_id;
    return -1;
}

int koe_store_delete(koe_store_t *store, uint64_t id)
{
    return koe_db_message_delete(store->db, (int64_t)id);
}

int koe_store_sweep_destruct(koe_store_t *store)
{
    return koe_db_destruct_sweep(store->db, (int64_t)time(NULL));
}

int koe_store_wipe(koe_store_t *store)
{
    /* Delete all messages. */
    koe_db_destruct_sweep(store->db, (int64_t)(time(NULL) + 9999999));
    return 0;
}
