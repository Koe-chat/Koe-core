/*
 * koe_store.h - Encrypted local message store (wraps koe_db).
 */
#ifndef KOE_STORE_H
#define KOE_STORE_H

#include "koe_crypto.h"
#include "koe_db.h"
#include "koe_message.h"
#include <stdint.h>

typedef struct {
    koe_db_conn_t *db;
    char           path[512];
    int            secret_unlocked;
} koe_store_t;

int  koe_store_open(koe_store_t *store, koe_db_conn_t *db);
void koe_store_close(koe_store_t *store);
int  koe_store_put(koe_store_t *store, const koe_message_t *msg,
                    const koe_identity_t *local_id);
int  koe_store_get(koe_store_t *store, uint64_t id, koe_message_t *out,
                    const koe_identity_t *local_id);
int  koe_store_delete(koe_store_t *store, uint64_t id);
int  koe_store_sweep_destruct(koe_store_t *store);
int  koe_store_wipe(koe_store_t *store);

#endif /* KOE_STORE_H */
