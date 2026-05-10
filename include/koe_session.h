#ifndef KOE_SESSION_H
#define KOE_SESSION_H

#include "koe_crypto.h"
#include "koe_packet.h"
#include <stdint.h>
#include <stddef.h>

#define KOE_MAX_SESSIONS 256

typedef struct {
    uint8_t           peer_pk[KOE_ED25519_PK_LEN];
    koe_session_t     sess;
    int64_t           created_at;
    int64_t           last_used;
    int               active;
} koe_session_entry_t;

typedef struct {
    koe_session_entry_t entries[KOE_MAX_SESSIONS];
    int                 count;
} koe_session_table_t;

void koe_session_table_init(koe_session_table_t *tbl);

int koe_session_table_add(koe_session_table_t *tbl,
                          const uint8_t peer_pk[KOE_ED25519_PK_LEN],
                          const koe_session_t *sess);

koe_session_t *koe_session_table_find(koe_session_table_t *tbl,
                                       const uint8_t peer_pk[KOE_ED25519_PK_LEN]);

int koe_session_table_remove(koe_session_table_t *tbl,
                             const uint8_t peer_pk[KOE_ED25519_PK_LEN]);

void koe_session_table_cleanup(koe_session_table_t *tbl, int64_t max_age_seconds);

#endif