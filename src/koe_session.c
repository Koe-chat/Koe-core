#include "koe_session.h"
#include <string.h>
#include <time.h>

void koe_session_table_init(koe_session_table_t *tbl) {
    memset(tbl, 0, sizeof(*tbl));
}

int koe_session_table_add(koe_session_table_t *tbl,
                          const uint8_t peer_pk[KOE_ED25519_PK_LEN],
                          const koe_session_t *sess) {
    if (!tbl || !peer_pk || !sess) return -1;
    if (tbl->count >= KOE_MAX_SESSIONS) return -1;

    for (int i = 0; i < KOE_MAX_SESSIONS; i++) {
        if (!tbl->entries[i].active) {
            memcpy(tbl->entries[i].peer_pk, peer_pk, KOE_ED25519_PK_LEN);
            memcpy(&tbl->entries[i].sess, sess, sizeof(koe_session_t));
            tbl->entries[i].created_at = time(NULL);
            tbl->entries[i].last_used = time(NULL);
            tbl->entries[i].active = 1;
            tbl->count++;
            return 0;
        }
    }
    return -1;
}

koe_session_t *koe_session_table_find(koe_session_table_t *tbl,
                                       const uint8_t peer_pk[KOE_ED25519_PK_LEN]) {
    if (!tbl || !peer_pk) return NULL;

    for (int i = 0; i < KOE_MAX_SESSIONS; i++) {
        if (tbl->entries[i].active &&
            memcmp(tbl->entries[i].peer_pk, peer_pk, KOE_ED25519_PK_LEN) == 0) {
            tbl->entries[i].last_used = time(NULL);
            return &tbl->entries[i].sess;
        }
    }
    return NULL;
}

int koe_session_table_remove(koe_session_table_t *tbl,
                             const uint8_t peer_pk[KOE_ED25519_PK_LEN]) {
    if (!tbl || !peer_pk) return -1;

    for (int i = 0; i < KOE_MAX_SESSIONS; i++) {
        if (tbl->entries[i].active &&
            memcmp(tbl->entries[i].peer_pk, peer_pk, KOE_ED25519_PK_LEN) == 0) {
            memset(&tbl->entries[i], 0, sizeof(koe_session_entry_t));
            tbl->count--;
            return 0;
        }
    }
    return -1;
}

void koe_session_table_cleanup(koe_session_table_t *tbl, int64_t max_age_seconds) {
    if (!tbl || max_age_seconds <= 0) return;

    int64_t now = time(NULL);
    for (int i = 0; i < KOE_MAX_SESSIONS; i++) {
        if (tbl->entries[i].active) {
            if (now - tbl->entries[i].last_used > max_age_seconds) {
                memset(&tbl->entries[i], 0, sizeof(koe_session_entry_t));
                tbl->count--;
            }
        }
    }
}