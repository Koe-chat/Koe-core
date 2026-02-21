/*
 * koe_queue.h - Persistent encrypted offline message queue.
 *
 * Messages are stored in the SQLite database when a peer is unreachable.
 * The queue is per-peer, ordered by sequence number.  Entries expire after
 * KOE_QUEUE_TTL_SECONDS.  The maximum per-peer depth is configurable.
 */
#ifndef KOE_QUEUE_H
#define KOE_QUEUE_H

#include "koe_crypto.h"
#include "koe_packet.h"
#include "koe_db.h"
#include <stdint.h>
#include <time.h>

#define KOE_QUEUE_MAX_PER_PEER     512
#define KOE_QUEUE_TTL_SECONDS      (7 * 24 * 3600)

typedef struct {
    koe_db_conn_t *db;
    int            max_per_peer;
    size_t         count;
} koe_queue_t;

int     koe_queue_open(koe_queue_t *q, koe_db_conn_t *db, int max_per_peer);
void    koe_queue_close(koe_queue_t *q);
int64_t koe_queue_push(koe_queue_t *q, const koe_packet_t *pkt);
int     koe_queue_pop(koe_queue_t *q, const uint8_t to_pk[KOE_ED25519_PK_LEN],
                       koe_packet_t *pkt_out);
int     koe_queue_count(koe_queue_t *q, const uint8_t to_pk[KOE_ED25519_PK_LEN]);
int     koe_queue_drain(koe_queue_t *q, const uint8_t to_pk[KOE_ED25519_PK_LEN],
                         int (*send_fn)(const koe_packet_t *, void *), void *ctx);
int     koe_queue_expire(koe_queue_t *q);

#endif /* KOE_QUEUE_H */
