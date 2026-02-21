#include "koe_queue.h"
#include "koe_packet.h"
#include "koe_db.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

int koe_queue_open(koe_queue_t *q, koe_db_conn_t *db, int max_per_peer)
{
    q->db           = db;
    q->max_per_peer = max_per_peer > 0 ? max_per_peer : KOE_QUEUE_MAX_PER_PEER;
    q->count        = 0;
    return koe_db_migrate(db);
}

void koe_queue_close(koe_queue_t *q)
{
    q->db = NULL;
}

int64_t koe_queue_push(koe_queue_t *q, const koe_packet_t *pkt)
{
    if (koe_queue_count(q, pkt->header.to) >= q->max_per_peer) {
        /* Drop oldest entry for this peer to make room. */
        koe_db_queued_t old = {0};
        if (koe_db_queue_pop(q->db, pkt->header.to, &old) == 0)
            free(old.packet_bytes);
    }

    /* Serialise packet. */
    size_t   buf_len = KOE_HEADER_SIZE + pkt->header.length;
    uint8_t *buf     = malloc(buf_len);
    if (!buf) return -1;
    koe_packet_serialise(pkt, buf, buf_len);

    koe_db_queued_t q_entry = {0};
    memcpy(q_entry.to_pk, pkt->header.to, 32);
    q_entry.packet_bytes = buf;
    q_entry.packet_len   = buf_len;
    q_entry.queued_at    = (int64_t)time(NULL);
    q_entry.expires_at   = q_entry.queued_at + KOE_QUEUE_TTL_SECONDS;
    q_entry.sequence     = q_entry.queued_at; /* monotonic approx */

    int rc = koe_db_queue_push(q->db, &q_entry);
    free(buf);
    return rc == 0 ? q_entry.id : -1;
}

int koe_queue_pop(koe_queue_t *q, const uint8_t to_pk[KOE_ED25519_PK_LEN],
                   koe_packet_t *pkt_out)
{
    koe_db_queued_t entry = {0};
    if (koe_db_queue_pop(q->db, to_pk, &entry) != 0) return -1;

    int rc = koe_packet_deserialise(pkt_out, entry.packet_bytes, entry.packet_len);
    free(entry.packet_bytes);
    return rc;
}

int koe_queue_count(koe_queue_t *q, const uint8_t to_pk[KOE_ED25519_PK_LEN])
{
    return koe_db_queue_count(q->db, to_pk);
}

int koe_queue_drain(koe_queue_t *q, const uint8_t to_pk[KOE_ED25519_PK_LEN],
                     int (*send_fn)(const koe_packet_t *, void *), void *ctx)
{
    int sent = 0;
    koe_packet_t pkt;
    while (koe_queue_pop(q, to_pk, &pkt) == 0) {
        int rc = send_fn(&pkt, ctx);
        koe_packet_free(&pkt);
        if (rc != 0) break;
        sent++;
    }
    return sent;
}

int koe_queue_expire(koe_queue_t *q)
{
    return koe_db_queue_expire(q->db, (int64_t)time(NULL));
}
