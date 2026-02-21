/*
 * koe_queue.h - Persistent offline message queue.
 *
 * When a message cannot be delivered because the recipient is unreachable,
 * it is pushed onto a per-recipient queue on disk. The queue drains
 * automatically when the peer comes back online.
 *
 * Storage: each entry is serialised as a length-prefixed binary blob and
 * appended to a per-recipient file under the queue directory. The entire
 * file is encrypted with the local identity key, so undelivered messages
 * are not exposed in plaintext on a stolen device.
 *
 * Sequence numbers are per-(sender, recipient) pair and monotonically
 * increasing. The recipient uses them to detect and discard duplicates and
 * to reassemble fragments in order.
 */

#ifndef KOE_QUEUE_H
#define KOE_QUEUE_H

#include "koe_crypto.h"
#include "koe_packet.h"
#include <stdint.h>
#include <time.h>

#define KOE_QUEUE_MAX_PER_PEER   512
#define KOE_QUEUE_TTL_SECONDS    (7 * 24 * 3600)   /* one week */

typedef struct {
    uint64_t  seq;
    time_t    enqueued_at;
    uint8_t   recipient[KOE_ED25519_PK_LEN];
    uint8_t  *data;         /* serialised koe_packet_t, heap-allocated */
    size_t    data_len;
    int       delivered;
} koe_queue_entry_t;

typedef struct koe_queue_node {
    koe_queue_entry_t      entry;
    struct koe_queue_node *next;
} koe_queue_node_t;

typedef struct {
    koe_queue_node_t *head;
    size_t            count;
    char              store_path[256];
    uint64_t          next_seq;
} koe_queue_t;

/* Callback used by koe_queue_drain to hand packets to the transport layer.
 * Return 0 to continue draining, non-zero to stop. */
typedef int (*koe_send_fn)(const koe_packet_t *pkt, void *ctx);

/* --- Lifecycle ---------------------------------------------------------- */

/* Open (or create) the queue store at `path`. Loads undelivered entries
 * from a previous run; expired entries are silently dropped during load. */
int koe_queue_open(koe_queue_t          *q,
                    const char           *path,
                    const koe_identity_t *local_id);

/* Flush pending entries to disk and free all in-memory structures. */
void koe_queue_close(koe_queue_t          *q,
                      const koe_identity_t *local_id);

/* --- Queue operations --------------------------------------------------- */

/* Enqueue a packet for later delivery. Returns the assigned sequence number,
 * -1 on general error, or -2 if KOE_QUEUE_MAX_PER_PEER is exceeded. */
int64_t koe_queue_push(koe_queue_t        *q,
                        const koe_packet_t *pkt);

/* Deliver all queued messages for a peer that just came online.
 * Calls `send_fn` for each pending entry in sequence order. If `send_fn`
 * returns non-zero, draining stops and the entry stays in the queue for
 * the next attempt. Successfully delivered entries are removed. */
int koe_queue_drain(koe_queue_t   *q,
                     const uint8_t  peer_pk[KOE_ED25519_PK_LEN],
                     koe_send_fn    send_fn,
                     void          *ctx);

/* Remove all entries for a given peer (e.g. when a contact is deleted). */
void koe_queue_purge(koe_queue_t   *q,
                      const uint8_t  peer_pk[KOE_ED25519_PK_LEN]);

/* Drop all entries older than KOE_QUEUE_TTL_SECONDS. Called automatically
 * during koe_queue_open; available for manual invocation as well. */
void koe_queue_expire(koe_queue_t *q);

/* Return the number of pending (undelivered) entries for a specific peer. */
size_t koe_queue_pending_count(const koe_queue_t *q,
                                const uint8_t      peer_pk[KOE_ED25519_PK_LEN]);

#endif /* KOE_QUEUE_H */
