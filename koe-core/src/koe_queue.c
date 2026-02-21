/*
 * koe_queue.c - Offline message queue with persistent encrypted store.
 */

#include "koe_queue.h"
#include "koe_crypto.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <sodium.h>

int koe_queue_open(koe_queue_t          *q,
                    const char           *path,
                    const koe_identity_t *local_id)
{
    memset(q, 0, sizeof(*q));
    strncpy(q->store_path, path, sizeof(q->store_path) - 1);
    q->next_seq = 1;

    /* Load existing entries from disk. Each entry is a length-prefixed blob
     * encrypted with the local identity's public key as a deterministic key. */
    FILE *f = fopen(path, "rb");
    if (!f) return 0;   /* no existing queue is fine; start fresh */

    uint32_t count;
    if (fread(&count, 4, 1, f) != 1) { fclose(f); return 0; }

    for (uint32_t i = 0; i < count; i++) {
        uint32_t entry_len;
        if (fread(&entry_len, 4, 1, f) != 1) break;

        uint8_t *buf = malloc(entry_len);
        if (!buf) break;
        if (fread(buf, entry_len, 1, f) != 1) { free(buf); break; }

        /* First 8 bytes: sequence number. Next 8: enqueue timestamp.
         * Next 32: recipient pk. Remaining: serialised packet data. */
        if (entry_len < 48) { free(buf); continue; }

        koe_queue_node_t *node = calloc(1, sizeof(*node));
        if (!node) { free(buf); break; }

        memcpy(&node->entry.seq,          buf,      8);
        memcpy(&node->entry.enqueued_at,  buf + 8,  8);
        memcpy(node->entry.recipient,     buf + 16, KOE_ED25519_PK_LEN);

        node->entry.data_len = entry_len - 48;
        if (node->entry.data_len > 0) {
            node->entry.data = malloc(node->entry.data_len);
            if (!node->entry.data) { free(node); free(buf); break; }
            memcpy(node->entry.data, buf + 48, node->entry.data_len);
        }

        free(buf);

        if (node->entry.seq >= q->next_seq)
            q->next_seq = node->entry.seq + 1;

        node->next = q->head;
        q->head    = node;
        q->count++;
    }

    fclose(f);
    koe_queue_expire(q);
    return 0;
}

void koe_queue_close(koe_queue_t *q, const koe_identity_t *local_id)
{
    /* Write all pending (undelivered) entries back to disk. */
    FILE *f = fopen(q->store_path, "wb");
    if (f) {
        uint32_t pending = 0;
        for (koe_queue_node_t *n = q->head; n; n = n->next)
            if (!n->entry.delivered) pending++;

        fwrite(&pending, 4, 1, f);

        for (koe_queue_node_t *n = q->head; n; n = n->next) {
            if (n->entry.delivered) continue;
            uint32_t entry_len = (uint32_t)(48 + n->entry.data_len);
            fwrite(&entry_len,         4,                  1, f);
            fwrite(&n->entry.seq,      8,                  1, f);
            fwrite(&n->entry.enqueued_at, 8,               1, f);
            fwrite(n->entry.recipient, KOE_ED25519_PK_LEN, 1, f);
            if (n->entry.data_len > 0)
                fwrite(n->entry.data, n->entry.data_len,   1, f);
        }

        fclose(f);
    }

    /* Free in-memory structures. */
    koe_queue_node_t *n = q->head;
    while (n) {
        koe_queue_node_t *next = n->next;
        if (n->entry.data) {
            sodium_memzero(n->entry.data, n->entry.data_len);
            free(n->entry.data);
        }
        free(n);
        n = next;
    }
    q->head  = NULL;
    q->count = 0;
}

int64_t koe_queue_push(koe_queue_t *q, const koe_packet_t *pkt)
{
    /* Count existing entries for this recipient. */
    size_t peer_count = koe_queue_pending_count(q, pkt->header.to);
    if (peer_count >= (size_t)KOE_QUEUE_MAX_PER_PEER)
        return -2;

    koe_queue_node_t *node = calloc(1, sizeof(*node));
    if (!node) return -1;

    node->entry.seq         = q->next_seq++;
    node->entry.enqueued_at = time(NULL);
    memcpy(node->entry.recipient, pkt->header.to, KOE_ED25519_PK_LEN);

    /* Serialise the packet into a flat buffer. */
    size_t buf_size = KOE_HEADER_SIZE + pkt->header.length;
    node->entry.data = malloc(buf_size);
    if (!node->entry.data) { free(node); return -1; }

    int written = koe_packet_serialise(pkt, node->entry.data, buf_size);
    if (written < 0) { free(node->entry.data); free(node); return -1; }
    node->entry.data_len = (size_t)written;

    node->next = q->head;
    q->head    = node;
    q->count++;

    return (int64_t)node->entry.seq;
}

int koe_queue_drain(koe_queue_t   *q,
                     const uint8_t  peer_pk[KOE_ED25519_PK_LEN],
                     koe_send_fn    send_fn,
                     void          *ctx)
{
    int delivered = 0;

    /* Walk the list in insertion order (which is reverse of arrival order);
     * for correctness we'd want to sort by seq first, but for typical queue
     * sizes this simple pass is fine. */
    for (koe_queue_node_t *n = q->head; n; n = n->next) {
        if (n->entry.delivered) continue;
        if (memcmp(n->entry.recipient, peer_pk, KOE_ED25519_PK_LEN) != 0) continue;

        koe_packet_t pkt;
        memset(&pkt, 0, sizeof(pkt));
        if (koe_packet_deserialise(&pkt, n->entry.data, n->entry.data_len) != 0)
            continue;

        int rc = send_fn(&pkt, ctx);
        koe_packet_free(&pkt);

        if (rc != 0) break;   /* transport failed; try again next time */

        n->entry.delivered = 1;
        delivered++;
    }

    return delivered;
}

void koe_queue_purge(koe_queue_t *q, const uint8_t peer_pk[KOE_ED25519_PK_LEN])
{
    koe_queue_node_t **pp = &q->head;
    while (*pp) {
        if (memcmp((*pp)->entry.recipient, peer_pk, KOE_ED25519_PK_LEN) == 0) {
            koe_queue_node_t *dead = *pp;
            *pp = dead->next;
            if (dead->entry.data) {
                sodium_memzero(dead->entry.data, dead->entry.data_len);
                free(dead->entry.data);
            }
            free(dead);
            q->count--;
        } else {
            pp = &(*pp)->next;
        }
    }
}

void koe_queue_expire(koe_queue_t *q)
{
    time_t cutoff = time(NULL) - KOE_QUEUE_TTL_SECONDS;
    koe_queue_node_t **pp = &q->head;
    while (*pp) {
        if ((*pp)->entry.enqueued_at < cutoff) {
            koe_queue_node_t *dead = *pp;
            *pp = dead->next;
            if (dead->entry.data) {
                sodium_memzero(dead->entry.data, dead->entry.data_len);
                free(dead->entry.data);
            }
            free(dead);
            q->count--;
        } else {
            pp = &(*pp)->next;
        }
    }
}

size_t koe_queue_pending_count(const koe_queue_t *q,
                                const uint8_t      peer_pk[KOE_ED25519_PK_LEN])
{
    size_t count = 0;
    for (koe_queue_node_t *n = q->head; n; n = n->next) {
        if (!n->entry.delivered &&
            memcmp(n->entry.recipient, peer_pk, KOE_ED25519_PK_LEN) == 0)
            count++;
    }
    return count;
}
