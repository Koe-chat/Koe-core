/*
 * koe_message.c - Message lifecycle, signing, self-destruct, scheduling.
 */

#include "koe_message.h"
#include "koe_crypto.h"
#include "koe_packet.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sodium.h>

/* Monotonically increasing local message ID. Not thread-safe; single-threaded
 * event loop is assumed. */
static uint64_t next_message_id = 1;

koe_message_t *koe_message_alloc(koe_msg_type_t   type,
                                   const uint8_t    to[KOE_ED25519_PK_LEN],
                                   const uint8_t   *body,
                                   size_t           body_len)
{
    koe_message_t *msg = calloc(1, sizeof(*msg));
    if (!msg) return NULL;

    msg->id      = next_message_id++;
    msg->type    = type;
    msg->status  = KOE_STATUS_PENDING;
    msg->sent_at = time(NULL);

    memcpy(msg->to, to, KOE_ED25519_PK_LEN);

    if (body_len > 0) {
        msg->body = malloc(body_len);
        if (!msg->body) { free(msg); return NULL; }
        memcpy(msg->body, body, body_len);
        msg->body_len = body_len;
    }

    return msg;
}

void koe_message_free(koe_message_t *msg)
{
    if (!msg) return;
    if (msg->body) {
        sodium_memzero(msg->body, msg->body_len);
        free(msg->body);
    }
    sodium_memzero(msg, sizeof(*msg));
    free(msg);
}

int koe_message_sign(koe_message_t        *msg,
                      const koe_identity_t *id)
{
    memcpy(msg->from, id->pk, KOE_ED25519_PK_LEN);
    return koe_sign(msg->sig, msg->body, msg->body_len, id);
}

int koe_message_verify(const koe_message_t *msg)
{
    return koe_verify(msg->sig, msg->body, msg->body_len, msg->from);
}

void koe_message_set_destruct(koe_message_t *msg, uint32_t seconds)
{
    msg->destruct_ttl_seconds = seconds;
    msg->destruct_at          = 0;   /* set on delivery by the receiver */
}

int koe_message_should_destruct(const koe_message_t *msg)
{
    if (msg->destruct_ttl_seconds == 0 || msg->destruct_at == 0)
        return 0;
    return time(NULL) >= msg->destruct_at;
}

void koe_message_destruct(koe_message_t *msg)
{
    if (msg->body) {
        sodium_memzero(msg->body, msg->body_len);
        free(msg->body);
        msg->body     = NULL;
        msg->body_len = 0;
    }
    msg->status = KOE_STATUS_DESTROYED;
}

void koe_message_schedule(koe_message_t *msg, time_t send_at)
{
    msg->send_at = send_at;
}

int koe_message_is_due(const koe_message_t *msg)
{
    if (msg->send_at == 0) return 1;   /* no schedule = send now */
    return time(NULL) >= msg->send_at;
}

int koe_message_fragment_count(const koe_message_t *msg)
{
    if (msg->body_len == 0) return 1;
    return (int)((msg->body_len + KOE_MAX_PAYLOAD - 1) / KOE_MAX_PAYLOAD);
}

int koe_message_build_fragment(const koe_message_t *msg,
                                 int                  index,
                                 koe_packet_t        *pkt,
                                 const koe_session_t *sess)
{
    int total = koe_message_fragment_count(msg);
    if (index < 0 || index >= total) return -1;

    size_t offset   = (size_t)index * KOE_MAX_PAYLOAD;
    size_t frag_len = msg->body_len - offset;
    if (frag_len > KOE_MAX_PAYLOAD)
        frag_len = KOE_MAX_PAYLOAD;

    uint8_t flags = KOE_FLAG_ENCRYPTED;
    if (index < total - 1) flags |= KOE_FLAG_FRAGMENTED;
    else                   flags |= KOE_FLAG_LAST_FRAG;
    if (msg->ephemeral) flags |= KOE_FLAG_EPHEMERAL;

    /* Plaintext fragment: 8 bytes of header (msg_id + fragment index) + body slice. */
    size_t plain_len = 8 + frag_len;
    uint8_t *plain = malloc(plain_len);
    if (!plain) return -1;

    uint64_t id_be = (uint64_t)msg->id;   /* could htonll but keeping simple */
    memcpy(plain, &id_be, 8);
    memcpy(plain + 8, msg->body + offset, frag_len);

    koe_packet_t *p = koe_packet_alloc(KOE_TYPE_MSG, flags,
                                        plain_len + KOE_TAG_LEN);
    if (!p) { free(plain); return -1; }

    uint8_t nonce[KOE_NONCE_LEN];
    koe_nonce_generate(nonce);
    memcpy(p->header.nonce, nonce, KOE_NONCE_LEN);
    memcpy(p->header.from,  msg->from, KOE_ID_LEN);
    memcpy(p->header.to,    msg->to,   KOE_ID_LEN);

    koe_encrypt(p->payload, plain, plain_len, nonce, sess->tx_key);

    free(plain);
    *pkt = *p;
    pkt->payload = p->payload;
    p->payload = NULL;
    koe_packet_free(p);

    return 0;
}
