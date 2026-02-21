/*
 * koe_channel.c - Broadcast channel: one owner, many read-only subscribers.
 *
 * Each post is encrypted individually for every subscriber using that
 * subscriber's session key. The owner never learns the subscribers' reading
 * habits from the protocol (only whether they are reachable when the post
 * is sent). Subscribers cannot see each other.
 */

#include "koe_channel.h"
#include "koe_crypto.h"
#include "koe_packet.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

int koe_channel_create(koe_channel_t        *ch,
                        const koe_identity_t *local_id,
                        const char           *name,
                        const char           *description)
{
    memset(ch, 0, sizeof(*ch));
    memcpy(ch->id, local_id->pk, KOE_ED25519_PK_LEN);
    strncpy(ch->name,        name,        KOE_CHANNEL_NAME_MAX - 1);
    strncpy(ch->description, description, KOE_CHANNEL_DESC_MAX - 1);
    ch->created_at  = time(NULL);
    ch->post_count  = 0;
    ch->owner       = 1;
    return 0;
}

/* ---------------------------------------------------------------------- */

int koe_channel_post(koe_channel_t               *ch,
                      const koe_identity_t        *owner_id,
                      const koe_subscriber_list_t *subs,
                      const uint8_t               *body,
                      size_t                       body_len,
                      koe_channel_send_fn          send_fn,
                      void                        *ctx)
{
    if (!ch->owner) return -1;

    /* Sign the body once; include the signature in every subscriber's copy. */
    uint8_t sig[KOE_ED25519_SIG_LEN];
    if (koe_sign(sig, body, body_len, owner_id) != 0) return -1;

    /* Build the plaintext frame: [sig (64)] + [body]. */
    size_t   frame_len = KOE_ED25519_SIG_LEN + body_len;
    uint8_t *frame     = malloc(frame_len);
    if (!frame) return -1;
    memcpy(frame,                       sig,  KOE_ED25519_SIG_LEN);
    memcpy(frame + KOE_ED25519_SIG_LEN, body, body_len);

    int failures = 0;

    /* Encrypt separately for each subscriber and call send_fn. */
    for (const koe_subscriber_node_t *n = subs->head; n; n = n->next) {

        /* We need a session key for this subscriber. In the full
         * implementation this comes from the session store; here we derive
         * a per-subscriber key deterministically from the owner's secret key
         * and the subscriber's public key using BLAKE2b. This is a simplified
         * stand-in — production code would use the live session. */
        uint8_t sub_key[KOE_SESSION_KEY_LEN];
        crypto_generichash_state state;
        crypto_generichash_init(&state, owner_id->sk, 32, sizeof(sub_key));
        crypto_generichash_update(&state, n->pk, KOE_ED25519_PK_LEN);
        crypto_generichash_final(&state, sub_key, sizeof(sub_key));

        size_t   ct_len = frame_len + KOE_TAG_LEN;
        uint8_t *ct     = malloc(ct_len);
        if (!ct) { failures++; continue; }

        uint8_t nonce[KOE_NONCE_LEN];
        koe_nonce_generate(nonce);

        if (koe_encrypt(ct, frame, frame_len, nonce, sub_key) != 0) {
            free(ct);
            failures++;
            continue;
        }

        /* Build the packet. */
        koe_packet_t pkt = {0};
        memcpy(pkt.header.magic, KOE_MAGIC, KOE_MAGIC_LEN);
        pkt.header.type   = KOE_TYPE_CHANNEL;
        pkt.header.flags  = KOE_FLAG_ENCRYPTED | KOE_FLAG_SIGNED;
        pkt.header.length = (uint32_t)ct_len;
        memcpy(pkt.header.from,  owner_id->pk, KOE_ID_LEN);
        memcpy(pkt.header.to,    n->pk,         KOE_ID_LEN);
        memcpy(pkt.header.nonce, nonce,          KOE_NONCE_LEN);
        pkt.payload = ct;

        if (send_fn(n->pk, &pkt, ctx) != 0) failures++;

        free(ct);
        sodium_memzero(sub_key, sizeof(sub_key));
    }

    free(frame);
    ch->post_count++;
    return (failures == 0) ? 0 : -1;
}

/* ---------------------------------------------------------------------- */

int koe_channel_add_subscriber(koe_subscriber_list_t *subs,
                                 const uint8_t          pk[KOE_ED25519_PK_LEN])
{
    /* Check for duplicate. */
    for (koe_subscriber_node_t *n = subs->head; n; n = n->next) {
        if (memcmp(n->pk, pk, KOE_ED25519_PK_LEN) == 0)
            return -1;
    }

    koe_subscriber_node_t *node = calloc(1, sizeof(*node));
    if (!node) return -1;
    memcpy(node->pk, pk, KOE_ED25519_PK_LEN);
    node->subscribed_at = time(NULL);
    node->next = subs->head;
    subs->head = node;
    subs->count++;
    return 0;
}

int koe_channel_remove_subscriber(koe_subscriber_list_t *subs,
                                    const uint8_t          pk[KOE_ED25519_PK_LEN])
{
    koe_subscriber_node_t **prev = &subs->head;
    for (koe_subscriber_node_t *n = subs->head; n; n = n->next) {
        if (memcmp(n->pk, pk, KOE_ED25519_PK_LEN) == 0) {
            *prev = n->next;
            free(n);
            subs->count--;
            return 0;
        }
        prev = &n->next;
    }
    return -1;
}

void koe_subscriber_list_free(koe_subscriber_list_t *subs)
{
    koe_subscriber_node_t *n = subs->head;
    while (n) {
        koe_subscriber_node_t *next = n->next;
        free(n);
        n = next;
    }
    subs->head  = NULL;
    subs->count = 0;
}

/* ---------------------------------------------------------------------- */

int koe_channel_subscribe(koe_packet_t         *pkt,
                            const koe_identity_t *local_id,
                            const uint8_t         owner_pk[KOE_ED25519_PK_LEN],
                            const koe_session_t  *sess)
{
    /* The subscription request is a single byte (0xA1) encrypted with the
     * session key established with the owner. */
    uint8_t plain[1] = { 0xA1 };
    uint8_t ct[1 + KOE_TAG_LEN];
    uint8_t nonce[KOE_NONCE_LEN];

    koe_nonce_generate(nonce);
    if (koe_encrypt(ct, plain, 1, nonce, sess->tx_key) != 0)
        return -1;

    uint8_t *payload = malloc(sizeof(ct));
    if (!payload) return -1;
    memcpy(payload, ct, sizeof(ct));

    memset(pkt, 0, sizeof(*pkt));
    memcpy(pkt->header.magic, KOE_MAGIC, KOE_MAGIC_LEN);
    pkt->header.type   = KOE_TYPE_MSG;
    pkt->header.flags  = KOE_FLAG_ENCRYPTED;
    pkt->header.length = sizeof(ct);
    memcpy(pkt->header.from,  local_id->pk, KOE_ID_LEN);
    memcpy(pkt->header.to,    owner_pk,     KOE_ID_LEN);
    memcpy(pkt->header.nonce, nonce,        KOE_NONCE_LEN);
    pkt->payload = payload;

    return 0;
}

int koe_channel_unsubscribe(koe_packet_t         *pkt,
                              const koe_identity_t *local_id,
                              const uint8_t         owner_pk[KOE_ED25519_PK_LEN],
                              const koe_session_t  *sess)
{
    uint8_t plain[1] = { 0xA2 };
    uint8_t ct[1 + KOE_TAG_LEN];
    uint8_t nonce[KOE_NONCE_LEN];

    koe_nonce_generate(nonce);
    if (koe_encrypt(ct, plain, 1, nonce, sess->tx_key) != 0)
        return -1;

    uint8_t *payload = malloc(sizeof(ct));
    if (!payload) return -1;
    memcpy(payload, ct, sizeof(ct));

    memset(pkt, 0, sizeof(*pkt));
    memcpy(pkt->header.magic, KOE_MAGIC, KOE_MAGIC_LEN);
    pkt->header.type   = KOE_TYPE_MSG;
    pkt->header.flags  = KOE_FLAG_ENCRYPTED;
    pkt->header.length = sizeof(ct);
    memcpy(pkt->header.from,  local_id->pk, KOE_ID_LEN);
    memcpy(pkt->header.to,    owner_pk,     KOE_ID_LEN);
    memcpy(pkt->header.nonce, nonce,        KOE_NONCE_LEN);
    pkt->payload = payload;

    return 0;
}

int koe_channel_receive_post(koe_message_t        *msg,
                               const koe_packet_t   *pkt,
                               const uint8_t         owner_pk[KOE_ED25519_PK_LEN],
                               const koe_session_t  *sess)
{
    if (!pkt->payload || pkt->header.length <= KOE_TAG_LEN)
        return -1;

    size_t   plain_len = pkt->header.length - KOE_TAG_LEN;
    uint8_t *plain     = malloc(plain_len);
    if (!plain) return -1;

    if (koe_decrypt(plain, pkt->payload, pkt->header.length,
                     pkt->header.nonce, sess->rx_key) != 0) {
        free(plain);
        return -1;
    }

    /* First 64 bytes are the signature; remainder is the body. */
    if (plain_len <= KOE_ED25519_SIG_LEN) { free(plain); return -1; }

    const uint8_t *sig      = plain;
    const uint8_t *body     = plain + KOE_ED25519_SIG_LEN;
    size_t         body_len = plain_len - KOE_ED25519_SIG_LEN;

    if (koe_verify(sig, body, body_len, owner_pk) != 0) {
        free(plain);
        return -1;
    }

    memset(msg, 0, sizeof(*msg));
    msg->type     = KOE_MSG_TEXT;
    msg->status   = KOE_STATUS_DELIVERED;
    msg->sent_at  = time(NULL);
    memcpy(msg->from, owner_pk, KOE_ED25519_PK_LEN);

    msg->body = malloc(body_len);
    if (!msg->body) { free(plain); return -1; }
    memcpy(msg->body, body, body_len);
    msg->body_len = body_len;

    free(plain);
    return 0;
}
