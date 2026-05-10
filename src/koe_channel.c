#include "koe_channel.h"
#include "koe_crypto.h"
#include <sodium.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int koe_channel_create(koe_channel_t *ch, const koe_identity_t *local_id,
                        const char *name, const char *description)
{
    memset(ch, 0, sizeof(*ch));
    memcpy(ch->id, local_id->pk, KOE_ED25519_PK_LEN);
    strncpy(ch->name, name, KOE_CHANNEL_NAME_MAX - 1);
    strncpy(ch->description, description, KOE_CHANNEL_DESC_MAX - 1);
    ch->created_at = time(NULL);
    ch->owner      = 1;
    return 0;
}

int koe_channel_add_subscriber(koe_subscriber_list_t *subs, const uint8_t pk[KOE_ED25519_PK_LEN])
{
    for (koe_subscriber_node_t *n = subs->head; n; n = n->next)
        if (memcmp(n->pk, pk, KOE_ED25519_PK_LEN) == 0) return -1;

    koe_subscriber_node_t *node = calloc(1, sizeof(*node));
    if (!node) return -1;
    memcpy(node->pk, pk, KOE_ED25519_PK_LEN);
    node->subscribed_at = time(NULL);
    node->next          = subs->head;
    subs->head          = node;
    subs->count++;
    return 0;
}

int koe_channel_remove_subscriber(koe_subscriber_list_t *subs, const uint8_t pk[KOE_ED25519_PK_LEN])
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

int koe_channel_post(koe_channel_t *ch, const koe_identity_t *owner_id,
                      const koe_subscriber_list_t *subs,
                      const uint8_t *body, size_t body_len,
                      koe_channel_send_fn send_fn, void *ctx)
{
    if (!ch->owner) return -1;

    for (const koe_subscriber_node_t *sub = subs->head; sub; sub = sub->next) {
        /* Derive a per-subscriber session key from owner sk + subscriber pk. */
        uint8_t sub_key[KOE_SESSION_KEY_LEN];
        crypto_generichash_state state;
        crypto_generichash_init(&state, NULL, 0, KOE_SESSION_KEY_LEN);
        crypto_generichash_update(&state, owner_id->sk, KOE_ED25519_SK_LEN);
        crypto_generichash_update(&state, sub->pk,      KOE_ED25519_PK_LEN);
        crypto_generichash_final(&state, sub_key, KOE_SESSION_KEY_LEN);

        size_t  ct_len = body_len + KOE_TAG_LEN;
        uint8_t *ct    = malloc(ct_len);
        if (!ct) { koe_memzero(sub_key, sizeof(sub_key)); continue; }

        uint8_t nonce[KOE_NONCE_LEN];
        koe_nonce_generate(nonce);

        if (koe_encrypt(ct, body, body_len, nonce, sub_key) != 0) {
            free(ct); koe_memzero(sub_key, sizeof(sub_key)); continue;
        }
        koe_memzero(sub_key, sizeof(sub_key));

        koe_packet_t pkt;
        koe_packet_init(&pkt, KOE_TYPE_CHANNEL, KOE_FLAG_ENCRYPTED | KOE_FLAG_SIGNED);
        pkt.header.length = (uint32_t)ct_len;
        memcpy(pkt.header.from, owner_id->pk, KOE_ID_LEN);
        memcpy(pkt.header.to,   sub->pk,      KOE_ID_LEN);
        memcpy(pkt.header.nonce, nonce,        KOE_NONCE_LEN);

        /* Append Ed25519 signature of body. */
        uint8_t sig[KOE_ED25519_SIG_LEN];
        koe_sign(sig, body, body_len, owner_id);
        /* TODO: append sig to payload in a structured envelope. */

        pkt.header.checksum = koe_packet_checksum(&pkt.header);
        pkt.payload = ct;

        send_fn(sub->pk, &pkt, ctx);
        koe_packet_free(&pkt);
    }

    ch->post_count++;
    return 0;
}

int koe_channel_subscribe(koe_packet_t *pkt, const koe_identity_t *local_id,
                            const uint8_t owner_pk[KOE_ED25519_PK_LEN],
                            const koe_session_t *sess)
{
    /* Subscribe request: a signed message to the channel owner. */
    uint8_t plain[KOE_ED25519_PK_LEN];
    memcpy(plain, local_id->pk, KOE_ED25519_PK_LEN);

    size_t  ct_len = KOE_ED25519_PK_LEN + KOE_TAG_LEN;
    uint8_t *ct    = malloc(ct_len);
    if (!ct) return -1;

    uint8_t nonce[KOE_NONCE_LEN];
    koe_nonce_generate(nonce);
    if (koe_encrypt(ct, plain, KOE_ED25519_PK_LEN, nonce, sess->tx_key) != 0) {
        free(ct); return -1;
    }

    koe_packet_init(pkt, KOE_TYPE_MSG, KOE_FLAG_ENCRYPTED);
    pkt->header.length = (uint32_t)ct_len;
    memcpy(pkt->header.from, local_id->pk, KOE_ID_LEN);
    memcpy(pkt->header.to,   owner_pk,     KOE_ID_LEN);
    memcpy(pkt->header.nonce, nonce,        KOE_NONCE_LEN);
    pkt->header.checksum = koe_packet_checksum(&pkt->header);
    pkt->payload = ct;
    return 0;
}

int koe_channel_receive_post(koe_message_t *msg, const koe_packet_t *pkt,
                               const uint8_t owner_pk[KOE_ED25519_PK_LEN],
                               const koe_session_t *sess)
{
    return koe_message_decrypt(msg, pkt, sess);
    (void)owner_pk;
}
