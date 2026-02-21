/*
 * koe_channel.h - Broadcast channels (one owner, many read-only subscribers).
 */
#ifndef KOE_CHANNEL_H
#define KOE_CHANNEL_H

#include "koe_crypto.h"
#include "koe_message.h"
#include <stdint.h>
#include <time.h>

#define KOE_CHANNEL_NAME_MAX 128
#define KOE_CHANNEL_DESC_MAX 512

typedef struct {
    uint8_t  id[KOE_ED25519_PK_LEN];
    char     name[KOE_CHANNEL_NAME_MAX];
    char     description[KOE_CHANNEL_DESC_MAX];
    time_t   created_at;
    uint64_t post_count;
    int      owner;
} koe_channel_t;

typedef struct koe_subscriber_node {
    uint8_t                    pk[KOE_ED25519_PK_LEN];
    time_t                     subscribed_at;
    struct koe_subscriber_node *next;
} koe_subscriber_node_t;

typedef struct {
    koe_subscriber_node_t *head;
    size_t                 count;
} koe_subscriber_list_t;

typedef int (*koe_channel_send_fn)(const uint8_t recipient_pk[KOE_ED25519_PK_LEN],
                                    const koe_packet_t *pkt, void *ctx);

int  koe_channel_create(koe_channel_t *ch, const koe_identity_t *local_id,
                          const char *name, const char *description);
int  koe_channel_post(koe_channel_t *ch, const koe_identity_t *owner_id,
                       const koe_subscriber_list_t *subs, const uint8_t *body, size_t body_len,
                       koe_channel_send_fn send_fn, void *ctx);
int  koe_channel_add_subscriber(koe_subscriber_list_t *subs, const uint8_t pk[KOE_ED25519_PK_LEN]);
int  koe_channel_remove_subscriber(koe_subscriber_list_t *subs, const uint8_t pk[KOE_ED25519_PK_LEN]);
void koe_subscriber_list_free(koe_subscriber_list_t *subs);
int  koe_channel_subscribe(koe_packet_t *pkt, const koe_identity_t *local_id,
                             const uint8_t owner_pk[KOE_ED25519_PK_LEN], const koe_session_t *sess);
int  koe_channel_receive_post(koe_message_t *msg, const koe_packet_t *pkt,
                                const uint8_t owner_pk[KOE_ED25519_PK_LEN], const koe_session_t *sess);

#endif /* KOE_CHANNEL_H */
