/*
 * koe_channel.h - Broadcast channels (one sender, many receivers).
 *
 * A channel is a one-to-many construct: the owner publishes messages that any
 * subscriber can read, but subscribers cannot send to the channel. There is no
 * group-chat dynamic here; use a Matrix-compatible server for that.
 *
 * Channel identity: a channel is identified by the owner's Ed25519 public key
 * plus a 16-byte channel ID. The owner signs every post with their identity
 * key; subscribers verify the signature before displaying the post.
 *
 * Distribution: channel posts are propagated via the relay server to all
 * online subscribers. Offline subscribers receive queued posts the next time
 * they connect. Subscribers do not know who else is subscribed.
 *
 * Privacy: message content is encrypted per-subscriber with that subscriber's
 * session key. The relay server cannot read channel content.
 */

#ifndef KOE_CHANNEL_H
#define KOE_CHANNEL_H

#include "koe_crypto.h"
#include "koe_packet.h"
#include <stdint.h>
#include <time.h>

#define KOE_CHANNEL_ID_LEN   16
#define KOE_CHANNEL_NAME_MAX 64

typedef struct {
    uint8_t  id[KOE_CHANNEL_ID_LEN];
    uint8_t  owner_pk[KOE_ED25519_PK_LEN];
    char     name[KOE_CHANNEL_NAME_MAX];
    time_t   created_at;
    uint64_t post_count;
} koe_channel_t;

typedef struct {
    uint64_t  seq;
    time_t    posted_at;
    uint8_t   author_pk[KOE_ED25519_PK_LEN];
    uint8_t  *body;          /* plaintext, heap-allocated */
    size_t    body_len;
    uint8_t   sig[KOE_ED25519_SIG_LEN];
} koe_channel_post_t;

/* --- Channel management ------------------------------------------------- */

/* Create a new channel owned by `owner`. Fills *ch and writes channel
 * metadata to `data_dir`. Returns 0 on success, -1 on error. */
int koe_channel_create(koe_channel_t        *ch,
                        const char           *name,
                        const koe_identity_t *owner,
                        const char           *data_dir);

/* Load a channel from disk. */
int koe_channel_load(koe_channel_t *ch,
                      const uint8_t  channel_id[KOE_CHANNEL_ID_LEN],
                      const char    *data_dir);

/* --- Publishing --------------------------------------------------------- */

/* Build an encrypted KOE_TYPE_CHANNEL packet for one subscriber.
 * The post body is signed by the owner before encryption.
 * pkt->payload is heap-allocated; call koe_packet_free when done. */
int koe_channel_build_post(koe_packet_t          *pkt,
                             const koe_channel_t   *ch,
                             const koe_identity_t  *owner,
                             const uint8_t          subscriber_pk[KOE_ED25519_PK_LEN],
                             const koe_session_t   *sess,
                             const uint8_t         *body,
                             size_t                 body_len);

/* --- Subscription ------------------------------------------------------- */

/* Decrypt and verify an incoming channel post.
 * Returns 0 if the signature and MAC are both valid, -1 otherwise. */
int koe_channel_receive_post(koe_channel_post_t  *post,
                               const koe_packet_t  *pkt,
                               const koe_session_t *sess);

void koe_channel_post_free(koe_channel_post_t *post);

#endif /* KOE_CHANNEL_H */
