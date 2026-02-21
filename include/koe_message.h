/*
 * koe_message.h - Application-level message management.
 */
#ifndef KOE_MESSAGE_H
#define KOE_MESSAGE_H

#include "koe_crypto.h"
#include "koe_packet.h"
#include <stdint.h>
#include <time.h>

typedef enum {
    KOE_MSG_TEXT  = 0,
    KOE_MSG_AUDIO = 1,
    KOE_MSG_MEDIA = 2,
    KOE_MSG_GROUP = 3,
} koe_msg_type_t;

typedef enum {
    KOE_STATUS_PENDING   = 0,
    KOE_STATUS_SENT      = 1,
    KOE_STATUS_DELIVERED = 2,
    KOE_STATUS_READ      = 3,
    KOE_STATUS_FAILED    = 4,
} koe_msg_status_t;

typedef struct {
    uint64_t        id;
    koe_msg_type_t  type;
    koe_msg_status_t status;
    uint8_t         from[KOE_ED25519_PK_LEN];
    uint8_t         to[KOE_ED25519_PK_LEN];
    uint8_t        *body;
    size_t          body_len;
    uint8_t         sig[KOE_ED25519_SIG_LEN];
    int64_t         sent_at;
    int64_t         delivered_at;
    int64_t         read_at;
    uint32_t        destruct_after_seconds;
    int64_t         destruct_at;
    int64_t         scheduled_at;
    int             is_secret;
} koe_message_t;

koe_message_t *koe_message_alloc(koe_msg_type_t type, const uint8_t to[KOE_ED25519_PK_LEN],
                                   const uint8_t *body, size_t body_len);
void  koe_message_free(koe_message_t *msg);
int   koe_message_sign(koe_message_t *msg, const koe_identity_t *id);
int   koe_message_verify(const koe_message_t *msg);
void  koe_message_set_destruct(koe_message_t *msg, uint32_t ttl_seconds);
int   koe_message_should_destruct(const koe_message_t *msg);
void  koe_message_schedule(koe_message_t *msg, int64_t send_at_unix);
int   koe_message_is_due(const koe_message_t *msg);
int   koe_message_encrypt(const koe_message_t *msg, const koe_session_t *sess,
                            koe_packet_t *pkt_out);
int   koe_message_decrypt(koe_message_t *msg, const koe_packet_t *pkt,
                            const koe_session_t *sess);

#endif /* KOE_MESSAGE_H */
