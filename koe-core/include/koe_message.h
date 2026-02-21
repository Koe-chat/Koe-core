/*
 * koe_message.h - Application-level message representation.
 *
 * A koe_message_t lives above the packet layer. One message may be split
 * across multiple packets if its body exceeds KOE_MAX_PAYLOAD; reassembly
 * happens here before the message reaches the UI layer.
 *
 * Self-destruct is a cooperative mechanism: the sender sets a TTL and the
 * receiver honours it. There is no cryptographic enforcement—both sides run
 * their own countdown starting from the moment the message is delivered.
 * This matches the Signal model and keeps the protocol simple.
 *
 * Scheduled messages are held locally and released to the transport when
 * their send_at timestamp is reached. The scheduler is driven by the main
 * event loop, not by a background thread, to keep the core single-threaded.
 */

#ifndef KOE_MESSAGE_H
#define KOE_MESSAGE_H

#include "koe_crypto.h"
#include <stdint.h>
#include <time.h>

typedef enum {
    KOE_MSG_TEXT       = 0,
    KOE_MSG_AUDIO_NOTE,     /* recorded voice note, not a live call */
    KOE_MSG_FILE,
    KOE_MSG_CONTACT_CARD,
    KOE_MSG_CALL_START,
    KOE_MSG_CALL_END,
} koe_msg_type_t;

typedef enum {
    KOE_STATUS_PENDING   = 0,   /* in queue, not yet sent         */
    KOE_STATUS_SENT,             /* handed to transport layer      */
    KOE_STATUS_DELIVERED,        /* ACK received from peer device  */
    KOE_STATUS_READ,             /* peer opened the conversation   */
    KOE_STATUS_FAILED,
    KOE_STATUS_DESTROYED,        /* self-destruct completed        */
} koe_msg_status_t;

typedef struct {
    uint64_t         id;                           /* local unique message ID */
    koe_msg_type_t   type;
    koe_msg_status_t status;

    uint8_t          from[KOE_ED25519_PK_LEN];
    uint8_t          to[KOE_ED25519_PK_LEN];

    time_t           sent_at;
    time_t           delivered_at;
    time_t           read_at;

    /* Self-destruct: 0 disables. destruct_at is set on the receiving end
     * when an ACK is sent back (i.e. TTL starts on delivery, not send). */
    uint32_t         destruct_ttl_seconds;
    time_t           destruct_at;

    /* Scheduled send: 0 means send immediately. */
    time_t           send_at;

    /* Set for messages that must not be written to conversation history. */
    int              ephemeral;

    uint8_t         *body;         /* plaintext content, heap-allocated */
    size_t           body_len;

    /* Ed25519 signature over body. Computed by the sender, verified on
     * arrival. An invalid signature causes the message to be silently
     * dropped before it reaches the UI. */
    uint8_t          sig[KOE_ED25519_SIG_LEN];
} koe_message_t;

/* --- Lifecycle ---------------------------------------------------------- */

/* Allocate and initialise an outgoing message. `body` is copied internally;
 * the caller retains ownership of its buffer. Returns NULL on error. */
koe_message_t *koe_message_alloc(koe_msg_type_t   type,
                                   const uint8_t    to[KOE_ED25519_PK_LEN],
                                   const uint8_t   *body,
                                   size_t           body_len);

/* Overwrite the body with zeroes and free the message. */
void koe_message_free(koe_message_t *msg);

/* --- Signing / verification -------------------------------------------- */

/* Sign the message body with the local identity key. Must be called before
 * handing the message to the send path. */
int koe_message_sign(koe_message_t        *msg,
                      const koe_identity_t *id);

/* Verify the body signature against msg->from. Returns 0 if valid, -1 if
 * the signature does not match. */
int koe_message_verify(const koe_message_t *msg);

/* --- Self-destruct ------------------------------------------------------ */

/* Set a self-destruct TTL. 0 disables the timer. */
void koe_message_set_destruct(koe_message_t *msg, uint32_t seconds);

/* Return 1 if the message has passed its destruct_at timestamp. */
int koe_message_should_destruct(const koe_message_t *msg);

/* Overwrite the body with zeroes, free it, and set status to DESTROYED. */
void koe_message_destruct(koe_message_t *msg);

/* --- Scheduled sending -------------------------------------------------- */

/* Set the absolute Unix timestamp at which this message should be sent.
 * 0 means send as soon as possible. */
void koe_message_schedule(koe_message_t *msg, time_t send_at);

/* Return 1 if a scheduled message is due to be sent right now. */
int koe_message_is_due(const koe_message_t *msg);

/* --- Fragmentation helpers --------------------------------------------- */

/* Return the number of packets needed to carry this message body. */
int koe_message_fragment_count(const koe_message_t *msg);

/* Fill `pkt` with fragment number `index` (0-based) of `msg`.
 * Sets KOE_FLAG_FRAGMENTED and KOE_FLAG_LAST_FRAG as appropriate.
 * Returns 0 on success, -1 on error. */
int koe_message_build_fragment(const koe_message_t *msg,
                                 int                  index,
                                 koe_packet_t        *pkt,
                                 const koe_session_t *sess);

#endif /* KOE_MESSAGE_H */
