/*
 * koe_event.h - Event loop supporting both polling and real-time callbacks.
 *
 * Two consumption models are available and can be used simultaneously:
 *
 *   Polling model (koe-chat TUI):
 *     Call koe_event_poll() on each render frame (~16 ms).  Events queued
 *     since the last call are dispatched synchronously.
 *
 *   Callback model (koe-api WebSocket / koe-server):
 *     Register one or more koe_event_cb functions.  They are called from
 *     inside koe_event_poll() in registration order.  Callbacks must not
 *     block — they are called on the same thread as koe_event_poll().
 *
 * The event queue is a lock-free single-producer / single-consumer ring
 * buffer.  Internal modules post events from any context; the consumer
 * (koe_event_poll) drains from the main thread.
 *
 * Plugin dispatch:
 *   Before a KOE_EV_MSG_RECEIVED or KOE_EV_MEDIA_RECEIVED event reaches the
 *   registered callbacks, it is first passed through the mruby plugin system
 *   (koe_plugin_dispatch).  Plugins may modify the event or suppress it.
 *
 * Bindgen notes:
 *   - koe_event_t uses a tagged union; each union member has its own named
 *     struct with explicit field names (no anonymous structs).
 *   - All callback types are typedef'd.
 */

#ifndef KOE_EVENT_H
#define KOE_EVENT_H

#include "koe_crypto.h"
#include "koe_packet.h"
#include <stdint.h>
#include <time.h>

/* ---------------------------------------------------------------------- */
/* Event types                                                               */
/* ---------------------------------------------------------------------- */

typedef enum {
    KOE_EV_NONE              = 0,

    /* Messaging */
    KOE_EV_MSG_RECEIVED      = 1,   /* a new message arrived              */
    KOE_EV_MSG_DELIVERED     = 2,   /* our message was ACKed by the peer  */
    KOE_EV_MSG_READ          = 3,   /* recipient opened the conversation  */
    KOE_EV_MSG_FAILED        = 4,   /* delivery permanently failed        */

    /* Peer lifecycle */
    KOE_EV_PEER_ONLINE       = 5,
    KOE_EV_PEER_OFFLINE      = 6,
    KOE_EV_PEER_DISCOVERED   = 7,   /* new peer found via local discovery */
    KOE_EV_PEER_TYPING       = 8,   /* peer started typing                */
    KOE_EV_PEER_STOPPED_TYPING = 9,

    /* Session */
    KOE_EV_HANDSHAKE_DONE    = 10,  /* session key established            */
    KOE_EV_SESSION_EXPIRED   = 11,  /* session timed out; need new HELLO  */

    /* Voice calls */
    KOE_EV_CALL_INCOMING     = 12,
    KOE_EV_CALL_ACCEPTED     = 13,
    KOE_EV_CALL_REJECTED     = 14,
    KOE_EV_CALL_ENDED        = 15,
    KOE_EV_CALL_AUDIO_FRAME  = 16,  /* decoded PCM frame ready for playback */

    /* Contacts */
    KOE_EV_CONTACT_REQUEST   = 17,  /* someone sent a contact add request */
    KOE_EV_CONTACT_ACCEPTED  = 18,
    KOE_EV_CONTACT_BLOCKED   = 19,
    KOE_EV_CONTACT_VERIFIED  = 20,

    /* Media */
    KOE_EV_MEDIA_OFFER       = 21,  /* incoming file transfer offer       */
    KOE_EV_MEDIA_ACCEPTED    = 22,
    KOE_EV_MEDIA_REJECTED    = 23,
    KOE_EV_MEDIA_PROGRESS    = 24,  /* chunk received / sent              */
    KOE_EV_MEDIA_DONE        = 25,  /* transfer complete                  */
    KOE_EV_MEDIA_FAILED      = 26,

    /* Keys and identity */
    KOE_EV_KEY_REVOKED       = 27,  /* a contact revoked their key        */
    KOE_EV_IDENTITY_SWITCHED = 28,  /* account rotation completed         */

    /* Timers */
    KOE_EV_DESTRUCT_FIRED    = 29,  /* a self-destruct timer expired      */
    KOE_EV_SCHEDULED_DUE     = 30,  /* a scheduled message is ready       */

    /* Queue */
    KOE_EV_QUEUE_DRAINED     = 31,  /* offline queue fully delivered      */

    /* Groups (Matrix) */
    KOE_EV_GROUP_MSG         = 32,  /* message in a Matrix room           */
    KOE_EV_GROUP_MEMBER_JOIN = 33,
    KOE_EV_GROUP_MEMBER_LEAVE = 34,
    KOE_EV_GROUP_KICKED      = 35,
    KOE_EV_GROUP_META_UPDATE = 36,  /* name or topic changed              */

    /* System */
    KOE_EV_ERROR             = 63,
} koe_event_type_t;

/* ---------------------------------------------------------------------- */
/* Per-event data payloads (named structs for bindgen)                      */
/* ---------------------------------------------------------------------- */

typedef struct {
    uint64_t message_id;
    uint8_t  from[KOE_ED25519_PK_LEN];
    uint8_t  body[4096];           /* plaintext (after plugin dispatch)   */
    size_t   body_len;
    int      is_secret;
    int64_t  sent_at;
    int64_t  destruct_ttl;         /* 0 = no self-destruct                */
} koe_ev_message_t;

typedef struct {
    uint8_t pk[KOE_ED25519_PK_LEN];
    int     transport;             /* KOE_TRANSPORT_* value               */
    char    addr[64];
} koe_ev_peer_t;

typedef struct {
    uint64_t message_id;
    int      error_code;
} koe_ev_delivery_t;

typedef struct {
    uint8_t from[KOE_ED25519_PK_LEN];
    int     is_typing;
} koe_ev_typing_t;

typedef struct {
    uint8_t from[KOE_ED25519_PK_LEN];
    char    transfer_id[32];
    char    filename[256];
    char    mime_type[128];
    uint64_t file_size;
} koe_ev_media_offer_t;

typedef struct {
    char     transfer_id[32];
    uint32_t chunks_done;
    uint32_t chunks_total;
} koe_ev_media_progress_t;

typedef struct {
    char     transfer_id[32];
    char     save_path[512];
} koe_ev_media_done_t;

typedef struct {
    uint8_t from[KOE_ED25519_PK_LEN];
} koe_ev_call_t;

typedef struct {
    int16_t samples[960];   /* one 20 ms Opus frame at 48 kHz stereo */
    int     sample_count;
} koe_ev_audio_frame_t;

typedef struct {
    char    room_id[256];
    uint8_t sender_pk[KOE_ED25519_PK_LEN];
    uint8_t body[4096];
    size_t  body_len;
} koe_ev_group_msg_t;

typedef struct {
    char room_id[256];
    char user_id[256];
} koe_ev_group_member_t;

typedef struct {
    char room_id[256];
    char new_name[128];
    char new_topic[1024];
} koe_ev_group_meta_t;

typedef struct {
    uint64_t message_id;
} koe_ev_destruct_t;

typedef struct {
    int  code;
    char desc[256];
} koe_ev_error_t;

/* ---------------------------------------------------------------------- */
/* Master event struct                                                       */
/* ---------------------------------------------------------------------- */

typedef struct {
    koe_event_type_t type;
    time_t           timestamp;
    int              suppressed;    /* set by plugins; do not deliver to UI */

    union {
        koe_ev_message_t       message;
        koe_ev_peer_t          peer;
        koe_ev_delivery_t      delivery;
        koe_ev_typing_t        typing;
        koe_ev_media_offer_t   media_offer;
        koe_ev_media_progress_t media_progress;
        koe_ev_media_done_t    media_done;
        koe_ev_call_t          call;
        koe_ev_audio_frame_t   audio;
        koe_ev_group_msg_t     group_msg;
        koe_ev_group_member_t  group_member;
        koe_ev_group_meta_t    group_meta;
        koe_ev_destruct_t      destruct;
        koe_ev_error_t         error;
    } data;
} koe_event_t;

/* ---------------------------------------------------------------------- */
/* Callback type                                                             */
/* ---------------------------------------------------------------------- */

/*
 * koe_event_cb - Called for each event that has not been suppressed.
 *
 * ev:  the event; do not store a pointer (the struct may be on the stack).
 * ctx: caller-provided context pointer.
 */
typedef void (*koe_event_cb)(const koe_event_t *ev, void *ctx);

/* ---------------------------------------------------------------------- */
/* Registration                                                              */
/* ---------------------------------------------------------------------- */

#define KOE_MAX_LISTENERS 32

/*
 * koe_event_register - Register a callback for all (non-suppressed) events.
 *
 * Multiple callbacks can be registered; they are called in registration order.
 * Returns 0 on success, -1 if the limit (KOE_MAX_LISTENERS) is reached.
 */
int koe_event_register(koe_event_cb cb, void *ctx);

/*
 * koe_event_unregister - Remove a previously registered callback.
 *
 * Matches by function pointer.
 */
int koe_event_unregister(koe_event_cb cb);

/* ---------------------------------------------------------------------- */
/* Polling                                                                   */
/* ---------------------------------------------------------------------- */

/*
 * koe_event_poll - Drain the queue and dispatch events.
 *
 * timeout_ms: how long to block waiting for new I/O before returning.
 *             Pass 0 for non-blocking, or a positive value for the TUI
 *             frame timeout.
 *
 * Returns the number of events dispatched (including suppressed ones).
 */
int koe_event_poll(int timeout_ms);

/* ---------------------------------------------------------------------- */
/* Internal posting (used by other koe-core modules)                        */
/* ---------------------------------------------------------------------- */

/*
 * koe_event_post - Enqueue an event for delivery on the next poll.
 *
 * Thread-safe (lock-free ring buffer).  If the ring is full, the oldest
 * unread event is discarded with a warning.
 */
int koe_event_post(const koe_event_t *ev);

/* ---------------------------------------------------------------------- */
/* Timer pumps (called automatically by koe_event_poll)                     */
/* ---------------------------------------------------------------------- */

void koe_event_pump_destruct(void);    /* fire expired self-destruct timers */
void koe_event_pump_scheduled(void);   /* deliver due scheduled messages    */
void koe_event_pump_presence(void);    /* expire stale presence entries     */
void koe_event_pump_ping(void);        /* send keepalive PINGs              */

#endif /* KOE_EVENT_H */
