/*
 * koe_event.h - Event loop and async event dispatcher.
 *
 * koe-core is single-threaded. All I/O is non-blocking and driven by a
 * central poll-based event loop. Callers register callbacks for the events
 * they care about; the loop calls them on the appropriate thread.
 *
 * This design means the TUI (Rust layer) drives the loop by calling
 * koe_event_poll() on each frame, rather than koe-core running its own
 * background threads. This keeps the threading model simple and avoids the
 * need for synchronisation primitives in the core.
 *
 * Events are queued in a ring buffer. If the consumer (the TUI) falls behind,
 * older events are dropped with a warning rather than blocking the producer.
 */

#ifndef KOE_EVENT_H
#define KOE_EVENT_H

#include "koe_crypto.h"
#include "koe_message.h"
#include "koe_identity.h"
#include "koe_transport.h"
#include <stdint.h>
#include <time.h>

typedef enum {
    KOE_EV_NONE = 0,
    KOE_EV_MSG_RECEIVED,        /* a new message arrived              */
    KOE_EV_MSG_DELIVERED,       /* our message was ACKed              */
    KOE_EV_MSG_READ,            /* recipient opened the conversation  */
    KOE_EV_PEER_ONLINE,         /* a contact came online              */
    KOE_EV_PEER_OFFLINE,        /* a contact went offline             */
    KOE_EV_PEER_DISCOVERED,     /* new peer found via discovery       */
    KOE_EV_HANDSHAKE_DONE,      /* session established with a peer    */
    KOE_EV_CALL_INCOMING,       /* incoming voice call                */
    KOE_EV_CALL_ACCEPTED,
    KOE_EV_CALL_ENDED,
    KOE_EV_CONTACT_REQUEST,     /* someone wants to add us            */
    KOE_EV_KEY_REVOKED,         /* a contact revoked their key        */
    KOE_EV_DESTRUCT_TICK,       /* a self-destruct timer fired        */
    KOE_EV_QUEUE_DRAINED,       /* offline queue for a peer delivered */
    KOE_EV_ERROR,
} koe_event_type_t;

typedef struct {
    koe_event_type_t type;
    time_t           timestamp;
    union {
        struct { koe_message_t *msg;  }                   message;
        struct { uint8_t pk[KOE_ED25519_PK_LEN]; }        peer;
        struct { uint64_t message_id; }                    destruct;
        struct { int code; char desc[128]; }               error;
    } data;
} koe_event_t;

typedef void (*koe_event_cb)(const koe_event_t *ev, void *ctx);

/* --- Event loop --------------------------------------------------------- */

/* Register a callback to be called for all events. Multiple callbacks can
 * be registered; they are invoked in registration order. */
int koe_event_register(koe_event_cb cb, void *ctx);

/* Process all pending I/O and fire queued events. Call this from the TUI
 * event loop on each frame (e.g. every 16 ms). `timeout_ms` is the maximum
 * time to block waiting for new I/O; pass 0 for non-blocking. */
int koe_event_poll(int timeout_ms);

/* Post an event directly into the queue (used internally by core modules). */
int koe_event_post(const koe_event_t *ev);

/* --- Scheduled message pump -------------------------------------------- */

/* Check all pending scheduled messages and send any that are due.
 * Called automatically by koe_event_poll. */
void koe_event_pump_scheduled(void);

/* --- Self-destruct pump ------------------------------------------------- */

/* Check all active self-destruct timers and destroy any expired messages.
 * Called automatically by koe_event_poll. Fires KOE_EV_DESTRUCT_TICK for
 * each message destroyed. */
void koe_event_pump_destruct(void);

#endif /* KOE_EVENT_H */
