/*
 * koe.h - Public API for koe-core.
 *
 * This is the single header that consumers (the Rust TUI, the Go server,
 * the C++ API layer) include. It pulls in all sub-module headers and
 * exposes the top-level initialisation and teardown interface.
 *
 * Usage:
 *
 *   #include "koe.h"
 *
 *   koe_ctx_t ctx;
 *   koe_init(&ctx, &cfg);
 *
 *   koe_event_register(my_callback, NULL);
 *
 *   while (running) {
 *       koe_event_poll(16);   // ~60 fps
 *       // handle UI
 *   }
 *
 *   koe_shutdown(&ctx);
 */

#ifndef KOE_H
#define KOE_H

#include "koe_packet.h"
#include "koe_crypto.h"
#include "koe_identity.h"
#include "koe_handshake.h"
#include "koe_transport.h"
#include "koe_message.h"
#include "koe_queue.h"
#include "koe_audio.h"
#include "koe_backup.h"
#include "koe_channel.h"
#include "koe_ghost.h"
#include "koe_store.h"
#include "koe_revoke.h"
#include "koe_event.h"

#define KOE_VERSION_MAJOR  0
#define KOE_VERSION_MINOR  1
#define KOE_VERSION_PATCH  0
#define KOE_VERSION_STRING "0.1.0"

/* -------------------------------------------------------------------------
 * Top-level configuration
 * ---------------------------------------------------------------------- */

typedef struct {
    /* Path to the directory holding identity, contacts, and history files. */
    const char *data_dir;

    /* Passphrase used to decrypt the local identity on startup. */
    const char *passphrase;

    /* Relay server for long-distance connections and server-side backup.
     * Set to NULL to disable relay entirely (local P2P only). */
    const char *relay_host;
    uint16_t    relay_port;

    /* How long to wait for local peer discovery responses, in milliseconds. */
    int discovery_timeout_ms;

    /* Enable Bluetooth transport. WiFi Direct is always attempted first. */
    int bluetooth_enabled;

    /* Maximum number of messages held in the offline queue per peer. */
    int queue_max_per_peer;
} koe_config_t;

/* -------------------------------------------------------------------------
 * Core context
 *
 * One koe_ctx_t per running instance. Not thread-safe; drive from a single
 * thread and rely on koe_event_poll for concurrency.
 * ---------------------------------------------------------------------- */

typedef struct {
    koe_config_t         cfg;
    koe_profile_t        profile;
    koe_contact_book_t   contacts;
    koe_transport_ctx_t  transport;
    koe_queue_t          queue;
    koe_ghost_mode_t     ghost;
    int                  initialised;
} koe_ctx_t;

/* -------------------------------------------------------------------------
 * Initialisation and teardown
 * ---------------------------------------------------------------------- */

/*
 * koe_init - Initialise the core from a config struct.
 *
 * Loads the local identity from cfg.data_dir (creating one if this is a
 * fresh installation), opens the contact book and message store, starts
 * the transport layer, and registers built-in event handlers.
 *
 * Returns 0 on success, -1 on any unrecoverable error. Specific error
 * details are written to stderr.
 */
int koe_init(koe_ctx_t *ctx, const koe_config_t *cfg);

/*
 * koe_shutdown - Flush all pending state to disk and tear down transports.
 *
 * Blocks until all in-flight I/O completes (or times out after 5 seconds).
 * Zeroes all session keys in memory before returning.
 */
void koe_shutdown(koe_ctx_t *ctx);

/* -------------------------------------------------------------------------
 * Convenience send wrappers
 * ---------------------------------------------------------------------- */

/*
 * koe_send_text - Send a text message to a contact.
 *
 * If the contact is online, the message is delivered immediately. If not,
 * it is pushed onto the offline queue.
 *
 * Returns the assigned message ID on success, or -1 on error.
 */
int64_t koe_send_text(koe_ctx_t     *ctx,
                       const uint8_t  to[KOE_ED25519_PK_LEN],
                       const char    *text,
                       uint32_t       destruct_ttl_seconds);

/*
 * koe_send_text_scheduled - Like koe_send_text but sent at `send_at`.
 */
int64_t koe_send_text_scheduled(koe_ctx_t     *ctx,
                                  const uint8_t  to[KOE_ED25519_PK_LEN],
                                  const char    *text,
                                  time_t         send_at);

/*
 * koe_add_contact - Send a contact request to a peer identified by short_id.
 *
 * short_id: the "name#shortid" string displayed in the UI, e.g. "water#a3f7".
 * The peer must be discoverable (local network or relay) for the request
 * to be delivered. Returns 0 on success, -1 on error.
 */
int koe_add_contact(koe_ctx_t  *ctx,
                     const char *short_id,
                     const char *display_name);

/*
 * koe_start_call - Initiate a voice call with a contact.
 *
 * Returns a koe_audio_ctx_t that the caller uses to drive the audio path,
 * or NULL on error.
 */
koe_audio_ctx_t *koe_start_call(koe_ctx_t     *ctx,
                                  const uint8_t  to[KOE_ED25519_PK_LEN]);

/*
 * koe_end_call - Terminate an active call.
 */
void koe_end_call(koe_ctx_t *ctx, koe_audio_ctx_t *audio);

/* -------------------------------------------------------------------------
 * Version query
 * ---------------------------------------------------------------------- */

/* Returns KOE_VERSION_STRING. */
const char *koe_version(void);

#endif /* KOE_H */
