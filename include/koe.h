/*
 * koe.h - koe-core public API.
 *
 * This is the single header that all consumers include.  It aggregates
 * every sub-module and exposes the top-level context, configuration,
 * and lifecycle functions.
 *
 * Usage (C):
 *
 *   #include "koe.h"
 *
 *   koe_ctx_t ctx;
 *   koe_config_t cfg = { ... };
 *   koe_init(&ctx, &cfg);
 *   koe_event_register(my_handler, NULL);
 *   while (running) koe_event_poll(16);
 *   koe_shutdown(&ctx);
 *
 * Usage (Rust, via bindgen):
 *
 *   // build.rs
 *   bindgen::Builder::default()
 *       .header("include/koe.h")
 *       .allowlist_function("koe_.*")
 *       .allowlist_type("koe_.*")
 *       .allowlist_var("KOE_.*")
 *       .generate()
 *       .unwrap()
 *       .write_to_file("src/bindings.rs")
 *       .unwrap();
 *
 * Usage (Go, via cgo):
 *
 *   // #cgo LDFLAGS: -lkoe-core -lsodium -lopus
 *   // #include "koe.h"
 *   import "C"
 *
 * Usage (C++):
 *
 *   extern "C" { #include "koe.h" }
 *
 * Usage (Swift):
 *
 *   // Set "Objective-C Bridging Header" to a file containing:
 *   // #include "koe.h"
 */

#ifndef KOE_H
#define KOE_H

/* Version information. */
#include "koe_version.h"

/* Protocol wire format. */
#include "koe_packet.h"

/* Session management. */
#include "koe_session.h"

/* Cryptographic primitives. */
#include "koe_crypto.h"

/* Identity and contacts. */
#include "koe_identity.h"

/* Multi-account support. */
#include "koe_account.h"

/* Key exchange. */
#include "koe_handshake.h"

/* Transport layer (WiFi Direct, Bluetooth, relay, WebSocket). */
#include "koe_transport.h"

/* Online presence and typing indicators. */
#include "koe_presence.h"

/* Application-level messages (text, scheduled, self-destruct). */
#include "koe_message.h"

/* Offline message queue. */
#include "koe_queue.h"

/* Voice calls (Opus). */
#include "koe_audio.h"

/* P2P file transfer. */
#include "koe_media.h"

/* Matrix group integration. */
#include "koe_matrix.h"

/* Broadcast channels. */
#include "koe_channel.h"

/* Ghost mode, secret chats, travel mode. */
#include "koe_ghost.h"

/* Key revocation. */
#include "koe_revoke.h"

/* Encrypted local message store. */
#include "koe_store.h"

/* Database abstraction. */
#include "koe_db.h"

/* mruby plugin system. */
#include "koe_plugin.h"

/* Event loop. */
#include "koe_event.h"

/* ---------------------------------------------------------------------- */
/* Top-level configuration                                                   */
/* ---------------------------------------------------------------------- */

typedef struct {
    /* Data directory for the active account.
     * Each account gets a subdirectory: <data_root>/accounts/<short_id>/  */
    const char *data_root;

    /* Passphrase for the active account's identity file. */
    const char *passphrase;

    /* Relay server.  Set relay_host to NULL for local-only operation. */
    const char *relay_host;
    uint16_t    relay_port;

    /* WebSocket endpoint for koe-api.  Set ws_port to -1 to disable. */
    int         ws_port;

    /* Matrix homeserver.  NULL = no group messaging. */
    const char *matrix_homeserver;

    /* Local peer discovery timeout (milliseconds). */
    int         discovery_timeout_ms;

    /* Enable Bluetooth transport (requires BlueZ on Linux/Android). */
    int         bluetooth_enabled;

    /* Max offline queue entries per peer. */
    int         queue_max_per_peer;

    /* Database backend for local storage. */
    koe_db_config_t    db;

    /* Optional Redis cache.  Set cache.enabled = 0 to disable. */
    koe_cache_config_t cache;

    /* Plugin system.  Set plugins_dir to NULL to disable. */
    const char *plugins_dir;

} koe_config_t;

/* ---------------------------------------------------------------------- */
/* Core context                                                              */
/*                                                                           */
/* One koe_ctx_t per running process.  Drive from a single thread via       */
/* koe_event_poll().  All sub-module state is owned here.                   */
/* ---------------------------------------------------------------------- */

/* Online presence and typing indicators. */
#include "koe_presence.h"

typedef struct {
    koe_config_t           cfg;
    koe_account_registry_t account_registry;
    koe_account_t          active_account;
    koe_contact_book_t     contacts;
    koe_transport_ctx_t    transport;
    koe_presence_table_t   presence;
    koe_session_table_t    sessions;
    koe_queue_t            queue;
    koe_ghost_state_t      ghost;
    koe_plugin_registry_t  plugins;
    koe_matrix_ctx_t       matrix;
    koe_db_conn_t         *db;
    koe_cache_conn_t      *cache;
    int                    initialised;
} koe_ctx_t;

/* ---------------------------------------------------------------------- */
/* Lifecycle                                                                 */
/* ---------------------------------------------------------------------- */

/*
 * koe_init - Bring up the full koe-core stack.
 *
 * Order of operations:
 *   1. libsodium init
 *   2. Account registry load (or create fresh)
 *   3. Activate the last-used account (or the only one if there is one)
 *   4. Open database
 *   5. Load contacts from DB
 *   6. Open offline queue
 *   7. Start transport layer
 *   8. Load plugins (if plugins_dir is set)
 *   9. Connect to Matrix homeserver (if configured)
 *  10. Register built-in event handlers
 *
 * Returns 0 on success, -1 on any unrecoverable error.
 */
int koe_init(koe_ctx_t *ctx, const koe_config_t *cfg);

/*
 * koe_shutdown - Flush state, zero secret keys, close transports.
 *
 * Blocks until all in-flight I/O completes (max 5 seconds), then
 * zeros all session keys and closes database connections.
 */
void koe_shutdown(koe_ctx_t *ctx);

/* ---------------------------------------------------------------------- */
/* Account management (convenience wrappers over koe_account_*)            */
/* ---------------------------------------------------------------------- */

/*
 * koe_switch_account - Rotate to a different identity.
 *
 * idx: index into ctx->account_registry.accounts.
 * passphrase: the target account's passphrase.
 *
 * Deactivates the current account, closes its DB, loads the new one, and
 * fires KOE_EV_IDENTITY_SWITCHED when done.
 *
 * Returns 0 on success.
 */
int koe_switch_account(koe_ctx_t *ctx, int idx, const char *passphrase);

/* ---------------------------------------------------------------------- */
/* Convenience send wrappers                                                 */
/* ---------------------------------------------------------------------- */

/*
 * koe_send_text - Send a UTF-8 text message.
 *
 * to:              recipient's Ed25519 public key.
 * text:            null-terminated plaintext.
 * destruct_ttl:    self-destruct after N seconds (0 = never).
 *
 * Returns the assigned message ID on success, -1 on error.
 */
int64_t koe_send_text(koe_ctx_t     *ctx,
                       const uint8_t  to[KOE_ED25519_PK_LEN],
                       const char    *text,
                       uint32_t       destruct_ttl);

/*
 * koe_send_text_scheduled - Like koe_send_text but deferred until send_at.
 */
int64_t koe_send_text_scheduled(koe_ctx_t     *ctx,
                                  const uint8_t  to[KOE_ED25519_PK_LEN],
                                  const char    *text,
                                  int64_t        send_at_unix);

/*
 * koe_send_file - Initiate a P2P file transfer.
 *
 * Builds a MEDIA_OFFER and queues the transfer.  Progress events are fired
 * as KOE_EV_MEDIA_PROGRESS.
 *
 * Returns a transfer_id string in transfer_id_out (at least 33 bytes).
 * Returns 0 on success, -1 on error.
 */
int koe_send_file(koe_ctx_t     *ctx,
                   const uint8_t  to[KOE_ED25519_PK_LEN],
                   const char    *file_path,
                   char          *transfer_id_out);

/*
 * koe_add_contact - Send a contact request to a peer by short ID.
 *
 * short_id: format "name#a3f7b2c9" (shown in the UI).
 * display_name: local label for this contact.
 *
 * Returns 0 on success.
 */
int koe_add_contact(koe_ctx_t  *ctx,
                     const char *short_id,
                     const char *display_name);

/*
 * koe_start_call / koe_end_call - Voice call lifecycle.
 */
koe_audio_ctx_t *koe_start_call(koe_ctx_t     *ctx,
                                  const uint8_t  to[KOE_ED25519_PK_LEN]);

void koe_end_call(koe_ctx_t *ctx, koe_audio_ctx_t *audio);

/* ---------------------------------------------------------------------- */
/* Matrix group convenience wrappers                                         */
/* ---------------------------------------------------------------------- */

/*
 * koe_group_create - Create a new Matrix room and return its room ID.
 */
int koe_group_create(koe_ctx_t  *ctx,
                      const char *name,
                      const char *topic,
                      char       *room_id_out);

/*
 * koe_group_send - Send an encrypted message to a Matrix room.
 */
int koe_group_send(koe_ctx_t  *ctx,
                    const char *room_id,
                    const char *text);

/* ---------------------------------------------------------------------- */
/* Session management                                                       */
/* ---------------------------------------------------------------------- */

/*
 * koe_session_establish - Add an active session with a peer.
 */
int koe_session_establish(koe_ctx_t *ctx, const uint8_t peer_pk[KOE_ED25519_PK_LEN],
                          const koe_session_t *sess);

/*
 * koe_session_active - Check if a session exists with a peer.
 */
int koe_session_active(koe_ctx_t *ctx, const uint8_t peer_pk[KOE_ED25519_PK_LEN]);

/*
 * koe_session_close - Remove session with a peer.
 */
void koe_session_close(koe_ctx_t *ctx, const uint8_t peer_pk[KOE_ED25519_PK_LEN]);

/*
 * koe_sessions_cleanup - Remove sessions older than max_age_seconds.
 */
void koe_sessions_cleanup(koe_ctx_t *ctx, int64_t max_age_seconds);

/* ---------------------------------------------------------------------- */
/* Handshake                                                                */
/* ---------------------------------------------------------------------- */

/*
 * koe_handshake_start - Initiate a new handshake with a peer.
 */
int koe_handshake_start(koe_ctx_t *ctx, const uint8_t peer_pk[KOE_ED25519_PK_LEN],
                        koe_packet_t *hello_out);

/*
 * koe_handshake_process - Process incoming handshake packet.
 */
int koe_handshake_process(koe_ctx_t *ctx, const koe_packet_t *in,
                          koe_packet_t *out, int *complete_out);

/* ---------------------------------------------------------------------- */
/* Message send/recv                                                       */
/* ---------------------------------------------------------------------- */

/*
 * koe_message_send_encrypted - Send an encrypted message to a peer.
 */
int koe_message_send_encrypted(koe_ctx_t *ctx, const uint8_t to[KOE_ED25519_PK_LEN],
                               const uint8_t *body, size_t body_len,
                               koe_packet_t *pkt_out);

/*
 * koe_message_recv_and_decrypt - Receive and decrypt a message.
 */
int koe_message_recv_and_decrypt(koe_ctx_t *ctx, const koe_packet_t *pkt,
                                 koe_message_t *msg_out);

/* ---------------------------------------------------------------------- */
/* Peer management                                                          */
/* ---------------------------------------------------------------------- */

/*
 * koe_peer_discover - Discover peers on local network.
 */
int koe_peer_discover(koe_ctx_t *ctx);

/*
 * koe_peer_connect - Connect to a peer by public key.
 */
int koe_peer_connect(koe_ctx_t *ctx, const uint8_t peer_pk[KOE_ED25519_PK_LEN]);

/*
 * koe_send_to_peer - Send a packet to a connected peer.
 */
int koe_send_to_peer(koe_ctx_t *ctx, const uint8_t peer_pk[KOE_ED25519_PK_LEN],
                     const koe_packet_t *pkt);

/* ---------------------------------------------------------------------- */
/* Event loop                                                               */
/* ---------------------------------------------------------------------- */

/*
 * koe_poll - Process pending events and cleanup.
 */
int koe_poll(koe_ctx_t *ctx, int timeout_ms);

/* ---------------------------------------------------------------------- */
/* Version query                                                             */
/* ---------------------------------------------------------------------- */

const char *koe_version_string_full(void);

#endif /* KOE_H */
