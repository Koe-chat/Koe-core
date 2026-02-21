/*
 * koe_presence.h - Online presence and typing indicators.
 *
 * Presence is tracked per-peer, per-transport.  The source of truth depends
 * on the transport:
 *
 *   WiFi Direct / Bluetooth:
 *     Presence is derived from recent PING/PONG exchanges and discovery
 *     broadcast responses.  A peer is considered online if a PONG was
 *     received within KOE_PRESENCE_TTL_LOCAL seconds.
 *
 *   TCP relay (Matrix):
 *     Presence is derived from Matrix /presence API calls.  The relay
 *     proxies these without reading message content.
 *
 * Ghost mode (koe_ghost.h) overrides local presence — when ghost mode is
 * active, this peer's presence is never published, though incoming presence
 * updates from other peers are still processed.
 *
 * Presence data is never stored on disk; it is purely in-memory and
 * regenerated on each session.
 */

#ifndef KOE_PRESENCE_H
#define KOE_PRESENCE_H

#include "koe_crypto.h"
#include "koe_packet.h"
#include <stdint.h>
#include <time.h>

#define KOE_PRESENCE_TTL_LOCAL   30   /* seconds until a local peer is "offline" */
#define KOE_PRESENCE_TTL_RELAY   90   /* seconds until a relay peer is "offline" */
#define KOE_PRESENCE_MAX_PEERS   512

/* ---------------------------------------------------------------------- */
/* Presence states                                                           */
/* ---------------------------------------------------------------------- */

typedef enum {
    KOE_PRESENCE_OFFLINE    = 0,
    KOE_PRESENCE_ONLINE     = 1,
    KOE_PRESENCE_AWAY       = 2,    /* Matrix /presence away */
    KOE_PRESENCE_BUSY       = 3,    /* user-set, published to Matrix */
    KOE_PRESENCE_GHOST      = 4,    /* local: ghost mode active       */
} koe_presence_state_t;

/* ---------------------------------------------------------------------- */
/* Per-peer presence record                                                  */
/* ---------------------------------------------------------------------- */

typedef struct {
    uint8_t              pk[KOE_ED25519_PK_LEN];
    koe_presence_state_t state;
    time_t               last_seen;          /* unix timestamp of last contact */
    int                  transport;          /* KOE_TRANSPORT_* of last contact */
    int                  is_typing;          /* 1 if typing indicator active    */
    time_t               typing_started_at;  /* 0 if not typing                 */
} koe_peer_presence_t;

/* ---------------------------------------------------------------------- */
/* Presence table                                                            */
/* ---------------------------------------------------------------------- */

typedef struct {
    koe_peer_presence_t peers[KOE_PRESENCE_MAX_PEERS];
    int                  count;
    koe_presence_state_t local_state;   /* our own advertised state */
} koe_presence_table_t;

/* ---------------------------------------------------------------------- */
/* Operations                                                                */
/* ---------------------------------------------------------------------- */

/*
 * koe_presence_init - Zero-initialise a presence table.
 */
void koe_presence_init(koe_presence_table_t *table);

/*
 * koe_presence_update - Update a peer's presence from a received event.
 *
 * Called internally when a PING, PONG, MSG, or AUDIO packet arrives from
 * a peer (any packet means they are reachable).
 */
void koe_presence_update(koe_presence_table_t *table,
                          const uint8_t         pk[KOE_ED25519_PK_LEN],
                          koe_presence_state_t  state,
                          int                   transport);

/*
 * koe_presence_get - Look up a peer's current presence.
 *
 * Returns KOE_PRESENCE_OFFLINE if the peer is not in the table or their
 * last_seen timestamp is too old.
 */
koe_presence_state_t koe_presence_get(const koe_presence_table_t *table,
                                        const uint8_t               pk[KOE_ED25519_PK_LEN]);

/*
 * koe_presence_is_online - Convenience; returns 1 if state != OFFLINE.
 */
int koe_presence_is_online(const koe_presence_table_t *table,
                             const uint8_t               pk[KOE_ED25519_PK_LEN]);

/*
 * koe_presence_expire - Remove stale entries whose last_seen is too old.
 *
 * Called by the event pump on each poll cycle.
 * Returns the number of entries removed.
 */
int koe_presence_expire(koe_presence_table_t *table);

/* ---------------------------------------------------------------------- */
/* Typing indicators                                                         */
/* ---------------------------------------------------------------------- */

/*
 * koe_presence_set_typing - Build a KOE_TYPE_TYPING packet to send.
 *
 * is_typing: 1 to start, 0 to stop.
 */
int koe_presence_set_typing(koe_packet_t         *pkt,
                              const koe_identity_t *local_id,
                              const uint8_t         to_pk[KOE_ED25519_PK_LEN],
                              const koe_session_t  *sess,
                              int                   is_typing);

/*
 * koe_presence_handle_typing - Process an incoming KOE_TYPE_TYPING packet.
 */
void koe_presence_handle_typing(koe_presence_table_t *table,
                                  const koe_packet_t   *pkt);

/*
 * koe_presence_typing_expired - Return 1 if a peer's typing indicator has
 *                               expired (no update for > 5 seconds).
 */
int koe_presence_typing_expired(const koe_peer_presence_t *peer);

/* ---------------------------------------------------------------------- */
/* Local state broadcast                                                     */
/* ---------------------------------------------------------------------- */

/*
 * koe_presence_set_local - Set our own advertised presence state.
 *
 * If ghost mode is active (g != NULL and g->active == 1), the state is
 * overridden to KOE_PRESENCE_GHOST and nothing is broadcast.
 */
int koe_presence_set_local(koe_presence_table_t *table,
                             koe_presence_state_t  state,
                             const koe_identity_t *local_id,
                             int                   ghost_active);

/*
 * koe_presence_build_packet - Build a KOE_TYPE_PRESENCE packet.
 *
 * Used to announce our state to a specific peer.
 */
int koe_presence_build_packet(koe_packet_t         *pkt,
                                const koe_identity_t *local_id,
                                const uint8_t         to_pk[KOE_ED25519_PK_LEN],
                                koe_presence_state_t  state,
                                const koe_session_t  *sess);

#endif /* KOE_PRESENCE_H */
