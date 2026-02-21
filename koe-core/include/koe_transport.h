/*
 * koe_transport.h - Network transport abstraction.
 *
 * The core never touches a socket directly. All network I/O goes through
 * this layer. Three transports are supported, tried in priority order:
 *
 *   1. WiFi Direct (P2P group owner socket) — lowest latency, no router.
 *   2. Bluetooth RFCOMM                     — longer range, no WiFi needed.
 *   3. TCP via Koe relay server             — internet, long distance.
 *
 * On Termux/Android, WiFi Direct is accessed through wpa_supplicant's
 * P2P interface via nl80211 netlink sockets. Bluetooth goes through the
 * BlueZ RFCOMM socket API exposed in the Linux kernel. Neither path
 * requires JNI or Android SDK involvement.
 */

#ifndef KOE_TRANSPORT_H
#define KOE_TRANSPORT_H

#include "koe_packet.h"
#include "koe_crypto.h"
#include <stddef.h>
#include <stdint.h>

typedef enum {
    KOE_TRANSPORT_NONE = 0,
    KOE_TRANSPORT_WIFI_DIRECT,
    KOE_TRANSPORT_BLUETOOTH,
    KOE_TRANSPORT_TCP_RELAY,
} koe_transport_type_t;

/* A discovered or connected peer */
typedef struct {
    uint8_t              pk[KOE_ED25519_PK_LEN];
    koe_transport_type_t transport;
    char                 addr[64];      /* IP, BT MAC, or relay host */
    uint16_t             port;
    int                  fd;            /* open socket, or -1 if not connected */
    int                  reachable;
    char                 display_name[64];
} koe_peer_t;

typedef struct {
    int       listen_fd;            /* passive socket for incoming connections */
    char      relay_host[256];
    uint16_t  relay_port;
    int       wifi_direct_enabled;
    int       bluetooth_enabled;
} koe_transport_ctx_t;

/* Callback invoked once per discovered peer during a discovery scan.
 * Must not block. `cb_ctx` is the opaque pointer passed to discover(). */
typedef void (*koe_peer_cb)(const koe_peer_t *peer, void *cb_ctx);

/* --- Lifecycle ---------------------------------------------------------- */

/* Initialise transport and start listening for incoming connections.
 * Pass relay_host=NULL / relay_port=0 to disable the relay transport. */
int koe_transport_init(koe_transport_ctx_t *ctx,
                        const char          *relay_host,
                        uint16_t             relay_port);

void koe_transport_shutdown(koe_transport_ctx_t *ctx);

/* --- Discovery ---------------------------------------------------------- */

/* Send discovery pings over all enabled local transports and collect
 * responses for up to `timeout_ms` milliseconds. Each responding peer
 * triggers one call to `on_peer`. Returns the number of peers found,
 * or -1 on error. */
int koe_transport_discover(koe_transport_ctx_t *tctx,
                             koe_peer_cb          on_peer,
                             void                *cb_ctx,
                             int                  timeout_ms);

/* --- Connection management --------------------------------------------- */

/* Connect to a peer. Tries WiFi Direct, then Bluetooth, then relay.
 * Updates peer->transport and peer->fd on success.
 * Returns 0 on success, -1 on failure. */
int koe_transport_connect(koe_transport_ctx_t *tctx,
                            koe_peer_t          *peer);

/* Accept the next incoming connection, blocking until one arrives.
 * Fills *peer on success. Returns 0 on success, -1 on error. */
int koe_transport_accept(koe_transport_ctx_t *tctx,
                          koe_peer_t          *peer);

void koe_transport_disconnect(koe_peer_t *peer);

/* --- Send / receive ----------------------------------------------------- */

/* Serialise and send a packet to a connected peer. Handles framing,
 * EINTR retries, and partial writes. Returns 0 on success, -1 on error. */
int koe_transport_send(const koe_peer_t   *peer,
                        const koe_packet_t *pkt);

/* Block until a complete framed packet is received from `peer`.
 * The returned pkt->payload is heap-allocated; call koe_packet_free when done.
 * Returns 0 on success, -1 on error or if the peer disconnects. */
int koe_transport_recv(const koe_peer_t *peer,
                        koe_packet_t     *pkt);

/* Non-blocking variant of koe_transport_recv. Returns 1 if a packet was
 * read, 0 if none was available yet, -1 on error. */
int koe_transport_recv_nonblock(const koe_peer_t *peer,
                                 koe_packet_t     *pkt);

#endif /* KOE_TRANSPORT_H */
