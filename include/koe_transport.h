/*
 * koe_transport.h - Transport abstraction: WiFi Direct, Bluetooth, TCP relay,
 *                   WebSocket (for koe-api).
 *
 * Transport priority (always tried in order):
 *   1. WiFi Direct / local TCP   — lowest latency, no infrastructure
 *   2. Bluetooth RFCOMM          — short range, ~60-110 ms RTT
 *   3. TCP relay (koe-server)    — internet, ~100-300 ms RTT
 *   4. WebSocket relay           — used by koe-api clients (browser, mobile)
 *
 * Discovery:
 *   Local peers are found by sending a UDP broadcast on KOE_DISCOVERY_PORT.
 *   The discovery payload carries the sender's Ed25519 public key and
 *   protocol version.  Peers respond with their own public key.
 *
 * All transports use the same framing: a 4-byte big-endian length prefix
 * followed by a serialised koe_packet_t.
 *
 * Thread safety:
 *   koe_transport_ctx_t is NOT thread-safe.  All calls must come from the
 *   same thread that runs koe_event_poll().
 */

#ifndef KOE_TRANSPORT_H
#define KOE_TRANSPORT_H

#include "koe_crypto.h"
#include "koe_packet.h"
#include "koe_version.h"
#include <stdint.h>
#include <stddef.h>

/* ---------------------------------------------------------------------- */
/* Ports and constants                                                       */
/* ---------------------------------------------------------------------- */

#define KOE_DISCOVERY_PORT    9473
#define KOE_RELAY_PORT_DEF    9474
#define KOE_MIGRATE_PORT      9475
#define KOE_MEDIA_PORT        9476    /* P2P file transfer HTTP endpoint   */
#define KOE_WS_PORT_DEF       9477    /* WebSocket relay port              */

#define KOE_DISCOVERY_TTL_MS  500     /* how long to collect discovery replies */
#define KOE_PING_INTERVAL_S   15      /* keepalive interval                */
#define KOE_PEER_TIMEOUT_S    45      /* declare peer offline after this   */
#define KOE_IO_TIMEOUT_MS     5000    /* per-operation socket timeout      */

/* ---------------------------------------------------------------------- */
/* Transport types                                                           */
/* ---------------------------------------------------------------------- */

typedef enum {
    KOE_TRANSPORT_NONE        = 0,
    KOE_TRANSPORT_WIFI_DIRECT = 1,
    KOE_TRANSPORT_BLUETOOTH   = 2,
    KOE_TRANSPORT_TCP_RELAY   = 3,
    KOE_TRANSPORT_WEBSOCKET   = 4,
} koe_transport_type_t;

/* ---------------------------------------------------------------------- */
/* Peer descriptor                                                           */
/* ---------------------------------------------------------------------- */

typedef struct {
    uint8_t              pk[KOE_ED25519_PK_LEN];
    char                 addr[64];         /* IPv4 or IPv6 address string  */
    uint16_t             port;
    int                  fd;               /* connected socket, -1 = none  */
    koe_transport_type_t transport;
    int                  reachable;
    koe_version_t        version;          /* protocol version negotiated  */
    int64_t              last_contact_us;  /* microseconds since epoch     */
} koe_peer_t;

/* ---------------------------------------------------------------------- */
/* Discovery callback                                                        */
/* ---------------------------------------------------------------------- */

typedef void (*koe_peer_cb)(const koe_peer_t *peer, void *ctx);

/* ---------------------------------------------------------------------- */
/* Transport context                                                         */
/* ---------------------------------------------------------------------- */

typedef struct {
    int                  listen_fd;         /* UDP discovery socket         */
    int                  tcp_listen_fd;     /* TCP accept socket            */
    int                  ws_listen_fd;      /* WebSocket accept socket      */
    char                 relay_host[256];
    uint16_t             relay_port;
    koe_transport_type_t active;
    int                  bluetooth_enabled;
} koe_transport_ctx_t;

/* ---------------------------------------------------------------------- */
/* Lifecycle                                                                 */
/* ---------------------------------------------------------------------- */

/*
 * koe_transport_init - Open discovery socket and start listening for peers.
 *
 * relay_host: hostname of the koe-server relay (NULL = no relay).
 * relay_port: relay TCP port (0 = use KOE_RELAY_PORT_DEF).
 * ws_port:    WebSocket port (0 = use KOE_WS_PORT_DEF; -1 = disable).
 *
 * Returns 0 on success.  On Android/Termux, WiFi Direct requires
 * wpa_supplicant access; if unavailable, falls back to plain UDP on the
 * local WiFi network.
 */
int koe_transport_init(koe_transport_ctx_t *ctx,
                        const char          *relay_host,
                        uint16_t             relay_port,
                        int                  ws_port);

/*
 * koe_transport_shutdown - Close all sockets.
 */
void koe_transport_shutdown(koe_transport_ctx_t *ctx);

/* ---------------------------------------------------------------------- */
/* Discovery                                                                 */
/* ---------------------------------------------------------------------- */

/*
 * koe_transport_discover - Broadcast a discovery ping and collect responses.
 *
 * local_id: our identity (public key sent in the ping payload).
 * on_peer:  called for each responding peer.
 * Returns 0 on success.
 */
int koe_transport_discover(koe_transport_ctx_t *ctx,
                             const koe_identity_t *local_id,
                             koe_peer_cb           on_peer,
                             void                 *cb_ctx);

/*
 * koe_transport_handle_discovery - Process an incoming discovery ping.
 *
 * Call this when select()/poll() indicates activity on ctx->listen_fd.
 * If the packet is a valid discovery ping, fires on_peer with the sender's
 * details and sends back a pong.
 */
int koe_transport_handle_discovery(koe_transport_ctx_t *ctx,
                                    const koe_identity_t *local_id,
                                    koe_peer_cb           on_peer,
                                    void                 *cb_ctx);

/* ---------------------------------------------------------------------- */
/* Connection                                                                */
/* ---------------------------------------------------------------------- */

/*
 * koe_transport_connect - Connect to a peer, trying transports in order.
 *
 * Fills peer->fd and peer->transport on success.
 * Returns 0 on success, -1 if all transports fail.
 */
int koe_transport_connect(koe_transport_ctx_t *ctx, koe_peer_t *peer);

/*
 * koe_transport_accept - Accept an incoming connection from any transport.
 *
 * Returns 0 on success, -1 if no incoming connection is pending.
 * The caller should select() on all listen_fd/ws_listen_fd/tcp_listen_fd
 * and call this when one is readable.
 */
int koe_transport_accept(koe_transport_ctx_t *ctx, koe_peer_t *peer);

/*
 * koe_transport_disconnect - Close a peer's connection cleanly.
 */
void koe_transport_disconnect(koe_peer_t *peer);

/* ---------------------------------------------------------------------- */
/* Send / receive                                                             */
/* ---------------------------------------------------------------------- */

/*
 * koe_transport_send - Serialise and send a packet to a connected peer.
 *
 * Returns 0 on success, -1 on error.
 */
int koe_transport_send(const koe_peer_t   *peer,
                        const koe_packet_t *pkt);

/*
 * koe_transport_recv - Read one packet from a connected peer.
 *
 * Allocates pkt->payload on the heap.  Caller must call koe_packet_free().
 * Returns 0 on success, -1 on error or disconnection.
 */
int koe_transport_recv(const koe_peer_t *peer,
                        koe_packet_t     *pkt);

/* ---------------------------------------------------------------------- */
/* WebSocket support (for koe-api)                                           */
/* ---------------------------------------------------------------------- */

/*
 * koe_transport_ws_accept - Accept a WebSocket upgrade on ws_listen_fd.
 *
 * Performs the HTTP upgrade handshake.
 * Returns the new file descriptor on success, -1 on error.
 */
int koe_transport_ws_accept(koe_transport_ctx_t *ctx);

/*
 * koe_transport_ws_send - Send a packet over a WebSocket connection.
 *
 * The packet is framed as a binary WebSocket message.
 */
int koe_transport_ws_send(int fd, const koe_packet_t *pkt);

/*
 * koe_transport_ws_recv - Read one packet from a WebSocket connection.
 */
int koe_transport_ws_recv(int fd, koe_packet_t *pkt);

/* ---------------------------------------------------------------------- */
/* Utilities                                                                 */
/* ---------------------------------------------------------------------- */

/*
 * koe_transport_fd_set - Populate a fd_set with all active transport fds.
 *
 * Returns the highest fd value, for use as the first argument to select().
 */
int koe_transport_fd_set(const koe_transport_ctx_t *ctx, void *fd_set_ptr);

/*
 * koe_transport_type_string - Return a human-readable transport name.
 */
const char *koe_transport_type_string(koe_transport_type_t t);

#endif /* KOE_TRANSPORT_H */
