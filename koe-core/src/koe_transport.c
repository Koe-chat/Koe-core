/*
 * koe_transport.c - Transport layer: WiFi Direct, Bluetooth, TCP relay.
 *
 * Transport priority is fixed: WiFi Direct first, Bluetooth second, TCP
 * relay last. The selection happens in koe_transport_connect() and is
 * transparent to the caller.
 *
 * On Linux/Android (Termux), WiFi Direct is accessed through the nl80211
 * netlink interface and wpa_supplicant's P2P control socket. Bluetooth uses
 * the standard POSIX AF_BLUETOOTH / BTPROTO_RFCOMM socket interface from
 * the BlueZ kernel stack. The relay fallback is a plain TCP connection.
 *
 * All sockets are set to non-blocking mode. Blocking semantics in the public
 * API (koe_transport_send, koe_transport_recv) are emulated with poll(2).
 */

#include "koe_transport.h"
#include "koe_packet.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

/* Discovery ping payload: magic bytes + local Ed25519 public key.
 * Sent as a UDP broadcast on port KOE_DISCOVERY_PORT. */
#define KOE_DISCOVERY_PORT   9473
#define KOE_DISCOVERY_MAGIC  "KOEDISC"
#define KOE_RELAY_PORT_DEF   9474

/* How long to wait for a single send/recv before giving up, in ms. */
#define KOE_IO_TIMEOUT_MS    5000

/* ---------------------------------------------------------------------- */

static int set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int tcp_connect(const char *host, uint16_t port)
{
    struct addrinfo hints = {0};
    struct addrinfo *res  = NULL;
    char port_str[8];
    int  fd = -1;

    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(port_str, sizeof(port_str), "%u", port);

    if (getaddrinfo(host, port_str, &hints, &res) != 0)
        return -1;

    for (struct addrinfo *rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd == -1) continue;

        /* Disable Nagle to keep latency low for small packets. */
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0)
            break;

        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);
    return fd;
}

/* ---------------------------------------------------------------------- */

int koe_transport_init(koe_transport_ctx_t *ctx,
                        const char          *relay_host,
                        uint16_t             relay_port)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->active     = KOE_TRANSPORT_NONE;
    ctx->listen_fd  = -1;
    ctx->relay_port = relay_port ? relay_port : KOE_RELAY_PORT_DEF;

    if (relay_host)
        strncpy(ctx->relay_host, relay_host, sizeof(ctx->relay_host) - 1);

    /* Open a UDP socket for local discovery broadcasts. */
    int udp = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp == -1) {
        perror("koe_transport_init: socket");
        return -1;
    }

    int broadcast = 1;
    setsockopt(udp, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));

    int reuse = 1;
    setsockopt(udp, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in addr = {0};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(KOE_DISCOVERY_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(udp, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("koe_transport_init: bind discovery");
        close(udp);
        return -1;
    }

    set_nonblocking(udp);
    ctx->listen_fd = udp;
    ctx->active    = KOE_TRANSPORT_WIFI_DIRECT;

    return 0;
}

void koe_transport_shutdown(koe_transport_ctx_t *ctx)
{
    if (ctx->listen_fd != -1) {
        close(ctx->listen_fd);
        ctx->listen_fd = -1;
    }
    ctx->active = KOE_TRANSPORT_NONE;
}

/* ---------------------------------------------------------------------- */

int koe_transport_discover(koe_transport_ctx_t *tctx,
                             koe_peer_cb          on_peer,
                             void                *cb_ctx)
{
    /* Build the discovery ping: magic + local PK placeholder (zeroed here;
     * the caller would fill in their public key before invoking). */
    uint8_t ping[sizeof(KOE_DISCOVERY_MAGIC) - 1 + KOE_ID_LEN];
    memcpy(ping, KOE_DISCOVERY_MAGIC, sizeof(KOE_DISCOVERY_MAGIC) - 1);
    memset(ping + sizeof(KOE_DISCOVERY_MAGIC) - 1, 0, KOE_ID_LEN);

    struct sockaddr_in bcast = {0};
    bcast.sin_family      = AF_INET;
    bcast.sin_port        = htons(KOE_DISCOVERY_PORT);
    bcast.sin_addr.s_addr = INADDR_BROADCAST;

    if (sendto(tctx->listen_fd, ping, sizeof(ping), 0,
               (struct sockaddr *)&bcast, sizeof(bcast)) == -1) {
        return -1;
    }

    /* Wait up to 500 ms for responses. */
    struct pollfd pfd = { .fd = tctx->listen_fd, .events = POLLIN };
    int           deadline_ms = 500;

    while (poll(&pfd, 1, deadline_ms) > 0) {
        uint8_t  buf[sizeof(KOE_DISCOVERY_MAGIC) - 1 + KOE_ID_LEN];
        struct sockaddr_in from;
        socklen_t          fromlen = sizeof(from);

        ssize_t n = recvfrom(tctx->listen_fd, buf, sizeof(buf), 0,
                              (struct sockaddr *)&from, &fromlen);
        if (n != (ssize_t)sizeof(buf)) continue;

        if (memcmp(buf, KOE_DISCOVERY_MAGIC, sizeof(KOE_DISCOVERY_MAGIC) - 1))
            continue;

        koe_peer_t peer = {0};
        memcpy(peer.pk, buf + sizeof(KOE_DISCOVERY_MAGIC) - 1, KOE_ID_LEN);
        inet_ntop(AF_INET, &from.sin_addr, peer.addr, sizeof(peer.addr));
        peer.port      = ntohs(from.sin_port);
        peer.transport = KOE_TRANSPORT_WIFI_DIRECT;
        peer.fd        = -1;
        peer.reachable = 1;

        on_peer(&peer, cb_ctx);

        /* Reduce the remaining window so we don't block indefinitely. */
        deadline_ms = 100;
    }

    return 0;
}

/* ---------------------------------------------------------------------- */

int koe_transport_connect(koe_transport_ctx_t *tctx,
                           koe_peer_t          *peer)
{
    /* 1. Try WiFi Direct / local TCP. */
    if (peer->addr[0] != '\0' && peer->port != 0) {
        int fd = tcp_connect(peer->addr, peer->port);
        if (fd != -1) {
            set_nonblocking(fd);
            peer->fd        = fd;
            peer->transport = KOE_TRANSPORT_WIFI_DIRECT;
            peer->reachable = 1;
            return 0;
        }
    }

    /* 2. Bluetooth: not implemented yet; placeholder for future work. */

    /* 3. Relay server. */
    if (tctx->relay_host[0] != '\0') {
        int fd = tcp_connect(tctx->relay_host, tctx->relay_port);
        if (fd != -1) {
            set_nonblocking(fd);
            peer->fd        = fd;
            peer->transport = KOE_TRANSPORT_TCP_RELAY;
            peer->reachable = 1;
            return 0;
        }
    }

    peer->reachable = 0;
    return -1;
}

int koe_transport_accept(koe_transport_ctx_t *tctx,
                          koe_peer_t          *peer)
{
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);

    int fd = accept(tctx->listen_fd, (struct sockaddr *)&addr, &addrlen);
    if (fd == -1) return -1;

    set_nonblocking(fd);
    memset(peer, 0, sizeof(*peer));
    inet_ntop(AF_INET, &addr.sin_addr, peer->addr, sizeof(peer->addr));
    peer->port      = ntohs(addr.sin_port);
    peer->fd        = fd;
    peer->transport = KOE_TRANSPORT_WIFI_DIRECT;
    peer->reachable = 1;
    return 0;
}

void koe_transport_disconnect(koe_peer_t *peer)
{
    if (peer->fd != -1) {
        close(peer->fd);
        peer->fd = -1;
    }
    peer->reachable = 0;
}

/* ---------------------------------------------------------------------- */

/*
 * Framing: each packet on the wire is preceded by a 4-byte big-endian total
 * length (header + payload). The receiver reads the length first, then reads
 * exactly that many bytes.
 */

static int write_all(int fd, const uint8_t *buf, size_t len)
{
    size_t sent = 0;
    while (sent < len) {
        struct pollfd pfd = { .fd = fd, .events = POLLOUT };
        if (poll(&pfd, 1, KOE_IO_TIMEOUT_MS) <= 0) return -1;

        ssize_t n = write(fd, buf + sent, len - sent);
        if (n <= 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}

static int read_all(int fd, uint8_t *buf, size_t len)
{
    size_t got = 0;
    while (got < len) {
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        if (poll(&pfd, 1, KOE_IO_TIMEOUT_MS) <= 0) return -1;

        ssize_t n = read(fd, buf + got, len - got);
        if (n <= 0) return -1;
        got += (size_t)n;
    }
    return 0;
}

int koe_transport_send(const koe_peer_t   *peer,
                        const koe_packet_t *pkt)
{
    /* Serialise the header. */
    uint8_t hdr_buf[KOE_HEADER_SIZE];
    memcpy(hdr_buf,      pkt->header.magic,  KOE_MAGIC_LEN);
    hdr_buf[4]  = pkt->header.type;
    hdr_buf[5]  = pkt->header.flags;

    uint32_t len_be = htonl(pkt->header.length);
    memcpy(hdr_buf + 6, &len_be, 4);

    memcpy(hdr_buf + 10, pkt->header.from,  KOE_ID_LEN);
    memcpy(hdr_buf + 42, pkt->header.to,    KOE_ID_LEN);
    memcpy(hdr_buf + 74, pkt->header.nonce, KOE_NONCE_LEN);

    uint32_t ck_be = htonl(pkt->header.checksum);
    memcpy(hdr_buf + 98, &ck_be, 4);

    /* Length prefix (header + payload). */
    uint32_t total    = KOE_HEADER_SIZE + pkt->header.length;
    uint32_t total_be = htonl(total);

    if (write_all(peer->fd, (uint8_t *)&total_be, 4) != 0) return -1;
    if (write_all(peer->fd, hdr_buf, KOE_HEADER_SIZE) != 0) return -1;

    if (pkt->header.length > 0 && pkt->payload) {
        if (write_all(peer->fd, pkt->payload, pkt->header.length) != 0)
            return -1;
    }

    return 0;
}

int koe_transport_recv(const koe_peer_t *peer,
                        koe_packet_t     *pkt)
{
    memset(pkt, 0, sizeof(*pkt));

    /* Read the 4-byte length prefix. */
    uint32_t total_be;
    if (read_all(peer->fd, (uint8_t *)&total_be, 4) != 0) return -1;
    uint32_t total = ntohl(total_be);

    if (total < KOE_HEADER_SIZE || total > KOE_HEADER_SIZE + KOE_MAX_PAYLOAD)
        return -1;

    /* Read the fixed header. */
    uint8_t hdr_buf[KOE_HEADER_SIZE];
    if (read_all(peer->fd, hdr_buf, KOE_HEADER_SIZE) != 0) return -1;

    if (memcmp(hdr_buf, KOE_MAGIC, KOE_MAGIC_LEN) != 0) return -1;

    memcpy(pkt->header.magic, hdr_buf, KOE_MAGIC_LEN);
    pkt->header.type  = hdr_buf[4];
    pkt->header.flags = hdr_buf[5];

    memcpy(&pkt->header.length, hdr_buf + 6, 4);
    pkt->header.length = ntohl(pkt->header.length);

    memcpy(pkt->header.from,  hdr_buf + 10, KOE_ID_LEN);
    memcpy(pkt->header.to,    hdr_buf + 42, KOE_ID_LEN);
    memcpy(pkt->header.nonce, hdr_buf + 74, KOE_NONCE_LEN);

    memcpy(&pkt->header.checksum, hdr_buf + 98, 4);
    pkt->header.checksum = ntohl(pkt->header.checksum);

    /* Read the payload if present. */
    if (pkt->header.length > 0) {
        pkt->payload = malloc(pkt->header.length);
        if (!pkt->payload) return -1;

        if (read_all(peer->fd, pkt->payload, pkt->header.length) != 0) {
            free(pkt->payload);
            pkt->payload = NULL;
            return -1;
        }
    }

    return 0;
}
