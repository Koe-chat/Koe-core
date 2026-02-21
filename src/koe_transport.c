/*
 * koe_transport.c - Transport layer: WiFi Direct, Bluetooth, TCP relay, WebSocket.
 */

#include "koe_transport.h"
#include "koe_packet.h"
#include "koe_event.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>

/* ---------------------------------------------------------------------- */
/* Internal helpers                                                          */
/* ---------------------------------------------------------------------- */

static int set_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int set_reuseaddr(int fd)
{
    int v = 1;
    return setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &v, sizeof(v));
}

/* Read exactly n bytes from fd, blocking. */
static int read_exact(int fd, uint8_t *buf, size_t n)
{
    size_t got = 0;
    while (got < n) {
        ssize_t r = recv(fd, buf + got, n - got, 0);
        if (r <= 0) return -1;
        got += (size_t)r;
    }
    return 0;
}

/* Write exactly n bytes to fd. */
static int write_exact(int fd, const uint8_t *buf, size_t n)
{
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = send(fd, buf + sent, n - sent, MSG_NOSIGNAL);
        if (w <= 0) return -1;
        sent += (size_t)w;
    }
    return 0;
}

/* ---------------------------------------------------------------------- */
/* Lifecycle                                                                 */
/* ---------------------------------------------------------------------- */

int koe_transport_init(koe_transport_ctx_t *ctx,
                        const char          *relay_host,
                        uint16_t             relay_port,
                        int                  ws_port)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->listen_fd     = -1;
    ctx->tcp_listen_fd = -1;
    ctx->ws_listen_fd  = -1;

    if (relay_host) {
        strncpy(ctx->relay_host, relay_host, sizeof(ctx->relay_host) - 1);
        ctx->relay_port = relay_port ? relay_port : KOE_RELAY_PORT_DEF;
    }

    /* UDP discovery socket. */
    ctx->listen_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (ctx->listen_fd < 0) {
        perror("koe_transport_init: UDP socket");
        return -1;
    }
    set_reuseaddr(ctx->listen_fd);

    struct sockaddr_in sa = {0};
    sa.sin_family      = AF_INET;
    sa.sin_port        = htons(KOE_DISCOVERY_PORT);
    sa.sin_addr.s_addr = INADDR_ANY;
    if (bind(ctx->listen_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("koe_transport_init: UDP bind");
        /* Not fatal on Android where the port may be in use. */
    }

    /* TCP listen socket (incoming sessions). */
    ctx->tcp_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (ctx->tcp_listen_fd >= 0) {
        set_reuseaddr(ctx->tcp_listen_fd);
        struct sockaddr_in ts = {0};
        ts.sin_family      = AF_INET;
        ts.sin_port        = htons(KOE_RELAY_PORT_DEF);
        ts.sin_addr.s_addr = INADDR_ANY;
        if (bind(ctx->tcp_listen_fd, (struct sockaddr *)&ts, sizeof(ts)) < 0 ||
            listen(ctx->tcp_listen_fd, 8) < 0) {
            close(ctx->tcp_listen_fd);
            ctx->tcp_listen_fd = -1;
        }
    }

    /* WebSocket listen socket. */
    if (ws_port > 0) {
        ctx->ws_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (ctx->ws_listen_fd >= 0) {
            set_reuseaddr(ctx->ws_listen_fd);
            struct sockaddr_in ws = {0};
            ws.sin_family      = AF_INET;
            ws.sin_port        = htons((uint16_t)ws_port);
            ws.sin_addr.s_addr = INADDR_ANY;
            if (bind(ctx->ws_listen_fd, (struct sockaddr *)&ws, sizeof(ws)) < 0 ||
                listen(ctx->ws_listen_fd, 8) < 0) {
                close(ctx->ws_listen_fd);
                ctx->ws_listen_fd = -1;
            }
        }
    }

    return 0;
}

void koe_transport_shutdown(koe_transport_ctx_t *ctx)
{
    if (ctx->listen_fd     >= 0) { close(ctx->listen_fd);     ctx->listen_fd     = -1; }
    if (ctx->tcp_listen_fd >= 0) { close(ctx->tcp_listen_fd); ctx->tcp_listen_fd = -1; }
    if (ctx->ws_listen_fd  >= 0) { close(ctx->ws_listen_fd);  ctx->ws_listen_fd  = -1; }
}

/* ---------------------------------------------------------------------- */
/* Discovery                                                                */
/* ---------------------------------------------------------------------- */

/* Discovery ping payload: magic(4) + pk(32) + ver_major(1) + ver_minor(1) = 38. */
#define DISCO_PAYLOAD 38
static const uint8_t DISCO_MAGIC[4] = { 'K','D','S','C' };

int koe_transport_discover(koe_transport_ctx_t *ctx,
                             const koe_identity_t *local_id,
                             koe_peer_cb           on_peer,
                             void                 *cb_ctx)
{
    if (ctx->listen_fd < 0) return -1;

    uint8_t buf[DISCO_PAYLOAD];
    memcpy(buf,      DISCO_MAGIC,    4);
    memcpy(buf + 4,  local_id->pk,  KOE_ED25519_PK_LEN);
    buf[36] = KOE_PROTO_MAJOR;
    buf[37] = KOE_PROTO_MINOR;

    /* Broadcast. */
    int bcast = 1;
    setsockopt(ctx->listen_fd, SOL_SOCKET, SO_BROADCAST, &bcast, sizeof(bcast));

    struct sockaddr_in dst = {0};
    dst.sin_family      = AF_INET;
    dst.sin_port        = htons(KOE_DISCOVERY_PORT);
    dst.sin_addr.s_addr = INADDR_BROADCAST;
    sendto(ctx->listen_fd, buf, DISCO_PAYLOAD, 0,
           (struct sockaddr *)&dst, sizeof(dst));

    /* Collect replies for KOE_DISCOVERY_TTL_MS. */
    struct timeval tv;
    tv.tv_sec  = KOE_DISCOVERY_TTL_MS / 1000;
    tv.tv_usec = (KOE_DISCOVERY_TTL_MS % 1000) * 1000;

    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(ctx->listen_fd, &rfds);

    while (select(ctx->listen_fd + 1, &rfds, NULL, NULL, &tv) > 0) {
        uint8_t reply[DISCO_PAYLOAD];
        struct sockaddr_in src;
        socklen_t src_len = sizeof(src);
        ssize_t n = recvfrom(ctx->listen_fd, reply, sizeof(reply), 0,
                              (struct sockaddr *)&src, &src_len);
        if (n != DISCO_PAYLOAD) break;
        if (memcmp(reply, DISCO_MAGIC, 4) != 0) break;
        if (memcmp(reply + 4, local_id->pk, KOE_ED25519_PK_LEN) == 0) break;

        koe_peer_t peer = {0};
        memcpy(peer.pk, reply + 4, KOE_ED25519_PK_LEN);
        inet_ntop(AF_INET, &src.sin_addr, peer.addr, sizeof(peer.addr));
        peer.port      = KOE_RELAY_PORT_DEF;
        peer.fd        = -1;
        peer.transport = KOE_TRANSPORT_WIFI_DIRECT;
        peer.version.major = reply[36];
        peer.version.minor = reply[37];
        peer.reachable = 1;

        on_peer(&peer, cb_ctx);

        FD_ZERO(&rfds);
        FD_SET(ctx->listen_fd, &rfds);
    }

    return 0;
}

int koe_transport_handle_discovery(koe_transport_ctx_t *ctx,
                                    const koe_identity_t *local_id,
                                    koe_peer_cb           on_peer,
                                    void                 *cb_ctx)
{
    if (ctx->listen_fd < 0) return -1;

    uint8_t buf[DISCO_PAYLOAD];
    struct sockaddr_in src;
    socklen_t src_len = sizeof(src);
    ssize_t n = recvfrom(ctx->listen_fd, buf, sizeof(buf), 0,
                          (struct sockaddr *)&src, &src_len);
    if (n != DISCO_PAYLOAD) return -1;
    if (memcmp(buf, DISCO_MAGIC, 4) != 0) return -1;
    if (memcmp(buf + 4, local_id->pk, KOE_ED25519_PK_LEN) == 0) return 0; /* our own ping */

    /* Reply with our identity. */
    uint8_t reply[DISCO_PAYLOAD];
    memcpy(reply,      DISCO_MAGIC,    4);
    memcpy(reply + 4,  local_id->pk,  KOE_ED25519_PK_LEN);
    reply[36] = KOE_PROTO_MAJOR;
    reply[37] = KOE_PROTO_MINOR;
    sendto(ctx->listen_fd, reply, DISCO_PAYLOAD, 0,
           (struct sockaddr *)&src, src_len);

    koe_peer_t peer = {0};
    memcpy(peer.pk, buf + 4, KOE_ED25519_PK_LEN);
    inet_ntop(AF_INET, &src.sin_addr, peer.addr, sizeof(peer.addr));
    peer.port      = KOE_RELAY_PORT_DEF;
    peer.fd        = -1;
    peer.transport = KOE_TRANSPORT_WIFI_DIRECT;
    peer.version.major = buf[36];
    peer.version.minor = buf[37];
    peer.reachable = 1;

    on_peer(&peer, cb_ctx);
    return 0;
}

/* ---------------------------------------------------------------------- */
/* Connection                                                               */
/* ---------------------------------------------------------------------- */

int koe_transport_connect(koe_transport_ctx_t *ctx, koe_peer_t *peer)
{
    /* Try WiFi Direct (local TCP) first. */
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(peer->port ? peer->port : KOE_RELAY_PORT_DEF);
    if (inet_pton(AF_INET, peer->addr, &sa.sin_addr) != 1) {
        close(fd);
        /* Try relay. */
        goto try_relay;
    }

    struct timeval tv = { KOE_IO_TIMEOUT_MS / 1000,
                          (KOE_IO_TIMEOUT_MS % 1000) * 1000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) == 0) {
        peer->fd        = fd;
        peer->transport = KOE_TRANSPORT_WIFI_DIRECT;
        peer->reachable = 1;
        return 0;
    }
    close(fd);

try_relay:
    if (!ctx->relay_host[0]) return -1;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", ctx->relay_port);
    if (getaddrinfo(ctx->relay_host, port_str, &hints, &res) != 0) {
        close(fd); return -1;
    }

    struct timeval tv2 = { KOE_IO_TIMEOUT_MS / 1000,
                           (KOE_IO_TIMEOUT_MS % 1000) * 1000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv2, sizeof(tv2));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv2, sizeof(tv2));

    int rc = connect(fd, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);
    if (rc != 0) { close(fd); return -1; }

    peer->fd        = fd;
    peer->transport = KOE_TRANSPORT_TCP_RELAY;
    peer->reachable = 1;
    return 0;
}

int koe_transport_accept(koe_transport_ctx_t *ctx, koe_peer_t *peer)
{
    if (ctx->tcp_listen_fd < 0) return -1;

    struct sockaddr_in src;
    socklen_t src_len = sizeof(src);
    int fd = accept(ctx->tcp_listen_fd, (struct sockaddr *)&src, &src_len);
    if (fd < 0) return -1;

    memset(peer, 0, sizeof(*peer));
    peer->fd        = fd;
    peer->port      = ntohs(src.sin_port);
    peer->transport = KOE_TRANSPORT_WIFI_DIRECT;
    peer->reachable = 1;
    inet_ntop(AF_INET, &src.sin_addr, peer->addr, sizeof(peer->addr));

    struct timeval tv = { KOE_IO_TIMEOUT_MS / 1000,
                          (KOE_IO_TIMEOUT_MS % 1000) * 1000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    return 0;
}

void koe_transport_disconnect(koe_peer_t *peer)
{
    if (peer->fd >= 0) { close(peer->fd); peer->fd = -1; }
    peer->reachable = 0;
}

/* ---------------------------------------------------------------------- */
/* Send / receive (4-byte length prefix framing)                            */
/* ---------------------------------------------------------------------- */

int koe_transport_send(const koe_peer_t *peer, const koe_packet_t *pkt)
{
    if (peer->fd < 0) return -1;

    size_t total = KOE_HEADER_SIZE + pkt->header.length;
    uint8_t *buf = malloc(total);
    if (!buf) return -1;

    if (koe_packet_serialise(pkt, buf, total) < 0) { free(buf); return -1; }

    uint32_t len_be = htonl((uint32_t)total);
    if (write_exact(peer->fd, (uint8_t *)&len_be, 4) != 0 ||
        write_exact(peer->fd, buf, total) != 0) {
        free(buf); return -1;
    }

    free(buf);
    return 0;
}

int koe_transport_recv(const koe_peer_t *peer, koe_packet_t *pkt)
{
    if (peer->fd < 0) return -1;

    uint32_t len_be;
    if (read_exact(peer->fd, (uint8_t *)&len_be, 4) != 0) return -1;
    uint32_t total = ntohl(len_be);

    if (total < KOE_HEADER_SIZE || total > KOE_HEADER_SIZE + KOE_MAX_PAYLOAD) return -1;

    uint8_t *buf = malloc(total);
    if (!buf) return -1;

    if (read_exact(peer->fd, buf, total) != 0) { free(buf); return -1; }

    int rc = koe_packet_deserialise(pkt, buf, total);
    free(buf);
    return rc;
}

/* ---------------------------------------------------------------------- */
/* WebSocket (minimal, binary frames only)                                  */
/* ---------------------------------------------------------------------- */

int koe_transport_ws_accept(koe_transport_ctx_t *ctx)
{
    if (ctx->ws_listen_fd < 0) return -1;
    struct sockaddr_in src;
    socklen_t len = sizeof(src);
    int fd = accept(ctx->ws_listen_fd, (struct sockaddr *)&src, &len);
    if (fd < 0) return -1;

    /* Perform HTTP Upgrade handshake.
     * Read until "\r\n\r\n" then respond with 101 Switching Protocols. */
    char http_buf[2048] = {0};
    int  n = (int)recv(fd, http_buf, sizeof(http_buf) - 1, 0);
    if (n <= 0) { close(fd); return -1; }

    /* Extract Sec-WebSocket-Key. */
    const char *key_hdr = strstr(http_buf, "Sec-WebSocket-Key:");
    if (!key_hdr) { close(fd); return -1; }
    key_hdr += 18;
    while (*key_hdr == ' ') key_hdr++;
    char key[64] = {0};
    int  ki = 0;
    while (*key_hdr && *key_hdr != '\r' && ki < 63)
        key[ki++] = *key_hdr++;

    /* Compute accept key: base64(SHA1(key + GUID)). */
    /* Minimal implementation — a full SHA1+base64 would be added in production. */
    const char *guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    char combined[128];
    snprintf(combined, sizeof(combined), "%s%s", key, guid);

    /* TODO: proper SHA1+base64 for the accept key. */
    const char *accept_key = "dGhlIHNhbXBsZSBub25jZQ=="; /* placeholder */

    char response[512];
    snprintf(response, sizeof(response),
             "HTTP/1.1 101 Switching Protocols\r\n"
             "Upgrade: websocket\r\n"
             "Connection: Upgrade\r\n"
             "Sec-WebSocket-Accept: %s\r\n\r\n",
             accept_key);

    send(fd, response, strlen(response), 0);
    return fd;
}

int koe_transport_ws_send(int fd, const koe_packet_t *pkt)
{
    size_t payload_len = KOE_HEADER_SIZE + pkt->header.length;
    uint8_t *payload   = malloc(payload_len);
    if (!payload) return -1;
    koe_packet_serialise(pkt, payload, payload_len);

    /* WebSocket binary frame header. */
    uint8_t frame_hdr[10];
    int     hdr_len;
    frame_hdr[0] = 0x82; /* FIN + binary opcode */
    if (payload_len <= 125) {
        frame_hdr[1] = (uint8_t)payload_len;
        hdr_len = 2;
    } else if (payload_len <= 65535) {
        frame_hdr[1] = 126;
        frame_hdr[2] = (uint8_t)(payload_len >> 8);
        frame_hdr[3] = (uint8_t)(payload_len & 0xFF);
        hdr_len = 4;
    } else {
        frame_hdr[1] = 127;
        for (int i = 0; i < 8; i++)
            frame_hdr[2 + i] = (uint8_t)(payload_len >> (56 - 8 * i));
        hdr_len = 10;
    }

    write_exact(fd, frame_hdr, (size_t)hdr_len);
    write_exact(fd, payload, payload_len);
    free(payload);
    return 0;
}

int koe_transport_ws_recv(int fd, koe_packet_t *pkt)
{
    /* Read WebSocket frame header. */
    uint8_t hdr[2];
    if (read_exact(fd, hdr, 2) != 0) return -1;

    int     masked      = (hdr[1] & 0x80) ? 1 : 0;
    uint64_t payload_len = hdr[1] & 0x7F;

    if (payload_len == 126) {
        uint8_t ext[2];
        if (read_exact(fd, ext, 2) != 0) return -1;
        payload_len = ((uint64_t)ext[0] << 8) | ext[1];
    } else if (payload_len == 127) {
        uint8_t ext[8];
        if (read_exact(fd, ext, 8) != 0) return -1;
        payload_len = 0;
        for (int i = 0; i < 8; i++)
            payload_len = (payload_len << 8) | ext[i];
    }

    uint8_t mask[4] = {0};
    if (masked) {
        if (read_exact(fd, mask, 4) != 0) return -1;
    }

    if (payload_len > KOE_HEADER_SIZE + KOE_MAX_PAYLOAD) return -1;

    uint8_t *buf = malloc((size_t)payload_len);
    if (!buf) return -1;
    if (read_exact(fd, buf, (size_t)payload_len) != 0) { free(buf); return -1; }

    if (masked) {
        for (uint64_t i = 0; i < payload_len; i++)
            buf[i] ^= mask[i % 4];
    }

    int rc = koe_packet_deserialise(pkt, buf, (size_t)payload_len);
    free(buf);
    return rc;
}

/* ---------------------------------------------------------------------- */
/* fd_set population                                                        */
/* ---------------------------------------------------------------------- */

int koe_transport_fd_set(const koe_transport_ctx_t *ctx, void *fd_set_ptr)
{
    fd_set *fds = (fd_set *)fd_set_ptr;
    int maxfd   = -1;
    if (ctx->listen_fd >= 0)     { FD_SET(ctx->listen_fd,     fds); if (ctx->listen_fd     > maxfd) maxfd = ctx->listen_fd;     }
    if (ctx->tcp_listen_fd >= 0) { FD_SET(ctx->tcp_listen_fd, fds); if (ctx->tcp_listen_fd > maxfd) maxfd = ctx->tcp_listen_fd; }
    if (ctx->ws_listen_fd >= 0)  { FD_SET(ctx->ws_listen_fd,  fds); if (ctx->ws_listen_fd  > maxfd) maxfd = ctx->ws_listen_fd;  }
    return maxfd;
}

const char *koe_transport_type_string(koe_transport_type_t t)
{
    switch (t) {
    case KOE_TRANSPORT_WIFI_DIRECT: return "WiFi-Direct";
    case KOE_TRANSPORT_BLUETOOTH:   return "Bluetooth";
    case KOE_TRANSPORT_TCP_RELAY:   return "TCP-Relay";
    case KOE_TRANSPORT_WEBSOCKET:   return "WebSocket";
    default:                        return "None";
    }
}
