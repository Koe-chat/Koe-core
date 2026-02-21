/*
 * koe_packet.h - Wire format and packet definitions for the Koe protocol.
 *
 * All multi-byte integers are big-endian on the wire. The serialise /
 * deserialise helpers handle byte-swapping transparently on the host side.
 *
 * Fixed header layout (102 bytes total):
 *
 *   Offset  Size  Field
 *   ------  ----  -----
 *        0     4  magic       "KOE\x01"
 *        4     1  type        packet type (KOE_TYPE_*)
 *        5     1  flags       bitmask (KOE_FLAG_*)
 *        6     4  length      payload length, uint32 big-endian
 *       10    32  from        sender Ed25519 public key
 *       42    32  to          recipient Ed25519 public key
 *       74    24  nonce       XChaCha20-Poly1305 nonce
 *       98     4  checksum    CRC32 of bytes [0..97]
 *      102     *  payload     encrypted content, `length` bytes
 */

#ifndef KOE_PACKET_H
#define KOE_PACKET_H

#include <stddef.h>
#include <stdint.h>

#define KOE_MAGIC           "KOE\x01"
#define KOE_MAGIC_LEN       4
#define KOE_HEADER_SIZE     102
#define KOE_MAX_PAYLOAD     65536
#define KOE_ID_LEN          32
#define KOE_NONCE_LEN       24
#define KOE_TAG_LEN         16

/* Packet types ----------------------------------------------------------- */
#define KOE_TYPE_HANDSHAKE  0x01  /* key exchange, first contact          */
#define KOE_TYPE_ACK        0x02  /* delivery acknowledgement             */
#define KOE_TYPE_MSG        0x03  /* text or file message                 */
#define KOE_TYPE_AUDIO      0x04  /* Opus-encoded voice frame (live call) */
#define KOE_TYPE_PING       0x05  /* liveness probe                       */
#define KOE_TYPE_PONG       0x06  /* ping reply                           */
#define KOE_TYPE_QUEUE      0x07  /* offline message relay delivery       */
#define KOE_TYPE_DESTRUCT   0x08  /* self-destruct timer negotiation      */
#define KOE_TYPE_CHANNEL    0x09  /* broadcast channel message            */
#define KOE_TYPE_MIGRATE    0x0A  /* device migration chunk               */
#define KOE_TYPE_BACKUP     0x0B  /* server backup chunk                  */
#define KOE_TYPE_VERIFY     0x0C  /* identity verification token          */
#define KOE_TYPE_REVOKE     0x0D  /* key revocation notice                */
#define KOE_TYPE_DISCOVERY  0x0E  /* local peer discovery ping/reply      */
#define KOE_TYPE_CALL_SIG   0x0F  /* call signalling (start / end)        */

/* Flags bitmask ---------------------------------------------------------- */
#define KOE_FLAG_ENCRYPTED  0x01  /* payload is encrypted + authenticated */
#define KOE_FLAG_SIGNED     0x02  /* Ed25519 signature appended           */
#define KOE_FLAG_FRAGMENTED 0x04  /* this is a fragment, more follow      */
#define KOE_FLAG_LAST_FRAG  0x08  /* this is the final fragment           */
#define KOE_FLAG_COMPRESSED 0x10  /* payload compressed before encryption */
#define KOE_FLAG_EPHEMERAL  0x20  /* do not persist to conversation store */

/* In-memory header (host byte order) ------------------------------------- */
typedef struct {
    uint8_t  magic[KOE_MAGIC_LEN];
    uint8_t  type;
    uint8_t  flags;
    uint32_t length;               /* payload length in bytes */
    uint8_t  from[KOE_ID_LEN];    /* sender Ed25519 public key */
    uint8_t  to[KOE_ID_LEN];      /* recipient Ed25519 public key */
    uint8_t  nonce[KOE_NONCE_LEN];
    uint32_t checksum;
} koe_header_t;

typedef struct {
    koe_header_t  header;
    uint8_t      *payload;         /* heap-allocated; free with koe_packet_free */
} koe_packet_t;

/* Packet lifecycle ------------------------------------------------------- */

/* Allocate a packet with a zeroed header and a payload buffer of the given
 * size. Sets magic, type, and flags. Returns NULL on allocation failure. */
koe_packet_t *koe_packet_alloc(uint8_t type, uint8_t flags, size_t payload_len);

/* Release a packet and its payload buffer. Safe to call with NULL. */
void koe_packet_free(koe_packet_t *pkt);

/* Serialise a packet to a flat byte buffer ready to hand to the transport.
 * Computes and writes the checksum automatically.
 * `out` must be at least KOE_HEADER_SIZE + pkt->header.length bytes.
 * Returns the total bytes written, or -1 on error. */
int koe_packet_serialise(const koe_packet_t *pkt,
                          uint8_t            *out,
                          size_t              out_len);

/* Parse a flat byte buffer into a koe_packet_t. Verifies the magic bytes
 * and checksum. Payload is heap-allocated; caller must call koe_packet_free.
 * Returns 0 on success, -1 on verification failure or allocation error. */
int koe_packet_deserialise(koe_packet_t  *pkt,
                             const uint8_t *buf,
                             size_t         buf_len);

/* CRC32 over `len` bytes starting at `data`. */
uint32_t koe_checksum(const uint8_t *data, size_t len);

#endif /* KOE_PACKET_H */
