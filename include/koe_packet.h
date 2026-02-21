/*
 * koe_packet.h - Koe wire-protocol packet format.
 *
 * Every packet on the wire consists of a fixed 106-byte header followed by
 * a variable-length encrypted payload.  The header layout is:
 *
 *   Offset  Size  Field
 *   ------  ----  -----
 *        0     4  magic        "KOE\x01"
 *        4     1  proto_major  KOE_PROTO_MAJOR
 *        5     1  proto_minor  KOE_PROTO_MINOR
 *        6     1  type         packet type (koe_packet_type_t)
 *        7     1  flags        bitmask (koe_packet_flags_t)
 *        8     4  length       payload length, uint32 big-endian
 *       12    32  from         sender Ed25519 public key
 *       44    32  to           recipient Ed25519 public key
 *       76    24  nonce        XChaCha20-Poly1305 nonce
 *      100     4  checksum     CRC32 over bytes [0..99]
 *      104     2  reserved     set to 0, ignored on receive
 *      106     *  payload      encrypted content
 *
 * Total header size: 106 bytes (KOE_HEADER_SIZE).
 *
 * Bindgen notes:
 *   - All integer fields are explicitly sized (uint8_t, uint32_t, ...).
 *   - No anonymous structs or unions.
 *   - koe_packet_t owns its payload allocation; free with koe_packet_free().
 */

#ifndef KOE_PACKET_H
#define KOE_PACKET_H

#include <stdint.h>
#include <stddef.h>

/* Magic bytes at offset 0 — identifies a Koe packet. */
#define KOE_MAGIC         "KOE\x01"
#define KOE_MAGIC_LEN     4

/* Fixed sizes. */
#define KOE_HEADER_SIZE   106
#define KOE_ID_LEN        32    /* Ed25519 public key length */
#define KOE_NONCE_LEN     24    /* XChaCha20-Poly1305 nonce */
#define KOE_TAG_LEN       16    /* Poly1305 authentication tag */
#define KOE_MAX_PAYLOAD   (1024 * 1024)  /* 1 MiB hard cap */

/* ---------------------------------------------------------------------- */
/* Packet types                                                              */
/* ---------------------------------------------------------------------- */

typedef enum {
    KOE_TYPE_HELLO        = 0x01,  /* version + ephemeral key exchange     */
    KOE_TYPE_HELLO_ACK    = 0x02,  /* responder's half of the handshake    */
    KOE_TYPE_ACK          = 0x03,  /* generic acknowledgement              */
    KOE_TYPE_MSG          = 0x04,  /* encrypted text message               */
    KOE_TYPE_AUDIO        = 0x05,  /* encrypted Opus voice frame           */
    KOE_TYPE_PING         = 0x06,  /* liveness probe                       */
    KOE_TYPE_PONG         = 0x07,  /* reply to PING                        */
    KOE_TYPE_QUEUE        = 0x08,  /* offline-queue drain packet           */
    KOE_TYPE_DESTRUCT     = 0x09,  /* self-destruct notification           */
    KOE_TYPE_CHANNEL      = 0x0A,  /* broadcast channel post               */
    KOE_TYPE_MIGRATE      = 0x0B,  /* device migration stream              */
    KOE_TYPE_BACKUP_ACK   = 0x0C,  /* backup upload acknowledged           */
    KOE_TYPE_VERIFY       = 0x0D,  /* identity verification token          */
    KOE_TYPE_REVOKE       = 0x0E,  /* key revocation notice                */
    KOE_TYPE_MEDIA_OFFER  = 0x0F,  /* LocalSend-style file transfer offer  */
    KOE_TYPE_MEDIA_ACK    = 0x10,  /* file transfer accept/reject          */
    KOE_TYPE_MEDIA_CHUNK  = 0x11,  /* file data chunk                      */
    KOE_TYPE_MEDIA_DONE   = 0x12,  /* file transfer complete               */
    KOE_TYPE_GROUP_META   = 0x13,  /* Matrix group metadata update         */
    KOE_TYPE_PRESENCE     = 0x14,  /* presence status update               */
    KOE_TYPE_TYPING       = 0x15,  /* typing indicator                     */
    KOE_TYPE_READ         = 0x16,  /* read receipt                         */
} koe_packet_type_t;

/* ---------------------------------------------------------------------- */
/* Packet flags                                                              */
/* ---------------------------------------------------------------------- */

typedef enum {
    KOE_FLAG_ENCRYPTED  = 0x01,   /* payload is XChaCha20-Poly1305 ciphertext */
    KOE_FLAG_SIGNED     = 0x02,   /* Ed25519 signature appended to payload     */
    KOE_FLAG_FRAGMENTED = 0x04,   /* this is one fragment of a larger message  */
    KOE_FLAG_LAST_FRAG  = 0x08,   /* this is the final fragment                */
    KOE_FLAG_COMPRESSED = 0x10,   /* payload is zlib-compressed before encrypt */
    KOE_FLAG_EPHEMERAL  = 0x20,   /* message carries a self-destruct TTL       */
    KOE_FLAG_SCHEDULED  = 0x40,   /* message has a future delivery timestamp   */
    KOE_FLAG_RELAY      = 0x80,   /* packet is being forwarded by a relay      */
} koe_packet_flags_t;

/* ---------------------------------------------------------------------- */
/* Header struct                                                             */
/* ---------------------------------------------------------------------- */

typedef struct {
    uint8_t  magic[KOE_MAGIC_LEN];   /* "KOE\x01"                          */
    uint8_t  proto_major;            /* protocol major version               */
    uint8_t  proto_minor;            /* protocol minor version               */
    uint8_t  type;                   /* koe_packet_type_t                    */
    uint8_t  flags;                  /* koe_packet_flags_t bitmask           */
    uint32_t length;                 /* payload length in bytes              */
    uint8_t  from[KOE_ID_LEN];      /* sender Ed25519 public key            */
    uint8_t  to[KOE_ID_LEN];        /* recipient Ed25519 public key         */
    uint8_t  nonce[KOE_NONCE_LEN];  /* per-packet XChaCha20 nonce           */
    uint32_t checksum;               /* CRC32 over bytes [0..99]             */
    uint8_t  reserved[2];            /* must be zero                         */
} koe_header_t;

/* ---------------------------------------------------------------------- */
/* Full packet                                                               */
/* ---------------------------------------------------------------------- */

typedef struct {
    koe_header_t  header;
    uint8_t      *payload;   /* heap-allocated; NULL when length == 0 */
} koe_packet_t;

/* ---------------------------------------------------------------------- */
/* Fragment reassembly                                                       */
/* ---------------------------------------------------------------------- */

#define KOE_MAX_FRAGMENTS  256

typedef struct {
    uint8_t  msg_id[16];                /* random ID shared by all fragments */
    uint8_t  total_fragments;
    uint8_t  received;
    uint8_t *fragments[KOE_MAX_FRAGMENTS];
    uint32_t frag_lengths[KOE_MAX_FRAGMENTS];
} koe_reassembly_t;

/* ---------------------------------------------------------------------- */
/* Functions                                                                 */
/* ---------------------------------------------------------------------- */

/*
 * koe_packet_init - Zero-initialise a packet and set the magic + version.
 */
void koe_packet_init(koe_packet_t *pkt, uint8_t type, uint8_t flags);

/*
 * koe_packet_free - Free the payload allocation and zero the struct.
 */
void koe_packet_free(koe_packet_t *pkt);

/*
 * koe_packet_checksum - Compute CRC32 over the first 100 header bytes.
 */
uint32_t koe_packet_checksum(const koe_header_t *hdr);

/*
 * koe_packet_validate - Verify magic, version compatibility, and checksum.
 *
 * Returns 0 if valid, -1 otherwise.
 */
int koe_packet_validate(const koe_packet_t *pkt);

/*
 * koe_packet_serialise - Write the packet to a flat byte buffer.
 *
 * buf must be at least KOE_HEADER_SIZE + pkt->header.length bytes.
 * Returns the total number of bytes written, or -1 on error.
 */
int koe_packet_serialise(const koe_packet_t *pkt, uint8_t *buf, size_t buf_len);

/*
 * koe_packet_deserialise - Parse a flat byte buffer into a packet.
 *
 * Allocates pkt->payload on the heap.  Caller must call koe_packet_free().
 * Returns 0 on success, -1 on error.
 */
int koe_packet_deserialise(koe_packet_t *pkt, const uint8_t *buf, size_t buf_len);

/*
 * koe_packet_fragment - Split a large packet into MTU-sized fragments.
 *
 * out_frags: caller-allocated array of koe_packet_t, at least max_frags long.
 * mtu:       maximum payload bytes per fragment (e.g. 65507 for UDP over WiFi).
 * Returns the number of fragments produced, or -1 on error.
 */
int koe_packet_fragment(const koe_packet_t *pkt,
                         koe_packet_t       *out_frags,
                         int                 max_frags,
                         size_t              mtu);

/*
 * koe_packet_reassemble - Feed a fragment into a reassembly context.
 *
 * Returns 0 while still waiting for fragments, 1 when complete (out_pkt is
 * filled), or -1 on error.
 */
int koe_packet_reassemble(koe_reassembly_t *ctx,
                            const koe_packet_t *frag,
                            koe_packet_t       *out_pkt);

#endif /* KOE_PACKET_H */
