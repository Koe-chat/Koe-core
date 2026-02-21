/*
 * koe_media.h - P2P file and media transfer (LocalSend-inspired protocol).
 *
 * Koe's media transfer is inspired by LocalSend but is its own protocol.
 * It is NOT wire-compatible with the LocalSend app.
 *
 * Design goals:
 *   - Works over the same local network as the Koe P2P transport.
 *   - No internet required.
 *   - Files are encrypted with the same session key as messages.
 *   - Large files are chunked (64 KiB per chunk by default).
 *   - Discovery uses the same mDNS/UDP broadcast as Koe transport.
 *
 * Flow:
 *   Sender                                Receiver
 *   ──────                                ────────
 *   KOE_TYPE_MEDIA_OFFER (metadata)  ──►
 *                                    ◄── KOE_TYPE_MEDIA_ACK (accept/reject)
 *   KOE_TYPE_MEDIA_CHUNK × N         ──►
 *   KOE_TYPE_MEDIA_DONE              ──►
 *                                    ◄── KOE_TYPE_ACK
 *
 * The OFFER payload contains file name, MIME type, size, SHA-256 hash of the
 * plaintext, and the number of chunks.  Each CHUNK payload carries a 4-byte
 * chunk index followed by the encrypted data.  The receiver reassembles and
 * verifies the SHA-256 on DONE.
 *
 * In koe-chat (TUI), received media is saved to the downloads directory.
 * The terminal cannot render images inline, but the file path is shown and
 * the user can open it externally.
 *
 * For Matrix groups, media is uploaded to the koe-server's Matrix media
 * endpoint and referenced by an MXC URI in the message body.  P2P transfer
 * is only used for direct (1:1) messages.
 */

#ifndef KOE_MEDIA_H
#define KOE_MEDIA_H

#include "koe_crypto.h"
#include "koe_packet.h"
#include <stdint.h>
#include <stddef.h>

#define KOE_MEDIA_CHUNK_SIZE        (64 * 1024)   /* 64 KiB per chunk         */
#define KOE_MEDIA_MAX_FILE_SIZE     (512 * 1024 * 1024)  /* 512 MiB hard cap  */
#define KOE_MEDIA_FILENAME_MAX      256
#define KOE_MEDIA_MIME_MAX          128
#define KOE_MEDIA_HASH_LEN          32            /* SHA-256                   */
#define KOE_MEDIA_TRANSFER_ID_LEN   16            /* random per-transfer ID    */

/* ---------------------------------------------------------------------- */
/* Transfer metadata                                                         */
/* ---------------------------------------------------------------------- */

typedef struct {
    uint8_t  transfer_id[KOE_MEDIA_TRANSFER_ID_LEN];
    char     filename[KOE_MEDIA_FILENAME_MAX];
    char     mime_type[KOE_MEDIA_MIME_MAX];
    uint64_t file_size;                     /* plaintext bytes              */
    uint32_t chunk_count;
    uint8_t  sha256[KOE_MEDIA_HASH_LEN];    /* hash of plaintext            */
    uint8_t  sender_pk[KOE_ED25519_PK_LEN];
    uint8_t  recipient_pk[KOE_ED25519_PK_LEN];
    int64_t  offered_at;
} koe_media_offer_t;

/* ---------------------------------------------------------------------- */
/* Transfer state (sender or receiver side)                                  */
/* ---------------------------------------------------------------------- */

typedef enum {
    KOE_MEDIA_IDLE       = 0,
    KOE_MEDIA_OFFERING   = 1,   /* OFFER sent, waiting for ACK     */
    KOE_MEDIA_ACCEPTED   = 2,   /* ACK received, sending chunks    */
    KOE_MEDIA_RECEIVING  = 3,   /* receiving chunks                */
    KOE_MEDIA_DONE       = 4,   /* transfer complete               */
    KOE_MEDIA_REJECTED   = 5,   /* peer rejected the offer         */
    KOE_MEDIA_FAILED     = 6,   /* error during transfer           */
} koe_media_state_t;

typedef struct {
    koe_media_offer_t offer;
    koe_media_state_t state;
    uint32_t          chunks_sent;
    uint32_t          chunks_received;
    char              save_path[512];   /* where to write received data */
    int               fd;               /* file descriptor during transfer */
} koe_media_transfer_t;

/* ---------------------------------------------------------------------- */
/* Sender API                                                                */
/* ---------------------------------------------------------------------- */

/*
 * koe_media_offer_build - Prepare a MEDIA_OFFER packet for a file.
 *
 * file_path:    path to the file on the local filesystem.
 * recipient_pk: the recipient's Ed25519 public key.
 * sess:         active session with the recipient.
 * offer_out:    filled with transfer metadata (keep for subsequent calls).
 * pkt_out:      the MEDIA_OFFER packet to send.
 *
 * Returns 0 on success, -1 if the file cannot be read or is too large.
 */
int koe_media_offer_build(const char           *file_path,
                            const uint8_t         recipient_pk[KOE_ED25519_PK_LEN],
                            const koe_session_t  *sess,
                            koe_media_offer_t    *offer_out,
                            koe_packet_t         *pkt_out);

/*
 * koe_media_chunk_build - Build one MEDIA_CHUNK packet.
 *
 * file_fd:      open file descriptor, seeked to the correct position.
 * chunk_index:  0-based chunk index.
 * offer:        the offer from koe_media_offer_build().
 * sess:         active session.
 * pkt_out:      the packet to send.
 *
 * Returns 0 on success, 1 if this was the last chunk, -1 on error.
 */
int koe_media_chunk_build(int                      file_fd,
                            uint32_t                 chunk_index,
                            const koe_media_offer_t *offer,
                            const koe_session_t     *sess,
                            koe_packet_t            *pkt_out);

/*
 * koe_media_done_build - Build the MEDIA_DONE packet.
 */
int koe_media_done_build(const koe_media_offer_t *offer,
                           const koe_session_t     *sess,
                           koe_packet_t            *pkt_out);

/* ---------------------------------------------------------------------- */
/* Receiver API                                                              */
/* ---------------------------------------------------------------------- */

/*
 * koe_media_offer_parse - Decrypt and parse a received MEDIA_OFFER packet.
 *
 * Returns 0 on success, -1 if the packet is malformed or authentication fails.
 */
int koe_media_offer_parse(const koe_packet_t   *pkt,
                            const koe_session_t  *sess,
                            koe_media_offer_t    *offer_out);

/*
 * koe_media_accept_build - Build a MEDIA_ACK (accept) packet.
 *
 * save_path: where the receiver wants to store the file.
 */
int koe_media_accept_build(const koe_media_offer_t *offer,
                             const koe_session_t     *sess,
                             const char              *save_path,
                             koe_packet_t            *pkt_out);

/*
 * koe_media_reject_build - Build a MEDIA_ACK (reject) packet.
 */
int koe_media_reject_build(const koe_media_offer_t *offer,
                             const koe_session_t     *sess,
                             koe_packet_t            *pkt_out);

/*
 * koe_media_chunk_receive - Decrypt and write one chunk to disk.
 *
 * transfer: the in-progress transfer state.
 * pkt:      the received MEDIA_CHUNK packet.
 * sess:     active session.
 *
 * Returns 0 on success, -1 on error.
 */
int koe_media_chunk_receive(koe_media_transfer_t *transfer,
                              const koe_packet_t   *pkt,
                              const koe_session_t  *sess);

/*
 * koe_media_finalise - Verify SHA-256 and close the file after MEDIA_DONE.
 *
 * Returns 0 if the hash matches, -1 if it does not (discard the file).
 */
int koe_media_finalise(koe_media_transfer_t *transfer);

/* ---------------------------------------------------------------------- */
/* mDNS-style local discovery for media transfers                            */
/* ---------------------------------------------------------------------- */

/*
 * koe_media_announce - Broadcast a transfer announcement on the local network.
 *
 * Used to notify nearby peers that a file is available to receive without
 * an existing session.  The announcement includes the sender's public key
 * and the transfer ID; interested peers initiate a session to receive the
 * OFFER.
 */
int koe_media_announce(const koe_media_offer_t *offer,
                         int                      udp_fd);

/* ---------------------------------------------------------------------- */
/* MIME type detection                                                       */
/* ---------------------------------------------------------------------- */

/*
 * koe_media_mime_from_extension - Guess the MIME type from a file extension.
 *
 * Returns a static string (do not free).  Returns "application/octet-stream"
 * if the extension is unknown.
 */
const char *koe_media_mime_from_extension(const char *filename);

#endif /* KOE_MEDIA_H */
