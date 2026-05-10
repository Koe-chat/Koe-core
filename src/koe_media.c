/*
 * koe_media.c - LocalSend-inspired P2P file transfer.
 */

#include "koe_media.h"
#include "koe_crypto.h"
#include "koe_packet.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <sodium.h>

/* ---------------------------------------------------------------------- */
/* Internal: compute SHA-256 of a file                                      */
/* ---------------------------------------------------------------------- */

static int sha256_file(const char *path, uint8_t hash[KOE_MEDIA_HASH_LEN])
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    crypto_hash_sha256_state state;
    crypto_hash_sha256_init(&state);

    uint8_t buf[8192];
    size_t  n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
        crypto_hash_sha256_update(&state, buf, n);

    fclose(f);
    crypto_hash_sha256_final(&state, hash);
    return 0;
}

/* ---------------------------------------------------------------------- */
/* MIME type table                                                           */
/* ---------------------------------------------------------------------- */

static const struct { const char *ext; const char *mime; } MIME_TABLE[] = {
    { "jpg",  "image/jpeg"               },
    { "jpeg", "image/jpeg"               },
    { "png",  "image/png"                },
    { "gif",  "image/gif"                },
    { "webp", "image/webp"               },
    { "mp4",  "video/mp4"                },
    { "mkv",  "video/x-matroska"         },
    { "mp3",  "audio/mpeg"               },
    { "ogg",  "audio/ogg"                },
    { "opus", "audio/opus"               },
    { "pdf",  "application/pdf"          },
    { "zip",  "application/zip"          },
    { "txt",  "text/plain"               },
    { "md",   "text/markdown"            },
    { NULL,   NULL                       },
};

const char *koe_media_mime_from_extension(const char *filename)
{
    const char *dot = strrchr(filename, '.');
    if (!dot || dot[1] == '\0') return "application/octet-stream";
    dot++;
    for (int i = 0; MIME_TABLE[i].ext; i++) {
        if (strcasecmp(MIME_TABLE[i].ext, dot) == 0)
            return MIME_TABLE[i].mime;
    }
    return "application/octet-stream";
}

/* ---------------------------------------------------------------------- */
/* Sender API                                                               */
/* ---------------------------------------------------------------------- */

int koe_media_offer_build(const char           *file_path,
                            const uint8_t         recipient_pk[KOE_ED25519_PK_LEN],
                            const koe_session_t  *sess,
                            koe_media_offer_t    *offer_out,
                            koe_packet_t         *pkt_out)
{
    /* Stat the file. */
    struct stat st;
    if (stat(file_path, &st) != 0) return -1;
    if ((uint64_t)st.st_size > KOE_MEDIA_MAX_FILE_SIZE) return -1;

    memset(offer_out, 0, sizeof(*offer_out));
    randombytes_buf(offer_out->transfer_id, KOE_MEDIA_TRANSFER_ID_LEN);
    memcpy(offer_out->recipient_pk, recipient_pk, KOE_ED25519_PK_LEN);
    offer_out->file_size   = (uint64_t)st.st_size;
    offer_out->chunk_count = (uint32_t)((st.st_size + KOE_MEDIA_CHUNK_SIZE - 1)
                                         / KOE_MEDIA_CHUNK_SIZE);
    offer_out->offered_at  = (int64_t)time(NULL);

    /* Extract filename. */
    const char *basename = strrchr(file_path, '/');
    basename = basename ? basename + 1 : file_path;
    strncpy(offer_out->filename, basename, KOE_MEDIA_FILENAME_MAX - 1);
    strncpy(offer_out->mime_type, koe_media_mime_from_extension(basename),
            KOE_MEDIA_MIME_MAX - 1);

    /* Hash plaintext. */
    if (sha256_file(file_path, offer_out->sha256) != 0) return -1;

    /* Serialize offer into a plaintext buffer. */
    size_t plain_len = sizeof(*offer_out);
    uint8_t *ct      = malloc(plain_len + KOE_TAG_LEN);
    if (!ct) return -1;

    uint8_t nonce[KOE_NONCE_LEN];
    koe_nonce_generate(nonce);
    if (koe_encrypt(ct, (const uint8_t *)offer_out, plain_len,
                     nonce, sess->tx_key) != 0) {
        free(ct); return -1;
    }

    koe_packet_init(pkt_out, KOE_TYPE_MEDIA_OFFER, KOE_FLAG_ENCRYPTED);
    pkt_out->header.length = (uint32_t)(plain_len + KOE_TAG_LEN);
    memcpy(pkt_out->header.from, offer_out->sender_pk, KOE_ID_LEN);
    memcpy(pkt_out->header.to,   recipient_pk,         KOE_ID_LEN);
    memcpy(pkt_out->header.nonce, nonce,                KOE_NONCE_LEN);
    pkt_out->header.checksum = koe_packet_checksum(&pkt_out->header);
    pkt_out->payload = ct;
    return 0;
}

int koe_media_chunk_build(int file_fd, uint32_t chunk_index,
                            const koe_media_offer_t *offer,
                            const koe_session_t *sess, koe_packet_t *pkt_out)
{
    off_t offset = (off_t)chunk_index * KOE_MEDIA_CHUNK_SIZE;
    if (lseek(file_fd, offset, SEEK_SET) < 0) return -1;

    size_t   remaining   = (size_t)(offer->file_size - (uint64_t)offset);
    size_t   chunk_bytes = remaining < KOE_MEDIA_CHUNK_SIZE ? remaining : KOE_MEDIA_CHUNK_SIZE;
    uint8_t *plain       = malloc(4 + chunk_bytes);  /* 4-byte index prefix */
    if (!plain) return -1;

    uint32_t idx_be = htonl(chunk_index);
    memcpy(plain, &idx_be, 4);
    if (read(file_fd, plain + 4, chunk_bytes) != (ssize_t)chunk_bytes) {
        free(plain); return -1;
    }

    size_t  ct_len = 4 + chunk_bytes + KOE_TAG_LEN;
    uint8_t *ct    = malloc(ct_len);
    if (!ct) { free(plain); return -1; }

    uint8_t nonce[KOE_NONCE_LEN];
    koe_nonce_generate(nonce);
    if (koe_encrypt(ct, plain, 4 + chunk_bytes, nonce, sess->tx_key) != 0) {
        free(plain); free(ct); return -1;
    }
    free(plain);

    koe_packet_init(pkt_out, KOE_TYPE_MEDIA_CHUNK, KOE_FLAG_ENCRYPTED);
    pkt_out->header.length = (uint32_t)ct_len;
    memcpy(pkt_out->header.to,    offer->recipient_pk, KOE_ID_LEN);
    memcpy(pkt_out->header.from,  offer->sender_pk,    KOE_ID_LEN);
    memcpy(pkt_out->header.nonce, nonce,                KOE_NONCE_LEN);
    pkt_out->header.flags |= KOE_FLAG_FRAGMENTED;
    if (chunk_index == offer->chunk_count - 1)
        pkt_out->header.flags |= KOE_FLAG_LAST_FRAG;
    pkt_out->header.checksum = koe_packet_checksum(&pkt_out->header);
    pkt_out->payload = ct;

    return (chunk_index == offer->chunk_count - 1) ? 1 : 0;
}

int koe_media_done_build(const koe_media_offer_t *offer,
                           const koe_session_t *sess, koe_packet_t *pkt_out)
{
    uint8_t plain[KOE_MEDIA_HASH_LEN];
    memcpy(plain, offer->sha256, KOE_MEDIA_HASH_LEN);

    size_t  ct_len = KOE_MEDIA_HASH_LEN + KOE_TAG_LEN;
    uint8_t *ct    = malloc(ct_len);
    if (!ct) return -1;

    uint8_t nonce[KOE_NONCE_LEN];
    koe_nonce_generate(nonce);
    if (koe_encrypt(ct, plain, KOE_MEDIA_HASH_LEN, nonce, sess->tx_key) != 0) {
        free(ct); return -1;
    }

    koe_packet_init(pkt_out, KOE_TYPE_MEDIA_DONE, KOE_FLAG_ENCRYPTED);
    pkt_out->header.length = (uint32_t)ct_len;
    memcpy(pkt_out->header.to,    offer->recipient_pk, KOE_ID_LEN);
    memcpy(pkt_out->header.from,  offer->sender_pk,    KOE_ID_LEN);
    memcpy(pkt_out->header.nonce, nonce,                KOE_NONCE_LEN);
    pkt_out->header.checksum = koe_packet_checksum(&pkt_out->header);
    pkt_out->payload = ct;
    return 0;
}

/* ---------------------------------------------------------------------- */
/* Receiver API                                                             */
/* ---------------------------------------------------------------------- */

int koe_media_offer_parse(const koe_packet_t *pkt, const koe_session_t *sess,
                            koe_media_offer_t *offer_out)
{
    if (!pkt->payload || pkt->header.length <= KOE_TAG_LEN) return -1;
    size_t plain_len = pkt->header.length - KOE_TAG_LEN;
    if (plain_len < sizeof(*offer_out)) return -1;

    uint8_t *plain = malloc(plain_len);
    if (!plain) return -1;
    if (koe_decrypt(plain, pkt->payload, pkt->header.length,
                     pkt->header.nonce, sess->rx_key) != 0) {
        free(plain); return -1;
    }
    memcpy(offer_out, plain, sizeof(*offer_out));
    free(plain);
    return 0;
}

int koe_media_accept_build(const koe_media_offer_t *offer,
                             const koe_session_t *sess,
                             const char *save_path, koe_packet_t *pkt_out)
{
    size_t plain_len = KOE_MEDIA_TRANSFER_ID_LEN + 1; /* id + accept byte */
    uint8_t plain[KOE_MEDIA_TRANSFER_ID_LEN + 1];
    memcpy(plain, offer->transfer_id, KOE_MEDIA_TRANSFER_ID_LEN);
    plain[KOE_MEDIA_TRANSFER_ID_LEN] = 1; /* accept */

    size_t  ct_len = plain_len + KOE_TAG_LEN;
    uint8_t *ct    = malloc(ct_len);
    if (!ct) return -1;
    uint8_t nonce[KOE_NONCE_LEN];
    koe_nonce_generate(nonce);
    if (koe_encrypt(ct, plain, plain_len, nonce, sess->tx_key) != 0) {
        free(ct); return -1;
    }

    koe_packet_init(pkt_out, KOE_TYPE_MEDIA_ACK, KOE_FLAG_ENCRYPTED);
    pkt_out->header.length = (uint32_t)ct_len;
    memcpy(pkt_out->header.to,    offer->sender_pk,    KOE_ID_LEN);
    memcpy(pkt_out->header.from,  offer->recipient_pk, KOE_ID_LEN);
    memcpy(pkt_out->header.nonce, nonce,                KOE_NONCE_LEN);
    pkt_out->header.checksum = koe_packet_checksum(&pkt_out->header);
    pkt_out->payload = ct;
    (void)save_path;
    return 0;
}

int koe_media_reject_build(const koe_media_offer_t *offer,
                             const koe_session_t *sess, koe_packet_t *pkt_out)
{
    uint8_t plain[KOE_MEDIA_TRANSFER_ID_LEN + 1];
    memcpy(plain, offer->transfer_id, KOE_MEDIA_TRANSFER_ID_LEN);
    plain[KOE_MEDIA_TRANSFER_ID_LEN] = 0; /* reject */

    size_t  ct_len = sizeof(plain) + KOE_TAG_LEN;
    uint8_t *ct    = malloc(ct_len);
    if (!ct) return -1;
    uint8_t nonce[KOE_NONCE_LEN];
    koe_nonce_generate(nonce);
    if (koe_encrypt(ct, plain, sizeof(plain), nonce, sess->tx_key) != 0) {
        free(ct); return -1;
    }

    koe_packet_init(pkt_out, KOE_TYPE_MEDIA_ACK, KOE_FLAG_ENCRYPTED);
    pkt_out->header.length = (uint32_t)ct_len;
    memcpy(pkt_out->header.to,    offer->sender_pk,    KOE_ID_LEN);
    memcpy(pkt_out->header.from,  offer->recipient_pk, KOE_ID_LEN);
    memcpy(pkt_out->header.nonce, nonce,                KOE_NONCE_LEN);
    pkt_out->header.checksum = koe_packet_checksum(&pkt_out->header);
    pkt_out->payload = ct;
    return 0;
}

int koe_media_chunk_receive(koe_media_transfer_t *transfer,
                              const koe_packet_t *pkt,
                              const koe_session_t *sess)
{
    if (!pkt->payload || pkt->header.length <= KOE_TAG_LEN) return -1;
    size_t plain_len = pkt->header.length - KOE_TAG_LEN;
    uint8_t *plain = malloc(plain_len);
    if (!plain) return -1;

    if (koe_decrypt(plain, pkt->payload, pkt->header.length,
                     pkt->header.nonce, sess->rx_key) != 0) {
        free(plain); return -1;
    }

    /* First 4 bytes = chunk index. */
    if (plain_len < 4) { free(plain); return -1; }
    uint32_t idx_be; memcpy(&idx_be, plain, 4);
    /* uint32_t idx = ntohl(idx_be); */

    /* Write data (skip 4-byte index prefix). */
    size_t data_len = plain_len - 4;
    if (write(transfer->fd, plain + 4, data_len) != (ssize_t)data_len) {
        free(plain); return -1;
    }
    free(plain);

    transfer->chunks_received++;
    return 0;
}

int koe_media_finalise(koe_media_transfer_t *transfer)
{
    close(transfer->fd);
    transfer->fd = -1;

    /* Compute SHA-256 of the written file and compare. */
    uint8_t actual[KOE_MEDIA_HASH_LEN];
    if (sha256_file(transfer->save_path, actual) != 0) return -1;
    return memcmp(actual, transfer->offer.sha256, KOE_MEDIA_HASH_LEN) == 0 ? 0 : -1;
}

int koe_media_announce(const koe_media_offer_t *offer, int udp_fd)
{
    /* Broadcast transfer_id + sender_pk so nearby peers know a file is available. */
    uint8_t buf[KOE_MEDIA_TRANSFER_ID_LEN + KOE_ED25519_PK_LEN];
    memcpy(buf,                            offer->transfer_id, KOE_MEDIA_TRANSFER_ID_LEN);
    memcpy(buf + KOE_MEDIA_TRANSFER_ID_LEN, offer->sender_pk,  KOE_ED25519_PK_LEN);

    int bcast = 1;
    setsockopt(udp_fd, SOL_SOCKET, SO_BROADCAST, &bcast, sizeof(bcast));

    struct sockaddr_in dst = {0};
    dst.sin_family      = AF_INET;
    dst.sin_port        = htons(KOE_MEDIA_PORT);
    dst.sin_addr.s_addr = INADDR_BROADCAST;
    sendto(udp_fd, buf, sizeof(buf), 0, (struct sockaddr *)&dst, sizeof(dst));
    return 0;
}
