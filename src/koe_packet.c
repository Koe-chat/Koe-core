/*
 * koe_packet.c - Wire packet serialisation, validation, and fragmentation.
 */

#include "koe_packet.h"
#include "koe_version.h"
#include <sodium.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>

/* ---------------------------------------------------------------------- */
/* CRC32 (ISO 3309 polynomial)                                              */
/* ---------------------------------------------------------------------- */

static uint32_t crc32_table[256];
static int      crc32_ready = 0;

static void crc32_init(void)
{
    if (crc32_ready) return;
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++)
            c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        crc32_table[i] = c;
    }
    crc32_ready = 1;
}

static uint32_t crc32(const uint8_t *buf, size_t len)
{
    crc32_init();
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++)
        c = crc32_table[(c ^ buf[i]) & 0xFF] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

/* ---------------------------------------------------------------------- */

void koe_packet_init(koe_packet_t *pkt, uint8_t type, uint8_t flags)
{
    memset(pkt, 0, sizeof(*pkt));
    memcpy(pkt->header.magic, KOE_MAGIC, KOE_MAGIC_LEN);
    pkt->header.proto_major = KOE_PROTO_MAJOR;
    pkt->header.proto_minor = KOE_PROTO_MINOR;
    pkt->header.type        = type;
    pkt->header.flags       = flags;
}

void koe_packet_free(koe_packet_t *pkt)
{
    if (pkt->payload) {
        free(pkt->payload);
        pkt->payload = NULL;
    }
    pkt->header.length = 0;
}

uint32_t koe_packet_checksum(const koe_header_t *hdr)
{
    /* CRC32 over the first 100 bytes of the serialised header
     * (before the checksum field itself). */
    uint8_t buf[100];
    int off = 0;

    memcpy(buf + off, hdr->magic, KOE_MAGIC_LEN);    off += 4;
    buf[off++] = hdr->proto_major;
    buf[off++] = hdr->proto_minor;
    buf[off++] = hdr->type;
    buf[off++] = hdr->flags;

    uint32_t len_be = htonl(hdr->length);
    memcpy(buf + off, &len_be, 4); off += 4;

    memcpy(buf + off, hdr->from,  KOE_ID_LEN);    off += 32;
    memcpy(buf + off, hdr->to,    KOE_ID_LEN);    off += 32;
    memcpy(buf + off, hdr->nonce, KOE_NONCE_LEN); off += 24;

    return crc32(buf, (size_t)off);
}

int koe_packet_validate(const koe_packet_t *pkt)
{
    if (memcmp(pkt->header.magic, KOE_MAGIC, KOE_MAGIC_LEN) != 0)
        return -1;

    koe_version_t local  = koe_version_local();
    koe_version_t remote = { pkt->header.proto_major, pkt->header.proto_minor };
    if (!koe_version_compatible(local, remote))
        return -1;

    uint32_t expected = koe_packet_checksum(&pkt->header);
    if (expected != pkt->header.checksum)
        return -1;

    return 0;
}

/* ---------------------------------------------------------------------- */
/* Serialisation                                                            */
/* ---------------------------------------------------------------------- */

int koe_packet_serialise(const koe_packet_t *pkt, uint8_t *buf, size_t buf_len)
{
    size_t total = KOE_HEADER_SIZE + pkt->header.length;
    if (buf_len < total) return -1;

    int off = 0;
    memcpy(buf + off, pkt->header.magic, KOE_MAGIC_LEN); off += 4;
    buf[off++] = pkt->header.proto_major;
    buf[off++] = pkt->header.proto_minor;
    buf[off++] = pkt->header.type;
    buf[off++] = pkt->header.flags;

    uint32_t len_be = htonl(pkt->header.length);
    memcpy(buf + off, &len_be, 4); off += 4;

    memcpy(buf + off, pkt->header.from,  KOE_ID_LEN);    off += 32;
    memcpy(buf + off, pkt->header.to,    KOE_ID_LEN);    off += 32;
    memcpy(buf + off, pkt->header.nonce, KOE_NONCE_LEN); off += 24;

    uint32_t ck_be = htonl(pkt->header.checksum);
    memcpy(buf + off, &ck_be, 4); off += 4;

    /* reserved (2 bytes). */
    buf[off++] = 0;
    buf[off++] = 0;

    if (pkt->header.length > 0 && pkt->payload)
        memcpy(buf + off, pkt->payload, pkt->header.length);

    return (int)total;
}

int koe_packet_deserialise(koe_packet_t *pkt, const uint8_t *buf, size_t buf_len)
{
    if (buf_len < KOE_HEADER_SIZE) return -1;

    memset(pkt, 0, sizeof(*pkt));
    int off = 0;

    memcpy(pkt->header.magic, buf + off, KOE_MAGIC_LEN); off += 4;
    pkt->header.proto_major = buf[off++];
    pkt->header.proto_minor = buf[off++];
    pkt->header.type        = buf[off++];
    pkt->header.flags       = buf[off++];

    uint32_t len_be;
    memcpy(&len_be, buf + off, 4); off += 4;
    pkt->header.length = ntohl(len_be);

    memcpy(pkt->header.from,  buf + off, KOE_ID_LEN);    off += 32;
    memcpy(pkt->header.to,    buf + off, KOE_ID_LEN);    off += 32;
    memcpy(pkt->header.nonce, buf + off, KOE_NONCE_LEN); off += 24;

    uint32_t ck_be;
    memcpy(&ck_be, buf + off, 4); off += 4;
    pkt->header.checksum = ntohl(ck_be);

    off += 2; /* reserved */

    if (pkt->header.length > 0) {
        if (buf_len < (size_t)(off) + pkt->header.length) return -1;
        if (pkt->header.length > KOE_MAX_PAYLOAD) return -1;

        pkt->payload = malloc(pkt->header.length);
        if (!pkt->payload) return -1;
        memcpy(pkt->payload, buf + off, pkt->header.length);
    }

    return 0;
}

/* ---------------------------------------------------------------------- */
/* Fragmentation (stub — full implementation uses msg_id ring)             */
/* ---------------------------------------------------------------------- */

int koe_packet_fragment(const koe_packet_t *pkt,
                         koe_packet_t       *out_frags,
                         int                 max_frags,
                         size_t              mtu)
{
    if (!pkt->payload || pkt->header.length == 0) return -1;

    size_t   total     = pkt->header.length;
    size_t   frag_size = mtu;
    int      count     = 0;
    size_t   offset    = 0;

    /* Generate a random 16-byte message ID for this fragmented message. */
    uint8_t msg_id[16];
    randombytes_buf(msg_id, sizeof(msg_id)); /* uses libsodium */

    uint8_t total_frags = (uint8_t)((total + frag_size - 1) / frag_size);
    if (total_frags > max_frags || total_frags == 0) return -1;

    for (uint8_t i = 0; i < total_frags; i++) {
        size_t chunk = offset + frag_size > total ? total - offset : frag_size;

        /* Payload layout: msg_id(16) + frag_index(1) + total(1) + data. */
        size_t   pay_len = 18 + chunk;
        uint8_t *pay     = malloc(pay_len);
        if (!pay) return -1;

        memcpy(pay,       msg_id, 16);
        pay[16] = i;
        pay[17] = total_frags;
        memcpy(pay + 18, pkt->payload + offset, chunk);

        out_frags[count] = *pkt;
        out_frags[count].header.length = (uint32_t)pay_len;
        out_frags[count].header.flags |= KOE_FLAG_FRAGMENTED;
        if (i == total_frags - 1)
            out_frags[count].header.flags |= KOE_FLAG_LAST_FRAG;
        out_frags[count].header.checksum =
            koe_packet_checksum(&out_frags[count].header);
        out_frags[count].payload = pay;

        offset += chunk;
        count++;
    }

    return count;
}

int koe_packet_reassemble(koe_reassembly_t *ctx,
                            const koe_packet_t *frag,
                            koe_packet_t       *out_pkt)
{
    if (!frag->payload || frag->header.length < 18) return -1;

    uint8_t msg_id[16];
    uint8_t frag_index = frag->payload[16];
    uint8_t total      = frag->payload[17];

    memcpy(msg_id, frag->payload, 16);

    /* First fragment: initialise context. */
    if (ctx->received == 0) {
        memcpy(ctx->msg_id, msg_id, 16);
        ctx->total_fragments = total;
    } else {
        if (memcmp(ctx->msg_id, msg_id, 16) != 0) return -1;
    }

    size_t   data_len = frag->header.length - 18;
    uint8_t *data     = malloc(data_len);
    if (!data) return -1;
    memcpy(data, frag->payload + 18, data_len);

    ctx->fragments[frag_index]    = data;
    ctx->frag_lengths[frag_index] = (uint32_t)data_len;
    ctx->received++;

    if (ctx->received < ctx->total_fragments) return 0;

    /* All fragments received — reassemble. */
    size_t total_len = 0;
    for (uint8_t i = 0; i < ctx->total_fragments; i++)
        total_len += ctx->frag_lengths[i];

    *out_pkt = *frag;
    out_pkt->payload = malloc(total_len);
    if (!out_pkt->payload) return -1;

    size_t off = 0;
    for (uint8_t i = 0; i < ctx->total_fragments; i++) {
        memcpy(out_pkt->payload + off, ctx->fragments[i], ctx->frag_lengths[i]);
        off += ctx->frag_lengths[i];
        free(ctx->fragments[i]);
        ctx->fragments[i] = NULL;
    }
    out_pkt->header.length   = (uint32_t)total_len;
    out_pkt->header.flags   &= ~(KOE_FLAG_FRAGMENTED | KOE_FLAG_LAST_FRAG);
    out_pkt->header.checksum = koe_packet_checksum(&out_pkt->header);

    return 1;
}
