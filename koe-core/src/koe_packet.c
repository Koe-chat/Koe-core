/*
 * koe_packet.c - Packet allocation, serialisation, and checksum.
 */

#include "koe_packet.h"
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>   /* htonl, ntohl */

/* CRC32 lookup table, standard polynomial 0xEDB88320 (reversed). */
static uint32_t crc32_table[256];
static int      crc32_table_ready = 0;

static void crc32_table_init(void)
{
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++)
            c = (c & 1) ? (0xEDB88320 ^ (c >> 1)) : (c >> 1);
        crc32_table[i] = c;
    }
    crc32_table_ready = 1;
}

uint32_t koe_checksum(const uint8_t *data, size_t len)
{
    if (!crc32_table_ready)
        crc32_table_init();

    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; i++)
        crc = crc32_table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFF;
}

koe_packet_t *koe_packet_alloc(uint8_t type, uint8_t flags, size_t payload_len)
{
    if (payload_len > KOE_MAX_PAYLOAD)
        return NULL;

    koe_packet_t *pkt = calloc(1, sizeof(koe_packet_t));
    if (!pkt)
        return NULL;

    if (payload_len > 0) {
        pkt->payload = calloc(1, payload_len);
        if (!pkt->payload) {
            free(pkt);
            return NULL;
        }
    }

    memcpy(pkt->header.magic, KOE_MAGIC, KOE_MAGIC_LEN);
    pkt->header.type   = type;
    pkt->header.flags  = flags;
    pkt->header.length = (uint32_t)payload_len;

    return pkt;
}

void koe_packet_free(koe_packet_t *pkt)
{
    if (!pkt)
        return;
    if (pkt->payload) {
        /* Zero before freeing to avoid leaving plaintext in freed heap. */
        memset(pkt->payload, 0, pkt->header.length);
        free(pkt->payload);
    }
    memset(pkt, 0, sizeof(*pkt));
    free(pkt);
}

int koe_packet_serialise(const koe_packet_t *pkt,
                          uint8_t            *out,
                          size_t              out_len)
{
    size_t total = KOE_HEADER_SIZE + pkt->header.length;
    if (out_len < total)
        return -1;

    uint8_t *p = out;

    memcpy(p, pkt->header.magic, KOE_MAGIC_LEN);   p += KOE_MAGIC_LEN;
    *p++ = pkt->header.type;
    *p++ = pkt->header.flags;

    uint32_t len_be = htonl(pkt->header.length);
    memcpy(p, &len_be, 4);                          p += 4;

    memcpy(p, pkt->header.from,  KOE_ID_LEN);       p += KOE_ID_LEN;
    memcpy(p, pkt->header.to,    KOE_ID_LEN);        p += KOE_ID_LEN;
    memcpy(p, pkt->header.nonce, KOE_NONCE_LEN);     p += KOE_NONCE_LEN;

    /* Checksum covers everything up to (but not including) the checksum field. */
    uint32_t csum = koe_checksum(out, (size_t)(p - out));
    uint32_t csum_be = htonl(csum);
    memcpy(p, &csum_be, 4);                          p += 4;

    /* Payload follows the header. */
    if (pkt->header.length > 0 && pkt->payload)
        memcpy(p, pkt->payload, pkt->header.length);

    return (int)total;
}

int koe_packet_deserialise(koe_packet_t  *pkt,
                             const uint8_t *buf,
                             size_t         buf_len)
{
    if (buf_len < KOE_HEADER_SIZE)
        return -1;

    if (memcmp(buf, KOE_MAGIC, KOE_MAGIC_LEN) != 0)
        return -1;

    /* Verify checksum before touching any other field. */
    uint32_t stored_csum;
    memcpy(&stored_csum, buf + 98, 4);
    stored_csum = ntohl(stored_csum);

    uint32_t computed = koe_checksum(buf, 98);
    if (computed != stored_csum)
        return -1;

    const uint8_t *p = buf;

    memcpy(pkt->header.magic, p, KOE_MAGIC_LEN);   p += KOE_MAGIC_LEN;
    pkt->header.type  = *p++;
    pkt->header.flags = *p++;

    uint32_t len_be;
    memcpy(&len_be, p, 4);
    pkt->header.length = ntohl(len_be);             p += 4;

    if (pkt->header.length > KOE_MAX_PAYLOAD)
        return -1;

    if (buf_len < KOE_HEADER_SIZE + pkt->header.length)
        return -1;

    memcpy(pkt->header.from,  p, KOE_ID_LEN);       p += KOE_ID_LEN;
    memcpy(pkt->header.to,    p, KOE_ID_LEN);        p += KOE_ID_LEN;
    memcpy(pkt->header.nonce, p, KOE_NONCE_LEN);     p += KOE_NONCE_LEN;

    memcpy(&len_be, p, 4);
    pkt->header.checksum = ntohl(len_be);            p += 4;

    pkt->payload = NULL;
    if (pkt->header.length > 0) {
        pkt->payload = malloc(pkt->header.length);
        if (!pkt->payload)
            return -1;
        memcpy(pkt->payload, p, pkt->header.length);
    }

    return 0;
}
