/*
 * koe_revoke.c - Key revocation and identity recovery.
 *
 * A revocation notice is a signed statement saying "this key is no longer
 * mine". It carries an optional replacement key so contacts can automatically
 * migrate their contact entry. Without a replacement, contacts must re-verify
 * the new identity out of band.
 *
 * The signature is over the concatenation:
 *   old_pk (32) || new_pk (32, zeroed if absent) || revoked_at (8, big-endian)
 *
 * This binds the old key, the new key, and the timestamp together in one
 * atomic signed statement.
 */

#include "koe_revoke.h"
#include "koe_crypto.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <sodium.h>

int koe_revoke_build(koe_revocation_t     *rev,
                      const koe_identity_t *old_id,
                      const koe_identity_t *new_id,
                      const char           *reason)
{
    memset(rev, 0, sizeof(*rev));
    memcpy(rev->old_pk, old_id->pk, KOE_ED25519_PK_LEN);

    if (new_id)
        memcpy(rev->new_pk, new_id->pk, KOE_ED25519_PK_LEN);
    /* If new_id is NULL, new_pk stays zeroed, which is the "no replacement" signal. */

    rev->revoked_at = (time_t)time(NULL);

    if (reason)
        strncpy(rev->reason, reason, sizeof(rev->reason) - 1);

    /* Build the data to sign: old_pk || new_pk || timestamp (8 bytes BE). */
    uint8_t to_sign[KOE_ED25519_PK_LEN + KOE_ED25519_PK_LEN + 8];
    memcpy(to_sign,                           rev->old_pk, KOE_ED25519_PK_LEN);
    memcpy(to_sign + KOE_ED25519_PK_LEN,      rev->new_pk, KOE_ED25519_PK_LEN);

    uint64_t ts_be = htobe64((uint64_t)rev->revoked_at);
    memcpy(to_sign + KOE_ED25519_PK_LEN * 2, &ts_be, 8);

    return koe_sign(rev->sig, to_sign, sizeof(to_sign), old_id);
}

int koe_revoke_verify(const koe_revocation_t *rev)
{
    uint8_t to_sign[KOE_ED25519_PK_LEN + KOE_ED25519_PK_LEN + 8];
    memcpy(to_sign,                           rev->old_pk, KOE_ED25519_PK_LEN);
    memcpy(to_sign + KOE_ED25519_PK_LEN,      rev->new_pk, KOE_ED25519_PK_LEN);

    uint64_t ts_be = htobe64((uint64_t)rev->revoked_at);
    memcpy(to_sign + KOE_ED25519_PK_LEN * 2, &ts_be, 8);

    return koe_verify(rev->sig, to_sign, sizeof(to_sign), rev->old_pk);
}

int koe_revoke_build_packet(koe_packet_t            *pkt,
                              const koe_revocation_t  *rev,
                              const uint8_t            to[KOE_ED25519_PK_LEN])
{
    /* Serialise the revocation into a flat buffer:
     *   old_pk (32) || new_pk (32) || revoked_at (8 BE) || sig (64) || reason (128) */
    size_t   payload_len = KOE_ED25519_PK_LEN + KOE_ED25519_PK_LEN + 8
                         + KOE_ED25519_SIG_LEN + 128;
    uint8_t *payload     = calloc(1, payload_len);
    if (!payload) return -1;

    size_t off = 0;
    memcpy(payload + off, rev->old_pk, KOE_ED25519_PK_LEN); off += KOE_ED25519_PK_LEN;
    memcpy(payload + off, rev->new_pk, KOE_ED25519_PK_LEN); off += KOE_ED25519_PK_LEN;

    uint64_t ts_be = htobe64((uint64_t)rev->revoked_at);
    memcpy(payload + off, &ts_be, 8); off += 8;

    memcpy(payload + off, rev->sig, KOE_ED25519_SIG_LEN); off += KOE_ED25519_SIG_LEN;
    strncpy((char *)(payload + off), rev->reason, 127);

    memset(pkt, 0, sizeof(*pkt));
    memcpy(pkt->header.magic, KOE_MAGIC, KOE_MAGIC_LEN);
    pkt->header.type   = KOE_TYPE_REVOKE;
    pkt->header.flags  = KOE_FLAG_SIGNED;
    pkt->header.length = (uint32_t)payload_len;
    memcpy(pkt->header.from, rev->old_pk, KOE_ID_LEN);
    memcpy(pkt->header.to,   to,          KOE_ID_LEN);
    pkt->payload = payload;

    return 0;
}

int koe_revoke_parse_packet(koe_revocation_t   *rev,
                              const koe_packet_t *pkt)
{
    size_t expected = KOE_ED25519_PK_LEN + KOE_ED25519_PK_LEN + 8
                    + KOE_ED25519_SIG_LEN + 128;
    if (pkt->header.length < expected || !pkt->payload) return -1;

    memset(rev, 0, sizeof(*rev));
    size_t off = 0;

    memcpy(rev->old_pk, pkt->payload + off, KOE_ED25519_PK_LEN); off += KOE_ED25519_PK_LEN;
    memcpy(rev->new_pk, pkt->payload + off, KOE_ED25519_PK_LEN); off += KOE_ED25519_PK_LEN;

    uint64_t ts_be;
    memcpy(&ts_be, pkt->payload + off, 8); off += 8;
    rev->revoked_at = (time_t)be64toh(ts_be);

    memcpy(rev->sig, pkt->payload + off, KOE_ED25519_SIG_LEN); off += KOE_ED25519_SIG_LEN;
    strncpy(rev->reason, (const char *)(pkt->payload + off), 127);

    return 0;
}
