#include "koe_revoke.h"
#include "koe_crypto.h"
#include "koe_packet.h"
#include <string.h>
#include <stdlib.h>

int koe_revoke_build(koe_revocation_t *rev, const koe_identity_t *old_id,
                      const koe_identity_t *new_id, const char *reason)
{
    memset(rev, 0, sizeof(*rev));
    memcpy(rev->old_pk, old_id->pk, KOE_ED25519_PK_LEN);
    memcpy(rev->new_pk, new_id->pk, KOE_ED25519_PK_LEN);
    rev->revoked_at = (time_t)time(NULL);
    strncpy(rev->reason, reason, sizeof(rev->reason) - 1);

    /* Sign: old_pk || new_pk || revoked_at using the OLD identity. */
    uint8_t msg[KOE_ED25519_PK_LEN * 2 + sizeof(int64_t)];
    memcpy(msg,      rev->old_pk, KOE_ED25519_PK_LEN);
    memcpy(msg + 32, rev->new_pk, KOE_ED25519_PK_LEN);
    int64_t ts = (int64_t)rev->revoked_at;
    memcpy(msg + 64, &ts, sizeof(ts));

    return koe_sign(rev->sig, msg, sizeof(msg), old_id);
}

int koe_revoke_verify(const koe_revocation_t *rev)
{
    uint8_t msg[KOE_ED25519_PK_LEN * 2 + sizeof(int64_t)];
    memcpy(msg,      rev->old_pk, KOE_ED25519_PK_LEN);
    memcpy(msg + 32, rev->new_pk, KOE_ED25519_PK_LEN);
    int64_t ts = (int64_t)rev->revoked_at;
    memcpy(msg + 64, &ts, sizeof(ts));
    return koe_verify(rev->sig, msg, sizeof(msg), rev->old_pk);
}

int koe_revoke_build_packet(koe_packet_t *pkt, const koe_revocation_t *rev,
                              const uint8_t to[KOE_ED25519_PK_LEN])
{
    size_t  payload_len = sizeof(*rev);
    uint8_t *payload    = malloc(payload_len);
    if (!payload) return -1;
    memcpy(payload, rev, payload_len);

    koe_packet_init(pkt, KOE_TYPE_REVOKE, KOE_FLAG_SIGNED);
    pkt->header.length = (uint32_t)payload_len;
    memcpy(pkt->header.from, rev->old_pk, KOE_ID_LEN);
    memcpy(pkt->header.to,   to,          KOE_ID_LEN);
    pkt->header.checksum = koe_packet_checksum(&pkt->header);
    pkt->payload = payload;
    return 0;
}

int koe_revoke_parse_packet(koe_revocation_t *rev, const koe_packet_t *pkt)
{
    if (!pkt->payload || pkt->header.length < sizeof(*rev)) return -1;
    memcpy(rev, pkt->payload, sizeof(*rev));
    return koe_revoke_verify(rev);
}
