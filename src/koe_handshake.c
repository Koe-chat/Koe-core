#include "koe_handshake.h"
#include "koe_crypto.h"
#include "koe_version.h"
#include <string.h>
#include <stdlib.h>
#include <sodium.h>

/* HELLO payload: version(2) + eph_pk(32) + id_pk(32) + sig(64) = 130 bytes */
#define HELLO_PAYLOAD 130

int koe_handshake_init(koe_handshake_t *hs, koe_packet_t *hello_out,
                        const koe_identity_t *local_id,
                        const uint8_t remote_pk[KOE_ED25519_PK_LEN])
{
    memset(hs, 0, sizeof(*hs));
    memcpy(hs->remote_pk, remote_pk, KOE_ED25519_PK_LEN);

    if (koe_ephemeral_generate(&hs->local_eph) != 0) return -1;

    uint8_t *payload = malloc(HELLO_PAYLOAD);
    if (!payload) return -1;

    koe_version_t v = koe_version_local();
    payload[0] = v.major;
    payload[1] = v.minor;
    memcpy(payload + 2,  hs->local_eph.pk, KOE_X25519_PK_LEN);
    memcpy(payload + 34, local_id->pk,     KOE_ED25519_PK_LEN);

    /* Sign: version || eph_pk || id_pk */
    if (koe_sign(payload + 66, payload, 66, local_id) != 0) {
        free(payload); return -1;
    }

    koe_packet_init(hello_out, KOE_TYPE_HELLO, KOE_FLAG_SIGNED);
    hello_out->header.length = HELLO_PAYLOAD;
    memcpy(hello_out->header.from, local_id->pk, KOE_ID_LEN);
    memcpy(hello_out->header.to,   remote_pk,    KOE_ID_LEN);
    hello_out->header.checksum = koe_packet_checksum(&hello_out->header);
    hello_out->payload = payload;

    hs->state = KOE_HS_SENT_HELLO;
    return 0;
}

int koe_handshake_respond(koe_handshake_t *hs, koe_packet_t *ack_out,
                           const koe_packet_t *hello,
                           const koe_identity_t *local_id)
{
    memset(hs, 0, sizeof(*hs));
    if (!hello->payload || hello->header.length < HELLO_PAYLOAD) return -1;

    koe_version_t remote_ver = { hello->payload[0], hello->payload[1] };
    koe_version_t local_ver  = koe_version_local();
    if (koe_version_negotiate(local_ver, remote_ver, &hs->negotiated_version) != 0)
        return -1;

    const uint8_t *remote_eph_pk = hello->payload + 2;
    const uint8_t *remote_id_pk  = hello->payload + 34;
    const uint8_t *sig           = hello->payload + 66;

    /* Verify signature over version || eph_pk || id_pk. */
    if (koe_verify(sig, hello->payload, 66, remote_id_pk) != 0) return -1;

    memcpy(hs->remote_pk, remote_id_pk, KOE_ED25519_PK_LEN);
    if (koe_ephemeral_generate(&hs->local_eph) != 0) return -1;

    if (koe_session_derive(&hs->session, &hs->local_eph, remote_eph_pk,
                            local_id, remote_id_pk, 0) != 0) return -1;

    /* Build HELLO_ACK */
    uint8_t *payload = malloc(HELLO_PAYLOAD);
    if (!payload) return -1;

    payload[0] = hs->negotiated_version.major;
    payload[1] = hs->negotiated_version.minor;
    memcpy(payload + 2,  hs->local_eph.pk, KOE_X25519_PK_LEN);
    memcpy(payload + 34, local_id->pk,     KOE_ED25519_PK_LEN);
    if (koe_sign(payload + 66, payload, 66, local_id) != 0) {
        free(payload); return -1;
    }

    koe_packet_init(ack_out, KOE_TYPE_HELLO_ACK, KOE_FLAG_SIGNED);
    ack_out->header.length = HELLO_PAYLOAD;
    memcpy(ack_out->header.from, local_id->pk,  KOE_ID_LEN);
    memcpy(ack_out->header.to,   remote_id_pk,  KOE_ID_LEN);
    ack_out->header.checksum = koe_packet_checksum(&ack_out->header);
    ack_out->payload = payload;

    hs->state = KOE_HS_COMPLETE;
    return 0;
}

int koe_handshake_finalise(koe_handshake_t *hs, const koe_packet_t *ack,
                             const koe_identity_t *local_id)
{
    if (!ack->payload || ack->header.length < HELLO_PAYLOAD) return -1;

    koe_version_t remote_ver = { ack->payload[0], ack->payload[1] };
    koe_version_t local_ver  = koe_version_local();
    if (koe_version_negotiate(local_ver, remote_ver, &hs->negotiated_version) != 0)
        return -1;

    const uint8_t *remote_eph_pk = ack->payload + 2;
    const uint8_t *remote_id_pk  = ack->payload + 34;
    const uint8_t *sig           = ack->payload + 66;

    if (koe_verify(sig, ack->payload, 66, remote_id_pk) != 0) return -1;

    if (koe_session_derive(&hs->session, &hs->local_eph, remote_eph_pk,
                            local_id, remote_id_pk, 1) != 0) return -1;

    hs->state = KOE_HS_COMPLETE;
    return 0;
}
