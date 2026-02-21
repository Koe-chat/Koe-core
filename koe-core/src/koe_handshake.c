/*
 * koe_handshake.c - Authenticated key exchange implementation.
 */

#include "koe_handshake.h"
#include "koe_crypto.h"
#include <string.h>
#include <stdlib.h>
#include <sodium.h>

/* Build the payload bytes that get signed: (id_pk || eph_pk). */
static void build_signed_material(uint8_t        out[KOE_ED25519_PK_LEN + KOE_X25519_PK_LEN],
                                   const uint8_t  id_pk[KOE_ED25519_PK_LEN],
                                   const uint8_t  eph_pk[KOE_X25519_PK_LEN])
{
    memcpy(out,                    id_pk,  KOE_ED25519_PK_LEN);
    memcpy(out + KOE_ED25519_PK_LEN, eph_pk, KOE_X25519_PK_LEN);
}

int koe_handshake_init(koe_handshake_t      *hs,
                        koe_packet_t         *pkt,
                        const koe_identity_t *local_id,
                        const uint8_t         remote_pk[KOE_ED25519_PK_LEN])
{
    memset(hs, 0, sizeof(*hs));
    hs->initiator = 1;
    hs->state     = KOE_HS_IDLE;

    memcpy(hs->remote_id_pk, remote_pk, KOE_ED25519_PK_LEN);

    if (koe_ephemeral_generate(&hs->local_eph) != 0)
        return -1;

    /* Sign (id_pk || eph_pk) with the local identity key. */
    uint8_t material[KOE_ED25519_PK_LEN + KOE_X25519_PK_LEN];
    build_signed_material(material, local_id->pk, hs->local_eph.pk);

    uint8_t sig[KOE_ED25519_SIG_LEN];
    if (koe_sign(sig, material, sizeof(material), local_id) != 0)
        return -1;

    /* Pack into a KOE_TYPE_HANDSHAKE packet. */
    koe_packet_t *p = koe_packet_alloc(KOE_TYPE_HANDSHAKE,
                                        KOE_FLAG_SIGNED,
                                        KOE_HS_PAYLOAD_LEN);
    if (!p) return -1;

    uint8_t *payload = p->payload;
    memcpy(payload,                                             local_id->pk,    KOE_ED25519_PK_LEN);
    memcpy(payload + KOE_ED25519_PK_LEN,                       hs->local_eph.pk, KOE_X25519_PK_LEN);
    memcpy(payload + KOE_ED25519_PK_LEN + KOE_X25519_PK_LEN,  sig,              KOE_ED25519_SIG_LEN);

    memcpy(p->header.from, local_id->pk, KOE_ID_LEN);
    memcpy(p->header.to,   remote_pk,    KOE_ID_LEN);
    koe_nonce_generate(p->header.nonce);

    *pkt      = *p;
    pkt->payload = p->payload;
    p->payload = NULL;
    koe_packet_free(p);

    hs->state = KOE_HS_SENT_HELLO;
    return 0;
}

/* Parse and validate a handshake payload; extract id_pk, eph_pk, and verify sig. */
static int parse_hs_payload(const koe_packet_t *pkt,
                              uint8_t             id_pk[KOE_ED25519_PK_LEN],
                              uint8_t             eph_pk[KOE_X25519_PK_LEN])
{
    if (pkt->header.type != KOE_TYPE_HANDSHAKE)
        return -1;
    if (pkt->header.length < KOE_HS_PAYLOAD_LEN)
        return -1;

    const uint8_t *p = pkt->payload;
    memcpy(id_pk,  p,                                             KOE_ED25519_PK_LEN);
    memcpy(eph_pk, p + KOE_ED25519_PK_LEN,                       KOE_X25519_PK_LEN);

    const uint8_t *sig = p + KOE_ED25519_PK_LEN + KOE_X25519_PK_LEN;

    uint8_t material[KOE_ED25519_PK_LEN + KOE_X25519_PK_LEN];
    build_signed_material(material, id_pk, eph_pk);

    return koe_verify(sig, material, sizeof(material), id_pk);
}

int koe_handshake_respond(koe_handshake_t      *hs,
                            koe_packet_t         *reply_pkt,
                            const koe_packet_t   *hello_pkt,
                            const koe_identity_t *local_id)
{
    memset(hs, 0, sizeof(*hs));
    hs->initiator = 0;
    hs->state     = KOE_HS_IDLE;

    uint8_t remote_id_pk[KOE_ED25519_PK_LEN];
    uint8_t remote_eph_pk[KOE_X25519_PK_LEN];

    if (parse_hs_payload(hello_pkt, remote_id_pk, remote_eph_pk) != 0)
        return -1;

    memcpy(hs->remote_id_pk,  remote_id_pk,  KOE_ED25519_PK_LEN);
    memcpy(hs->remote_eph_pk, remote_eph_pk, KOE_X25519_PK_LEN);

    if (koe_ephemeral_generate(&hs->local_eph) != 0)
        return -1;

    /* Derive session keys immediately — responder is done after this. */
    if (koe_session_derive(&hs->session,
                            &hs->local_eph,
                            remote_eph_pk,
                            local_id,
                            remote_id_pk,
                            0) != 0)
        return -1;

    hs->state = KOE_HS_COMPLETE;

    /* Build and return the HELLO_ACK packet. */
    uint8_t material[KOE_ED25519_PK_LEN + KOE_X25519_PK_LEN];
    build_signed_material(material, local_id->pk, hs->local_eph.pk);

    uint8_t sig[KOE_ED25519_SIG_LEN];
    if (koe_sign(sig, material, sizeof(material), local_id) != 0)
        return -1;

    koe_packet_t *p = koe_packet_alloc(KOE_TYPE_HANDSHAKE,
                                        KOE_FLAG_SIGNED,
                                        KOE_HS_PAYLOAD_LEN);
    if (!p) return -1;

    uint8_t *payload = p->payload;
    memcpy(payload,                                             local_id->pk,    KOE_ED25519_PK_LEN);
    memcpy(payload + KOE_ED25519_PK_LEN,                       hs->local_eph.pk, KOE_X25519_PK_LEN);
    memcpy(payload + KOE_ED25519_PK_LEN + KOE_X25519_PK_LEN,  sig,              KOE_ED25519_SIG_LEN);

    memcpy(p->header.from, local_id->pk,  KOE_ID_LEN);
    memcpy(p->header.to,   remote_id_pk,  KOE_ID_LEN);
    koe_nonce_generate(p->header.nonce);

    *reply_pkt = *p;
    reply_pkt->payload = p->payload;
    p->payload = NULL;
    koe_packet_free(p);

    return 0;
}

int koe_handshake_finalise(koe_handshake_t      *hs,
                             const koe_packet_t   *ack_pkt,
                             const koe_identity_t *local_id)
{
    if (hs->state != KOE_HS_SENT_HELLO)
        return -1;

    uint8_t remote_id_pk[KOE_ED25519_PK_LEN];
    uint8_t remote_eph_pk[KOE_X25519_PK_LEN];

    if (parse_hs_payload(ack_pkt, remote_id_pk, remote_eph_pk) != 0) {
        hs->state = KOE_HS_FAILED;
        return -1;
    }

    /* The ACK must come from the same public key we sent HELLO to. */
    if (memcmp(remote_id_pk, hs->remote_id_pk, KOE_ED25519_PK_LEN) != 0) {
        hs->state = KOE_HS_FAILED;
        return -1;
    }

    if (koe_session_derive(&hs->session,
                            &hs->local_eph,
                            remote_eph_pk,
                            local_id,
                            remote_id_pk,
                            1) != 0) {
        hs->state = KOE_HS_FAILED;
        return -1;
    }

    hs->state = KOE_HS_COMPLETE;
    return 0;
}
