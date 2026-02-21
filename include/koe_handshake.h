/*
 * koe_handshake.h - Two-round X25519 key exchange.
 */
#ifndef KOE_HANDSHAKE_H
#define KOE_HANDSHAKE_H

#include "koe_crypto.h"
#include "koe_packet.h"
#include "koe_version.h"
#include <stdint.h>

typedef enum {
    KOE_HS_IDLE         = 0,
    KOE_HS_SENT_HELLO   = 1,
    KOE_HS_COMPLETE     = 2,
    KOE_HS_FAILED       = 3,
} koe_handshake_state_t;

typedef struct {
    koe_handshake_state_t state;
    koe_ephemeral_t       local_eph;
    uint8_t               remote_pk[KOE_ED25519_PK_LEN];
    koe_session_t         session;
    koe_version_t         negotiated_version;
} koe_handshake_t;

int  koe_handshake_init(koe_handshake_t *hs, koe_packet_t *hello_out,
                         const koe_identity_t *local_id,
                         const uint8_t remote_pk[KOE_ED25519_PK_LEN]);
int  koe_handshake_respond(koe_handshake_t *hs, koe_packet_t *ack_out,
                            const koe_packet_t *hello,
                            const koe_identity_t *local_id);
int  koe_handshake_finalise(koe_handshake_t *hs, const koe_packet_t *ack,
                              const koe_identity_t *local_id);

#endif /* KOE_HANDSHAKE_H */
