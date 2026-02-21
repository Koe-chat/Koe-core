/*
 * koe_handshake.h - Two-round authenticated key exchange.
 *
 * Protocol overview:
 *
 *   Initiator (A)                              Responder (B)
 *   ─────────────                              ─────────────
 *   koe_handshake_init()
 *     generate ephemeral X25519 keypair
 *     sign (id_a.pk || eph_a.pk) with id_a.sk
 *     build HELLO packet
 *                          ──── HELLO ────>
 *                                             koe_handshake_respond()
 *                                               verify A's signature
 *                                               generate ephemeral X25519 keypair
 *                                               derive session keys
 *                                               sign (id_b.pk || eph_b.pk)
 *                                               build HELLO_ACK packet
 *                          <─── HELLO_ACK ──
 *   koe_handshake_finalise()
 *     verify B's signature
 *     derive session keys
 *     send ACK
 *                          ──── ACK ────>
 *   session established                        session established
 *
 * Both parties derive the same pair of session keys from:
 *   X25519(eph_a.sk, eph_b.pk) and X25519(eph_b.sk, eph_a.pk)
 *   plus both long-term public keys as derivation context.
 * The initiator's tx key equals the responder's rx key and vice versa.
 */

#ifndef KOE_HANDSHAKE_H
#define KOE_HANDSHAKE_H

#include "koe_crypto.h"
#include "koe_packet.h"

typedef enum {
    KOE_HS_IDLE = 0,
    KOE_HS_SENT_HELLO,   /* initiator is waiting for HELLO_ACK */
    KOE_HS_RECV_HELLO,   /* responder has received HELLO, reply sent */
    KOE_HS_COMPLETE,
    KOE_HS_FAILED,
} koe_hs_state_t;

typedef struct {
    koe_hs_state_t   state;
    koe_ephemeral_t  local_eph;
    koe_session_t    session;                       /* valid when COMPLETE */
    uint8_t          remote_eph_pk[KOE_X25519_PK_LEN];
    uint8_t          remote_id_pk[KOE_ED25519_PK_LEN];
    int              initiator;
} koe_handshake_t;

/* Payload inside a KOE_TYPE_HANDSHAKE packet:
 *   [0..31]   Ed25519 public key of the sender
 *   [32..63]  X25519 ephemeral public key
 *   [64..127] Ed25519 signature over bytes [0..63] of this payload */
#define KOE_HS_PAYLOAD_LEN  (KOE_ED25519_PK_LEN + KOE_X25519_PK_LEN + KOE_ED25519_SIG_LEN)

/* --- Initiator side ----------------------------------------------------- */

/* Start a handshake as the initiating party. Generates an ephemeral X25519
 * keypair, signs it with the local identity, and fills *pkt with a
 * KOE_TYPE_HANDSHAKE packet ready to send.
 *
 * hs must be kept alive until koe_handshake_finalise() completes.
 * pkt->payload is heap-allocated; caller must call koe_packet_free(pkt). */
int koe_handshake_init(koe_handshake_t      *hs,
                        koe_packet_t         *pkt,
                        const koe_identity_t *local_id,
                        const uint8_t         remote_pk[KOE_ED25519_PK_LEN]);

/* Process the responder's HELLO_ACK and derive session keys.
 * On return, hs->state == KOE_HS_COMPLETE and hs->session is ready to use.
 * Returns 0 on success, -1 if the signature or format is invalid. */
int koe_handshake_finalise(koe_handshake_t      *hs,
                             const koe_packet_t   *ack_pkt,
                             const koe_identity_t *local_id);

/* --- Responder side ----------------------------------------------------- */

/* Handle an incoming HELLO packet and produce a HELLO_ACK reply.
 * On success, hs->state == KOE_HS_COMPLETE and hs->session is ready.
 * reply_pkt->payload is heap-allocated; caller must call koe_packet_free. */
int koe_handshake_respond(koe_handshake_t      *hs,
                            koe_packet_t         *reply_pkt,
                            const koe_packet_t   *hello_pkt,
                            const koe_identity_t *local_id);

#endif /* KOE_HANDSHAKE_H */
