/*
 * koe_revoke.h - Key revocation and identity recovery.
 *
 * If a device is stolen or a secret key is compromised, the user can revoke
 * their old identity and generate a new one. A signed revocation notice is
 * broadcast to all contacts and to the relay server.
 *
 * Contacts who receive the notice will:
 *   1. Stop accepting messages signed by the old key.
 *   2. Mark the old contact entry as revoked.
 *   3. Display a warning if they receive a future message from the old key.
 *
 * The new identity is linked to the old one by a cross-signature: the old key
 * signs the new public key at revocation time. Contacts can verify the link
 * and automatically migrate their contact entry to the new key if they trust
 * the cross-signature. If the old secret key is unavailable (e.g. the device
 * was stolen before revocation), the new identity must be established through
 * out-of-band contact re-verification.
 */

#ifndef KOE_REVOKE_H
#define KOE_REVOKE_H

#include "koe_crypto.h"
#include "koe_packet.h"
#include <stdint.h>
#include <time.h>

/* Payload of a KOE_TYPE_REVOKE packet */
typedef struct {
    uint8_t  old_pk[KOE_ED25519_PK_LEN];     /* key being revoked          */
    uint8_t  new_pk[KOE_ED25519_PK_LEN];     /* replacement (may be zero)  */
    time_t   revoked_at;
    char     reason[128];                      /* human-readable, optional   */
    uint8_t  sig[KOE_ED25519_SIG_LEN];        /* signature by old_pk over
                                                * (old_pk || new_pk || timestamp) */
} koe_revocation_t;

/* Build a revocation notice signed by the current identity.
 * new_id may be NULL if the replacement identity is not yet established. */
int koe_revoke_build(koe_revocation_t     *rev,
                      const koe_identity_t *old_id,
                      const koe_identity_t *new_id,
                      const char           *reason);

/* Verify a received revocation notice. Returns 0 if the signature is valid,
 * -1 otherwise. */
int koe_revoke_verify(const koe_revocation_t *rev);

/* Serialise a revocation into a KOE_TYPE_REVOKE packet for broadcast. */
int koe_revoke_build_packet(koe_packet_t            *pkt,
                              const koe_revocation_t  *rev,
                              const uint8_t            to[KOE_ED25519_PK_LEN]);

/* Parse a KOE_TYPE_REVOKE packet into a koe_revocation_t struct. */
int koe_revoke_parse_packet(koe_revocation_t   *rev,
                              const koe_packet_t *pkt);

#endif /* KOE_REVOKE_H */
