/*
 * koe_revoke.h - Key revocation and identity recovery.
 */
#ifndef KOE_REVOKE_H
#define KOE_REVOKE_H

#include "koe_crypto.h"
#include "koe_packet.h"
#include <stdint.h>
#include <time.h>

typedef struct {
    uint8_t old_pk[KOE_ED25519_PK_LEN];
    uint8_t new_pk[KOE_ED25519_PK_LEN];
    time_t  revoked_at;
    char    reason[128];
    uint8_t sig[KOE_ED25519_SIG_LEN];
} koe_revocation_t;

int koe_revoke_build(koe_revocation_t *rev, const koe_identity_t *old_id,
                      const koe_identity_t *new_id, const char *reason);
int koe_revoke_verify(const koe_revocation_t *rev);
int koe_revoke_build_packet(koe_packet_t *pkt, const koe_revocation_t *rev,
                              const uint8_t to[KOE_ED25519_PK_LEN]);
int koe_revoke_parse_packet(koe_revocation_t *rev, const koe_packet_t *pkt);

#endif /* KOE_REVOKE_H */
