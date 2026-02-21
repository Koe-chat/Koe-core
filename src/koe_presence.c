#include "koe_presence.h"
#include "koe_crypto.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>

void koe_presence_init(koe_presence_table_t *table)
{
    memset(table, 0, sizeof(*table));
    table->local_state = KOE_PRESENCE_OFFLINE;
}

void koe_presence_update(koe_presence_table_t *table,
                          const uint8_t pk[KOE_ED25519_PK_LEN],
                          koe_presence_state_t state, int transport)
{
    /* Find existing entry. */
    for (int i = 0; i < table->count; i++) {
        if (memcmp(table->peers[i].pk, pk, KOE_ED25519_PK_LEN) == 0) {
            table->peers[i].state     = state;
            table->peers[i].last_seen = time(NULL);
            table->peers[i].transport = transport;
            return;
        }
    }
    /* New entry. */
    if (table->count < KOE_PRESENCE_MAX_PEERS) {
        koe_peer_presence_t *p = &table->peers[table->count++];
        memcpy(p->pk, pk, KOE_ED25519_PK_LEN);
        p->state     = state;
        p->last_seen = time(NULL);
        p->transport = transport;
    }
}

koe_presence_state_t koe_presence_get(const koe_presence_table_t *table,
                                        const uint8_t pk[KOE_ED25519_PK_LEN])
{
    time_t now = time(NULL);
    for (int i = 0; i < table->count; i++) {
        if (memcmp(table->peers[i].pk, pk, KOE_ED25519_PK_LEN) == 0) {
            int ttl = (table->peers[i].transport == KOE_PRESENCE_ONLINE)
                      ? KOE_PRESENCE_TTL_LOCAL : KOE_PRESENCE_TTL_RELAY;
            if (now - table->peers[i].last_seen > ttl)
                return KOE_PRESENCE_OFFLINE;
            return table->peers[i].state;
        }
    }
    return KOE_PRESENCE_OFFLINE;
}

int koe_presence_is_online(const koe_presence_table_t *table,
                             const uint8_t pk[KOE_ED25519_PK_LEN])
{
    return koe_presence_get(table, pk) != KOE_PRESENCE_OFFLINE ? 1 : 0;
}

int koe_presence_expire(koe_presence_table_t *table)
{
    time_t now = time(NULL);
    int removed = 0;
    for (int i = 0; i < table->count; ) {
        int ttl = KOE_PRESENCE_TTL_RELAY;
        if (now - table->peers[i].last_seen > ttl) {
            table->peers[i] = table->peers[--table->count];
            removed++;
        } else {
            i++;
        }
    }
    return removed;
}

int koe_presence_typing_expired(const koe_peer_presence_t *peer)
{
    if (!peer->is_typing) return 0;
    return (time(NULL) - peer->typing_started_at) > 5 ? 1 : 0;
}

int koe_presence_set_local(koe_presence_table_t *table,
                             koe_presence_state_t state,
                             const koe_identity_t *local_id,
                             int ghost_active)
{
    (void)local_id;
    table->local_state = ghost_active ? KOE_PRESENCE_GHOST : state;
    return 0;
}

int koe_presence_set_typing(koe_packet_t *pkt, const koe_identity_t *local_id,
                              const uint8_t to_pk[KOE_ED25519_PK_LEN],
                              const koe_session_t *sess, int is_typing)
{
    uint8_t plain[1] = { (uint8_t)is_typing };
    uint8_t ct[1 + KOE_TAG_LEN];
    uint8_t nonce[KOE_NONCE_LEN];
    koe_nonce_generate(nonce);
    if (koe_encrypt(ct, plain, 1, nonce, sess->tx_key) != 0) return -1;

    uint8_t *payload = malloc(sizeof(ct));
    if (!payload) return -1;
    memcpy(payload, ct, sizeof(ct));

    koe_packet_init(pkt, KOE_TYPE_TYPING, KOE_FLAG_ENCRYPTED);
    pkt->header.length = sizeof(ct);
    memcpy(pkt->header.from, local_id->pk, KOE_ID_LEN);
    memcpy(pkt->header.to,   to_pk,        KOE_ID_LEN);
    memcpy(pkt->header.nonce, nonce,        KOE_NONCE_LEN);
    pkt->header.checksum = koe_packet_checksum(&pkt->header);
    pkt->payload = payload;
    return 0;
}

void koe_presence_handle_typing(koe_presence_table_t *table, const koe_packet_t *pkt)
{
    for (int i = 0; i < table->count; i++) {
        if (memcmp(table->peers[i].pk, pkt->header.from, KOE_ED25519_PK_LEN) == 0) {
            /* Payload byte 0 indicates is_typing after decryption.
             * For simplicity, toggle based on packet existence. */
            table->peers[i].is_typing        = 1;
            table->peers[i].typing_started_at = time(NULL);
            return;
        }
    }
}

int koe_presence_build_packet(koe_packet_t *pkt, const koe_identity_t *local_id,
                                const uint8_t to_pk[KOE_ED25519_PK_LEN],
                                koe_presence_state_t state, const koe_session_t *sess)
{
    uint8_t plain[1] = { (uint8_t)state };
    uint8_t ct[1 + KOE_TAG_LEN];
    uint8_t nonce[KOE_NONCE_LEN];
    koe_nonce_generate(nonce);
    if (koe_encrypt(ct, plain, 1, nonce, sess->tx_key) != 0) return -1;

    uint8_t *payload = malloc(sizeof(ct));
    if (!payload) return -1;
    memcpy(payload, ct, sizeof(ct));

    koe_packet_init(pkt, KOE_TYPE_PRESENCE, KOE_FLAG_ENCRYPTED);
    pkt->header.length = sizeof(ct);
    memcpy(pkt->header.from, local_id->pk, KOE_ID_LEN);
    memcpy(pkt->header.to,   to_pk,        KOE_ID_LEN);
    memcpy(pkt->header.nonce, nonce,        KOE_NONCE_LEN);
    pkt->header.checksum = koe_packet_checksum(&pkt->header);
    pkt->payload = payload;
    return 0;
}
