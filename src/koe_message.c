/*
 * koe_message.c - Application-level message management.
 */

#include "koe_message.h"
#include "koe_identity.h"
#include "koe_crypto.h"
#include "koe_packet.h"
#include <sodium.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>

static uint64_t g_message_id_counter = 0;

static uint64_t generate_message_id(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    uint64_t id = (uint64_t)ts.tv_sec * 1000000ULL + (ts.tv_nsec / 1000);
    id += (++g_message_id_counter);
    return id;
}

koe_message_t *koe_message_alloc(koe_msg_type_t type, const uint8_t to[KOE_ED25519_PK_LEN],
                                   const uint8_t *body, size_t body_len)
{
    if (!body || body_len == 0 || !to) {
        return NULL;
    }

    koe_message_t *msg = calloc(1, sizeof(koe_message_t));
    if (!msg) {
        return NULL;
    }

    msg->id = generate_message_id();
    msg->type = type;
    msg->status = KOE_STATUS_PENDING;

    memcpy(msg->to, to, KOE_ED25519_PK_LEN);

    msg->body = malloc(body_len);
    if (!msg->body) {
        free(msg);
        return NULL;
    }
    memcpy(msg->body, body, body_len);
    msg->body_len = body_len;

    msg->sent_at = time(NULL);
    msg->destruct_after_seconds = 0;
    msg->destruct_at = 0;
    msg->scheduled_at = 0;
    msg->is_secret = 0;

    memset(msg->from, 0, KOE_ED25519_PK_LEN);
    memset(msg->sig, 0, KOE_ED25519_SIG_LEN);

    return msg;
}

void koe_message_free(koe_message_t *msg)
{
    if (!msg) {
        return;
    }

    if (msg->body) {
        memset(msg->body, 0, msg->body_len);
        free(msg->body);
    }

    memset(msg->sig, 0, KOE_ED25519_SIG_LEN);
    memset(msg->from, 0, KOE_ED25519_PK_LEN);
    memset(msg->to, 0, KOE_ED25519_PK_LEN);

    free(msg);
}

int koe_message_sign(koe_message_t *msg, const koe_identity_t *id)
{
    if (!msg || !id) {
        return -1;
    }

    if (koe_sign(msg->sig, msg->body, msg->body_len, id) != 0) {
        return -1;
    }

    memcpy(msg->from, id->pk, KOE_ED25519_PK_LEN);

    return 0;
}

int koe_message_verify(const koe_message_t *msg)
{
    if (!msg || !msg->body) {
        return -1;
    }

    return koe_verify(msg->sig, msg->body, msg->body_len, msg->from);
}

void koe_message_set_destruct(koe_message_t *msg, uint32_t ttl_seconds)
{
    if (!msg || ttl_seconds == 0) {
        return;
    }

    msg->destruct_after_seconds = ttl_seconds;
    msg->destruct_at = time(NULL) + ttl_seconds;
}

int koe_message_should_destruct(const koe_message_t *msg)
{
    if (!msg || msg->destruct_after_seconds == 0) {
        return 0;
    }

    return time(NULL) >= msg->destruct_at;
}

void koe_message_schedule(koe_message_t *msg, int64_t send_at_unix)
{
    if (!msg) {
        return;
    }

    msg->scheduled_at = send_at_unix;
}

int koe_message_is_due(const koe_message_t *msg)
{
    if (!msg) {
        return 0;
    }

    if (msg->scheduled_at == 0) {
        return 1;
    }

    return time(NULL) >= msg->scheduled_at;
}

int koe_message_encrypt(const koe_message_t *msg, const koe_session_t *sess,
                         koe_packet_t *pkt_out)
{
    if (!msg || !sess || !pkt_out) {
        return -1;
    }

    koe_packet_init(pkt_out, KOE_TYPE_MSG, KOE_FLAG_ENCRYPTED);

    memcpy(pkt_out->header.from, msg->from, KOE_ED25519_PK_LEN);
    memcpy(pkt_out->header.to, msg->to, KOE_ED25519_PK_LEN);

    koe_nonce_generate(pkt_out->header.nonce);

    size_t ct_len = msg->body_len + crypto_secretbox_MACBYTES;
    uint8_t *ciphertext = malloc(ct_len);
    if (!ciphertext) {
        return -1;
    }

    if (koe_encrypt(ciphertext, msg->body, msg->body_len,
                    pkt_out->header.nonce, sess->tx_key) != 0) {
        free(ciphertext);
        return -1;
    }

    pkt_out->header.length = ct_len;
    pkt_out->payload = ciphertext;

    pkt_out->header.flags |= KOE_FLAG_SIGNED;

    return 0;
}

int koe_message_decrypt(koe_message_t *msg, const koe_packet_t *pkt,
                        const koe_session_t *sess)
{
    if (!msg || !pkt || !sess) {
        return -1;
    }

    if (!(pkt->header.flags & KOE_FLAG_ENCRYPTED)) {
        return -1;
    }

    if (pkt->header.length < crypto_secretbox_MACBYTES) {
        return -1;
    }

    size_t plain_len = pkt->header.length - crypto_secretbox_MACBYTES;
    uint8_t *plaintext = malloc(plain_len);
    if (!plaintext) {
        return -1;
    }

    if (koe_decrypt(plaintext, pkt->payload, pkt->header.length,
                    pkt->header.nonce, sess->rx_key) != 0) {
        free(plaintext);
        return -1;
    }

    if (msg->body) {
        free(msg->body);
    }

    msg->body = plaintext;
    msg->body_len = plain_len;

    memcpy(msg->from, pkt->header.from, KOE_ED25519_PK_LEN);
    memcpy(msg->to, pkt->header.to, KOE_ED25519_PK_LEN);

    msg->status = KOE_STATUS_DELIVERED;
    msg->delivered_at = time(NULL);

    return 0;
}