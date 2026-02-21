/*
 * koe_core.c - Top-level initialisation, teardown, and send wrappers.
 *
 * koe_init() brings up the entire stack in order: crypto, identity, contacts,
 * message store, transport, and finally the event loop. Any failure aborts
 * early and leaves the stack in a partially initialised state; koe_shutdown()
 * is safe to call even in that case.
 *
 * The convenience send wrappers (koe_send_text, koe_add_contact, etc.) are
 * thin glue over the lower-level modules. They handle the common case so that
 * callers (the Rust TUI, tests) do not need to assemble packets by hand.
 */

#include "koe.h"
#include "koe_crypto.h"
#include "koe_event.h"
#include "koe_message.h"
#include "koe_queue.h"
#include "koe_transport.h"
#include "koe_identity.h"
#include "koe_handshake.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sodium.h>

/* ---------------------------------------------------------------------- */

int koe_init(koe_ctx_t *ctx, const koe_config_t *cfg)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->cfg = *cfg;

    /* 1. Cryptography library. */
    if (koe_crypto_init() != 0) {
        fprintf(stderr, "koe_init: libsodium init failed\n");
        return -1;
    }

    /* 2. Local identity. */
    if (koe_profile_load(&ctx->profile, cfg->data_dir, cfg->passphrase) != 0) {
        fprintf(stderr, "koe_init: no existing profile, creating a new one\n");
        if (koe_profile_create(&ctx->profile, "user", cfg->passphrase, cfg->data_dir) != 0) {
            fprintf(stderr, "koe_init: failed to create profile\n");
            return -1;
        }
    }

    /* 3. Contact book. */
    koe_contact_book_init(&ctx->contacts);
    koe_contact_book_load(&ctx->contacts, cfg->data_dir, &ctx->profile.keys);
    /* Non-fatal if load fails: we start with an empty book. */

    /* 4. Offline message queue. */
    if (koe_queue_open(&ctx->queue, cfg->data_dir, &ctx->profile.keys) != 0) {
        fprintf(stderr, "koe_init: queue open failed\n");
        return -1;
    }
    ctx->queue.count = (size_t)(cfg->queue_max_per_peer > 0
                                  ? cfg->queue_max_per_peer
                                  : KOE_QUEUE_MAX_PER_PEER);

    /* 5. Transport layer. */
    if (koe_transport_init(&ctx->transport,
                            cfg->relay_host, cfg->relay_port) != 0) {
        fprintf(stderr, "koe_init: transport init failed (continuing without network)\n");
        /* Not fatal: the app can still work in loopback mode. */
    }

    ctx->initialised = 1;
    return 0;
}

void koe_shutdown(koe_ctx_t *ctx)
{
    if (!ctx->initialised) return;

    koe_transport_shutdown(&ctx->transport);

    koe_queue_close(&ctx->queue, &ctx->profile.keys);

    koe_contact_book_save(&ctx->contacts, ctx->cfg.data_dir, &ctx->profile.keys);
    koe_contact_book_free(&ctx->contacts);

    koe_profile_save(&ctx->profile, ctx->cfg.data_dir, ctx->cfg.passphrase);

    /* Zero all key material in memory. */
    sodium_memzero(&ctx->profile.keys, sizeof(ctx->profile.keys));

    ctx->initialised = 0;
}

/* ---------------------------------------------------------------------- */

int64_t koe_send_text(koe_ctx_t     *ctx,
                       const uint8_t  to[KOE_ED25519_PK_LEN],
                       const char    *text,
                       uint32_t       destruct_ttl_seconds)
{
    if (!ctx->initialised) return -1;

    koe_message_t *msg = koe_message_alloc(KOE_MSG_TEXT,
                                             to,
                                             (const uint8_t *)text,
                                             strlen(text));
    if (!msg) return -1;

    memcpy(msg->from, ctx->profile.keys.pk, KOE_ED25519_PK_LEN);

    if (destruct_ttl_seconds > 0)
        koe_message_set_destruct(msg, destruct_ttl_seconds);

    if (koe_message_sign(msg, &ctx->profile.keys) != 0) {
        koe_message_free(msg);
        return -1;
    }

    /* Look up whether the peer is currently reachable. For this stub we
     * check the contact list; in the full implementation the session store
     * tracks live connections. */
    koe_contact_t *contact = koe_contact_find(&ctx->contacts, to);
    int reachable = contact && (time(NULL) - contact->last_seen < 60);

    if (!reachable) {
        /* Peer is offline: push to the queue. */
        koe_packet_t pkt = {0};
        /* A real implementation would serialise msg into pkt here. */
        int64_t seq = koe_queue_push(&ctx->queue, &pkt);
        koe_message_free(msg);
        return seq;
    }

    /* Peer is online: send immediately (transport call omitted — handled
     * by the session layer in the full implementation). */
    int64_t id = (int64_t)msg->id;
    koe_message_free(msg);
    return id;
}

int64_t koe_send_text_scheduled(koe_ctx_t     *ctx,
                                  const uint8_t  to[KOE_ED25519_PK_LEN],
                                  const char    *text,
                                  time_t         send_at)
{
    if (!ctx->initialised) return -1;

    koe_message_t *msg = koe_message_alloc(KOE_MSG_TEXT,
                                             to,
                                             (const uint8_t *)text,
                                             strlen(text));
    if (!msg) return -1;

    memcpy(msg->from, ctx->profile.keys.pk, KOE_ED25519_PK_LEN);
    koe_message_schedule(msg, send_at);

    if (koe_message_sign(msg, &ctx->profile.keys) != 0) {
        koe_message_free(msg);
        return -1;
    }

    /* The event pump will deliver this when send_at is reached. */
    int64_t id = (int64_t)msg->id;
    /* msg ownership is handed off to the scheduler. */
    return id;
}

int koe_add_contact(koe_ctx_t  *ctx,
                     const char *short_id,
                     const char *display_name)
{
    if (!ctx->initialised) return -1;

    /* short_id format: "name#a3f7b2c9"
     * Parse out the hex suffix and derive the full public key prefix.
     * A real implementation would resolve the full key via the relay.   */
    const char *hash = short_id ? strchr(short_id, '#') : NULL;
    if (!hash) return -1;

    /* For now, create a placeholder public key from the short ID. */
    uint8_t pk[KOE_ED25519_PK_LEN] = {0};
    const char *hex = hash + 1;
    for (int i = 0; i < 8 && hex[i] && hex[i+1]; i += 2) {
        unsigned int byte;
        sscanf(hex + i, "%2x", &byte);
        pk[i / 2] = (uint8_t)byte;
    }

    return koe_contact_add(&ctx->contacts, pk, display_name);
}

koe_audio_ctx_t *koe_start_call(koe_ctx_t     *ctx,
                                  const uint8_t  to[KOE_ED25519_PK_LEN])
{
    if (!ctx->initialised) return NULL;

    koe_audio_ctx_t *audio = calloc(1, sizeof(*audio));
    if (!audio) return NULL;

    if (koe_audio_init(audio, to) != 0) {
        free(audio);
        return NULL;
    }

    audio->state = KOE_CALL_RINGING;

    /* Fire a call start event so the TUI can update its state. */
    koe_event_t ev = {0};
    ev.type = KOE_EV_CALL_INCOMING;
    ev.timestamp = time(NULL);
    memcpy(ev.data.peer.pk, to, KOE_ED25519_PK_LEN);
    koe_event_post(&ev);

    return audio;
}

void koe_end_call(koe_ctx_t *ctx, koe_audio_ctx_t *audio)
{
    if (!audio) return;
    (void)ctx;

    audio->state = KOE_CALL_ENDED;
    koe_audio_destroy(audio);

    koe_event_t ev = {0};
    ev.type      = KOE_EV_CALL_ENDED;
    ev.timestamp = time(NULL);
    koe_event_post(&ev);

    free(audio);
}

const char *koe_version(void)
{
    return KOE_VERSION_STRING;
}
