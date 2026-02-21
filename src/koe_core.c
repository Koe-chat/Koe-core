/*
 * koe_core.c - Top-level lifecycle and convenience wrappers.
 */

#include "koe.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>

/* Global plugin registry pointer accessed by koe_event.c. */
struct koe_plugin_registry *g_plugin_registry = NULL;

/* ---------------------------------------------------------------------- */
/* Helpers                                                                  */
/* ---------------------------------------------------------------------- */

static void mkdir_p(const char *path)
{
    char tmp[512];
    strncpy(tmp, path, sizeof(tmp) - 1);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') { *p = '\0'; mkdir(tmp, 0700); *p = '/'; }
    }
    mkdir(tmp, 0700);
}

/* ---------------------------------------------------------------------- */
/* Init                                                                     */
/* ---------------------------------------------------------------------- */

int koe_init(koe_ctx_t *ctx, const koe_config_t *cfg)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->cfg = *cfg;

    /* 1. libsodium. */
    if (koe_crypto_init() != 0) {
        fprintf(stderr, "koe_init: libsodium init failed\n");
        return -1;
    }

    /* 2. Ensure data root exists. */
    mkdir_p(cfg->data_root);

    /* 3. Account registry. */
    if (koe_account_registry_load(&ctx->account_registry,
                                   cfg->data_root,
                                   cfg->passphrase) != 0) {
        fprintf(stderr, "koe_init: account registry load failed\n");
        return -1;
    }

    /* 4. Activate account.
     *    If no accounts exist, create one now. */
    if (ctx->account_registry.count == 0) {
        fprintf(stderr, "koe_init: no accounts found, creating default\n");
        if (koe_account_create(&ctx->active_account,
                                &ctx->account_registry,
                                "me",
                                cfg->passphrase) != 0) {
            fprintf(stderr, "koe_init: account creation failed\n");
            return -1;
        }
    } else {
        /* Activate the first account (last-used tracking is a TODO). */
        if (koe_account_activate(&ctx->active_account,
                                  &ctx->account_registry,
                                  0,
                                  cfg->passphrase) != 0) {
            fprintf(stderr, "koe_init: account activation failed\n");
            return -1;
        }
    }

    /* 5. Open database. */
    char db_path[512];
    snprintf(db_path, sizeof(db_path), "%s/accounts/%s/history.db",
             cfg->data_root,
             ctx->active_account.desc.data_subdir);

    koe_db_config_t db_cfg = cfg->db;
    if (db_cfg.backend == KOE_DB_SQLITE)
        db_cfg.sqlite_path = db_path;

    ctx->db = koe_db_open(&db_cfg);
    if (!ctx->db) {
        fprintf(stderr, "koe_init: database open failed\n");
        return -1;
    }

    /* 6. Load contacts. */
    koe_contact_book_init(&ctx->contacts);
    koe_contact_book_load(&ctx->contacts, ctx->db);

    /* 7. Open offline queue. */
    koe_queue_open(&ctx->queue, ctx->db,
                   cfg->queue_max_per_peer > 0 ? cfg->queue_max_per_peer
                                                : KOE_QUEUE_MAX_PER_PEER);

    /* 8. Start transport. */
    if (koe_transport_init(&ctx->transport,
                            cfg->relay_host,
                            cfg->relay_port,
                            cfg->ws_port) != 0) {
        fprintf(stderr, "koe_init: transport init failed (continuing)\n");
    }

    /* 9. Presence table. */
    koe_presence_init(&ctx->presence);

    /* 10. Redis cache (optional). */
    ctx->cache = koe_cache_open(&cfg->cache);

    /* 11. Plugins. */
    if (cfg->plugins_dir) {
        if (koe_plugin_registry_load(&ctx->plugins, cfg->plugins_dir) == 0)
            g_plugin_registry = (struct koe_plugin_registry *)&ctx->plugins;
    }

    /* 12. Matrix. */
    if (cfg->matrix_homeserver) {
        koe_matrix_login(&ctx->matrix,
                          &ctx->active_account.keys,
                          cfg->matrix_homeserver);
    }

    ctx->initialised = 1;
    fprintf(stderr, "koe_init: ready (account=%s)\n",
            ctx->active_account.desc.display_name);
    return 0;
}

/* ---------------------------------------------------------------------- */
/* Shutdown                                                                 */
/* ---------------------------------------------------------------------- */

void koe_shutdown(koe_ctx_t *ctx)
{
    if (!ctx->initialised) return;

    /* Flush contacts to DB. */
    if (ctx->db)
        koe_contact_book_save(&ctx->contacts, ctx->db);

    /* Disconnect Matrix. */
    if (ctx->matrix.access_token[0])
        koe_matrix_logout(&ctx->matrix);

    /* Disable plugins. */
    for (int i = 0; i < ctx->plugins.count; i++)
        koe_plugin_disable(&ctx->plugins.plugins[i]);
    g_plugin_registry = NULL;

    /* Close transports. */
    koe_transport_shutdown(&ctx->transport);

    /* Close cache and DB. */
    koe_cache_close(ctx->cache); ctx->cache = NULL;
    koe_queue_close(&ctx->queue);
    koe_db_close(ctx->db); ctx->db = NULL;

    /* Free contact book. */
    koe_contact_book_free(&ctx->contacts);

    /* Deactivate account (zeros secret keys). */
    koe_account_deactivate(&ctx->active_account);

    ctx->initialised = 0;
}

/* ---------------------------------------------------------------------- */
/* Account rotation                                                         */
/* ---------------------------------------------------------------------- */

int koe_switch_account(koe_ctx_t *ctx, int idx, const char *passphrase)
{
    if (!ctx->initialised) return -1;

    /* Save current state. */
    koe_contact_book_save(&ctx->contacts, ctx->db);
    koe_db_close(ctx->db); ctx->db = NULL;
    koe_contact_book_free(&ctx->contacts);
    koe_account_deactivate(&ctx->active_account);

    /* Load new account. */
    if (koe_account_activate(&ctx->active_account,
                              &ctx->account_registry,
                              idx,
                              passphrase) != 0) return -1;

    /* Re-open DB for the new account. */
    char db_path[512];
    snprintf(db_path, sizeof(db_path), "%s/accounts/%s/history.db",
             ctx->cfg.data_root,
             ctx->active_account.desc.data_subdir);

    koe_db_config_t db_cfg = ctx->cfg.db;
    if (db_cfg.backend == KOE_DB_SQLITE) db_cfg.sqlite_path = db_path;
    ctx->db = koe_db_open(&db_cfg);
    if (!ctx->db) return -1;

    koe_contact_book_init(&ctx->contacts);
    koe_contact_book_load(&ctx->contacts, ctx->db);

    /* Fire event. */
    koe_event_t ev = {0};
    ev.type = KOE_EV_IDENTITY_SWITCHED;
    koe_event_post(&ev);

    return 0;
}

/* ---------------------------------------------------------------------- */
/* Convenience sends                                                        */
/* ---------------------------------------------------------------------- */

int64_t koe_send_text(koe_ctx_t *ctx, const uint8_t to[KOE_ED25519_PK_LEN],
                       const char *text, uint32_t destruct_ttl)
{
    if (!ctx->initialised) return -1;

    koe_message_t *msg = koe_message_alloc(KOE_MSG_TEXT, to,
                                            (const uint8_t *)text, strlen(text));
    if (!msg) return -1;

    memcpy(msg->from, ctx->active_account.keys.pk, KOE_ED25519_PK_LEN);
    if (destruct_ttl > 0) koe_message_set_destruct(msg, destruct_ttl);
    koe_message_sign(msg, &ctx->active_account.keys);

    int64_t id = (int64_t)msg->id;

    /* Try to deliver immediately; if the peer is unreachable, queue. */
    koe_contact_t *contact = koe_contact_find(&ctx->contacts, to);
    (void)contact;

    /* Look up active session — simplified: build a dummy packet and push to queue. */
    koe_packet_t pkt;
    koe_session_t dummy_sess = {0};
    if (koe_message_encrypt(msg, &dummy_sess, &pkt) == 0) {
        koe_queue_push(&ctx->queue, &pkt);
        koe_packet_free(&pkt);
    }

    koe_message_free(msg);
    return id;
}

int64_t koe_send_text_scheduled(koe_ctx_t *ctx, const uint8_t to[KOE_ED25519_PK_LEN],
                                  const char *text, int64_t send_at_unix)
{
    if (!ctx->initialised) return -1;

    koe_message_t *msg = koe_message_alloc(KOE_MSG_TEXT, to,
                                            (const uint8_t *)text, strlen(text));
    if (!msg) return -1;

    memcpy(msg->from, ctx->active_account.keys.pk, KOE_ED25519_PK_LEN);
    koe_message_schedule(msg, send_at_unix);
    koe_message_sign(msg, &ctx->active_account.keys);

    int64_t id = (int64_t)msg->id;
    koe_message_free(msg);
    return id;
}

int koe_send_file(koe_ctx_t *ctx, const uint8_t to[KOE_ED25519_PK_LEN],
                   const char *file_path, char *transfer_id_out)
{
    if (!ctx->initialised) return -1;

    koe_media_offer_t offer;
    koe_packet_t      pkt;
    koe_session_t     dummy_sess = {0};

    if (koe_media_offer_build(file_path, to, &dummy_sess, &offer, &pkt) != 0)
        return -1;

    if (transfer_id_out) {
        /* Hex-encode transfer_id. */
        for (int i = 0; i < KOE_MEDIA_TRANSFER_ID_LEN; i++)
            snprintf(transfer_id_out + i * 2, 3, "%02x", offer.transfer_id[i]);
        transfer_id_out[KOE_MEDIA_TRANSFER_ID_LEN * 2] = '\0';
    }

    koe_queue_push(&ctx->queue, &pkt);
    koe_packet_free(&pkt);
    return 0;
}

int koe_add_contact(koe_ctx_t *ctx, const char *short_id, const char *display_name)
{
    if (!ctx->initialised) return -1;

    /* In a full implementation we would resolve short_id to a full pk
     * via the relay or discovery.  For now, stub with a zeroed pk. */
    uint8_t pk[KOE_ED25519_PK_LEN] = {0};
    (void)short_id;

    if (koe_contact_add(&ctx->contacts, pk, display_name) != 0) return -1;
    return koe_contact_book_save(&ctx->contacts, ctx->db);
}

koe_audio_ctx_t *koe_start_call(koe_ctx_t *ctx, const uint8_t to[KOE_ED25519_PK_LEN])
{
    if (!ctx->initialised) return NULL;
    koe_audio_ctx_t *audio = calloc(1, sizeof(*audio));
    if (!audio) return NULL;
    if (koe_audio_init(audio, to) != 0) { free(audio); return NULL; }
    return audio;
}

void koe_end_call(koe_ctx_t *ctx, koe_audio_ctx_t *audio)
{
    (void)ctx;
    if (audio) {
        koe_audio_destroy(audio);
        free(audio);
    }
}

/* ---------------------------------------------------------------------- */
/* Group convenience                                                        */
/* ---------------------------------------------------------------------- */

int koe_group_create(koe_ctx_t *ctx, const char *name,
                      const char *topic, char *room_id_out)
{
    if (!ctx->initialised) return -1;
    return koe_matrix_room_create(&ctx->matrix, name, topic, room_id_out);
}

int koe_group_send(koe_ctx_t *ctx, const char *room_id, const char *text)
{
#ifdef KOE_NO_CURL
    (void)ctx; (void)room_id; (void)text; return -1;
#else
    if (!ctx->initialised) return -1;

    /* Encrypt text with Megolm (stub: send plaintext JSON for now).
     * A full implementation uses libolm. */
    char path[512];
    snprintf(path, sizeof(path),
             "/_matrix/client/r0/rooms/%s/send/m.room.message/%" PRId64,
             room_id, (int64_t)time(NULL));

    char body[4096];
    snprintf(body, sizeof(body),
             "{\"msgtype\":\"m.text\",\"body\":\"%s\"}", text);

    /* matrix_http is static in koe_matrix.c; we call the public Matrix API. */
    /* For now this is a no-op placeholder. */
    (void)path; (void)body;
    return -1;
#endif
}

/* ---------------------------------------------------------------------- */
/* Version                                                                  */
/* ---------------------------------------------------------------------- */

const char *koe_version_string_full(void)
{
    return "koe-core/" KOE_VERSION_STRING " proto/" KOE_PROTO_STRING;
}
