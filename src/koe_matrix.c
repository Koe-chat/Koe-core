/*
 * koe_matrix.c - Matrix Client-Server API (r0.6+) implementation.
 *
 * HTTP requests are made using libcurl.  On Android/Termux:
 *   pkg install libcurl-dev
 *
 * If libcurl is not available at build time, all functions return -1 and
 * a warning is printed (compile with -DKOE_NO_CURL to suppress).
 *
 * JSON is produced by hand (no external JSON library needed for the subset
 * of Matrix events we generate).  JSON parsing uses a small inline helper.
 */

#include "koe_matrix.h"
#include "koe_crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifndef KOE_NO_CURL
#include <curl/curl.h>
#endif

/* ---------------------------------------------------------------------- */
/* HTTP response accumulator                                                 */
/* ---------------------------------------------------------------------- */

typedef struct {
    char  *buf;
    size_t len;
    size_t cap;
} koe_http_response_t;

#ifndef KOE_NO_CURL
static size_t write_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    koe_http_response_t *r = (koe_http_response_t *)userdata;
    size_t n = size * nmemb;
    if (r->len + n + 1 > r->cap) {
        size_t new_cap = r->cap + n + 1024;
        char  *new_buf = realloc(r->buf, new_cap);
        if (!new_buf) return 0;
        r->buf = new_buf;
        r->cap = new_cap;
    }
    memcpy(r->buf + r->len, ptr, n);
    r->len += n;
    r->buf[r->len] = '\0';
    return n;
}

/* ---------------------------------------------------------------------- */
/* Internal HTTP helpers                                                     */
/* ---------------------------------------------------------------------- */

typedef enum { HTTP_GET, HTTP_POST, HTTP_PUT } http_method_t;

static int matrix_http(koe_matrix_ctx_t *ctx, http_method_t method,
                        const char *path, const char *body,
                        koe_http_response_t *resp)
{
    CURL *curl = curl_easy_init();
    if (!curl) return -1;

    /* Build full URL. */
    char url[512];
    snprintf(url, sizeof(url), "%s%s", ctx->homeserver, path);

    /* Auth header. */
    char auth_hdr[KOE_MATRIX_TOKEN_MAX + 32];
    snprintf(auth_hdr, sizeof(auth_hdr), "Authorization: Bearer %s", ctx->access_token);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, auth_hdr);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, (long)ctx->timeout_ms);
    if (!ctx->use_tls) curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);

    if (method == HTTP_POST) {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        if (body) curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
        else      curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, 0L);
    } else if (method == HTTP_PUT) {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
        if (body) curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    }

    CURLcode rc = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (rc != CURLE_OK) return -1;
    return (http_code >= 200 && http_code < 300) ? 0 : -1;
}
#endif /* KOE_NO_CURL */

/* ---------------------------------------------------------------------- */
/* Minimal JSON field extractor                                              */
/* ---------------------------------------------------------------------- */

/*
 * Extract the string value of a JSON key from a flat JSON object.
 * e.g. json_get(buf, "access_token", out, sizeof(out))
 * This only works for string values at the top level.
 */
static int json_get_str(const char *json, const char *key, char *out, size_t out_len)
{
    char pattern[256];
    snprintf(pattern, sizeof(pattern), "\"%s\":", key);
    const char *p = strstr(json, pattern);
    if (!p) return -1;
    p += strlen(pattern);
    while (*p == ' ') p++;
    if (*p != '"') return -1;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i < out_len - 1)
        out[i++] = *p++;
    out[i] = '\0';
    return 0;
}

/* ---------------------------------------------------------------------- */
/* Authentication                                                            */
/* ---------------------------------------------------------------------- */

int koe_matrix_login(koe_matrix_ctx_t *ctx, const koe_identity_t *id,
                      const char *homeserver)
{
#ifdef KOE_NO_CURL
    (void)ctx; (void)id; (void)homeserver;
    fprintf(stderr, "koe_matrix: libcurl not compiled in\n");
    return -1;
#else
    strncpy(ctx->homeserver, homeserver, sizeof(ctx->homeserver) - 1);
    ctx->use_tls    = 1;
    ctx->timeout_ms = 10000;

    /* Derive Matrix user ID and password from the Ed25519 identity. */
    koe_short_id_t sid;
    koe_identity_short_id(&sid, id->pk);

    uint8_t pw_hash[32];
    crypto_generichash_state state;
    crypto_generichash_init(&state, NULL, 0, 32);
    crypto_generichash_update(&state, id->sk, KOE_ED25519_SK_LEN);
    crypto_generichash_update(&state, (const uint8_t *)"koe-matrix-auth", 15);
    crypto_generichash_final(&state, pw_hash, 32);

    /* Base64 encode the password hash. */
    char pw_b64[64];
    /* sodium's base64 encode */
    sodium_bin2base64(pw_b64, sizeof(pw_b64), pw_hash, sizeof(pw_hash),
                      sodium_base64_VARIANT_URLSAFE_NO_PADDING);

    char body[512];
    snprintf(body, sizeof(body),
             "{\"type\":\"m.login.password\","
             "\"user\":\"%s\","
             "\"password\":\"%s\"}",
             sid.value, pw_b64);

    koe_http_response_t resp = { calloc(1, 4096), 0, 4096 };
    int rc = matrix_http(ctx, HTTP_POST, "/_matrix/client/r0/login", body, &resp);
    if (rc == 0) {
        json_get_str(resp.buf, "access_token", ctx->access_token, KOE_MATRIX_TOKEN_MAX);
        json_get_str(resp.buf, "user_id",      ctx->user_id,      KOE_MATRIX_USER_ID_MAX);
    }
    free(resp.buf);
    return rc;
#endif
}

int koe_matrix_logout(koe_matrix_ctx_t *ctx)
{
#ifdef KOE_NO_CURL
    (void)ctx; return -1;
#else
    koe_http_response_t resp = { calloc(1, 256), 0, 256 };
    int rc = matrix_http(ctx, HTTP_POST, "/_matrix/client/r0/logout", "{}", &resp);
    free(resp.buf);
    koe_memzero(ctx->access_token, sizeof(ctx->access_token));
    return rc;
#endif
}

/* ---------------------------------------------------------------------- */
/* Room management                                                           */
/* ---------------------------------------------------------------------- */

int koe_matrix_room_create(koe_matrix_ctx_t *ctx, const char *name,
                             const char *topic, char *room_id_out)
{
#ifdef KOE_NO_CURL
    (void)ctx; (void)name; (void)topic; (void)room_id_out; return -1;
#else
    char body[1024];
    snprintf(body, sizeof(body),
             "{\"name\":\"%s\","
             "\"topic\":\"%s\","
             "\"initial_state\":[{"
             "\"type\":\"m.room.encryption\","
             "\"state_key\":\"\","
             "\"content\":{\"algorithm\":\"m.megolm.v1.aes-sha2\"}"
             "}]}",
             name, topic);

    koe_http_response_t resp = { calloc(1, 1024), 0, 1024 };
    int rc = matrix_http(ctx, HTTP_POST, "/_matrix/client/r0/createRoom", body, &resp);
    if (rc == 0 && room_id_out)
        json_get_str(resp.buf, "room_id", room_id_out, KOE_MATRIX_ROOM_ID_MAX);
    free(resp.buf);
    return rc;
#endif
}

int koe_matrix_room_set_name(koe_matrix_ctx_t *ctx, const char *room_id,
                               const char *new_name)
{
#ifdef KOE_NO_CURL
    (void)ctx; (void)room_id; (void)new_name; return -1;
#else
    char path[512], body[256];
    snprintf(path, sizeof(path),
             "/_matrix/client/r0/rooms/%s/state/m.room.name", room_id);
    snprintf(body, sizeof(body), "{\"name\":\"%s\"}", new_name);
    koe_http_response_t resp = { calloc(1, 256), 0, 256 };
    int rc = matrix_http(ctx, HTTP_PUT, path, body, &resp);
    free(resp.buf);
    return rc;
#endif
}

int koe_matrix_room_set_topic(koe_matrix_ctx_t *ctx, const char *room_id,
                                const char *new_topic)
{
#ifdef KOE_NO_CURL
    (void)ctx; (void)room_id; (void)new_topic; return -1;
#else
    char path[512], body[1200];
    snprintf(path, sizeof(path),
             "/_matrix/client/r0/rooms/%s/state/m.room.topic", room_id);
    snprintf(body, sizeof(body), "{\"topic\":\"%s\"}", new_topic);
    koe_http_response_t resp = { calloc(1, 256), 0, 256 };
    int rc = matrix_http(ctx, HTTP_PUT, path, body, &resp);
    free(resp.buf);
    return rc;
#endif
}

int koe_matrix_room_invite(koe_matrix_ctx_t *ctx, const char *room_id,
                             const char *user_id)
{
#ifdef KOE_NO_CURL
    (void)ctx; (void)room_id; (void)user_id; return -1;
#else
    char path[512], body[512];
    snprintf(path, sizeof(path), "/_matrix/client/r0/rooms/%s/invite", room_id);
    snprintf(body, sizeof(body), "{\"user_id\":\"%s\"}", user_id);
    koe_http_response_t resp = { calloc(1, 256), 0, 256 };
    int rc = matrix_http(ctx, HTTP_POST, path, body, &resp);
    free(resp.buf);
    return rc;
#endif
}

int koe_matrix_room_join(koe_matrix_ctx_t *ctx, const char *room_id)
{
#ifdef KOE_NO_CURL
    (void)ctx; (void)room_id; return -1;
#else
    char path[512];
    snprintf(path, sizeof(path), "/_matrix/client/r0/rooms/%s/join", room_id);
    koe_http_response_t resp = { calloc(1, 256), 0, 256 };
    int rc = matrix_http(ctx, HTTP_POST, path, "{}", &resp);
    free(resp.buf);
    return rc;
#endif
}

int koe_matrix_room_leave(koe_matrix_ctx_t *ctx, const char *room_id)
{
#ifdef KOE_NO_CURL
    (void)ctx; (void)room_id; return -1;
#else
    char path[512];
    snprintf(path, sizeof(path), "/_matrix/client/r0/rooms/%s/leave", room_id);
    koe_http_response_t resp = { calloc(1, 256), 0, 256 };
    int rc = matrix_http(ctx, HTTP_POST, path, "{}", &resp);
    free(resp.buf);
    return rc;
#endif
}

static int matrix_membership_action(koe_matrix_ctx_t *ctx, const char *room_id,
                                      const char *action, const char *user_id,
                                      const char *reason)
{
#ifdef KOE_NO_CURL
    (void)ctx; (void)room_id; (void)action; (void)user_id; (void)reason; return -1;
#else
    char path[512], body[512];
    snprintf(path, sizeof(path), "/_matrix/client/r0/rooms/%s/%s", room_id, action);
    snprintf(body, sizeof(body), "{\"user_id\":\"%s\",\"reason\":\"%s\"}",
             user_id, reason ? reason : "");
    koe_http_response_t resp = { calloc(1, 256), 0, 256 };
    int rc = matrix_http(ctx, HTTP_POST, path, body, &resp);
    free(resp.buf);
    return rc;
#endif
}

int koe_matrix_room_kick(koe_matrix_ctx_t *ctx, const char *room_id,
                           const char *user_id, const char *reason)
{ return matrix_membership_action(ctx, room_id, "kick", user_id, reason); }

int koe_matrix_room_ban(koe_matrix_ctx_t *ctx, const char *room_id,
                          const char *user_id, const char *reason)
{ return matrix_membership_action(ctx, room_id, "ban", user_id, reason); }

int koe_matrix_room_unban(koe_matrix_ctx_t *ctx, const char *room_id,
                            const char *user_id)
{ return matrix_membership_action(ctx, room_id, "unban", user_id, ""); }

int koe_matrix_room_members(koe_matrix_ctx_t *ctx, const char *room_id,
                              koe_matrix_member_t *out, int max, int *out_count)
{
    /* Full member list parsing is complex; stub returns 0 members. */
    (void)ctx; (void)room_id; (void)out; (void)max;
    *out_count = 0;
    return 0;
}

int koe_matrix_room_set_power(koe_matrix_ctx_t *ctx, const char *room_id,
                                const char *user_id, int power_level)
{
#ifdef KOE_NO_CURL
    (void)ctx; (void)room_id; (void)user_id; (void)power_level; return -1;
#else
    char path[512], body[512];
    snprintf(path, sizeof(path),
             "/_matrix/client/r0/rooms/%s/state/m.room.power_levels", room_id);
    snprintf(body, sizeof(body),
             "{\"users\":{\"%s\":%d}}", user_id, power_level);
    koe_http_response_t resp = { calloc(1, 256), 0, 256 };
    int rc = matrix_http(ctx, HTTP_PUT, path, body, &resp);
    free(resp.buf);
    return rc;
#endif
}

/* ---------------------------------------------------------------------- */
/* Sync                                                                     */
/* ---------------------------------------------------------------------- */

int koe_matrix_sync(koe_matrix_ctx_t *ctx, const koe_matrix_sync_token_t *token,
                     int timeout_ms, koe_matrix_event_cb cb, void *cb_ctx,
                     koe_matrix_sync_token_t *next_token)
{
#ifdef KOE_NO_CURL
    (void)ctx; (void)token; (void)timeout_ms; (void)cb; (void)cb_ctx;
    (void)next_token;
    return -1;
#else
    char path[512];
    if (token && token->value[0])
        snprintf(path, sizeof(path), "/_matrix/client/r0/sync?since=%s&timeout=%d",
                 token->value, timeout_ms);
    else
        snprintf(path, sizeof(path), "/_matrix/client/r0/sync?timeout=%d", timeout_ms);

    koe_http_response_t resp = { calloc(1, 65536), 0, 65536 };
    int rc = matrix_http(ctx, HTTP_GET, path, NULL, &resp);
    if (rc == 0) {
        /* Extract next_batch for the next sync call. */
        if (next_token)
            json_get_str(resp.buf, "next_batch", next_token->value,
                          sizeof(next_token->value));

        /* Fire the callback with the raw JSON response.
         * A full implementation would parse rooms.join[].timeline.events
         * and call cb() per event. */
        if (cb) cb("", "m.sync.response", resp.buf, cb_ctx);
    }
    free(resp.buf);
    return rc;
#endif
}

/* ---------------------------------------------------------------------- */
/* Media                                                                    */
/* ---------------------------------------------------------------------- */

int koe_matrix_media_upload(koe_matrix_ctx_t *ctx, const uint8_t *data,
                              size_t data_len, const char *content_type,
                              char *mxc_uri_out)
{
#ifdef KOE_NO_CURL
    (void)ctx; (void)data; (void)data_len; (void)content_type; (void)mxc_uri_out;
    return -1;
#else
    /* Direct data upload using a raw POST with the content-type set. */
    CURL *curl = curl_easy_init();
    if (!curl) return -1;

    char url[512];
    snprintf(url, sizeof(url), "%s/_matrix/media/r0/upload", ctx->homeserver);

    char auth_hdr[KOE_MATRIX_TOKEN_MAX + 32];
    snprintf(auth_hdr, sizeof(auth_hdr), "Authorization: Bearer %s", ctx->access_token);

    char ct_hdr[256];
    snprintf(ct_hdr, sizeof(ct_hdr), "Content-Type: %s", content_type);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, auth_hdr);
    headers = curl_slist_append(headers, ct_hdr);

    koe_http_response_t resp = { calloc(1, 512), 0, 512 };

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)data_len);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, (long)ctx->timeout_ms);
    if (!ctx->use_tls) curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);

    CURLcode rc = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (rc == CURLE_OK && http_code >= 200 && http_code < 300 && mxc_uri_out)
        json_get_str(resp.buf, "content_uri", mxc_uri_out, 256);

    free(resp.buf);
    return (rc == CURLE_OK && http_code >= 200 && http_code < 300) ? 0 : -1;
#endif
}

int koe_matrix_media_download(koe_matrix_ctx_t *ctx, const char *mxc_uri,
                                uint8_t **out, size_t *out_len)
{
    (void)ctx; (void)mxc_uri; (void)out; (void)out_len;
    /* Full implementation uses curl to GET /_matrix/media/r0/download/<mxc_uri>. */
    return -1;
}
