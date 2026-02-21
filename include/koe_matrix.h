/*
 * koe_matrix.h - Matrix protocol bridge for group messaging.
 *
 * Groups in Koe are Matrix rooms.  koe-core provides a thin client that
 * speaks the Matrix Client-Server API (r0.6+) so that:
 *
 *   1. Koe users can create and join rooms on their own koe-server instance.
 *   2. Those rooms federate with the wider Matrix network (Element, Fractal,
 *      etc.) over the Matrix Server-Server API (handled by koe-server, not
 *      this layer).
 *   3. Moderation actions (kick, ban, topic, name) are performed via Matrix
 *      events without the moderator or server reading message content.
 *
 * E2E encryption within Matrix rooms uses the Matrix Megolm session
 * (Olm library) so that the koe-server never has access to plaintext.
 *
 * This header exposes the Matrix client operations that koe-core needs.
 * koe-server implements the server side; the two communicate via HTTPS.
 *
 * Bindgen note: the Matrix access token is a heap string; ownership is
 * always documented explicitly.
 */

#ifndef KOE_MATRIX_H
#define KOE_MATRIX_H

#include "koe_crypto.h"
#include <stdint.h>
#include <stddef.h>

#define KOE_MATRIX_ROOM_ID_MAX    256
#define KOE_MATRIX_USER_ID_MAX    256
#define KOE_MATRIX_TOKEN_MAX      512
#define KOE_MATRIX_TOPIC_MAX      1024
#define KOE_MATRIX_NAME_MAX       128
#define KOE_MATRIX_MAX_MEMBERS    1000

/* ---------------------------------------------------------------------- */
/* Connection context                                                        */
/* ---------------------------------------------------------------------- */

typedef struct {
    char    homeserver[256];   /* e.g. "https://opceanai-koe-server.hf.space" */
    char    access_token[KOE_MATRIX_TOKEN_MAX];
    char    user_id[KOE_MATRIX_USER_ID_MAX];
    int     use_tls;
    int     timeout_ms;        /* HTTP request timeout */
} koe_matrix_ctx_t;

/* ---------------------------------------------------------------------- */
/* Room metadata (safe for moderators to see — no message content)          */
/* ---------------------------------------------------------------------- */

typedef struct {
    char    room_id[KOE_MATRIX_ROOM_ID_MAX];
    char    name[KOE_MATRIX_NAME_MAX];
    char    topic[KOE_MATRIX_TOPIC_MAX];
    char    canonical_alias[256];
    int     member_count;
    int     is_encrypted;
    int64_t created_at;
} koe_matrix_room_t;

/* Membership states. */
typedef enum {
    KOE_MATRIX_MEMBER_INVITE  = 0,
    KOE_MATRIX_MEMBER_JOIN    = 1,
    KOE_MATRIX_MEMBER_LEAVE   = 2,
    KOE_MATRIX_MEMBER_BAN     = 3,
} koe_matrix_membership_t;

typedef struct {
    char                    user_id[KOE_MATRIX_USER_ID_MAX];
    koe_matrix_membership_t state;
    int                     power_level;   /* 0=user, 50=mod, 100=admin */
} koe_matrix_member_t;

/* ---------------------------------------------------------------------- */
/* Authentication                                                            */
/* ---------------------------------------------------------------------- */

/*
 * koe_matrix_login - Authenticate with the homeserver.
 *
 * Derives the Matrix user ID and password from the Koe Ed25519 identity:
 *   user_id: "@<short_id>:homeserver"
 *   password: BLAKE2b(identity.sk || "koe-matrix-auth")
 *
 * This means Koe users never choose a separate Matrix password; their Koe
 * identity IS their Matrix identity.
 *
 * Fills ctx->access_token and ctx->user_id on success.
 * Returns 0 on success, -1 on failure.
 */
int koe_matrix_login(koe_matrix_ctx_t    *ctx,
                      const koe_identity_t *id,
                      const char           *homeserver);

/*
 * koe_matrix_logout - Invalidate the access token on the server.
 */
int koe_matrix_logout(koe_matrix_ctx_t *ctx);

/* ---------------------------------------------------------------------- */
/* Room management                                                           */
/* ---------------------------------------------------------------------- */

/*
 * koe_matrix_room_create - Create a new encrypted Matrix room.
 *
 * name:    human-readable room name.
 * topic:   optional room topic (pass "" for none).
 * room_id_out: filled with the assigned room ID (e.g. "!abc123:homeserver").
 *              Must be at least KOE_MATRIX_ROOM_ID_MAX bytes.
 */
int koe_matrix_room_create(koe_matrix_ctx_t *ctx,
                             const char       *name,
                             const char       *topic,
                             char             *room_id_out);

/*
 * koe_matrix_room_info - Fetch room metadata.
 */
int koe_matrix_room_info(koe_matrix_ctx_t  *ctx,
                          const char        *room_id,
                          koe_matrix_room_t *out);

/*
 * koe_matrix_room_set_name - Change the room name (moderator action).
 */
int koe_matrix_room_set_name(koe_matrix_ctx_t *ctx,
                               const char       *room_id,
                               const char       *new_name);

/*
 * koe_matrix_room_set_topic - Change the room topic (moderator action).
 */
int koe_matrix_room_set_topic(koe_matrix_ctx_t *ctx,
                                const char       *room_id,
                                const char       *new_topic);

/* ---------------------------------------------------------------------- */
/* Membership management                                                     */
/* ---------------------------------------------------------------------- */

/*
 * koe_matrix_room_invite - Invite a user to a room.
 *
 * user_id: full Matrix user ID, e.g. "@shortid:homeserver".
 */
int koe_matrix_room_invite(koe_matrix_ctx_t *ctx,
                             const char       *room_id,
                             const char       *user_id);

/*
 * koe_matrix_room_join - Accept an invitation (or join a public room).
 */
int koe_matrix_room_join(koe_matrix_ctx_t *ctx, const char *room_id);

/*
 * koe_matrix_room_leave - Leave a room.
 */
int koe_matrix_room_leave(koe_matrix_ctx_t *ctx, const char *room_id);

/*
 * koe_matrix_room_kick - Remove a member without banning.
 *
 * reason: optional human-readable reason (pass "" for none).
 * Metadata-only: the server logs the kick event but does not decrypt messages.
 */
int koe_matrix_room_kick(koe_matrix_ctx_t *ctx,
                           const char       *room_id,
                           const char       *user_id,
                           const char       *reason);

/*
 * koe_matrix_room_ban - Ban a member (they cannot rejoin).
 */
int koe_matrix_room_ban(koe_matrix_ctx_t *ctx,
                          const char       *room_id,
                          const char       *user_id,
                          const char       *reason);

/*
 * koe_matrix_room_unban - Remove a ban.
 */
int koe_matrix_room_unban(koe_matrix_ctx_t *ctx,
                            const char       *room_id,
                            const char       *user_id);

/*
 * koe_matrix_room_members - List all members of a room.
 *
 * out:       caller-allocated array of koe_matrix_member_t.
 * max:       capacity of out.
 * out_count: set to the number of members returned.
 */
int koe_matrix_room_members(koe_matrix_ctx_t  *ctx,
                              const char        *room_id,
                              koe_matrix_member_t *out,
                              int                max,
                              int               *out_count);

/*
 * koe_matrix_room_set_power - Promote or demote a member.
 *
 * power_level: 0=user, 50=moderator, 100=admin.
 */
int koe_matrix_room_set_power(koe_matrix_ctx_t *ctx,
                                const char       *room_id,
                                const char       *user_id,
                                int               power_level);

/* ---------------------------------------------------------------------- */
/* Sync and events                                                           */
/* ---------------------------------------------------------------------- */

/*
 * koe_matrix_sync_token_t - Opaque since token for incremental sync.
 */
typedef struct {
    char value[256];
} koe_matrix_sync_token_t;

/*
 * Callback fired for each Matrix event received during sync.
 * event_type: e.g. "m.room.message", "m.room.member".
 * payload:    raw JSON event as a null-terminated string.
 * ctx:        caller-provided context pointer.
 */
typedef void (*koe_matrix_event_cb)(const char *room_id,
                                     const char *event_type,
                                     const char *payload,
                                     void       *ctx);

/*
 * koe_matrix_sync - Perform a Matrix /sync request.
 *
 * token:    pass NULL for initial sync, or the token from the previous call.
 * timeout:  long-poll timeout in milliseconds (0 = no wait).
 * cb:       fired for each event in the response.
 * next_token: set to the token to use for the next call.
 *
 * Returns 0 on success, -1 on error.
 */
int koe_matrix_sync(koe_matrix_ctx_t        *ctx,
                     const koe_matrix_sync_token_t *token,
                     int                      timeout_ms,
                     koe_matrix_event_cb      cb,
                     void                    *cb_ctx,
                     koe_matrix_sync_token_t *next_token);

/* ---------------------------------------------------------------------- */
/* Media upload (server-side only)                                           */
/* ---------------------------------------------------------------------- */

/*
 * koe_matrix_media_upload - Upload a file to the Matrix media endpoint.
 *
 * The file content should already be encrypted by koe_media_* before upload.
 * Returns an MXC URI in mxc_uri_out (at least 256 bytes).
 */
int koe_matrix_media_upload(koe_matrix_ctx_t *ctx,
                              const uint8_t    *data,
                              size_t            data_len,
                              const char       *content_type,
                              char             *mxc_uri_out);

/*
 * koe_matrix_media_download - Download a file by MXC URI.
 *
 * Returns heap-allocated data in *out; caller must free.
 */
int koe_matrix_media_download(koe_matrix_ctx_t *ctx,
                                const char       *mxc_uri,
                                uint8_t         **out,
                                size_t           *out_len);

#endif /* KOE_MATRIX_H */
