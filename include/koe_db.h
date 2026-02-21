/*
 * koe_db.h - Database abstraction layer.
 *
 * koe-core supports three backends:
 *
 *   KOE_DB_SQLITE      — local device storage (Termux, embedded)
 *   KOE_DB_POSTGRES    — server-side persistent storage (koe-server)
 *   KOE_DB_MYSQL       — alternative server-side backend
 *
 * Additionally, Redis is supported as an optional cache layer:
 *
 *   KOE_CACHE_REDIS    — group membership cache, presence cache
 *
 * The active backend is chosen at init time and is transparent to the rest
 * of the core.  All queries go through a small set of typed operations;
 * raw SQL is never exposed above this layer.
 *
 * Thread safety: koe_db_t is not thread-safe.  Use one connection per thread
 * or protect with a mutex in multi-threaded environments (koe-server).
 */

#ifndef KOE_DB_H
#define KOE_DB_H

#include <stdint.h>
#include <stddef.h>

/* ---------------------------------------------------------------------- */
/* Backend selection                                                         */
/* ---------------------------------------------------------------------- */

typedef enum {
    KOE_DB_SQLITE   = 0,
    KOE_DB_POSTGRES = 1,
    KOE_DB_MYSQL    = 2,
} koe_db_backend_t;

typedef enum {
    KOE_CACHE_NONE  = 0,
    KOE_CACHE_REDIS = 1,
} koe_cache_backend_t;

/* ---------------------------------------------------------------------- */
/* Connection config                                                         */
/* ---------------------------------------------------------------------- */

typedef struct {
    koe_db_backend_t  backend;

    /* SQLite: path to the .db file. */
    const char *sqlite_path;

    /* PostgreSQL / MySQL. */
    const char *host;
    uint16_t    port;
    const char *database;
    const char *user;
    const char *password;
    int         use_tls;

    /* Connection pool size (0 = single connection). */
    int pool_size;
} koe_db_config_t;

typedef struct {
    koe_cache_backend_t backend;
    const char         *host;
    uint16_t            port;
    const char         *password;   /* NULL if no auth */
    int                 db_index;   /* Redis DB number, default 0 */
    int                 enabled;    /* 0 = cache disabled         */
} koe_cache_config_t;

/* ---------------------------------------------------------------------- */
/* Opaque connection handles                                                 */
/* Defined in the implementation; forward-declared here for bindgen.         */
/* ---------------------------------------------------------------------- */

typedef struct koe_db_conn   koe_db_conn_t;
typedef struct koe_cache_conn koe_cache_conn_t;

/* ---------------------------------------------------------------------- */
/* Stored record types                                                       */
/* ---------------------------------------------------------------------- */

/* A single message row. */
typedef struct {
    int64_t  id;
    uint8_t  from_pk[32];
    uint8_t  to_pk[32];
    uint8_t *body_encrypted;   /* raw ciphertext, heap-allocated */
    size_t   body_len;
    int64_t  sent_at;
    int64_t  delivered_at;    /* 0 if not yet delivered */
    int64_t  read_at;         /* 0 if not yet read      */
    int64_t  destruct_at;     /* 0 if no self-destruct  */
    uint8_t  status;
    int      is_secret;       /* stored in secret partition */
} koe_db_message_t;

/* A contact row. */
typedef struct {
    uint8_t pk[32];
    char    display_name[64];
    char    short_id[16];
    int64_t added_at;
    int64_t last_seen;
    int     blocked;
    int     verified;         /* identity verification completed */
} koe_db_contact_t;

/* A queued offline message row. */
typedef struct {
    int64_t  id;
    uint8_t  to_pk[32];
    uint8_t *packet_bytes;    /* serialised koe_packet_t, heap-allocated */
    size_t   packet_len;
    int64_t  queued_at;
    int64_t  expires_at;
    int64_t  sequence;
} koe_db_queued_t;

/* ---------------------------------------------------------------------- */
/* Connection management                                                     */
/* ---------------------------------------------------------------------- */

/*
 * koe_db_open - Open a database connection.
 *
 * Returns a heap-allocated koe_db_conn_t on success, NULL on failure.
 * The schema is created if it does not exist (SQLite only; for Postgres/MySQL
 * the schema must be applied separately using the migration files in
 * koe-server/db/migrations/).
 */
koe_db_conn_t *koe_db_open(const koe_db_config_t *cfg);

/*
 * koe_db_close - Close and free a connection.
 */
void koe_db_close(koe_db_conn_t *conn);

/*
 * koe_cache_open - Open a Redis cache connection.
 *
 * Returns NULL if cfg->enabled == 0 (cache is optional).
 */
koe_cache_conn_t *koe_cache_open(const koe_cache_config_t *cfg);

void koe_cache_close(koe_cache_conn_t *conn);

/* ---------------------------------------------------------------------- */
/* Message operations                                                        */
/* ---------------------------------------------------------------------- */

int koe_db_message_insert(koe_db_conn_t *conn, koe_db_message_t *msg);
int koe_db_message_update_status(koe_db_conn_t *conn, int64_t id, uint8_t status);
int koe_db_message_mark_delivered(koe_db_conn_t *conn, int64_t id, int64_t ts);
int koe_db_message_mark_read(koe_db_conn_t *conn, int64_t id, int64_t ts);
int koe_db_message_delete(koe_db_conn_t *conn, int64_t id);

/*
 * koe_db_message_query - Fetch messages for a conversation.
 *
 * peer_pk:    the other party's public key.
 * since_id:   return only messages with id > since_id (0 = all).
 * limit:      max rows to return.
 * out:        caller-allocated array of koe_db_message_t.
 * out_count:  set to the number of rows returned.
 *
 * The caller must free each out[i].body_encrypted.
 */
int koe_db_message_query(koe_db_conn_t    *conn,
                          const uint8_t     peer_pk[32],
                          int64_t           since_id,
                          int               limit,
                          koe_db_message_t *out,
                          int              *out_count);

/*
 * koe_db_destruct_sweep - Delete all messages whose destruct_at <= now.
 *
 * Returns the number of rows deleted.
 */
int koe_db_destruct_sweep(koe_db_conn_t *conn, int64_t now_unix);

/* ---------------------------------------------------------------------- */
/* Contact operations                                                        */
/* ---------------------------------------------------------------------- */

int koe_db_contact_upsert(koe_db_conn_t *conn, const koe_db_contact_t *c);
int koe_db_contact_delete(koe_db_conn_t *conn, const uint8_t pk[32]);
int koe_db_contact_find(koe_db_conn_t *conn, const uint8_t pk[32], koe_db_contact_t *out);
int koe_db_contact_list(koe_db_conn_t *conn, koe_db_contact_t *out, int max, int *count);
int koe_db_contact_set_blocked(koe_db_conn_t *conn, const uint8_t pk[32], int blocked);
int koe_db_contact_set_verified(koe_db_conn_t *conn, const uint8_t pk[32], int verified);

/* ---------------------------------------------------------------------- */
/* Offline queue operations                                                  */
/* ---------------------------------------------------------------------- */

int koe_db_queue_push(koe_db_conn_t *conn, koe_db_queued_t *q);
int koe_db_queue_pop(koe_db_conn_t *conn, const uint8_t to_pk[32], koe_db_queued_t *out);
int koe_db_queue_count(koe_db_conn_t *conn, const uint8_t to_pk[32]);
int koe_db_queue_expire(koe_db_conn_t *conn, int64_t now_unix);

/* ---------------------------------------------------------------------- */
/* Cache operations (Redis, group-specific)                                  */
/* ---------------------------------------------------------------------- */

/*
 * koe_cache_group_set - Store a group's member list in the cache.
 *
 * group_id:    Matrix room ID string.
 * members:     array of 32-byte public keys.
 * count:       number of members.
 * ttl_seconds: how long to cache (0 = use default 3600).
 */
int koe_cache_group_set(koe_cache_conn_t *cache,
                         const char       *group_id,
                         const uint8_t    *members,
                         int               count,
                         int               ttl_seconds);

/*
 * koe_cache_group_get - Retrieve a group's member list from cache.
 *
 * out:       caller-allocated buffer for member public keys.
 * out_count: set to the number of members returned.
 *
 * Returns 0 if found, 1 if cache miss, -1 on error.
 */
int koe_cache_group_get(koe_cache_conn_t *cache,
                         const char       *group_id,
                         uint8_t          *out,
                         int               max_members,
                         int              *out_count);

int koe_cache_group_invalidate(koe_cache_conn_t *cache, const char *group_id);

/* ---------------------------------------------------------------------- */
/* Schema migration (SQLite only)                                            */
/* ---------------------------------------------------------------------- */

/*
 * koe_db_migrate - Apply any pending schema migrations.
 *
 * Safe to call every time the library starts; it is idempotent.
 * Returns 0 on success, -1 on error.
 */
int koe_db_migrate(koe_db_conn_t *conn);

#endif /* KOE_DB_H */
