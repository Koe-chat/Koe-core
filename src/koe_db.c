/*
 * koe_db.c - Database abstraction layer (SQLite implementation).
 *
 * PostgreSQL and MySQL backends follow the same interface.  Their
 * implementations live in koe_db_postgres.c and koe_db_mysql.c; this file
 * covers SQLite (the device-side default) and the Redis cache.
 *
 * Redis cache is implemented as a simple key-value wrapper.  The hiredis
 * library is used for the TCP connection.  If hiredis is not available at
 * build time, the cache backend compiles to no-ops (KOE_CACHE_NONE).
 */

#include "koe_db.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sqlite3.h>

/* ---------------------------------------------------------------------- */
/* Opaque handle definitions                                                 */
/* ---------------------------------------------------------------------- */

struct koe_db_conn {
    koe_db_backend_t backend;
    sqlite3         *sqlite;   /* non-NULL for KOE_DB_SQLITE */
    /* Postgres/MySQL handles would live here. */
};

struct koe_cache_conn {
    koe_cache_backend_t backend;
    /* hiredis redisContext *redis; */
    int enabled;
};

/* ---------------------------------------------------------------------- */
/* SQLite schema                                                             */
/* ---------------------------------------------------------------------- */

static const char *SCHEMA_SQL =
    "PRAGMA journal_mode = WAL;"
    "PRAGMA foreign_keys = ON;"

    "CREATE TABLE IF NOT EXISTS messages ("
    "  id           INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  from_pk      BLOB    NOT NULL,"
    "  to_pk        BLOB    NOT NULL,"
    "  body         BLOB    NOT NULL,"
    "  sent_at      INTEGER NOT NULL,"
    "  delivered_at INTEGER DEFAULT 0,"
    "  read_at      INTEGER DEFAULT 0,"
    "  destruct_at  INTEGER DEFAULT 0,"
    "  status       INTEGER DEFAULT 0,"
    "  is_secret    INTEGER DEFAULT 0"
    ");"

    "CREATE TABLE IF NOT EXISTS contacts ("
    "  pk           BLOB PRIMARY KEY,"
    "  display_name TEXT NOT NULL,"
    "  short_id     TEXT NOT NULL,"
    "  added_at     INTEGER NOT NULL,"
    "  last_seen    INTEGER DEFAULT 0,"
    "  blocked      INTEGER DEFAULT 0,"
    "  verified     INTEGER DEFAULT 0"
    ");"

    "CREATE TABLE IF NOT EXISTS queue ("
    "  id          INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  to_pk       BLOB    NOT NULL,"
    "  packet      BLOB    NOT NULL,"
    "  queued_at   INTEGER NOT NULL,"
    "  expires_at  INTEGER NOT NULL,"
    "  sequence    INTEGER NOT NULL"
    ");"

    "CREATE TABLE IF NOT EXISTS schema_version ("
    "  version INTEGER PRIMARY KEY"
    ");"
    "INSERT OR IGNORE INTO schema_version VALUES (1);";

/* ---------------------------------------------------------------------- */

koe_db_conn_t *koe_db_open(const koe_db_config_t *cfg)
{
    koe_db_conn_t *conn = calloc(1, sizeof(*conn));
    if (!conn) return NULL;
    conn->backend = cfg->backend;

    if (cfg->backend == KOE_DB_SQLITE) {
        if (sqlite3_open(cfg->sqlite_path, &conn->sqlite) != SQLITE_OK) {
            fprintf(stderr, "koe_db_open: sqlite3_open failed: %s\n",
                    sqlite3_errmsg(conn->sqlite));
            free(conn);
            return NULL;
        }

        /* Apply WAL mode and schema. */
        char *errmsg = NULL;
        if (sqlite3_exec(conn->sqlite, SCHEMA_SQL, NULL, NULL, &errmsg) != SQLITE_OK) {
            fprintf(stderr, "koe_db_open: schema error: %s\n", errmsg);
            sqlite3_free(errmsg);
            sqlite3_close(conn->sqlite);
            free(conn);
            return NULL;
        }

        return conn;
    }

    /* PostgreSQL and MySQL: not implemented in this file. */
    fprintf(stderr, "koe_db_open: backend %d not compiled in\n", cfg->backend);
    free(conn);
    return NULL;
}

void koe_db_close(koe_db_conn_t *conn)
{
    if (!conn) return;
    if (conn->sqlite) sqlite3_close(conn->sqlite);
    free(conn);
}

koe_cache_conn_t *koe_cache_open(const koe_cache_config_t *cfg)
{
    if (!cfg || !cfg->enabled) return NULL;

    koe_cache_conn_t *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->backend = cfg->backend;
    c->enabled = 0;   /* hiredis not linked in default build */

    /* TODO: initialise hiredis connection when KOE_CACHE_REDIS is built. */
    (void)cfg;
    return c;
}

void koe_cache_close(koe_cache_conn_t *conn)
{
    if (conn) free(conn);
}

/* ---------------------------------------------------------------------- */
/* Message operations                                                        */
/* ---------------------------------------------------------------------- */

int koe_db_message_insert(koe_db_conn_t *conn, koe_db_message_t *msg)
{
    if (!conn || !conn->sqlite) return -1;

    const char *sql =
        "INSERT INTO messages"
        " (from_pk,to_pk,body,sent_at,delivered_at,read_at,destruct_at,status,is_secret)"
        " VALUES (?,?,?,?,?,?,?,?,?)";

    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(conn->sqlite, sql, -1, &stmt, NULL) != SQLITE_OK)
        return -1;

    sqlite3_bind_blob(stmt, 1, msg->from_pk, 32, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, msg->to_pk,   32, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 3, msg->body_encrypted, (int)msg->body_len, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 4, msg->sent_at);
    sqlite3_bind_int64(stmt, 5, msg->delivered_at);
    sqlite3_bind_int64(stmt, 6, msg->read_at);
    sqlite3_bind_int64(stmt, 7, msg->destruct_at);
    sqlite3_bind_int(stmt,  8, msg->status);
    sqlite3_bind_int(stmt,  9, msg->is_secret);

    int rc = sqlite3_step(stmt);
    msg->id = sqlite3_last_insert_rowid(conn->sqlite);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? 0 : -1;
}

int koe_db_message_update_status(koe_db_conn_t *conn, int64_t id, uint8_t status)
{
    if (!conn || !conn->sqlite) return -1;
    const char *sql = "UPDATE messages SET status=? WHERE id=?";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(conn->sqlite, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_int(stmt, 1, status);
    sqlite3_bind_int64(stmt, 2, id);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? 0 : -1;
}

int koe_db_message_mark_delivered(koe_db_conn_t *conn, int64_t id, int64_t ts)
{
    if (!conn || !conn->sqlite) return -1;
    const char *sql = "UPDATE messages SET delivered_at=?,status=2 WHERE id=?";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(conn->sqlite, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_int64(stmt, 1, ts);
    sqlite3_bind_int64(stmt, 2, id);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? 0 : -1;
}

int koe_db_message_mark_read(koe_db_conn_t *conn, int64_t id, int64_t ts)
{
    if (!conn || !conn->sqlite) return -1;
    const char *sql = "UPDATE messages SET read_at=?,status=3 WHERE id=?";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(conn->sqlite, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_int64(stmt, 1, ts);
    sqlite3_bind_int64(stmt, 2, id);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? 0 : -1;
}

int koe_db_message_delete(koe_db_conn_t *conn, int64_t id)
{
    if (!conn || !conn->sqlite) return -1;
    const char *sql = "DELETE FROM messages WHERE id=?";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(conn->sqlite, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_int64(stmt, 1, id);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? 0 : -1;
}

int koe_db_destruct_sweep(koe_db_conn_t *conn, int64_t now_unix)
{
    if (!conn || !conn->sqlite) return -1;
    const char *sql = "DELETE FROM messages WHERE destruct_at > 0 AND destruct_at <= ?";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(conn->sqlite, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_int64(stmt, 1, now_unix);
    sqlite3_step(stmt);
    int deleted = sqlite3_changes(conn->sqlite);
    sqlite3_finalize(stmt);
    return deleted;
}

/* ---------------------------------------------------------------------- */
/* Contact operations                                                        */
/* ---------------------------------------------------------------------- */

int koe_db_contact_upsert(koe_db_conn_t *conn, const koe_db_contact_t *c)
{
    if (!conn || !conn->sqlite) return -1;
    const char *sql =
        "INSERT OR REPLACE INTO contacts"
        " (pk,display_name,short_id,added_at,last_seen,blocked,verified)"
        " VALUES (?,?,?,?,?,?,?)";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(conn->sqlite, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_blob(stmt, 1, c->pk, 32, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, c->display_name, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, c->short_id, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 4, c->added_at);
    sqlite3_bind_int64(stmt, 5, c->last_seen);
    sqlite3_bind_int(stmt, 6, c->blocked);
    sqlite3_bind_int(stmt, 7, c->verified);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? 0 : -1;
}

int koe_db_contact_delete(koe_db_conn_t *conn, const uint8_t pk[32])
{
    if (!conn || !conn->sqlite) return -1;
    const char *sql = "DELETE FROM contacts WHERE pk=?";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(conn->sqlite, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_blob(stmt, 1, pk, 32, SQLITE_STATIC);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? 0 : -1;
}

int koe_db_contact_find(koe_db_conn_t *conn, const uint8_t pk[32], koe_db_contact_t *out)
{
    if (!conn || !conn->sqlite) return -1;
    const char *sql = "SELECT pk,display_name,short_id,added_at,last_seen,blocked,verified"
                      " FROM contacts WHERE pk=? LIMIT 1";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(conn->sqlite, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_blob(stmt, 1, pk, 32, SQLITE_STATIC);
    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        memcpy(out->pk, sqlite3_column_blob(stmt, 0), 32);
        strncpy(out->display_name, (const char *)sqlite3_column_text(stmt, 1), 63);
        strncpy(out->short_id,     (const char *)sqlite3_column_text(stmt, 2), 15);
        out->added_at  = sqlite3_column_int64(stmt, 3);
        out->last_seen = sqlite3_column_int64(stmt, 4);
        out->blocked   = sqlite3_column_int(stmt, 5);
        out->verified  = sqlite3_column_int(stmt, 6);
        sqlite3_finalize(stmt);
        return 0;
    }
    sqlite3_finalize(stmt);
    return -1;
}

int koe_db_contact_set_blocked(koe_db_conn_t *conn, const uint8_t pk[32], int blocked)
{
    if (!conn || !conn->sqlite) return -1;
    const char *sql = "UPDATE contacts SET blocked=? WHERE pk=?";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(conn->sqlite, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_int(stmt, 1, blocked);
    sqlite3_bind_blob(stmt, 2, pk, 32, SQLITE_STATIC);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? 0 : -1;
}

int koe_db_contact_set_verified(koe_db_conn_t *conn, const uint8_t pk[32], int verified)
{
    if (!conn || !conn->sqlite) return -1;
    const char *sql = "UPDATE contacts SET verified=? WHERE pk=?";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(conn->sqlite, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_int(stmt, 1, verified);
    sqlite3_bind_blob(stmt, 2, pk, 32, SQLITE_STATIC);
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? 0 : -1;
}

/* ---------------------------------------------------------------------- */
/* Queue operations                                                          */
/* ---------------------------------------------------------------------- */

int koe_db_queue_push(koe_db_conn_t *conn, koe_db_queued_t *q)
{
    if (!conn || !conn->sqlite) return -1;
    const char *sql =
        "INSERT INTO queue (to_pk,packet,queued_at,expires_at,sequence)"
        " VALUES (?,?,?,?,?)";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(conn->sqlite, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_blob(stmt, 1, q->to_pk, 32, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, q->packet_bytes, (int)q->packet_len, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, q->queued_at);
    sqlite3_bind_int64(stmt, 4, q->expires_at);
    sqlite3_bind_int64(stmt, 5, q->sequence);
    int rc = sqlite3_step(stmt);
    q->id = sqlite3_last_insert_rowid(conn->sqlite);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? 0 : -1;
}

int koe_db_queue_pop(koe_db_conn_t *conn, const uint8_t to_pk[32], koe_db_queued_t *out)
{
    if (!conn || !conn->sqlite) return -1;
    const char *sql =
        "SELECT id,to_pk,packet,queued_at,expires_at,sequence"
        " FROM queue WHERE to_pk=? ORDER BY sequence ASC LIMIT 1";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(conn->sqlite, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_blob(stmt, 1, to_pk, 32, SQLITE_STATIC);

    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) { sqlite3_finalize(stmt); return -1; }

    out->id       = sqlite3_column_int64(stmt, 0);
    memcpy(out->to_pk, sqlite3_column_blob(stmt, 1), 32);
    out->packet_len   = (size_t)sqlite3_column_bytes(stmt, 2);
    out->packet_bytes = malloc(out->packet_len);
    if (out->packet_bytes)
        memcpy(out->packet_bytes, sqlite3_column_blob(stmt, 2), out->packet_len);
    out->queued_at  = sqlite3_column_int64(stmt, 3);
    out->expires_at = sqlite3_column_int64(stmt, 4);
    out->sequence   = sqlite3_column_int64(stmt, 5);
    sqlite3_finalize(stmt);

    /* Remove from queue. */
    const char *del = "DELETE FROM queue WHERE id=?";
    sqlite3_stmt *del_stmt;
    sqlite3_prepare_v2(conn->sqlite, del, -1, &del_stmt, NULL);
    sqlite3_bind_int64(del_stmt, 1, out->id);
    sqlite3_step(del_stmt);
    sqlite3_finalize(del_stmt);

    return out->packet_bytes ? 0 : -1;
}

int koe_db_queue_count(koe_db_conn_t *conn, const uint8_t to_pk[32])
{
    if (!conn || !conn->sqlite) return 0;
    const char *sql = "SELECT COUNT(*) FROM queue WHERE to_pk=?";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(conn->sqlite, sql, -1, &stmt, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_blob(stmt, 1, to_pk, 32, SQLITE_STATIC);
    int count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW) count = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return count;
}

int koe_db_queue_expire(koe_db_conn_t *conn, int64_t now_unix)
{
    if (!conn || !conn->sqlite) return 0;
    const char *sql = "DELETE FROM queue WHERE expires_at <= ?";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(conn->sqlite, sql, -1, &stmt, NULL) != SQLITE_OK) return 0;
    sqlite3_bind_int64(stmt, 1, now_unix);
    sqlite3_step(stmt);
    int deleted = sqlite3_changes(conn->sqlite);
    sqlite3_finalize(stmt);
    return deleted;
}

/* ---------------------------------------------------------------------- */
/* Cache stubs (hiredis not linked in default build)                        */
/* ---------------------------------------------------------------------- */

int koe_cache_group_set(koe_cache_conn_t *cache, const char *group_id,
                         const uint8_t *members, int count, int ttl_seconds)
{
    if (!cache || !cache->enabled) return 0;
    (void)group_id; (void)members; (void)count; (void)ttl_seconds;
    return 0;
}

int koe_cache_group_get(koe_cache_conn_t *cache, const char *group_id,
                         uint8_t *out, int max_members, int *out_count)
{
    if (!cache || !cache->enabled) return 1;  /* cache miss */
    (void)group_id; (void)out; (void)max_members;
    *out_count = 0;
    return 1;
}

int koe_cache_group_invalidate(koe_cache_conn_t *cache, const char *group_id)
{
    if (!cache || !cache->enabled) return 0;
    (void)group_id;
    return 0;
}

/* ---------------------------------------------------------------------- */
/* Migration                                                                 */
/* ---------------------------------------------------------------------- */

int koe_db_migrate(koe_db_conn_t *conn)
{
    if (!conn || !conn->sqlite) return -1;
    char *errmsg = NULL;
    int rc = sqlite3_exec(conn->sqlite, SCHEMA_SQL, NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "koe_db_migrate: %s\n", errmsg);
        sqlite3_free(errmsg);
        return -1;
    }
    return 0;
}
