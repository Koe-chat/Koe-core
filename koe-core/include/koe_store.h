/*
 * koe_store.h - Encrypted conversation history store.
 *
 * Messages are appended to a per-conversation log file. Each entry is a
 * serialised koe_message_t encrypted with the local identity key. The file
 * format is a sequence of length-prefixed encrypted blobs; no index is
 * maintained in the file itself. An in-memory index is built at open time
 * by scanning the file once.
 *
 * Design constraints:
 *   - The store is append-only. Deletion of a specific message (e.g. for
 *     self-destruct) rewrites the entire conversation file, which is
 *     acceptable given typical conversation sizes on mobile devices.
 *   - The store is not a database. No SQL, no external format. This keeps
 *     the parser attack surface minimal and the binary self-contained.
 *   - Ephemeral messages are never written to the store.
 */

#ifndef KOE_STORE_H
#define KOE_STORE_H

#include "koe_crypto.h"
#include "koe_message.h"
#include <stdint.h>
#include <stddef.h>

#define KOE_STORE_MAGIC      "KOESTORE\x01"
#define KOE_STORE_MAGIC_LEN  9

typedef struct {
    char    path[512];
    int     fd;
    /* In-memory message index: array of (offset, length) pairs. */
    uint64_t *offsets;
    uint32_t *lengths;
    size_t    count;
    size_t    capacity;
    const koe_identity_t *local_id;   /* not owned; borrowed from caller */
} koe_store_t;

/* --- Lifecycle ---------------------------------------------------------- */

/* Open (or create) a conversation store at `path`.
 * Scans the file to build the in-memory index. Returns 0 on success. */
int koe_store_open(koe_store_t          *store,
                    const char           *path,
                    const koe_identity_t *local_id);

/* Flush pending writes and free the in-memory index. */
void koe_store_close(koe_store_t *store);

/* --- Reading ------------------------------------------------------------ */

/* Read the message at position `index` (0-based, oldest first).
 * The returned koe_message_t is heap-allocated; call koe_message_free when done.
 * Returns NULL on error or if index is out of range. */
koe_message_t *koe_store_get(koe_store_t *store, size_t index);

/* Read the `count` most recent messages, newest first.
 * Fills `msgs`; caller must free each entry with koe_message_free.
 * Returns the number of messages actually read. */
size_t koe_store_get_recent(koe_store_t    *store,
                              koe_message_t **msgs,
                              size_t          count);

/* Return the total number of messages in this conversation. */
size_t koe_store_count(const koe_store_t *store);

/* --- Writing ------------------------------------------------------------ */

/* Append a message to the store. Ephemeral messages are silently ignored.
 * Returns 0 on success, -1 on error. */
int koe_store_append(koe_store_t         *store,
                      const koe_message_t *msg);

/* --- Deletion ----------------------------------------------------------- */

/* Remove a specific message by its ID. Rewrites the conversation file.
 * Returns 0 on success, -1 if the ID was not found. */
int koe_store_delete(koe_store_t *store, uint64_t message_id);

/* Remove all messages with a set destruct_at that is in the past.
 * Returns the number of messages removed. */
int koe_store_purge_expired(koe_store_t *store);

/* Delete the entire conversation. Overwrites the file with zeroes before
 * unlinking it so the content does not persist in unallocated disk space. */
int koe_store_wipe(koe_store_t *store);

#endif /* KOE_STORE_H */
