/*
 * koe_backup.h - Backup and device migration.
 *
 * Local backup: exports a single self-contained .koebak file. The file
 * header is stored in plaintext so that decryption parameters can be read
 * without a passphrase; the payload is encrypted with XChaCha20-Poly1305
 * using a key derived from the user's passphrase via Argon2id.
 *
 * Server backup: encrypts the backup locally, then uploads opaque ciphertext
 * to the relay server. The server stores blobs; it has no access to content.
 * Up to KOE_BACKUP_MAX_VERSIONS are retained; older versions are pruned.
 * Authentication to the server uses an Ed25519 signature over a challenge.
 *
 * Device migration: the source device generates a .koebak bundle in memory
 * and streams it directly to the target device over WiFi Direct or Bluetooth.
 * A 64-bit one-time token is displayed on both screens before transfer begins;
 * both sides verify it before any data moves. The transfer window is
 * KOE_MIGRATE_TTL_SECONDS. After expiry the source aborts and any partial
 * data on the target is discarded.
 *
 * What is included in a backup:
 *   - Ed25519 identity keypair
 *   - Display name and settings
 *   - Contact book
 *   - Full conversation history (excluding ephemeral messages)
 *   - Pending offline queue entries
 *
 * What is excluded:
 *   - Active session keys (ephemeral by design)
 *   - Self-destruct messages past their TTL
 */

#ifndef KOE_BACKUP_H
#define KOE_BACKUP_H

#include "koe_crypto.h"
#include "koe_identity.h"
#include <stdint.h>
#include <stddef.h>

#define KOE_BACKUP_MAX_VERSIONS  5
#define KOE_MIGRATE_TTL_SECONDS  300       /* 5 minute transfer window */
#define KOE_BACKUP_EXT           ".koebak"

#define KOE_BACKUP_MAGIC         "KOEBAK\x02"
#define KOE_BACKUP_MAGIC_LEN     7
#define KOE_BACKUP_FORMAT_VER    1

/* Plaintext file header — always at offset 0 in a .koebak file */
typedef struct {
    uint8_t  magic[KOE_BACKUP_MAGIC_LEN];
    uint8_t  format_version;
    uint64_t created_at;             /* Unix timestamp */
    uint8_t  salt[32];               /* Argon2id salt */
    uint8_t  nonce[KOE_NONCE_LEN];
    uint64_t payload_len;            /* bytes of encrypted payload that follow */
    uint32_t header_checksum;        /* CRC32 of this struct, excluding this field */
} koe_backup_header_t;

/* --- Local backup ------------------------------------------------------- */

/* Export the data at `data_dir` to a .koebak file at `out_path`.
 * The secret key is encrypted with a key derived from `passphrase`.
 * Returns 0 on success, -1 on error. */
int koe_backup_export(const char *out_path,
                       const char *passphrase,
                       const char *data_dir);

/* Restore a .koebak file into `data_dir`. Overwrites existing data without
 * prompting — callers are expected to have confirmed with the user already. */
int koe_backup_import(const char *in_path,
                       const char *passphrase,
                       const char *data_dir);

/* Validate a .koebak file's header and checksum without decrypting it.
 * Returns 0 if the file looks intact, -1 on error or corruption. */
int koe_backup_validate(const char *path);

/* --- Server backup ------------------------------------------------------ */

/* Encrypt `data_dir` locally and upload to the relay server.
 * Authenticates with an Ed25519 challenge-response. */
int koe_backup_upload(const char           *relay_host,
                       uint16_t              relay_port,
                       const koe_identity_t *local_id,
                       const char           *data_dir);

/* Download and decrypt a backup from the relay server.
 * `version` 0 means the latest; 1..KOE_BACKUP_MAX_VERSIONS selects older ones.
 * Restores into `out_dir`. */
int koe_backup_download(const char           *relay_host,
                          uint16_t              relay_port,
                          const koe_identity_t *local_id,
                          const char           *out_dir,
                          int                   version);

/* List available server-side backup versions. Fills `versions` with up to
 * `max` Unix timestamps (newest first). Returns the number of versions found,
 * or -1 on error. */
int koe_backup_list_versions(const char           *relay_host,
                               uint16_t              relay_port,
                               const koe_identity_t *local_id,
                               uint64_t             *versions,
                               int                   max);

/* --- Device migration --------------------------------------------------- */

/* Stream this device's data to a new device over a local transport.
 *
 * Waits for an incoming connection from the target for up to
 * KOE_MIGRATE_TTL_SECONDS. Generates and prints a one-time 64-bit token
 * to stdout (the TUI layer is responsible for displaying it prominently).
 *
 * Returns 0 on success, -1 on error, -2 on timeout. */
int koe_migrate_send(const char           *data_dir,
                      const koe_identity_t *local_id);

/* Accept a migration stream from the source device.
 *
 * `source_addr` is the IP or Bluetooth MAC of the source device.
 * `token` must match what was displayed on the source device.
 * Data is written into `out_dir`.
 *
 * Returns 0 on success, -1 on error, -3 on token mismatch. */
int koe_migrate_receive(const char *source_addr,
                          uint64_t    token,
                          const char *out_dir);

#endif /* KOE_BACKUP_H */
