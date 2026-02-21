/*
 * koe_backup.h - Local .koebak backup and device migration.
 */
#ifndef KOE_BACKUP_H
#define KOE_BACKUP_H

#include "koe_crypto.h"
#include <stdint.h>

#define KOE_BACKUP_MAGIC     "KOEBAK"
#define KOE_BACKUP_MAGIC_LEN 6
#define KOE_BACKUP_VERSION   1
#define KOE_MIGRATE_TTL_SECONDS 300

typedef struct {
    char     magic[KOE_BACKUP_MAGIC_LEN];
    uint8_t  version;
    uint64_t created_at;
    uint8_t  salt[32];
    uint8_t  nonce[KOE_NONCE_LEN];
    uint64_t payload_len;
} koe_backup_header_t;

int koe_backup_export(const char *out_path, const char *passphrase, const char *data_dir);
int koe_backup_import(const char *in_path, const char *passphrase, const char *data_dir);
int koe_backup_upload(const char *relay_host, uint16_t port,
                       const koe_identity_t *id, const char *data_dir);
int koe_backup_download(const char *relay_host, uint16_t port,
                          const koe_identity_t *id, const char *out_dir, int version);
int koe_migrate_send(const char *data_dir, const koe_identity_t *id);
int koe_migrate_receive(const char *source_addr, uint64_t token, const char *out_dir);

#endif /* KOE_BACKUP_H */
