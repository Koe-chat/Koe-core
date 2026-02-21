/*
 * koe_backup.c - Encrypted local .koebak backup and device migration.
 */

#include "koe_backup.h"
#include "koe_crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sodium.h>

/* ---------------------------------------------------------------------- */
/* Internal: archive a directory tree into a flat byte buffer               */
/* ---------------------------------------------------------------------- */

typedef struct {
    uint8_t *data;
    size_t   len;
    size_t   cap;
} koe_archive_t;

static int archive_append(koe_archive_t *a, const uint8_t *bytes, size_t n)
{
    if (a->len + n > a->cap) {
        size_t new_cap = (a->cap + n) * 2;
        uint8_t *nb = realloc(a->data, new_cap);
        if (!nb) return -1;
        a->data = nb;
        a->cap  = new_cap;
    }
    memcpy(a->data + a->len, bytes, n);
    a->len += n;
    return 0;
}

/* Append a file as: path_len(2) + path + data_len(4) + data. */
static int archive_file(koe_archive_t *a, const char *rel_path, const char *abs_path)
{
    FILE *f = fopen(abs_path, "rb");
    if (!f) return 0; /* skip unreadable files */

    fseek(f, 0, SEEK_END);
    long fsz = ftell(f);
    rewind(f);
    if (fsz < 0 || fsz > (long)(64 * 1024 * 1024)) { fclose(f); return 0; }

    uint8_t *file_data = malloc((size_t)fsz);
    if (!file_data) { fclose(f); return -1; }
    if (fread(file_data, 1, (size_t)fsz, f) != (size_t)fsz) {
        free(file_data); fclose(f); return -1;
    }
    fclose(f);

    uint16_t path_len = (uint16_t)strlen(rel_path);
    uint32_t data_len = (uint32_t)fsz;

    archive_append(a, (uint8_t *)&path_len, 2);
    archive_append(a, (const uint8_t *)rel_path, path_len);
    archive_append(a, (uint8_t *)&data_len, 4);
    archive_append(a, file_data, data_len);
    free(file_data);
    return 0;
}

static int archive_dir(koe_archive_t *a, const char *base, const char *rel)
{
    char abs[512];
    snprintf(abs, sizeof(abs), "%s/%s", base, rel);

    DIR *d = opendir(abs);
    if (!d) return 0;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;
        char child_rel[512], child_abs[512];
        snprintf(child_rel, sizeof(child_rel), "%s/%s", rel, ent->d_name);
        snprintf(child_abs, sizeof(child_abs), "%s/%s", abs, ent->d_name);

        struct stat st;
        if (stat(child_abs, &st) != 0) continue;
        if (S_ISDIR(st.st_mode))  archive_dir(a, base, child_rel);
        else if (S_ISREG(st.st_mode)) archive_file(a, child_rel, child_abs);
    }
    closedir(d);
    return 0;
}

/* ---------------------------------------------------------------------- */
/* Export                                                                   */
/* ---------------------------------------------------------------------- */

int koe_backup_export(const char *out_path, const char *passphrase, const char *data_dir)
{
    /* Build plain archive. */
    koe_archive_t arc = { malloc(65536), 0, 65536 };
    if (!arc.data) return -1;
    archive_dir(&arc, data_dir, "");

    /* Derive encryption key. */
    uint8_t salt[crypto_pwhash_SALTBYTES];
    randombytes_buf(salt, sizeof(salt));

    uint8_t key[KOE_SESSION_KEY_LEN];
    if (crypto_pwhash(key, sizeof(key), passphrase, strlen(passphrase),
                       salt, crypto_pwhash_OPSLIMIT_INTERACTIVE,
                       crypto_pwhash_MEMLIMIT_INTERACTIVE,
                       crypto_pwhash_ALG_ARGON2ID13) != 0) {
        free(arc.data); return -1;
    }

    uint8_t nonce[KOE_NONCE_LEN];
    koe_nonce_generate(nonce);

    uint8_t *ct = malloc(arc.len + KOE_TAG_LEN);
    if (!ct) { free(arc.data); koe_memzero(key, sizeof(key)); return -1; }

    if (koe_encrypt(ct, arc.data, arc.len, nonce, key) != 0) {
        free(arc.data); free(ct); koe_memzero(key, sizeof(key)); return -1;
    }
    free(arc.data);
    koe_memzero(key, sizeof(key));

    /* Write file. */
    FILE *f = fopen(out_path, "wb");
    if (!f) { free(ct); return -1; }

    koe_backup_header_t hdr;
    memcpy(hdr.magic, KOE_BACKUP_MAGIC, KOE_BACKUP_MAGIC_LEN);
    hdr.version     = KOE_BACKUP_VERSION;
    hdr.created_at  = (uint64_t)time(NULL);
    memcpy(hdr.salt,  salt,  sizeof(salt));
    memcpy(hdr.nonce, nonce, sizeof(nonce));
    hdr.payload_len = arc.len + KOE_TAG_LEN;

    fwrite(&hdr, sizeof(hdr), 1, f);
    fwrite(ct, 1, hdr.payload_len, f);
    fclose(f);
    free(ct);
    return 0;
}

/* ---------------------------------------------------------------------- */
/* Import                                                                   */
/* ---------------------------------------------------------------------- */

int koe_backup_import(const char *in_path, const char *passphrase, const char *data_dir)
{
    FILE *f = fopen(in_path, "rb");
    if (!f) return -1;

    koe_backup_header_t hdr;
    if (fread(&hdr, sizeof(hdr), 1, f) != 1 ||
        memcmp(hdr.magic, KOE_BACKUP_MAGIC, KOE_BACKUP_MAGIC_LEN) != 0) {
        fclose(f); return -1;
    }

    uint8_t *ct = malloc(hdr.payload_len);
    if (!ct || fread(ct, 1, hdr.payload_len, f) != hdr.payload_len) {
        free(ct); fclose(f); return -1;
    }
    fclose(f);

    uint8_t key[KOE_SESSION_KEY_LEN];
    if (crypto_pwhash(key, sizeof(key), passphrase, strlen(passphrase),
                       hdr.salt, crypto_pwhash_OPSLIMIT_INTERACTIVE,
                       crypto_pwhash_MEMLIMIT_INTERACTIVE,
                       crypto_pwhash_ALG_ARGON2ID13) != 0) {
        free(ct); return -1;
    }

    size_t   plain_len = hdr.payload_len - KOE_TAG_LEN;
    uint8_t *plain     = malloc(plain_len);
    if (!plain) { free(ct); koe_memzero(key, sizeof(key)); return -1; }

    if (koe_decrypt(plain, ct, hdr.payload_len, hdr.nonce, key) != 0) {
        free(ct); free(plain); koe_memzero(key, sizeof(key)); return -1;
    }
    free(ct);
    koe_memzero(key, sizeof(key));

    /* Extract files from the archive. */
    size_t offset = 0;
    while (offset + 6 < plain_len) {
        uint16_t path_len;
        memcpy(&path_len, plain + offset, 2); offset += 2;
        if (offset + path_len > plain_len) break;

        char rel_path[512] = {0};
        memcpy(rel_path, plain + offset, path_len < 511 ? path_len : 511);
        offset += path_len;

        uint32_t data_len;
        memcpy(&data_len, plain + offset, 4); offset += 4;
        if (offset + data_len > plain_len) break;

        /* Build absolute path. */
        char abs_path[512];
        snprintf(abs_path, sizeof(abs_path), "%s/%s", data_dir, rel_path);

        /* Create parent directories. */
        char dir_path[512];
        strncpy(dir_path, abs_path, sizeof(dir_path) - 1);
        char *slash = strrchr(dir_path, '/');
        if (slash) {
            *slash = '\0';
            mkdir(dir_path, 0700);
        }

        FILE *out = fopen(abs_path, "wb");
        if (out) {
            fwrite(plain + offset, 1, data_len, out);
            fclose(out);
        }
        offset += data_len;
    }

    koe_memzero(plain, plain_len);
    free(plain);
    return 0;
}

/* Stubs for server upload/download and migration. */
int koe_backup_upload(const char *relay_host, uint16_t port,
                       const koe_identity_t *id, const char *data_dir)
{ (void)relay_host; (void)port; (void)id; (void)data_dir; return -1; }

int koe_backup_download(const char *relay_host, uint16_t port,
                          const koe_identity_t *id, const char *out_dir, int version)
{ (void)relay_host; (void)port; (void)id; (void)out_dir; (void)version; return -1; }

int koe_migrate_send(const char *data_dir, const koe_identity_t *id)
{ (void)data_dir; (void)id; return -1; }

int koe_migrate_receive(const char *source_addr, uint64_t token, const char *out_dir)
{ (void)source_addr; (void)token; (void)out_dir; return -1; }
