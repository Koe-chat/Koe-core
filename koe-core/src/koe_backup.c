/*
 * koe_backup.c - Local and server-side backup, device migration.
 *
 * The backup format is straightforward: a fixed plaintext header carries the
 * Argon2id salt and the XChaCha20-Poly1305 nonce; the rest of the file is an
 * opaque encrypted blob containing a tar-like directory archive.
 *
 * The archive is built in memory (limited to KOE_BACKUP_MAX_MEM bytes) before
 * encryption. If the data directory is larger than this limit the export
 * fails. For typical Koe installations (text messages, no large media) this
 * limit is not hit in practice.
 *
 * Device migration uses the same encrypted archive format but streams it
 * over a short-lived TCP connection on the local network instead of writing
 * to disk.
 */

#include "koe_backup.h"
#include "koe_crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <poll.h>
#include <sodium.h>

#define KOE_BACKUP_MAX_MEM   (64 * 1024 * 1024)  /* 64 MB in-memory cap */
#define KOE_MIGRATE_PORT     9475

/* ---------------------------------------------------------------------- */
/* Simple in-memory archive (file_name[256] + uint64 size + data) */

typedef struct {
    uint8_t *data;
    size_t   len;
    size_t   cap;
} koe_membuf_t;

static int membuf_init(koe_membuf_t *b, size_t cap)
{
    b->data = malloc(cap);
    b->len  = 0;
    b->cap  = cap;
    return b->data ? 0 : -1;
}

static int membuf_append(koe_membuf_t *b, const void *src, size_t n)
{
    if (b->len + n > b->cap) return -1;
    memcpy(b->data + b->len, src, n);
    b->len += n;
    return 0;
}

static void membuf_free(koe_membuf_t *b)
{
    if (b->data) {
        sodium_memzero(b->data, b->len);
        free(b->data);
        b->data = NULL;
    }
    b->len = b->cap = 0;
}

/* ---------------------------------------------------------------------- */

static int archive_file(koe_membuf_t *buf, const char *path, const char *name)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (sz < 0) { fclose(f); return -1; }

    /* Write entry header: name (256 bytes, zero-padded) + size (8 bytes BE). */
    uint8_t entry_hdr[264];
    memset(entry_hdr, 0, sizeof(entry_hdr));
    strncpy((char *)entry_hdr, name, 255);
    uint64_t sz_be = htobe64((uint64_t)sz);
    memcpy(entry_hdr + 256, &sz_be, 8);

    if (membuf_append(buf, entry_hdr, sizeof(entry_hdr)) != 0) {
        fclose(f);
        return -1;
    }

    uint8_t fbuf[4096];
    size_t  remaining = (size_t)sz;
    while (remaining > 0) {
        size_t chunk = remaining < sizeof(fbuf) ? remaining : sizeof(fbuf);
        if (fread(fbuf, 1, chunk, f) != chunk) { fclose(f); return -1; }
        if (membuf_append(buf, fbuf, chunk) != 0) { fclose(f); return -1; }
        remaining -= chunk;
    }

    fclose(f);
    return 0;
}

static int archive_dir(koe_membuf_t *buf, const char *dir_path)
{
    DIR           *d = opendir(dir_path);
    struct dirent *ent;
    char           full[512];

    if (!d) return -1;

    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;

        snprintf(full, sizeof(full), "%s/%s", dir_path, ent->d_name);

        struct stat st;
        if (stat(full, &st) != 0) continue;

        if (S_ISREG(st.st_mode)) {
            if (archive_file(buf, full, ent->d_name) != 0) {
                closedir(d);
                return -1;
            }
        }
        /* Subdirectories are not recursed; Koe's data dir is flat. */
    }

    closedir(d);
    return 0;
}

/* ---------------------------------------------------------------------- */

int koe_backup_export(const char *out_path,
                       const char *passphrase,
                       const char *data_dir)
{
    koe_membuf_t plain = {0};
    if (membuf_init(&plain, KOE_BACKUP_MAX_MEM) != 0) return -1;

    if (archive_dir(&plain, data_dir) != 0) {
        membuf_free(&plain);
        return -1;
    }

    /* Derive encryption key from passphrase. */
    uint8_t salt[32];
    randombytes_buf(salt, sizeof(salt));

    uint8_t enc_key[KOE_SESSION_KEY_LEN];
    if (crypto_pwhash(enc_key, sizeof(enc_key),
                       passphrase, strlen(passphrase),
                       salt,
                       crypto_pwhash_OPSLIMIT_INTERACTIVE,
                       crypto_pwhash_MEMLIMIT_INTERACTIVE,
                       crypto_pwhash_ALG_ARGON2ID13) != 0) {
        membuf_free(&plain);
        return -1;
    }

    size_t   ct_len = plain.len + KOE_TAG_LEN;
    uint8_t *ct     = malloc(ct_len);
    if (!ct) { membuf_free(&plain); return -1; }

    uint8_t nonce[KOE_NONCE_LEN];
    koe_nonce_generate(nonce);

    if (koe_encrypt(ct, plain.data, plain.len, nonce, enc_key) != 0) {
        sodium_memzero(enc_key, sizeof(enc_key));
        membuf_free(&plain);
        free(ct);
        return -1;
    }

    sodium_memzero(enc_key, sizeof(enc_key));
    membuf_free(&plain);

    /* Write header + ciphertext. */
    FILE *f = fopen(out_path, "wb");
    if (!f) { free(ct); return -1; }

    koe_backup_header_t hdr = {0};
    memcpy(hdr.magic, KOE_BACKUP_MAGIC, KOE_BACKUP_MAGIC_LEN);
    hdr.version     = 1;
    hdr.created_at  = (uint64_t)time(NULL);
    memcpy(hdr.salt,  salt,  sizeof(salt));
    memcpy(hdr.nonce, nonce, KOE_NONCE_LEN);
    hdr.payload_len = (uint64_t)ct_len;

    fwrite(&hdr, sizeof(hdr), 1, f);
    fwrite(ct, 1, ct_len, f);
    fclose(f);
    free(ct);
    return 0;
}

int koe_backup_import(const char *in_path,
                       const char *passphrase,
                       const char *data_dir)
{
    FILE *f = fopen(in_path, "rb");
    if (!f) return -1;

    koe_backup_header_t hdr;
    if (fread(&hdr, sizeof(hdr), 1, f) != 1) { fclose(f); return -1; }

    if (memcmp(hdr.magic, KOE_BACKUP_MAGIC, KOE_BACKUP_MAGIC_LEN) != 0) {
        fclose(f);
        return -1;
    }

    uint8_t *ct = malloc((size_t)hdr.payload_len);
    if (!ct) { fclose(f); return -1; }
    if (fread(ct, 1, (size_t)hdr.payload_len, f) != hdr.payload_len) {
        free(ct);
        fclose(f);
        return -1;
    }
    fclose(f);

    uint8_t enc_key[KOE_SESSION_KEY_LEN];
    if (crypto_pwhash(enc_key, sizeof(enc_key),
                       passphrase, strlen(passphrase),
                       hdr.salt,
                       crypto_pwhash_OPSLIMIT_INTERACTIVE,
                       crypto_pwhash_MEMLIMIT_INTERACTIVE,
                       crypto_pwhash_ALG_ARGON2ID13) != 0) {
        free(ct);
        return -1;
    }

    size_t   plain_len = (size_t)hdr.payload_len - KOE_TAG_LEN;
    uint8_t *plain     = malloc(plain_len);
    if (!plain) { sodium_memzero(enc_key, sizeof(enc_key)); free(ct); return -1; }

    int rc = koe_decrypt(plain, ct, (size_t)hdr.payload_len, hdr.nonce, enc_key);
    sodium_memzero(enc_key, sizeof(enc_key));
    free(ct);

    if (rc != 0) { free(plain); return -1; }

    /* Extract archive entries back to data_dir. */
    size_t   off = 0;
    char     out_path[512];
    while (off + 264 <= plain_len) {
        char     name[256];
        uint64_t entry_sz_be;
        memcpy(name,         plain + off,       256);
        memcpy(&entry_sz_be, plain + off + 256,   8);
        off += 264;

        name[255] = '\0';
        uint64_t entry_sz = be64toh(entry_sz_be);

        if (off + entry_sz > plain_len) break;

        snprintf(out_path, sizeof(out_path), "%s/%s", data_dir, name);
        FILE *out = fopen(out_path, "wb");
        if (out) {
            fwrite(plain + off, 1, (size_t)entry_sz, out);
            fclose(out);
        }
        off += (size_t)entry_sz;
    }

    sodium_memzero(plain, plain_len);
    free(plain);
    return 0;
}

/* ---------------------------------------------------------------------- */
/* Server backup: stub — real implementation requires the relay protocol. */

int koe_backup_upload(const char           *relay_host,
                       uint16_t              relay_port,
                       const koe_identity_t *local_id,
                       const char           *data_dir)
{
    /* Export to a temporary file, then stream it to the relay. */
    char tmp[256];
    snprintf(tmp, sizeof(tmp), "/tmp/koe-backup-%llu.koebak",
             (unsigned long long)time(NULL));

    if (koe_backup_export(tmp, (const char *)local_id->pk, data_dir) != 0)
        return -1;

    /* TODO: relay upload protocol (authenticate, send, confirm). */
    (void)relay_host;
    (void)relay_port;

    unlink(tmp);
    return 0;
}

int koe_backup_download(const char           *relay_host,
                          uint16_t              relay_port,
                          const koe_identity_t *local_id,
                          const char           *out_dir,
                          int                   version)
{
    /* TODO: relay download protocol. */
    (void)relay_host;
    (void)relay_port;
    (void)local_id;
    (void)out_dir;
    (void)version;
    return -1;
}

/* ---------------------------------------------------------------------- */
/* Device migration — P2P local transfer. */

int koe_migrate_send(const char           *data_dir,
                      const koe_identity_t *local_id)
{
    char tmp[256];
    snprintf(tmp, sizeof(tmp), "/tmp/koe-migrate-%llu.koebak",
             (unsigned long long)time(NULL));

    if (koe_backup_export(tmp, (const char *)local_id->pk, data_dir) != 0)
        return -1;

    /* Open a listening TCP socket on the migration port. */
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv == -1) { unlink(tmp); return -1; }

    int reuse = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in addr = {0};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(KOE_MIGRATE_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        listen(srv, 1) != 0) {
        close(srv);
        unlink(tmp);
        return -1;
    }

    /* Wait for the target device to connect within the TTL window. */
    struct pollfd pfd = { .fd = srv, .events = POLLIN };
    if (poll(&pfd, 1, KOE_MIGRATE_TTL_SECONDS * 1000) <= 0) {
        close(srv);
        unlink(tmp);
        return -2;   /* timed out */
    }

    int cli = accept(srv, NULL, NULL);
    close(srv);

    if (cli == -1) { unlink(tmp); return -1; }

    /* Stream the backup file. */
    FILE *f = fopen(tmp, "rb");
    if (!f) { close(cli); unlink(tmp); return -1; }

    uint8_t buf[4096];
    size_t  n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        if (send(cli, buf, n, 0) == -1) break;
    }

    fclose(f);
    close(cli);
    unlink(tmp);
    return 0;
}

int koe_migrate_receive(const char           *source_addr,
                          uint64_t              token,
                          const char           *out_dir)
{
    /* Connect to the source device's migration socket. */
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", KOE_MIGRATE_PORT);

    struct addrinfo hints = {0};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res = NULL;
    if (getaddrinfo(source_addr, port_str, &hints, &res) != 0) return -1;

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        freeaddrinfo(res);
        close(fd);
        return -1;
    }
    freeaddrinfo(res);

    /* Receive into a temporary file. */
    char tmp[256];
    snprintf(tmp, sizeof(tmp), "/tmp/koe-recv-%llu.koebak",
             (unsigned long long)time(NULL));

    FILE *f = fopen(tmp, "wb");
    if (!f) { close(fd); return -1; }

    uint8_t buf[4096];
    ssize_t n;
    while ((n = recv(fd, buf, sizeof(buf), 0)) > 0)
        fwrite(buf, 1, (size_t)n, f);
    fclose(f);
    close(fd);

    /* Use the token as the passphrase key material — it was displayed on
     * both screens for out-of-band verification. */
    char passphrase[32];
    snprintf(passphrase, sizeof(passphrase), "%llu", (unsigned long long)token);

    int rc = koe_backup_import(tmp, passphrase, out_dir);
    unlink(tmp);
    return rc;
}
