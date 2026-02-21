/*
 * koe_account.c - Multi-identity account management.
 */

#include "koe_account.h"
#include "koe_crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sodium.h>

#define REGISTRY_MAGIC "KOEREG\x01"
#define REGISTRY_MAGIC_LEN 7

/* Registry file path. */
static void registry_path(const koe_account_registry_t *reg, char *out, size_t len)
{
    snprintf(out, len, "%s/accounts.koe", reg->data_root);
}

/* Account subdirectory path. */
static void account_dir(const koe_account_registry_t *reg, int idx, char *out, size_t len)
{
    snprintf(out, len, "%s/accounts/%s", reg->data_root,
             reg->accounts[idx].data_subdir);
}

static void mkdir_p(const char *path)
{
    char tmp[512];
    strncpy(tmp, path, sizeof(tmp) - 1);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0700);
            *p = '/';
        }
    }
    mkdir(tmp, 0700);
}

/* ---------------------------------------------------------------------- */

int koe_account_registry_load(koe_account_registry_t *reg,
                                const char             *data_root,
                                const char             *passphrase)
{
    memset(reg, 0, sizeof(*reg));
    strncpy(reg->data_root, data_root, sizeof(reg->data_root) - 1);

    char path[512];
    registry_path(reg, path, sizeof(path));

    FILE *f = fopen(path, "rb");
    if (!f) {
        /* Fresh install — empty registry is fine. */
        return 0;
    }

    /* Read magic. */
    uint8_t magic[REGISTRY_MAGIC_LEN];
    if (fread(magic, 1, sizeof(magic), f) != sizeof(magic) ||
        memcmp(magic, REGISTRY_MAGIC, REGISTRY_MAGIC_LEN) != 0) {
        fclose(f);
        return -1;
    }

    /* Read count. */
    int count = 0;
    if (fread(&count, sizeof(count), 1, f) != 1) { fclose(f); return -1; }
    if (count < 0 || count > KOE_ACCOUNT_MAX) { fclose(f); return -1; }

    /* Read descriptors (plaintext — no secret data in the registry). */
    for (int i = 0; i < count; i++) {
        if (fread(&reg->accounts[i], sizeof(koe_account_descriptor_t), 1, f) != 1) {
            fclose(f);
            return -1;
        }
        reg->accounts[i].active = 0;
    }
    reg->count = count;
    fclose(f);
    (void)passphrase;
    return 0;
}

int koe_account_registry_save(const koe_account_registry_t *reg,
                                const char                   *passphrase)
{
    char path[512];
    registry_path(reg, path, sizeof(path));

    /* Make sure the parent directory exists. */
    char dir[512];
    snprintf(dir, sizeof(dir), "%s", reg->data_root);
    mkdir_p(dir);

    FILE *f = fopen(path, "wb");
    if (!f) return -1;

    fwrite(REGISTRY_MAGIC, 1, REGISTRY_MAGIC_LEN, f);
    fwrite(&reg->count, sizeof(reg->count), 1, f);
    for (int i = 0; i < reg->count; i++)
        fwrite(&reg->accounts[i], sizeof(koe_account_descriptor_t), 1, f);

    fclose(f);
    (void)passphrase;
    return 0;
}

/* ---------------------------------------------------------------------- */

int koe_account_create(koe_account_t          *out,
                        koe_account_registry_t *reg,
                        const char             *display_name,
                        const char             *passphrase)
{
    if (reg->count >= KOE_ACCOUNT_MAX) return -1;

    /* Generate a fresh identity. */
    if (koe_identity_generate(&out->keys) != 0) return -1;

    /* Fill descriptor. */
    koe_account_descriptor_t *desc = &reg->accounts[reg->count];
    memset(desc, 0, sizeof(*desc));
    memcpy(desc->id, out->keys.pk, KOE_ED25519_PK_LEN);
    strncpy(desc->display_name, display_name, KOE_ACCOUNT_DISPLAY_NAME_MAX - 1);
    desc->created_at    = time(NULL);
    desc->last_active_at = time(NULL);
    desc->active        = 1;

    /* Use the short ID as the subdirectory name. */
    koe_short_id_t sid;
    koe_identity_short_id(&sid, out->keys.pk);
    strncpy(desc->data_subdir, sid.value, sizeof(desc->data_subdir) - 1);

    out->desc = *desc;
    strncpy(out->passphrase, passphrase, sizeof(out->passphrase) - 1);

    /* Create the account's data directory. */
    char acct_dir[512];
    snprintf(acct_dir, sizeof(acct_dir), "%s/accounts/%s", reg->data_root, desc->data_subdir);
    mkdir_p(acct_dir);

    /* Save the identity file. */
    char id_path[512];
    snprintf(id_path, sizeof(id_path), "%s/identity.koe", acct_dir);
    if (koe_identity_save(&out->keys, id_path, passphrase) != 0) return -1;

    reg->count++;
    koe_account_registry_save(reg, passphrase);
    return 0;
}

int koe_account_activate(koe_account_t                *out,
                          const koe_account_registry_t *reg,
                          int                           idx,
                          const char                   *passphrase)
{
    if (idx < 0 || idx >= reg->count) return -1;

    const koe_account_descriptor_t *desc = &reg->accounts[idx];

    char id_path[512];
    snprintf(id_path, sizeof(id_path), "%s/accounts/%s/identity.koe",
             reg->data_root, desc->data_subdir);

    if (koe_identity_load(&out->keys, id_path, passphrase) != 0) return -1;

    out->desc = *desc;
    out->desc.active = 1;
    strncpy(out->passphrase, passphrase, sizeof(out->passphrase) - 1);
    return 0;
}

void koe_account_deactivate(koe_account_t *account)
{
    koe_memzero(&account->keys, sizeof(account->keys));
    koe_memzero(account->passphrase, sizeof(account->passphrase));
    account->desc.active = 0;
}

int koe_account_delete(koe_account_registry_t *reg, int idx)
{
    if (idx < 0 || idx >= reg->count) return -1;
    if (reg->accounts[idx].active) return -1;  /* cannot delete active account */

    /* Shift remaining entries. */
    for (int i = idx; i < reg->count - 1; i++)
        reg->accounts[i] = reg->accounts[i + 1];
    reg->count--;

    /* TODO: wipe files in the account's data_subdir. */
    return koe_account_registry_save(reg, "");
}

int koe_account_rename(koe_account_registry_t *reg, int idx, const char *new_name)
{
    if (idx < 0 || idx >= reg->count) return -1;
    strncpy(reg->accounts[idx].display_name, new_name, KOE_ACCOUNT_DISPLAY_NAME_MAX - 1);
    return koe_account_registry_save(reg, "");
}

int koe_account_change_passphrase(koe_account_t *account,
                                    const char    *old_passphrase,
                                    const char    *new_passphrase)
{
    if (!account->desc.active) return -1;

    /* Verify old passphrase by trying to load. */
    koe_identity_t check;
    char id_path[512];
    snprintf(id_path, sizeof(id_path), "%s/identity.koe", account->desc.data_subdir);
    if (koe_identity_load(&check, id_path, old_passphrase) != 0) return -1;
    koe_memzero(&check, sizeof(check));

    /* Re-save with new passphrase. */
    if (koe_identity_save(&account->keys, id_path, new_passphrase) != 0) return -1;
    strncpy(account->passphrase, new_passphrase, sizeof(account->passphrase) - 1);
    return 0;
}
