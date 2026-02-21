/*
 * koe_account.h - Multi-identity account management.
 *
 * koe-core supports multiple identities on the same device, but only one can
 * be active at a time.  Switching identities is an explicit rotation — the old
 * session keys are zeroed, the contact book is swapped, and the event loop is
 * restarted cleanly.
 *
 * Each account is stored in its own subdirectory under the data root:
 *
 *   <data_dir>/accounts/<account_id>/
 *     identity.koe          Ed25519 keypair (Argon2id encrypted)
 *     contacts.koe          contact book (encrypted)
 *     history.db            SQLite message store
 *     queue/                per-peer offline queues
 *
 * The account registry lives at <data_dir>/accounts.koe and lists all
 * known accounts by their short ID and display name.
 *
 * Rotation procedure:
 *   1. koe_account_deactivate() — flush state, zero session keys.
 *   2. koe_account_activate()   — load the new identity and rebuild sessions.
 *
 * The active account pointer is stored in koe_ctx_t.  Only one
 * koe_account_t is ever in a decrypted state at a time.
 */

#ifndef KOE_ACCOUNT_H
#define KOE_ACCOUNT_H

#include "koe_crypto.h"
#include <stdint.h>
#include <time.h>

#define KOE_ACCOUNT_DISPLAY_NAME_MAX  64
#define KOE_ACCOUNT_MAX               16   /* max accounts per device */

/* ---------------------------------------------------------------------- */
/* Account descriptor                                                        */
/* ---------------------------------------------------------------------- */

typedef struct {
    uint8_t  id[KOE_ED25519_PK_LEN];              /* public key = account ID */
    char     display_name[KOE_ACCOUNT_DISPLAY_NAME_MAX];
    char     data_subdir[256];                      /* relative to data root   */
    time_t   created_at;
    time_t   last_active_at;
    int      active;                                /* 1 if currently loaded   */
} koe_account_descriptor_t;

/* A fully loaded account — only one of these is ever decrypted. */
typedef struct {
    koe_account_descriptor_t desc;
    koe_identity_t           keys;    /* decrypted Ed25519 keypair   */
    char                     passphrase[256]; /* kept for re-saves, zeroed on deactivate */
} koe_account_t;

/* Registry of all accounts on the device. */
typedef struct {
    koe_account_descriptor_t accounts[KOE_ACCOUNT_MAX];
    int                       count;
    char                      data_root[512];
} koe_account_registry_t;

/* ---------------------------------------------------------------------- */
/* Registry management                                                       */
/* ---------------------------------------------------------------------- */

/*
 * koe_account_registry_load - Read the accounts.koe registry file.
 *
 * data_root: top-level data directory.
 * passphrase: master passphrase used to decrypt the registry index.
 *
 * Creates an empty registry if none exists.  Returns 0 on success.
 */
int koe_account_registry_load(koe_account_registry_t *reg,
                                const char             *data_root,
                                const char             *passphrase);

/*
 * koe_account_registry_save - Persist the registry.
 */
int koe_account_registry_save(const koe_account_registry_t *reg,
                                const char                   *passphrase);

/* ---------------------------------------------------------------------- */
/* Account lifecycle                                                         */
/* ---------------------------------------------------------------------- */

/*
 * koe_account_create - Generate a new identity and register it.
 *
 * display_name: human-friendly label shown in the account switcher.
 * passphrase:   per-account passphrase (may differ between accounts).
 * reg:          registry to add the new account to.
 * out:          filled with the newly created (and already active) account.
 *
 * Returns 0 on success.
 */
int koe_account_create(koe_account_t          *out,
                        koe_account_registry_t *reg,
                        const char             *display_name,
                        const char             *passphrase);

/*
 * koe_account_activate - Load and decrypt an account.
 *
 * idx:        index into reg->accounts.
 * passphrase: per-account passphrase.
 * out:        filled with the decrypted account.
 *
 * Returns 0 on success, -1 if the passphrase is wrong or the file is missing.
 */
int koe_account_activate(koe_account_t                *out,
                          const koe_account_registry_t *reg,
                          int                           idx,
                          const char                   *passphrase);

/*
 * koe_account_deactivate - Zero all secret material and mark inactive.
 *
 * Call this before activating a different account.
 */
void koe_account_deactivate(koe_account_t *account);

/*
 * koe_account_delete - Remove an account from the device.
 *
 * Wipes all files in the account's data_subdir and removes the entry from
 * the registry.  Cannot delete the currently active account.
 *
 * Returns 0 on success, -1 if the account is active or not found.
 */
int koe_account_delete(koe_account_registry_t *reg, int idx);

/*
 * koe_account_rename - Change the display name of an account.
 */
int koe_account_rename(koe_account_registry_t *reg, int idx, const char *new_name);

/*
 * koe_account_change_passphrase - Re-encrypt an account under a new passphrase.
 *
 * The account must be currently active (decrypted) for this to succeed.
 */
int koe_account_change_passphrase(koe_account_t *account,
                                    const char    *old_passphrase,
                                    const char    *new_passphrase);

#endif /* KOE_ACCOUNT_H */
