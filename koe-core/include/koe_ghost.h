/*
 * koe_ghost.h - Ghost mode and secret chat vaults.
 *
 * Ghost mode: the local client does not broadcast presence to other peers.
 * Incoming messages are received and queued normally; the sender sees the
 * message as "sent" but never receives a delivery ACK until ghost mode is
 * disabled. No read receipts are sent while ghost mode is active.
 *
 * Secret chats: conversations that are stored in a separate encrypted vault
 * behind a PIN or biometric prompt. The vault does not appear in the main
 * conversation list. If the device is seized or unlocked by a third party
 * without the vault PIN, no evidence that secret chats exist is visible
 * through the normal UI.
 *
 * Travel mode: temporarily removes all conversation data from the device
 * without permanently deleting it. The data is encrypted and stored as a
 * detached blob (locally or on the relay server); restoring it requires the
 * travel PIN. Designed for border crossings or situations where device
 * inspection is a concern.
 */

#ifndef KOE_GHOST_H
#define KOE_GHOST_H

#include "koe_crypto.h"
#include "koe_identity.h"
#include <stdint.h>

/* --- Ghost mode --------------------------------------------------------- */

typedef struct {
    int      active;
    uint64_t activated_at;    /* Unix timestamp, 0 if not active */
} koe_ghost_mode_t;

/* Enable ghost mode. While active, no ACKs or read receipts are sent.
 * Returns 0 on success. */
int koe_ghost_enable(koe_ghost_mode_t *gm);

/* Disable ghost mode and flush any ACKs that were held back. */
int koe_ghost_disable(koe_ghost_mode_t *gm,
                       const koe_identity_t *local_id);

/* Return 1 if ghost mode is currently active. */
int koe_ghost_is_active(const koe_ghost_mode_t *gm);

/* --- Secret chat vault -------------------------------------------------- */

#define KOE_VAULT_PIN_MAX  32

typedef struct {
    char    vault_path[256];   /* path to the encrypted vault directory */
    int     unlocked;
    uint8_t vault_key[KOE_SESSION_KEY_LEN];   /* zeroed when locked */
} koe_vault_t;

/* Initialise a new vault at `path` protected by `pin`.
 * Returns 0 on success, -1 on error. */
int koe_vault_create(koe_vault_t *vault,
                      const char  *path,
                      const char  *pin);

/* Unlock the vault. The key is derived from `pin` via Argon2id.
 * Returns 0 on success, -1 if the PIN is wrong or the vault is corrupted. */
int koe_vault_unlock(koe_vault_t *vault,
                      const char  *path,
                      const char  *pin);

/* Lock the vault. Zeroes the in-memory key. */
void koe_vault_lock(koe_vault_t *vault);

/* Write a message blob into the vault. Encrypted with vault_key.
 * Returns 0 on success, -1 if the vault is locked or on write error. */
int koe_vault_write(koe_vault_t   *vault,
                     const uint8_t *data,
                     size_t         len,
                     const char    *key);

/* Read a message blob from the vault. Caller must free *out.
 * Returns 0 on success, -1 on error or if the vault is locked. */
int koe_vault_read(koe_vault_t  *vault,
                    uint8_t     **out,
                    size_t       *out_len,
                    const char   *key);

/* --- Travel mode -------------------------------------------------------- */

#define KOE_TRAVEL_PIN_MAX  32

/* Pack all conversation data into an encrypted blob and remove it from the
 * normal data directory. The blob is stored at `stash_path` (local) or
 * uploaded to the relay if `relay_host` is non-NULL.
 *
 * Returns 0 on success, -1 on error. */
int koe_travel_engage(const char           *data_dir,
                       const char           *stash_path,
                       const char           *travel_pin,
                       const char           *relay_host,
                       uint16_t              relay_port,
                       const koe_identity_t *local_id);

/* Restore conversation data from the travel stash.
 * `travel_pin` must match what was used in koe_travel_engage. */
int koe_travel_disengage(const char           *data_dir,
                           const char           *stash_path,
                           const char           *travel_pin,
                           const char           *relay_host,
                           uint16_t              relay_port,
                           const koe_identity_t *local_id);

#endif /* KOE_GHOST_H */
