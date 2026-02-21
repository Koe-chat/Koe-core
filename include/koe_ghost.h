/*
 * koe_ghost.h - Ghost mode, secret chats, and travel mode.
 */
#ifndef KOE_GHOST_H
#define KOE_GHOST_H

#include "koe_crypto.h"
#include <stdint.h>

typedef struct {
    int active;
    int suppress_read_receipts;
    int suppress_typing;
} koe_ghost_state_t;

void koe_ghost_enable(koe_ghost_state_t *g);
void koe_ghost_disable(koe_ghost_state_t *g);
int  koe_ghost_should_respond(const koe_ghost_state_t *g, uint8_t packet_type);

int  koe_secret_chat_unlock(const char *pin, const char *data_dir);
void koe_secret_chat_lock(void);
int  koe_secret_chat_is_unlocked(void);
int  koe_secret_chat_wipe(const char *data_dir);

int  koe_travel_mode_enable(const char *recovery_pin, const char *data_dir);
int  koe_travel_mode_disable(const char *recovery_pin, const char *data_dir);
int  koe_travel_mode_active(const char *data_dir);

#endif /* KOE_GHOST_H */
