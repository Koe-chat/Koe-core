#ifndef KOE_FFI_H
#define KOE_FFI_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------------------------------------------------------------- */
/* Context lifecycle                                                       */
/* ---------------------------------------------------------------------- */

typedef struct koe_ctx koe_ctx_t;

koe_ctx_t *koe_ctx_new(void);
void koe_ctx_free(koe_ctx_t *ctx);

int koe_ctx_init(koe_ctx_t *ctx, const char *data_dir, const char *passphrase);
void koe_ctx_shutdown(koe_ctx_t *ctx);

/* Polling (call this in your event loop) */
int koe_ctx_poll(koe_ctx_t *ctx, int timeout_ms);

/* ---------------------------------------------------------------------- */
/* Identity management                                                    */
/* ---------------------------------------------------------------------- */

/* Generate a new identity keypair.
 * pubkey_out: 32-byte output buffer for Ed25519 public key
 * privkey_out: 64-byte output buffer for Ed25519 private key
 * Returns 0 on success. */
int koe_identity_generate(uint8_t pubkey_out[32], uint8_t privkey_out[64]);

/* Get the current identity's public key.
 * pk_out: 32-byte buffer for public key.
 * Returns 0 if identity exists, -1 if not initialized. */
int koe_identity_get_pubkey(koe_ctx_t *ctx, uint8_t pk_out[32]);

/* Get the short ID (base58 of first 8 bytes of pk).
 * short_id_out: 17-byte buffer (16 chars + null terminator). */
void koe_identity_get_short_id(koe_ctx_t *ctx, char short_id_out[17]);

/* ---------------------------------------------------------------------- */
/* Contact management                                                     */
/* ---------------------------------------------------------------------- */

/* Add a contact by their public key.
 * display_name: null-terminated string (max 64 bytes) */
int koe_contact_add(koe_ctx_t *ctx,
                     const uint8_t pubkey[32],
                     const char *display_name);

/* Remove a contact */
int koe_contact_remove(koe_ctx_t *ctx, const uint8_t pubkey[32]);

/* List contacts.
 * buffer: caller-allocated array of 32-byte public keys
 * max_count: size of buffer
 * Returns number of contacts written, or -1 on error. */
int koe_contact_list(koe_ctx_t *ctx, uint8_t *buffer, int max_count);

/* ---------------------------------------------------------------------- */
/* Messaging                                                              */
/* ---------------------------------------------------------------------- */

/* Send a text message.
 * to: 32-byte recipient public key
 * text: null-terminated UTF-8 string
 * ttl: self-destruct seconds (0 = never)
 * Returns message ID on success, -1 on error. */
int64_t koe_message_send(koe_ctx_t *ctx,
                          const uint8_t to[32],
                          const char *text,
                          uint32_t ttl);

/* Receive a message (non-blocking).
 * from_out: 32-byte buffer for sender's public key
 * text_out: buffer for message text (max 4096 bytes)
 * text_len_out: actual text length
 * Returns 0 if a message was received, -1 if none available. */
int koe_message_recv(koe_ctx_t *ctx,
                     uint8_t from_out[32],
                     char *text_out,
                     int *text_len_out);

/* ---------------------------------------------------------------------- */
/* Voice calls                                                            */
/* ---------------------------------------------------------------------- */

/* Start a voice call.
 * Returns call handle (>0) on success, 0 if peer unreachable, -1 on error. */
int64_t koe_call_start(koe_ctx_t *ctx, const uint8_t to[32]);

/* End an active call */
void koe_call_end(koe_ctx_t *ctx, int64_t call_handle);

/* Encode an audio frame.
 * in: 160 bytes of 8kHz PCM (20ms at 8kHz)
 * out: output buffer for Opus frame (typically ~40 bytes)
 * out_len: size of output buffer (call with pointer to 64)
 * Returns encoded length on success, -1 on error. */
int koe_call_encode(koe_ctx_t *ctx,
                     int64_t call_handle,
                     const uint8_t in[160],
                     uint8_t *out,
                     int *out_len);

/* Decode an audio frame.
 * in: Opus frame
 * in_len: size of Opus frame
 * out: output buffer for 160 bytes of PCM
 * Returns 0 on success, -1 on error. */
int koe_call_decode(koe_ctx_t *ctx,
                     int64_t call_handle,
                     const uint8_t *in,
                     int in_len,
                     uint8_t out[160]);

/* ---------------------------------------------------------------------- */
/* File transfer                                                          */
/* ---------------------------------------------------------------------- */

/* Send a file.
 * to: recipient's public key
 * path: path to file on local filesystem
 * Returns transfer ID (>0) on success, -1 on error. */
int64_t koe_file_send(koe_ctx_t *ctx,
                       const uint8_t to[32],
                       const char *path);

/* Accept an incoming file transfer.
 * transfer_id: from the offer event
 * save_path: where to save the file
 * Returns 0 on success. */
int koe_file_accept(koe_ctx_t *ctx,
                     int64_t transfer_id,
                     const char *save_path);

/* Reject an incoming file transfer */
int koe_file_reject(koe_ctx_t *ctx, int64_t transfer_id);

/* ---------------------------------------------------------------------- */
/* Event callbacks                                                        */
/* ---------------------------------------------------------------------- */

/* Event types */
#define KOE_EV_MESSAGE_RECEIVED 1
#define KOE_EV_PEER_ONLINE      2
#define KOE_EV_PEER_OFFLINE     3
#define KOE_EV_CALL_INCOMING    4
#define KOE_EV_CALL_ENDED       5
#define KOE_EV_FILE_OFFER       6
#define KOE_EV_FILE_PROGRESS    7

typedef struct {
    int type;
    int64_t id;
    uint8_t from[32];
    union {
        struct {
            char text[4096];
            int text_len;
        } message;
        struct {
            int64_t call_handle;
        } call;
        struct {
            int64_t transfer_id;
            char filename[256];
            uint64_t file_size;
        } file;
    } data;
} koe_event_t;

/* Register event callback.
 * callback: function pointer
 * user_data: passed to callback
 * Returns 0 on success. */
int koe_event_set_callback(koe_ctx_t *ctx,
                            void (*callback)(const koe_event_t *, void *),
                            void *user_data);

/* ---------------------------------------------------------------------- */
/* Configuration                                                          */
/* ---------------------------------------------------------------------- */

typedef struct {
    const char *relay_host;
    uint16_t relay_port;
    int discovery_timeout_ms;
    int bluetooth_enabled;
    int queue_max_per_peer;
} koe_config_t;

/* Default configuration */
#define KOE_CONFIG_DEFAULT { \
    .relay_host = "koe-relay.hf.space", \
    .relay_port = 9474, \
    .discovery_timeout_ms = 500, \
    .bluetooth_enabled = 1, \
    .queue_max_per_peer = 512 \
}

int koe_config_set(koe_ctx_t *ctx, const koe_config_t *config);
int koe_config_get(koe_ctx_t *ctx, koe_config_t *config_out);

/* ---------------------------------------------------------------------- */
/* Error handling                                                         */
/* ---------------------------------------------------------------------- */

/* Get last error message (null-terminated, max 256 bytes) */
const char *koe_error(void);

/* Clear error state */
void koe_error_clear(void);

#ifdef __cplusplus
}
#endif

#endif /* KOE_FFI_H */