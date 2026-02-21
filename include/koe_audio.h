/*
 * koe_audio.h - Voice calls with Opus encoding and jitter buffer.
 */
#ifndef KOE_AUDIO_H
#define KOE_AUDIO_H

#include "koe_crypto.h"
#include "koe_packet.h"
#include <stdint.h>

/* Opus parameters. */
#define KOE_AUDIO_SAMPLE_RATE     8000
#define KOE_AUDIO_CHANNELS        1
#define KOE_AUDIO_FRAME_MS        20
#define KOE_AUDIO_FRAME_SAMPLES   (KOE_AUDIO_SAMPLE_RATE * KOE_AUDIO_FRAME_MS / 1000)
#define KOE_AUDIO_MAX_FRAME_BYTES 256
#define KOE_JITTER_BUF_FRAMES     4

typedef enum {
    KOE_CALL_IDLE    = 0,
    KOE_CALL_RINGING = 1,
    KOE_CALL_ACTIVE  = 2,
    KOE_CALL_ENDED   = 3,
} koe_call_state_t;

/* Opaque Opus encoder/decoder handles. */
typedef struct OpusEncoder OpusEncoder;
typedef struct OpusDecoder OpusDecoder;

typedef struct {
    OpusEncoder   *encoder;
    OpusDecoder   *decoder;
    koe_call_state_t state;
    uint8_t        remote_pk[KOE_ED25519_PK_LEN];
    int            muted;
    int            speaker_muted;
    uint64_t       frames_sent;
    uint64_t       frames_received;
    uint64_t       frames_lost;
    /* Jitter buffer: ring of decoded frames. */
    int16_t        jitter_buf[KOE_JITTER_BUF_FRAMES][KOE_AUDIO_FRAME_SAMPLES];
    int            jitter_write;
    int            jitter_read;
} koe_audio_ctx_t;

int  koe_audio_init(koe_audio_ctx_t *ctx, const uint8_t remote_pk[KOE_ED25519_PK_LEN]);
void koe_audio_destroy(koe_audio_ctx_t *ctx);
int  koe_audio_encode_frame(koe_audio_ctx_t *ctx, const int16_t pcm[KOE_AUDIO_FRAME_SAMPLES],
                              const koe_session_t *sess, koe_packet_t *pkt_out);
int  koe_audio_decode_frame(koe_audio_ctx_t *ctx, const koe_packet_t *pkt,
                              const koe_session_t *sess, int16_t pcm[KOE_AUDIO_FRAME_SAMPLES]);
int  koe_audio_build_call_start(koe_packet_t *pkt, const koe_identity_t *local_id,
                                  const uint8_t remote_pk[KOE_ED25519_PK_LEN],
                                  const koe_session_t *sess);
int  koe_audio_build_call_end(koe_packet_t *pkt, const koe_identity_t *local_id,
                                const uint8_t remote_pk[KOE_ED25519_PK_LEN],
                                const koe_session_t *sess);
void koe_audio_set_mute(koe_audio_ctx_t *ctx, int muted);
void koe_audio_set_speaker_mute(koe_audio_ctx_t *ctx, int muted);

#endif /* KOE_AUDIO_H */
