/*
 * koe_audio.h - Live voice call support using Opus.
 *
 * Audio path (outbound):
 *   mic capture -> PCM (int16, 8 kHz mono) -> Opus encoder
 *     -> encrypted KOE_TYPE_AUDIO packet -> transport
 *
 * Audio path (inbound):
 *   transport -> KOE_TYPE_AUDIO packet -> decrypt
 *     -> Opus decoder -> PCM -> speaker
 *
 * Frame size is fixed at 20 ms (160 samples at 8 kHz). Each encoded frame
 * becomes exactly one KOE_TYPE_AUDIO packet on the wire.
 *
 * Opus's built-in PLC (packet loss concealment) is used for lost frames.
 * When koe_audio_decode_frame is called with a NULL packet, the decoder
 * synthesises a plausible substitution instead of producing silence.
 *
 * The jitter buffer holds up to 4 frames (80 ms) to smooth out network
 * jitter before samples reach the playback device. Frames received out of
 * order within the buffer window are reordered; frames that arrive too late
 * are discarded and counted toward frames_lost.
 */

#ifndef KOE_AUDIO_H
#define KOE_AUDIO_H

#include "koe_crypto.h"
#include "koe_packet.h"
#include <stdint.h>
#include <stddef.h>

#define KOE_AUDIO_SAMPLE_RATE    8000
#define KOE_AUDIO_CHANNELS       1
#define KOE_AUDIO_FRAME_MS       20
#define KOE_AUDIO_FRAME_SAMPLES  (KOE_AUDIO_SAMPLE_RATE * KOE_AUDIO_FRAME_MS / 1000)  /* 160 */
#define KOE_AUDIO_MAX_FRAME_BYTES 256
#define KOE_AUDIO_JITTER_FRAMES  4

typedef enum {
    KOE_CALL_IDLE     = 0,
    KOE_CALL_RINGING,       /* outbound: awaiting remote acceptance */
    KOE_CALL_INCOMING,      /* inbound: awaiting local user action  */
    KOE_CALL_ACTIVE,
    KOE_CALL_ENDED,
} koe_call_state_t;

typedef struct {
    koe_call_state_t  state;

    /* Opus encoder and decoder handles. Declared as void* to avoid pulling
     * opus/opus.h into every translation unit that includes this header.
     * The implementation casts them to the correct Opus types internally. */
    void *encoder;
    void *decoder;

    /* Small ring buffer of received PCM frames. Smooths out per-packet
     * jitter before the playback device pulls samples. */
    int16_t  jitter_buf[KOE_AUDIO_JITTER_FRAMES][KOE_AUDIO_FRAME_SAMPLES];
    uint64_t jitter_seq[KOE_AUDIO_JITTER_FRAMES];   /* sequence number per slot */
    int      jitter_write;
    int      jitter_read;

    uint8_t  remote_pk[KOE_ED25519_PK_LEN];

    int      mic_muted;
    int      speaker_muted;

    uint64_t frames_sent;
    uint64_t frames_received;
    uint64_t frames_lost;       /* estimated from sequence number gaps */
    uint64_t next_seq;          /* sequence number for the next outgoing frame */
} koe_audio_ctx_t;

/* --- Lifecycle ---------------------------------------------------------- */

/* Initialise an audio context for a new call.
 * Returns 0 on success, -1 if the Opus library is not available. */
int koe_audio_init(koe_audio_ctx_t *ctx,
                    const uint8_t    remote_pk[KOE_ED25519_PK_LEN]);

/* Tear down the call and release Opus encoder/decoder resources. */
void koe_audio_destroy(koe_audio_ctx_t *ctx);

/* --- Capture path ------------------------------------------------------- */

/* Encode one frame of PCM and build an encrypted KOE_TYPE_AUDIO packet.
 *
 * pcm must contain exactly KOE_AUDIO_FRAME_SAMPLES signed 16-bit samples.
 * pkt is populated and ready to pass to the transport layer.
 * pkt->payload is heap-allocated; call koe_packet_free(pkt) after sending. */
int koe_audio_encode_frame(koe_audio_ctx_t    *ctx,
                             const int16_t       pcm[KOE_AUDIO_FRAME_SAMPLES],
                             const koe_session_t *sess,
                             koe_packet_t        *pkt);

/* --- Playback path ------------------------------------------------------ */

/* Decrypt and decode an incoming KOE_TYPE_AUDIO packet into PCM.
 * Writes KOE_AUDIO_FRAME_SAMPLES samples to `pcm`.
 *
 * Pass pkt=NULL to invoke Opus PLC for a lost frame. */
int koe_audio_decode_frame(koe_audio_ctx_t    *ctx,
                             const koe_packet_t *pkt,
                             const koe_session_t *sess,
                             int16_t             pcm[KOE_AUDIO_FRAME_SAMPLES]);

/* Push a decoded PCM frame into the jitter buffer. */
int koe_audio_jitter_push(koe_audio_ctx_t *ctx,
                            const int16_t    pcm[KOE_AUDIO_FRAME_SAMPLES],
                            uint64_t         seq);

/* Pull the next frame in order from the jitter buffer.
 * Returns 1 if a frame was available, 0 if the buffer is empty. */
int koe_audio_jitter_pull(koe_audio_ctx_t *ctx,
                            int16_t          pcm[KOE_AUDIO_FRAME_SAMPLES]);

/* --- Call signalling ---------------------------------------------------- */

/* Build a KOE_TYPE_CALL_SIG packet to initiate a call. */
int koe_audio_build_call_start(koe_packet_t         *pkt,
                                 const koe_identity_t *local_id,
                                 const uint8_t         remote_pk[KOE_ED25519_PK_LEN],
                                 const koe_session_t  *sess);

/* Build a KOE_TYPE_CALL_SIG packet to end a call. */
int koe_audio_build_call_end(koe_packet_t         *pkt,
                               const koe_identity_t *local_id,
                               const uint8_t         remote_pk[KOE_ED25519_PK_LEN],
                               const koe_session_t  *sess);

/* --- Mute controls ------------------------------------------------------ */

void koe_audio_set_mic_mute(koe_audio_ctx_t *ctx, int muted);
void koe_audio_set_speaker_mute(koe_audio_ctx_t *ctx, int muted);

/* Return current call statistics for display in the TUI. */
void koe_audio_stats(const koe_audio_ctx_t *ctx,
                      uint64_t *sent,
                      uint64_t *received,
                      uint64_t *lost);

#endif /* KOE_AUDIO_H */
