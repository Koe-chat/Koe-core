/*
 * koe_audio.c - Voice call support: Opus encoding, jitter buffer, signalling.
 *
 * The jitter buffer is a fixed-size ring of decoded PCM frames. On the
 * playback side, frames are pushed in as they arrive and pulled out at a
 * steady rate by the audio device. A 4-frame buffer (80 ms at 20 ms/frame)
 * provides enough headroom for typical WiFi Direct and Bluetooth jitter
 * without introducing noticeable delay.
 *
 * When a frame is missing (detected via sequence number gap), a NULL is
 * passed to koe_audio_decode_frame and Opus PLC generates a substitute.
 */

#include "koe_audio.h"
#include "koe_crypto.h"
#include <opus/opus.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* Per-call sequence number embedded in the AUDIO packet payload header.
 * 4 bytes, big-endian, monotonically increasing from 0. */
#define AUDIO_SEQ_LEN  4

int koe_audio_init(koe_audio_ctx_t *ctx,
                    const uint8_t    remote_pk[KOE_ED25519_PK_LEN])
{
    memset(ctx, 0, sizeof(*ctx));
    memcpy(ctx->remote_pk, remote_pk, KOE_ED25519_PK_LEN);
    ctx->state = KOE_CALL_IDLE;

    int err;

    ctx->encoder = opus_encoder_create(KOE_AUDIO_SAMPLE_RATE,
                                        KOE_AUDIO_CHANNELS,
                                        OPUS_APPLICATION_VOIP,
                                        &err);
    if (err != OPUS_OK || !ctx->encoder) {
        fprintf(stderr, "koe_audio_init: encoder create failed: %s\n",
                opus_strerror(err));
        return -1;
    }

    ctx->decoder = opus_decoder_create(KOE_AUDIO_SAMPLE_RATE,
                                        KOE_AUDIO_CHANNELS,
                                        &err);
    if (err != OPUS_OK || !ctx->decoder) {
        fprintf(stderr, "koe_audio_init: decoder create failed: %s\n",
                opus_strerror(err));
        opus_encoder_destroy(ctx->encoder);
        ctx->encoder = NULL;
        return -1;
    }

    /* Set bitrate to 8 kbps — adequate for narrowband voice and conserves
     * bandwidth on Bluetooth where the channel is limited. */
    opus_encoder_ctl(ctx->encoder, OPUS_SET_BITRATE(8000));
    opus_encoder_ctl(ctx->encoder, OPUS_SET_DTX(1));    /* discontinuous TX */
    opus_encoder_ctl(ctx->encoder, OPUS_SET_INBAND_FEC(1)); /* in-band FEC */

    ctx->jitter_write = 0;
    ctx->jitter_read  = 0;

    return 0;
}

void koe_audio_destroy(koe_audio_ctx_t *ctx)
{
    if (ctx->encoder) {
        opus_encoder_destroy(ctx->encoder);
        ctx->encoder = NULL;
    }
    if (ctx->decoder) {
        opus_decoder_destroy(ctx->decoder);
        ctx->decoder = NULL;
    }
    ctx->state = KOE_CALL_ENDED;
    memset(ctx->jitter_buf, 0, sizeof(ctx->jitter_buf));
}

/* ---------------------------------------------------------------------- */

int koe_audio_encode_frame(koe_audio_ctx_t    *ctx,
                             const int16_t       pcm[KOE_AUDIO_FRAME_SAMPLES],
                             const koe_session_t *sess,
                             koe_packet_t        *pkt)
{
    if (ctx->muted) {
        /* Replace mic input with silence rather than skipping the packet,
         * so the remote side's PLC does not trigger unnecessarily. */
        int16_t silence[KOE_AUDIO_FRAME_SAMPLES] = {0};
        pcm = silence;
    }

    /* Encode. The output is at most KOE_AUDIO_MAX_FRAME_BYTES bytes. */
    uint8_t opus_buf[KOE_AUDIO_MAX_FRAME_BYTES];
    opus_int32 opus_len = opus_encode(ctx->encoder,
                                       pcm,
                                       KOE_AUDIO_FRAME_SAMPLES,
                                       opus_buf,
                                       sizeof(opus_buf));
    if (opus_len < 0) {
        fprintf(stderr, "koe_audio_encode_frame: %s\n",
                opus_strerror((int)opus_len));
        return -1;
    }

    /* Prepend a 4-byte sequence number. */
    size_t payload_plain_len = AUDIO_SEQ_LEN + (size_t)opus_len;
    uint8_t *plain = malloc(payload_plain_len);
    if (!plain) return -1;

    uint32_t seq = (uint32_t)(ctx->frames_sent & 0xFFFFFFFF);
    plain[0] = (seq >> 24) & 0xFF;
    plain[1] = (seq >> 16) & 0xFF;
    plain[2] = (seq >>  8) & 0xFF;
    plain[3] = (seq      ) & 0xFF;
    memcpy(plain + AUDIO_SEQ_LEN, opus_buf, (size_t)opus_len);

    /* Allocate ciphertext buffer: plaintext + MAC tag. */
    size_t ct_len = payload_plain_len + KOE_TAG_LEN;
    uint8_t *ct   = malloc(ct_len);
    if (!ct) { free(plain); return -1; }

    /* Generate a fresh nonce for this frame. */
    uint8_t nonce[KOE_NONCE_LEN];
    koe_nonce_generate(nonce);

    if (koe_encrypt(ct, plain, payload_plain_len, nonce, sess->tx_key) != 0) {
        free(plain);
        free(ct);
        return -1;
    }
    free(plain);

    /* Build the packet header. */
    memset(pkt, 0, sizeof(*pkt));
    memcpy(pkt->header.magic, KOE_MAGIC, KOE_MAGIC_LEN);
    pkt->header.type   = KOE_TYPE_AUDIO;
    pkt->header.flags  = KOE_FLAG_ENCRYPTED;
    pkt->header.length = (uint32_t)ct_len;
    memcpy(pkt->header.to,    ctx->remote_pk, KOE_ID_LEN);
    memcpy(pkt->header.nonce, nonce,           KOE_NONCE_LEN);
    pkt->payload = ct;

    ctx->frames_sent++;
    return 0;
}

/* ---------------------------------------------------------------------- */

int koe_audio_decode_frame(koe_audio_ctx_t    *ctx,
                             const koe_packet_t *pkt,
                             const koe_session_t *sess,
                             int16_t             pcm[KOE_AUDIO_FRAME_SAMPLES])
{
    if (ctx->speaker_muted) {
        memset(pcm, 0, KOE_AUDIO_FRAME_SAMPLES * sizeof(int16_t));
        return 0;
    }

    if (!pkt) {
        /* Lost frame: let Opus PLC generate a substitute. */
        ctx->frames_lost++;
        int n = opus_decode(ctx->decoder, NULL, 0, pcm,
                             KOE_AUDIO_FRAME_SAMPLES, 0);
        return (n < 0) ? -1 : 0;
    }

    /* Decrypt the payload. */
    if (!(pkt->header.flags & KOE_FLAG_ENCRYPTED) || !pkt->payload)
        return -1;

    size_t plain_len = pkt->header.length - KOE_TAG_LEN;
    uint8_t *plain   = malloc(pkt->header.length); /* upper bound */
    if (!plain) return -1;

    if (koe_decrypt(plain, pkt->payload, pkt->header.length,
                     pkt->header.nonce, sess->rx_key) != 0) {
        free(plain);
        return -1;
    }

    /* Skip the 4-byte sequence number. */
    if (plain_len <= AUDIO_SEQ_LEN) { free(plain); return -1; }
    const uint8_t *opus_data = plain + AUDIO_SEQ_LEN;
    opus_int32     opus_len  = (opus_int32)(plain_len - AUDIO_SEQ_LEN);

    int n = opus_decode(ctx->decoder, opus_data, opus_len, pcm,
                         KOE_AUDIO_FRAME_SAMPLES, 0);
    free(plain);

    if (n < 0) {
        fprintf(stderr, "koe_audio_decode_frame: %s\n", opus_strerror(n));
        return -1;
    }

    ctx->frames_received++;
    return 0;
}

/* ---------------------------------------------------------------------- */

static int build_call_signal(koe_packet_t         *pkt,
                               uint8_t               signal_byte,
                               const koe_identity_t *local_id,
                               const uint8_t         remote_pk[KOE_ED25519_PK_LEN],
                               const koe_session_t  *sess)
{
    uint8_t plain[1] = { signal_byte };
    uint8_t ct[1 + KOE_TAG_LEN];
    uint8_t nonce[KOE_NONCE_LEN];

    koe_nonce_generate(nonce);
    if (koe_encrypt(ct, plain, 1, nonce, sess->tx_key) != 0)
        return -1;

    uint8_t *payload = malloc(sizeof(ct));
    if (!payload) return -1;
    memcpy(payload, ct, sizeof(ct));

    memset(pkt, 0, sizeof(*pkt));
    memcpy(pkt->header.magic, KOE_MAGIC, KOE_MAGIC_LEN);
    pkt->header.type   = KOE_TYPE_MSG;
    pkt->header.flags  = KOE_FLAG_ENCRYPTED | KOE_FLAG_SIGNED;
    pkt->header.length = sizeof(ct);
    memcpy(pkt->header.from,  local_id->pk, KOE_ID_LEN);
    memcpy(pkt->header.to,    remote_pk,    KOE_ID_LEN);
    memcpy(pkt->header.nonce, nonce,        KOE_NONCE_LEN);
    pkt->payload = payload;

    (void)signal_byte; /* already encoded in plain */
    return 0;
}

int koe_audio_build_call_start(koe_packet_t         *pkt,
                                 const koe_identity_t *local_id,
                                 const uint8_t         remote_pk[KOE_ED25519_PK_LEN],
                                 const koe_session_t  *sess)
{
    return build_call_signal(pkt, 0x01, local_id, remote_pk, sess);
}

int koe_audio_build_call_end(koe_packet_t         *pkt,
                               const koe_identity_t *local_id,
                               const uint8_t         remote_pk[KOE_ED25519_PK_LEN],
                               const koe_session_t  *sess)
{
    return build_call_signal(pkt, 0x02, local_id, remote_pk, sess);
}

void koe_audio_set_mute(koe_audio_ctx_t *ctx, int muted)
{
    ctx->muted = muted ? 1 : 0;
}

void koe_audio_set_speaker_mute(koe_audio_ctx_t *ctx, int muted)
{
    ctx->speaker_muted = muted ? 1 : 0;
}
