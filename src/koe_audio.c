#include "koe_audio.h"
#include "koe_crypto.h"
#include <opus/opus.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int koe_audio_init(koe_audio_ctx_t *ctx, const uint8_t remote_pk[KOE_ED25519_PK_LEN])
{
    memset(ctx, 0, sizeof(*ctx));
    memcpy(ctx->remote_pk, remote_pk, KOE_ED25519_PK_LEN);

    int err;
    ctx->encoder = opus_encoder_create(KOE_AUDIO_SAMPLE_RATE, KOE_AUDIO_CHANNELS,
                                        OPUS_APPLICATION_VOIP, &err);
    if (err != OPUS_OK || !ctx->encoder) return -1;

    ctx->decoder = opus_decoder_create(KOE_AUDIO_SAMPLE_RATE, KOE_AUDIO_CHANNELS, &err);
    if (err != OPUS_OK || !ctx->decoder) {
        opus_encoder_destroy(ctx->encoder);
        ctx->encoder = NULL;
        return -1;
    }

    /* Tune for low-latency voice on lossy links. */
    opus_encoder_ctl(ctx->encoder, OPUS_SET_BITRATE(12000));
    opus_encoder_ctl(ctx->encoder, OPUS_SET_COMPLEXITY(5));
    opus_encoder_ctl(ctx->encoder, OPUS_SET_DTX(1));
    opus_encoder_ctl(ctx->encoder, OPUS_SET_INBAND_FEC(1));
    opus_encoder_ctl(ctx->encoder, OPUS_SET_PACKET_LOSS_PERC(10));

    ctx->state = KOE_CALL_RINGING;
    return 0;
}

void koe_audio_destroy(koe_audio_ctx_t *ctx)
{
    if (ctx->encoder) { opus_encoder_destroy(ctx->encoder); ctx->encoder = NULL; }
    if (ctx->decoder) { opus_decoder_destroy(ctx->decoder); ctx->decoder = NULL; }
    ctx->state = KOE_CALL_ENDED;
}

int koe_audio_encode_frame(koe_audio_ctx_t *ctx,
                             const int16_t pcm[KOE_AUDIO_FRAME_SAMPLES],
                             const koe_session_t *sess, koe_packet_t *pkt_out)
{
    if (ctx->muted) return 0;

    uint8_t opus_buf[KOE_AUDIO_MAX_FRAME_BYTES];
    int opus_len = opus_encode(ctx->encoder, pcm, KOE_AUDIO_FRAME_SAMPLES,
                                opus_buf, KOE_AUDIO_MAX_FRAME_BYTES);
    if (opus_len < 0) return -1;

    size_t  ct_len = (size_t)opus_len + KOE_TAG_LEN;
    uint8_t *ct    = malloc(ct_len);
    if (!ct) return -1;

    uint8_t nonce[KOE_NONCE_LEN];
    koe_nonce_generate(nonce);
    if (koe_encrypt(ct, opus_buf, (size_t)opus_len, nonce, sess->tx_key) != 0) {
        free(ct); return -1;
    }

    koe_packet_init(pkt_out, KOE_TYPE_AUDIO, KOE_FLAG_ENCRYPTED);
    pkt_out->header.length = (uint32_t)ct_len;
    memcpy(pkt_out->header.from, sess->tx_key, KOE_ID_LEN); /* placeholder */
    memcpy(pkt_out->header.to, ctx->remote_pk, KOE_ID_LEN);
    memcpy(pkt_out->header.nonce, nonce, KOE_NONCE_LEN);
    pkt_out->header.checksum = koe_packet_checksum(&pkt_out->header);
    pkt_out->payload = ct;

    ctx->frames_sent++;
    return 0;
}

int koe_audio_decode_frame(koe_audio_ctx_t *ctx, const koe_packet_t *pkt,
                             const koe_session_t *sess, int16_t pcm[KOE_AUDIO_FRAME_SAMPLES])
{
    if (!pkt->payload || pkt->header.length <= KOE_TAG_LEN) {
        /* Packet loss — use PLC. */
        ctx->frames_lost++;
        int n = opus_decode(ctx->decoder, NULL, 0, pcm, KOE_AUDIO_FRAME_SAMPLES, 0);
        return n > 0 ? 0 : -1;
    }

    size_t  plain_len = pkt->header.length - KOE_TAG_LEN;
    uint8_t *plain    = malloc(plain_len);
    if (!plain) return -1;

    if (koe_decrypt(plain, pkt->payload, pkt->header.length,
                     pkt->header.nonce, sess->rx_key) != 0) {
        free(plain); ctx->frames_lost++; return -1;
    }

    int n = opus_decode(ctx->decoder, plain, (opus_int32)plain_len,
                         pcm, KOE_AUDIO_FRAME_SAMPLES, 0);
    free(plain);
    if (n < 0) return -1;

    ctx->frames_received++;

    /* Write into jitter buffer. */
    memcpy(ctx->jitter_buf[ctx->jitter_write], pcm,
           KOE_AUDIO_FRAME_SAMPLES * sizeof(int16_t));
    ctx->jitter_write = (ctx->jitter_write + 1) % KOE_JITTER_BUF_FRAMES;

    return 0;
}

static int build_call_signal(koe_packet_t *pkt, uint8_t signal_type,
                               const koe_identity_t *local_id,
                               const uint8_t remote_pk[KOE_ED25519_PK_LEN],
                               const koe_session_t *sess)
{
    uint8_t plain[1] = { signal_type };
    uint8_t ct[1 + KOE_TAG_LEN];
    uint8_t nonce[KOE_NONCE_LEN];
    koe_nonce_generate(nonce);
    if (koe_encrypt(ct, plain, 1, nonce, sess->tx_key) != 0) return -1;

    uint8_t *payload = malloc(sizeof(ct));
    if (!payload) return -1;
    memcpy(payload, ct, sizeof(ct));

    koe_packet_init(pkt, signal_type == 1 ? KOE_TYPE_HELLO : KOE_TYPE_ACK,
                    KOE_FLAG_ENCRYPTED);
    pkt->header.length = sizeof(ct);
    memcpy(pkt->header.from, local_id->pk, KOE_ID_LEN);
    memcpy(pkt->header.to,   remote_pk,    KOE_ID_LEN);
    memcpy(pkt->header.nonce, nonce,        KOE_NONCE_LEN);
    pkt->header.checksum = koe_packet_checksum(&pkt->header);
    pkt->payload = payload;
    return 0;
}

int koe_audio_build_call_start(koe_packet_t *pkt, const koe_identity_t *local_id,
                                 const uint8_t remote_pk[KOE_ED25519_PK_LEN],
                                 const koe_session_t *sess)
{
    return build_call_signal(pkt, 1, local_id, remote_pk, sess);
}

int koe_audio_build_call_end(koe_packet_t *pkt, const koe_identity_t *local_id,
                               const uint8_t remote_pk[KOE_ED25519_PK_LEN],
                               const koe_session_t *sess)
{
    return build_call_signal(pkt, 0, local_id, remote_pk, sess);
}

void koe_audio_set_mute(koe_audio_ctx_t *ctx, int muted) { ctx->muted = muted; }
void koe_audio_set_speaker_mute(koe_audio_ctx_t *ctx, int muted) { ctx->speaker_muted = muted; }
