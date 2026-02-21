/*
 * tests/test_koe_core.c - koe-core unit tests.
 *
 * Build:
 *   mkdir build && cd build
 *   cmake .. -DKOE_BUILD_TESTS=ON
 *   make && ctest -V
 *
 * Or manually:
 *   gcc -std=c11 -O0 -g -I../include \
 *       test_koe_core.c -L../build -lkoe-core -lsodium -lopus -lsqlite3 \
 *       -o koe-test && ./koe-test
 */

#include "koe.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

/* ---------------------------------------------------------------------- */
/* Test runner                                                              */
/* ---------------------------------------------------------------------- */

#define CHECK(cond) \
    do { if (!(cond)) { \
        fprintf(stderr, "  FAIL  %s:%d  (%s)\n", __FILE__, __LINE__, #cond); \
        return -1; \
    } } while (0)

static int s_pass = 0, s_fail = 0;

static void run(const char *name, int (*fn)(void))
{
    printf("  %-56s ", name);
    fflush(stdout);
    int rc = fn();
    if (rc == 0) { s_pass++; puts("PASS"); }
    else         { s_fail++; puts("FAIL"); }
}

/* ---------------------------------------------------------------------- */
/* Tests: version                                                           */
/* ---------------------------------------------------------------------- */

static int test_version_local(void)
{
    koe_version_t v = koe_version_local();
    CHECK(v.major == KOE_PROTO_MAJOR);
    CHECK(v.minor == KOE_PROTO_MINOR);
    return 0;
}

static int test_version_compatible_same_major(void)
{
    koe_version_t a = {1, 0}, b = {1, 9};
    CHECK(koe_version_compatible(a, b) == 1);
    return 0;
}

static int test_version_compatible_adjacent_ok(void)
{
    /* v0.x <-> v1.0 must be compatible. */
    koe_version_t a = {0, 9}, b = {1, 0};
    CHECK(koe_version_compatible(a, b) == 1);
    CHECK(koe_version_compatible(b, a) == 1);
    return 0;
}

static int test_version_compatible_adjacent_fail(void)
{
    /* v0.9 <-> v1.1 must NOT be compatible. */
    koe_version_t a = {0, 9}, b = {1, 1};
    CHECK(koe_version_compatible(a, b) == 0);
    return 0;
}

static int test_version_compatible_two_major_apart(void)
{
    koe_version_t a = {0, 9}, b = {2, 0};
    CHECK(koe_version_compatible(a, b) == 0);
    return 0;
}

/* ---------------------------------------------------------------------- */
/* Tests: crypto                                                            */
/* ---------------------------------------------------------------------- */

static int test_crypto_init(void)
{
    CHECK(koe_crypto_init() == 0);
    return 0;
}

static int test_identity_generate(void)
{
    koe_identity_t id;
    CHECK(koe_identity_generate(&id) == 0);
    uint8_t zeros[KOE_ED25519_PK_LEN] = {0};
    CHECK(memcmp(id.pk, zeros, KOE_ED25519_PK_LEN) != 0);
    return 0;
}

static int test_sign_verify(void)
{
    koe_identity_t id;
    CHECK(koe_identity_generate(&id) == 0);

    const uint8_t msg[] = "koe sign test";
    uint8_t sig[KOE_ED25519_SIG_LEN];
    CHECK(koe_sign(sig, msg, sizeof(msg), &id) == 0);
    CHECK(koe_verify(sig, msg, sizeof(msg), id.pk) == 0);

    /* Tamper. */
    sig[0] ^= 0xFF;
    CHECK(koe_verify(sig, msg, sizeof(msg), id.pk) != 0);
    return 0;
}

static int test_encrypt_decrypt(void)
{
    koe_identity_t id;
    CHECK(koe_identity_generate(&id) == 0);

    uint8_t key[KOE_SESSION_KEY_LEN];
    memcpy(key, id.sk, KOE_SESSION_KEY_LEN);

    const uint8_t plain[] = "hello koe encrypted world";
    size_t plain_len = sizeof(plain);
    uint8_t nonce[KOE_NONCE_LEN];
    koe_nonce_generate(nonce);

    uint8_t ct[sizeof(plain) + KOE_TAG_LEN];
    CHECK(koe_encrypt(ct, plain, plain_len, nonce, key) == 0);

    uint8_t dec[sizeof(plain)] = {0};
    CHECK(koe_decrypt(dec, ct, sizeof(ct), nonce, key) == 0);
    CHECK(memcmp(dec, plain, plain_len) == 0);

    ct[4] ^= 0x01;
    CHECK(koe_decrypt(dec, ct, sizeof(ct), nonce, key) != 0);
    return 0;
}

static int test_nonce_unique(void)
{
    uint8_t n1[KOE_NONCE_LEN], n2[KOE_NONCE_LEN];
    koe_nonce_generate(n1);
    koe_nonce_generate(n2);
    CHECK(memcmp(n1, n2, KOE_NONCE_LEN) != 0);
    return 0;
}

static int test_short_id(void)
{
    koe_identity_t id1, id2;
    CHECK(koe_identity_generate(&id1) == 0);
    CHECK(koe_identity_generate(&id2) == 0);

    koe_short_id_t s1, s2;
    koe_identity_short_id(&s1, id1.pk);
    koe_identity_short_id(&s2, id2.pk);

    CHECK(s1.value[0] != '\0');
    CHECK(s2.value[0] != '\0');
    CHECK(strcmp(s1.value, s2.value) != 0);
    return 0;
}

static int test_verify_token(void)
{
    koe_identity_t id;
    CHECK(koe_identity_generate(&id) == 0);

    char    token[7];
    uint8_t nonce[16];
    CHECK(koe_verify_token_generate(token, nonce, id.pk) == 0);
    CHECK(strlen(token) == 6);

    int64_t now = (int64_t)time(NULL);
    CHECK(koe_verify_token_check(token, nonce, id.pk, now) == 0);
    CHECK(koe_verify_token_check("000000", nonce, id.pk, now) != 0);

    /* Expired token. */
    int64_t old = now - KOE_VERIFY_TOKEN_TTL - 1;
    CHECK(koe_verify_token_check(token, nonce, id.pk, old) != 0);
    return 0;
}

/* ---------------------------------------------------------------------- */
/* Tests: identity save/load                                                */
/* ---------------------------------------------------------------------- */

static int test_identity_save_load(void)
{
    koe_identity_t id, loaded;
    CHECK(koe_identity_generate(&id) == 0);

    const char *path = "/tmp/koe_test_identity.koe";
    CHECK(koe_identity_save(&id, path, "testpass123") == 0);
    CHECK(koe_identity_load(&loaded, path, "testpass123") == 0);
    CHECK(memcmp(id.pk, loaded.pk, KOE_ED25519_PK_LEN) == 0);
    CHECK(memcmp(id.sk, loaded.sk, KOE_ED25519_SK_LEN) == 0);

    /* Wrong passphrase. */
    koe_identity_t bad;
    CHECK(koe_identity_load(&bad, path, "wrongpass") != 0);

    remove(path);
    return 0;
}

/* ---------------------------------------------------------------------- */
/* Tests: packet                                                            */
/* ---------------------------------------------------------------------- */

static int test_packet_header_size(void)
{
    CHECK(KOE_HEADER_SIZE == 106);
    return 0;
}

static int test_packet_magic(void)
{
    CHECK(memcmp(KOE_MAGIC, "KOE\x01", 4) == 0);
    return 0;
}

static int test_packet_serialise_roundtrip(void)
{
    koe_packet_t pkt, out;
    koe_packet_init(&pkt, KOE_TYPE_PING, 0);

    const uint8_t payload[] = "ping body";
    pkt.header.length = sizeof(payload);
    pkt.payload = malloc(sizeof(payload));
    CHECK(pkt.payload != NULL);
    memcpy(pkt.payload, payload, sizeof(payload));
    pkt.header.checksum = koe_packet_checksum(&pkt.header);

    size_t total = KOE_HEADER_SIZE + sizeof(payload);
    uint8_t *buf = malloc(total);
    CHECK(buf != NULL);
    CHECK(koe_packet_serialise(&pkt, buf, total) == (int)total);
    CHECK(koe_packet_deserialise(&out, buf, total) == 0);
    CHECK(out.header.type == KOE_TYPE_PING);
    CHECK(out.header.length == sizeof(payload));
    CHECK(memcmp(out.payload, payload, sizeof(payload)) == 0);

    free(buf);
    koe_packet_free(&pkt);
    koe_packet_free(&out);
    return 0;
}

static int test_packet_checksum_detects_corruption(void)
{
    koe_packet_t pkt;
    koe_packet_init(&pkt, KOE_TYPE_MSG, KOE_FLAG_ENCRYPTED);
    pkt.header.checksum = koe_packet_checksum(&pkt.header);

    /* Corrupt. */
    pkt.header.type = KOE_TYPE_AUDIO;
    CHECK(koe_packet_validate(&pkt) != 0);
    return 0;
}

/* ---------------------------------------------------------------------- */
/* Tests: handshake                                                         */
/* ---------------------------------------------------------------------- */

static int test_handshake_full(void)
{
    koe_identity_t id_a, id_b;
    CHECK(koe_identity_generate(&id_a) == 0);
    CHECK(koe_identity_generate(&id_b) == 0);

    koe_handshake_t hs_a, hs_b;
    koe_packet_t hello, ack;

    CHECK(koe_handshake_init(&hs_a, &hello, &id_a, id_b.pk) == 0);
    CHECK(hs_a.state == KOE_HS_SENT_HELLO);

    CHECK(koe_handshake_respond(&hs_b, &ack, &hello, &id_b) == 0);
    CHECK(hs_b.state == KOE_HS_COMPLETE);

    CHECK(koe_handshake_finalise(&hs_a, &ack, &id_a) == 0);
    CHECK(hs_a.state == KOE_HS_COMPLETE);

    /* Session keys must match cross-side. */
    CHECK(memcmp(hs_a.session.tx_key, hs_b.session.rx_key, KOE_SESSION_KEY_LEN) == 0);
    CHECK(memcmp(hs_a.session.rx_key, hs_b.session.tx_key, KOE_SESSION_KEY_LEN) == 0);

    /* Keys must not be all zeros. */
    uint8_t zeros[KOE_SESSION_KEY_LEN] = {0};
    CHECK(memcmp(hs_a.session.tx_key, zeros, KOE_SESSION_KEY_LEN) != 0);

    koe_packet_free(&hello);
    koe_packet_free(&ack);
    return 0;
}

/* ---------------------------------------------------------------------- */
/* Tests: message                                                           */
/* ---------------------------------------------------------------------- */

static int test_message_alloc_free(void)
{
    uint8_t to[KOE_ED25519_PK_LEN] = {0};
    const uint8_t body[] = "test message";
    koe_message_t *m = koe_message_alloc(KOE_MSG_TEXT, to, body, sizeof(body));
    CHECK(m != NULL);
    CHECK(m->body_len == sizeof(body));
    CHECK(memcmp(m->body, body, sizeof(body)) == 0);
    CHECK(m->status == KOE_STATUS_PENDING);
    koe_message_free(m);
    return 0;
}

static int test_message_sign_verify(void)
{
    koe_identity_t id;
    CHECK(koe_identity_generate(&id) == 0);

    uint8_t to[KOE_ED25519_PK_LEN] = {0};
    const uint8_t body[] = "signed";
    koe_message_t *m = koe_message_alloc(KOE_MSG_TEXT, to, body, sizeof(body));
    CHECK(m != NULL);
    memcpy(m->from, id.pk, KOE_ED25519_PK_LEN);

    CHECK(koe_message_sign(m, &id) == 0);
    CHECK(koe_message_verify(m) == 0);

    m->body[0] ^= 0xFF;
    CHECK(koe_message_verify(m) != 0);

    koe_message_free(m);
    return 0;
}

static int test_message_encrypt_decrypt(void)
{
    koe_identity_t id_a, id_b;
    CHECK(koe_identity_generate(&id_a) == 0);
    CHECK(koe_identity_generate(&id_b) == 0);

    /* Perform a full handshake to get real session keys. */
    koe_handshake_t hs_a, hs_b;
    koe_packet_t hello, ack;
    CHECK(koe_handshake_init(&hs_a, &hello, &id_a, id_b.pk) == 0);
    CHECK(koe_handshake_respond(&hs_b, &ack, &hello, &id_b) == 0);
    CHECK(koe_handshake_finalise(&hs_a, &ack, &id_a) == 0);
    koe_packet_free(&hello);
    koe_packet_free(&ack);

    const uint8_t body[] = "hello encrypted";
    koe_message_t *msg = koe_message_alloc(KOE_MSG_TEXT, id_b.pk,
                                            body, sizeof(body));
    CHECK(msg != NULL);
    memcpy(msg->from, id_a.pk, KOE_ED25519_PK_LEN);

    koe_packet_t pkt;
    CHECK(koe_message_encrypt(msg, &hs_a.session, &pkt) == 0);

    koe_message_t decrypted = {0};
    CHECK(koe_message_decrypt(&decrypted, &pkt, &hs_b.session) == 0);
    CHECK(decrypted.body_len == sizeof(body));
    CHECK(memcmp(decrypted.body, body, sizeof(body)) == 0);

    koe_message_free(msg);
    koe_packet_free(&pkt);
    if (decrypted.body) free(decrypted.body);
    return 0;
}

static int test_message_self_destruct(void)
{
    uint8_t to[KOE_ED25519_PK_LEN] = {0};
    koe_message_t *m = koe_message_alloc(KOE_MSG_TEXT, to,
                                          (const uint8_t *)"bye", 3);
    CHECK(m != NULL);
    koe_message_set_destruct(m, 1);
    CHECK(m->destruct_after_seconds == 1);
    CHECK(koe_message_should_destruct(m) == 0);  /* not yet delivered */

    m->destruct_at = (int64_t)time(NULL) - 5;
    CHECK(koe_message_should_destruct(m) == 1);

    koe_message_free(m);
    return 0;
}

static int test_message_schedule(void)
{
    uint8_t to[KOE_ED25519_PK_LEN] = {0};
    koe_message_t *m = koe_message_alloc(KOE_MSG_TEXT, to,
                                          (const uint8_t *)"later", 5);
    CHECK(m != NULL);

    koe_message_schedule(m, (int64_t)time(NULL) + 3600);
    CHECK(koe_message_is_due(m) == 0);

    koe_message_schedule(m, (int64_t)time(NULL) - 1);
    CHECK(koe_message_is_due(m) == 1);

    koe_message_free(m);
    return 0;
}

/* ---------------------------------------------------------------------- */
/* Tests: ghost mode                                                        */
/* ---------------------------------------------------------------------- */

static int test_ghost_mode(void)
{
    koe_ghost_state_t g = {0};
    CHECK(koe_ghost_should_respond(&g, KOE_TYPE_PING) == 1);
    CHECK(koe_ghost_should_respond(&g, KOE_TYPE_MSG)  == 1);

    koe_ghost_enable(&g);
    CHECK(g.active == 1);
    CHECK(koe_ghost_should_respond(&g, KOE_TYPE_PING)  == 0);
    CHECK(koe_ghost_should_respond(&g, KOE_TYPE_PONG)  == 0);
    CHECK(koe_ghost_should_respond(&g, KOE_TYPE_MSG)   == 1);  /* direct msgs pass */
    CHECK(koe_ghost_should_respond(&g, KOE_TYPE_HELLO) == 1);

    koe_ghost_disable(&g);
    CHECK(g.active == 0);
    return 0;
}

/* ---------------------------------------------------------------------- */
/* Tests: revocation                                                        */
/* ---------------------------------------------------------------------- */

static int test_revoke(void)
{
    koe_identity_t old_id, new_id;
    CHECK(koe_identity_generate(&old_id) == 0);
    CHECK(koe_identity_generate(&new_id) == 0);

    koe_revocation_t rev;
    CHECK(koe_revoke_build(&rev, &old_id, &new_id, "device lost") == 0);
    CHECK(koe_revoke_verify(&rev) == 0);

    /* Tamper. */
    rev.new_pk[0] ^= 0xFF;
    CHECK(koe_revoke_verify(&rev) != 0);
    return 0;
}

/* ---------------------------------------------------------------------- */
/* Tests: account registry                                                  */
/* ---------------------------------------------------------------------- */

static int test_account_registry(void)
{
    koe_account_registry_t reg;
    CHECK(koe_account_registry_load(&reg, "/tmp/koe_test_reg", "pass") == 0);
    CHECK(reg.count == 0);

    koe_account_t acc;
    CHECK(koe_account_create(&acc, &reg, "TestUser", "pass") == 0);
    CHECK(reg.count == 1);
    CHECK(strcmp(reg.accounts[0].display_name, "TestUser") == 0);
    CHECK(acc.desc.active == 1);

    koe_account_deactivate(&acc);
    CHECK(acc.desc.active == 0);

    /* Cleanup. */
    remove("/tmp/koe_test_reg/accounts.koe");
    rmdir("/tmp/koe_test_reg/accounts/");
    rmdir("/tmp/koe_test_reg/");
    return 0;
}

/* ---------------------------------------------------------------------- */
/* Tests: presence                                                          */
/* ---------------------------------------------------------------------- */

static int test_presence(void)
{
    koe_presence_table_t table;
    koe_presence_init(&table);
    CHECK(table.count == 0);

    koe_identity_t id;
    CHECK(koe_identity_generate(&id) == 0);

    koe_presence_update(&table, id.pk, KOE_PRESENCE_ONLINE, KOE_TRANSPORT_WIFI_DIRECT);
    CHECK(koe_presence_is_online(&table, id.pk) == 1);
    CHECK(koe_presence_get(&table, id.pk) == KOE_PRESENCE_ONLINE);

    koe_presence_update(&table, id.pk, KOE_PRESENCE_AWAY, KOE_TRANSPORT_TCP_RELAY);
    CHECK(koe_presence_get(&table, id.pk) == KOE_PRESENCE_AWAY);

    /* Unknown peer should be offline. */
    uint8_t unknown[KOE_ED25519_PK_LEN] = {0};
    CHECK(koe_presence_get(&table, unknown) == KOE_PRESENCE_OFFLINE);
    return 0;
}

/* ---------------------------------------------------------------------- */
/* Tests: media MIME detection                                              */
/* ---------------------------------------------------------------------- */

static int test_media_mime(void)
{
    CHECK(strcmp(koe_media_mime_from_extension("photo.jpg"),   "image/jpeg")  == 0);
    CHECK(strcmp(koe_media_mime_from_extension("video.mp4"),   "video/mp4")   == 0);
    CHECK(strcmp(koe_media_mime_from_extension("README.md"),   "text/markdown") == 0);
    CHECK(strcmp(koe_media_mime_from_extension("archive.zip"), "application/zip") == 0);
    CHECK(strcmp(koe_media_mime_from_extension("unknown.xyz"), "application/octet-stream") == 0);
    return 0;
}

/* ---------------------------------------------------------------------- */
/* Runner                                                                   */
/* ---------------------------------------------------------------------- */

int main(void)
{
    puts("\nkoe-core test suite v" KOE_VERSION_STRING);
    puts("═══════════════════════════════════════════════════════════════");

    /* Version */
    run("version: local version matches build constants",     test_version_local);
    run("version: same major always compatible",              test_version_compatible_same_major);
    run("version: v0.x <-> v1.0 compatible (adjacent)",      test_version_compatible_adjacent_ok);
    run("version: v0.9 <-> v1.1 NOT compatible",             test_version_compatible_adjacent_fail);
    run("version: two majors apart NOT compatible",           test_version_compatible_two_major_apart);

    /* Crypto */
    run("crypto: libsodium init",                             test_crypto_init);
    run("crypto: Ed25519 keypair generation",                 test_identity_generate);
    run("crypto: sign and verify",                            test_sign_verify);
    run("crypto: XChaCha20-Poly1305 encrypt/decrypt",         test_encrypt_decrypt);
    run("crypto: nonce uniqueness",                           test_nonce_unique);
    run("crypto: short ID derivation",                        test_short_id);
    run("crypto: 6-digit verification token",                 test_verify_token);
    run("crypto: identity save and load (Argon2id)",          test_identity_save_load);

    /* Packet */
    run("packet: header size is 106 bytes",                   test_packet_header_size);
    run("packet: magic bytes 'KOE\\x01'",                    test_packet_magic);
    run("packet: serialise/deserialise roundtrip",            test_packet_serialise_roundtrip);
    run("packet: checksum detects corruption",                test_packet_checksum_detects_corruption);

    /* Handshake */
    run("handshake: full two-round X25519 exchange",          test_handshake_full);

    /* Message */
    run("message: alloc and free",                            test_message_alloc_free);
    run("message: Ed25519 sign and verify",                   test_message_sign_verify);
    run("message: encrypt and decrypt over real session",     test_message_encrypt_decrypt);
    run("message: self-destruct timer logic",                 test_message_self_destruct);
    run("message: scheduled delivery check",                  test_message_schedule);

    /* Ghost */
    run("ghost: enable/disable, packet filter rules",         test_ghost_mode);

    /* Revocation */
    run("revoke: build and verify cross-signature",           test_revoke);

    /* Account */
    run("account: registry create and deactivate",            test_account_registry);

    /* Presence */
    run("presence: update, query, offline unknown peer",      test_presence);

    /* Media */
    run("media: MIME type detection from extension",          test_media_mime);

    puts("═══════════════════════════════════════════════════════════════");
    printf("%d passed, %d failed\n\n", s_pass, s_fail);
    return s_fail > 0 ? 1 : 0;
}
