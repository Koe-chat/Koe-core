#include "koe.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

static void print_hex(const char *label, const uint8_t *data, size_t len)
{
    printf("%s: ", label);
    for (size_t i = 0; i < len && i < 16; i++) {
        printf("%02x", data[i]);
    }
    if (len > 16) printf("...");
    printf("\n");
}

int main(void)
{
    printf("=== Koe Message Send Example ===\n\n");

    koe_crypto_init();

    koe_identity_t alice, bob;
    koe_identity_generate(&alice);
    koe_identity_generate(&bob);

    print_hex("Alice", alice.pk, 32);
    print_hex("Bob", bob.pk, 32);

    printf("\n--- Handshake: Alice -> Bob ---\n");

    koe_handshake_t hs_a;
    koe_packet_t hello;
    koe_handshake_init(&hs_a, &hello, &alice, bob.pk);

    printf("HELLO created (type=%d, len=%u)\n", hello.header.type, hello.header.length);

    koe_handshake_t hs_b;
    koe_packet_t hello_ack;
    koe_handshake_respond(&hs_b, &hello_ack, &hello, &bob);

    printf("HELLO_ACK created (type=%d, len=%u)\n", hello_ack.header.type, hello_ack.header.length);

    koe_handshake_finalise(&hs_a, &hello_ack, &alice);

    printf("Session established!\n");

    print_hex("Alice tx_key", hs_a.session.tx_key, 8);
    print_hex("Alice rx_key", hs_a.session.rx_key, 8);

    printf("\n--- Session table ---\n");

    koe_session_table_t sessions;
    koe_session_table_init(&sessions);
    koe_session_table_add(&sessions, bob.pk, &hs_a.session);

    koe_session_t *sess = koe_session_table_find(&sessions, bob.pk);
    if (sess) {
        printf("Session found with Bob!\n");
    }

    printf("\n--- Send message ---\n");

    const char *msg_text = "Hello Bob! This is Alice.";
    koe_message_t *msg = koe_message_alloc(KOE_MSG_TEXT, bob.pk,
                                           (const uint8_t *)msg_text, strlen(msg_text));
    memcpy(msg->from, alice.pk, 32);
    koe_message_sign(msg, &alice);

    printf("Message: %s\n", msg_text);

    koe_packet_t pkt;
    int rc = koe_message_encrypt(msg, sess, &pkt);
    if (rc == 0) {
        printf("Encrypted! Packet type=%d, length=%u\n", pkt.header.type, pkt.header.length);

        printf("\n--- Receive and decrypt ---\n");

        koe_message_t recv_msg = {0};
        rc = koe_message_decrypt(&recv_msg, &pkt, &hs_b.session);
        if (rc == 0) {
            printf("Decrypted message: %.*s\n", (int)recv_msg.body_len, recv_msg.body);
        } else {
            printf("Decrypt failed!\n");
        }

        if (recv_msg.body) free(recv_msg.body);
        koe_packet_free(&pkt);
    } else {
        printf("Encrypt failed!\n");
    }

    koe_message_free(msg);

    printf("\n=== Success! ===\n");

    return 0;
}