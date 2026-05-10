#include "koe_session.h"
#include "koe_crypto.h"
#include <stdio.h>
#include <string.h>

static int pass = 0, fail = 0;

#define CHECK(cond) \
    do { if (!(cond)) { \
        printf("  FAIL  %s:%d\n", __FILE__, __LINE__); \
        fail++; \
        return -1; \
    } } while (0)

static int test_session_table_init(void)
{
    koe_session_table_t tbl;
    koe_session_table_init(&tbl);
    CHECK(tbl.count == 0);
    pass++;
    return 0;
}

static int test_session_table_add(void)
{
    koe_session_table_t tbl;
    koe_session_table_init(&tbl);

    uint8_t pk[KOE_ED25519_PK_LEN] = {1, 2, 3};
    koe_session_t sess = {0};
    sess.tx_key[0] = 0xAA;
    sess.rx_key[0] = 0xBB;

    CHECK(koe_session_table_add(&tbl, pk, &sess) == 0);
    CHECK(tbl.count == 1);
    pass++;
    return 0;
}

static int test_session_table_find(void)
{
    koe_session_table_t tbl;
    koe_session_table_init(&tbl);

    uint8_t pk[KOE_ED25519_PK_LEN] = {1, 2, 3};
    koe_session_t sess = {0};
    sess.tx_key[0] = 0xAA;
    sess.rx_key[0] = 0xBB;

    koe_session_table_add(&tbl, pk, &sess);

    koe_session_t *found = koe_session_table_find(&tbl, pk);
    CHECK(found != NULL);
    CHECK(found->tx_key[0] == 0xAA);
    CHECK(found->rx_key[0] == 0xBB);
    pass++;
    return 0;
}

static int test_session_table_not_found(void)
{
    koe_session_table_t tbl;
    koe_session_table_init(&tbl);

    uint8_t pk[KOE_ED25519_PK_LEN] = {1, 2, 3};
    uint8_t other_pk[KOE_ED25519_PK_LEN] = {9, 9, 9};

    koe_session_t sess = {0};
    koe_session_table_add(&tbl, pk, &sess);

    koe_session_t *found = koe_session_table_find(&tbl, other_pk);
    CHECK(found == NULL);
    pass++;
    return 0;
}

static int test_session_table_remove(void)
{
    koe_session_table_t tbl;
    koe_session_table_init(&tbl);

    uint8_t pk[KOE_ED25519_PK_LEN] = {1, 2, 3};
    koe_session_t sess = {0};

    koe_session_table_add(&tbl, pk, &sess);
    CHECK(tbl.count == 1);

    koe_session_table_remove(&tbl, pk);
    CHECK(tbl.count == 0);

    koe_session_t *found = koe_session_table_find(&tbl, pk);
    CHECK(found == NULL);
    pass++;
    return 0;
}

static int test_session_table_max(void)
{
    koe_session_table_t tbl;
    koe_session_table_init(&tbl);

    for (int i = 0; i < KOE_MAX_SESSIONS; i++) {
        uint8_t pk[KOE_ED25519_PK_LEN] = {0};
        pk[0] = i;
        koe_session_t sess = {0};
        int rc = koe_session_table_add(&tbl, pk, &sess);
        if (rc != 0) {
            printf("  FAIL  could not add session %d\n", i);
            fail++;
            return -1;
        }
    }

    CHECK(tbl.count == KOE_MAX_SESSIONS);

    uint8_t new_pk[KOE_ED25519_PK_LEN] = {0xFF};
    koe_session_t sess = {0};
    CHECK(koe_session_table_add(&tbl, new_pk, &sess) != 0);

    pass++;
    return 0;
}

static int run(const char *name, int (*fn)(void))
{
    printf("  %-50s ", name);
    fflush(stdout);
    int rc = fn();
    if (rc == 0) { puts("PASS"); }
    else         { puts("FAIL"); }
    return rc;
}

int main(void)
{
    puts("koe-session test suite\n");

    run("session: table init", test_session_table_init);
    run("session: table add", test_session_table_add);
    run("session: table find", test_session_table_find);
    run("session: table not found", test_session_table_not_found);
    run("session: table remove", test_session_table_remove);
    run("session: table max capacity", test_session_table_max);

    printf("\n========================================\n");
    printf("Results: %d passed, %d failed\n", pass, fail);
    printf("========================================\n");

    return fail > 0 ? 1 : 0;
}