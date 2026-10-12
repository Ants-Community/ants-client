/*
 * test_antsd_config.c — round-trip + strictness tests for the antsd
 * CBOR config codec.
 */
#include "config.h"

#include "ants_common.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            failures++;                                                                            \
            fprintf(stderr, "FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond);                        \
        }                                                                                          \
    } while (0)

static void fill_seed(antsd_seed_t *s, const char *addr, uint8_t tag)
{
    memset(s, 0, sizeof *s);
    memcpy(s->addr, addr, strlen(addr));
    memset(s->peer_id, tag, sizeof s->peer_id);
}

static int configs_equal(const antsd_config_t *a, const antsd_config_t *b)
{
    if (memcmp(a->identity_priv, b->identity_priv, sizeof a->identity_priv) != 0) {
        return 0;
    }
    if (strcmp(a->listen_multiaddr, b->listen_multiaddr) != 0) {
        return 0;
    }
    if (a->seed_count != b->seed_count) {
        return 0;
    }
    for (size_t i = 0; i < a->seed_count; i++) {
        if (strcmp(a->seeds[i].addr, b->seeds[i].addr) != 0) {
            return 0;
        }
        if (memcmp(a->seeds[i].peer_id, b->seeds[i].peer_id, sizeof a->seeds[i].peer_id) != 0) {
            return 0;
        }
    }
    return 1;
}

static void test_roundtrip_full(void)
{
    antsd_config_t in;
    memset(&in, 0, sizeof in);
    for (size_t i = 0; i < sizeof in.identity_priv; i++) {
        in.identity_priv[i] = (uint8_t)(i * 7 + 1);
    }
    memcpy(in.listen_multiaddr,
           "/ip4/127.0.0.1/udp/4242/quic-v1",
           strlen("/ip4/127.0.0.1/udp/4242/quic-v1"));
    fill_seed(&in.seeds[0], "/ip4/10.0.0.1/udp/4001/quic-v1", 0xAA);
    fill_seed(&in.seeds[1], "/ip6/::1/udp/4002/quic-v1", 0xBB);
    in.seed_count = 2;

    uint8_t buf[ANTSD_CONFIG_ENCODED_MAX];
    size_t len;
    ants_error_t rc = antsd_config_encode(&in, buf, sizeof buf, &len);
    CHECK(rc == ANTS_OK);
    CHECK(len > 0 && len <= sizeof buf);

    antsd_config_t out;
    CHECK(antsd_config_decode(buf, len, &out) == ANTS_OK);
    CHECK(configs_equal(&in, &out));
}

static void test_roundtrip_minimal(void)
{
    /* Dial-only (empty listen), no seeds. */
    antsd_config_t in;
    memset(&in, 0, sizeof in);
    in.identity_priv[0] = 0x01;

    uint8_t buf[ANTSD_CONFIG_ENCODED_MAX];
    size_t len;
    CHECK(antsd_config_encode(&in, buf, sizeof buf, &len) == ANTS_OK);

    antsd_config_t out;
    CHECK(antsd_config_decode(buf, len, &out) == ANTS_OK);
    CHECK(out.seed_count == 0);
    CHECK(out.listen_multiaddr[0] == '\0');
    CHECK(configs_equal(&in, &out));
}

static void test_roundtrip_max_seeds(void)
{
    antsd_config_t in;
    memset(&in, 0, sizeof in);
    for (size_t i = 0; i < ANTSD_MAX_SEEDS; i++) {
        char addr[32];
        snprintf(addr, sizeof addr, "/ip4/127.0.0.1/udp/%zu/quic-v1", 5000 + i);
        fill_seed(&in.seeds[i], addr, (uint8_t)i);
    }
    in.seed_count = ANTSD_MAX_SEEDS;

    uint8_t buf[ANTSD_CONFIG_ENCODED_MAX];
    size_t len;
    CHECK(antsd_config_encode(&in, buf, sizeof buf, &len) == ANTS_OK);

    antsd_config_t out;
    CHECK(antsd_config_decode(buf, len, &out) == ANTS_OK);
    CHECK(out.seed_count == ANTSD_MAX_SEEDS);
    CHECK(configs_equal(&in, &out));
}

static void test_encode_rejects_overlong_seed_count(void)
{
    antsd_config_t in;
    memset(&in, 0, sizeof in);
    in.seed_count = ANTSD_MAX_SEEDS + 1;
    uint8_t buf[ANTSD_CONFIG_ENCODED_MAX];
    size_t len;
    CHECK(antsd_config_encode(&in, buf, sizeof buf, &len) == ANTS_ERROR_INVALID_ARG);
}

static void test_encode_rejects_small_buffer(void)
{
    antsd_config_t in;
    memset(&in, 0, sizeof in);
    uint8_t buf[4]; /* far too small for the map */
    size_t len;
    CHECK(antsd_config_encode(&in, buf, sizeof buf, &len) == ANTS_ERROR_BUFFER_TOO_SMALL);
}

static void test_decode_rejects_garbage(void)
{
    antsd_config_t out;
    /* Empty input. */
    CHECK(antsd_config_decode((const uint8_t *)"", 0, &out) != ANTS_OK);
    /* A bare uint, not a map. */
    const uint8_t not_map[] = {0x01};
    CHECK(antsd_config_decode(not_map, sizeof not_map, &out) != ANTS_OK);
    /* A map of the wrong arity (1 entry). */
    const uint8_t map1[] = {0xA1, 0x00, 0x00};
    CHECK(antsd_config_decode(map1, sizeof map1, &out) != ANTS_OK);
}

static void test_decode_rejects_truncated(void)
{
    antsd_config_t in;
    memset(&in, 0, sizeof in);
    memcpy(in.listen_multiaddr,
           "/ip4/127.0.0.1/udp/0/quic-v1",
           strlen("/ip4/127.0.0.1/udp/0/quic-v1"));
    uint8_t buf[ANTSD_CONFIG_ENCODED_MAX];
    size_t len;
    CHECK(antsd_config_encode(&in, buf, sizeof buf, &len) == ANTS_OK);

    antsd_config_t out;
    /* Any prefix shorter than the whole must fail to decode. */
    CHECK(antsd_config_decode(buf, len - 1, &out) != ANTS_OK);
}

static void test_invalid_args(void)
{
    antsd_config_t cfg;
    memset(&cfg, 0, sizeof cfg);
    uint8_t buf[ANTSD_CONFIG_ENCODED_MAX];
    size_t len;
    CHECK(antsd_config_encode(NULL, buf, sizeof buf, &len) == ANTS_ERROR_INVALID_ARG);
    CHECK(antsd_config_encode(&cfg, NULL, sizeof buf, &len) == ANTS_ERROR_INVALID_ARG);
    CHECK(antsd_config_encode(&cfg, buf, sizeof buf, NULL) == ANTS_ERROR_INVALID_ARG);
    CHECK(antsd_config_decode(NULL, 0, &cfg) == ANTS_ERROR_INVALID_ARG);
    CHECK(antsd_config_decode(buf, sizeof buf, NULL) == ANTS_ERROR_INVALID_ARG);
}

static void test_genesis_roundtrip_and_rejects(void)
{
    /* A config carrying the v1 genesis (key 3) round-trips byte-exactly,
     * including at the trustee ceiling; trustees out of order, duplicated
     * or absent are refused on encode, and a hand-corrupted order on
     * decode. A config without genesis still decodes with present = false. */
    antsd_config_t in;
    memset(&in, 0, sizeof in);
    in.identity_priv[0] = 1;
    in.genesis.present = true;
    in.genesis.time = 1735689600;
    memset(in.genesis.hash, 0x47, sizeof in.genesis.hash);
    in.genesis.trustee_count = ANTSD_MAX_TRUSTEES;
    for (size_t i = 0; i < ANTSD_MAX_TRUSTEES; i++) {
        memset(in.genesis.trustees[i], 0, sizeof in.genesis.trustees[i]);
        in.genesis.trustees[i][0] = (uint8_t)(i + 1); /* ascending */
    }
    static uint8_t buf[ANTSD_CONFIG_ENCODED_MAX];
    size_t len;
    CHECK(antsd_config_encode(&in, buf, sizeof buf, &len) == ANTS_OK);
    antsd_config_t out;
    CHECK(antsd_config_decode(buf, len, &out) == ANTS_OK);
    CHECK(out.genesis.present && out.genesis.time == in.genesis.time);
    CHECK(memcmp(out.genesis.hash, in.genesis.hash, 32) == 0);
    CHECK(out.genesis.trustee_count == ANTSD_MAX_TRUSTEES);
    CHECK(memcmp(out.genesis.trustees, in.genesis.trustees, sizeof in.genesis.trustees) == 0);

    /* Decode-side: swap two trustees' leading bytes in the encoded form. */
    uint8_t first = in.genesis.trustees[0][0], second = in.genesis.trustees[1][0];
    size_t at0 = len, at1 = len;
    for (size_t i = 0; i + 34 < len; i++) {
        if (buf[i] == 0x58 && buf[i + 1] == 0x20 && buf[i + 2] == first && at0 == len) {
            at0 = i + 2;
        } else if (buf[i] == 0x58 && buf[i + 1] == 0x20 && buf[i + 2] == second && at0 != len) {
            at1 = i + 2;
            break;
        }
    }
    CHECK(at0 < len && at1 < len);
    buf[at0] = second;
    buf[at1] = first;
    CHECK(antsd_config_decode(buf, len, &out) == ANTS_ERROR_MALFORMED);

    /* Encode-side refusals. */
    in.genesis.trustees[1][0] = in.genesis.trustees[0][0]; /* duplicate */
    CHECK(antsd_config_encode(&in, buf, sizeof buf, &len) == ANTS_ERROR_INVALID_ARG);
    in.genesis.trustees[1][0] = 2;
    in.genesis.trustee_count = 0;
    CHECK(antsd_config_encode(&in, buf, sizeof buf, &len) == ANTS_ERROR_INVALID_ARG);

    /* No genesis: present stays false. */
    in.genesis.present = false;
    CHECK(antsd_config_encode(&in, buf, sizeof buf, &len) == ANTS_OK);
    CHECK(antsd_config_decode(buf, len, &out) == ANTS_OK);
    CHECK(!out.genesis.present);

    /* Trailing bytes after the map are rejected (strict decode). */
    buf[len] = 0x00;
    CHECK(antsd_config_decode(buf, len + 1, &out) != ANTS_OK);
}

int main(void)
{
    test_roundtrip_full();
    test_roundtrip_minimal();
    test_roundtrip_max_seeds();
    test_encode_rejects_overlong_seed_count();
    test_encode_rejects_small_buffer();
    test_decode_rejects_garbage();
    test_decode_rejects_truncated();
    test_invalid_args();
    test_genesis_roundtrip_and_rejects();

    if (failures == 0) {
        printf("all checks passed\n");
        return 0;
    }
    fprintf(stderr, "%d check(s) failed\n", failures);
    return 1;
}
