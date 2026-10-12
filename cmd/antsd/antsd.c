/*
 * antsd — the ANTS node daemon.
 *
 * The composing process: it owns all node state (the libraries are
 * caller-owns-memory and never malloc) and drives a single-threaded
 * event loop over the QUIC transport. This is the first non-test
 * executable in the tree.
 *
 *   antsd init <config>   — generate an Ed25519 identity + write a config
 *   antsd show <config>   — decode + print a config (CBOR is not
 *                           hand-editable, so this is how you read it)
 *   antsd genesis <config> <unix-time> <hash-hex> <trustee-hex>...
 *                         — write the v1 genesis (RFC-0004 §"Block
 *                           production runtime") into a config; trustees
 *                           are sorted, duplicates refused
 *   antsd archive <config> on|off
 *                         — archive node: never prune the L1 G-Set
 *   antsd run  <config>   — stand up transport + DHT (bootstrapped from
 *                           the config seeds) + gossip (view fed from
 *                           DHT discovery, anti-eclipse epoch refresh)
 *                           + the attestation gate + the L2 chain loop
 *                           (when the config carries a genesis) and
 *                           drive the tick loop until SIGINT/SIGTERM
 *                           (see run.c); the node serves inference
 *                           (RFC-0008 §11.14) with the v1 reference model
 *   antsd receipts <config>
 *                         — the node's receipt bag: count, A and T now
 *   antsd ask <multiaddr> <peer-id-hex> <prompt> [tier]
 *                         — one inference request to a node, the answer
 *                           checked and the verdict printed (see ask.c)
 */
#define _POSIX_C_SOURCE 200809L

#include "ask.h"
#include "config.h"
#include "receipts.h"
#include "run.h"
#include "util.h"

#include "ants_common.h"
#include "ants_crypto.h"

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* Default listen address written by `antsd init`: all interfaces, an
 * OS-assigned UDP port, QUIC v1. */
#define ANTSD_DEFAULT_LISTEN "/ip4/0.0.0.0/udp/0/quic-v1"

static int write_file(const char *path, const uint8_t *buf, size_t len, int mode)
{
    int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, mode);
    if (fd < 0) {
        return -1;
    }
    size_t put = 0;
    while (put < len) {
        ssize_t w = write(fd, buf + put, len - put);
        if (w < 0) {
            close(fd);
            return -1;
        }
        put += (size_t)w;
    }
    return close(fd) == 0 ? 0 : -1;
}

static void print_hex(const char *label, const uint8_t *b, size_t n)
{
    printf("%s", label);
    for (size_t i = 0; i < n; i++) {
        printf("%02x", b[i]);
    }
    printf("\n");
}

static int cmd_init(const char *path)
{
    antsd_config_t cfg;
    memset(&cfg, 0, sizeof cfg);

    if (antsd_read_random(cfg.identity_priv, sizeof cfg.identity_priv) != 0) {
        fprintf(stderr, "antsd: could not read /dev/urandom\n");
        return 1;
    }
    /* Derive the pubkey just to report the node's identity to the operator;
     * the daemon will sign with the private seed. */
    uint8_t pub[ANTS_ED25519_PUBKEY_SIZE];
    ants_error_t rc = ants_ed25519_pubkey_from_priv(cfg.identity_priv, pub);
    if (rc != ANTS_OK) {
        fprintf(stderr, "antsd: key derivation failed: %s\n", ants_strerror(rc));
        return 1;
    }
    memcpy(cfg.listen_multiaddr, ANTSD_DEFAULT_LISTEN, sizeof ANTSD_DEFAULT_LISTEN);
    cfg.seed_count = 0;

    uint8_t enc[ANTSD_CONFIG_ENCODED_MAX];
    size_t enc_len;
    rc = antsd_config_encode(&cfg, enc, sizeof enc, &enc_len);
    if (rc != ANTS_OK) {
        fprintf(stderr, "antsd: config encode failed: %s\n", ants_strerror(rc));
        return 1;
    }
    /* 0600: the file holds the private identity seed. */
    if (write_file(path, enc, enc_len, 0600) != 0) {
        fprintf(stderr, "antsd: could not write %s\n", path);
        return 1;
    }
    printf("antsd: wrote %s (%zu bytes)\n", path, enc_len);
    print_hex("antsd: peer id ", pub, sizeof pub);
    printf("antsd: listen  %s\n", cfg.listen_multiaddr);
    return 0;
}

static int cmd_show(const char *path)
{
    uint8_t buf[ANTSD_CONFIG_ENCODED_MAX];
    size_t len;
    if (antsd_read_file(path, buf, sizeof buf, &len) != 0) {
        fprintf(stderr, "antsd: could not read %s (missing or too large)\n", path);
        return 1;
    }
    antsd_config_t cfg;
    ants_error_t rc = antsd_config_decode(buf, len, &cfg);
    if (rc != ANTS_OK) {
        fprintf(stderr, "antsd: malformed config: %s\n", ants_strerror(rc));
        return 1;
    }
    uint8_t pub[ANTS_ED25519_PUBKEY_SIZE];
    rc = ants_ed25519_pubkey_from_priv(cfg.identity_priv, pub);
    if (rc != ANTS_OK) {
        fprintf(stderr, "antsd: key derivation failed: %s\n", ants_strerror(rc));
        return 1;
    }
    print_hex("peer id: ", pub, sizeof pub);
    printf("listen:  %s\n", cfg.listen_multiaddr[0] ? cfg.listen_multiaddr : "(dial-only)");
    printf("seeds:   %zu\n", cfg.seed_count);
    for (size_t i = 0; i < cfg.seed_count; i++) {
        printf("  [%zu] %s\n", i, cfg.seeds[i].addr);
        print_hex("      peer id ", cfg.seeds[i].peer_id, sizeof cfg.seeds[i].peer_id);
    }
    printf("archive: %s\n", cfg.archive ? "on (L1 never pruned)" : "off");
    if (!cfg.genesis.present) {
        printf("genesis: (none — chain loop off)\n");
        return 0;
    }
    printf("genesis: time %llu\n", (unsigned long long)cfg.genesis.time);
    print_hex("         hash ", cfg.genesis.hash, sizeof cfg.genesis.hash);
    printf("         trustees %zu\n", cfg.genesis.trustee_count);
    for (size_t i = 0; i < cfg.genesis.trustee_count; i++) {
        print_hex("           ", cfg.genesis.trustees[i], sizeof cfg.genesis.trustees[i]);
    }
    return 0;
}

static int cmd_archive(const char *path, const char *mode)
{
    bool on;
    if (strcmp(mode, "on") == 0) {
        on = true;
    } else if (strcmp(mode, "off") == 0) {
        on = false;
    } else {
        fprintf(stderr, "antsd: archive takes on|off\n");
        return 2;
    }
    static uint8_t buf[ANTSD_CONFIG_ENCODED_MAX];
    size_t len;
    if (antsd_read_file(path, buf, sizeof buf, &len) != 0) {
        fprintf(stderr, "antsd: could not read %s (missing or too large)\n", path);
        return 1;
    }
    static antsd_config_t cfg;
    ants_error_t rc = antsd_config_decode(buf, len, &cfg);
    if (rc != ANTS_OK) {
        fprintf(stderr, "antsd: malformed config: %s\n", ants_strerror(rc));
        return 1;
    }
    cfg.archive = on;
    rc = antsd_config_encode(&cfg, buf, sizeof buf, &len);
    if (rc != ANTS_OK || write_file(path, buf, len, 0600) != 0) {
        fprintf(stderr, "antsd: could not write %s\n", path);
        return 1;
    }
    printf("antsd: archive %s in %s\n", on ? "on" : "off", path);
    return 0;
}

static int cmd_receipts(const char *path)
{
    uint8_t buf[ANTSD_CONFIG_ENCODED_MAX];
    size_t len;
    if (antsd_read_file(path, buf, sizeof buf, &len) != 0) {
        fprintf(stderr, "antsd: could not read %s (missing or too large)\n", path);
        return 1;
    }
    antsd_config_t cfg;
    ants_error_t rc = antsd_config_decode(buf, len, &cfg);
    memset(buf, 0, sizeof buf);
    if (rc != ANTS_OK) {
        fprintf(stderr, "antsd: malformed config: %s\n", ants_strerror(rc));
        return 1;
    }
    uint8_t pub[ANTS_ED25519_PUBKEY_SIZE];
    rc = ants_ed25519_pubkey_from_priv(cfg.identity_priv, pub);
    memset(cfg.identity_priv, 0, sizeof cfg.identity_priv);
    if (rc != ANTS_OK) {
        fprintf(stderr, "antsd: key derivation failed: %s\n", ants_strerror(rc));
        return 1;
    }
    static antsd_receipts_t bag; /* ~1 MB — static */
    if (antsd_receipts_open(&bag, path, pub) != ANTS_OK) {
        fprintf(stderr, "antsd: bad receipts path for %s\n", path);
        return 1;
    }
    uint64_t a = 0;
    uint64_t t = 0;
    (void)antsd_receipts_reputation(&bag, (uint64_t)time(NULL), &a, &t);
    printf("receipts: %zu (%zu skipped, %zu torn bytes cut) in %s\n",
           bag.n,
           bag.skipped,
           bag.truncated,
           bag.path);
    printf("A:        %llu uNCS\n", (unsigned long long)a);
    printf("T:        %llu uNCS\n", (unsigned long long)t);
    antsd_receipts_close(&bag);
    return 0;
}

static int cmp_trustee(const void *a, const void *b)
{
    return memcmp(a, b, ANTS_ED25519_PUBKEY_SIZE);
}

static int cmd_genesis(const char *path, int n_args, char **args)
{
    /* args: <unix-time> <hash-hex> <trustee-hex>... */
    if (n_args < 3) {
        fprintf(stderr, "antsd: genesis needs <unix-time> <hash-hex> <trustee-hex>...\n");
        return 2;
    }
    static uint8_t buf[ANTSD_CONFIG_ENCODED_MAX];
    size_t len;
    if (antsd_read_file(path, buf, sizeof buf, &len) != 0) {
        fprintf(stderr, "antsd: could not read %s (missing or too large)\n", path);
        return 1;
    }
    static antsd_config_t cfg;
    ants_error_t rc = antsd_config_decode(buf, len, &cfg);
    if (rc != ANTS_OK) {
        fprintf(stderr, "antsd: malformed config: %s\n", ants_strerror(rc));
        return 1;
    }
    char *end = NULL;
    unsigned long long t = strtoull(args[0], &end, 10);
    if (end == args[0] || *end != '\0') {
        fprintf(stderr, "antsd: bad genesis time %s\n", args[0]);
        return 2;
    }
    antsd_genesis_t g;
    memset(&g, 0, sizeof g);
    g.present = true;
    g.time = (uint64_t)t;
    if (antsd_hex_parse(args[1], g.hash, sizeof g.hash) != 0) {
        fprintf(stderr, "antsd: genesis hash must be 64 hex digits\n");
        return 2;
    }
    size_t n = (size_t)(n_args - 2);
    if (n > ANTSD_MAX_TRUSTEES) {
        fprintf(stderr, "antsd: at most %d trustees\n", ANTSD_MAX_TRUSTEES);
        return 2;
    }
    for (size_t i = 0; i < n; i++) {
        if (antsd_hex_parse(args[2 + i], g.trustees[i], sizeof g.trustees[i]) != 0) {
            fprintf(stderr, "antsd: trustee %s is not 64 hex digits\n", args[2 + i]);
            return 2;
        }
    }
    g.trustee_count = n;
    qsort(g.trustees, n, sizeof g.trustees[0], cmp_trustee);
    if (!antsd_genesis_trustees_valid(&g)) {
        fprintf(stderr, "antsd: duplicate trustee\n");
        return 2;
    }
    cfg.genesis = g;
    rc = antsd_config_encode(&cfg, buf, sizeof buf, &len);
    if (rc != ANTS_OK) {
        fprintf(stderr, "antsd: config encode failed: %s\n", ants_strerror(rc));
        return 1;
    }
    if (write_file(path, buf, len, 0600) != 0) {
        fprintf(stderr, "antsd: could not write %s\n", path);
        return 1;
    }
    printf("antsd: genesis written to %s (%zu trustees)\n", path, n);
    return 0;
}

static int usage(const char *argv0)
{
    fprintf(stderr,
            "usage: %s <command> <config-path> [args]\n"
            "  init     generate an Ed25519 identity and write a config\n"
            "  show     decode and print a config\n"
            "  genesis  <config> <unix-time> <hash-hex> <trustee-hex>...\n"
            "           write the v1 chain genesis into a config\n"
            "  archive  <config> on|off\n"
            "           archive node: never prune the L1 G-Set\n"
            "  run      drive the node event loop until SIGINT/SIGTERM\n"
            "  receipts the node's receipt bag: count, A and T now\n"
            "  ask      <multiaddr> <peer-id-hex> <prompt> [tier]\n"
            "           ask a node for an inference answer (tier 1..3, default 2)\n",
            argv0);
    return 2;
}

int main(int argc, char **argv)
{
    if ((argc == 5 || argc == 6) && strcmp(argv[1], "ask") == 0) {
        unsigned long tier = 2;
        if (argc == 6) {
            char *end = NULL;
            tier = strtoul(argv[5], &end, 10);
            if (end == argv[5] || *end != '\0' || tier > 255) {
                fprintf(stderr, "antsd: bad tier %s\n", argv[5]);
                return 2;
            }
        }
        return antsd_cmd_ask(argv[2], argv[3], argv[4], (unsigned)tier);
    }
    if (argc == 4 && strcmp(argv[1], "archive") == 0) {
        return cmd_archive(argv[2], argv[3]);
    }
    if (argc >= 3 && strcmp(argv[1], "genesis") == 0) {
        return cmd_genesis(argv[2], argc - 3, argv + 3);
    }
    if (argc != 3) {
        return usage(argv[0]);
    }
    if (strcmp(argv[1], "init") == 0) {
        return cmd_init(argv[2]);
    }
    if (strcmp(argv[1], "show") == 0) {
        return cmd_show(argv[2]);
    }
    if (strcmp(argv[1], "receipts") == 0) {
        return cmd_receipts(argv[2]);
    }
    if (strcmp(argv[1], "run") == 0) {
        return antsd_cmd_run(argv[2]);
    }
    return usage(argv[0]);
}
