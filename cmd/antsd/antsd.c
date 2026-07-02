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
 *   antsd run  <config>   — stand up transport + DHT (bootstrapped from
 *                           the config seeds) and drive the tick loop
 *                           until SIGINT/SIGTERM (see run.c)
 *
 * Gossip wiring lands next.
 */
#define _POSIX_C_SOURCE 200809L

#include "config.h"
#include "run.h"
#include "util.h"

#include "ants_common.h"
#include "ants_crypto.h"

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* Default listen address written by `antsd init`: all interfaces, an
 * OS-assigned UDP port, QUIC v1. */
#define ANTSD_DEFAULT_LISTEN "/ip4/0.0.0.0/udp/0/quic-v1"

static int read_exact(int fd, uint8_t *buf, size_t n)
{
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, buf + got, n - got);
        if (r < 0) {
            return -1;
        }
        if (r == 0) {
            return -1; /* unexpected EOF */
        }
        got += (size_t)r;
    }
    return 0;
}

static int read_random(uint8_t *buf, size_t n)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    int rc = read_exact(fd, buf, n);
    close(fd);
    return rc;
}

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

    if (read_random(cfg.identity_priv, sizeof cfg.identity_priv) != 0) {
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
    return 0;
}

static int usage(const char *argv0)
{
    fprintf(stderr,
            "usage: %s <command> <config-path>\n"
            "  init   generate an Ed25519 identity and write a config\n"
            "  show   decode and print a config\n"
            "  run    drive the node event loop until SIGINT/SIGTERM\n",
            argv0);
    return 2;
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        return usage(argv[0]);
    }
    if (strcmp(argv[1], "init") == 0) {
        return cmd_init(argv[2]);
    }
    if (strcmp(argv[1], "show") == 0) {
        return cmd_show(argv[2]);
    }
    if (strcmp(argv[1], "run") == 0) {
        return antsd_cmd_run(argv[2]);
    }
    return usage(argv[0]);
}
