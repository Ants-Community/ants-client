/*
 * cmd/antsd/receipts.c — the node's receipt bag on disk (see receipts.h).
 */
#define _POSIX_C_SOURCE 200809L

#include "receipts.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* The largest record: 2-byte length, the largest body, two signatures. */
#define RECEIPT_RECORD_MAX (2u + ANTS_REP_RECEIPT_BODY_ENCODED_MAX + 2u * ANTS_REP_SIG_SIZE)

/* ---- the paid-nonce set -------------------------------------------------- */

/* Nonces are BLAKE3 output: their first 8 bytes are already a good hash. */
static size_t nonce_slot(const uint8_t nonce[ANTS_REP_NONCE_SIZE], size_t cap)
{
    uint64_t h = 0;
    memcpy(&h, nonce, sizeof h);
    return (size_t)h & (cap - 1u);
}

static bool nonce_is_empty(const uint8_t n[ANTS_REP_NONCE_SIZE])
{
    static const uint8_t zero[ANTS_REP_NONCE_SIZE] = {0};
    return memcmp(n, zero, ANTS_REP_NONCE_SIZE) == 0;
}

/* Slot i of a nonce set. */
#define SLOT(set, i) ((set) + (size_t)(i) * ANTS_REP_NONCE_SIZE)

bool antsd_receipts_paid(const antsd_receipts_t *r, const uint8_t nonce[ANTS_REP_NONCE_SIZE])
{
    size_t i;
    if (r == NULL || r->paid_cap == 0) {
        return false;
    }
    for (i = nonce_slot(nonce, r->paid_cap);; i = (i + 1u) & (r->paid_cap - 1u)) {
        if (nonce_is_empty(SLOT(r->paid, i))) {
            return false;
        }
        if (memcmp(SLOT(r->paid, i), nonce, ANTS_REP_NONCE_SIZE) == 0) {
            return true;
        }
    }
}

/* Insert without growing (cap > n). The all-zero nonce marks an empty slot;
 * a genuine all-zero nonce (a 2^-128 event) is simply not remembered. */
static void paid_put(uint8_t *set, size_t cap, size_t *n, const uint8_t nonce[ANTS_REP_NONCE_SIZE])
{
    size_t i;
    if (nonce_is_empty(nonce)) {
        return;
    }
    for (i = nonce_slot(nonce, cap);; i = (i + 1u) & (cap - 1u)) {
        if (nonce_is_empty(SLOT(set, i))) {
            memcpy(SLOT(set, i), nonce, ANTS_REP_NONCE_SIZE);
            (*n)++;
            return;
        }
        if (memcmp(SLOT(set, i), nonce, ANTS_REP_NONCE_SIZE) == 0) {
            return;
        }
    }
}

/* Remember `nonce`, doubling the table at half load. Returns false only on
 * allocation failure (the nonce is then not remembered). */
static bool paid_add(antsd_receipts_t *r, const uint8_t nonce[ANTS_REP_NONCE_SIZE])
{
    if (r->paid_cap == 0 || 2u * (r->paid_n + 1u) > r->paid_cap) {
        size_t cap = r->paid_cap == 0 ? 1024u : 2u * r->paid_cap;
        uint8_t *set = (uint8_t *)calloc(cap, ANTS_REP_NONCE_SIZE);
        size_t n = 0;
        size_t i;
        if (set == NULL) {
            return false;
        }
        for (i = 0; i < r->paid_cap; i++) {
            paid_put(set, cap, &n, SLOT(r->paid, i));
        }
        free(r->paid);
        r->paid = set;
        r->paid_cap = cap;
        r->paid_n = n;
    }
    paid_put(r->paid, r->paid_cap, &r->paid_n, nonce);
    return true;
}

void antsd_receipts_close(antsd_receipts_t *r)
{
    if (r != NULL) {
        free(r->paid);
        r->paid = NULL;
        r->paid_cap = 0;
        r->paid_n = 0;
    }
}

/* ---- the bag ----------------------------------------------------------- */

/* Keep `rc` as the newest receipt, dropping the oldest when full. */
static void bag_push(antsd_receipts_t *r, const ants_reputation_receipt_t *rc)
{
    if (r->n == ANTS_REP_MAX_RECEIPTS) {
        memmove(&r->bag[0], &r->bag[1], (ANTS_REP_MAX_RECEIPTS - 1u) * sizeof r->bag[0]);
        r->n--;
    }
    r->bag[r->n++] = *rc;
}

ants_error_t antsd_receipts_open(antsd_receipts_t *r,
                                 const char *config_path,
                                 const uint8_t self[ANTS_REP_PEER_ID_SIZE])
{
    uint8_t rec[RECEIPT_RECORD_MAX];
    struct stat st;
    off_t good = 0;
    int fd;
    if (r == NULL || config_path == NULL || self == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    memset(r, 0, sizeof *r);
    if ((size_t)snprintf(r->path, sizeof r->path, "%s.receipts", config_path) >= sizeof r->path) {
        return ANTS_ERROR_INVALID_ARG;
    }
    memcpy(r->self, self, sizeof r->self);

    fd = open(r->path, O_RDWR);
    if (fd < 0) {
        return ANTS_OK; /* no file yet: an empty bag */
    }
    for (;;) {
        ants_reputation_receipt_t rc;
        size_t body_len;
        size_t need;
        bool ok = false;
        ssize_t got = read(fd, rec, 2);
        if (got != 2) {
            break; /* end of file, or a torn length */
        }
        body_len = ((size_t)rec[0] << 8) | rec[1];
        if (body_len == 0 || body_len > ANTS_REP_RECEIPT_BODY_ENCODED_MAX) {
            break; /* not a record: stop rather than misparse the rest */
        }
        need = body_len + 2u * ANTS_REP_SIG_SIZE;
        got = read(fd, rec + 2, need);
        if (got < 0 || (size_t)got != need) {
            break; /* torn final record */
        }
        good += (off_t)(2u + need); /* a well-framed record, valid or not */
        if (ants_reputation_receipt_body_decode(rec + 2, body_len, &rc) != ANTS_OK) {
            r->skipped++;
            continue;
        }
        memcpy(rc.server_sig, rec + 2 + body_len, ANTS_REP_SIG_SIZE);
        memcpy(rc.client_sig, rec + 2 + body_len + ANTS_REP_SIG_SIZE, ANTS_REP_SIG_SIZE);
        if (memcmp(rc.server, r->self, sizeof rc.server) != 0 ||
            ants_reputation_receipt_verify(&rc, &ok) != ANTS_OK || !ok) {
            r->skipped++;
            continue;
        }
        bag_push(r, &rc);
        (void)paid_add(r, rc.nonce);
    }
    /* Cut whatever did not frame, so the next append starts on a record
     * boundary instead of behind garbage. */
    if (fstat(fd, &st) == 0 && st.st_size > good && ftruncate(fd, good) == 0) {
        r->truncated = (size_t)(st.st_size - good);
    }
    close(fd);
    return ANTS_OK;
}

ants_error_t antsd_receipts_add(antsd_receipts_t *r, const ants_reputation_receipt_t *rc)
{
    uint8_t rec[RECEIPT_RECORD_MAX];
    size_t body_len;
    size_t total;
    ssize_t put;
    struct stat st;
    int fd;
    if (r == NULL || rc == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    bag_push(r, rc);
    (void)paid_add(r, rc->nonce);
    if (ants_reputation_receipt_body_encode(
            rc, rec + 2, ANTS_REP_RECEIPT_BODY_ENCODED_MAX, &body_len) != ANTS_OK) {
        return ANTS_ERROR_INVALID_ARG;
    }
    rec[0] = (uint8_t)(body_len >> 8);
    rec[1] = (uint8_t)body_len;
    memcpy(rec + 2 + body_len, rc->server_sig, ANTS_REP_SIG_SIZE);
    memcpy(rec + 2 + body_len + ANTS_REP_SIG_SIZE, rc->client_sig, ANTS_REP_SIG_SIZE);
    total = 2u + body_len + 2u * ANTS_REP_SIG_SIZE;

    /* One write of the whole record: a crash leaves at worst a torn final
     * record, which the next load stops at. 0600, like the config. */
    fd = open(r->path, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (fstat(fd, &st) != 0) {
        close(fd);
        return ANTS_ERROR_INVALID_ARG;
    }
    put = write(fd, rec, total);
    if (put < 0 || (size_t)put != total || fsync(fd) != 0) {
        /* A short write would leave a torn record that every later append
         * sits behind: cut it back off now. */
        (void)ftruncate(fd, st.st_size);
        close(fd);
        return ANTS_ERROR_INVALID_ARG;
    }
    return close(fd) == 0 ? ANTS_OK : ANTS_ERROR_INVALID_ARG;
}

ants_error_t
antsd_receipts_reputation(const antsd_receipts_t *r, uint64_t now, uint64_t *out_a, uint64_t *out_t)
{
    ants_reputation_params_t params;
    ants_error_t err;
    if (r == NULL || out_a == NULL || out_t == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if ((err = ants_reputation_params_default(&params)) != ANTS_OK) {
        return err;
    }
    return ants_reputation_compute(r->self, r->bag, r->n, now, &params, out_a, out_t);
}
