/*
 * cmd/antsd/util.h — small file-I/O + formatting helpers shared by the
 * antsd commands. Daemon-side only: the protocol libraries stay
 * I/O-free and log-free by convention; anything that touches the
 * filesystem or renders for humans lives here.
 */
#ifndef ANTSD_UTIL_H
#define ANTSD_UTIL_H

#include <stddef.h>
#include <stdint.h>

/* Read up to `cap` bytes of `path` into `buf`; *out_len gets the count.
 * Returns -1 on open/read error or if the file exceeds `cap`. */
int antsd_read_file(const char *path, uint8_t *buf, size_t cap, size_t *out_len);

/* Render `n` bytes as lowercase hex into `out` (capacity `cap`). Always
 * NUL-terminates; truncates at whole bytes if cap < 2*n + 1. */
void antsd_hex_format(const uint8_t *bytes, size_t n, char *out, size_t cap);

#endif /* ANTSD_UTIL_H */
