#define _POSIX_C_SOURCE 200809L

#include "util.h"

#include <fcntl.h>
#include <unistd.h>

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

int antsd_read_random(uint8_t *buf, size_t n)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    int rc = read_exact(fd, buf, n);
    close(fd);
    return rc;
}

int antsd_read_file(const char *path, uint8_t *buf, size_t cap, size_t *out_len)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    size_t got = 0;
    for (;;) {
        if (got == cap) {
            /* One more byte would overflow → file too large. */
            uint8_t extra;
            ssize_t r = read(fd, &extra, 1);
            close(fd);
            return r == 0 ? (int)(*out_len = got, 0) : -1;
        }
        ssize_t r = read(fd, buf + got, cap - got);
        if (r < 0) {
            close(fd);
            return -1;
        }
        if (r == 0) {
            break;
        }
        got += (size_t)r;
    }
    close(fd);
    *out_len = got;
    return 0;
}

void antsd_hex_format(const uint8_t *bytes, size_t n, char *out, size_t cap)
{
    static const char digits[] = "0123456789abcdef";
    size_t o = 0;
    for (size_t i = 0; i < n && o + 2 < cap; i++) {
        out[o++] = digits[bytes[i] >> 4];
        out[o++] = digits[bytes[i] & 0x0F];
    }
    if (cap > 0) {
        out[o] = '\0';
    }
}

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

int antsd_hex_parse(const char *hex, uint8_t *out, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (hex[2 * i] == '\0' || hex[2 * i + 1] == '\0') {
            return -1;
        }
        int hi = hex_nibble(hex[2 * i]);
        int lo = hex_nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            return -1;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return hex[2 * n] == '\0' ? 0 : -1;
}
