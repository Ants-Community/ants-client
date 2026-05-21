/*
 * transport.c — P2P transport implementation against vendored picoquic.
 *
 * Phase 1 (this PR): init + destroy + size check. The remaining
 * functions still return NOT_IMPLEMENTED while we wire them
 * incrementally in subsequent PRs (phase 2 = tick+dial+listener,
 * phase 3 = streams+loopback test).
 *
 * Layout: the caller's opaque ants_transport_t buffer holds a
 * `struct ants_transport_state` (defined here, not exposed) whose
 * first field is the picoquic_quic_t pointer. Compile-time check at
 * the bottom of this file asserts the state fits in
 * ANTS_TRANSPORT_CTX_SIZE.
 *
 * Same opaque-context discipline as foundation/crypto's
 * ants_blake3_ctx_t and foundation/tee.
 */

#include "ants_transport.h"

#include "picoquic.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if defined(_WIN32) || defined(_WIN64)
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET ants_socket_t;
#define ANTS_INVALID_SOCKET INVALID_SOCKET
#else
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
typedef int ants_socket_t;
#define ANTS_INVALID_SOCKET (-1)
#endif

/* Receive buffer per tick(): one MTU per syscall is the typical
 * picoquic upper-bound packet size. We loop draining the socket until
 * recvfrom() blocks (EAGAIN). */
#define ANTS_TRANSPORT_MTU 1500

/* Max packets prepared per tick before yielding control back to the
 * caller. Prevents a tick() from starving the embedding event loop if
 * the QUIC ctx has many pending packets to drain. */
#define ANTS_TRANSPORT_MAX_PACKETS_PER_TICK 32

/* ------------------------------------------------------------------------ */
/* Internal state                                                           */
/*                                                                          */
/* The public ants_transport_t is a uint8_t[16384] union; we cast it to    */
/* this internal struct. Adding fields is safe up to ~16 KB; the           */
/* compile-time assert at the bottom catches overrun.                       */
/* ------------------------------------------------------------------------ */

struct ants_transport_state {
    /* The vendored picoquic QUIC context. Allocated by picoquic_create
     * in init; freed by picoquic_free in destroy. */
    picoquic_quic_t *quic;

    /* Snapshot of the caller's local identity. Copied so the caller may
     * free its config after init. */
    uint8_t pub[ANTS_ED25519_PUBKEY_SIZE];

    /* Caller's sign callback + opaque cookie. Invoked by picotls during
     * the TLS 1.3 handshake to sign the transcript. */
    ants_transport_sign_fn sign_fn;
    void *sign_ctx;

    /* Caller's event callback + opaque cookie. Phase 2 will invoke this
     * from inside ants_transport_tick(); phase 1 just stores it. */
    ants_transport_event_fn event_fn;
    void *event_ctx;

    /* Connection / stream budget caps from the config. */
    uint32_t max_connections;
    uint32_t max_streams_per_conn;
    uint32_t idle_timeout_ms;

    /* Listening UDP socket. ANTS_INVALID_SOCKET when listen_multiaddr
     * was NULL (dial-only client). */
    ants_socket_t sock_fd;
    /* Local bound address. Captured for ants_transport_conn_peer_addr
     * symmetry and for echoing back in outgoing packet sendto(). */
    struct sockaddr_storage local_addr;
    socklen_t local_addr_len;
};

/* ants_transport_t MUST be at least as large as the internal state
 * struct. The trick: declare a typedef whose array size is -1 (an
 * invalid type) when the condition fails. C99 compile error then
 * surfaces at build time rather than corrupting memory at run time.
 * Same pattern as ants_blake3_ctx_size_check in foundation/crypto. */
typedef char ants_transport_state_size_check
    [(sizeof(struct ants_transport_state) <= sizeof(((ants_transport_t *)0)->_opaque)) ? 1 : -1];

/* ------------------------------------------------------------------------ */
/* Multiaddr parser                                                         */
/*                                                                          */
/* Accepts the libp2p textual form:                                         */
/*   /ip4/A.B.C.D/udp/PORT/quic-v1                                          */
/*   /ip6/AAAA::BB/udp/PORT/quic-v1                                        */
/*                                                                          */
/* Phase 2 needs only the address+port; the /p2p/<peer_id> trailer is       */
/* parsed by callers (it's already in expected_peer_id when present).      */
/* ------------------------------------------------------------------------ */

static ants_error_t
parse_multiaddr(const char *ma, struct sockaddr_storage *out, socklen_t *out_len)
{
    if (ma == NULL || out == NULL || out_len == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    memset(out, 0, sizeof *out);

    /* Expect leading "/ip4/" or "/ip6/" prefix. */
    const char *p = ma;
    int is_ip6;
    if (strncmp(p, "/ip4/", 5) == 0) {
        is_ip6 = 0;
        p += 5;
    } else if (strncmp(p, "/ip6/", 5) == 0) {
        is_ip6 = 1;
        p += 5;
    } else {
        return ANTS_ERROR_INVALID_ARG;
    }

    /* Address ends at the next '/'. Cap at 64 bytes (more than enough
     * for IPv6 textual form which is 39 chars max). */
    char addr_buf[64];
    size_t i = 0;
    while (*p && *p != '/' && i + 1 < sizeof addr_buf) {
        addr_buf[i++] = *p++;
    }
    if (*p != '/' || i == 0) {
        return ANTS_ERROR_INVALID_ARG;
    }
    addr_buf[i] = '\0';
    p++; /* skip '/' */

    /* Expect "udp/" next. */
    if (strncmp(p, "udp/", 4) != 0) {
        return ANTS_ERROR_INVALID_ARG;
    }
    p += 4;

    /* Parse port (1-5 digits). */
    unsigned long port = 0;
    if (*p < '0' || *p > '9') {
        return ANTS_ERROR_INVALID_ARG;
    }
    while (*p >= '0' && *p <= '9') {
        port = port * 10 + (unsigned long)(*p - '0');
        if (port > 65535) {
            return ANTS_ERROR_INVALID_ARG;
        }
        p++;
    }

    /* Expect "/quic-v1" trailer (or end of string for a port-only
     * variant — we accept both). */
    if (*p == '/') {
        if (strncmp(p, "/quic-v1", 8) != 0) {
            return ANTS_ERROR_INVALID_ARG;
        }
        p += 8;
        /* Ignore anything after /quic-v1 (e.g. /p2p/...); peer-id is
         * passed via the expected_peer_id parameter when needed. */
    }

    if (is_ip6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)out;
        sin6->sin6_family = AF_INET6;
        if (inet_pton(AF_INET6, addr_buf, &sin6->sin6_addr) != 1) {
            return ANTS_ERROR_INVALID_ARG;
        }
        sin6->sin6_port = htons((uint16_t)port);
        *out_len = sizeof(struct sockaddr_in6);
    } else {
        struct sockaddr_in *sin = (struct sockaddr_in *)out;
        sin->sin_family = AF_INET;
        if (inet_pton(AF_INET, addr_buf, &sin->sin_addr) != 1) {
            return ANTS_ERROR_INVALID_ARG;
        }
        sin->sin_port = htons((uint16_t)port);
        *out_len = sizeof(struct sockaddr_in);
    }
    return ANTS_OK;
}

/* ------------------------------------------------------------------------ */
/* Socket helpers                                                           */
/* ------------------------------------------------------------------------ */

static int set_nonblocking(ants_socket_t fd)
{
#if defined(_WIN32) || defined(_WIN64)
    u_long mode = 1;
    return ioctlsocket(fd, FIONBIO, &mode) == 0 ? 0 : -1;
#else
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#endif
}

static void close_socket(ants_socket_t fd)
{
    if (fd == ANTS_INVALID_SOCKET) {
        return;
    }
#if defined(_WIN32) || defined(_WIN64)
    closesocket(fd);
#else
    close(fd);
#endif
}

static ants_error_t bind_listen_socket(struct ants_transport_state *state, const char *multiaddr)
{
    struct sockaddr_storage addr;
    socklen_t addr_len;
    ants_error_t err = parse_multiaddr(multiaddr, &addr, &addr_len);
    if (err != ANTS_OK) {
        return err;
    }

    state->sock_fd = socket(addr.ss_family, SOCK_DGRAM, IPPROTO_UDP);
    if (state->sock_fd == ANTS_INVALID_SOCKET) {
        return ANTS_ERROR_PEER_UNREACHABLE;
    }
    if (bind(state->sock_fd, (const struct sockaddr *)&addr, addr_len) != 0) {
        close_socket(state->sock_fd);
        state->sock_fd = ANTS_INVALID_SOCKET;
        return ANTS_ERROR_PEER_UNREACHABLE;
    }
    if (set_nonblocking(state->sock_fd) != 0) {
        close_socket(state->sock_fd);
        state->sock_fd = ANTS_INVALID_SOCKET;
        return ANTS_ERROR_PEER_UNREACHABLE;
    }

    /* Capture the actually-bound address (port may have been kernel-
     * assigned via port 0). */
    state->local_addr_len = sizeof state->local_addr;
    if (getsockname(
            state->sock_fd, (struct sockaddr *)&state->local_addr, &state->local_addr_len) != 0) {
        close_socket(state->sock_fd);
        state->sock_fd = ANTS_INVALID_SOCKET;
        return ANTS_ERROR_PEER_UNREACHABLE;
    }
    return ANTS_OK;
}

/* ------------------------------------------------------------------------ */
/* Lifecycle                                                                */
/* ------------------------------------------------------------------------ */

ants_error_t ants_transport_init(ants_transport_t *t, const ants_transport_config_t *config)
{
    if (t == NULL || config == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    /* Required fields: sign_fn (TLS handshake signatures) and event_fn
     * (the only way the caller learns about I/O events). Both must be
     * non-NULL. The pub key is required so peers can identify us during
     * the handshake (raw-pubkey TLS per RFC 7250). */
    if (config->sign_fn == NULL || config->event_fn == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }

    struct ants_transport_state *state = (struct ants_transport_state *)(void *)t->_opaque;
    /* Zero the entire opaque buffer so any later fields default to
     * well-defined values; the picoquic pointer is then explicitly
     * NULL until create() succeeds. */
    memset(t->_opaque, 0, sizeof t->_opaque);
    state->sock_fd = ANTS_INVALID_SOCKET;

    /* Snapshot identity + callbacks. */
    memcpy(state->pub, config->pub, ANTS_ED25519_PUBKEY_SIZE);
    state->sign_fn = config->sign_fn;
    state->sign_ctx = config->sign_ctx;
    state->event_fn = config->event_fn;
    state->event_ctx = config->event_ctx;
    state->max_connections = config->max_connections;
    state->max_streams_per_conn = config->max_streams_per_conn;
    state->idle_timeout_ms = config->idle_timeout_ms;

    /* Create the picoquic context.
     *
     * Phase-1 caveats (lifted in phase 2/3):
     *   - cert/key files are NULL. We will plumb RFC 7250 raw-pubkey
     *     TLS via picotls in phase 2, when dial/listener wire-up
     *     requires real TLS material.
     *   - default callback is NULL. Phase 3 will register the bridge
     *     that translates picoquic stream events to ants_transport_event_t.
     *   - reset_seed is zeroed. Production callers will supply a real
     *     16-byte secret; phase 1 doesn't accept connections so this
     *     doesn't matter yet.
     *
     * max_connections=0 in the config means "unbounded" to us, but
     * picoquic requires a positive bound. Default to 1024 in that case. */
    uint32_t max_cnx = (config->max_connections == 0) ? 1024 : config->max_connections;
    uint8_t reset_seed[PICOQUIC_RESET_SECRET_SIZE] = {0};
    uint64_t current_time = picoquic_current_time();

    state->quic = picoquic_create(max_cnx,
                                  NULL,   /* cert_file_name */
                                  NULL,   /* key_file_name */
                                  NULL,   /* cert_root_file_name */
                                  "ants", /* default_alpn — registered with peers */
                                  NULL,   /* default_callback_fn — phase 3 */
                                  NULL,   /* default_callback_ctx — phase 3 */
                                  NULL,   /* cnx_id_callback */
                                  NULL,   /* cnx_id_callback_data */
                                  reset_seed,
                                  current_time,
                                  NULL, /* p_simulated_time — production uses wall clock */
                                  NULL, /* ticket_file_name — no session resumption yet */
                                  NULL, /* ticket_encryption_key */
                                  0);
    if (state->quic == NULL) {
        memset(t->_opaque, 0, sizeof t->_opaque);
        return ANTS_ERROR_MALFORMED;
    }

    /* Bind the listening UDP socket if the caller asked for one.
     * NULL listen_multiaddr means "dial-only client" — no socket yet.
     * (Phase 3 will lazily open an ephemeral socket on first dial so
     * dial-only clients can also send packets.) */
    if (config->listen_multiaddr != NULL) {
        ants_error_t err = bind_listen_socket(state, config->listen_multiaddr);
        if (err != ANTS_OK) {
            picoquic_free(state->quic);
            memset(t->_opaque, 0, sizeof t->_opaque);
            return err;
        }
    }

    /* Idle timeout: picoquic exposes per-connection idle timeouts.
     * Phase 2 will plumb config->idle_timeout_ms through. */

    return ANTS_OK;
}

ants_error_t ants_transport_destroy(ants_transport_t *t, uint64_t close_code)
{
    (void)close_code; /* Phase 3 will pass close_code to per-connection
                       * CONNECTION_CLOSE frames. */
    if (t == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    struct ants_transport_state *state = (struct ants_transport_state *)(void *)t->_opaque;
    if (state->sock_fd != ANTS_INVALID_SOCKET) {
        close_socket(state->sock_fd);
        state->sock_fd = ANTS_INVALID_SOCKET;
    }
    if (state->quic != NULL) {
        picoquic_free(state->quic);
        state->quic = NULL;
    }
    /* Wipe the rest of the opaque buffer so later misuse of the (now
     * dead) transport is observable as zeroed fields rather than
     * dangling state. */
    memset(t->_opaque, 0, sizeof t->_opaque);
    return ANTS_OK;
}

/* ------------------------------------------------------------------------ */
/* Event loop tick                                                          */
/*                                                                          */
/* The core of caller-driven async: drain inbound UDP packets, hand them   */
/* to picoquic; pump outbound packets from picoquic, send via UDP;         */
/* return the time the caller may sleep before tick()-ing again.           */
/*                                                                          */
/* Phase 2 doesn't yet bridge picoquic's stream/connection callbacks to    */
/* ants_transport_event_t — that wires up in phase 3 alongside the        */
/* stream APIs. Phase 2's tick() is therefore a correctness exercise:     */
/* prove the I/O loop drives picoquic without crashes, leaks, or          */
/* unbounded loops, and that the wake-delay value is meaningful.          */
/* ------------------------------------------------------------------------ */

static void tick_drain_incoming(struct ants_transport_state *state, uint64_t now_us)
{
    if (state->sock_fd == ANTS_INVALID_SOCKET) {
        return;
    }
    uint8_t buf[ANTS_TRANSPORT_MTU];
    for (;;) {
        struct sockaddr_storage from_addr;
        socklen_t from_len = sizeof from_addr;
        ssize_t n = recvfrom(
            state->sock_fd, (char *)buf, sizeof buf, 0, (struct sockaddr *)&from_addr, &from_len);
        if (n < 0) {
#if defined(_WIN32) || defined(_WIN64)
            if (WSAGetLastError() == WSAEWOULDBLOCK)
                break;
#else
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
#endif
            /* Other errors: stop draining; picoquic will retry next tick. */
            break;
        }
        if (n == 0) {
            break;
        }
        (void)picoquic_incoming_packet(state->quic,
                                       buf,
                                       (size_t)n,
                                       (struct sockaddr *)&from_addr,
                                       (struct sockaddr *)&state->local_addr,
                                       0, /* if_index */
                                       0, /* received_ecn */
                                       now_us);
    }
}

static void tick_drain_outgoing(struct ants_transport_state *state, uint64_t now_us)
{
    if (state->sock_fd == ANTS_INVALID_SOCKET) {
        return;
    }
    uint8_t send_buf[ANTS_TRANSPORT_MTU];
    for (int i = 0; i < ANTS_TRANSPORT_MAX_PACKETS_PER_TICK; i++) {
        struct sockaddr_storage peer_addr;
        struct sockaddr_storage local_addr;
        int if_index = 0;
        picoquic_connection_id_t log_cid;
        picoquic_cnx_t *last_cnx = NULL;
        size_t send_length = 0;
        size_t send_msg_size = 0;
        int rc = picoquic_prepare_next_packet_ex(state->quic,
                                                 now_us,
                                                 send_buf,
                                                 sizeof send_buf,
                                                 &send_length,
                                                 &peer_addr,
                                                 &local_addr,
                                                 &if_index,
                                                 &log_cid,
                                                 &last_cnx,
                                                 &send_msg_size);
        if (rc != 0 || send_length == 0) {
            /* No more packets pending. */
            break;
        }
        socklen_t peer_len = peer_addr.ss_family == AF_INET6
                                 ? (socklen_t)sizeof(struct sockaddr_in6)
                                 : (socklen_t)sizeof(struct sockaddr_in);
        (void)sendto(state->sock_fd,
                     (const char *)send_buf,
                     send_length,
                     0,
                     (const struct sockaddr *)&peer_addr,
                     peer_len);
    }
}

uint32_t ants_transport_tick(ants_transport_t *t)
{
    if (t == NULL) {
        return UINT32_MAX;
    }
    struct ants_transport_state *state = (struct ants_transport_state *)(void *)t->_opaque;
    if (state->quic == NULL) {
        return UINT32_MAX;
    }

    uint64_t now_us = picoquic_current_time();
    tick_drain_incoming(state, now_us);
    tick_drain_outgoing(state, now_us);

    /* Ask picoquic when it next wants attention. The function returns
     * the delay in *microseconds*; we convert to ms (rounding up so the
     * caller never wakes too late). We pass delay_max as UINT32_MAX
     * microseconds (~71 minutes), which is well below INT64_MAX so the
     * later `+ 999` rounding can't overflow. Larger waits become
     * UINT32_MAX ms (the documented "idle" sentinel). */
    int64_t wake_us = picoquic_get_next_wake_delay(state->quic, now_us, (int64_t)UINT32_MAX);
    if (wake_us <= 0) {
        return 0; /* picoquic wants attention immediately */
    }
    int64_t wake_ms = (wake_us + 999) / 1000;
    if (wake_ms >= UINT32_MAX) {
        return UINT32_MAX;
    }
    return (uint32_t)wake_ms;
}

/* ------------------------------------------------------------------------ */
/* Local-address introspection                                              */
/*                                                                          */
/* Phase 2 doesn't yet implement conn-level introspection (no real          */
/* connections to enumerate). It DOES make the transport's listening       */
/* address visible via the same multiaddr convention, which the loopback   */
/* test in phase 3 will need to write into the dialer's config.            */
/* ------------------------------------------------------------------------ */

ants_error_t ants_transport_local_addr(const ants_transport_t *t, char *out_buf, size_t cap)
{
    if (t == NULL || out_buf == NULL || cap == 0) {
        return ANTS_ERROR_INVALID_ARG;
    }
    const struct ants_transport_state *state =
        (const struct ants_transport_state *)(const void *)t->_opaque;
    if (state->sock_fd == ANTS_INVALID_SOCKET || state->local_addr_len == 0) {
        return ANTS_ERROR_NOT_IMPLEMENTED;
    }
    char ip[INET6_ADDRSTRLEN];
    uint16_t port_h = 0;
    const char *family;
    if (state->local_addr.ss_family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)&state->local_addr;
        if (inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof ip) == NULL) {
            return ANTS_ERROR_MALFORMED;
        }
        port_h = ntohs(sin->sin_port);
        family = "ip4";
    } else if (state->local_addr.ss_family == AF_INET6) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)&state->local_addr;
        if (inet_ntop(AF_INET6, &sin6->sin6_addr, ip, sizeof ip) == NULL) {
            return ANTS_ERROR_MALFORMED;
        }
        port_h = ntohs(sin6->sin6_port);
        family = "ip6";
    } else {
        return ANTS_ERROR_MALFORMED;
    }
    int written = snprintf(out_buf, cap, "/%s/%s/udp/%u/quic-v1", family, ip, (unsigned)port_h);
    if (written < 0 || (size_t)written >= cap) {
        return ANTS_ERROR_BUFFER_TOO_SMALL;
    }
    return ANTS_OK;
}

/* ------------------------------------------------------------------------ */
/* Dialing                                                                  */
/* ------------------------------------------------------------------------ */

/* ------------------------------------------------------------------------ */
/* Connection-state internal struct                                         */
/*                                                                          */
/* Lives inside the caller's opaque ants_transport_conn_t buffer.           */
/* Pinned at 8 KB by the public header; the size-check typedef below       */
/* asserts the struct fits.                                                 */
/* ------------------------------------------------------------------------ */

struct ants_transport_conn_state {
    /* The vendored picoquic connection. NULL until picoquic_create_client_cnx
     * succeeds; cleared back to NULL when picoquic eventually deletes it
     * (e.g. after the connection drains). */
    picoquic_cnx_t *cnx;

    /* Back-pointer to the parent transport. Lets connection-scoped
     * callbacks (phase 3b) reach the caller's event_fn. */
    struct ants_transport_state *parent;

    /* expected_peer_id from dial(), if any. When set (expected_set != 0)
     * we use it to verify the handshake binds the right pubkey. */
    uint8_t expected_peer_id[ANTS_PEER_ID_SIZE];
    int expected_set;
};

typedef char ants_transport_conn_state_size_check[(sizeof(struct ants_transport_conn_state) <=
                                                   sizeof(((ants_transport_conn_t *)0)->_opaque))
                                                      ? 1
                                                      : -1];

/* Lazily open an ephemeral UDP socket on a dial-only client (no
 * listener was configured). The kernel-assigned port doesn't matter —
 * the dialer just needs SOMETHING to send packets from. */
static ants_error_t ensure_dial_socket(struct ants_transport_state *state, int family)
{
    if (state->sock_fd != ANTS_INVALID_SOCKET) {
        return ANTS_OK;
    }
    state->sock_fd = socket(family, SOCK_DGRAM, IPPROTO_UDP);
    if (state->sock_fd == ANTS_INVALID_SOCKET) {
        return ANTS_ERROR_PEER_UNREACHABLE;
    }
    /* Bind to "any address, ephemeral port". The kernel picks both. */
    if (family == AF_INET) {
        struct sockaddr_in sin = {0};
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = htonl(INADDR_ANY);
        sin.sin_port = 0;
        if (bind(state->sock_fd, (struct sockaddr *)&sin, sizeof sin) != 0) {
            close_socket(state->sock_fd);
            state->sock_fd = ANTS_INVALID_SOCKET;
            return ANTS_ERROR_PEER_UNREACHABLE;
        }
    } else {
        struct sockaddr_in6 sin6 = {0};
        sin6.sin6_family = AF_INET6;
        sin6.sin6_addr = in6addr_any;
        sin6.sin6_port = 0;
        if (bind(state->sock_fd, (struct sockaddr *)&sin6, sizeof sin6) != 0) {
            close_socket(state->sock_fd);
            state->sock_fd = ANTS_INVALID_SOCKET;
            return ANTS_ERROR_PEER_UNREACHABLE;
        }
    }
    if (set_nonblocking(state->sock_fd) != 0) {
        close_socket(state->sock_fd);
        state->sock_fd = ANTS_INVALID_SOCKET;
        return ANTS_ERROR_PEER_UNREACHABLE;
    }
    state->local_addr_len = sizeof state->local_addr;
    if (getsockname(
            state->sock_fd, (struct sockaddr *)&state->local_addr, &state->local_addr_len) != 0) {
        close_socket(state->sock_fd);
        state->sock_fd = ANTS_INVALID_SOCKET;
        return ANTS_ERROR_PEER_UNREACHABLE;
    }
    return ANTS_OK;
}

ants_error_t ants_transport_dial(ants_transport_t *t,
                                 const char *multiaddr,
                                 const ants_peer_id_t *expected_peer_id,
                                 ants_transport_conn_t *out_conn)
{
    if (t == NULL || multiaddr == NULL || out_conn == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    struct ants_transport_state *state = (struct ants_transport_state *)(void *)t->_opaque;
    if (state->quic == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }

    /* Parse the multiaddr (also validates the format). */
    struct sockaddr_storage peer_addr;
    socklen_t peer_addr_len;
    ants_error_t err = parse_multiaddr(multiaddr, &peer_addr, &peer_addr_len);
    if (err != ANTS_OK) {
        return err;
    }

    /* Open an ephemeral local socket if we don't have a listener. */
    err = ensure_dial_socket(state, peer_addr.ss_family);
    if (err != ANTS_OK) {
        return err;
    }

    /* Initialise the conn-state buffer. */
    memset(out_conn->_opaque, 0, sizeof out_conn->_opaque);
    struct ants_transport_conn_state *cs =
        (struct ants_transport_conn_state *)(void *)out_conn->_opaque;
    cs->parent = state;
    if (expected_peer_id != NULL) {
        memcpy(cs->expected_peer_id, expected_peer_id->bytes, ANTS_PEER_ID_SIZE);
        cs->expected_set = 1;
    }

    /* picoquic_create_client_cnx is the convenience entry point that
     * creates the connection AND queues the initial packet. We pass
     * ALPN "ants" and SNI=NULL (we don't use server-name routing —
     * peer identity comes from the raw-pubkey TLS handshake, plumbed
     * in phase 3b). The picoquic_stream_data_cb_fn is NULL here; the
     * bridge that translates picoquic events to ants_transport_event_t
     * lands in phase 3c. */
    uint64_t now = picoquic_current_time();
    cs->cnx = picoquic_create_client_cnx(state->quic,
                                         (struct sockaddr *)&peer_addr,
                                         now,
                                         0,    /* preferred_version (0 = auto) */
                                         NULL, /* sni */
                                         "ants",
                                         NULL, /* callback_fn — phase 3c */
                                         NULL /* callback_ctx — phase 3c */);
    if (cs->cnx == NULL) {
        memset(out_conn->_opaque, 0, sizeof out_conn->_opaque);
        return ANTS_ERROR_HANDSHAKE_FAILED;
    }

    /* Phase 3 caveat: without TLS material (RFC 7250 raw pubkey + the
     * sign_fn wired into picotls — phase 3b), the handshake will fail
     * once the server-side validation kicks in. The dial *queues* the
     * INITIAL packet successfully and the caller's tick() will flush
     * it onto the wire, so the network path is exercised. The CONN_
     * READY / CONN_CLOSED events surface in phase 3c once the
     * callback bridge is in place. */

    return ANTS_OK;
}

/* ------------------------------------------------------------------------ */
/* Streams                                                                  */
/* ------------------------------------------------------------------------ */

ants_error_t ants_transport_open_bidi_stream(ants_transport_conn_t *conn,
                                             ants_transport_stream_t *out_stream)
{
    (void)conn;
    (void)out_stream;
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

ants_error_t ants_transport_open_uni_stream(ants_transport_conn_t *conn,
                                            ants_transport_stream_t *out_stream)
{
    (void)conn;
    (void)out_stream;
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

ants_error_t ants_transport_stream_send(ants_transport_stream_t *stream,
                                        const uint8_t *data,
                                        size_t len,
                                        bool fin)
{
    (void)stream;
    (void)data;
    (void)len;
    (void)fin;
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

ants_error_t ants_transport_stream_recv(ants_transport_stream_t *stream,
                                        uint8_t *out,
                                        size_t cap,
                                        size_t *out_len)
{
    (void)stream;
    (void)out;
    (void)cap;
    (void)out_len;
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

ants_error_t ants_transport_stream_close(ants_transport_stream_t *stream)
{
    (void)stream;
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

ants_error_t ants_transport_stream_reset(ants_transport_stream_t *stream, uint64_t error_code)
{
    (void)stream;
    (void)error_code;
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

/* ------------------------------------------------------------------------ */
/* Flow control / introspection                                             */
/* ------------------------------------------------------------------------ */

uint64_t ants_transport_stream_send_window(const ants_transport_stream_t *stream)
{
    /* Documented contract: UINT64_MAX = "effectively unbounded". Safe
     * default until the real implementation tracks actual windows. */
    (void)stream;
    return UINT64_MAX;
}

uint64_t ants_transport_stream_bytes_sent(const ants_transport_stream_t *stream)
{
    (void)stream;
    return 0;
}

uint64_t ants_transport_stream_bytes_received(const ants_transport_stream_t *stream)
{
    (void)stream;
    return 0;
}

ants_error_t ants_transport_conn_peer_id(const ants_transport_conn_t *conn,
                                         ants_peer_id_t *out_peer_id)
{
    (void)conn;
    (void)out_peer_id;
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

ants_error_t
ants_transport_conn_peer_addr(const ants_transport_conn_t *conn, char *out_buf, size_t cap)
{
    (void)conn;
    (void)out_buf;
    (void)cap;
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

ants_error_t ants_transport_peer_disconnect(ants_transport_conn_t *conn, uint64_t error_code)
{
    (void)conn;
    (void)error_code;
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

ants_error_t ants_transport_peer_list(const ants_transport_t *t,
                                      ants_peer_id_t *out_peers,
                                      size_t cap,
                                      size_t *out_count)
{
    /* Documented contract: in v1.0 the transport has no real peer state,
     * so the list is always empty. */
    (void)t;
    (void)out_peers;
    (void)cap;
    if (out_count != NULL) {
        *out_count = 0;
    }
    return ANTS_ERROR_NOT_IMPLEMENTED;
}
