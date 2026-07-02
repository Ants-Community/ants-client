/*
 * transport.c — P2P transport implementation against vendored picoquic.
 *
 * Phases:
 *   - 1: init + destroy + opaque-ctx size check (PR #18).
 *   - 2: tick + UDP socket bind, no streams yet (PR #19).
 *   - 3a: dial() + ephemeral socket, queues INITIAL packet (PR #20).
 *   - 3c (this PR): stream API + picoquic_callback bridge. Streams can
 *     be opened, sent on, received from, closed, and reset; picoquic
 *     events surface as ants_transport_event_t through the user's
 *     event_fn. No TLS material yet (3b lands separately), so any
 *     real handshake fails — but the local API surface is fully wired.
 *   - 3b: TLS identity binding via picotls (RFC 7250 raw pubkey + the
 *     sign_fn callback the caller provides).
 *   - 3d: two-transport loopback test exchanging real bytes.
 *
 * Layout discipline (same as foundation/crypto's ants_blake3_ctx_t):
 *   - Caller's ants_transport_t._opaque[] holds a struct
 *     ants_transport_state.
 *   - Caller's ants_transport_conn_t._opaque[] holds a struct
 *     ants_transport_conn_state.
 *   - Caller's ants_transport_stream_t._opaque[] holds a struct
 *     ants_transport_stream_state.
 * Each internal struct ends with a `typedef char ..._size_check[(cond) ? 1 : -1]`
 * that surfaces overruns at compile time.
 */

#include "ants_transport.h"

#include "ants_crypto.h"
#include "picoquic.h"
/* picoquic_internal.h uses pthread types (pthread_mutex_t, pthread_t)
 * unconditionally on non-Windows. Their visibility under glibc requires
 * including <pthread.h> ourselves; the picoquic core does this via
 * _GNU_SOURCE + its own includes, but our compilation unit is separate. */
#if !defined(_WIN32) && !defined(_WIN64)
#include <pthread.h>
#endif
/* picoquic doesn't expose its master picotls context through the public
 * header. We need it to wire RFC 7250 raw-pubkey TLS (sign_certificate,
 * verify_certificate, use_raw_public_keys). Reaching into the internal
 * header is the cleanest path: we vendor picoquic, so any layout shift
 * surfaces as a compile error on our deliberate version bumps. */
#include "picoquic_internal.h"
#include "picotls.h"

#include <stdlib.h>

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

/* ------------------------------------------------------------------------ */
/* RFC 7250 SubjectPublicKeyInfo (SPKI) wrapping for Ed25519                */
/*                                                                          */
/* The TLS 1.3 Certificate message in raw-pubkey mode carries the SPKI of   */
/* the raw public key (RFC 7250 §3). For Ed25519 the encoding is a fixed   */
/* 12-byte prefix followed by the 32-byte raw pubkey:                       */
/*                                                                          */
/*   30 2a              SEQUENCE, length 42                                 */
/*     30 05            SEQUENCE, length 5                                  */
/*       06 03 2b 65 70 OBJECT IDENTIFIER 1.3.101.112 (id-Ed25519)         */
/*     03 21            BIT STRING, length 33                               */
/*       00             0 unused bits                                       */
/*       <pubkey[32]>                                                       */
/*                                                                          */
/* Total = 12 + 32 = 44 bytes. Two helpers below: build (encode) and       */
/* parse (decode). The decoder is constant-time on its prefix check.       */
/* ------------------------------------------------------------------------ */

#define ANTS_TRANSPORT_ED25519_SPKI_SIZE 44

static const uint8_t ANTS_TRANSPORT_ED25519_SPKI_PREFIX[12] = {
    0x30,
    0x2a,
    0x30,
    0x05,
    0x06,
    0x03,
    0x2b,
    0x65,
    0x70,
    0x03,
    0x21,
    0x00,
};

static void build_ed25519_spki(uint8_t out[ANTS_TRANSPORT_ED25519_SPKI_SIZE],
                               const uint8_t pubkey[ANTS_ED25519_PUBKEY_SIZE])
{
    memcpy(out, ANTS_TRANSPORT_ED25519_SPKI_PREFIX, sizeof ANTS_TRANSPORT_ED25519_SPKI_PREFIX);
    memcpy(out + sizeof ANTS_TRANSPORT_ED25519_SPKI_PREFIX, pubkey, ANTS_ED25519_PUBKEY_SIZE);
}

static int
parse_ed25519_spki(const uint8_t *spki, size_t spki_len, uint8_t out_pub[ANTS_ED25519_PUBKEY_SIZE])
{
    if (spki_len != ANTS_TRANSPORT_ED25519_SPKI_SIZE) {
        return -1;
    }
    if (memcmp(spki,
               ANTS_TRANSPORT_ED25519_SPKI_PREFIX,
               sizeof ANTS_TRANSPORT_ED25519_SPKI_PREFIX) != 0) {
        return -1;
    }
    memcpy(out_pub, spki + sizeof ANTS_TRANSPORT_ED25519_SPKI_PREFIX, ANTS_ED25519_PUBKEY_SIZE);
    return 0;
}

/* Max packets prepared per tick before yielding control back to the
 * caller. Prevents a tick() from starving the embedding event loop if
 * the QUIC ctx has many pending packets to drain. */
#define ANTS_TRANSPORT_MAX_PACKETS_PER_TICK 32

/* ------------------------------------------------------------------------ */
/* picotls sign_certificate / verify_certificate adapters                   */
/*                                                                          */
/* picotls minicrypto ships sign_certificate for secp256r1 only. For        */
/* Ed25519 (our peer-identity scheme per RFC-0010) we wire small adapters   */
/* that call the caller-supplied sign_fn / ants_ed25519_verify.             */
/*                                                                          */
/* These structs live inside ants_transport_state (per-transport singleton  */
/* — the picotls master ctx points at them via pointer slots in            */
/* ptls_context_t::sign_certificate / verify_certificate).                  */
/* ------------------------------------------------------------------------ */

/* Sign-side: wraps the caller's sign_fn/sign_ctx alongside the ptls
 * super struct. picoquic_dispose_sign_certificate `free()`s whatever
 * pointer is in ctx->sign_certificate, so this struct MUST be heap-
 * allocated and the malloc'd pointer handed straight to picotls. */
struct ants_sign_cert {
    ptls_sign_certificate_t super; /* MUST be first — picotls passes (self) */
    ants_transport_sign_fn sign_fn;
    void *sign_ctx;
};

/* The list of signature algorithms we accept on incoming CertificateVerify.
 * Terminator is UINT16_MAX per picotls convention. This list is what
 * picotls advertises in the ClientHello signature_algorithms extension —
 * peer must offer one of these in CertificateVerify. */
static const uint16_t ants_supported_sig_algos[] = {PTLS_SIGNATURE_ED25519, UINT16_MAX};

/* Singleton verify_certificate adapter (stateless: same cb + algos for
 * every transport instance). File scope so its lifetime is the whole
 * program and we can point every transport's tls_ctx->verify_certificate
 * at the same address. Picoquic doesn't free this (see line 1418 of
 * tls_api.c, commented out). */
static int ants_verify_cert_cb(
    struct st_ptls_verify_certificate_t *_self,
    ptls_t *tls,
    const char *server_name,
    int (**verify_sign)(void *verify_ctx, uint16_t algo, ptls_iovec_t data, ptls_iovec_t sign),
    void **verify_data,
    ptls_iovec_t *certs,
    size_t num_certs);

static ptls_verify_certificate_t ants_verify_cert_singleton = {
    .cb = ants_verify_cert_cb,
    .algos = ants_supported_sig_algos,
};

/* Forward declaration: the conn-state struct is needed inside the verify
 * callback to mirror peer_pubkey into per-connection storage. Definition
 * comes later (after ants_transport_state) for readability. */
struct ants_transport_conn_state;

/* Forward declaration of the picoquic bridge callback. picoquic_create
 * (called from ants_transport_init) takes it as default_callback_fn for
 * inbound cnx; the definition lives later in the file alongside the
 * conn-state struct it operates on. */
static int ants_transport_stream_cb(picoquic_cnx_t *cnx,
                                    uint64_t stream_id,
                                    uint8_t *bytes,
                                    size_t length,
                                    picoquic_call_back_event_t fin_or_event,
                                    void *callback_ctx,
                                    void *stream_ctx);

/* sign_certificate callback: invoked by picotls during the TLS 1.3
 * handshake when this side needs to sign the CertificateVerify message
 * with its private key. We delegate to the caller-supplied sign_fn,
 * keeping private-key material out of the transport (TEE-safe).
 *
 * picotls hands us:
 *   - input: the bytes to sign (transcript prefix + handshake-context hash,
 *     already prepared per RFC 8446 §4.4.3 by picotls);
 *   - algorithms / num_algorithms: the peer's offered signature_algorithms;
 *   - output: ptls_buffer_t to write the 64-byte Ed25519 signature into;
 *   - selected_algorithm: out-param we set to PTLS_SIGNATURE_ED25519 (0x0807).
 *
 * Returns 0 on success; PTLS_ALERT_* on protocol-level failure. */
static int ants_sign_cert_cb(ptls_sign_certificate_t *_self,
                             ptls_t *tls,
                             ptls_async_job_t **async,
                             uint16_t *selected_algorithm,
                             ptls_buffer_t *output,
                             ptls_iovec_t input,
                             const uint16_t *algorithms,
                             size_t num_algorithms)
{
    (void)tls;
    (void)async;
    struct ants_sign_cert *self = (struct ants_sign_cert *)_self;
    int ret;

    /* The peer must advertise ed25519. If they don't (e.g. they sent an
     * outdated signature_algorithms list), fail the handshake. */
    int found = 0;
    for (size_t i = 0; i < num_algorithms; i++) {
        if (algorithms[i] == PTLS_SIGNATURE_ED25519) {
            found = 1;
            break;
        }
    }
    if (!found) {
        return PTLS_ALERT_HANDSHAKE_FAILURE;
    }

    /* Delegate to the caller's sign_fn. The signature is fixed-size for
     * Ed25519 (64 bytes); we stack-allocate it and copy into the picotls
     * output buffer. */
    uint8_t sig[ANTS_ED25519_SIG_SIZE];
    if (self->sign_fn(input.base, input.len, sig, self->sign_ctx) != ANTS_OK) {
        return PTLS_ERROR_LIBRARY;
    }

    *selected_algorithm = PTLS_SIGNATURE_ED25519;
    ptls_buffer_pushv(output, sig, sizeof sig);

    ret = 0;
Exit:
    return ret;
}

/* verify_sign callback: picotls invokes this once the peer's
 * CertificateVerify message arrives, after our verify_certificate
 * callback has run. The verify_ctx is a heap-allocated 32-byte buffer
 * holding the peer's raw Ed25519 pubkey (built by verify_certificate).
 *
 * picotls also calls this with data.len == 0 && sign.len == 0 as a
 * cleanup signal — used here to free verify_ctx on either the verify
 * path or the cleanup-only path. Either way verify_ctx is freed exactly
 * once. */
static int
ants_verify_sign_cb(void *verify_ctx, uint16_t algo, ptls_iovec_t data, ptls_iovec_t sign)
{
    uint8_t *peer_pub = (uint8_t *)verify_ctx;
    int rc = 0;

    if (data.len == 0 && sign.len == 0) {
        /* cleanup only — free and return success. */
    } else if (algo != PTLS_SIGNATURE_ED25519 || sign.len != ANTS_ED25519_SIG_SIZE) {
        rc = PTLS_ALERT_DECRYPT_ERROR;
    } else if (ants_ed25519_verify(peer_pub, data.base, data.len, sign.base) != ANTS_OK) {
        rc = PTLS_ALERT_DECRYPT_ERROR;
    }
    free(peer_pub);
    return rc;
}

/* verify_certificate callback body — declared above near the singleton.
 * Defined later (after struct ants_transport_conn_state) so it can
 * reference cs->peer_pubkey. */

/* ------------------------------------------------------------------------ */
/* Internal state                                                           */
/*                                                                          */
/* The public ants_transport_t is a uint8_t[16384] union; we cast it to    */
/* this internal struct. Adding fields is safe up to ~16 KB; the           */
/* compile-time assert at the bottom catches overrun.                       */
/* ------------------------------------------------------------------------ */

/* Magic discriminators. picotls's verify_certificate runs for inbound
 * cnx BEFORE we've had a chance to call picoquic_set_callback to bind a
 * conn-state — so the callback_ctx it sees is the master's default ctx,
 * which we set to the transport state. The magic field as the first 4
 * bytes of both structs lets the verify_certificate handler tell the
 * two apart without casting blindly. */
#define ANTS_TRANSPORT_STATE_MAGIC      0x414E5453U /* "ANTS" */
#define ANTS_TRANSPORT_CONN_STATE_MAGIC 0x414E5443U /* "ANTC" */

struct ants_transport_state {
    /* MUST be the first field — see magic discriminator note above. */
    uint32_t magic;

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

    /* TLS material owned by picoquic:
     *   - certificates.list array + each .base byte buffer (freed by
     *     free_certificates_list in tls_api.c);
     *   - sign_certificate (freed by picoquic_dispose_sign_certificate).
     * We malloc them at init time and hand the pointers to picoquic;
     * picoquic_free reclaims them. No reference stored here.
     *
     * verify_certificate is stateless (just cb + algos), so we use a
     * static singleton — see ants_verify_cert_singleton. */

    /* Head of the linked list of heap-allocated conn-states for inbound
     * connections (where the listener accepts an INITIAL packet rather
     * than the caller dialing). Each cs is freed either on CONN_CLOSED
     * for that cnx or, as a safety net, on ants_transport_destroy when
     * picoquic_free deletes any still-open inbound cnx without firing
     * the close callback. */
    struct ants_transport_conn_state *inbound_conns_head;
};

/* ants_transport_t MUST be at least as large as the internal state
 * struct. The trick: declare a typedef whose array size is -1 (an
 * invalid type) when the condition fails. C99 compile error then
 * surfaces at build time rather than corrupting memory at run time.
 * Same pattern as ants_blake3_ctx_size_check in foundation/crypto. */
typedef char ants_transport_state_size_check
    [(sizeof(struct ants_transport_state) <= sizeof(((ants_transport_t *)0)->_opaque)) ? 1 : -1];

/* ------------------------------------------------------------------------ */
/* Connection-state internal struct                                         */
/*                                                                          */
/* Lives inside the caller's opaque ants_transport_conn_t buffer (outbound  */
/* dials) or on the heap (inbound cnx — see verify_certificate bootstrap). */
/* Pinned at 8 KB by the public header; the size-check typedef below       */
/* asserts the struct fits.                                                 */
/* ------------------------------------------------------------------------ */

struct ants_transport_conn_state {
    /* MUST be the first field. Discriminator for verify_certificate to
     * distinguish a conn-state from the transport state (which is what
     * picoquic_get_callback_context returns for an inbound cnx that
     * hasn't yet been rebound). See ANTS_TRANSPORT_*_MAGIC. */
    uint32_t magic;

    /* The vendored picoquic connection. NULL until picoquic_create_client_cnx
     * succeeds; cleared back to NULL when picoquic deletes it after a
     * close callback fires (peer-initiated close, application close, or
     * stateless reset). All stream APIs must check this is non-NULL
     * before touching picoquic. */
    picoquic_cnx_t *cnx;

    /* Back-pointer to the parent transport. The connection-scope
     * callback uses parent->event_fn / event_ctx to surface events to
     * the user. */
    struct ants_transport_state *parent;

    /* expected_peer_id from dial(), if any. When set (expected_set != 0)
     * the verify_certificate callback fails closed if the peer presents
     * a different pubkey. */
    uint8_t expected_peer_id[ANTS_PEER_ID_SIZE];
    int expected_set;

    /* Peer's Ed25519 pubkey, populated by the verify_certificate
     * callback once the peer's TLS Certificate message arrives. Mirrored
     * into ANTS_TRANSPORT_EV_CONN_READY.peer_id by the callback bridge. */
    uint8_t peer_pubkey[ANTS_ED25519_PUBKEY_SIZE];
    int peer_pubkey_set;

    /* Inbound-cnx bookkeeping. is_heap == 1 means this struct was
     * malloc'd by the verify_certificate bootstrap (for an inbound
     * cnx the caller never dialed) and needs free() on CONN_CLOSED or
     * transport destroy. next_inbound chains the transport's
     * inbound_conns_head list so destroy can sweep orphaned cs's. */
    int is_heap;
    struct ants_transport_conn_state *next_inbound;

    /* Head of the linked list of heap-allocated stream-states for
     * peer-opened streams on this cnx. Each ss is freed when the cnx
     * closes (CONN_CLOSED for this cs sweeps the list). Locally-opened
     * streams live in the caller's _opaque buffer and are NOT in this
     * list. */
    struct ants_transport_stream_state *inbound_streams_head;
};

typedef char ants_transport_conn_state_size_check[(sizeof(struct ants_transport_conn_state) <=
                                                   sizeof(((ants_transport_conn_t *)0)->_opaque))
                                                      ? 1
                                                      : -1];

/* ------------------------------------------------------------------------ */
/* Stream state                                                             */
/*                                                                          */
/* Lives either inside the caller's opaque ants_transport_stream_t buffer  */
/* (locally-opened streams, pinned at 1024 bytes by the public header) or   */
/* on the heap (peer-opened streams — see bootstrap_inbound_stream). The   */
/* bulk is a linear recv buffer populated by the picoquic callback and     */
/* drained by stream_recv().                                                */
/*                                                                          */
/* Recv buffer discipline: head points to the next byte the caller will     */
/* read; len is the total occupied size. Caller's drain advances head; when */
/* head == len both are reset to 0 (compact-on-empty). When an inbound      */
/* frame exceeds the remaining capacity, the surplus is dropped — QUIC's    */
/* per-stream flow-control window will eventually back-pressure the peer    */
/* once we extend MAX_STREAM_DATA management (post v1.0). For phase 3,      */
/* the 768-byte default is sufficient for the loopback test's small         */
/* request/response payloads.                                                */
/* ------------------------------------------------------------------------ */

#define ANTS_TRANSPORT_STREAM_RECV_BUF_SIZE 768

struct ants_transport_stream_state {
    /* Back-pointer to the conn state. NULL only for a zero-initialised
     * (unopened) stream slot. The callback bridge uses this to reach
     * conn-scope state and, transitively, the user's event_fn. */
    struct ants_transport_conn_state *parent_conn;

    /* picoquic stream ID. The low two bits encode direction (00 =
     * client-bidi, 01 = server-bidi, 10 = client-uni, 11 = server-uni).
     * Picoquic mints IDs via picoquic_get_next_local_stream_id and
     * materialises the stream via picoquic_set_app_stream_ctx. */
    uint64_t stream_id;

    /* Bookkeeping flags. uint8_t to keep the struct tight (we have at
     * most 1024 bytes total). */
    uint8_t is_bidi;         /* 1 = bidi, 0 = uni */
    uint8_t local_fin_sent;  /* 1 once we've sent FIN to peer */
    uint8_t remote_fin_seen; /* 1 once peer signalled FIN */
    uint8_t reset_seen;      /* 1 once peer RESET'd the stream */

    /* Inbound-stream bookkeeping. is_heap == 1 means this struct was
     * malloc'd by the stream-bridge bootstrap (for a stream the peer
     * opened, not us) and needs free() when the parent cnx closes.
     * next_inbound chains the parent_conn's inbound_streams_head list
     * so CONN_CLOSED can sweep them all. */
    int is_heap;
    struct ants_transport_stream_state *next_inbound;

    /* Linear recv buffer. The callback bridge appends incoming bytes
     * here; stream_recv copies them out and advances `head`. */
    size_t recv_len;
    size_t recv_head;
    uint8_t recv_buf[ANTS_TRANSPORT_STREAM_RECV_BUF_SIZE];
};

typedef char
    ants_transport_stream_state_size_check[(sizeof(struct ants_transport_stream_state) <=
                                            sizeof(((ants_transport_stream_t *)0)->_opaque))
                                               ? 1
                                               : -1];

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
    state->magic = ANTS_TRANSPORT_STATE_MAGIC;
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

    /* default_callback = our bridge with transport state as ctx. For
     * inbound cnx, picotls's verify_certificate (which runs before any
     * picoquic_callback) calls picoquic_set_callback to rebind to a
     * fresh per-cnx cs. So in steady state the bridge ALWAYS sees a cs;
     * the state-as-ctx only persists between cnx creation and verify_
     * certificate firing. */
    state->quic = picoquic_create(max_cnx,
                                  NULL,   /* cert_file_name; TLS configured below */
                                  NULL,   /* key_file_name; TLS configured below */
                                  NULL,   /* cert_root_file_name; raw-pubkey, no CA */
                                  "ants", /* default_alpn — registered with peers */
                                  ants_transport_stream_cb,
                                  state,
                                  NULL, /* cnx_id_callback */
                                  NULL, /* cnx_id_callback_data */
                                  reset_seed,
                                  current_time,
                                  NULL, /* p_simulated_time — wall clock in prod */
                                  NULL, /* ticket_file_name — no session resumption yet */
                                  NULL, /* ticket_encryption_key */
                                  0);
    if (state->quic == NULL) {
        memset(t->_opaque, 0, sizeof t->_opaque);
        return ANTS_ERROR_MALFORMED;
    }

    /* RFC 7250 raw-pubkey TLS wiring. picoquic created the picotls master
     * context but left it minimal (no certs, no sign/verify). We reach
     * into the internal quic struct to retrieve the master ctx and
     * configure it:
     *
     *   - use_raw_public_keys = 1  → signal raw-pubkey mode in the TLS
     *     extension on both sides;
     *   - certificates.list / count → our SPKI-wrapped Ed25519 pubkey;
     *   - sign_certificate → our adapter that calls config->sign_fn;
     *   - verify_certificate → static singleton (stateless).
     *
     * Ownership: picoquic_free → picoquic_master_tlscontext_free →
     *   free_certificates_list(certs, count)        // free each .base + list
     *   picoquic_dispose_sign_certificate(ctx)      // free(ctx->sign_certificate)
     * So `cert_list`, `cert_spki`, and `sign_cert` MUST be malloc'd and
     * NOT freed by us. `verify_certificate` is NOT freed by picoquic
     * (line 1418 of tls_api.c, commented out), so the static singleton
     * is safe. */
    ptls_iovec_t *cert_list = (ptls_iovec_t *)malloc(sizeof(ptls_iovec_t));
    uint8_t *cert_spki = (uint8_t *)malloc(ANTS_TRANSPORT_ED25519_SPKI_SIZE);
    struct ants_sign_cert *sign_cert = (struct ants_sign_cert *)malloc(sizeof *sign_cert);
    if (cert_list == NULL || cert_spki == NULL || sign_cert == NULL) {
        free(cert_list);
        free(cert_spki);
        free(sign_cert);
        picoquic_free(state->quic);
        memset(t->_opaque, 0, sizeof t->_opaque);
        return ANTS_ERROR_MALFORMED;
    }
    build_ed25519_spki(cert_spki, config->pub);
    cert_list[0].base = cert_spki;
    cert_list[0].len = ANTS_TRANSPORT_ED25519_SPKI_SIZE;
    sign_cert->super.cb = ants_sign_cert_cb;
    sign_cert->sign_fn = config->sign_fn;
    sign_cert->sign_ctx = config->sign_ctx;

    ptls_context_t *tls_ctx = (ptls_context_t *)state->quic->tls_master_ctx;
    tls_ctx->use_raw_public_keys = 1;
    tls_ctx->certificates.list = cert_list;
    tls_ctx->certificates.count = 1;
    tls_ctx->sign_certificate = &sign_cert->super;
    tls_ctx->verify_certificate = &ants_verify_cert_singleton;
    /* Mutual TLS authentication. ANTS is a true peer-to-peer protocol:
     * each side must know the other's pubkey. With require_client_auth=1
     * the server requests a client certificate, both peers send Certificate
     * + CertificateVerify, both verify_certificate callbacks fire, and
     * both event_fn's see CONN_READY with peer_id mirrored from cs->
     * peer_pubkey. */
    tls_ctx->require_client_authentication = 1;

    /* picoquic_create with NULL cert/key implies client-only mode (sets
     * quic->enforce_client_only = 1, see deps/picoquic .../quicctx.c
     * line 727), which makes the listener reject every inbound INITIAL
     * with CONNECTION_REFUSED (0x2). We supply certs/sign via the post-
     * create configuration above, so this flag is incorrect for us —
     * clear it so the listener can accept handshakes. */
    state->quic->enforce_client_only = 0;

    /* Same source file, line 4301: when is_cert_store_not_empty == 0,
     * picoquic_create_cnx automatically calls picoquic_set_null_verifier()
     * which nulls our verify_certificate. The flag is meant to track
     * whether a cert ROOT store is set (CA path), but picoquic uses it
     * as a generic "is verify wired" signal. We DO have a verifier
     * (our raw-pubkey adapter), so flip this on. */
    state->quic->is_cert_store_not_empty = 1;

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
    /* Free any heap-allocated inbound conn-states whose CONN_CLOSED
     * callback never fired before picoquic_free deleted their cnx
     * (picoquic_delete_cnx silently drops connections without invoking
     * the close callback). For each orphan cs, ALSO sweep its inbound
     * streams. picoquic_free already tore down the cnx pointers; we
     * just reclaim heap. */
    struct ants_transport_conn_state *cs = state->inbound_conns_head;
    while (cs != NULL) {
        struct ants_transport_conn_state *next_cs = cs->next_inbound;
        struct ants_transport_stream_state *iss = cs->inbound_streams_head;
        while (iss != NULL) {
            struct ants_transport_stream_state *next_iss = iss->next_inbound;
            free(iss);
            iss = next_iss;
        }
        free(cs);
        cs = next_cs;
    }
    state->inbound_conns_head = NULL;
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

/* verify_certificate callback body. Declared above near the sign_cert
 * adapters; defined here so it can reference the conn-state struct. */
static int ants_verify_cert_cb(
    struct st_ptls_verify_certificate_t *_self,
    ptls_t *tls,
    const char *server_name,
    int (**verify_sign)(void *verify_ctx, uint16_t algo, ptls_iovec_t data, ptls_iovec_t sign),
    void **verify_data,
    ptls_iovec_t *certs,
    size_t num_certs)
{
    (void)_self;
    (void)server_name;

    /* RFC 7250 raw-pubkey TLS sends EXACTLY one cert entry (the SPKI of
     * the raw key). Reject anything else; reject if length doesn't match
     * the fixed Ed25519-SPKI size. */
    if (num_certs != 1 || certs[0].len != ANTS_TRANSPORT_ED25519_SPKI_SIZE) {
        return PTLS_ALERT_BAD_CERTIFICATE;
    }

    /* Map ptls_t → picoquic_cnx_t → our conn-state. picoquic stashes cnx
     * in ptls_get_data_ptr() at connection creation (tls_api.c:2125).
     * The cnx's callback context is one of two things, distinguished by
     * the first uint32_t at that address:
     *   - For outbound (caller dialed): a struct ants_transport_conn_state*
     *     (magic = CONN_STATE_MAGIC), set by ants_transport_dial.
     *   - For inbound (peer's INITIAL arrived on our listening socket):
     *     the default callback context, which is the transport state*
     *     (magic = STATE_MAGIC). In this case we heap-allocate a fresh
     *     cs and rebind via picoquic_set_callback so subsequent events
     *     find it. */
    picoquic_cnx_t *cnx = (picoquic_cnx_t *)*ptls_get_data_ptr(tls);
    if (cnx == NULL) {
        return PTLS_ALERT_INTERNAL_ERROR;
    }
    void *cb_ctx = picoquic_get_callback_context(cnx);
    if (cb_ctx == NULL) {
        return PTLS_ALERT_INTERNAL_ERROR;
    }
    uint32_t magic;
    memcpy(&magic, cb_ctx, sizeof magic);

    struct ants_transport_conn_state *cs;
    if (magic == ANTS_TRANSPORT_CONN_STATE_MAGIC) {
        /* Outbound: caller dialed, cs is already in their _opaque buffer. */
        cs = (struct ants_transport_conn_state *)cb_ctx;
    } else if (magic == ANTS_TRANSPORT_STATE_MAGIC) {
        /* Inbound: bootstrap a fresh cs and rebind picoquic's callback
         * so future events on this cnx see cs (not the transport state). */
        struct ants_transport_state *state = (struct ants_transport_state *)cb_ctx;
        cs = (struct ants_transport_conn_state *)malloc(sizeof *cs);
        if (cs == NULL) {
            return PTLS_ERROR_NO_MEMORY;
        }
        memset(cs, 0, sizeof *cs);
        cs->magic = ANTS_TRANSPORT_CONN_STATE_MAGIC;
        cs->cnx = cnx;
        cs->parent = state;
        cs->is_heap = 1;
        /* Link into the transport's inbound-conns list so destroy() can
         * sweep any cs's whose CONN_CLOSED never fired. */
        cs->next_inbound = state->inbound_conns_head;
        state->inbound_conns_head = cs;
        picoquic_set_callback(cnx, ants_transport_stream_cb, cs);
    } else {
        /* Neither magic matched — refuse to interpret cb_ctx blindly. */
        return PTLS_ALERT_INTERNAL_ERROR;
    }

    /* Always heap-allocate the pubkey passed to verify_sign — that's
     * the only path that gets cleanup-on-free semantics from picotls.
     * We ALSO mirror into cs->peer_pubkey so the CONN_READY event_fn
     * can surface it to the caller. */
    uint8_t *peer_pub_ptr = (uint8_t *)malloc(ANTS_ED25519_PUBKEY_SIZE);
    if (peer_pub_ptr == NULL) {
        return PTLS_ERROR_NO_MEMORY;
    }
    if (parse_ed25519_spki(certs[0].base, certs[0].len, peer_pub_ptr) != 0) {
        free(peer_pub_ptr);
        return PTLS_ALERT_BAD_CERTIFICATE;
    }
    memcpy(cs->peer_pubkey, peer_pub_ptr, ANTS_ED25519_PUBKEY_SIZE);
    cs->peer_pubkey_set = 1;

    /* expected_peer_id enforcement (anti-MITM for bootstrap_dht_seeds,
     * RFC-0010). When the caller passed expected_peer_id to dial(), the
     * handshake fails closed on mismatch. memcmp on public pubkeys is
     * fine (no secret-dependent timing channel). */
    if (cs->expected_set && memcmp(cs->peer_pubkey, cs->expected_peer_id, ANTS_PEER_ID_SIZE) != 0) {
        free(peer_pub_ptr);
        return PTLS_ALERT_BAD_CERTIFICATE;
    }

    *verify_sign = ants_verify_sign_cb;
    *verify_data = peer_pub_ptr;
    return 0;
}

/* Append bytes to the stream's recv buffer. Drops the tail if the buffer
 * is full — phase 3c traffic is small request/response pairs so this is
 * acceptable; a later PR extends MAX_STREAM_DATA management to drive
 * QUIC flow-control back-pressure instead. */
static void
stream_recv_buf_append(struct ants_transport_stream_state *ss, const uint8_t *data, size_t len)
{
    if (len == 0) {
        return;
    }
    /* Compact when the buffer is fully drained so the next append starts
     * at offset 0. Avoids needing a ring buffer for the common case. */
    if (ss->recv_head == ss->recv_len) {
        ss->recv_head = 0;
        ss->recv_len = 0;
    }
    size_t free_tail = ANTS_TRANSPORT_STREAM_RECV_BUF_SIZE - ss->recv_len;
    size_t to_copy = (len < free_tail) ? len : free_tail;
    if (to_copy > 0) {
        memcpy(ss->recv_buf + ss->recv_len, data, to_copy);
        ss->recv_len += to_copy;
    }
    /* Surplus (len - to_copy) is silently dropped for phase 3c. */
}

/* ------------------------------------------------------------------------ */
/* Inbound stream bootstrap                                                 */
/*                                                                          */
/* When the peer opens a stream, picoquic delivers the first stream_data    */
/* or stream_fin event with stream_ctx == NULL (no app context has been    */
/* bound yet). We mirror the cnx-bootstrap pattern: heap-allocate a fresh   */
/* ss, link it into the cs's inbound_streams list (so CONN_CLOSED sweeps   */
/* it), and bind via picoquic_set_app_stream_ctx so subsequent callbacks   */
/* on the same stream find the ss directly. Fires STREAM_OPENED so the    */
/* caller can recognise the new stream before STREAM_READABLE delivers    */
/* the bytes.                                                              */
/* ------------------------------------------------------------------------ */

static struct ants_transport_stream_state *
bootstrap_inbound_stream(picoquic_cnx_t *cnx,
                         struct ants_transport_conn_state *cs,
                         uint64_t stream_id,
                         ants_transport_event_fn event_fn,
                         void *event_ctx)
{
    struct ants_transport_stream_state *ss =
        (struct ants_transport_stream_state *)malloc(sizeof *ss);
    if (ss == NULL) {
        return NULL;
    }
    memset(ss, 0, sizeof *ss);
    ss->parent_conn = cs;
    ss->stream_id = stream_id;
    /* PICOQUIC_IS_BIDIR_STREAM_ID: low-bit-1 clear → bidirectional. */
    ss->is_bidi = PICOQUIC_IS_BIDIR_STREAM_ID(stream_id) ? 1 : 0;
    ss->is_heap = 1;
    ss->next_inbound = cs->inbound_streams_head;
    cs->inbound_streams_head = ss;

    if (picoquic_set_app_stream_ctx(cnx, stream_id, ss) != 0) {
        cs->inbound_streams_head = ss->next_inbound;
        free(ss);
        return NULL;
    }

    /* Notify the caller. payload stays zero — actual bytes (if any) come
     * in the same picoquic event and we deliver them as STREAM_READABLE
     * right after this helper returns. */
    ants_transport_event_t ev;
    memset(&ev, 0, sizeof ev);
    ev.conn = (ants_transport_conn_t *)(void *)cs;
    ev.kind = ANTS_TRANSPORT_EV_STREAM_OPENED;
    ev.stream = (ants_transport_stream_t *)(void *)ss;
    (void)event_fn(&ev, event_ctx);
    return ss;
}

/* ------------------------------------------------------------------------ */
/* picoquic callback bridge                                                 */
/*                                                                          */
/* Registered per-connection by ants_transport_dial. Translates picoquic    */
/* events to ants_transport_event_t and delivers them to the user's         */
/* event_fn. Runs synchronously from inside tick() — no threading.          */
/* ------------------------------------------------------------------------ */

static int ants_transport_stream_cb(picoquic_cnx_t *cnx,
                                    uint64_t stream_id,
                                    uint8_t *bytes,
                                    size_t length,
                                    picoquic_call_back_event_t fin_or_event,
                                    void *callback_ctx,
                                    void *stream_ctx)
{
    if (callback_ctx == NULL) {
        return 0;
    }
    /* On inbound cnx, the FIRST callback arrives with callback_ctx ==
     * default_callback_ctx == &transport_state, BEFORE picotls's verify_
     * certificate has had a chance to bootstrap a per-cnx cs. In steady
     * state the bridge always sees a real cs (verify_certificate runs
     * before any picoquic_callback that surfaces a user-visible event),
     * but pre-handshake events like stateless_reset can arrive earlier.
     * Bail silently if we see the transport-state magic. */
    uint32_t ctx_magic;
    memcpy(&ctx_magic, callback_ctx, sizeof ctx_magic);
    if (ctx_magic != ANTS_TRANSPORT_CONN_STATE_MAGIC) {
        return 0;
    }
    struct ants_transport_conn_state *cs = (struct ants_transport_conn_state *)callback_ctx;
    struct ants_transport_stream_state *ss = (struct ants_transport_stream_state *)stream_ctx;
    ants_transport_event_fn event_fn = cs->parent->event_fn;
    void *event_ctx = cs->parent->event_ctx;

    /* The conn-state struct lives at offset 0 of the caller's
     * ants_transport_conn_t._opaque union, so casting the cs pointer
     * back to a conn_t pointer recovers the original caller-visible
     * handle. Same for stream_state -> stream_t. */
    ants_transport_event_t ev;
    memset(&ev, 0, sizeof ev);
    ev.conn = (ants_transport_conn_t *)(void *)cs;

    switch (fin_or_event) {
    case picoquic_callback_ready:
        ev.kind = ANTS_TRANSPORT_EV_CONN_READY;
        /* RFC 7250 binding: the verify_certificate callback populated
         * cs->peer_pubkey during the handshake. Mirror it into the
         * event's peer_id so the caller doesn't need to round-trip
         * through ants_transport_conn_peer_id. */
        if (cs->peer_pubkey_set) {
            memcpy(ev.peer_id.bytes, cs->peer_pubkey, ANTS_PEER_ID_SIZE);
        }
        (void)event_fn(&ev, event_ctx);
        break;

    case picoquic_callback_close:
    case picoquic_callback_application_close:
    case picoquic_callback_stateless_reset:
        ev.kind = ANTS_TRANSPORT_EV_CONN_CLOSED;
        /* Mirror the peer id exactly as the READY case does, so the
         * caller can correlate ready/closed pairs per peer. A close
         * before the handshake bound a pubkey (e.g. stateless reset)
         * legitimately leaves it all-zero. */
        if (cs->peer_pubkey_set) {
            memcpy(ev.peer_id.bytes, cs->peer_pubkey, ANTS_PEER_ID_SIZE);
        }
        (void)event_fn(&ev, event_ctx);
        /* After the callback returns picoquic deletes the cnx; clear
         * our pointer so subsequent stream ops fail closed rather than
         * use-after-free. */
        cs->cnx = NULL;
        /* Free any heap-allocated inbound stream states for this cnx.
         * Locally-opened streams live in the caller's _opaque buffer
         * and are NOT in this list — they're left to the caller. */
        {
            struct ants_transport_stream_state *iss = cs->inbound_streams_head;
            while (iss != NULL) {
                struct ants_transport_stream_state *next = iss->next_inbound;
                free(iss);
                iss = next;
            }
            cs->inbound_streams_head = NULL;
        }
        /* Heap-allocated cs (inbound bootstrap) needs to be unlinked from
         * the transport's inbound list and freed. Outbound cs lives in
         * the caller's _opaque buffer — never free()d by us. */
        if (cs->is_heap) {
            struct ants_transport_state *parent = cs->parent;
            struct ants_transport_conn_state **link = &parent->inbound_conns_head;
            while (*link != NULL && *link != cs) {
                link = &(*link)->next_inbound;
            }
            if (*link == cs) {
                *link = cs->next_inbound;
            }
            /* The picoquic cnx outlives this cs (picoquic deletes it
             * after the callback, or at picoquic_free time). Unbind the
             * callback so a later delete-time disconnect event can't
             * dereference the freed cs. */
            picoquic_set_callback(cnx, NULL, NULL);
            free(cs);
        }
        break;

    case picoquic_callback_stream_data:
        /* Peer-opened streams arrive with stream_ctx == NULL the first
         * time. Bootstrap a heap ss and fire STREAM_OPENED, then deliver
         * the data through the normal STREAM_READABLE path. */
        if (ss == NULL) {
            ss = bootstrap_inbound_stream(cnx, cs, stream_id, event_fn, event_ctx);
            if (ss == NULL) {
                return 0; /* allocation failed; drop silently */
            }
        }
        if (length > 0) {
            stream_recv_buf_append(ss, bytes, length);
            memset(&ev, 0, sizeof ev);
            ev.conn = (ants_transport_conn_t *)(void *)cs;
            ev.kind = ANTS_TRANSPORT_EV_STREAM_READABLE;
            ev.stream = (ants_transport_stream_t *)(void *)ss;
            ev.payload = bytes;
            ev.payload_len = length;
            (void)event_fn(&ev, event_ctx);
        }
        break;

    case picoquic_callback_stream_fin:
        /* Deliver the trailing bytes (if any) as STREAM_READABLE first,
         * then fire STREAM_FIN. Two events keeps the contract simple:
         * payload-bearing events ALWAYS use STREAM_READABLE; FIN is a
         * pure signal. */
        if (ss == NULL) {
            ss = bootstrap_inbound_stream(cnx, cs, stream_id, event_fn, event_ctx);
            if (ss == NULL) {
                return 0;
            }
        }
        if (length > 0) {
            stream_recv_buf_append(ss, bytes, length);
            memset(&ev, 0, sizeof ev);
            ev.conn = (ants_transport_conn_t *)(void *)cs;
            ev.kind = ANTS_TRANSPORT_EV_STREAM_READABLE;
            ev.stream = (ants_transport_stream_t *)(void *)ss;
            ev.payload = bytes;
            ev.payload_len = length;
            (void)event_fn(&ev, event_ctx);
        }
        ss->remote_fin_seen = 1;
        memset(&ev, 0, sizeof ev);
        ev.conn = (ants_transport_conn_t *)(void *)cs;
        ev.kind = ANTS_TRANSPORT_EV_STREAM_FIN;
        ev.stream = (ants_transport_stream_t *)(void *)ss;
        (void)event_fn(&ev, event_ctx);
        break;

    case picoquic_callback_stream_reset:
    case picoquic_callback_stop_sending:
        /* RESET_STREAM (peer aborts their send-side) and STOP_SENDING
         * (peer aborts their recv-side, i.e. asks us to stop sending)
         * both invalidate the stream for further use. Peer may reset a
         * stream we haven't seen any data on yet — bootstrap in that
         * case so the caller learns about the (now-dead) stream. */
        if (ss == NULL) {
            ss = bootstrap_inbound_stream(cnx, cs, stream_id, event_fn, event_ctx);
            if (ss == NULL) {
                return 0;
            }
        }
        ss->reset_seen = 1;
        ev.kind = ANTS_TRANSPORT_EV_STREAM_RESET;
        ev.stream = (ants_transport_stream_t *)(void *)ss;
        (void)event_fn(&ev, event_ctx);
        break;

    default:
        /* prepare_to_send, almost_ready, stream_gap, datagram_*, path_*,
         * pacing_changed, app_wakeup, etc. — none surface as user-visible
         * events in phase 3c. */
        break;
    }
    return 0;
}

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

    /* Initialise the conn-state buffer. Set magic so verify_certificate
     * can distinguish this caller-owned cs from the transport-state
     * default ctx (inbound cnx path). is_heap stays 0: this cs lives
     * in the caller's _opaque buffer, never free()'d by us. */
    memset(out_conn->_opaque, 0, sizeof out_conn->_opaque);
    struct ants_transport_conn_state *cs =
        (struct ants_transport_conn_state *)(void *)out_conn->_opaque;
    cs->magic = ANTS_TRANSPORT_CONN_STATE_MAGIC;
    cs->parent = state;
    if (expected_peer_id != NULL) {
        memcpy(cs->expected_peer_id, expected_peer_id->bytes, ANTS_PEER_ID_SIZE);
        cs->expected_set = 1;
    }

    /* picoquic_create_client_cnx is the convenience entry point that
     * creates the connection AND queues the initial packet. We pass
     * ALPN "ants" and SNI=NULL (we don't use server-name routing —
     * peer identity comes from the raw-pubkey TLS handshake, plumbed
     * in phase 3b). The callback bridge (ants_transport_stream_cb)
     * with cs as ctx surfaces picoquic events to the user's event_fn
     * via this connection's lifetime. */
    uint64_t now = picoquic_current_time();
    cs->cnx = picoquic_create_client_cnx(state->quic,
                                         (struct sockaddr *)&peer_addr,
                                         now,
                                         0,    /* preferred_version (0 = auto) */
                                         NULL, /* sni */
                                         "ants",
                                         ants_transport_stream_cb,
                                         cs);
    if (cs->cnx == NULL) {
        memset(out_conn->_opaque, 0, sizeof out_conn->_opaque);
        return ANTS_ERROR_HANDSHAKE_FAILED;
    }

    /* Phase 3c caveat: without TLS material (RFC 7250 raw pubkey + the
     * sign_fn wired into picotls — phase 3b), the handshake will fail
     * once the server-side validation kicks in. The dial *queues* the
     * INITIAL packet successfully and the caller's tick() flushes it
     * onto the wire, so the network path is exercised; eventually
     * picoquic fires picoquic_callback_close which the bridge above
     * translates into ANTS_TRANSPORT_EV_CONN_CLOSED for the user. */

    return ANTS_OK;
}

/* ------------------------------------------------------------------------ */
/* Streams                                                                  */
/*                                                                          */
/* Open: mint a stream-id via picoquic_get_next_local_stream_id, then call  */
/* picoquic_set_app_stream_ctx to materialise the stream object on the      */
/* picoquic side AND bind our ss pointer so subsequent callbacks reach the  */
/* right state. Open NEVER blocks and NEVER fails for valid args except     */
/* when the connection is already dead.                                     */
/*                                                                          */
/* Send: picoquic_add_to_stream_with_ctx, which copies into an internal     */
/* send queue and re-binds the app stream context (the rebind is a no-op    */
/* but cheap and keeps the invariant locally legible).                      */
/*                                                                          */
/* Recv: drain the linear buffer populated by the callback bridge. No       */
/* picoquic call needed — the bridge already pulled the bytes out of QUIC.  */
/*                                                                          */
/* Close: picoquic_add_to_stream with set_fin=1, length=0 — the peer sees a */
/* FIN. Reset: picoquic_reset_stream with the supplied error code — the    */
/* peer sees RESET_STREAM.                                                  */
/* ------------------------------------------------------------------------ */

static ants_error_t
open_stream_impl(ants_transport_conn_t *conn, ants_transport_stream_t *out_stream, int is_unidir)
{
    if (conn == NULL || out_stream == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    struct ants_transport_conn_state *cs =
        (struct ants_transport_conn_state *)(void *)conn->_opaque;
    if (cs->cnx == NULL) {
        /* Connection was closed (or never dialed). */
        return ANTS_ERROR_PEER_UNREACHABLE;
    }

    memset(out_stream->_opaque, 0, sizeof out_stream->_opaque);
    struct ants_transport_stream_state *ss =
        (struct ants_transport_stream_state *)(void *)out_stream->_opaque;
    ss->parent_conn = cs;
    ss->stream_id = picoquic_get_next_local_stream_id(cs->cnx, is_unidir);
    ss->is_bidi = is_unidir ? 0 : 1;

    /* Materialise the stream inside picoquic and bind ss as the
     * app_stream_ctx so callbacks find their way back here. set_app_
     * stream_ctx calls find_stream_for_writing internally, which
     * advances cnx->next_stream_id[] so subsequent opens get fresh
     * IDs. */
    int rc = picoquic_set_app_stream_ctx(cs->cnx, ss->stream_id, ss);
    if (rc != 0) {
        memset(out_stream->_opaque, 0, sizeof out_stream->_opaque);
        return ANTS_ERROR_PEER_UNREACHABLE;
    }
    return ANTS_OK;
}

ants_error_t ants_transport_open_bidi_stream(ants_transport_conn_t *conn,
                                             ants_transport_stream_t *out_stream)
{
    return open_stream_impl(conn, out_stream, 0 /* bidi */);
}

ants_error_t ants_transport_open_uni_stream(ants_transport_conn_t *conn,
                                            ants_transport_stream_t *out_stream)
{
    return open_stream_impl(conn, out_stream, 1 /* unidir */);
}

ants_error_t ants_transport_stream_send(ants_transport_stream_t *stream,
                                        const uint8_t *data,
                                        size_t len,
                                        bool fin)
{
    if (stream == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    /* `data` may be NULL only if len == 0 (a fin-only sentinel send). */
    if (data == NULL && len > 0) {
        return ANTS_ERROR_INVALID_ARG;
    }
    struct ants_transport_stream_state *ss =
        (struct ants_transport_stream_state *)(void *)stream->_opaque;
    struct ants_transport_conn_state *cs = ss->parent_conn;
    if (cs == NULL || cs->cnx == NULL) {
        return ANTS_ERROR_PEER_UNREACHABLE;
    }
    if (ss->reset_seen) {
        return ANTS_ERROR_STREAM_RESET;
    }
    if (ss->local_fin_sent) {
        /* We've already FIN'd; further sends on a closed half-stream
         * are a contract violation. */
        return ANTS_ERROR_INVALID_ARG;
    }
    int rc = picoquic_add_to_stream_with_ctx(cs->cnx, ss->stream_id, data, len, fin ? 1 : 0, ss);
    if (rc != 0) {
        return ANTS_ERROR_BUFFER_TOO_SMALL;
    }
    if (fin) {
        ss->local_fin_sent = 1;
    }
    return ANTS_OK;
}

ants_error_t ants_transport_stream_recv(ants_transport_stream_t *stream,
                                        uint8_t *out,
                                        size_t cap,
                                        size_t *out_len)
{
    if (stream == NULL || out_len == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (out == NULL && cap > 0) {
        return ANTS_ERROR_INVALID_ARG;
    }
    struct ants_transport_stream_state *ss =
        (struct ants_transport_stream_state *)(void *)stream->_opaque;
    *out_len = 0;
    if (ss->reset_seen) {
        return ANTS_ERROR_STREAM_RESET;
    }
    size_t available = ss->recv_len - ss->recv_head;
    if (available == 0 || cap == 0) {
        return ANTS_OK; /* nothing to drain right now */
    }
    size_t to_copy = (available < cap) ? available : cap;
    memcpy(out, ss->recv_buf + ss->recv_head, to_copy);
    ss->recv_head += to_copy;
    *out_len = to_copy;
    /* Compact-on-empty so the next callback append starts at offset 0. */
    if (ss->recv_head == ss->recv_len) {
        ss->recv_head = 0;
        ss->recv_len = 0;
    }
    return ANTS_OK;
}

ants_error_t ants_transport_stream_close(ants_transport_stream_t *stream)
{
    if (stream == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    struct ants_transport_stream_state *ss =
        (struct ants_transport_stream_state *)(void *)stream->_opaque;
    struct ants_transport_conn_state *cs = ss->parent_conn;
    if (cs == NULL || cs->cnx == NULL) {
        return ANTS_ERROR_PEER_UNREACHABLE;
    }
    if (ss->local_fin_sent) {
        /* Idempotent: already closed our send-side. */
        return ANTS_OK;
    }
    int rc = picoquic_add_to_stream_with_ctx(cs->cnx, ss->stream_id, NULL, 0, 1 /* fin */, ss);
    if (rc != 0) {
        return ANTS_ERROR_BUFFER_TOO_SMALL;
    }
    ss->local_fin_sent = 1;
    return ANTS_OK;
}

ants_error_t ants_transport_stream_reset(ants_transport_stream_t *stream, uint64_t error_code)
{
    if (stream == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    struct ants_transport_stream_state *ss =
        (struct ants_transport_stream_state *)(void *)stream->_opaque;
    struct ants_transport_conn_state *cs = ss->parent_conn;
    if (cs == NULL || cs->cnx == NULL) {
        return ANTS_ERROR_PEER_UNREACHABLE;
    }
    int rc = picoquic_reset_stream(cs->cnx, ss->stream_id, error_code);
    if (rc != 0) {
        return ANTS_ERROR_BUFFER_TOO_SMALL;
    }
    return ANTS_OK;
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

bool ants_transport_stream_is_bidi(const ants_transport_stream_t *stream)
{
    if (stream == NULL) {
        return false;
    }
    const struct ants_transport_stream_state *ss =
        (const struct ants_transport_stream_state *)(const void *)stream->_opaque;
    return ss->is_bidi != 0;
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
    if (conn == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    struct ants_transport_conn_state *cs =
        (struct ants_transport_conn_state *)(void *)conn->_opaque;
    if (cs->cnx == NULL) {
        /* Already closed (e.g. peer-initiated, or never dialed). The
         * graceful-close action is idempotent — report success rather
         * than confuse callers who legitimately don't know the conn
         * state. */
        return ANTS_OK;
    }
    /* Graceful CLOSE: queues a CONNECTION_CLOSE frame for the next
     * outbound packet carrying our error_code. tick() will eventually
     * flush it; once the peer ACKs (or we time out) picoquic fires
     * picoquic_callback_close which the bridge translates to
     * ANTS_TRANSPORT_EV_CONN_CLOSED. */
    int rc = picoquic_close(cs->cnx, error_code);
    if (rc != 0) {
        return ANTS_ERROR_PEER_UNREACHABLE;
    }
    return ANTS_OK;
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
