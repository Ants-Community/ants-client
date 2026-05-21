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
#include <string.h>

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
};

/* ants_transport_t MUST be at least as large as the internal state
 * struct. The trick: declare a typedef whose array size is -1 (an
 * invalid type) when the condition fails. C99 compile error then
 * surfaces at build time rather than corrupting memory at run time.
 * Same pattern as ants_blake3_ctx_size_check in foundation/crypto. */
typedef char ants_transport_state_size_check
    [(sizeof(struct ants_transport_state) <= sizeof(((ants_transport_t *)0)->_opaque)) ? 1 : -1];

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

    /* Idle timeout: picoquic exposes per-connection idle timeouts.
     * Phase 2 will plumb config->idle_timeout_ms through. */

    return ANTS_OK;
}

ants_error_t ants_transport_destroy(ants_transport_t *t, uint64_t close_code)
{
    (void)close_code; /* Phase 2 will pass close_code to per-connection
                       * CONNECTION_CLOSE frames. */
    if (t == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    struct ants_transport_state *state = (struct ants_transport_state *)(void *)t->_opaque;
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

uint32_t ants_transport_tick(ants_transport_t *t)
{
    /* Documented contract: returns the number of ms until next wake.
     * Until the real implementation lands, return UINT32_MAX so any
     * caller-driven loop using us as a placeholder simply sleeps
     * forever rather than spinning. */
    (void)t;
    return UINT32_MAX;
}

/* ------------------------------------------------------------------------ */
/* Dialing                                                                  */
/* ------------------------------------------------------------------------ */

ants_error_t ants_transport_dial(ants_transport_t *t,
                                 const char *multiaddr,
                                 const ants_peer_id_t *expected_peer_id,
                                 ants_transport_conn_t *out_conn)
{
    (void)t;
    (void)multiaddr;
    (void)expected_peer_id;
    (void)out_conn;
    return ANTS_ERROR_NOT_IMPLEMENTED;
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
