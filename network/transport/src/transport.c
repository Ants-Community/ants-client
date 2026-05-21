/*
 * transport.c — Stub implementation of the P2P transport.
 *
 * v1.0 scaffold: every function returns ANTS_ERROR_NOT_IMPLEMENTED or
 * the documented safe default. The real implementation against
 * vendored picoquic lands in subsequent PRs. See ants_transport.h for
 * the API contract.
 *
 * Why the stub exists: upstream components (network/dht, network/
 * gossip, reputation/identity) reference the transport API in their
 * data structures and call sites. Having the API compiled — even as a
 * NOT_IMPLEMENTED stub — means those components can integrate against
 * the agreed shape without mocking or ifdef'ing around a future API.
 *
 * Same pattern as foundation/tee.
 */

#include "ants_transport.h"

#include <stddef.h>
#include <stdint.h>

/* ------------------------------------------------------------------------ */
/* Lifecycle                                                                */
/* ------------------------------------------------------------------------ */

ants_error_t ants_transport_init(ants_transport_t *t, const ants_transport_config_t *config)
{
    (void)t;
    (void)config;
    return ANTS_ERROR_NOT_IMPLEMENTED;
}

ants_error_t ants_transport_destroy(ants_transport_t *t, uint64_t close_code)
{
    (void)t;
    (void)close_code;
    return ANTS_ERROR_NOT_IMPLEMENTED;
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
