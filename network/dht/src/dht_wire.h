/*
 * dht_wire.h — DHT wire-format codec (PRIVATE: not installed).
 *
 * Defines the on-wire structure of the four DHT RPC pairs (PING,
 * FIND_NODE, GET_PEERS, ANNOUNCE_PEER + their responses) plus the
 * encode/decode functions. Each message is a single CBOR object,
 * canonically encoded per foundation/cbor's RFC 8949 §4.2.1 rules.
 *
 * Wire format (formalised in RFC-0008 v0.6 §11.2 "DHT RPC"):
 *
 *   envelope = {
 *       0: uint,     ; type discriminator (1..8, see ants_dht_msg_type_t)
 *       1: uint,     ; txid (request) or matched txid (response)
 *       2: map,      ; body — fields per type (possibly empty)
 *   }
 *
 * Integer keys (rather than text) for two reasons: (a) more compact
 * on the wire (1 byte vs 4-5 bytes per key), and (b) canonical-map
 * ordering is by numeric value — so the encoder emits 0, 1, 2 in that
 * order naturally without needing to think about key strings.
 *
 * Stream framing: each DHT RPC travels on its own bidi stream. The
 * sender writes one CBOR envelope and FIN. The receiver reads until
 * FIN and decodes the accumulated buffer. No length prefix needed
 * (QUIC stream FIN gives us the boundary).
 *
 * This header is private to the DHT implementation. It lives under
 * src/ rather than include/ so it isn't exposed to downstream
 * consumers — only dht.c and the test_dht.c unit tests reference it.
 */

#ifndef ANTS_DHT_WIRE_H
#define ANTS_DHT_WIRE_H

#include "ants_common.h"
#include "ants_crypto.h"
#include "ants_dht.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------ */
/* Message type discriminator                                               */
/* ------------------------------------------------------------------------ */

typedef enum {
    ANTS_DHT_MSG_PING = 1,
    ANTS_DHT_MSG_FIND_NODE = 2,
    ANTS_DHT_MSG_GET_PEERS = 3,
    ANTS_DHT_MSG_ANNOUNCE_PEER = 4,
    ANTS_DHT_MSG_PING_RESP = 5,
    ANTS_DHT_MSG_FIND_NODE_RESP = 6,
    ANTS_DHT_MSG_GET_PEERS_RESP = 7,
    ANTS_DHT_MSG_ANNOUNCE_PEER_RESP = 8,
} ants_dht_msg_type_t;

/* ------------------------------------------------------------------------ */
/* Token type                                                               */
/*                                                                          */
/* BitTorrent-style admission token: GET_PEERS responses carry one; clients */
/* must echo it back in the subsequent ANNOUNCE_PEER for the listener to    */
/* accept the announce. Defeats off-path spoofing — an attacker needs to    */
/* receive the GET_PEERS_RESP to know the token. 16 bytes is the BitTorrent */
/* convention.                                                              */
/* ------------------------------------------------------------------------ */

#define ANTS_DHT_TOKEN_SIZE 16

/* ------------------------------------------------------------------------ */
/* Bound on peers carried in a single response                              */
/*                                                                          */
/* FIND_NODE_RESP and GET_PEERS_RESP both carry an array of peers. Cap at K */
/* (Kademlia replication factor) so the worst-case message stays bounded   */
/* (~1.6 KB on the wire).                                                   */
/* ------------------------------------------------------------------------ */

#define ANTS_DHT_MAX_PEERS_PER_MSG ANTS_DHT_K

/* ------------------------------------------------------------------------ */
/* Request types                                                            */
/* ------------------------------------------------------------------------ */

typedef struct {
    uint32_t txid;
    /* No body fields. */
} ants_dht_ping_req_t;

typedef struct {
    uint32_t txid;
    /* Body: { "target": bytes(32) } */
    ants_peer_id_t target;
} ants_dht_find_node_req_t;

typedef struct {
    uint32_t txid;
    /* Body: { "key": uint64 } */
    ants_dht_shard_key_t key;
} ants_dht_get_peers_req_t;

typedef struct {
    uint32_t txid;
    /* Body: { "key": uint64, "token": bytes(16) } */
    ants_dht_shard_key_t key;
    uint8_t token[ANTS_DHT_TOKEN_SIZE];
} ants_dht_announce_peer_req_t;

/* ------------------------------------------------------------------------ */
/* Response types                                                           */
/* ------------------------------------------------------------------------ */

typedef struct {
    uint32_t txid;
    /* No body fields. */
} ants_dht_ping_resp_t;

typedef struct {
    uint32_t txid;
    /* Body: { "peers": [{"addr": text, "id": bytes(32)}, ...] }
     * Up to K closest peers to the request's target, by XOR distance. */
    size_t peer_count;
    ants_dht_peer_t peers[ANTS_DHT_MAX_PEERS_PER_MSG];
} ants_dht_find_node_resp_t;

typedef struct {
    uint32_t txid;
    /* Body: { "peers": [...], "token": bytes(16) }
     *
     * The peers array carries:
     *   - peers known to host the requested shard, when we have any;
     *   - otherwise the K closest peers to the shard-key's peer-id
     *     expansion (so the requester can iterate further).
     *
     * The token is required for any subsequent ANNOUNCE_PEER from the
     * same client. */
    size_t peer_count;
    ants_dht_peer_t peers[ANTS_DHT_MAX_PEERS_PER_MSG];
    uint8_t token[ANTS_DHT_TOKEN_SIZE];
} ants_dht_get_peers_resp_t;

typedef struct {
    uint32_t txid;
    /* No body fields — just an ACK that the announce was accepted. */
} ants_dht_announce_peer_resp_t;

/* ------------------------------------------------------------------------ */
/* Envelope peek                                                            */
/*                                                                          */
/* Decodes just the type discriminator (and the map shape that surrounds    */
/* it) from a wire buffer. The caller dispatches on the type and then       */
/* calls the type-specific decoder against the same buffer.                  */
/*                                                                          */
/* This is a pure peek — it does NOT advance any decoder state and may be   */
/* called multiple times on the same buffer.                                */
/* ------------------------------------------------------------------------ */

ants_error_t ants_dht_wire_peek_type(const uint8_t *buf, size_t len, ants_dht_msg_type_t *out_type);

/* ------------------------------------------------------------------------ */
/* Encoders                                                                 */
/*                                                                          */
/* Each encoder takes a caller-provided write buffer (buf, cap) and an      */
/* input message struct. On success writes the canonical CBOR encoding and  */
/* sets *out_len to the number of bytes written.                           */
/*                                                                          */
/* Errors:                                                                  */
/*   ANTS_ERROR_INVALID_ARG       — NULL args.                              */
/*   ANTS_ERROR_BUFFER_TOO_SMALL  — cap < required size.                    */
/*   ANTS_ERROR_NON_CANONICAL    — should never happen here (our encoder    */
/*                                  emits canonical order by construction). */
/* ------------------------------------------------------------------------ */

ants_error_t ants_dht_wire_encode_ping_req(uint8_t *buf,
                                           size_t cap,
                                           size_t *out_len,
                                           const ants_dht_ping_req_t *msg);

ants_error_t ants_dht_wire_encode_find_node_req(uint8_t *buf,
                                                size_t cap,
                                                size_t *out_len,
                                                const ants_dht_find_node_req_t *msg);

ants_error_t ants_dht_wire_encode_get_peers_req(uint8_t *buf,
                                                size_t cap,
                                                size_t *out_len,
                                                const ants_dht_get_peers_req_t *msg);

ants_error_t ants_dht_wire_encode_announce_peer_req(uint8_t *buf,
                                                    size_t cap,
                                                    size_t *out_len,
                                                    const ants_dht_announce_peer_req_t *msg);

ants_error_t ants_dht_wire_encode_ping_resp(uint8_t *buf,
                                            size_t cap,
                                            size_t *out_len,
                                            const ants_dht_ping_resp_t *msg);

ants_error_t ants_dht_wire_encode_find_node_resp(uint8_t *buf,
                                                 size_t cap,
                                                 size_t *out_len,
                                                 const ants_dht_find_node_resp_t *msg);

ants_error_t ants_dht_wire_encode_get_peers_resp(uint8_t *buf,
                                                 size_t cap,
                                                 size_t *out_len,
                                                 const ants_dht_get_peers_resp_t *msg);

ants_error_t ants_dht_wire_encode_announce_peer_resp(uint8_t *buf,
                                                     size_t cap,
                                                     size_t *out_len,
                                                     const ants_dht_announce_peer_resp_t *msg);

/* ------------------------------------------------------------------------ */
/* Decoders                                                                 */
/*                                                                          */
/* Each decoder takes a wire buffer and fills the corresponding struct. The */
/* multiaddr field of any peer entry is COPIED into the struct (zero-       */
/* terminated) so the struct outlives the input buffer.                    */
/*                                                                          */
/* Errors:                                                                  */
/*   ANTS_ERROR_INVALID_ARG       — NULL args.                              */
/*   ANTS_ERROR_NON_CANONICAL    — input violates canonical CBOR or shape.  */
/*   ANTS_ERROR_BUFFER_TOO_SMALL  — too many peers / multiaddr too long.    */
/* ------------------------------------------------------------------------ */

ants_error_t
ants_dht_wire_decode_ping_req(const uint8_t *buf, size_t len, ants_dht_ping_req_t *out);

ants_error_t
ants_dht_wire_decode_find_node_req(const uint8_t *buf, size_t len, ants_dht_find_node_req_t *out);

ants_error_t
ants_dht_wire_decode_get_peers_req(const uint8_t *buf, size_t len, ants_dht_get_peers_req_t *out);

ants_error_t ants_dht_wire_decode_announce_peer_req(const uint8_t *buf,
                                                    size_t len,
                                                    ants_dht_announce_peer_req_t *out);

ants_error_t
ants_dht_wire_decode_ping_resp(const uint8_t *buf, size_t len, ants_dht_ping_resp_t *out);

ants_error_t
ants_dht_wire_decode_find_node_resp(const uint8_t *buf, size_t len, ants_dht_find_node_resp_t *out);

ants_error_t
ants_dht_wire_decode_get_peers_resp(const uint8_t *buf, size_t len, ants_dht_get_peers_resp_t *out);

ants_error_t ants_dht_wire_decode_announce_peer_resp(const uint8_t *buf,
                                                     size_t len,
                                                     ants_dht_announce_peer_resp_t *out);

#ifdef __cplusplus
}
#endif

#endif /* ANTS_DHT_WIRE_H */
