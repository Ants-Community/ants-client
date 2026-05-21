/*
 * dht_wire.c — CBOR encoder/decoder for the four DHT RPC pairs.
 *
 * Wire format conventions are documented in dht_wire.h. This file
 * implements one encoder + one decoder per message type, sharing a
 * small set of helpers for the common envelope (type, txid, body) and
 * for serialising/deserialising the recurring peer-descriptor shape.
 *
 * All encoders emit canonical CBOR (RFC 8949 §4.2.1) by construction:
 * map keys are integers (0, 1, 2 — for type, txid, body) which sort
 * numerically. The decoder is strict — any non-canonical input is
 * rejected by foundation/cbor's dec_finalise / per-element calls.
 */

#include "dht_wire.h"

#include "ants_cbor.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* ------------------------------------------------------------------------ */
/* Helpers                                                                  */
/* ------------------------------------------------------------------------ */

/* Forward declaration: expect_text_key is used by decode_peer below; its
 * body lives further down (alongside the other key-decoding helpers). */
static ants_error_t expect_text_key(ants_cbor_dec_t *dec, const char *expected, size_t exp_len);

/* Encode the envelope opener: map(N) where N is 3 if has_body else 2,
 * followed by `0: type` and `1: txid`. The caller continues with the
 * body block (key 2 + body map) if has_body. */
static ants_error_t
encode_envelope_head(ants_cbor_enc_t *enc, ants_dht_msg_type_t type, uint32_t txid, int has_body)
{
    ants_error_t err;
    if ((err = ants_cbor_enc_map(enc, (size_t)(has_body ? 3 : 2))) != ANTS_OK) {
        return err;
    }
    /* Canonical key order: 0 < 1 < 2 numerically. */
    if ((err = ants_cbor_enc_uint(enc, 0)) != ANTS_OK) {
        return err;
    }
    if ((err = ants_cbor_enc_uint(enc, (uint64_t)type)) != ANTS_OK) {
        return err;
    }
    if ((err = ants_cbor_enc_uint(enc, 1)) != ANTS_OK) {
        return err;
    }
    if ((err = ants_cbor_enc_uint(enc, (uint64_t)txid)) != ANTS_OK) {
        return err;
    }
    if (has_body) {
        /* Key 2 opens the body map; caller emits the inner map(N). */
        if ((err = ants_cbor_enc_uint(enc, 2)) != ANTS_OK) {
            return err;
        }
    }
    return ANTS_OK;
}

/* Encode a peer descriptor as { "id": bytes(32), "addr": text }.
 * Canonical CBOR (RFC 8949 §4.2.1) sorts map keys by their CBOR
 * encoding bytewise. "id" encodes as text(2)="0x62 69 64" while
 * "addr" encodes as text(4)="0x64 61 64 64 72" — the length-tag byte
 * makes "id" (0x62 ...) sort BEFORE "addr" (0x64 ...). Foundation/cbor
 * rejects non-canonical key order, so emit them in this order. */
static ants_error_t encode_peer(ants_cbor_enc_t *enc, const ants_dht_peer_t *peer)
{
    ants_error_t err;
    if ((err = ants_cbor_enc_map(enc, 2)) != ANTS_OK) {
        return err;
    }
    if ((err = ants_cbor_enc_text(enc, "id", 2)) != ANTS_OK) {
        return err;
    }
    if ((err = ants_cbor_enc_bytes(enc, peer->peer_id.bytes, ANTS_PEER_ID_SIZE)) != ANTS_OK) {
        return err;
    }
    if ((err = ants_cbor_enc_text(enc, "addr", 4)) != ANTS_OK) {
        return err;
    }
    if ((err = ants_cbor_enc_text(enc, peer->multiaddr, strlen(peer->multiaddr))) != ANTS_OK) {
        return err;
    }
    return ANTS_OK;
}

/* Decode the envelope opener. Reads:
 *   map(N) → 0 → type → 1 → txid → [2 → expects body next, returned via has_body]
 * The caller then decodes the body map (if has_body) or finalises.
 *
 * Validates expected_type matches what was read. */
static ants_error_t decode_envelope_head(ants_cbor_dec_t *dec,
                                         ants_dht_msg_type_t expected_type,
                                         uint32_t *out_txid,
                                         int *out_has_body)
{
    ants_error_t err;
    size_t map_n;
    if ((err = ants_cbor_dec_map(dec, &map_n)) != ANTS_OK) {
        return err;
    }
    if (map_n != 2 && map_n != 3) {
        return ANTS_ERROR_NON_CANONICAL;
    }
    /* key 0 → type */
    uint64_t key;
    if ((err = ants_cbor_dec_uint(dec, &key)) != ANTS_OK) {
        return err;
    }
    if (key != 0) {
        return ANTS_ERROR_NON_CANONICAL;
    }
    uint64_t type_val;
    if ((err = ants_cbor_dec_uint(dec, &type_val)) != ANTS_OK) {
        return err;
    }
    if (type_val != (uint64_t)expected_type) {
        return ANTS_ERROR_NON_CANONICAL;
    }
    /* key 1 → txid */
    if ((err = ants_cbor_dec_uint(dec, &key)) != ANTS_OK) {
        return err;
    }
    if (key != 1) {
        return ANTS_ERROR_NON_CANONICAL;
    }
    uint64_t txid_val;
    if ((err = ants_cbor_dec_uint(dec, &txid_val)) != ANTS_OK) {
        return err;
    }
    if (txid_val > UINT32_MAX) {
        return ANTS_ERROR_NON_CANONICAL;
    }
    *out_txid = (uint32_t)txid_val;

    if (map_n == 3) {
        /* key 2 → body follows */
        if ((err = ants_cbor_dec_uint(dec, &key)) != ANTS_OK) {
            return err;
        }
        if (key != 2) {
            return ANTS_ERROR_NON_CANONICAL;
        }
        *out_has_body = 1;
    } else {
        *out_has_body = 0;
    }
    return ANTS_OK;
}

/* Decode a peer descriptor map → ants_dht_peer_t. Order matches the
 * canonical encoding above: "id" first, then "addr". */
static ants_error_t decode_peer(ants_cbor_dec_t *dec, ants_dht_peer_t *out)
{
    ants_error_t err;
    size_t map_n;
    if ((err = ants_cbor_dec_map(dec, &map_n)) != ANTS_OK) {
        return err;
    }
    if (map_n != 2) {
        return ANTS_ERROR_NON_CANONICAL;
    }
    /* "id" first (canonical: "id" encoded as text(2) sorts before
     * "addr" encoded as text(4)). */
    if ((err = expect_text_key(dec, "id", 2)) != ANTS_OK) {
        return err;
    }
    const uint8_t *id_bytes;
    size_t id_len;
    if ((err = ants_cbor_dec_bytes(dec, &id_bytes, &id_len)) != ANTS_OK) {
        return err;
    }
    if (id_len != ANTS_PEER_ID_SIZE) {
        return ANTS_ERROR_NON_CANONICAL;
    }
    memcpy(out->peer_id.bytes, id_bytes, ANTS_PEER_ID_SIZE);

    /* "addr" second. */
    if ((err = expect_text_key(dec, "addr", 4)) != ANTS_OK) {
        return err;
    }
    const char *addr_text;
    size_t addr_len;
    if ((err = ants_cbor_dec_text(dec, &addr_text, &addr_len)) != ANTS_OK) {
        return err;
    }
    if (addr_len >= ANTS_MULTIADDR_MAX_LEN) {
        return ANTS_ERROR_BUFFER_TOO_SMALL;
    }
    memcpy(out->multiaddr, addr_text, addr_len);
    out->multiaddr[addr_len] = '\0';
    return ANTS_OK;
}

/* Decode a CBOR text key and assert it matches expected. */
static ants_error_t expect_text_key(ants_cbor_dec_t *dec, const char *expected, size_t exp_len)
{
    const char *key_text;
    size_t key_len;
    ants_error_t err = ants_cbor_dec_text(dec, &key_text, &key_len);
    if (err != ANTS_OK) {
        return err;
    }
    if (key_len != exp_len || memcmp(key_text, expected, exp_len) != 0) {
        return ANTS_ERROR_NON_CANONICAL;
    }
    return ANTS_OK;
}

/* ------------------------------------------------------------------------ */
/* Envelope peek                                                            */
/* ------------------------------------------------------------------------ */

ants_error_t ants_dht_wire_peek_type(const uint8_t *buf, size_t len, ants_dht_msg_type_t *out_type)
{
    if (buf == NULL || out_type == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    ants_cbor_dec_t dec;
    ants_error_t err = ants_cbor_dec_init(&dec, buf, len);
    if (err != ANTS_OK) {
        return err;
    }
    size_t map_n;
    if ((err = ants_cbor_dec_map(&dec, &map_n)) != ANTS_OK) {
        return err;
    }
    if (map_n != 2 && map_n != 3) {
        return ANTS_ERROR_NON_CANONICAL;
    }
    uint64_t key;
    if ((err = ants_cbor_dec_uint(&dec, &key)) != ANTS_OK) {
        return err;
    }
    if (key != 0) {
        return ANTS_ERROR_NON_CANONICAL;
    }
    uint64_t type_val;
    if ((err = ants_cbor_dec_uint(&dec, &type_val)) != ANTS_OK) {
        return err;
    }
    if (type_val < ANTS_DHT_MSG_PING || type_val > ANTS_DHT_MSG_ANNOUNCE_PEER_RESP) {
        return ANTS_ERROR_NON_CANONICAL;
    }
    *out_type = (ants_dht_msg_type_t)type_val;
    return ANTS_OK;
}

/* ------------------------------------------------------------------------ */
/* PING / PING_RESP — empty body                                            */
/* ------------------------------------------------------------------------ */

ants_error_t ants_dht_wire_encode_ping_req(uint8_t *buf,
                                           size_t cap,
                                           size_t *out_len,
                                           const ants_dht_ping_req_t *msg)
{
    if (buf == NULL || out_len == NULL || msg == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    ants_cbor_enc_t enc;
    ants_error_t err = ants_cbor_enc_init(&enc, buf, cap);
    if (err != ANTS_OK) {
        return err;
    }
    if ((err = encode_envelope_head(&enc, ANTS_DHT_MSG_PING, msg->txid, 0)) != ANTS_OK) {
        return err;
    }
    if ((err = ants_cbor_enc_finalise(&enc)) != ANTS_OK) {
        return err;
    }
    *out_len = enc.pos;
    return ANTS_OK;
}

ants_error_t ants_dht_wire_decode_ping_req(const uint8_t *buf, size_t len, ants_dht_ping_req_t *out)
{
    if (buf == NULL || out == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    ants_cbor_dec_t dec;
    ants_error_t err = ants_cbor_dec_init(&dec, buf, len);
    if (err != ANTS_OK) {
        return err;
    }
    int has_body;
    if ((err = decode_envelope_head(&dec, ANTS_DHT_MSG_PING, &out->txid, &has_body)) != ANTS_OK) {
        return err;
    }
    if (has_body) {
        return ANTS_ERROR_NON_CANONICAL;
    }
    return ants_cbor_dec_finalise(&dec);
}

ants_error_t ants_dht_wire_encode_ping_resp(uint8_t *buf,
                                            size_t cap,
                                            size_t *out_len,
                                            const ants_dht_ping_resp_t *msg)
{
    if (buf == NULL || out_len == NULL || msg == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    ants_cbor_enc_t enc;
    ants_error_t err = ants_cbor_enc_init(&enc, buf, cap);
    if (err != ANTS_OK) {
        return err;
    }
    if ((err = encode_envelope_head(&enc, ANTS_DHT_MSG_PING_RESP, msg->txid, 0)) != ANTS_OK) {
        return err;
    }
    if ((err = ants_cbor_enc_finalise(&enc)) != ANTS_OK) {
        return err;
    }
    *out_len = enc.pos;
    return ANTS_OK;
}

ants_error_t
ants_dht_wire_decode_ping_resp(const uint8_t *buf, size_t len, ants_dht_ping_resp_t *out)
{
    if (buf == NULL || out == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    ants_cbor_dec_t dec;
    ants_error_t err = ants_cbor_dec_init(&dec, buf, len);
    if (err != ANTS_OK) {
        return err;
    }
    int has_body;
    if ((err = decode_envelope_head(&dec, ANTS_DHT_MSG_PING_RESP, &out->txid, &has_body)) !=
        ANTS_OK) {
        return err;
    }
    if (has_body) {
        return ANTS_ERROR_NON_CANONICAL;
    }
    return ants_cbor_dec_finalise(&dec);
}

/* ------------------------------------------------------------------------ */
/* FIND_NODE / FIND_NODE_RESP                                               */
/* ------------------------------------------------------------------------ */

ants_error_t ants_dht_wire_encode_find_node_req(uint8_t *buf,
                                                size_t cap,
                                                size_t *out_len,
                                                const ants_dht_find_node_req_t *msg)
{
    if (buf == NULL || out_len == NULL || msg == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    ants_cbor_enc_t enc;
    ants_error_t err = ants_cbor_enc_init(&enc, buf, cap);
    if (err != ANTS_OK) {
        return err;
    }
    if ((err = encode_envelope_head(&enc, ANTS_DHT_MSG_FIND_NODE, msg->txid, 1)) != ANTS_OK) {
        return err;
    }
    /* body: { "target": bytes(32) } */
    if ((err = ants_cbor_enc_map(&enc, 1)) != ANTS_OK) {
        return err;
    }
    if ((err = ants_cbor_enc_text(&enc, "target", 6)) != ANTS_OK) {
        return err;
    }
    if ((err = ants_cbor_enc_bytes(&enc, msg->target.bytes, ANTS_PEER_ID_SIZE)) != ANTS_OK) {
        return err;
    }
    if ((err = ants_cbor_enc_finalise(&enc)) != ANTS_OK) {
        return err;
    }
    *out_len = enc.pos;
    return ANTS_OK;
}

ants_error_t
ants_dht_wire_decode_find_node_req(const uint8_t *buf, size_t len, ants_dht_find_node_req_t *out)
{
    if (buf == NULL || out == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    ants_cbor_dec_t dec;
    ants_error_t err = ants_cbor_dec_init(&dec, buf, len);
    if (err != ANTS_OK) {
        return err;
    }
    int has_body;
    if ((err = decode_envelope_head(&dec, ANTS_DHT_MSG_FIND_NODE, &out->txid, &has_body)) !=
        ANTS_OK) {
        return err;
    }
    if (!has_body) {
        return ANTS_ERROR_NON_CANONICAL;
    }
    size_t body_n;
    if ((err = ants_cbor_dec_map(&dec, &body_n)) != ANTS_OK) {
        return err;
    }
    if (body_n != 1) {
        return ANTS_ERROR_NON_CANONICAL;
    }
    if ((err = expect_text_key(&dec, "target", 6)) != ANTS_OK) {
        return err;
    }
    const uint8_t *target_bytes;
    size_t target_len;
    if ((err = ants_cbor_dec_bytes(&dec, &target_bytes, &target_len)) != ANTS_OK) {
        return err;
    }
    if (target_len != ANTS_PEER_ID_SIZE) {
        return ANTS_ERROR_NON_CANONICAL;
    }
    memcpy(out->target.bytes, target_bytes, ANTS_PEER_ID_SIZE);
    return ants_cbor_dec_finalise(&dec);
}

/* Common to FIND_NODE_RESP and GET_PEERS_RESP: encode the peers array.
 * Caller is inside the body map at the "peers" key position. */
static ants_error_t
encode_peers_array(ants_cbor_enc_t *enc, const ants_dht_peer_t *peers, size_t count)
{
    ants_error_t err;
    if ((err = ants_cbor_enc_array(enc, count)) != ANTS_OK) {
        return err;
    }
    for (size_t i = 0; i < count; i++) {
        if ((err = encode_peer(enc, &peers[i])) != ANTS_OK) {
            return err;
        }
    }
    return ANTS_OK;
}

/* Common to FIND_NODE_RESP / GET_PEERS_RESP: decode the peers array. */
static ants_error_t
decode_peers_array(ants_cbor_dec_t *dec, ants_dht_peer_t *out_peers, size_t cap, size_t *out_count)
{
    ants_error_t err;
    size_t arr_n;
    if ((err = ants_cbor_dec_array(dec, &arr_n)) != ANTS_OK) {
        return err;
    }
    if (arr_n > cap) {
        return ANTS_ERROR_BUFFER_TOO_SMALL;
    }
    for (size_t i = 0; i < arr_n; i++) {
        if ((err = decode_peer(dec, &out_peers[i])) != ANTS_OK) {
            return err;
        }
    }
    *out_count = arr_n;
    return ANTS_OK;
}

ants_error_t ants_dht_wire_encode_find_node_resp(uint8_t *buf,
                                                 size_t cap,
                                                 size_t *out_len,
                                                 const ants_dht_find_node_resp_t *msg)
{
    if (buf == NULL || out_len == NULL || msg == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (msg->peer_count > ANTS_DHT_MAX_PEERS_PER_MSG) {
        return ANTS_ERROR_INVALID_ARG;
    }
    ants_cbor_enc_t enc;
    ants_error_t err = ants_cbor_enc_init(&enc, buf, cap);
    if (err != ANTS_OK) {
        return err;
    }
    if ((err = encode_envelope_head(&enc, ANTS_DHT_MSG_FIND_NODE_RESP, msg->txid, 1)) != ANTS_OK) {
        return err;
    }
    /* body: { "peers": [...] } */
    if ((err = ants_cbor_enc_map(&enc, 1)) != ANTS_OK) {
        return err;
    }
    if ((err = ants_cbor_enc_text(&enc, "peers", 5)) != ANTS_OK) {
        return err;
    }
    if ((err = encode_peers_array(&enc, msg->peers, msg->peer_count)) != ANTS_OK) {
        return err;
    }
    if ((err = ants_cbor_enc_finalise(&enc)) != ANTS_OK) {
        return err;
    }
    *out_len = enc.pos;
    return ANTS_OK;
}

ants_error_t
ants_dht_wire_decode_find_node_resp(const uint8_t *buf, size_t len, ants_dht_find_node_resp_t *out)
{
    if (buf == NULL || out == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    ants_cbor_dec_t dec;
    ants_error_t err = ants_cbor_dec_init(&dec, buf, len);
    if (err != ANTS_OK) {
        return err;
    }
    int has_body;
    if ((err = decode_envelope_head(&dec, ANTS_DHT_MSG_FIND_NODE_RESP, &out->txid, &has_body)) !=
        ANTS_OK) {
        return err;
    }
    if (!has_body) {
        return ANTS_ERROR_NON_CANONICAL;
    }
    size_t body_n;
    if ((err = ants_cbor_dec_map(&dec, &body_n)) != ANTS_OK) {
        return err;
    }
    if (body_n != 1) {
        return ANTS_ERROR_NON_CANONICAL;
    }
    if ((err = expect_text_key(&dec, "peers", 5)) != ANTS_OK) {
        return err;
    }
    if ((err = decode_peers_array(
             &dec, out->peers, ANTS_DHT_MAX_PEERS_PER_MSG, &out->peer_count)) != ANTS_OK) {
        return err;
    }
    return ants_cbor_dec_finalise(&dec);
}

/* ------------------------------------------------------------------------ */
/* GET_PEERS / GET_PEERS_RESP                                               */
/* ------------------------------------------------------------------------ */

ants_error_t ants_dht_wire_encode_get_peers_req(uint8_t *buf,
                                                size_t cap,
                                                size_t *out_len,
                                                const ants_dht_get_peers_req_t *msg)
{
    if (buf == NULL || out_len == NULL || msg == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    ants_cbor_enc_t enc;
    ants_error_t err = ants_cbor_enc_init(&enc, buf, cap);
    if (err != ANTS_OK) {
        return err;
    }
    if ((err = encode_envelope_head(&enc, ANTS_DHT_MSG_GET_PEERS, msg->txid, 1)) != ANTS_OK) {
        return err;
    }
    /* body: { "key": uint64 } */
    if ((err = ants_cbor_enc_map(&enc, 1)) != ANTS_OK) {
        return err;
    }
    if ((err = ants_cbor_enc_text(&enc, "key", 3)) != ANTS_OK) {
        return err;
    }
    if ((err = ants_cbor_enc_uint(&enc, msg->key)) != ANTS_OK) {
        return err;
    }
    if ((err = ants_cbor_enc_finalise(&enc)) != ANTS_OK) {
        return err;
    }
    *out_len = enc.pos;
    return ANTS_OK;
}

ants_error_t
ants_dht_wire_decode_get_peers_req(const uint8_t *buf, size_t len, ants_dht_get_peers_req_t *out)
{
    if (buf == NULL || out == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    ants_cbor_dec_t dec;
    ants_error_t err = ants_cbor_dec_init(&dec, buf, len);
    if (err != ANTS_OK) {
        return err;
    }
    int has_body;
    if ((err = decode_envelope_head(&dec, ANTS_DHT_MSG_GET_PEERS, &out->txid, &has_body)) !=
        ANTS_OK) {
        return err;
    }
    if (!has_body) {
        return ANTS_ERROR_NON_CANONICAL;
    }
    size_t body_n;
    if ((err = ants_cbor_dec_map(&dec, &body_n)) != ANTS_OK) {
        return err;
    }
    if (body_n != 1) {
        return ANTS_ERROR_NON_CANONICAL;
    }
    if ((err = expect_text_key(&dec, "key", 3)) != ANTS_OK) {
        return err;
    }
    if ((err = ants_cbor_dec_uint(&dec, &out->key)) != ANTS_OK) {
        return err;
    }
    return ants_cbor_dec_finalise(&dec);
}

ants_error_t ants_dht_wire_encode_get_peers_resp(uint8_t *buf,
                                                 size_t cap,
                                                 size_t *out_len,
                                                 const ants_dht_get_peers_resp_t *msg)
{
    if (buf == NULL || out_len == NULL || msg == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    if (msg->peer_count > ANTS_DHT_MAX_PEERS_PER_MSG) {
        return ANTS_ERROR_INVALID_ARG;
    }
    ants_cbor_enc_t enc;
    ants_error_t err = ants_cbor_enc_init(&enc, buf, cap);
    if (err != ANTS_OK) {
        return err;
    }
    if ((err = encode_envelope_head(&enc, ANTS_DHT_MSG_GET_PEERS_RESP, msg->txid, 1)) != ANTS_OK) {
        return err;
    }
    /* body: { "peers": [...], "token": bytes(16) } */
    if ((err = ants_cbor_enc_map(&enc, 2)) != ANTS_OK) {
        return err;
    }
    if ((err = ants_cbor_enc_text(&enc, "peers", 5)) != ANTS_OK) {
        return err;
    }
    if ((err = encode_peers_array(&enc, msg->peers, msg->peer_count)) != ANTS_OK) {
        return err;
    }
    if ((err = ants_cbor_enc_text(&enc, "token", 5)) != ANTS_OK) {
        return err;
    }
    if ((err = ants_cbor_enc_bytes(&enc, msg->token, ANTS_DHT_TOKEN_SIZE)) != ANTS_OK) {
        return err;
    }
    if ((err = ants_cbor_enc_finalise(&enc)) != ANTS_OK) {
        return err;
    }
    *out_len = enc.pos;
    return ANTS_OK;
}

ants_error_t
ants_dht_wire_decode_get_peers_resp(const uint8_t *buf, size_t len, ants_dht_get_peers_resp_t *out)
{
    if (buf == NULL || out == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    ants_cbor_dec_t dec;
    ants_error_t err = ants_cbor_dec_init(&dec, buf, len);
    if (err != ANTS_OK) {
        return err;
    }
    int has_body;
    if ((err = decode_envelope_head(&dec, ANTS_DHT_MSG_GET_PEERS_RESP, &out->txid, &has_body)) !=
        ANTS_OK) {
        return err;
    }
    if (!has_body) {
        return ANTS_ERROR_NON_CANONICAL;
    }
    size_t body_n;
    if ((err = ants_cbor_dec_map(&dec, &body_n)) != ANTS_OK) {
        return err;
    }
    if (body_n != 2) {
        return ANTS_ERROR_NON_CANONICAL;
    }
    if ((err = expect_text_key(&dec, "peers", 5)) != ANTS_OK) {
        return err;
    }
    if ((err = decode_peers_array(
             &dec, out->peers, ANTS_DHT_MAX_PEERS_PER_MSG, &out->peer_count)) != ANTS_OK) {
        return err;
    }
    if ((err = expect_text_key(&dec, "token", 5)) != ANTS_OK) {
        return err;
    }
    const uint8_t *token_bytes;
    size_t token_len;
    if ((err = ants_cbor_dec_bytes(&dec, &token_bytes, &token_len)) != ANTS_OK) {
        return err;
    }
    if (token_len != ANTS_DHT_TOKEN_SIZE) {
        return ANTS_ERROR_NON_CANONICAL;
    }
    memcpy(out->token, token_bytes, ANTS_DHT_TOKEN_SIZE);
    return ants_cbor_dec_finalise(&dec);
}

/* ------------------------------------------------------------------------ */
/* ANNOUNCE_PEER / ANNOUNCE_PEER_RESP                                       */
/* ------------------------------------------------------------------------ */

ants_error_t ants_dht_wire_encode_announce_peer_req(uint8_t *buf,
                                                    size_t cap,
                                                    size_t *out_len,
                                                    const ants_dht_announce_peer_req_t *msg)
{
    if (buf == NULL || out_len == NULL || msg == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    ants_cbor_enc_t enc;
    ants_error_t err = ants_cbor_enc_init(&enc, buf, cap);
    if (err != ANTS_OK) {
        return err;
    }
    if ((err = encode_envelope_head(&enc, ANTS_DHT_MSG_ANNOUNCE_PEER, msg->txid, 1)) != ANTS_OK) {
        return err;
    }
    /* body: { "key": uint64, "token": bytes(16) } */
    if ((err = ants_cbor_enc_map(&enc, 2)) != ANTS_OK) {
        return err;
    }
    if ((err = ants_cbor_enc_text(&enc, "key", 3)) != ANTS_OK) {
        return err;
    }
    if ((err = ants_cbor_enc_uint(&enc, msg->key)) != ANTS_OK) {
        return err;
    }
    if ((err = ants_cbor_enc_text(&enc, "token", 5)) != ANTS_OK) {
        return err;
    }
    if ((err = ants_cbor_enc_bytes(&enc, msg->token, ANTS_DHT_TOKEN_SIZE)) != ANTS_OK) {
        return err;
    }
    if ((err = ants_cbor_enc_finalise(&enc)) != ANTS_OK) {
        return err;
    }
    *out_len = enc.pos;
    return ANTS_OK;
}

ants_error_t ants_dht_wire_decode_announce_peer_req(const uint8_t *buf,
                                                    size_t len,
                                                    ants_dht_announce_peer_req_t *out)
{
    if (buf == NULL || out == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    ants_cbor_dec_t dec;
    ants_error_t err = ants_cbor_dec_init(&dec, buf, len);
    if (err != ANTS_OK) {
        return err;
    }
    int has_body;
    if ((err = decode_envelope_head(&dec, ANTS_DHT_MSG_ANNOUNCE_PEER, &out->txid, &has_body)) !=
        ANTS_OK) {
        return err;
    }
    if (!has_body) {
        return ANTS_ERROR_NON_CANONICAL;
    }
    size_t body_n;
    if ((err = ants_cbor_dec_map(&dec, &body_n)) != ANTS_OK) {
        return err;
    }
    if (body_n != 2) {
        return ANTS_ERROR_NON_CANONICAL;
    }
    if ((err = expect_text_key(&dec, "key", 3)) != ANTS_OK) {
        return err;
    }
    if ((err = ants_cbor_dec_uint(&dec, &out->key)) != ANTS_OK) {
        return err;
    }
    if ((err = expect_text_key(&dec, "token", 5)) != ANTS_OK) {
        return err;
    }
    const uint8_t *token_bytes;
    size_t token_len;
    if ((err = ants_cbor_dec_bytes(&dec, &token_bytes, &token_len)) != ANTS_OK) {
        return err;
    }
    if (token_len != ANTS_DHT_TOKEN_SIZE) {
        return ANTS_ERROR_NON_CANONICAL;
    }
    memcpy(out->token, token_bytes, ANTS_DHT_TOKEN_SIZE);
    return ants_cbor_dec_finalise(&dec);
}

ants_error_t ants_dht_wire_encode_announce_peer_resp(uint8_t *buf,
                                                     size_t cap,
                                                     size_t *out_len,
                                                     const ants_dht_announce_peer_resp_t *msg)
{
    if (buf == NULL || out_len == NULL || msg == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    ants_cbor_enc_t enc;
    ants_error_t err = ants_cbor_enc_init(&enc, buf, cap);
    if (err != ANTS_OK) {
        return err;
    }
    if ((err = encode_envelope_head(&enc, ANTS_DHT_MSG_ANNOUNCE_PEER_RESP, msg->txid, 0)) !=
        ANTS_OK) {
        return err;
    }
    if ((err = ants_cbor_enc_finalise(&enc)) != ANTS_OK) {
        return err;
    }
    *out_len = enc.pos;
    return ANTS_OK;
}

ants_error_t ants_dht_wire_decode_announce_peer_resp(const uint8_t *buf,
                                                     size_t len,
                                                     ants_dht_announce_peer_resp_t *out)
{
    if (buf == NULL || out == NULL) {
        return ANTS_ERROR_INVALID_ARG;
    }
    ants_cbor_dec_t dec;
    ants_error_t err = ants_cbor_dec_init(&dec, buf, len);
    if (err != ANTS_OK) {
        return err;
    }
    int has_body;
    if ((err = decode_envelope_head(
             &dec, ANTS_DHT_MSG_ANNOUNCE_PEER_RESP, &out->txid, &has_body)) != ANTS_OK) {
        return err;
    }
    if (has_body) {
        return ANTS_ERROR_NON_CANONICAL;
    }
    return ants_cbor_dec_finalise(&dec);
}
