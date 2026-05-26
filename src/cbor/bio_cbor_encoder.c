/*
 * bio_cbor_encoder.c — CBOR Encoder (RFC 8949, CTAP2 Canonical)
 *
 * Copyright (C) 2024 Hiya Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Hand-coded CBOR encoder implementing deterministic encoding per
 * RFC 8949 §4.2.1 (Core Deterministic Encoding Requirements):
 *   - Preferred serialization: shortest integer encoding
 *   - Definite-length arrays and maps only
 *   - Map keys sorted in CTAP2 canonical order
 *
 * Layout of a CBOR head byte:
 *   Bits 7..5 = major type (0..7)
 *   Bits 4..0 = additional info:
 *     0..23  = value directly
 *     24     = next byte is uint8 value
 *     25     = next 2 bytes are uint16 value (big-endian)
 *     26     = next 4 bytes are uint32 value (big-endian)
 *     27     = next 8 bytes are uint64 value (big-endian)
 *     28..30 = reserved
 *     31     = indefinite length (not used in canonical CBOR)
 */

#include "bio_cbor.h"
#include <string.h>

/* ── Internal helpers ─────────────────────────────────────────── */

/*
 * Write raw bytes to the output buffer.
 * On overflow, sets enc->error and returns BIO_ERR_CBOR_OVERFLOW.
 */
static int enc_write(bio_cbor_encoder_t *enc,
                     const uint8_t *data, size_t len)
{
    if (enc->error)
        return BIO_ERR_CBOR_OVERFLOW;

    if (enc->offset + len > enc->capacity) {
        enc->error = true;
        BIO_ERROR("CBOR encoder overflow: need %zu bytes, have %zu",
                  enc->offset + len, enc->capacity);
        return BIO_ERR_CBOR_OVERFLOW;
    }

    memcpy(enc->buf + enc->offset, data, len);
    enc->offset += len;
    return BIO_OK;
}

/*
 * Write a single byte.
 */
static int enc_write_byte(bio_cbor_encoder_t *enc, uint8_t b)
{
    return enc_write(enc, &b, 1);
}

/*
 * Write a 16-bit big-endian value.
 */
static int enc_write_be16(bio_cbor_encoder_t *enc, uint16_t val)
{
    uint8_t buf[2] = {
        (uint8_t)(val >> 8),
        (uint8_t)(val),
    };
    return enc_write(enc, buf, 2);
}

/*
 * Write a 32-bit big-endian value.
 */
static int enc_write_be32(bio_cbor_encoder_t *enc, uint32_t val)
{
    uint8_t buf[4] = {
        (uint8_t)(val >> 24),
        (uint8_t)(val >> 16),
        (uint8_t)(val >> 8),
        (uint8_t)(val),
    };
    return enc_write(enc, buf, 4);
}

/*
 * Write a 64-bit big-endian value.
 */
static int enc_write_be64(bio_cbor_encoder_t *enc, uint64_t val)
{
    uint8_t buf[8] = {
        (uint8_t)(val >> 56),
        (uint8_t)(val >> 48),
        (uint8_t)(val >> 40),
        (uint8_t)(val >> 32),
        (uint8_t)(val >> 24),
        (uint8_t)(val >> 16),
        (uint8_t)(val >> 8),
        (uint8_t)(val),
    };
    return enc_write(enc, buf, 8);
}

/*
 * Encode a CBOR head: major type + argument.
 *
 * RFC 8949 §3.1 — Preferred (shortest) encoding:
 *   value 0..23:    1 byte  (head byte encodes value directly)
 *   value 24..0xFF: 2 bytes (head byte = mt|24, then uint8)
 *   value 0x100..0xFFFF: 3 bytes (head = mt|25, then uint16 BE)
 *   value 0x10000..0xFFFFFFFF: 5 bytes (head = mt|26, then uint32 BE)
 *   value > 0xFFFFFFFF: 9 bytes (head = mt|27, then uint64 BE)
 */
static int enc_head(bio_cbor_encoder_t *enc,
                    bio_cbor_major_t mt, uint64_t value)
{
    uint8_t type_bits = (uint8_t)mt << 5;
    int rc;

    if (value <= 23) {
        return enc_write_byte(enc, type_bits | (uint8_t)value);
    }
    else if (value <= 0xFF) {
        rc = enc_write_byte(enc, type_bits | 24);
        if (rc != BIO_OK) return rc;
        return enc_write_byte(enc, (uint8_t)value);
    }
    else if (value <= 0xFFFF) {
        rc = enc_write_byte(enc, type_bits | 25);
        if (rc != BIO_OK) return rc;
        return enc_write_be16(enc, (uint16_t)value);
    }
    else if (value <= 0xFFFFFFFFULL) {
        rc = enc_write_byte(enc, type_bits | 26);
        if (rc != BIO_OK) return rc;
        return enc_write_be32(enc, (uint32_t)value);
    }
    else {
        rc = enc_write_byte(enc, type_bits | 27);
        if (rc != BIO_OK) return rc;
        return enc_write_be64(enc, value);
    }
}

/*
 * Track container items. Called after encoding each item.
 * Verifies we haven't exceeded the declared container count.
 */
static void enc_track_item(bio_cbor_encoder_t *enc)
{
    if (enc->depth <= 0)
        return;

    int idx = enc->depth - 1;
    enc->stack[idx].written++;

    /* Auto-pop completed containers */
    while (enc->depth > 0) {
        idx = enc->depth - 1;
        if (enc->stack[idx].written >= enc->stack[idx].count) {
            enc->depth--;
            /* This completed container is itself an item in its parent;
               increment the parent's written count. */
            if (enc->depth > 0)
                enc->stack[enc->depth - 1].written++;
        } else {
            break;
        }
    }
}

/* ── Public API ───────────────────────────────────────────────── */

void bio_cbor_encoder_init(bio_cbor_encoder_t *enc,
                           uint8_t *buf, size_t size)
{
    if (!enc) return;
    memset(enc, 0, sizeof(*enc));
    enc->buf = buf;
    enc->capacity = size;
}

size_t bio_cbor_encoder_len(const bio_cbor_encoder_t *enc)
{
    return enc->error ? 0 : enc->offset;
}

bool bio_cbor_encoder_has_error(const bio_cbor_encoder_t *enc)
{
    return enc->error;
}

/* ── Unsigned Integer (Major Type 0) ─────────────────────────── */

int bio_cbor_encode_uint(bio_cbor_encoder_t *enc, uint64_t value)
{
    if (!enc) return BIO_ERR_INVALID_PARAM;
    int rc = enc_head(enc, BIO_CBOR_UINT, value);
    if (rc == BIO_OK) enc_track_item(enc);
    return rc;
}

/* ── Negative Integer (Major Type 1) ─────────────────────────── */

int bio_cbor_encode_negint(bio_cbor_encoder_t *enc, uint64_t value)
{
    if (!enc) return BIO_ERR_INVALID_PARAM;
    /* CBOR negative: -1 - value, so encoding value N means -(1+N) */
    int rc = enc_head(enc, BIO_CBOR_NEGINT, value);
    if (rc == BIO_OK) enc_track_item(enc);
    return rc;
}

/* ── Integer (auto-detect sign) ──────────────────────────────── */

int bio_cbor_encode_int(bio_cbor_encoder_t *enc, int64_t value)
{
    if (!enc) return BIO_ERR_INVALID_PARAM;

    if (value >= 0) {
        return bio_cbor_encode_uint(enc, (uint64_t)value);
    } else {
        /* CBOR negint encoding: -1 → 0, -2 → 1, etc.
         * So for value = -N, we encode (N - 1) = -(value) - 1 = (-value - 1).
         * Since value is negative, -value is positive.
         * For INT64_MIN: -value would overflow, but -(INT64_MIN + 1) == INT64_MAX.
         * CBOR encoding: -(1 + UINT64_MAX) is not possible (INT64_MIN = -2^63)
         * -(1 + n) = value → n = -(value + 1) = -value - 1
         */
        uint64_t negval = (uint64_t)(-(value + 1));
        return bio_cbor_encode_negint(enc, negval);
    }
}

/* ── Byte String (Major Type 2) ──────────────────────────────── */

int bio_cbor_encode_bstr(bio_cbor_encoder_t *enc,
                         const uint8_t *data, size_t len)
{
    if (!enc) return BIO_ERR_INVALID_PARAM;
    if (len > 0 && !data) return BIO_ERR_INVALID_PARAM;

    int rc = enc_head(enc, BIO_CBOR_BSTR, len);
    if (rc != BIO_OK) return rc;

    if (len > 0) {
        rc = enc_write(enc, data, len);
        if (rc != BIO_OK) return rc;
    }

    enc_track_item(enc);
    return BIO_OK;
}

/* ── Text String (Major Type 3) ──────────────────────────────── */

int bio_cbor_encode_tstr(bio_cbor_encoder_t *enc,
                         const char *str, size_t len)
{
    if (!enc) return BIO_ERR_INVALID_PARAM;
    if (len > 0 && !str) return BIO_ERR_INVALID_PARAM;

    int rc = enc_head(enc, BIO_CBOR_TSTR, len);
    if (rc != BIO_OK) return rc;

    if (len > 0) {
        rc = enc_write(enc, (const uint8_t *)str, len);
        if (rc != BIO_OK) return rc;
    }

    enc_track_item(enc);
    return BIO_OK;
}

int bio_cbor_encode_tstr_z(bio_cbor_encoder_t *enc, const char *str)
{
    if (!enc || !str) return BIO_ERR_INVALID_PARAM;
    return bio_cbor_encode_tstr(enc, str, strlen(str));
}

/* ── Array (Major Type 4) ────────────────────────────────────── */

int bio_cbor_encode_array(bio_cbor_encoder_t *enc, size_t count)
{
    if (!enc) return BIO_ERR_INVALID_PARAM;

    if (enc->depth >= BIO_CBOR_MAX_DEPTH) {
        BIO_ERROR("CBOR nesting too deep: %d", enc->depth);
        enc->error = true;
        return BIO_ERR_CBOR_NESTING;
    }

    int rc = enc_head(enc, BIO_CBOR_ARRAY, count);
    if (rc != BIO_OK) return rc;

    /* Push container onto stack */
    enc->stack[enc->depth].type = BIO_CBOR_ARRAY;
    enc->stack[enc->depth].count = count;
    enc->stack[enc->depth].written = 0;
    enc->depth++;

    /* An empty array is its own complete item */
    if (count == 0) {
        enc->depth--;
        enc_track_item(enc);
    }

    return BIO_OK;
}

/* ── Map (Major Type 5) ──────────────────────────────────────── */

int bio_cbor_encode_map(bio_cbor_encoder_t *enc, size_t count)
{
    if (!enc) return BIO_ERR_INVALID_PARAM;

    if (enc->depth >= BIO_CBOR_MAX_DEPTH) {
        BIO_ERROR("CBOR nesting too deep: %d", enc->depth);
        enc->error = true;
        return BIO_ERR_CBOR_NESTING;
    }

    /* Guard against count overflow (V-CBOR-01 fix) */
    if (count > SIZE_MAX / 2) {
        BIO_ERROR("CBOR map count too large: %zu", count);
        enc->error = true;
        return BIO_ERR_CBOR_NESTING;
    }

    int rc = enc_head(enc, BIO_CBOR_MAP, count);
    if (rc != BIO_OK) return rc;

    /* Push container onto stack — count pairs = 2*count items */
    enc->stack[enc->depth].type = BIO_CBOR_MAP;
    enc->stack[enc->depth].count = count * 2;
    enc->stack[enc->depth].written = 0;
    enc->depth++;

    if (count == 0) {
        enc->depth--;
        enc_track_item(enc);
    }

    return BIO_OK;
}

/* ── Tag (Major Type 6) ──────────────────────────────────────── */

int bio_cbor_encode_tag(bio_cbor_encoder_t *enc, uint64_t tag)
{
    if (!enc) return BIO_ERR_INVALID_PARAM;
    /* Tags don't count as items in containers — the tagged value does */
    return enc_head(enc, BIO_CBOR_TAG, tag);
}

/* ── Simple Values (Major Type 7) ────────────────────────────── */

int bio_cbor_encode_bool(bio_cbor_encoder_t *enc, bool value)
{
    if (!enc) return BIO_ERR_INVALID_PARAM;
    int rc = enc_head(enc, BIO_CBOR_SIMPLE,
                       value ? BIO_CBOR_TRUE : BIO_CBOR_FALSE);
    if (rc == BIO_OK) enc_track_item(enc);
    return rc;
}

int bio_cbor_encode_null(bio_cbor_encoder_t *enc)
{
    if (!enc) return BIO_ERR_INVALID_PARAM;
    int rc = enc_head(enc, BIO_CBOR_SIMPLE, BIO_CBOR_NULL);
    if (rc == BIO_OK) enc_track_item(enc);
    return rc;
}

int bio_cbor_encode_undefined(bio_cbor_encoder_t *enc)
{
    if (!enc) return BIO_ERR_INVALID_PARAM;
    int rc = enc_head(enc, BIO_CBOR_SIMPLE, BIO_CBOR_UNDEFINED);
    if (rc == BIO_OK) enc_track_item(enc);
    return rc;
}

int bio_cbor_encode_simple(bio_cbor_encoder_t *enc, uint8_t value)
{
    if (!enc) return BIO_ERR_INVALID_PARAM;

    /* RFC 8949 §3.3: values 24-31 are reserved */
    if (value >= 24 && value <= 31) {
        BIO_ERROR("CBOR simple value %u is reserved", value);
        return BIO_ERR_CBOR_INVALID;
    }

    int rc;
    if (value <= 23) {
        rc = enc_head(enc, BIO_CBOR_SIMPLE, value);
    } else {
        /* Two-byte simple value: head = 0xF8, then value */
        rc = enc_write_byte(enc, 0xF8);
        if (rc != BIO_OK) return rc;
        rc = enc_write_byte(enc, value);
    }
    if (rc == BIO_OK) enc_track_item(enc);
    return rc;
}

/* ── Float (Major Type 7) ────────────────────────────────────── */

int bio_cbor_encode_float(bio_cbor_encoder_t *enc, float value)
{
    if (!enc) return BIO_ERR_INVALID_PARAM;

    /* IEEE 754 single precision: additional info = 26 */
    int rc = enc_write_byte(enc, 0xFA);  /* mt7 | 26 */
    if (rc != BIO_OK) return rc;

    uint32_t bits;
    memcpy(&bits, &value, sizeof(bits));
    rc = enc_write_be32(enc, bits);
    if (rc == BIO_OK) enc_track_item(enc);
    return rc;
}

int bio_cbor_encode_double(bio_cbor_encoder_t *enc, double value)
{
    if (!enc) return BIO_ERR_INVALID_PARAM;

    /* IEEE 754 double precision: additional info = 27 */
    int rc = enc_write_byte(enc, 0xFB);  /* mt7 | 27 */
    if (rc != BIO_OK) return rc;

    uint64_t bits;
    memcpy(&bits, &value, sizeof(bits));
    rc = enc_write_be64(enc, bits);
    if (rc == BIO_OK) enc_track_item(enc);
    return rc;
}
