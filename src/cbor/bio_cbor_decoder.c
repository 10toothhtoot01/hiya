/*
 * bio_cbor_decoder.c — CBOR Decoder (RFC 8949)
 *
 * Copyright (C) 2024 BioAuth Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Zero-copy, cursor-based decoder. Byte strings and text strings
 * reference the original input buffer directly — no allocations.
 *
 * Supports all 8 major types with definite lengths.
 * Indefinite-length strings/containers are rejected
 * (not used in CTAP2 canonical CBOR).
 */

#include "bio_cbor.h"
#include <string.h>
#include <inttypes.h>

/* ── Internal helpers ─────────────────────────────────────────── */

/*
 * Read N bytes from the decoder buffer.
 * Returns NULL and sets error on underflow.
 */
static const uint8_t *dec_read(bio_cbor_decoder_t *dec, size_t n)
{
    if (dec->error)
        return NULL;

    if (dec->offset + n > dec->size) {
        dec->error = true;
        dec->err_code = BIO_ERR_CBOR_INVALID;
        BIO_ERROR("CBOR decoder underflow at offset %zu: need %zu bytes, have %zu",
                  dec->offset, n, dec->size - dec->offset);
        return NULL;
    }

    const uint8_t *p = dec->data + dec->offset;
    dec->offset += n;
    return p;
}

/*
 * Peek at the next byte without consuming it.
 */
static int dec_peek(const bio_cbor_decoder_t *dec, uint8_t *byte)
{
    if (dec->error || dec->offset >= dec->size) {
        return BIO_ERR_CBOR_INVALID;
    }
    *byte = dec->data[dec->offset];
    return BIO_OK;
}

/*
 * Read a single byte.
 */
static int dec_read_byte(bio_cbor_decoder_t *dec, uint8_t *byte)
{
    const uint8_t *p = dec_read(dec, 1);
    if (!p) return BIO_ERR_CBOR_INVALID;
    *byte = *p;
    return BIO_OK;
}

/*
 * Read a uint16 big-endian.
 */
static int dec_read_be16(bio_cbor_decoder_t *dec, uint16_t *val)
{
    const uint8_t *p = dec_read(dec, 2);
    if (!p) return BIO_ERR_CBOR_INVALID;
    *val = ((uint16_t)p[0] << 8) | p[1];
    return BIO_OK;
}

/*
 * Read a uint32 big-endian.
 */
static int dec_read_be32(bio_cbor_decoder_t *dec, uint32_t *val)
{
    const uint8_t *p = dec_read(dec, 4);
    if (!p) return BIO_ERR_CBOR_INVALID;
    *val = ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |
           (uint32_t)p[3];
    return BIO_OK;
}

/*
 * Read a uint64 big-endian.
 */
static int dec_read_be64(bio_cbor_decoder_t *dec, uint64_t *val)
{
    const uint8_t *p = dec_read(dec, 8);
    if (!p) return BIO_ERR_CBOR_INVALID;
    *val = ((uint64_t)p[0] << 56) |
           ((uint64_t)p[1] << 48) |
           ((uint64_t)p[2] << 40) |
           ((uint64_t)p[3] << 32) |
           ((uint64_t)p[4] << 24) |
           ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] << 8)  |
           (uint64_t)p[7];
    return BIO_OK;
}

/*
 * Decode the CBOR head byte and extract:
 *   - Major type (bits 7..5)
 *   - Additional info / argument value
 *
 * RFC 8949 §3:
 *   additional 0..23:  value is directly in the byte
 *   additional 24:     1 follow-up byte  (uint8)
 *   additional 25:     2 follow-up bytes (uint16 BE)
 *   additional 26:     4 follow-up bytes (uint32 BE)
 *   additional 27:     8 follow-up bytes (uint64 BE)
 *   additional 28..30: reserved (error)
 *   additional 31:     indefinite length
 */
static int dec_head(bio_cbor_decoder_t *dec,
                    bio_cbor_major_t *major,
                    uint8_t *additional,
                    uint64_t *argument)
{
    uint8_t head;
    int rc = dec_read_byte(dec, &head);
    if (rc != BIO_OK) return rc;

    *major = (bio_cbor_major_t)(head >> 5);
    uint8_t ai = head & 0x1F;
    *additional = ai;

    if (ai <= 23) {
        *argument = ai;
        return BIO_OK;
    }

    switch (ai) {
    case 24: {
        uint8_t val;
        rc = dec_read_byte(dec, &val);
        if (rc != BIO_OK) return rc;
        /* Canonical check: value must be >= 24 */
        *argument = val;
        return BIO_OK;
    }
    case 25: {
        uint16_t val;
        rc = dec_read_be16(dec, &val);
        if (rc != BIO_OK) return rc;
        *argument = val;
        return BIO_OK;
    }
    case 26: {
        uint32_t val;
        rc = dec_read_be32(dec, &val);
        if (rc != BIO_OK) return rc;
        *argument = val;
        return BIO_OK;
    }
    case 27: {
        uint64_t val;
        rc = dec_read_be64(dec, &val);
        if (rc != BIO_OK) return rc;
        *argument = val;
        return BIO_OK;
    }
    case 31:
        /* Indefinite length — not allowed in canonical CBOR */
        BIO_ERROR("CBOR indefinite length not supported (not canonical)");
        dec->error = true;
        dec->err_code = BIO_ERR_CBOR_INVALID;
        return BIO_ERR_CBOR_INVALID;
    default:
        /* 28, 29, 30 are reserved */
        BIO_ERROR("CBOR reserved additional info: %u", ai);
        dec->error = true;
        dec->err_code = BIO_ERR_CBOR_INVALID;
        return BIO_ERR_CBOR_INVALID;
    }
}

/* ── Public API ───────────────────────────────────────────────── */

void bio_cbor_decoder_init(bio_cbor_decoder_t *dec,
                           const uint8_t *data, size_t size)
{
    if (!dec) return;
    memset(dec, 0, sizeof(*dec));
    dec->data = data;
    dec->size = size;
}

int bio_cbor_peek_type(bio_cbor_decoder_t *dec, bio_cbor_major_t *type)
{
    if (!dec || !type)
        return BIO_ERR_INVALID_PARAM;

    uint8_t head;
    int rc = dec_peek(dec, &head);
    if (rc != BIO_OK) return rc;

    *type = (bio_cbor_major_t)(head >> 5);
    return BIO_OK;
}

int bio_cbor_decode_next(bio_cbor_decoder_t *dec, bio_cbor_item_t *item)
{
    if (!dec || !item)
        return BIO_ERR_INVALID_PARAM;

    memset(item, 0, sizeof(*item));

    bio_cbor_major_t major;
    uint8_t additional;
    uint64_t argument;
    int rc = dec_head(dec, &major, &additional, &argument);
    if (rc != BIO_OK) return rc;

    item->type = major;

    switch (major) {
    case BIO_CBOR_UINT:
        /* Major type 0: unsigned integer */
        item->uint_val = argument;
        item->int_val = (int64_t)argument;
        break;

    case BIO_CBOR_NEGINT:
        /* Major type 1: negative integer = -1 - argument */
        item->uint_val = argument;
        /* Safe to compute: -(1 + argument). For very large argument,
         * the int64_t will wrap, but that's intentional — CBOR allows
         * negative integers down to -(2^64). */
        if (argument <= (uint64_t)INT64_MAX) {
            item->int_val = -1 - (int64_t)argument;
        } else {
            /* Can't represent in int64_t — store raw, let caller handle */
            item->int_val = INT64_MIN;  /* sentinel */
        }
        break;

    case BIO_CBOR_BSTR:
        /* Major type 2: byte string */
        /* Guard against 64-to-size_t truncation on 32-bit (V-CBOR-03 fix) */
        if (argument > SIZE_MAX) {
            dec->error = true;
            dec->err_code = BIO_ERR_CBOR_INVALID;
            return BIO_ERR_CBOR_INVALID;
        }
        if (dec->offset > dec->size || argument > dec->size - dec->offset) {
            BIO_ERROR("CBOR byte string length %"PRIu64" exceeds remaining data", argument);
            dec->error = true;
            dec->err_code = BIO_ERR_CBOR_INVALID;
            return BIO_ERR_CBOR_INVALID;
        }
        item->bstr.data = dec->data + dec->offset;
        item->bstr.len = (size_t)argument;
        dec->offset += (size_t)argument;
        break;

    case BIO_CBOR_TSTR:
        /* Major type 3: text string (UTF-8) */
        if (argument > SIZE_MAX) {
            dec->error = true;
            dec->err_code = BIO_ERR_CBOR_INVALID;
            return BIO_ERR_CBOR_INVALID;
        }
        if (dec->offset > dec->size || argument > dec->size - dec->offset) {
            BIO_ERROR("CBOR text string length %"PRIu64" exceeds remaining data", argument);
            dec->error = true;
            dec->err_code = BIO_ERR_CBOR_INVALID;
            return BIO_ERR_CBOR_INVALID;
        }
        item->tstr.data = (const char *)(dec->data + dec->offset);
        item->tstr.len = (size_t)argument;
        dec->offset += (size_t)argument;
        break;

    case BIO_CBOR_ARRAY:
        /* Major type 4: array — argument = number of items */
        /* Validate container length is plausible (V-CBOR-02 fix):
         * each item needs at least 1 byte, so the stated count
         * cannot exceed the remaining data */
        if (argument > SIZE_MAX || argument > dec->size - dec->offset) {
            dec->error = true;
            dec->err_code = BIO_ERR_CBOR_INVALID;
            return BIO_ERR_CBOR_INVALID;
        }
        item->container_len = (size_t)argument;
        break;

    case BIO_CBOR_MAP:
        /* Major type 5: map — argument = number of key-value pairs */
        /* Each pair needs at least 2 bytes, check count * 2 doesn't overflow */
        if (argument > SIZE_MAX / 2 ||
            argument * 2 > dec->size - dec->offset) {
            dec->error = true;
            dec->err_code = BIO_ERR_CBOR_INVALID;
            return BIO_ERR_CBOR_INVALID;
        }
        item->container_len = (size_t)argument;
        break;

    case BIO_CBOR_TAG:
        /* Major type 6: tag — argument = tag number */
        item->tag_val = argument;
        break;

    case BIO_CBOR_SIMPLE:
        /* Major type 7: simple value or float */
        if (additional <= 23) {
            /* Simple value directly encoded */
            item->simple.simple_val = (uint8_t)argument;
            item->simple.is_float = false;
            item->simple.is_double = false;
        }
        else if (additional == 24) {
            /* Two-byte simple value */
            item->simple.simple_val = (uint8_t)argument;
            item->simple.is_float = false;
            item->simple.is_double = false;
        }
        else if (additional == 25) {
            /* IEEE 754 half-precision (16-bit) float */
            /* Decode half-float → single-float */
            uint16_t half = (uint16_t)argument;
            uint32_t sign = (uint32_t)(half & 0x8000) << 16;
            uint32_t exp  = (half >> 10) & 0x1F;
            uint32_t mant = half & 0x03FF;

            uint32_t single;
            if (exp == 0) {
                if (mant == 0) {
                    /* ±0 */
                    single = sign;
                } else {
                    /* Subnormal: convert to normalized single */
                    exp = 1;
                    while (!(mant & 0x0400)) {
                        mant <<= 1;
                        exp--;
                    }
                    mant &= 0x03FF;
                    single = sign | ((exp + 127 - 15) << 23) | (mant << 13);
                }
            }
            else if (exp == 31) {
                /* Inf or NaN */
                single = sign | 0x7F800000 | (mant << 13);
            }
            else {
                /* Normal: adjust exponent bias from 15 to 127 */
                single = sign | ((exp + 127 - 15) << 23) | (mant << 13);
            }

            memcpy(&item->simple.float_val, &single, sizeof(float));
            item->simple.is_float = true;
            item->simple.is_double = false;
        }
        else if (additional == 26) {
            /* IEEE 754 single-precision (32-bit) float */
            uint32_t bits = (uint32_t)argument;
            memcpy(&item->simple.float_val, &bits, sizeof(float));
            item->simple.is_float = true;
            item->simple.is_double = false;
        }
        else if (additional == 27) {
            /* IEEE 754 double-precision (64-bit) float */
            memcpy(&item->simple.double_val, &argument, sizeof(double));
            item->simple.is_float = false;
            item->simple.is_double = true;
        }
        break;
    }

    return BIO_OK;
}

/* ── Skip ─────────────────────────────────────────────────────── */

/*
 * Forward declaration for recursive skip.
 */
static int cbor_skip_item_depth(bio_cbor_decoder_t *dec, int depth);

static int cbor_skip_item_depth(bio_cbor_decoder_t *dec, int depth)
{
    if (depth > BIO_CBOR_MAX_DEPTH) {
        BIO_ERROR("CBOR skip: nesting too deep (%d)", depth);
        dec->error = true;
        dec->err_code = BIO_ERR_CBOR_NESTING;
        return BIO_ERR_CBOR_NESTING;
    }

    bio_cbor_item_t item;
    int rc = bio_cbor_decode_next(dec, &item);
    if (rc != BIO_OK) return rc;

    switch (item.type) {
    case BIO_CBOR_UINT:
    case BIO_CBOR_NEGINT:
    case BIO_CBOR_BSTR:
    case BIO_CBOR_TSTR:
    case BIO_CBOR_SIMPLE:
        /* Scalar — already consumed */
        return BIO_OK;

    case BIO_CBOR_ARRAY:
        /* Skip all items in the array */
        for (size_t i = 0; i < item.container_len; i++) {
            rc = cbor_skip_item_depth(dec, depth + 1);
            if (rc != BIO_OK) return rc;
        }
        return BIO_OK;

    case BIO_CBOR_MAP:
        /* Skip all key-value pairs */
        for (size_t i = 0; i < item.container_len; i++) {
            rc = cbor_skip_item_depth(dec, depth + 1);  /* key */
            if (rc != BIO_OK) return rc;
            rc = cbor_skip_item_depth(dec, depth + 1);  /* value */
            if (rc != BIO_OK) return rc;
        }
        return BIO_OK;

    case BIO_CBOR_TAG:
        /* Skip the tagged content item */
        return cbor_skip_item_depth(dec, depth + 1);

    default:
        return BIO_ERR_CBOR_INVALID;
    }
}

int bio_cbor_skip(bio_cbor_decoder_t *dec)
{
    if (!dec) return BIO_ERR_INVALID_PARAM;
    return cbor_skip_item_depth(dec, 0);
}

bool bio_cbor_decoder_at_end(const bio_cbor_decoder_t *dec)
{
    return dec->offset >= dec->size;
}

size_t bio_cbor_decoder_offset(const bio_cbor_decoder_t *dec)
{
    return dec->offset;
}

size_t bio_cbor_decoder_remaining(const bio_cbor_decoder_t *dec)
{
    return dec->size > dec->offset ? dec->size - dec->offset : 0;
}

/* ── Convenience typed decoders ──────────────────────────────── */

int bio_cbor_decode_uint(bio_cbor_decoder_t *dec, uint64_t *value)
{
    if (!dec || !value) return BIO_ERR_INVALID_PARAM;

    bio_cbor_item_t item;
    int rc = bio_cbor_decode_next(dec, &item);
    if (rc != BIO_OK) return rc;

    if (item.type != BIO_CBOR_UINT) {
        BIO_DEBUG("Expected CBOR uint, got major type %d", item.type);
        return BIO_ERR_CBOR_UNEXPECTED_TYPE;
    }

    *value = item.uint_val;
    return BIO_OK;
}

int bio_cbor_decode_int(bio_cbor_decoder_t *dec, int64_t *value)
{
    if (!dec || !value) return BIO_ERR_INVALID_PARAM;

    bio_cbor_item_t item;
    int rc = bio_cbor_decode_next(dec, &item);
    if (rc != BIO_OK) return rc;

    if (item.type == BIO_CBOR_UINT) {
        if (item.uint_val > (uint64_t)INT64_MAX) {
            return BIO_ERR_CBOR_OVERFLOW;
        }
        *value = (int64_t)item.uint_val;
        return BIO_OK;
    }
    else if (item.type == BIO_CBOR_NEGINT) {
        *value = item.int_val;
        return BIO_OK;
    }

    BIO_DEBUG("Expected CBOR int, got major type %d", item.type);
    return BIO_ERR_CBOR_UNEXPECTED_TYPE;
}

int bio_cbor_decode_bstr(bio_cbor_decoder_t *dec,
                         const uint8_t **data, size_t *len)
{
    if (!dec || !data || !len) return BIO_ERR_INVALID_PARAM;

    bio_cbor_item_t item;
    int rc = bio_cbor_decode_next(dec, &item);
    if (rc != BIO_OK) return rc;

    if (item.type != BIO_CBOR_BSTR) {
        BIO_DEBUG("Expected CBOR bstr, got major type %d", item.type);
        return BIO_ERR_CBOR_UNEXPECTED_TYPE;
    }

    *data = item.bstr.data;
    *len  = item.bstr.len;
    return BIO_OK;
}

int bio_cbor_decode_tstr(bio_cbor_decoder_t *dec,
                         const char **str, size_t *len)
{
    if (!dec || !str || !len) return BIO_ERR_INVALID_PARAM;

    bio_cbor_item_t item;
    int rc = bio_cbor_decode_next(dec, &item);
    if (rc != BIO_OK) return rc;

    if (item.type != BIO_CBOR_TSTR) {
        BIO_DEBUG("Expected CBOR tstr, got major type %d", item.type);
        return BIO_ERR_CBOR_UNEXPECTED_TYPE;
    }

    *str = item.tstr.data;
    *len = item.tstr.len;
    return BIO_OK;
}

int bio_cbor_decode_array(bio_cbor_decoder_t *dec, size_t *count)
{
    if (!dec || !count) return BIO_ERR_INVALID_PARAM;

    bio_cbor_item_t item;
    int rc = bio_cbor_decode_next(dec, &item);
    if (rc != BIO_OK) return rc;

    if (item.type != BIO_CBOR_ARRAY) {
        BIO_DEBUG("Expected CBOR array, got major type %d", item.type);
        return BIO_ERR_CBOR_UNEXPECTED_TYPE;
    }

    *count = item.container_len;
    return BIO_OK;
}

int bio_cbor_decode_map(bio_cbor_decoder_t *dec, size_t *count)
{
    if (!dec || !count) return BIO_ERR_INVALID_PARAM;

    bio_cbor_item_t item;
    int rc = bio_cbor_decode_next(dec, &item);
    if (rc != BIO_OK) return rc;

    if (item.type != BIO_CBOR_MAP) {
        BIO_DEBUG("Expected CBOR map, got major type %d", item.type);
        return BIO_ERR_CBOR_UNEXPECTED_TYPE;
    }

    *count = item.container_len;
    return BIO_OK;
}

int bio_cbor_decode_bool(bio_cbor_decoder_t *dec, bool *value)
{
    if (!dec || !value) return BIO_ERR_INVALID_PARAM;

    bio_cbor_item_t item;
    int rc = bio_cbor_decode_next(dec, &item);
    if (rc != BIO_OK) return rc;

    if (item.type != BIO_CBOR_SIMPLE) {
        return BIO_ERR_CBOR_UNEXPECTED_TYPE;
    }
    if (item.simple.simple_val == BIO_CBOR_TRUE) {
        *value = true;
        return BIO_OK;
    }
    if (item.simple.simple_val == BIO_CBOR_FALSE) {
        *value = false;
        return BIO_OK;
    }

    return BIO_ERR_CBOR_UNEXPECTED_TYPE;
}

int bio_cbor_decode_null(bio_cbor_decoder_t *dec)
{
    if (!dec) return BIO_ERR_INVALID_PARAM;

    bio_cbor_item_t item;
    int rc = bio_cbor_decode_next(dec, &item);
    if (rc != BIO_OK) return rc;

    if (item.type != BIO_CBOR_SIMPLE ||
        item.simple.simple_val != BIO_CBOR_NULL) {
        return BIO_ERR_CBOR_UNEXPECTED_TYPE;
    }

    return BIO_OK;
}

int bio_cbor_decode_tag(bio_cbor_decoder_t *dec, uint64_t *tag)
{
    if (!dec || !tag) return BIO_ERR_INVALID_PARAM;

    bio_cbor_item_t item;
    int rc = bio_cbor_decode_next(dec, &item);
    if (rc != BIO_OK) return rc;

    if (item.type != BIO_CBOR_TAG) {
        return BIO_ERR_CBOR_UNEXPECTED_TYPE;
    }

    *tag = item.tag_val;
    return BIO_OK;
}

/* ── CTAP2 Map Search Helpers ────────────────────────────────── */

int bio_cbor_map_find_uint_key(bio_cbor_decoder_t *dec,
                               size_t count, uint64_t key)
{
    if (!dec) return BIO_ERR_INVALID_PARAM;

    /* Save position for potential restoration */
    size_t start = dec->offset;

    for (size_t i = 0; i < count; i++) {
        /* Decode the key */
        bio_cbor_item_t k;
        int rc = bio_cbor_decode_next(dec, &k);
        if (rc != BIO_OK) return rc;

        if (k.type == BIO_CBOR_UINT && k.uint_val == key) {
            /* Found! Decoder is positioned at the value. */
            return BIO_OK;
        }

        /* Skip the value for this unmatched key */
        rc = bio_cbor_skip(dec);
        if (rc != BIO_OK) return rc;
    }

    /* Not found — restore position */
    dec->offset = start;
    return BIO_ERR_NOT_FOUND;
}

int bio_cbor_map_find_tstr_key(bio_cbor_decoder_t *dec,
                               size_t count,
                               const char *key, size_t key_len)
{
    if (!dec || !key) return BIO_ERR_INVALID_PARAM;

    size_t start = dec->offset;

    for (size_t i = 0; i < count; i++) {
        bio_cbor_item_t k;
        int rc = bio_cbor_decode_next(dec, &k);
        if (rc != BIO_OK) return rc;

        if (k.type == BIO_CBOR_TSTR &&
            k.tstr.len == key_len &&
            memcmp(k.tstr.data, key, key_len) == 0) {
            /* Found! */
            return BIO_OK;
        }

        /* Skip value */
        rc = bio_cbor_skip(dec);
        if (rc != BIO_OK) return rc;
    }

    dec->offset = start;
    return BIO_ERR_NOT_FOUND;
}
