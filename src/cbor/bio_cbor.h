/*
 * bio_cbor.h — Complete CBOR (RFC 8949) Encoder/Decoder
 *
 * Copyright (C) 2024 Hiya Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Hand-coded from scratch. Implements:
 *   - All 8 major types (0–7)
 *   - Deterministic encoding (CTAP2 canonical CBOR)
 *   - Definite-length maps & arrays
 *   - Byte strings, text strings
 *   - Tagged values (for COSE keys, etc.)
 *   - Simple values (true, false, null, undefined)
 *   - Half/single/double precision floats
 *   - Nested containers up to 16 levels deep
 *   - Zero-copy decoder with cursor-based parsing
 */

#ifndef BIO_CBOR_H
#define BIO_CBOR_H

#include "bio_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── CBOR Major Types (RFC 8949 §3.1) ────────────────────────── */
typedef enum {
    BIO_CBOR_UINT       = 0,   /* Major type 0: unsigned integer */
    BIO_CBOR_NEGINT     = 1,   /* Major type 1: negative integer (-1 - value) */
    BIO_CBOR_BSTR       = 2,   /* Major type 2: byte string */
    BIO_CBOR_TSTR       = 3,   /* Major type 3: text string (UTF-8) */
    BIO_CBOR_ARRAY      = 4,   /* Major type 4: array */
    BIO_CBOR_MAP        = 5,   /* Major type 5: map (key-value pairs) */
    BIO_CBOR_TAG        = 6,   /* Major type 6: tagged value */
    BIO_CBOR_SIMPLE     = 7,   /* Major type 7: simple/float */
} bio_cbor_major_t;

/* ── CBOR Simple Values ──────────────────────────────────────── */
#define BIO_CBOR_FALSE      20
#define BIO_CBOR_TRUE       21
#define BIO_CBOR_NULL       22
#define BIO_CBOR_UNDEFINED  23

/* ── Common CBOR Tags ────────────────────────────────────────── */
#define BIO_CBOR_TAG_DATETIME_STRING   0   /* RFC 3339 date/time */
#define BIO_CBOR_TAG_DATETIME_EPOCH    1   /* Epoch-based date/time */
#define BIO_CBOR_TAG_UNSIGNED_BIGNUM   2   /* Unsigned bignum */
#define BIO_CBOR_TAG_NEGATIVE_BIGNUM   3   /* Negative bignum */
#define BIO_CBOR_TAG_COSE_SIGN1       18   /* COSE_Sign1 */

/* ── CTAP2 Canonical CBOR Ordering ───────────────────────────── */
/*
 * CTAP2 canonical CBOR (from FIDO2 spec):
 *   1. Integers/negative integers sorted by value
 *   2. Text strings sorted by byte length, then lexicographic
 *   3. Map keys must be sorted per above rules
 *   4. Only definite-length encoding
 *   5. Use shortest form for each integer
 */

/* ── Maximum nesting depth ───────────────────────────────────── */
#define BIO_CBOR_MAX_DEPTH  16

/* ══════════════════════════════════════════════════════════════════
 *  ENCODER
 * ══════════════════════════════════════════════════════════════════ */

/**
 * CBOR encoder context.
 * Writes CBOR data into a caller-provided buffer.
 * Tracks nesting (map/array depths) for proper encoding.
 */
typedef struct {
    uint8_t *buf;             /* Output buffer */
    size_t   capacity;        /* Total buffer capacity */
    size_t   offset;          /* Current write position */
    bool     error;           /* Set on overflow — all writes become no-ops */

    /* Container tracking for nested maps/arrays */
    struct {
        bio_cbor_major_t type;    /* ARRAY or MAP */
        size_t           count;   /* Items remaining */
        size_t           written; /* Items written so far */
    } stack[BIO_CBOR_MAX_DEPTH];
    int      depth;           /* Current nesting depth */
} bio_cbor_encoder_t;

/**
 * Initialize encoder with output buffer.
 * @param enc    Encoder context
 * @param buf    Output buffer
 * @param size   Buffer capacity in bytes
 */
void bio_cbor_encoder_init(bio_cbor_encoder_t *enc,
                           uint8_t *buf, size_t size);

/**
 * Get the number of bytes written so far.
 * Returns 0 if encoder is in error state.
 */
size_t bio_cbor_encoder_len(const bio_cbor_encoder_t *enc);

/**
 * Check if encoder encountered an error (buffer overflow).
 */
bool bio_cbor_encoder_has_error(const bio_cbor_encoder_t *enc);

/* ── Unsigned Integer (Major Type 0) ─────────────────────────── */
int bio_cbor_encode_uint(bio_cbor_encoder_t *enc, uint64_t value);

/* ── Negative Integer (Major Type 1) ─────────────────────────── */
/* Encodes the value -(1 + value), so bio_cbor_encode_negint(enc, 0) = -1 */
int bio_cbor_encode_negint(bio_cbor_encoder_t *enc, uint64_t value);

/* ── Integer (auto-detect sign) ──────────────────────────────── */
int bio_cbor_encode_int(bio_cbor_encoder_t *enc, int64_t value);

/* ── Byte String (Major Type 2) ──────────────────────────────── */
int bio_cbor_encode_bstr(bio_cbor_encoder_t *enc,
                         const uint8_t *data, size_t len);

/* ── Text String (Major Type 3) ──────────────────────────────── */
int bio_cbor_encode_tstr(bio_cbor_encoder_t *enc,
                         const char *str, size_t len);

/* Convenience: encode null-terminated string */
int bio_cbor_encode_tstr_z(bio_cbor_encoder_t *enc, const char *str);

/* ── Array (Major Type 4) ────────────────────────────────────── */
/**
 * Begin a definite-length array.
 * After this, encode exactly `count` items.
 */
int bio_cbor_encode_array(bio_cbor_encoder_t *enc, size_t count);

/* ── Map (Major Type 5) ──────────────────────────────────────── */
/**
 * Begin a definite-length map.
 * After this, encode exactly `count` key-value pairs (2*count items).
 * Keys MUST be encoded in CTAP2 canonical order by the caller.
 */
int bio_cbor_encode_map(bio_cbor_encoder_t *enc, size_t count);

/* ── Tag (Major Type 6) ──────────────────────────────────────── */
int bio_cbor_encode_tag(bio_cbor_encoder_t *enc, uint64_t tag);

/* ── Simple Values (Major Type 7) ────────────────────────────── */
int bio_cbor_encode_bool(bio_cbor_encoder_t *enc, bool value);
int bio_cbor_encode_null(bio_cbor_encoder_t *enc);
int bio_cbor_encode_undefined(bio_cbor_encoder_t *enc);
int bio_cbor_encode_simple(bio_cbor_encoder_t *enc, uint8_t value);

/* ── Float (Major Type 7) ────────────────────────────────────── */
int bio_cbor_encode_float(bio_cbor_encoder_t *enc, float value);
int bio_cbor_encode_double(bio_cbor_encoder_t *enc, double value);


/* ══════════════════════════════════════════════════════════════════
 *  DECODER
 * ══════════════════════════════════════════════════════════════════ */

/**
 * Decoded CBOR item.
 * Zero-copy: byte/text strings point into the source buffer.
 */
typedef struct {
    bio_cbor_major_t type;
    union {
        uint64_t     uint_val;        /* Major 0: unsigned integer */
        int64_t      int_val;         /* Sign-extended integer (convenience) */
        struct {
            const uint8_t *data;
            size_t         len;
        } bstr;                       /* Major 2: byte string */
        struct {
            const char *data;
            size_t      len;
        } tstr;                       /* Major 3: text string */
        size_t       container_len;   /* Major 4/5: array/map item count */
        uint64_t     tag_val;         /* Major 6: tag number */
        struct {
            uint8_t  simple_val;      /* Major 7, additional < 24 */
            float    float_val;       /* Major 7, additional 26 */
            double   double_val;      /* Major 7, additional 27 */
            bool     is_float;        /* true if float/double */
            bool     is_double;       /* true if double */
        } simple;
    };
} bio_cbor_item_t;

/**
 * CBOR decoder context.
 * Stateful cursor into a CBOR byte buffer.
 */
typedef struct {
    const uint8_t *data;      /* Source buffer */
    size_t         size;      /* Buffer size */
    size_t         offset;    /* Current read position */
    bool           error;     /* Set on parse error */
    int            err_code;  /* Specific error code */
} bio_cbor_decoder_t;

/**
 * Initialize decoder with CBOR data.
 */
void bio_cbor_decoder_init(bio_cbor_decoder_t *dec,
                           const uint8_t *data, size_t size);

/**
 * Decode the next CBOR item.
 * Advances the cursor past the item header. For containers (array/map),
 * the cursor is positioned at the first child item.
 *
 * @param dec   Decoder context
 * @param item  Output item
 * @return BIO_OK or BIO_ERR_CBOR_*
 */
int bio_cbor_decode_next(bio_cbor_decoder_t *dec, bio_cbor_item_t *item);

/**
 * Peek at the type of the next item without advancing the cursor.
 */
int bio_cbor_peek_type(bio_cbor_decoder_t *dec, bio_cbor_major_t *type);

/**
 * Skip the next CBOR item entirely (including nested content).
 */
int bio_cbor_skip(bio_cbor_decoder_t *dec);

/**
 * Check if all data has been consumed.
 */
bool bio_cbor_decoder_at_end(const bio_cbor_decoder_t *dec);

/**
 * Get current offset into the buffer.
 */
size_t bio_cbor_decoder_offset(const bio_cbor_decoder_t *dec);

/**
 * Get remaining bytes in the buffer.
 */
size_t bio_cbor_decoder_remaining(const bio_cbor_decoder_t *dec);

/* ── Convenience decoding helpers ────────────────────────────── */

/**
 * Decode the next item and expect it to be an unsigned integer.
 */
int bio_cbor_decode_uint(bio_cbor_decoder_t *dec, uint64_t *value);

/**
 * Decode the next item and expect integer (positive or negative).
 */
int bio_cbor_decode_int(bio_cbor_decoder_t *dec, int64_t *value);

/**
 * Decode the next item and expect a byte string.
 * Returns a pointer into the decoder's source buffer (zero-copy).
 */
int bio_cbor_decode_bstr(bio_cbor_decoder_t *dec,
                         const uint8_t **data, size_t *len);

/**
 * Decode the next item and expect a text string.
 */
int bio_cbor_decode_tstr(bio_cbor_decoder_t *dec,
                         const char **str, size_t *len);

/**
 * Decode the next item and expect an array header.
 * Returns the number of items in the array.
 */
int bio_cbor_decode_array(bio_cbor_decoder_t *dec, size_t *count);

/**
 * Decode the next item and expect a map header.
 * Returns the number of key-value pairs.
 */
int bio_cbor_decode_map(bio_cbor_decoder_t *dec, size_t *count);

/**
 * Decode the next item and expect a boolean.
 */
int bio_cbor_decode_bool(bio_cbor_decoder_t *dec, bool *value);

/**
 * Decode the next item and expect null.
 */
int bio_cbor_decode_null(bio_cbor_decoder_t *dec);

/**
 * Decode a tag.
 */
int bio_cbor_decode_tag(bio_cbor_decoder_t *dec, uint64_t *tag);

/* ── CTAP2 Map Search Helper ─────────────────────────────────── */

/**
 * Search a CBOR map for a key (uint).
 * Decoder must be positioned right after the map header.
 * On success, decoder is positioned at the value.
 * @param dec       Decoder positioned after map header
 * @param count     Number of map pairs (from decode_map)
 * @param key       The uint key to find
 * @return BIO_OK if found, BIO_ERR_NOT_FOUND otherwise
 */
int bio_cbor_map_find_uint_key(bio_cbor_decoder_t *dec,
                               size_t count, uint64_t key);

/**
 * Search a CBOR map for a key (text string).
 */
int bio_cbor_map_find_tstr_key(bio_cbor_decoder_t *dec,
                               size_t count,
                               const char *key, size_t key_len);

/* ── Low-level head encode/decode ────────────────────────────── */

/**
 * Encode a CBOR head byte (major type + argument) directly into a buffer.
 * Returns the number of bytes written, or 0 on error.
 *
 * @param buf     Output buffer
 * @param cap     Buffer capacity
 * @param mt      Major type (0–7)
 * @param value   Argument value
 * @return        Number of bytes written (1, 2, 3, 5, or 9), 0 on overflow
 */
size_t bio_cbor_encode_head_raw(uint8_t *buf, size_t cap,
                                bio_cbor_major_t mt, uint64_t value);

/**
 * Decode a CBOR head byte from a buffer.
 * Returns the number of bytes consumed, or 0 on error.
 *
 * @param data    Input buffer
 * @param size    Buffer size
 * @param major   Output: major type
 * @param value   Output: argument value
 * @return        Number of bytes consumed (1, 2, 3, 5, or 9), 0 on error
 */
size_t bio_cbor_decode_head_raw(const uint8_t *data, size_t size,
                                bio_cbor_major_t *major, uint64_t *value);

/* ── CTAP2 Canonical CBOR Sort ───────────────────────────────── */

/**
 * Sort a CBOR map's key-value pairs in CTAP2 canonical order.
 * Operates on an already-encoded CBOR map (first byte must be a map head).
 *
 * CTAP2 canonical order:
 *   1. Sort by key encoded length (shorter first)
 *   2. If same length, sort lexicographically by raw bytes
 *
 * @param cbor_buf   Buffer containing the CBOR-encoded map
 * @param cbor_len   Length of the CBOR data
 * @return BIO_OK on success, error code otherwise
 */
int bio_cbor_sort_map_ctap2(uint8_t *cbor_buf, size_t cbor_len);

/**
 * Compute the encoded size of a single CBOR item (head + payload).
 * For containers (array/map), returns the total encoded size including
 * all nested items.
 *
 * @param data   Pointer to start of a CBOR-encoded item
 * @param len    Available bytes
 * @param out_sz Output: total encoded size of the item
 * @return BIO_OK or error
 */
int bio_cbor_item_encoded_size(const uint8_t *data, size_t len, size_t *out_sz);

#ifdef __cplusplus
}
#endif

#endif /* BIO_CBOR_H */
