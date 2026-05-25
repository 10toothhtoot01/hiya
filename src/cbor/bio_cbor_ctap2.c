/*
 * bio_cbor_ctap2.c — CTAP2 Canonical CBOR Utilities
 *
 * Copyright (C) 2024 BioAuth Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Implements CTAP2 canonical CBOR map key sorting and
 * public low-level encode/decode head helpers.
 *
 * CTAP2 canonical CBOR sorting (FIDO CTAP2 §6):
 *   - Map keys sorted by key's encoded length (shorter first)
 *   - If same length, sorted by lexicographic byte order
 *   - This is NOT the same as RFC 7049 deterministic encoding
 *
 * References:
 *   - FIDO CTAP2 specification §6 "Canonical CBOR Encoding Form"
 *   - RFC 8949 §4.2 "Deterministically Encoded CBOR"
 */

#include "cbor/bio_cbor.h"

#include <string.h>
#include <stdlib.h>

/* ── Low-level head encode/decode ────────────────────────────── */

size_t bio_cbor_encode_head_raw(uint8_t *buf, size_t cap,
                                bio_cbor_major_t mt, uint64_t value)
{
    if (!buf || cap == 0) return 0;

    uint8_t type_bits = (uint8_t)mt << 5;

    if (value <= 23) {
        buf[0] = type_bits | (uint8_t)value;
        return 1;
    }
    else if (value <= 0xFF) {
        if (cap < 2) return 0;
        buf[0] = type_bits | 24;
        buf[1] = (uint8_t)value;
        return 2;
    }
    else if (value <= 0xFFFF) {
        if (cap < 3) return 0;
        buf[0] = type_bits | 25;
        buf[1] = (uint8_t)(value >> 8);
        buf[2] = (uint8_t)value;
        return 3;
    }
    else if (value <= 0xFFFFFFFFULL) {
        if (cap < 5) return 0;
        buf[0] = type_bits | 26;
        buf[1] = (uint8_t)(value >> 24);
        buf[2] = (uint8_t)(value >> 16);
        buf[3] = (uint8_t)(value >> 8);
        buf[4] = (uint8_t)value;
        return 5;
    }
    else {
        if (cap < 9) return 0;
        buf[0] = type_bits | 27;
        buf[1] = (uint8_t)(value >> 56);
        buf[2] = (uint8_t)(value >> 48);
        buf[3] = (uint8_t)(value >> 40);
        buf[4] = (uint8_t)(value >> 32);
        buf[5] = (uint8_t)(value >> 24);
        buf[6] = (uint8_t)(value >> 16);
        buf[7] = (uint8_t)(value >> 8);
        buf[8] = (uint8_t)value;
        return 9;
    }
}

size_t bio_cbor_decode_head_raw(const uint8_t *data, size_t size,
                                bio_cbor_major_t *major, uint64_t *value)
{
    if (!data || !major || !value || size == 0) return 0;

    uint8_t head = data[0];
    *major = (bio_cbor_major_t)(head >> 5);
    uint8_t ai = head & 0x1F;

    if (ai <= 23) {
        *value = ai;
        return 1;
    }
    else if (ai == 24) {
        if (size < 2) return 0;
        *value = data[1];
        return 2;
    }
    else if (ai == 25) {
        if (size < 3) return 0;
        *value = ((uint16_t)data[1] << 8) | data[2];
        return 3;
    }
    else if (ai == 26) {
        if (size < 5) return 0;
        *value = ((uint32_t)data[1] << 24) | ((uint32_t)data[2] << 16) |
                 ((uint32_t)data[3] << 8)  | data[4];
        return 5;
    }
    else if (ai == 27) {
        if (size < 9) return 0;
        *value = ((uint64_t)data[1] << 56) | ((uint64_t)data[2] << 48) |
                 ((uint64_t)data[3] << 40) | ((uint64_t)data[4] << 32) |
                 ((uint64_t)data[5] << 24) | ((uint64_t)data[6] << 16) |
                 ((uint64_t)data[7] << 8)  | data[8];
        return 9;
    }
    else {
        /* 28, 29, 30 are reserved; 31 = break (indefinite) */
        return 0;
    }
}

/* ── Item encoded size calculator ────────────────────────────── */

static int cbor_item_encoded_size_depth(const uint8_t *data, size_t len,
                                        size_t *out_sz, int depth)
{
    if (depth > 32)
        return BIO_ERR_CBOR_NESTING;
    if (!data || !out_sz || len == 0)
        return BIO_ERR_INVALID_PARAM;

    bio_cbor_major_t mt;
    uint64_t val;
    size_t head_sz = bio_cbor_decode_head_raw(data, len, &mt, &val);
    if (head_sz == 0)
        return BIO_ERR_CBOR_INVALID;

    switch (mt) {
    case BIO_CBOR_UINT:
    case BIO_CBOR_NEGINT:
        /* Integer: head only */
        *out_sz = head_sz;
        return BIO_OK;

    case BIO_CBOR_BSTR:
    case BIO_CBOR_TSTR:
        /* Byte/text string: head + val payload bytes */
        if (val > SIZE_MAX - head_sz || head_sz + (size_t)val > len)
            return BIO_ERR_CBOR_INVALID;
        *out_sz = head_sz + (size_t)val;
        return BIO_OK;

    case BIO_CBOR_TAG: {
        /* Tag: head + one nested item */
        size_t child_sz;
        int rc = cbor_item_encoded_size_depth(data + head_sz, len - head_sz, &child_sz, depth + 1);
        if (rc != BIO_OK) return rc;
        *out_sz = head_sz + child_sz;
        return BIO_OK;
    }

    case BIO_CBOR_ARRAY: {
        /* Array: head + val items */
        size_t total = head_sz;
        for (uint64_t i = 0; i < val; i++) {
            if (total >= len) return BIO_ERR_CBOR_INVALID;
            size_t child_sz;
            int rc = cbor_item_encoded_size_depth(data + total, len - total, &child_sz, depth + 1);
            if (rc != BIO_OK) return rc;
            total += child_sz;
        }
        *out_sz = total;
        return BIO_OK;
    }

    case BIO_CBOR_MAP: {
        /* Map: head + 2*val items (key-value pairs) */
        size_t total = head_sz;
        if (val > UINT64_MAX / 2)
            return BIO_ERR_CBOR_INVALID;
        for (uint64_t i = 0; i < val * 2; i++) {
            if (total >= len) return BIO_ERR_CBOR_INVALID;
            size_t child_sz;
            int rc = cbor_item_encoded_size_depth(data + total, len - total, &child_sz, depth + 1);
            if (rc != BIO_OK) return rc;
            total += child_sz;
        }
        *out_sz = total;
        return BIO_OK;
    }

    case BIO_CBOR_SIMPLE: {
        uint8_t ai = data[0] & 0x1F;
        if (ai == 25) {
            /* half float: 3 bytes total */
            *out_sz = 3;
        } else if (ai == 26) {
            /* single float: 5 bytes total */
            *out_sz = 5;
        } else if (ai == 27) {
            /* double float: 9 bytes total */
            *out_sz = 9;
        } else {
            *out_sz = head_sz;
        }
        if (*out_sz > len) return BIO_ERR_CBOR_INVALID;
        return BIO_OK;
    }
    }

    return BIO_ERR_CBOR_INVALID;
}

int bio_cbor_item_encoded_size(const uint8_t *data, size_t len, size_t *out_sz)
{
    return cbor_item_encoded_size_depth(data, len, out_sz, 0);
}

/* ── CTAP2 Canonical Map Sorting ─────────────────────────────── */

/*
 * Internal: representation of a key-value pair within an encoded map.
 * We store pointers + sizes rather than copying for efficiency.
 */
typedef struct {
    const uint8_t *key_data;
    size_t         key_len;
    const uint8_t *val_data;
    size_t         val_len;
} cbor_kv_pair_t;

/*
 * CTAP2 canonical comparison for CBOR-encoded map keys:
 *   1. Shorter key encoding sorts first
 *   2. Same length: lexicographic comparison of raw bytes
 */
static int ctap2_key_compare(const void *a, const void *b)
{
    const cbor_kv_pair_t *pa = (const cbor_kv_pair_t *)a;
    const cbor_kv_pair_t *pb = (const cbor_kv_pair_t *)b;

    if (pa->key_len < pb->key_len) return -1;
    if (pa->key_len > pb->key_len) return  1;

    return memcmp(pa->key_data, pb->key_data, pa->key_len);
}

int bio_cbor_sort_map_ctap2(uint8_t *cbor_buf, size_t cbor_len)
{
    if (!cbor_buf || cbor_len == 0)
        return BIO_ERR_INVALID_PARAM;

    /* Decode map header */
    bio_cbor_major_t mt;
    uint64_t pair_count;
    size_t head_sz = bio_cbor_decode_head_raw(cbor_buf, cbor_len, &mt, &pair_count);
    if (head_sz == 0 || mt != BIO_CBOR_MAP)
        return BIO_ERR_CBOR_INVALID;

    if (pair_count == 0)
        return BIO_OK;  /* Nothing to sort */

    if (pair_count > 256)
        return BIO_ERR_CBOR_INVALID;  /* Sanity limit */

    /* Parse all key-value pairs to find their offsets and sizes */
    cbor_kv_pair_t *pairs = calloc((size_t)pair_count, sizeof(cbor_kv_pair_t));
    if (!pairs)
        return BIO_ERR_NOMEM;

    size_t pos = head_sz;
    int rc = BIO_OK;

    for (uint64_t i = 0; i < pair_count; i++) {
        /* Parse key */
        pairs[i].key_data = cbor_buf + pos;
        size_t key_sz;
        rc = bio_cbor_item_encoded_size(cbor_buf + pos, cbor_len - pos, &key_sz);
        if (rc != BIO_OK) goto cleanup;
        pairs[i].key_len = key_sz;
        pos += key_sz;

        /* Parse value */
        pairs[i].val_data = cbor_buf + pos;
        size_t val_sz;
        rc = bio_cbor_item_encoded_size(cbor_buf + pos, cbor_len - pos, &val_sz);
        if (rc != BIO_OK) goto cleanup;
        pairs[i].val_len = val_sz;
        pos += val_sz;
    }

    /* Sort pairs using CTAP2 canonical comparison */
    qsort(pairs, (size_t)pair_count, sizeof(cbor_kv_pair_t), ctap2_key_compare);

    /* Rebuild the map body from sorted pairs into a temporary buffer.
     * We need to be careful: the original data pointers are into cbor_buf,
     * so we must copy into a fresh buffer before writing back. */
    size_t body_len = pos - head_sz;
    uint8_t *sorted_body = malloc(body_len);
    if (!sorted_body) {
        rc = BIO_ERR_NOMEM;
        goto cleanup;
    }

    size_t out_pos = 0;
    for (uint64_t i = 0; i < pair_count; i++) {
        memcpy(sorted_body + out_pos, pairs[i].key_data, pairs[i].key_len);
        out_pos += pairs[i].key_len;
        memcpy(sorted_body + out_pos, pairs[i].val_data, pairs[i].val_len);
        out_pos += pairs[i].val_len;
    }

    /* Write sorted body back into the original buffer */
    memcpy(cbor_buf + head_sz, sorted_body, body_len);

    free(sorted_body);

cleanup:
    free(pairs);
    return rc;
}
