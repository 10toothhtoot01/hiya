/*
 * pm_kdf.c - In-tree Argon2id implementation for PM vault KDF
 *
 * Copyright (C) 2026 BioAuth Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "pm/pm_kdf.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "crypto/bio_crypto.h"
#include "pm/pm_secure_mem.h"

#define PM_ARGON2_VERSION_13 0x13u
#define PM_ARGON2_TYPE_ID 2u

#define PM_ARGON2_BLOCK_WORDS 128u
#define PM_ARGON2_BLOCK_BYTES 1024u
#define PM_ARGON2_SYNC_POINTS 4u
#define PM_ARGON2_PREHASH_DIGEST_LENGTH 64u
#define PM_ARGON2_DEFAULT_T_COST 3u
#define PM_ARGON2_DEFAULT_M_COST_KIB 65536u
#define PM_ARGON2_DEFAULT_PARALLELISM 1u

/* Conservative limits to avoid unbounded resource abuse in daemon path. */
#define PM_ARGON2_MIN_T_COST 1u
#define PM_ARGON2_MAX_T_COST 10u
#define PM_ARGON2_MIN_M_COST_KIB 8u
#define PM_ARGON2_MAX_M_COST_KIB (1024u * 1024u)
#define PM_ARGON2_MIN_PARALLELISM 1u
#define PM_ARGON2_MAX_PARALLELISM 8u

typedef struct
{
    uint64_t v[PM_ARGON2_BLOCK_WORDS];
} pm_argon2_block_t;

typedef struct
{
    uint8_t *buf;
    size_t len;
    size_t cap;
} pm_buf_t;

static void store32_le(uint8_t dst[4], uint32_t v)
{
    dst[0] = (uint8_t)(v & 0xFFu);
    dst[1] = (uint8_t)((v >> 8) & 0xFFu);
    dst[2] = (uint8_t)((v >> 16) & 0xFFu);
    dst[3] = (uint8_t)((v >> 24) & 0xFFu);
}

static uint64_t load64_le(const uint8_t src[8])
{
    return ((uint64_t)src[0]) |
           ((uint64_t)src[1] << 8) |
           ((uint64_t)src[2] << 16) |
           ((uint64_t)src[3] << 24) |
           ((uint64_t)src[4] << 32) |
           ((uint64_t)src[5] << 40) |
           ((uint64_t)src[6] << 48) |
           ((uint64_t)src[7] << 56);
}

static void store64_le(uint8_t dst[8], uint64_t v)
{
    dst[0] = (uint8_t)(v & 0xFFu);
    dst[1] = (uint8_t)((v >> 8) & 0xFFu);
    dst[2] = (uint8_t)((v >> 16) & 0xFFu);
    dst[3] = (uint8_t)((v >> 24) & 0xFFu);
    dst[4] = (uint8_t)((v >> 32) & 0xFFu);
    dst[5] = (uint8_t)((v >> 40) & 0xFFu);
    dst[6] = (uint8_t)((v >> 48) & 0xFFu);
    dst[7] = (uint8_t)((v >> 56) & 0xFFu);
}

static uint64_t rotr64(uint64_t x, uint32_t n)
{
    return (x >> n) | (x << (64u - n));
}

/* ---------------- BLAKE2b ---------------- */

typedef struct
{
    uint64_t h[8];
    uint64_t t[2];
    uint64_t f[2];
    uint8_t buf[128];
    size_t buflen;
    size_t outlen;
} pm_blake2b_ctx_t;

static const uint64_t blake2b_iv[8] = {
    0x6a09e667f3bcc908ULL,
    0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL,
    0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL,
    0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL,
    0x5be0cd19137e2179ULL,
};

static const uint8_t blake2b_sigma[12][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
    {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
    {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
};

#define B2_G(a, b, c, d, x, y)       \
    do                               \
    {                                \
        (a) = (a) + (b) + (x);       \
        (d) = rotr64((d) ^ (a), 32); \
        (c) = (c) + (d);             \
        (b) = rotr64((b) ^ (c), 24); \
        (a) = (a) + (b) + (y);       \
        (d) = rotr64((d) ^ (a), 16); \
        (c) = (c) + (d);             \
        (b) = rotr64((b) ^ (c), 63); \
    } while (0)

static void blake2b_compress(pm_blake2b_ctx_t *ctx, const uint8_t block[128], bool last)
{
    uint64_t m[16];
    uint64_t v[16];

    for (size_t i = 0; i < 16; i++)
    {
        m[i] = load64_le(block + (i * 8));
    }

    for (size_t i = 0; i < 8; i++)
    {
        v[i] = ctx->h[i];
        v[i + 8] = blake2b_iv[i];
    }

    v[12] ^= ctx->t[0];
    v[13] ^= ctx->t[1];
    if (last)
    {
        v[14] = ~v[14];
    }

    for (size_t r = 0; r < 12; r++)
    {
        B2_G(v[0], v[4], v[8], v[12], m[blake2b_sigma[r][0]], m[blake2b_sigma[r][1]]);
        B2_G(v[1], v[5], v[9], v[13], m[blake2b_sigma[r][2]], m[blake2b_sigma[r][3]]);
        B2_G(v[2], v[6], v[10], v[14], m[blake2b_sigma[r][4]], m[blake2b_sigma[r][5]]);
        B2_G(v[3], v[7], v[11], v[15], m[blake2b_sigma[r][6]], m[blake2b_sigma[r][7]]);
        B2_G(v[0], v[5], v[10], v[15], m[blake2b_sigma[r][8]], m[blake2b_sigma[r][9]]);
        B2_G(v[1], v[6], v[11], v[12], m[blake2b_sigma[r][10]], m[blake2b_sigma[r][11]]);
        B2_G(v[2], v[7], v[8], v[13], m[blake2b_sigma[r][12]], m[blake2b_sigma[r][13]]);
        B2_G(v[3], v[4], v[9], v[14], m[blake2b_sigma[r][14]], m[blake2b_sigma[r][15]]);
    }

    for (size_t i = 0; i < 8; i++)
    {
        ctx->h[i] ^= v[i] ^ v[i + 8];
    }
}

static void blake2b_init(pm_blake2b_ctx_t *ctx, size_t outlen)
{
    memset(ctx, 0, sizeof(*ctx));
    for (size_t i = 0; i < 8; i++)
    {
        ctx->h[i] = blake2b_iv[i];
    }

    /* fanout=1, depth=1, keylen=0, outlen variable */
    ctx->h[0] ^= 0x01010000u ^ (uint64_t)outlen;
    ctx->outlen = outlen;
}

static void blake2b_update(pm_blake2b_ctx_t *ctx, const uint8_t *in, size_t inlen)
{
    while (inlen > 0)
    {
        size_t left = ctx->buflen;
        size_t fill = 128u - left;

        if (inlen > fill)
        {
            memcpy(ctx->buf + left, in, fill);
            ctx->buflen = 0;
            ctx->t[0] += 128u;
            if (ctx->t[0] < 128u)
            {
                ctx->t[1]++;
            }
            blake2b_compress(ctx, ctx->buf, false);
            in += fill;
            inlen -= fill;
        }
        else
        {
            memcpy(ctx->buf + left, in, inlen);
            ctx->buflen = left + inlen;
            in += inlen;
            inlen = 0;
        }
    }
}

static void blake2b_final(pm_blake2b_ctx_t *ctx, uint8_t *out)
{
    memset(ctx->buf + ctx->buflen, 0, 128u - ctx->buflen);
    ctx->t[0] += (uint64_t)ctx->buflen;
    if (ctx->t[0] < (uint64_t)ctx->buflen)
    {
        ctx->t[1]++;
    }

    blake2b_compress(ctx, ctx->buf, true);

    for (size_t i = 0; i < 8; i++)
    {
        store64_le(out + i * 8, ctx->h[i]);
    }
}

static void blake2b_hash(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen)
{
    pm_blake2b_ctx_t ctx;
    uint8_t tmp[64];

    blake2b_init(&ctx, outlen <= 64u ? outlen : 64u);
    blake2b_update(&ctx, in, inlen);
    blake2b_final(&ctx, tmp);

    if (outlen <= 64u)
    {
        memcpy(out, tmp, outlen);
    }
    else
    {
        /* Caller should use argon2_hprime for >64 outputs. */
        memcpy(out, tmp, 64u);
    }

    bio_secure_wipe(&ctx, sizeof(ctx));
    bio_secure_wipe(tmp, sizeof(tmp));
}

/* Argon2 variable-length hash H' */
static pm_error_t argon2_hprime(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen)
{
    uint8_t *buf = NULL;
    uint8_t v_prev[64];
    uint8_t v_curr[64];

    if (!in || !out || outlen == 0)
    {
        return PM_ERR_INVALID_PARAM;
    }

    buf = malloc(4u + inlen);
    if (!buf)
    {
        return PM_ERR_NOMEM;
    }

    store32_le(buf, (uint32_t)outlen);
    memcpy(buf + 4u, in, inlen);

    if (outlen <= 64u)
    {
        blake2b_hash(buf, 4u + inlen, out, outlen);
        bio_secure_wipe(buf, 4u + inlen);
        free(buf);
        return PM_OK;
    }

    blake2b_hash(buf, 4u + inlen, v_prev, 64u);
    size_t produced = 0;

    while (outlen - produced > 64u)
    {
        memcpy(out + produced, v_prev, 32u);
        produced += 32u;
        blake2b_hash(v_prev, 64u, v_curr, 64u);
        memcpy(v_prev, v_curr, 64u);
    }

    blake2b_hash(v_prev, 64u, out + produced, outlen - produced);

    bio_secure_wipe(v_prev, sizeof(v_prev));
    bio_secure_wipe(v_curr, sizeof(v_curr));
    bio_secure_wipe(buf, 4u + inlen);
    free(buf);
    return PM_OK;
}

/* ---------------- Argon2 compression ---------------- */

static inline uint64_t blamka(uint64_t x, uint64_t y)
{
    uint64_t xl = (uint32_t)x;
    uint64_t yl = (uint32_t)y;
    return x + y + 2u * xl * yl;
}

#define ARGON2_G(a, b, c, d)         \
    do                               \
    {                                \
        (a) = blamka((a), (b));      \
        (d) = rotr64((d) ^ (a), 32); \
        (c) = blamka((c), (d));      \
        (b) = rotr64((b) ^ (c), 24); \
        (a) = blamka((a), (b));      \
        (d) = rotr64((d) ^ (a), 16); \
        (c) = blamka((c), (d));      \
        (b) = rotr64((b) ^ (c), 63); \
    } while (0)

static void argon2_permute_16(uint64_t *x)
{
    ARGON2_G(x[0], x[4], x[8], x[12]);
    ARGON2_G(x[1], x[5], x[9], x[13]);
    ARGON2_G(x[2], x[6], x[10], x[14]);
    ARGON2_G(x[3], x[7], x[11], x[15]);
    ARGON2_G(x[0], x[5], x[10], x[15]);
    ARGON2_G(x[1], x[6], x[11], x[12]);
    ARGON2_G(x[2], x[7], x[8], x[13]);
    ARGON2_G(x[3], x[4], x[9], x[14]);
}

static void argon2_compress(pm_argon2_block_t *out,
                            const pm_argon2_block_t *a,
                            const pm_argon2_block_t *b,
                            bool xor_with_old)
{
    pm_argon2_block_t r, z;

    for (size_t i = 0; i < PM_ARGON2_BLOCK_WORDS; i++)
    {
        r.v[i] = a->v[i] ^ b->v[i];
        z.v[i] = r.v[i];
    }

    for (size_t i = 0; i < 8; i++)
    {
        argon2_permute_16(&z.v[i * 16u]);
    }

    for (size_t i = 0; i < 8; i++)
    {
        uint64_t x[16];
        for (size_t j = 0; j < 8; j++)
        {
            x[2u * j] = z.v[16u * j + i * 2u];
            x[2u * j + 1u] = z.v[16u * j + i * 2u + 1u];
        }
        argon2_permute_16(x);
        for (size_t j = 0; j < 8; j++)
        {
            z.v[16u * j + i * 2u] = x[2u * j];
            z.v[16u * j + i * 2u + 1u] = x[2u * j + 1u];
        }
    }

    if (xor_with_old)
    {
        for (size_t i = 0; i < PM_ARGON2_BLOCK_WORDS; i++)
        {
            out->v[i] ^= r.v[i] ^ z.v[i];
        }
    }
    else
    {
        for (size_t i = 0; i < PM_ARGON2_BLOCK_WORDS; i++)
        {
            out->v[i] = r.v[i] ^ z.v[i];
        }
    }

    bio_secure_wipe(&r, sizeof(r));
    bio_secure_wipe(&z, sizeof(z));
}

static void block_from_bytes(pm_argon2_block_t *blk, const uint8_t *src)
{
    for (size_t i = 0; i < PM_ARGON2_BLOCK_WORDS; i++)
    {
        blk->v[i] = load64_le(src + i * 8u);
    }
}

static void block_to_bytes(uint8_t *dst, const pm_argon2_block_t *blk)
{
    for (size_t i = 0; i < PM_ARGON2_BLOCK_WORDS; i++)
    {
        store64_le(dst + i * 8u, blk->v[i]);
    }
}

static size_t lane_offset(uint32_t lane, uint32_t lane_len)
{
    return (size_t)lane * (size_t)lane_len;
}

static void append_u32(pm_buf_t *b, uint32_t v)
{
    if (b->len + 4u <= b->cap)
    {
        store32_le(b->buf + b->len, v);
        b->len += 4u;
    }
}

static void append_bytes(pm_buf_t *b, const uint8_t *src, size_t n)
{
    if (b->len + n <= b->cap)
    {
        if (n > 0 && src)
        {
            memcpy(b->buf + b->len, src, n);
        }
        b->len += n;
    }
}

static pm_error_t argon2_initial_hash(const uint8_t *pwd,
                                      size_t pwd_len,
                                      const uint8_t salt[PM_KDF_SALT_SIZE],
                                      const pm_argon2_params_t *p,
                                      uint8_t h0[PM_ARGON2_PREHASH_DIGEST_LENGTH])
{
    uint8_t prehash[256];
    pm_buf_t b = {
        .buf = prehash,
        .len = 0,
        .cap = sizeof(prehash),
    };

    append_u32(&b, p->parallelism);
    append_u32(&b, PM_KDF_KEY_SIZE);
    append_u32(&b, p->m_cost_kib);
    append_u32(&b, p->t_cost);
    append_u32(&b, p->version);
    append_u32(&b, PM_ARGON2_TYPE_ID);

    append_u32(&b, (uint32_t)pwd_len);
    append_bytes(&b, pwd, pwd_len);

    append_u32(&b, PM_KDF_SALT_SIZE);
    append_bytes(&b, salt, PM_KDF_SALT_SIZE);

    append_u32(&b, 0u);
    append_u32(&b, 0u);

    if (b.len > b.cap)
    {
        return PM_ERR_INTERNAL;
    }

    blake2b_hash(prehash, b.len, h0, PM_ARGON2_PREHASH_DIGEST_LENGTH);
    bio_secure_wipe(prehash, sizeof(prehash));
    return PM_OK;
}

static pm_error_t fill_first_blocks(pm_argon2_block_t *mem,
                                    uint32_t lanes,
                                    uint32_t lane_len,
                                    const uint8_t h0[PM_ARGON2_PREHASH_DIGEST_LENGTH])
{
    uint8_t inbuf[PM_ARGON2_PREHASH_DIGEST_LENGTH + 8u];
    uint8_t outbuf[PM_ARGON2_BLOCK_BYTES];

    memcpy(inbuf, h0, PM_ARGON2_PREHASH_DIGEST_LENGTH);

    for (uint32_t lane = 0; lane < lanes; lane++)
    {
        store32_le(inbuf + PM_ARGON2_PREHASH_DIGEST_LENGTH, 0u);
        store32_le(inbuf + PM_ARGON2_PREHASH_DIGEST_LENGTH + 4u, lane);
        pm_error_t rc0 = argon2_hprime(inbuf, sizeof(inbuf), outbuf, sizeof(outbuf));
        if (rc0 != PM_OK)
        {
            bio_secure_wipe(inbuf, sizeof(inbuf));
            bio_secure_wipe(outbuf, sizeof(outbuf));
            return rc0;
        }
        block_from_bytes(&mem[lane_offset(lane, lane_len) + 0u], outbuf);

        store32_le(inbuf + PM_ARGON2_PREHASH_DIGEST_LENGTH, 1u);
        pm_error_t rc1 = argon2_hprime(inbuf, sizeof(inbuf), outbuf, sizeof(outbuf));
        if (rc1 != PM_OK)
        {
            bio_secure_wipe(inbuf, sizeof(inbuf));
            bio_secure_wipe(outbuf, sizeof(outbuf));
            return rc1;
        }
        block_from_bytes(&mem[lane_offset(lane, lane_len) + 1u], outbuf);
    }

    bio_secure_wipe(inbuf, sizeof(inbuf));
    bio_secure_wipe(outbuf, sizeof(outbuf));
    return PM_OK;
}

static uint32_t index_alpha(uint32_t pass,
                            uint32_t slice,
                            uint32_t index,
                            uint32_t lane,
                            uint32_t ref_lane,
                            uint32_t lane_len,
                            uint32_t seg_len,
                            uint32_t pseudo_rand)
{
    uint32_t ref_area_size;
    uint32_t start_pos;

    if (pass == 0u)
    {
        if (slice == 0u)
        {
            ref_area_size = index - 1u;
        }
        else
        {
            if (ref_lane == lane)
            {
                ref_area_size = slice * seg_len + index - 1u;
            }
            else
            {
                ref_area_size = slice * seg_len + (index == 0u ? 0u : (uint32_t)-1 + 1u);
                if (index == 0u)
                {
                    ref_area_size = slice * seg_len - 1u;
                }
            }
        }
        start_pos = 0u;
    }
    else
    {
        if (ref_lane == lane)
        {
            ref_area_size = lane_len - seg_len + index - 1u;
        }
        else
        {
            ref_area_size = lane_len - seg_len + (index == 0u ? (uint32_t)-1 + 1u : 0u);
            if (index == 0u)
            {
                ref_area_size = lane_len - seg_len - 1u;
            }
        }

        if (slice == PM_ARGON2_SYNC_POINTS - 1u)
        {
            start_pos = 0u;
        }
        else
        {
            start_pos = (slice + 1u) * seg_len;
        }
    }

    if (ref_area_size == 0u)
    {
        return 0u;
    }

    uint64_t x = (uint64_t)pseudo_rand;
    uint64_t y = (x * x) >> 32;
    uint64_t z = ((uint64_t)ref_area_size * y) >> 32;
    uint32_t rel = ref_area_size - 1u - (uint32_t)z;

    return (start_pos + rel) % lane_len;
}

static void fill_segment(pm_argon2_block_t *mem,
                         uint32_t pass,
                         uint32_t lane,
                         uint32_t slice,
                         uint32_t m_blocks,
                         uint32_t t_cost,
                         uint32_t lanes,
                         uint32_t lane_len,
                         uint32_t seg_len)
{
    uint32_t start_index = 0u;
    uint32_t curr_offset = lane * lane_len + slice * seg_len;

    pm_argon2_block_t zero_block;
    pm_argon2_block_t input_block;
    pm_argon2_block_t addr_block;

    memset(&zero_block, 0, sizeof(zero_block));
    memset(&input_block, 0, sizeof(input_block));
    memset(&addr_block, 0, sizeof(addr_block));

    bool data_independent = (pass == 0u && slice < 2u);

    if (pass == 0u && slice == 0u)
    {
        start_index = 2u;
    }

    if (data_independent)
    {
        input_block.v[0] = pass;
        input_block.v[1] = lane;
        input_block.v[2] = slice;
        input_block.v[3] = m_blocks;
        input_block.v[4] = t_cost;
        input_block.v[5] = PM_ARGON2_TYPE_ID;
    }

    for (uint32_t i = start_index; i < seg_len; i++)
    {
        uint32_t curr_index = slice * seg_len + i;
        uint32_t prev_index = (curr_index == 0u) ? (lane_len - 1u) : (curr_index - 1u);
        pm_argon2_block_t *prev = &mem[lane * lane_len + prev_index];

        uint64_t pseudo_rand64;
        if (data_independent)
        {
            if ((i % 128u) == 0u)
            {
                input_block.v[6]++;
                argon2_compress(&addr_block, &zero_block, &input_block, false);
                argon2_compress(&addr_block, &zero_block, &addr_block, false);
            }
            pseudo_rand64 = addr_block.v[i % 128u];
        }
        else
        {
            pseudo_rand64 = prev->v[0];
        }

        uint32_t ref_lane = (uint32_t)((pseudo_rand64 >> 32) % lanes);
        if (pass == 0u && slice == 0u)
        {
            ref_lane = lane;
        }

        uint32_t ref_index = index_alpha(pass,
                                         slice,
                                         i,
                                         lane,
                                         ref_lane,
                                         lane_len,
                                         seg_len,
                                         (uint32_t)(pseudo_rand64 & 0xFFFFFFFFu));

        pm_argon2_block_t *ref = &mem[ref_lane * lane_len + ref_index];
        pm_argon2_block_t *curr = &mem[curr_offset + i];

        bool with_xor = (pass != 0u);
        argon2_compress(curr, prev, ref, with_xor);
    }

    bio_secure_wipe(&zero_block, sizeof(zero_block));
    bio_secure_wipe(&input_block, sizeof(input_block));
    bio_secure_wipe(&addr_block, sizeof(addr_block));
}

pm_error_t pm_argon2id_validate_params(pm_argon2_params_t *params)
{
    if (!params)
    {
        return PM_ERR_INVALID_PARAM;
    }

    if (params->t_cost == 0u)
    {
        params->t_cost = PM_ARGON2_DEFAULT_T_COST;
    }
    if (params->m_cost_kib == 0u)
    {
        params->m_cost_kib = PM_ARGON2_DEFAULT_M_COST_KIB;
    }
    if (params->parallelism == 0u)
    {
        params->parallelism = PM_ARGON2_DEFAULT_PARALLELISM;
    }
    if (params->version == 0u)
    {
        params->version = PM_ARGON2_VERSION_13;
    }

    if (params->version != PM_ARGON2_VERSION_13)
    {
        return PM_ERR_KDF;
    }

    if (params->t_cost < PM_ARGON2_MIN_T_COST || params->t_cost > PM_ARGON2_MAX_T_COST)
    {
        return PM_ERR_KDF;
    }

    if (params->parallelism < PM_ARGON2_MIN_PARALLELISM || params->parallelism > PM_ARGON2_MAX_PARALLELISM)
    {
        return PM_ERR_KDF;
    }

    if (params->m_cost_kib < PM_ARGON2_MIN_M_COST_KIB || params->m_cost_kib > PM_ARGON2_MAX_M_COST_KIB)
    {
        return PM_ERR_KDF;
    }

    if (params->m_cost_kib < 8u * params->parallelism)
    {
        return PM_ERR_KDF;
    }

    return PM_OK;
}

pm_error_t pm_argon2id_derive(const uint8_t *password,
                              size_t password_len,
                              const uint8_t salt[PM_KDF_SALT_SIZE],
                              const pm_argon2_params_t *params,
                              uint8_t out_key[PM_KDF_KEY_SIZE])
{
    pm_argon2_params_t p;
    pm_argon2_block_t *mem = NULL;
    pm_argon2_block_t final_block;
    uint8_t h0[PM_ARGON2_PREHASH_DIGEST_LENGTH];
    uint8_t final_block_bytes[PM_ARGON2_BLOCK_BYTES];

    if (!password || password_len == 0u || !salt || !params || !out_key)
    {
        return PM_ERR_INVALID_PARAM;
    }

    p = *params;
    pm_error_t rc = pm_argon2id_validate_params(&p);
    if (rc != PM_OK)
    {
        return rc;
    }

    uint32_t m_blocks = p.m_cost_kib;
    uint32_t lane_len = m_blocks / p.parallelism;
    lane_len = (lane_len / PM_ARGON2_SYNC_POINTS) * PM_ARGON2_SYNC_POINTS;
    m_blocks = lane_len * p.parallelism;
    uint32_t seg_len = lane_len / PM_ARGON2_SYNC_POINTS;

    size_t mem_bytes = (size_t)m_blocks * sizeof(pm_argon2_block_t);
    rc = pm_secure_alloc(mem_bytes, (void **)&mem);
    if (rc != PM_OK)
    {
        return rc;
    }

    memset(mem, 0, mem_bytes);
    memset(&final_block, 0, sizeof(final_block));

    rc = argon2_initial_hash(password, password_len, salt, &p, h0);
    if (rc != PM_OK)
    {
        pm_secure_free(mem, mem_bytes);
        return rc;
    }

    rc = fill_first_blocks(mem, p.parallelism, lane_len, h0);
    if (rc != PM_OK)
    {
        bio_secure_wipe(h0, sizeof(h0));
        pm_secure_free(mem, mem_bytes);
        return rc;
    }

    for (uint32_t pass = 0; pass < p.t_cost; pass++)
    {
        for (uint32_t slice = 0; slice < PM_ARGON2_SYNC_POINTS; slice++)
        {
            for (uint32_t lane = 0; lane < p.parallelism; lane++)
            {
                fill_segment(mem,
                             pass,
                             lane,
                             slice,
                             m_blocks,
                             p.t_cost,
                             p.parallelism,
                             lane_len,
                             seg_len);
            }
        }
    }

    for (uint32_t lane = 0; lane < p.parallelism; lane++)
    {
        pm_argon2_block_t *last = &mem[lane * lane_len + (lane_len - 1u)];
        for (size_t w = 0; w < PM_ARGON2_BLOCK_WORDS; w++)
        {
            final_block.v[w] ^= last->v[w];
        }
    }

    block_to_bytes(final_block_bytes, &final_block);
    rc = argon2_hprime(final_block_bytes, sizeof(final_block_bytes), out_key, PM_KDF_KEY_SIZE);

    bio_secure_wipe(h0, sizeof(h0));
    bio_secure_wipe(&final_block, sizeof(final_block));
    bio_secure_wipe(final_block_bytes, sizeof(final_block_bytes));
    pm_secure_free(mem, mem_bytes);

    return rc;
}
