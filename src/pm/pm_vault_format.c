/*
 * pm_vault_format.c - PM vault binary container format I/O
 *
 * Copyright (C) 2026 BioAuth Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "pm/pm_vault_format.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "crypto/bio_crypto.h"
#include "pm/pm_secure_mem.h"

#define PM_VAULT_HEADER_CRC_OFFSET 0x18u
#define PM_VAULT_GCM_TAG_OFFSET 0x60u
#define PM_VAULT_AAD_LEN PM_VAULT_HEADER_SIZE
#define PM_VAULT_VERSION_MAJOR_SUPPORTED 1u
#define PM_VAULT_KDF_BLOCK_VERSION_MAJOR 1u
#define PM_VAULT_KDF_BLOCK_VERSION_MINOR 0u

static const uint8_t PM_VAULT_MAGIC[PM_VAULT_MAGIC_SIZE] = {
    0x50,
    0x4D,
    0x56,
    0x4C,
    0x54,
    0x00,
    0x01,
    0x00,
};

static void store16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
}

static void store32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
    p[2] = (uint8_t)((v >> 16) & 0xFFu);
    p[3] = (uint8_t)((v >> 24) & 0xFFu);
}

static void store64(uint8_t *p, uint64_t v)
{
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
    p[2] = (uint8_t)((v >> 16) & 0xFFu);
    p[3] = (uint8_t)((v >> 24) & 0xFFu);
    p[4] = (uint8_t)((v >> 32) & 0xFFu);
    p[5] = (uint8_t)((v >> 40) & 0xFFu);
    p[6] = (uint8_t)((v >> 48) & 0xFFu);
    p[7] = (uint8_t)((v >> 56) & 0xFFu);
}

static uint16_t load16(const uint8_t *p)
{
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t load32(const uint8_t *p)
{
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static uint64_t load64(const uint8_t *p)
{
    return (uint64_t)p[0] |
           ((uint64_t)p[1] << 8) |
           ((uint64_t)p[2] << 16) |
           ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) |
           ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) |
           ((uint64_t)p[7] << 56);
}

static uint32_t crc32_bytes(const uint8_t *data, size_t len)
{
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++)
    {
        crc ^= (uint32_t)data[i];
        for (int b = 0; b < 8; b++)
        {
            uint32_t mask = (uint32_t)-(int32_t)(crc & 1u);
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }
    return ~crc;
}

static void header_prepare_authenticated_view(uint8_t dst[PM_VAULT_HEADER_SIZE],
                                              const uint8_t src[PM_VAULT_HEADER_SIZE])
{
    memcpy(dst, src, PM_VAULT_HEADER_SIZE);
    memset(dst + PM_VAULT_GCM_TAG_OFFSET, 0, PM_VAULT_GCM_TAG_SIZE);
}

static uint32_t header_crc32_authenticated(const uint8_t header[PM_VAULT_HEADER_SIZE])
{
    uint8_t auth_header[PM_VAULT_HEADER_SIZE];

    header_prepare_authenticated_view(auth_header, header);
    store32(auth_header + PM_VAULT_HEADER_CRC_OFFSET, 0u);
    return crc32_bytes(auth_header, PM_VAULT_AAD_LEN);
}

static void composite_mode_from_flags(uint32_t flags, pm_composite_mode_t *mode)
{
    memset(mode, 0, sizeof(*mode));
    mode->use_password = (flags & (1u << 0)) != 0u;
    mode->use_biometric = (flags & (1u << 1)) != 0u;
    mode->use_keyfile = (flags & (1u << 2)) != 0u;
    mode->use_yubikey = (flags & (1u << 3)) != 0u;
}

static bool composite_modes_equal(const pm_composite_mode_t *a,
                                  const pm_composite_mode_t *b)
{
    return a->use_password == b->use_password &&
           a->use_biometric == b->use_biometric &&
           a->use_keyfile == b->use_keyfile &&
           a->use_yubikey == b->use_yubikey;
}

static pm_error_t composite_mode_from_enum(uint16_t raw, pm_composite_mode_t *mode)
{
    memset(mode, 0, sizeof(*mode));

    switch (raw)
    {
    case 0u:
        mode->use_password = true;
        return PM_OK;
    case 1u:
        mode->use_biometric = true;
        return PM_OK;
    case 2u:
        mode->use_password = true;
        mode->use_biometric = true;
        return PM_OK;
    case 3u:
        mode->use_password = true;
        mode->use_keyfile = true;
        return PM_OK;
    case 4u:
        mode->use_password = true;
        mode->use_yubikey = true;
        return PM_OK;
    case 5u:
        mode->use_password = true;
        mode->use_biometric = true;
        mode->use_keyfile = true;
        return PM_OK;
    case 6u:
        mode->use_password = true;
        mode->use_biometric = true;
        mode->use_yubikey = true;
        return PM_OK;
    case 7u:
        mode->use_password = true;
        mode->use_keyfile = true;
        mode->use_yubikey = true;
        return PM_OK;
    case 8u:
        mode->use_password = true;
        mode->use_biometric = true;
        mode->use_keyfile = true;
        mode->use_yubikey = true;
        return PM_OK;
    case 9u:
        mode->use_keyfile = true;
        return PM_OK;
    case 10u:
        mode->use_yubikey = true;
        return PM_OK;
    case 11u:
        mode->use_biometric = true;
        mode->use_keyfile = true;
        return PM_OK;
    case 12u:
        mode->use_biometric = true;
        mode->use_yubikey = true;
        return PM_OK;
    case 13u:
        mode->use_keyfile = true;
        mode->use_yubikey = true;
        return PM_OK;
    case 14u:
        mode->use_biometric = true;
        mode->use_keyfile = true;
        mode->use_yubikey = true;
        return PM_OK;
    default:
        return PM_ERR_FORMAT;
    }
}

static pm_error_t parse_kdf_block_metadata(const uint8_t *kdf_block,
                                           size_t kdf_len,
                                           pm_vault_format_params_t *params,
                                           pm_composite_mode_t *mode)
{
    const uint8_t *p;
    const uint8_t *end;
    uint32_t tlv_count;
    bool have_composite_mode = false;
    pm_composite_mode_t flags_mode;

    if (!kdf_block || !params || !mode)
    {
        return PM_ERR_INVALID_PARAM;
    }

    if (kdf_len < 8u)
    {
        return PM_ERR_FORMAT;
    }

    composite_mode_from_flags(params->flags, &flags_mode);

    p = kdf_block;
    end = kdf_block + kdf_len;

    if (load16(p + 0u) != PM_VAULT_KDF_BLOCK_VERSION_MAJOR ||
        load16(p + 2u) != PM_VAULT_KDF_BLOCK_VERSION_MINOR)
    {
        return PM_ERR_FORMAT_VERSION;
    }

    tlv_count = load32(p + 4u);
    p += 8u;

    for (uint32_t i = 0; i < tlv_count; i++)
    {
        uint16_t type;
        uint32_t vlen;

        if ((size_t)(end - p) < 8u)
        {
            return PM_ERR_FORMAT;
        }

        type = load16(p + 0u);
        vlen = load32(p + 4u);
        p += 8u;

        if ((size_t)(end - p) < vlen)
        {
            return PM_ERR_FORMAT;
        }

        switch (type)
        {
        case 0x0001u:
            if (vlen != 4u)
            {
                return PM_ERR_FORMAT;
            }
            params->argon2.t_cost = load32(p);
            break;
        case 0x0002u:
            if (vlen != 4u)
            {
                return PM_ERR_FORMAT;
            }
            params->argon2.m_cost_kib = load32(p);
            break;
        case 0x0003u:
            if (vlen != 4u)
            {
                return PM_ERR_FORMAT;
            }
            params->argon2.parallelism = load32(p);
            break;
        case 0x0004u:
            if (vlen != 4u || load32(p) != PM_KDF_KEY_SIZE)
            {
                return PM_ERR_FORMAT;
            }
            break;
        case 0x0005u:
            if (vlen != 4u)
            {
                return PM_ERR_FORMAT;
            }
            params->argon2.version = load32(p);
            break;
        case 0x0010u:
            if (vlen != 2u)
            {
                return PM_ERR_FORMAT;
            }
            params->composite_mode = load16(p);
            have_composite_mode = true;
            {
                pm_error_t rc = composite_mode_from_enum(params->composite_mode, mode);
                if (rc != PM_OK)
                {
                    return rc;
                }
            }
            break;
        default:
            break;
        }

        p += vlen;
    }

    if (have_composite_mode && !composite_modes_equal(&flags_mode, mode))
    {
        return PM_ERR_FORMAT;
    }

    return pm_argon2id_validate_params(&params->argon2);
}

static pm_error_t build_kdf_block(const pm_vault_format_params_t *params,
                                  uint8_t **out,
                                  size_t *out_len)
{
    const uint32_t tlv_count = 6u;
    const size_t tlv_bytes = (5u * (2u + 2u + 4u + 4u)) +
                             (2u + 2u + 4u + 2u);
    const size_t total = 2u + 2u + 4u + tlv_bytes;

    uint8_t *buf = calloc(1, total);
    if (!buf)
    {
        return PM_ERR_NOMEM;
    }

    uint8_t *p = buf;
    store16(p, PM_VAULT_KDF_BLOCK_VERSION_MAJOR);
    p += 2;
    store16(p, PM_VAULT_KDF_BLOCK_VERSION_MINOR);
    p += 2;
    store32(p, tlv_count);
    p += 4;

    /* t_cost */
    store16(p, 0x0001u);
    p += 2;
    store16(p, 0x0000u);
    p += 2;
    store32(p, 4u);
    p += 4;
    store32(p, params->argon2.t_cost);
    p += 4;

    /* m_cost_kib */
    store16(p, 0x0002u);
    p += 2;
    store16(p, 0x0000u);
    p += 2;
    store32(p, 4u);
    p += 4;
    store32(p, params->argon2.m_cost_kib);
    p += 4;

    /* parallelism */
    store16(p, 0x0003u);
    p += 2;
    store16(p, 0x0000u);
    p += 2;
    store32(p, 4u);
    p += 4;
    store32(p, params->argon2.parallelism);
    p += 4;

    /* output_len */
    store16(p, 0x0004u);
    p += 2;
    store16(p, 0x0000u);
    p += 2;
    store32(p, 4u);
    p += 4;
    store32(p, PM_KDF_KEY_SIZE);
    p += 4;

    /* version */
    store16(p, 0x0005u);
    p += 2;
    store16(p, 0x0000u);
    p += 2;
    store32(p, 4u);
    p += 4;
    store32(p, params->argon2.version);
    p += 4;

    /* composite_mode */
    store16(p, 0x0010u);
    p += 2;
    store16(p, 0x0000u);
    p += 2;
    store32(p, 2u);
    p += 4;
    store16(p, params->composite_mode);
    p += 2;

    *out = buf;
    *out_len = total;
    return PM_OK;
}

static pm_error_t derive_hmac_key(const uint8_t master_key[32],
                                  const uint8_t salt[PM_VAULT_SALT_SIZE],
                                  uint8_t out_hmac_key[32])
{
    static const uint8_t info[] = {
        'P', 'M', 'V', 'L', 'T', '-', 'H', 'M', 'A', 'C', '-', 'v', '1'};

    if (bio_hkdf_sha256(salt, PM_VAULT_SALT_SIZE,
                        master_key, 32,
                        info, sizeof(info),
                        out_hmac_key, 32) != BIO_OK)
    {
        return PM_ERR_KDF;
    }

    return PM_OK;
}

void pm_vault_format_defaults(pm_vault_format_params_t *params)
{
    if (!params)
    {
        return;
    }

    memset(params, 0, sizeof(*params));
    params->version_major = 1u;
    params->version_minor = 0u;
    params->flags = (1u << 0);
    params->argon2.t_cost = 3u;
    params->argon2.m_cost_kib = 65536u;
    params->argon2.parallelism = 1u;
    params->argon2.version = 0x13u;
    params->composite_mode = 0u;
}

pm_error_t pm_vault_serialize(const pm_vault_write_request_t *req,
                              uint8_t **out_blob,
                              size_t *out_blob_len)
{
    pm_error_t rc;
    uint8_t *kdf_block = NULL;
    size_t kdf_len = 0;
    uint8_t header[PM_VAULT_HEADER_SIZE];
    uint8_t aad_header[PM_VAULT_HEADER_SIZE];
    uint8_t hmac_key[32];
    uint8_t *ciphertext = NULL;
    uint8_t *blob = NULL;

    if (!req || !out_blob || !out_blob_len ||
        !req->master_key || !req->payload || req->payload_len == 0)
    {
        return PM_ERR_INVALID_PARAM;
    }

    if (bio_crypto_init() != BIO_OK)
    {
        return PM_ERR_CRYPTO;
    }

    *out_blob = NULL;
    *out_blob_len = 0;

    if (req->params.version_major != PM_VAULT_VERSION_MAJOR_SUPPORTED)
    {
        return PM_ERR_FORMAT_VERSION;
    }

    pm_argon2_params_t argon = req->params.argon2;
    rc = pm_argon2id_validate_params(&argon);
    if (rc != PM_OK)
    {
        return rc;
    }

    pm_composite_mode_t flags_mode;
    pm_composite_mode_t enum_mode;
    composite_mode_from_flags(req->params.flags, &flags_mode);
    rc = composite_mode_from_enum(req->params.composite_mode, &enum_mode);
    if (rc != PM_OK)
    {
        return rc;
    }
    if (!composite_modes_equal(&flags_mode, &enum_mode))
    {
        return PM_ERR_FORMAT;
    }

    rc = build_kdf_block(&req->params, &kdf_block, &kdf_len);
    if (rc != PM_OK)
    {
        return rc;
    }

    memset(header, 0, sizeof(header));
    memcpy(header + 0x00, PM_VAULT_MAGIC, PM_VAULT_MAGIC_SIZE);
    header[0x08] = req->params.version_major;
    header[0x09] = req->params.version_minor;
    store16(header + 0x0A, PM_VAULT_HEADER_SIZE);
    store32(header + 0x0C, req->params.flags);
    store64(header + 0x10, req->params.file_sequence);
    store32(header + 0x18, 0u); /* placeholder crc */
    store16(header + 0x1C, PM_VAULT_KDF_ALG_ARGON2ID);
    store16(header + 0x1E, PM_VAULT_ENC_ALG_AES256_GCM);
    store16(header + 0x20, PM_VAULT_PAYLOAD_CODEC_CBOR);
    store16(header + 0x22, 0u);
    store32(header + 0x24, (uint32_t)kdf_len);
    store64(header + 0x28, (uint64_t)req->payload_len);

    if (req->has_salt)
    {
        memcpy(header + 0x30, req->salt, PM_VAULT_SALT_SIZE);
    }
    else
    {
        if (bio_random_bytes(header + 0x30, PM_VAULT_SALT_SIZE) != BIO_OK)
        {
            free(kdf_block);
            return PM_ERR_CRYPTO;
        }
    }

    if (req->has_iv)
    {
        memcpy(header + 0x50, req->iv, PM_VAULT_IV_SIZE);
    }
    else
    {
        if (bio_random_bytes(header + 0x50, PM_VAULT_IV_SIZE) != BIO_OK)
        {
            free(kdf_block);
            return PM_ERR_CRYPTO;
        }
    }

    store32(header + 0x5C, PM_VAULT_AAD_LEN);
    store32(header + PM_VAULT_HEADER_CRC_OFFSET,
            header_crc32_authenticated(header));
    header_prepare_authenticated_view(aad_header, header);

    ciphertext = malloc(req->payload_len);
    if (!ciphertext)
    {
        free(kdf_block);
        return PM_ERR_NOMEM;
    }

    if (bio_aes256_gcm_seal(req->master_key,
                            header + 0x50,
                            aad_header,
                            PM_VAULT_AAD_LEN,
                            req->payload,
                            req->payload_len,
                            ciphertext,
                            header + PM_VAULT_GCM_TAG_OFFSET) != BIO_OK)
    {
        free(kdf_block);
        free(ciphertext);
        return PM_ERR_CRYPTO;
    }

    rc = derive_hmac_key(req->master_key, header + 0x30, hmac_key);
    if (rc != PM_OK)
    {
        free(kdf_block);
        free(ciphertext);
        return rc;
    }

    size_t total_len = PM_VAULT_HEADER_SIZE + kdf_len + req->payload_len + PM_VAULT_HMAC_SIZE;
    blob = malloc(total_len);
    if (!blob)
    {
        bio_secure_wipe(hmac_key, sizeof(hmac_key));
        free(kdf_block);
        free(ciphertext);
        return PM_ERR_NOMEM;
    }

    memcpy(blob, header, PM_VAULT_HEADER_SIZE);
    memcpy(blob + PM_VAULT_HEADER_SIZE, kdf_block, kdf_len);
    memcpy(blob + PM_VAULT_HEADER_SIZE + kdf_len, ciphertext, req->payload_len);

    if (bio_hmac_sha256(hmac_key, sizeof(hmac_key),
                        blob, PM_VAULT_HEADER_SIZE + kdf_len + req->payload_len,
                        blob + PM_VAULT_HEADER_SIZE + kdf_len + req->payload_len) != BIO_OK)
    {
        bio_secure_wipe(hmac_key, sizeof(hmac_key));
        free(kdf_block);
        free(ciphertext);
        free(blob);
        return PM_ERR_CRYPTO;
    }

    bio_secure_wipe(hmac_key, sizeof(hmac_key));
    free(kdf_block);
    free(ciphertext);

    *out_blob = blob;
    *out_blob_len = total_len;
    return PM_OK;
}

pm_error_t pm_vault_parse_metadata(const uint8_t *blob,
                                   size_t blob_len,
                                   pm_vault_metadata_t *out)
{
    const uint8_t *header;
    uint32_t header_size;
    uint32_t stored_crc;
    uint32_t calc_crc;
    uint32_t kdf_len;
    uint64_t payload_len64;
    size_t payload_len;

    if (!blob || !out)
    {
        return PM_ERR_INVALID_PARAM;
    }

    memset(out, 0, sizeof(*out));

    if (blob_len < PM_VAULT_HEADER_SIZE + PM_VAULT_HMAC_SIZE)
    {
        return PM_ERR_FORMAT;
    }

    header = blob;

    if (memcmp(header, PM_VAULT_MAGIC, PM_VAULT_MAGIC_SIZE) != 0)
    {
        return PM_ERR_FORMAT_MAGIC;
    }

    header_size = load16(header + 0x0A);
    if (header_size != PM_VAULT_HEADER_SIZE)
    {
        return PM_ERR_FORMAT_VERSION;
    }

    stored_crc = load32(header + PM_VAULT_HEADER_CRC_OFFSET);
    calc_crc = header_crc32_authenticated(header);
    if (stored_crc != calc_crc)
    {
        return PM_ERR_FORMAT_INTEGRITY;
    }

    if (load16(header + 0x1C) != PM_VAULT_KDF_ALG_ARGON2ID ||
        load16(header + 0x1E) != PM_VAULT_ENC_ALG_AES256_GCM ||
        load16(header + 0x20) != PM_VAULT_PAYLOAD_CODEC_CBOR)
    {
        return PM_ERR_FORMAT_VERSION;
    }

    if (load32(header + 0x5C) != PM_VAULT_AAD_LEN)
    {
        return PM_ERR_FORMAT;
    }

    kdf_len = load32(header + 0x24);
    payload_len64 = load64(header + 0x28);
    if (payload_len64 > SIZE_MAX)
    {
        return PM_ERR_FORMAT;
    }
    payload_len = (size_t)payload_len64;

    if (PM_VAULT_HEADER_SIZE + (size_t)kdf_len + payload_len + PM_VAULT_HMAC_SIZE != blob_len)
    {
        return PM_ERR_FORMAT;
    }

    out->params.version_major = header[0x08];
    out->params.version_minor = header[0x09];
    if (out->params.version_major != PM_VAULT_VERSION_MAJOR_SUPPORTED)
    {
        return PM_ERR_FORMAT_VERSION;
    }
    out->params.flags = load32(header + 0x0C);
    out->params.file_sequence = load64(header + 0x10);
    out->params.argon2.t_cost = 3u;
    out->params.argon2.m_cost_kib = 65536u;
    out->params.argon2.parallelism = 1u;
    out->params.argon2.version = 0x13u;
    out->params.composite_mode = 0u;
    composite_mode_from_flags(out->params.flags, &out->mode);
    out->kdf_block_len = kdf_len;
    out->payload_len = payload_len;
    memcpy(out->salt, header + 0x30, PM_VAULT_SALT_SIZE);
    memcpy(out->iv, header + 0x50, PM_VAULT_IV_SIZE);

    return parse_kdf_block_metadata(blob + PM_VAULT_HEADER_SIZE,
                                    kdf_len,
                                    &out->params,
                                    &out->mode);
}

pm_error_t pm_vault_deserialize(const uint8_t *blob,
                                size_t blob_len,
                                const uint8_t master_key[32],
                                pm_vault_read_result_t *out)
{
    uint8_t header[PM_VAULT_HEADER_SIZE];
    uint8_t aad_header[PM_VAULT_HEADER_SIZE];
    uint8_t hmac_key[32];
    uint8_t expected_hmac[32];
    pm_vault_metadata_t meta;
    const uint8_t *kdf_block;
    const uint8_t *ciphertext;
    const uint8_t *hmac_tail;

    if (!blob || !master_key || !out)
    {
        return PM_ERR_INVALID_PARAM;
    }

    if (bio_crypto_init() != BIO_OK)
    {
        return PM_ERR_CRYPTO;
    }

    memset(out, 0, sizeof(*out));

    pm_error_t rc = pm_vault_parse_metadata(blob, blob_len, &meta);
    if (rc != PM_OK)
    {
        return rc;
    }

    memcpy(header, blob, PM_VAULT_HEADER_SIZE);

    kdf_block = blob + PM_VAULT_HEADER_SIZE;
    ciphertext = kdf_block + meta.kdf_block_len;
    hmac_tail = ciphertext + meta.payload_len;

    rc = derive_hmac_key(master_key, header + 0x30, hmac_key);
    if (rc != PM_OK)
    {
        return rc;
    }

    if (bio_hmac_sha256(hmac_key, sizeof(hmac_key),
                        blob, blob_len - PM_VAULT_HMAC_SIZE,
                        expected_hmac) != BIO_OK)
    {
        bio_secure_wipe(hmac_key, sizeof(hmac_key));
        return PM_ERR_CRYPTO;
    }
    bio_secure_wipe(hmac_key, sizeof(hmac_key));

    if (bio_constant_time_compare(expected_hmac, hmac_tail, sizeof(expected_hmac)) != 0)
    {
        bio_secure_wipe(expected_hmac, sizeof(expected_hmac));
        return PM_ERR_FORMAT_INTEGRITY;
    }
    bio_secure_wipe(expected_hmac, sizeof(expected_hmac));

    out->payload = malloc(meta.payload_len);
    if (!out->payload)
    {
        return PM_ERR_NOMEM;
    }

    header_prepare_authenticated_view(aad_header, header);

    if (bio_aes256_gcm_open(master_key,
                            header + 0x50,
                            aad_header,
                            PM_VAULT_AAD_LEN,
                            ciphertext,
                            meta.payload_len,
                            header + PM_VAULT_GCM_TAG_OFFSET,
                            out->payload) != BIO_OK)
    {
        free(out->payload);
        out->payload = NULL;
        return PM_ERR_AEAD_TAG;
    }

    out->payload_len = meta.payload_len;
    out->params = meta.params;
    memcpy(out->salt, meta.salt, PM_VAULT_SALT_SIZE);
    memcpy(out->iv, meta.iv, PM_VAULT_IV_SIZE);

    return PM_OK;
}

void pm_vault_read_result_free(pm_vault_read_result_t *res)
{
    if (!res)
    {
        return;
    }

    if (res->payload)
    {
        pm_secure_zero(res->payload, res->payload_len);
        free(res->payload);
        res->payload = NULL;
    }
    res->payload_len = 0;
    memset(&res->params, 0, sizeof(res->params));
    memset(res->salt, 0, sizeof(res->salt));
    memset(res->iv, 0, sizeof(res->iv));
}
