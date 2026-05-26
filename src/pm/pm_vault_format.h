/*
 * pm_vault_format.h - PM vault binary container format I/O
 *
 * Copyright (C) 2026 Hiya Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef PM_VAULT_FORMAT_H
#define PM_VAULT_FORMAT_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "pm/pm_errors.h"
#include "pm/pm_kdf.h"
#include "pm/pm_master_key.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define PM_VAULT_MAGIC_SIZE 8u
#define PM_VAULT_HEADER_SIZE 128u
#define PM_VAULT_HMAC_SIZE 32u
#define PM_VAULT_IV_SIZE 12u
#define PM_VAULT_GCM_TAG_SIZE 16u
#define PM_VAULT_SALT_SIZE 32u

#define PM_VAULT_KDF_ALG_ARGON2ID 0x0001u
#define PM_VAULT_ENC_ALG_AES256_GCM 0x0001u
#define PM_VAULT_PAYLOAD_CODEC_CBOR 0x0002u

    typedef struct
    {
        uint8_t version_major;
        uint8_t version_minor;
        uint32_t flags;
        uint64_t file_sequence;
        pm_argon2_params_t argon2;
        uint16_t composite_mode;
    } pm_vault_format_params_t;

    typedef struct
    {
        pm_vault_format_params_t params;
        const uint8_t *master_key;
        const uint8_t *payload;
        size_t payload_len;
        bool has_salt;
        uint8_t salt[PM_VAULT_SALT_SIZE];
        bool has_iv;
        uint8_t iv[PM_VAULT_IV_SIZE];
    } pm_vault_write_request_t;

    typedef struct
    {
        pm_vault_format_params_t params;
        pm_composite_mode_t mode;
        uint32_t kdf_block_len;
        size_t payload_len;
        uint8_t salt[PM_VAULT_SALT_SIZE];
        uint8_t iv[PM_VAULT_IV_SIZE];
    } pm_vault_metadata_t;

    typedef struct
    {
        pm_vault_format_params_t params;
        uint8_t salt[PM_VAULT_SALT_SIZE];
        uint8_t iv[PM_VAULT_IV_SIZE];
        uint8_t *payload;
        size_t payload_len;
    } pm_vault_read_result_t;

    void pm_vault_format_defaults(pm_vault_format_params_t *params);

    pm_error_t pm_vault_serialize(const pm_vault_write_request_t *req,
                                  uint8_t **out_blob,
                                  size_t *out_blob_len);

    pm_error_t pm_vault_parse_metadata(const uint8_t *blob,
                                       size_t blob_len,
                                       pm_vault_metadata_t *out);

    pm_error_t pm_vault_deserialize(const uint8_t *blob,
                                    size_t blob_len,
                                    const uint8_t master_key[32],
                                    pm_vault_read_result_t *out);

    void pm_vault_read_result_free(pm_vault_read_result_t *res);

#ifdef __cplusplus
}
#endif

#endif /* PM_VAULT_FORMAT_H */
