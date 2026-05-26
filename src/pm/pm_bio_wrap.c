/*
 * pm_bio_wrap.c - TPM-backed biometric vault wrapping-key helpers
 *
 * Copyright (C) 2026 Hiya Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "pm/pm_bio_wrap.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "crypto/bio_crypto.h"
#include "pm/pm_secure_mem.h"
#include "tpm/bio_tpm.h"

#define PM_BIO_WRAP_HEADER_SIZE 32u

static const uint8_t k_pm_bio_wrap_magic[8] = {'P', 'M', 'B', 'W', 'R', 'A', 'P', '\0'};

static uint16_t load_le16(const uint8_t *p)
{
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t load_le32(const uint8_t *p)
{
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static void store_le16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
}

static void store_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
    p[2] = (uint8_t)((v >> 16) & 0xFFu);
    p[3] = (uint8_t)((v >> 24) & 0xFFu);
}

static pm_error_t map_bio_error(int rc)
{
    switch (rc)
    {
    case BIO_OK:
        return PM_OK;
    case BIO_ERR_NOMEM:
        return PM_ERR_NOMEM;
    case BIO_ERR_INVALID_PARAM:
        return PM_ERR_INVALID_PARAM;
    case BIO_ERR_NOT_FOUND:
        return PM_ERR_NOT_FOUND;
    case BIO_ERR_PERMISSION:
        return PM_ERR_PERMISSION;
    case BIO_ERR_TIMEOUT:
        return PM_ERR_TIMEOUT;
    case BIO_ERR_IO:
        return PM_ERR_IO;
    case BIO_ERR_CRYPTO_INIT:
    case BIO_ERR_CRYPTO_RANDOM:
    case BIO_ERR_CRYPTO_HASH:
    case BIO_ERR_CRYPTO_MAC:
    case BIO_ERR_CRYPTO_ENCRYPT:
    case BIO_ERR_CRYPTO_DECRYPT:
    case BIO_ERR_CRYPTO_SIGN:
    case BIO_ERR_CRYPTO_VERIFY:
    case BIO_ERR_CRYPTO_KEYGEN:
    case BIO_ERR_CRYPTO_TAG_MISMATCH:
        return PM_ERR_CRYPTO;
    case BIO_ERR_TPM_OPEN:
    case BIO_ERR_TPM_COMMAND:
    case BIO_ERR_TPM_RESPONSE:
    case BIO_ERR_TPM_AUTH:
    case BIO_ERR_TPM_SEALED:
    case BIO_ERR_TPM_PCR:
    case BIO_ERR_TPM_HIERARCHY:
    case BIO_ERR_TPM_HANDLE:
        return PM_ERR_TPM;
    default:
        return PM_ERR_BIO;
    }
}

static pm_error_t read_file_all(const char *path, uint8_t **out, size_t *out_len)
{
    struct stat st;
    uint8_t *buf = NULL;
    FILE *f = NULL;

    if (!path || !out || !out_len)
    {
        return PM_ERR_INVALID_PARAM;
    }

    *out = NULL;
    *out_len = 0;

    if (stat(path, &st) != 0)
    {
        return errno == ENOENT ? PM_ERR_NOT_FOUND : PM_ERR_IO;
    }

    if (st.st_size <= 0)
    {
        return PM_ERR_FORMAT;
    }

    if ((uint64_t)st.st_size > SIZE_MAX)
    {
        return PM_ERR_IO;
    }

    buf = malloc((size_t)st.st_size);
    if (!buf)
    {
        return PM_ERR_NOMEM;
    }

    f = fopen(path, "rb");
    if (!f)
    {
        free(buf);
        return PM_ERR_IO;
    }

    if (fread(buf, 1, (size_t)st.st_size, f) != (size_t)st.st_size)
    {
        fclose(f);
        free(buf);
        return PM_ERR_IO;
    }

    fclose(f);
    *out = buf;
    *out_len = (size_t)st.st_size;
    return PM_OK;
}

static pm_error_t write_file_atomic(const char *path, const uint8_t *data, size_t len)
{
    char tmp_path[PATH_MAX];
    int fd = -1;
    size_t off = 0;

    if (!path || !data || len == 0)
    {
        return PM_ERR_INVALID_PARAM;
    }

    if (snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", path) >= (int)sizeof(tmp_path))
    {
        return PM_ERR_IO;
    }

    fd = open(tmp_path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
    if (fd < 0)
    {
        return PM_ERR_IO;
    }

    while (off < len)
    {
        ssize_t w = write(fd, data + off, len - off);
        if (w < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            close(fd);
            unlink(tmp_path);
            return PM_ERR_IO;
        }
        off += (size_t)w;
    }

    if (fsync(fd) != 0)
    {
        close(fd);
        unlink(tmp_path);
        return PM_ERR_IO;
    }

    close(fd);

    if (rename(tmp_path, path) != 0)
    {
        unlink(tmp_path);
        return PM_ERR_IO;
    }

    return PM_OK;
}

static pm_error_t validate_params(const pm_bio_wrap_params_t *params)
{
    if (!params)
    {
        return PM_ERR_INVALID_PARAM;
    }

    if (params->pcr_index > 23u)
    {
        return PM_ERR_INVALID_PARAM;
    }

    return PM_OK;
}

void pm_bio_wrap_params_defaults(pm_bio_wrap_params_t *params)
{
    if (!params)
    {
        return;
    }

    params->require_tpm = false;
    params->pcr_index = PM_BIO_WRAP_DEFAULT_PCR;
}

pm_error_t pm_bio_wrap_generate(uint8_t wrapping_key[PM_BIO_WRAP_KEY_SIZE])
{
    if (!wrapping_key)
    {
        return PM_ERR_INVALID_PARAM;
    }

    if (bio_crypto_init() != BIO_OK)
    {
        return PM_ERR_CRYPTO;
    }

    return map_bio_error(bio_random_bytes(wrapping_key, PM_BIO_WRAP_KEY_SIZE));
}

pm_error_t pm_bio_wrap_sidecar_path(const char *vault_path,
                                    char *out_path,
                                    size_t out_path_len)
{
    if (!vault_path || !out_path || out_path_len == 0)
    {
        return PM_ERR_INVALID_PARAM;
    }

    if (snprintf(out_path, out_path_len, "%s.tpmwrap", vault_path) >= (int)out_path_len)
    {
        return PM_ERR_IO;
    }

    return PM_OK;
}

pm_error_t pm_bio_wrap_write_sidecar(const char *vault_path,
                                     const pm_bio_wrap_params_t *params,
                                     const uint8_t *sealed_blob,
                                     size_t sealed_blob_len)
{
    char path[PATH_MAX];
    uint8_t *blob = NULL;
    pm_error_t rc;

    if (!vault_path || !sealed_blob || sealed_blob_len == 0 || sealed_blob_len > UINT32_MAX)
    {
        return PM_ERR_INVALID_PARAM;
    }

    rc = validate_params(params);
    if (rc != PM_OK)
    {
        return rc;
    }

    rc = pm_bio_wrap_sidecar_path(vault_path, path, sizeof(path));
    if (rc != PM_OK)
    {
        return rc;
    }

    blob = calloc(1, PM_BIO_WRAP_HEADER_SIZE + sealed_blob_len);
    if (!blob)
    {
        return PM_ERR_NOMEM;
    }

    memcpy(blob, k_pm_bio_wrap_magic, sizeof(k_pm_bio_wrap_magic));
    blob[8] = 1u;
    blob[9] = 0u;
    store_le16(blob + 10, params->require_tpm ? 1u : 0u);
    store_le32(blob + 12, params->pcr_index);
    store_le32(blob + 16, (uint32_t)sealed_blob_len);
    memcpy(blob + PM_BIO_WRAP_HEADER_SIZE, sealed_blob, sealed_blob_len);

    rc = write_file_atomic(path, blob, PM_BIO_WRAP_HEADER_SIZE + sealed_blob_len);
    free(blob);
    return rc;
}

pm_error_t pm_bio_wrap_read_sidecar(const char *vault_path,
                                    pm_bio_wrap_params_t *out_params,
                                    uint8_t **out_sealed_blob,
                                    size_t *out_sealed_blob_len)
{
    char path[PATH_MAX];
    uint8_t *blob = NULL;
    size_t blob_len = 0;
    uint32_t flags;
    uint32_t pcr_index;
    uint32_t sealed_blob_len;
    uint8_t *sealed_blob = NULL;
    pm_error_t rc;

    if (!vault_path || !out_params || !out_sealed_blob || !out_sealed_blob_len)
    {
        return PM_ERR_INVALID_PARAM;
    }

    *out_sealed_blob = NULL;
    *out_sealed_blob_len = 0;
    pm_bio_wrap_params_defaults(out_params);

    rc = pm_bio_wrap_sidecar_path(vault_path, path, sizeof(path));
    if (rc != PM_OK)
    {
        return rc;
    }

    rc = read_file_all(path, &blob, &blob_len);
    if (rc != PM_OK)
    {
        return rc;
    }

    if (blob_len < PM_BIO_WRAP_HEADER_SIZE)
    {
        free(blob);
        return PM_ERR_FORMAT;
    }

    if (memcmp(blob, k_pm_bio_wrap_magic, sizeof(k_pm_bio_wrap_magic)) != 0)
    {
        free(blob);
        return PM_ERR_FORMAT_MAGIC;
    }

    if (blob[8] != 1u || blob[9] != 0u)
    {
        free(blob);
        return PM_ERR_FORMAT_VERSION;
    }

    flags = load_le16(blob + 10);
    if ((flags & ~1u) != 0u)
    {
        free(blob);
        return PM_ERR_FORMAT;
    }

    pcr_index = load_le32(blob + 12);
    sealed_blob_len = load_le32(blob + 16);

    if (pcr_index > 23u ||
        sealed_blob_len == 0u ||
        blob_len != PM_BIO_WRAP_HEADER_SIZE + (size_t)sealed_blob_len)
    {
        free(blob);
        return PM_ERR_FORMAT;
    }

    sealed_blob = malloc(sealed_blob_len);
    if (!sealed_blob)
    {
        free(blob);
        return PM_ERR_NOMEM;
    }

    memcpy(sealed_blob, blob + PM_BIO_WRAP_HEADER_SIZE, sealed_blob_len);
    free(blob);

    out_params->require_tpm = (flags & 1u) != 0u;
    out_params->pcr_index = pcr_index;
    *out_sealed_blob = sealed_blob;
    *out_sealed_blob_len = sealed_blob_len;
    return PM_OK;
}

pm_error_t pm_bio_wrap_seal_to_tpm(const char *vault_path,
                                   const pm_bio_wrap_params_t *params,
                                   const uint8_t wrapping_key[PM_BIO_WRAP_KEY_SIZE])
{
    bio_tpm_ctx_t tpm;
    uint8_t sealed_blob[1024];
    size_t sealed_blob_len = sizeof(sealed_blob);
    pm_error_t rc;
    int bio_rc;

    if (!vault_path || !wrapping_key)
    {
        return PM_ERR_INVALID_PARAM;
    }

    rc = validate_params(params);
    if (rc != PM_OK)
    {
        return rc;
    }

    bio_rc = bio_tpm_init(&tpm, NULL);
    if (bio_rc != BIO_OK)
    {
        return map_bio_error(bio_rc);
    }

    bio_rc = bio_tpm_seal_for_user_pcr(&tpm,
                                       wrapping_key,
                                       PM_BIO_WRAP_KEY_SIZE,
                                       NULL,
                                       0,
                                       params->pcr_index,
                                       sealed_blob,
                                       &sealed_blob_len);
    bio_tpm_cleanup(&tpm);
    if (bio_rc != BIO_OK)
    {
        pm_secure_zero(sealed_blob, sizeof(sealed_blob));
        return map_bio_error(bio_rc);
    }

    rc = pm_bio_wrap_write_sidecar(vault_path, params, sealed_blob, sealed_blob_len);
    pm_secure_zero(sealed_blob, sizeof(sealed_blob));
    return rc;
}

pm_error_t pm_bio_wrap_unseal_from_tpm(const char *vault_path,
                                       pm_bio_wrap_params_t *out_params,
                                       uint8_t wrapping_key[PM_BIO_WRAP_KEY_SIZE])
{
    pm_bio_wrap_params_t params;
    bio_tpm_ctx_t tpm;
    uint8_t *sealed_blob = NULL;
    size_t sealed_blob_len = 0;
    size_t out_len = PM_BIO_WRAP_KEY_SIZE;
    pm_error_t rc;
    int bio_rc;

    if (!vault_path || !out_params || !wrapping_key)
    {
        return PM_ERR_INVALID_PARAM;
    }

    pm_secure_zero(wrapping_key, PM_BIO_WRAP_KEY_SIZE);
    pm_bio_wrap_params_defaults(out_params);

    rc = pm_bio_wrap_read_sidecar(vault_path, &params, &sealed_blob, &sealed_blob_len);
    if (rc != PM_OK)
    {
        return rc;
    }

    bio_rc = bio_tpm_init(&tpm, NULL);
    if (bio_rc != BIO_OK)
    {
        pm_secure_zero(sealed_blob, sealed_blob_len);
        free(sealed_blob);
        return map_bio_error(bio_rc);
    }

    bio_rc = bio_tpm_unseal_for_user_pcr(&tpm,
                                         sealed_blob,
                                         sealed_blob_len,
                                         NULL,
                                         0,
                                         params.pcr_index,
                                         wrapping_key,
                                         &out_len);
    bio_tpm_cleanup(&tpm);
    pm_secure_zero(sealed_blob, sealed_blob_len);
    free(sealed_blob);
    if (bio_rc != BIO_OK)
    {
        pm_secure_zero(wrapping_key, PM_BIO_WRAP_KEY_SIZE);
        return map_bio_error(bio_rc);
    }

    if (out_len != PM_BIO_WRAP_KEY_SIZE)
    {
        pm_secure_zero(wrapping_key, PM_BIO_WRAP_KEY_SIZE);
        return PM_ERR_FORMAT;
    }

    *out_params = params;
    return PM_OK;
}

pm_error_t pm_bio_wrap_unseal_vault_key(const char *vault_path,
                                        uint8_t wrapping_key[PM_BIO_WRAP_KEY_SIZE])
{
    pm_bio_wrap_params_t params;
    return pm_bio_wrap_unseal_from_tpm(vault_path, &params, wrapping_key);
}
