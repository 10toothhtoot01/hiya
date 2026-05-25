/*
 * pm_vault_store.c - Vault lifecycle and persistence manager
 *
 * Copyright (C) 2026 BioAuth Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "pm/pm_vault_store.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "crypto/bio_crypto.h"
#include "pm/pm_kdf.h"
#include "pm/pm_payload.h"
#include "pm/pm_secure_mem.h"
#include "pm/pm_tpm_wrapping.h"
#include "tpm/bio_tpm.h"

struct pm_vault_handle
{
    char path[PATH_MAX];
    pm_vault_format_params_t format;
    pm_composite_mode_t mode;

    bool locked;
    uint8_t *master_key;

    uint8_t salt[PM_VAULT_SALT_SIZE];

    uint8_t *payload;
    size_t payload_len;
};

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
        return PM_ERR_IO;
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

    size_t n = fread(buf, 1, (size_t)st.st_size, f);
    fclose(f);
    if (n != (size_t)st.st_size)
    {
        free(buf);
        return PM_ERR_IO;
    }

    *out = buf;
    *out_len = n;
    return PM_OK;
}

static pm_error_t write_file_atomic(const char *path, const uint8_t *data, size_t len)
{
    char tmp_path[PATH_MAX];
    int fd = -1;

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

    size_t off = 0;
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

static pm_error_t derive_master_key(const pm_vault_handle_t *h,
                                    const pm_unlock_factors_t *factors,
                                    uint8_t out_master[32])
{
    uint8_t k_pwd[32] = {0};
    const uint8_t *kpwd_ptr = NULL;
    const uint8_t *kbio_ptr = NULL;
    const uint8_t *kfile_ptr = NULL;
    const uint8_t *kyubi_ptr = NULL;

    if (!h || !factors || !out_master)
    {
        return PM_ERR_INVALID_PARAM;
    }

    if (h->mode.use_password)
    {
        if (!factors->password || factors->password_len == 0)
        {
            return PM_ERR_DENIED;
        }

        pm_error_t rc = pm_argon2id_derive(factors->password,
                                           factors->password_len,
                                           h->salt,
                                           &h->format.argon2,
                                           k_pwd);
        if (rc != PM_OK)
        {
            return rc;
        }

        kpwd_ptr = k_pwd;
    }

    if (h->mode.use_biometric)
    {
        if (!factors->has_wrapping_key)
        {
            bio_secure_wipe(k_pwd, sizeof(k_pwd));
            return PM_ERR_DENIED;
        }
        kbio_ptr = factors->wrapping_key;
    }

    if (h->mode.use_keyfile)
    {
        if (!factors->has_keyfile_hash)
        {
            bio_secure_wipe(k_pwd, sizeof(k_pwd));
            return PM_ERR_DENIED;
        }
        kfile_ptr = factors->keyfile_hash;
    }

    if (h->mode.use_yubikey)
    {
        bio_secure_wipe(k_pwd, sizeof(k_pwd));
        return PM_ERR_UNSUPPORTED;
    }

    pm_error_t rc = pm_master_key_derive(&h->mode,
                                         kpwd_ptr,
                                         kbio_ptr,
                                         kfile_ptr,
                                         kyubi_ptr,
                                         out_master);

    bio_secure_wipe(k_pwd, sizeof(k_pwd));
    return rc;
}

static void handle_free_payload(pm_vault_handle_t *h)
{
    if (h->payload)
    {
        pm_secure_zero(h->payload, h->payload_len);
        free(h->payload);
        h->payload = NULL;
    }
    h->payload_len = 0;
}

static pm_error_t validate_payload_blob(const uint8_t *payload, size_t payload_len)
{
    pm_payload_t decoded;
    pm_error_t rc;

    if (!payload || payload_len == 0)
    {
        return PM_ERR_INVALID_PARAM;
    }

    pm_payload_init(&decoded);
    rc = pm_payload_decode_cbor(payload, payload_len, &decoded);
    pm_payload_free(&decoded);
    return rc;
}

static uint32_t vault_flags_from_mode(const pm_composite_mode_t *mode)
{
    uint32_t flags = 0u;

    if (mode->use_password)
    {
        flags |= (1u << 0);
    }
    if (mode->use_biometric)
    {
        flags |= (1u << 1);
    }
    if (mode->use_keyfile)
    {
        flags |= (1u << 2);
    }
    if (mode->use_yubikey)
    {
        flags |= (1u << 3);
    }

    return flags;
}

static pm_error_t vault_composite_enum_from_mode(const pm_composite_mode_t *mode,
                                                 uint16_t *out_value)
{
    if (!mode || !out_value)
    {
        return PM_ERR_INVALID_PARAM;
    }

    if (mode->use_password && !mode->use_biometric &&
        !mode->use_keyfile && !mode->use_yubikey)
    {
        *out_value = 0u;
    }
    else if (!mode->use_password && mode->use_biometric &&
             !mode->use_keyfile && !mode->use_yubikey)
    {
        *out_value = 1u;
    }
    else if (mode->use_password && mode->use_biometric &&
             !mode->use_keyfile && !mode->use_yubikey)
    {
        *out_value = 2u;
    }
    else if (mode->use_password && !mode->use_biometric &&
             mode->use_keyfile && !mode->use_yubikey)
    {
        *out_value = 3u;
    }
    else if (mode->use_password && !mode->use_biometric &&
             !mode->use_keyfile && mode->use_yubikey)
    {
        *out_value = 4u;
    }
    else if (mode->use_password && mode->use_biometric &&
             mode->use_keyfile && !mode->use_yubikey)
    {
        *out_value = 5u;
    }
    else if (mode->use_password && mode->use_biometric &&
             !mode->use_keyfile && mode->use_yubikey)
    {
        *out_value = 6u;
    }
    else if (mode->use_password && !mode->use_biometric &&
             mode->use_keyfile && mode->use_yubikey)
    {
        *out_value = 7u;
    }
    else if (mode->use_password && mode->use_biometric &&
             mode->use_keyfile && mode->use_yubikey)
    {
        *out_value = 8u;
    }
    else if (!mode->use_password && !mode->use_biometric &&
             mode->use_keyfile && !mode->use_yubikey)
    {
        *out_value = 9u;
    }
    else if (!mode->use_password && !mode->use_biometric &&
             !mode->use_keyfile && mode->use_yubikey)
    {
        *out_value = 10u;
    }
    else if (!mode->use_password && mode->use_biometric &&
             mode->use_keyfile && !mode->use_yubikey)
    {
        *out_value = 11u;
    }
    else if (!mode->use_password && mode->use_biometric &&
             !mode->use_keyfile && mode->use_yubikey)
    {
        *out_value = 12u;
    }
    else if (!mode->use_password && !mode->use_biometric &&
             mode->use_keyfile && mode->use_yubikey)
    {
        *out_value = 13u;
    }
    else if (!mode->use_password && mode->use_biometric &&
             mode->use_keyfile && mode->use_yubikey)
    {
        *out_value = 14u;
    }
    else
    {
        return PM_ERR_UNSUPPORTED;
    }

    return PM_OK;
}

static uint64_t vault_initial_file_sequence(uint64_t requested)
{
    if (requested == 0u)
    {
        return 1u;
    }

    return requested;
}

pm_error_t pm_vault_create(const char *path,
                           const pm_vault_create_opts_t *opts,
                           pm_vault_handle_t **out)
{
    pm_vault_handle_t *h = NULL;
    uint8_t *blob = NULL;
    size_t blob_len = 0;
    uint8_t master_key[32];
    pm_unlock_factors_t factors;

    if (!path || !opts || !out ||
        !opts->initial_payload || opts->initial_payload_len == 0)
    {
        return PM_ERR_INVALID_PARAM;
    }

    pm_error_t rc = validate_payload_blob(opts->initial_payload,
                                          opts->initial_payload_len);
    if (rc != PM_OK)
    {
        return rc;
    }

    *out = NULL;

    h = calloc(1, sizeof(*h));
    if (!h)
    {
        return PM_ERR_NOMEM;
    }

    if (snprintf(h->path, sizeof(h->path), "%s", path) >= (int)sizeof(h->path))
    {
        free(h);
        return PM_ERR_IO;
    }

    h->format = opts->format;
    h->mode = opts->mode;
    h->format.file_sequence = vault_initial_file_sequence(h->format.file_sequence);
    h->format.flags = vault_flags_from_mode(&h->mode);

    rc = vault_composite_enum_from_mode(&h->mode,
                                        &h->format.composite_mode);
    if (rc != PM_OK)
    {
        free(h);
        return rc;
    }

    if (bio_crypto_init() != BIO_OK)
    {
        free(h);
        return PM_ERR_CRYPTO;
    }

    if (bio_random_bytes(h->salt, sizeof(h->salt)) != BIO_OK)
    {
        free(h);
        return PM_ERR_CRYPTO;
    }

    memset(&factors, 0, sizeof(factors));
    factors.password = opts->password;
    factors.password_len = opts->password_len;
    factors.has_wrapping_key = opts->has_wrapping_key;
    factors.has_keyfile_hash = opts->has_keyfile_hash;
    factors.has_yubikey_key = opts->has_yubikey_key;
    if (opts->has_wrapping_key)
    {
        memcpy(factors.wrapping_key, opts->wrapping_key, sizeof(factors.wrapping_key));
    }
    if (opts->has_keyfile_hash)
    {
        memcpy(factors.keyfile_hash, opts->keyfile_hash, sizeof(factors.keyfile_hash));
    }
    if (opts->has_yubikey_key)
    {
        memcpy(factors.yubikey_key, opts->yubikey_key, sizeof(factors.yubikey_key));
    }

    if ((h->mode.use_password && (!opts->password || opts->password_len == 0)) ||
        (h->mode.use_biometric && !opts->has_wrapping_key) ||
        (h->mode.use_keyfile && !opts->has_keyfile_hash) ||
        (h->mode.use_yubikey && !opts->has_yubikey_key))
    {
        bio_secure_wipe(&factors, sizeof(factors));
        free(h);
        return PM_ERR_INVALID_PARAM;
    }

    rc = derive_master_key(h, &factors, master_key);
    bio_secure_wipe(&factors, sizeof(factors));
    if (rc != PM_OK)
    {
        free(h);
        return rc;
    }

    pm_vault_write_request_t wreq = {
        .params = h->format,
        .master_key = master_key,
        .payload = opts->initial_payload,
        .payload_len = opts->initial_payload_len,
        .has_salt = true,
        .has_iv = false,
    };
    memcpy(wreq.salt, h->salt, sizeof(wreq.salt));

    rc = pm_vault_serialize(&wreq, &blob, &blob_len);
    bio_secure_wipe(master_key, sizeof(master_key));
    if (rc != PM_OK)
    {
        free(h);
        return rc;
    }

    rc = write_file_atomic(path, blob, blob_len);
    free(blob);
    if (rc != PM_OK)
    {
        free(h);
        return rc;
    }

    h->locked = true;
    *out = h;
    return PM_OK;
}

pm_error_t pm_vault_open(const char *path, pm_vault_handle_t **out)
{
    uint8_t *blob = NULL;
    size_t blob_len = 0;
    pm_vault_metadata_t meta;

    if (!path || !out)
    {
        return PM_ERR_INVALID_PARAM;
    }

    *out = NULL;

    pm_vault_handle_t *h = calloc(1, sizeof(*h));
    if (!h)
    {
        return PM_ERR_NOMEM;
    }

    if (snprintf(h->path, sizeof(h->path), "%s", path) >= (int)sizeof(h->path))
    {
        free(h);
        return PM_ERR_IO;
    }

    pm_error_t rc = read_file_all(path, &blob, &blob_len);
    if (rc != PM_OK)
    {
        free(h);
        return rc;
    }

    rc = pm_vault_parse_metadata(blob, blob_len, &meta);
    if (rc != PM_OK)
    {
        free(blob);
        free(h);
        return rc;
    }

    memcpy(h->salt, meta.salt, PM_VAULT_SALT_SIZE);
    h->format = meta.params;
    h->mode = meta.mode;

    free(blob);
    h->locked = true;
    *out = h;
    return PM_OK;
}

pm_error_t pm_vault_unlock(pm_vault_handle_t *h, const pm_unlock_factors_t *factors)
{
    uint8_t derived[32];
    uint8_t *blob = NULL;
    size_t blob_len = 0;
    pm_vault_read_result_t rr;

    if (!h || !factors)
    {
        return PM_ERR_INVALID_PARAM;
    }

    if (!h->locked)
    {
        return PM_OK;
    }

    pm_error_t rc = derive_master_key(h, factors, derived);
    if (rc != PM_OK)
    {
        return rc;
    }

    rc = read_file_all(h->path, &blob, &blob_len);
    if (rc != PM_OK)
    {
        bio_secure_wipe(derived, sizeof(derived));
        return rc;
    }

    rc = pm_vault_deserialize(blob, blob_len, derived, &rr);
    free(blob);
    if (rc != PM_OK)
    {
        bio_secure_wipe(derived, sizeof(derived));
        return rc;
    }

    rc = pm_secure_alloc(32, (void **)&h->master_key);
    if (rc != PM_OK)
    {
        pm_vault_read_result_free(&rr);
        bio_secure_wipe(derived, sizeof(derived));
        return rc;
    }

    memcpy(h->master_key, derived, 32);
    bio_secure_wipe(derived, sizeof(derived));

    handle_free_payload(h);
    h->payload = rr.payload;
    h->payload_len = rr.payload_len;
    rr.payload = NULL;
    rr.payload_len = 0;
    pm_vault_read_result_free(&rr);

    h->locked = false;
    return PM_OK;
}

pm_error_t pm_vault_lock(pm_vault_handle_t *h, pm_lock_reason_t reason)
{
    (void)reason;

    if (!h)
    {
        return PM_ERR_INVALID_PARAM;
    }

    if (h->master_key)
    {
        pm_secure_free(h->master_key, 32);
        h->master_key = NULL;
    }

    handle_free_payload(h);
    h->locked = true;
    return PM_OK;
}

pm_error_t pm_vault_save(pm_vault_handle_t *h)
{
    pm_vault_format_params_t save_format;

    if (!h)
    {
        return PM_ERR_INVALID_PARAM;
    }

    if (h->locked || !h->master_key)
    {
        return PM_ERR_LOCKED;
    }

    if (!h->payload || h->payload_len == 0)
    {
        return PM_ERR_STATE;
    }

    if (h->format.file_sequence == UINT64_MAX)
    {
        return PM_ERR_STATE;
    }

    save_format = h->format;
    save_format.file_sequence++;

    pm_vault_write_request_t req = {
        .params = save_format,
        .master_key = h->master_key,
        .payload = h->payload,
        .payload_len = h->payload_len,
        .has_salt = true,
        .has_iv = false,
    };
    memcpy(req.salt, h->salt, sizeof(req.salt));

    uint8_t *blob = NULL;
    size_t blob_len = 0;
    pm_error_t rc = pm_vault_serialize(&req, &blob, &blob_len);
    if (rc != PM_OK)
    {
        return rc;
    }

    rc = write_file_atomic(h->path, blob, blob_len);
    free(blob);
    if (rc == PM_OK)
    {
        h->format = save_format;
    }
    return rc;
}

bool pm_vault_is_locked(const pm_vault_handle_t *h)
{
    if (!h)
    {
        return true;
    }
    return h->locked;
}

pm_error_t pm_vault_get_mode(const pm_vault_handle_t *h,
                             pm_composite_mode_t *mode_out)
{
    if (!h || !mode_out)
    {
        return PM_ERR_INVALID_PARAM;
    }

    *mode_out = h->mode;
    return PM_OK;
}

pm_error_t pm_vault_get_payload(const pm_vault_handle_t *h,
                                const uint8_t **payload,
                                size_t *payload_len)
{
    if (!h || !payload || !payload_len)
    {
        return PM_ERR_INVALID_PARAM;
    }

    if (h->locked)
    {
        return PM_ERR_LOCKED;
    }

    *payload = h->payload;
    *payload_len = h->payload_len;
    return PM_OK;
}

pm_error_t pm_vault_set_payload(pm_vault_handle_t *h,
                                const uint8_t *payload,
                                size_t payload_len)
{
    uint8_t *copy = NULL;
    pm_error_t rc;

    if (!h || !payload || payload_len == 0)
    {
        return PM_ERR_INVALID_PARAM;
    }

    if (h->locked)
    {
        return PM_ERR_LOCKED;
    }

    rc = validate_payload_blob(payload, payload_len);
    if (rc != PM_OK)
    {
        return rc;
    }

    copy = malloc(payload_len);
    if (!copy)
    {
        return PM_ERR_NOMEM;
    }
    memcpy(copy, payload, payload_len);

    handle_free_payload(h);
    h->payload = copy;
    h->payload_len = payload_len;
    return PM_OK;
}

pm_error_t pm_vault_get_payload_model(const pm_vault_handle_t *h,
                                      pm_payload_t *out_payload)
{
    if (!h || !out_payload)
    {
        return PM_ERR_INVALID_PARAM;
    }

    if (h->locked)
    {
        return PM_ERR_LOCKED;
    }

    if (!h->payload || h->payload_len == 0)
    {
        return PM_ERR_STATE;
    }

    return pm_payload_decode_cbor(h->payload, h->payload_len, out_payload);
}

pm_error_t pm_vault_set_payload_model(pm_vault_handle_t *h,
                                      const pm_payload_t *payload)
{
    pm_error_t rc;
    uint8_t *encoded = NULL;
    size_t encoded_len = 0;

    if (!h || !payload)
    {
        return PM_ERR_INVALID_PARAM;
    }

    if (h->locked)
    {
        return PM_ERR_LOCKED;
    }

    rc = pm_payload_encode_cbor(payload, &encoded, &encoded_len);
    if (rc != PM_OK)
    {
        return rc;
    }

    rc = pm_vault_set_payload(h, encoded, encoded_len);
    free(encoded);
    return rc;
}

static pm_error_t build_tpm_sidecar_path(const char *vault_path, char *out, size_t out_size)
{
    size_t len;

    if (!vault_path || !out || out_size == 0)
    {
        return PM_ERR_INVALID_PARAM;
    }

    len = strlen(vault_path);
    if (len + 5 >= out_size)
    {
        return PM_ERR_NOMEM;
    }

    snprintf(out, out_size, "%s.tpm", vault_path);
    return PM_OK;
}

pm_error_t pm_vault_tpm_seal_wrapping_key(const char *vault_path,
                                          uint32_t pcr_index,
                                          uint8_t *key_out)
{
    bio_tpm_ctx_t tpm_ctx;
    uint8_t sealed_blob[PM_TPM_SEALED_BLOB_MAX];
    size_t sealed_len = PM_TPM_SEALED_BLOB_MAX;
    char sidecar_path[PATH_MAX];
    pm_error_t pm_rc;
    int tpm_rc;
    FILE *f = NULL;

    if (!vault_path || !key_out)
    {
        return PM_ERR_INVALID_PARAM;
    }

    pm_rc = build_tpm_sidecar_path(vault_path, sidecar_path, sizeof(sidecar_path));
    if (pm_rc != PM_OK)
    {
        return pm_rc;
    }

    tpm_rc = bio_tpm_init(&tpm_ctx, "/dev/tpmrm0");
    if (tpm_rc != BIO_OK)
    {
        return PM_ERR_TPM;
    }

    pm_rc = pm_tpm_generate_and_seal_wrapping_key(&tpm_ctx,
                                                  pcr_index,
                                                  sealed_blob,
                                                  &sealed_len);
    if (pm_rc != PM_OK)
    {
        bio_tpm_cleanup(&tpm_ctx);
        bio_secure_wipe(sealed_blob, sizeof(sealed_blob));
        return pm_rc;
    }

    tpm_rc = pm_tpm_unseal_wrapping_key(&tpm_ctx,
                                        sealed_blob, sealed_len,
                                        pcr_index,
                                        key_out);
    bio_tpm_cleanup(&tpm_ctx);

    if (tpm_rc != PM_OK)
    {
        bio_secure_wipe(sealed_blob, sizeof(sealed_blob));
        bio_secure_wipe(key_out, PM_TPM_WRAPPING_KEY_SIZE);
        return tpm_rc;
    }

    f = fopen(sidecar_path, "wb");
    if (!f)
    {
        bio_secure_wipe(sealed_blob, sizeof(sealed_blob));
        bio_secure_wipe(key_out, PM_TPM_WRAPPING_KEY_SIZE);
        return PM_ERR_IO;
    }

    if (fwrite(sealed_blob, 1, sealed_len, f) != sealed_len)
    {
        fclose(f);
        bio_secure_wipe(sealed_blob, sizeof(sealed_blob));
        bio_secure_wipe(key_out, PM_TPM_WRAPPING_KEY_SIZE);
        return PM_ERR_IO;
    }

    fclose(f);
    bio_secure_wipe(sealed_blob, sizeof(sealed_blob));
    return PM_OK;
}

pm_error_t pm_vault_tpm_unseal_wrapping_key(const char *vault_path,
                                            uint32_t pcr_index,
                                            uint8_t *key_out)
{
    bio_tpm_ctx_t tpm_ctx;
    uint8_t *sealed_blob = NULL;
    size_t sealed_len = 0;
    char sidecar_path[PATH_MAX];
    pm_error_t pm_rc;
    int tpm_rc;

    if (!vault_path || !key_out)
    {
        return PM_ERR_INVALID_PARAM;
    }

    pm_rc = build_tpm_sidecar_path(vault_path, sidecar_path, sizeof(sidecar_path));
    if (pm_rc != PM_OK)
    {
        return pm_rc;
    }

    pm_rc = read_file_all(sidecar_path, &sealed_blob, &sealed_len);
    if (pm_rc != PM_OK)
    {
        return pm_rc;
    }

    tpm_rc = bio_tpm_init(&tpm_ctx, "/dev/tpmrm0");
    if (tpm_rc != BIO_OK)
    {
        bio_secure_wipe(sealed_blob, sealed_len);
        free(sealed_blob);
        return PM_ERR_TPM;
    }

    pm_rc = pm_tpm_unseal_wrapping_key(&tpm_ctx,
                                       sealed_blob, sealed_len,
                                       pcr_index,
                                       key_out);

    bio_tpm_cleanup(&tpm_ctx);
    bio_secure_wipe(sealed_blob, sealed_len);
    free(sealed_blob);

    return pm_rc;
}

void pm_vault_close(pm_vault_handle_t *h)
{
    if (!h)
    {
        return;
    }

    (void)pm_vault_lock(h, PM_LOCK_REASON_EXPLICIT);
    memset(h->path, 0, sizeof(h->path));
    memset(&h->format, 0, sizeof(h->format));
    memset(&h->mode, 0, sizeof(h->mode));
    memset(h->salt, 0, sizeof(h->salt));
    free(h);
}
