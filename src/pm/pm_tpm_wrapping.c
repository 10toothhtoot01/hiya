/*
 * pm_tpm_wrapping.c - TPM-sealed wrapping key for biometric vault unlock
 *
 * Copyright (C) 2026 Hiya Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "pm/pm_tpm_wrapping.h"

#include <string.h>

#include "crypto/bio_crypto.h"

pm_error_t pm_tpm_generate_and_seal_wrapping_key(bio_tpm_ctx_t *ctx,
                                                 uint32_t pcr_index,
                                                 uint8_t *sealed_blob,
                                                 size_t *sealed_len)
{
    uint8_t wrapping_key[PM_TPM_WRAPPING_KEY_SIZE];
    int ret;

    if (!ctx || !sealed_blob || !sealed_len)
    {
        return PM_ERR_INVALID_PARAM;
    }

    /* Generate random wrapping key */
    ret = bio_random_bytes(wrapping_key, sizeof(wrapping_key));
    if (ret != BIO_OK)
    {
        bio_secure_wipe(wrapping_key, sizeof(wrapping_key));
        return PM_ERR_CRYPTO;
    }

    /* Seal to TPM PCR */
    ret = bio_tpm_seal_for_user_pcr(ctx,
                                    wrapping_key, sizeof(wrapping_key),
                                    NULL, 0u,
                                    pcr_index,
                                    sealed_blob, sealed_len);

    bio_secure_wipe(wrapping_key, sizeof(wrapping_key));

    if (ret != BIO_OK)
    {
        return PM_ERR_TPM;
    }

    return PM_OK;
}

pm_error_t pm_tpm_unseal_wrapping_key(bio_tpm_ctx_t *ctx,
                                      const uint8_t *sealed_blob,
                                      size_t sealed_len,
                                      uint32_t pcr_index,
                                      uint8_t *key_out)
{
    size_t unsealed_len = PM_TPM_WRAPPING_KEY_SIZE;
    int ret;

    if (!ctx || !sealed_blob || !key_out || sealed_len == 0)
    {
        return PM_ERR_INVALID_PARAM;
    }

    ret = bio_tpm_unseal_for_user_pcr(ctx,
                                      sealed_blob, sealed_len,
                                      NULL, 0u,
                                      pcr_index,
                                      key_out, &unsealed_len);

    if (ret != BIO_OK)
    {
        bio_secure_wipe(key_out, PM_TPM_WRAPPING_KEY_SIZE);
        return PM_ERR_TPM;
    }

    if (unsealed_len != PM_TPM_WRAPPING_KEY_SIZE)
    {
        bio_secure_wipe(key_out, PM_TPM_WRAPPING_KEY_SIZE);
        return PM_ERR_STATE;
    }

    return PM_OK;
}
