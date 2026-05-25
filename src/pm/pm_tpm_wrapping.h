/*
 * pm_tpm_wrapping.h - TPM-sealed wrapping key for biometric vault unlock
 *
 * Copyright (C) 2026 BioAuth Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef PM_TPM_WRAPPING_H
#define PM_TPM_WRAPPING_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "pm/pm_errors.h"
#include "tpm/bio_tpm.h"

#ifdef __cplusplus
extern "C"
{
#endif

/* Default PCR index for wrapping-key policy (PCR 7 = Secure Boot state) */
#define PM_TPM_DEFAULT_PCR_INDEX 7u

/* Maximum sealed blob size (conservative estimate) */
#define PM_TPM_SEALED_BLOB_MAX 1024u

/* Wrapping key size (AES-256 key) */
#define PM_TPM_WRAPPING_KEY_SIZE 32u

    /**
     * Generate and TPM-seal a random wrapping key.
     *
     * The wrapping key is generated via bio_secure_random(), then sealed
     * to the specified PCR index using bio_tpm_seal_for_user_pcr().
     * The sealed blob can be written to disk and later unsealed on
     * biometric authentication.
     *
     * @param ctx           TPM context
     * @param pcr_index     PCR index to bind to (default: PM_TPM_DEFAULT_PCR_INDEX)
     * @param sealed_blob   Output: sealed blob (caller-allocated, PM_TPM_SEALED_BLOB_MAX bytes)
     * @param sealed_len    Output: actual sealed blob length
     * @return PM_OK on success, PM_ERR_* on failure
     */
    pm_error_t pm_tpm_generate_and_seal_wrapping_key(bio_tpm_ctx_t *ctx,
                                                     uint32_t pcr_index,
                                                     uint8_t *sealed_blob,
                                                     size_t *sealed_len);

    /**
     * Unseal a TPM-sealed wrapping key.
     *
     * The sealed blob is unsealed using bio_tpm_unseal_for_user_pcr().
     * Unsealing succeeds only if the current PCR values match those at seal time.
     *
     * @param ctx           TPM context
     * @param sealed_blob   Sealed blob (from disk or prior seal operation)
     * @param sealed_len    Sealed blob length
     * @param pcr_index     PCR index the blob was bound to
     * @param key_out       Output: unsealed wrapping key (32 bytes, caller-allocated, mlock'd)
     * @return PM_OK on success, PM_ERR_* on failure
     */
    pm_error_t pm_tpm_unseal_wrapping_key(bio_tpm_ctx_t *ctx,
                                          const uint8_t *sealed_blob,
                                          size_t sealed_len,
                                          uint32_t pcr_index,
                                          uint8_t *key_out);

#ifdef __cplusplus
}
#endif

#endif /* PM_TPM_WRAPPING_H */
