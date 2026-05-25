/*
 * pm_bio_wrap.h - TPM-backed biometric vault wrapping-key helpers
 *
 * Copyright (C) 2026 BioAuth Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef PM_BIO_WRAP_H
#define PM_BIO_WRAP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "pm/pm_errors.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define PM_BIO_WRAP_KEY_SIZE 32u
#define PM_BIO_WRAP_DEFAULT_PCR 7u

    typedef struct
    {
        bool require_tpm;
        uint32_t pcr_index;
    } pm_bio_wrap_params_t;

    void pm_bio_wrap_params_defaults(pm_bio_wrap_params_t *params);

    pm_error_t pm_bio_wrap_generate(uint8_t wrapping_key[PM_BIO_WRAP_KEY_SIZE]);

    pm_error_t pm_bio_wrap_sidecar_path(const char *vault_path,
                                        char *out_path,
                                        size_t out_path_len);

    pm_error_t pm_bio_wrap_write_sidecar(const char *vault_path,
                                         const pm_bio_wrap_params_t *params,
                                         const uint8_t *sealed_blob,
                                         size_t sealed_blob_len);

    pm_error_t pm_bio_wrap_read_sidecar(const char *vault_path,
                                        pm_bio_wrap_params_t *out_params,
                                        uint8_t **out_sealed_blob,
                                        size_t *out_sealed_blob_len);

    pm_error_t pm_bio_wrap_seal_to_tpm(const char *vault_path,
                                       const pm_bio_wrap_params_t *params,
                                       const uint8_t wrapping_key[PM_BIO_WRAP_KEY_SIZE]);

    pm_error_t pm_bio_wrap_unseal_from_tpm(const char *vault_path,
                                           pm_bio_wrap_params_t *out_params,
                                           uint8_t wrapping_key[PM_BIO_WRAP_KEY_SIZE]);

    pm_error_t pm_bio_wrap_unseal_vault_key(const char *vault_path,
                                            uint8_t wrapping_key[PM_BIO_WRAP_KEY_SIZE]);

#ifdef __cplusplus
}
#endif

#endif /* PM_BIO_WRAP_H */
