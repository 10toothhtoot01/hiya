/*
 * pm_kdf.h - Argon2id key derivation for vault master key material
 *
 * Copyright (C) 2026 BioAuth Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef PM_KDF_H
#define PM_KDF_H

#include <stdint.h>
#include <stddef.h>

#include "pm/pm_errors.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define PM_KDF_SALT_SIZE 32
#define PM_KDF_KEY_SIZE 32

    typedef struct
    {
        uint32_t t_cost;      /* Iterations/passes */
        uint32_t m_cost_kib;  /* Memory in KiB (1 KiB blocks) */
        uint32_t parallelism; /* Lanes */
        uint32_t version;     /* Argon2 version (0x13) */
    } pm_argon2_params_t;

    /*
     * Derive a 32-byte key using Argon2id.
     */
    pm_error_t pm_argon2id_derive(const uint8_t *password,
                                  size_t password_len,
                                  const uint8_t salt[PM_KDF_SALT_SIZE],
                                  const pm_argon2_params_t *params,
                                  uint8_t out_key[PM_KDF_KEY_SIZE]);

    /*
     * Validate and normalize params (fills defaults when fields are zero).
     */
    pm_error_t pm_argon2id_validate_params(pm_argon2_params_t *params);

#ifdef __cplusplus
}
#endif

#endif /* PM_KDF_H */
