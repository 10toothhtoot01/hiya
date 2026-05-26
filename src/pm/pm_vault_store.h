/*
 * pm_vault_store.h - Vault lifecycle and persistence manager
 *
 * Copyright (C) 2026 Hiya Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef PM_VAULT_STORE_H
#define PM_VAULT_STORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "pm/pm_master_key.h"
#include "pm/pm_payload.h"
#include "pm/pm_vault_format.h"

#ifdef __cplusplus
extern "C"
{
#endif

    typedef enum
    {
        PM_LOCK_REASON_EXPLICIT = 0,
        PM_LOCK_REASON_IDLE = 1,
        PM_LOCK_REASON_SESSION_LOCK = 2,
        PM_LOCK_REASON_LID_CLOSE = 3,
    } pm_lock_reason_t;

    typedef struct
    {
        const uint8_t *password;
        size_t password_len;

        bool has_wrapping_key;
        uint8_t wrapping_key[32];

        bool has_keyfile_hash;
        uint8_t keyfile_hash[32];

        bool has_yubikey_key;
        uint8_t yubikey_key[32];
    } pm_unlock_factors_t;

    typedef struct pm_vault_handle pm_vault_handle_t;

    typedef struct
    {
        pm_vault_format_params_t format;
        pm_composite_mode_t mode;
        const uint8_t *password;
        size_t password_len;
        bool has_wrapping_key;
        uint8_t wrapping_key[32];
        bool has_keyfile_hash;
        uint8_t keyfile_hash[32];
        bool has_yubikey_key;
        uint8_t yubikey_key[32];
        const uint8_t *initial_payload;
        size_t initial_payload_len;
    } pm_vault_create_opts_t;

    pm_error_t pm_vault_create(const char *path,
                               const pm_vault_create_opts_t *opts,
                               pm_vault_handle_t **out);

    pm_error_t pm_vault_open(const char *path, pm_vault_handle_t **out);

    pm_error_t pm_vault_unlock(pm_vault_handle_t *h, const pm_unlock_factors_t *factors);

    pm_error_t pm_vault_lock(pm_vault_handle_t *h, pm_lock_reason_t reason);

    pm_error_t pm_vault_save(pm_vault_handle_t *h);

    bool pm_vault_is_locked(const pm_vault_handle_t *h);

    pm_error_t pm_vault_get_mode(const pm_vault_handle_t *h,
                                 pm_composite_mode_t *mode_out);

    pm_error_t pm_vault_get_payload(const pm_vault_handle_t *h,
                                    const uint8_t **payload,
                                    size_t *payload_len);

    pm_error_t pm_vault_set_payload(pm_vault_handle_t *h,
                                    const uint8_t *payload,
                                    size_t payload_len);

    pm_error_t pm_vault_get_payload_model(const pm_vault_handle_t *h,
                                          pm_payload_t *out_payload);

    pm_error_t pm_vault_set_payload_model(pm_vault_handle_t *h,
                                          const pm_payload_t *payload);

    void pm_vault_close(pm_vault_handle_t *h);

    /**
     * Write TPM-sealed wrapping key sidecar file for a vault.
     *
     * Generates a random wrapping key, seals it to TPM PCR, and writes
     * the sealed blob to <vault_path>.tpm.
     *
     * @param vault_path    Path to vault file
     * @param pcr_index     TPM PCR index to bind to (default: 7)
     * @param key_out       Output: the generated wrapping key (32 bytes, mlock'd)
     * @return PM_OK on success, PM_ERR_* on failure
     */
    pm_error_t pm_vault_tpm_seal_wrapping_key(const char *vault_path,
                                              uint32_t pcr_index,
                                              uint8_t *key_out);

    /**
     * Read and unseal TPM wrapping key from sidecar file.
     *
     * Reads sealed blob from <vault_path>.tpm and unseals it via TPM.
     * Succeeds only if current PCR values match those at seal time.
     *
     * @param vault_path    Path to vault file
     * @param pcr_index     TPM PCR index the blob was bound to
     * @param key_out       Output: unsealed wrapping key (32 bytes, mlock'd)
     * @return PM_OK on success, PM_ERR_* on failure
     */
    pm_error_t pm_vault_tpm_unseal_wrapping_key(const char *vault_path,
                                                uint32_t pcr_index,
                                                uint8_t *key_out);

#ifdef __cplusplus
}
#endif

#endif /* PM_VAULT_STORE_H */
