/*
 * pm_master_key.h - Composite master key derivation
 *
 * Copyright (C) 2026 BioAuth Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef PM_MASTER_KEY_H
#define PM_MASTER_KEY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "pm/pm_errors.h"

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct
    {
        bool use_password;
        bool use_biometric;
        bool use_keyfile;
        bool use_yubikey;
    } pm_composite_mode_t;

    /*
     * Derive final 32-byte master key by XOR-combining enabled factor keys
     * in deterministic order: password, biometric, keyfile, yubikey.
     */
    pm_error_t pm_master_key_derive(const pm_composite_mode_t *mode,
                                    const uint8_t *k_pwd,
                                    const uint8_t *k_bio,
                                    const uint8_t *k_keyfile,
                                    const uint8_t *k_yubi,
                                    uint8_t out_master_key[32]);

#ifdef __cplusplus
}
#endif

#endif /* PM_MASTER_KEY_H */
