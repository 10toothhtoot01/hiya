/*
 * pm_master_key.c - Composite master key derivation
 *
 * Copyright (C) 2026 Hiya Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "pm/pm_master_key.h"

#include <string.h>

#include "crypto/bio_crypto.h"

static void xor32(uint8_t dst[32], const uint8_t src[32])
{
    for (size_t i = 0; i < 32; i++)
    {
        dst[i] ^= src[i];
    }
}

pm_error_t pm_master_key_derive(const pm_composite_mode_t *mode,
                                const uint8_t *k_pwd,
                                const uint8_t *k_bio,
                                const uint8_t *k_keyfile,
                                const uint8_t *k_yubi,
                                uint8_t out_master_key[32])
{
    uint8_t tmp[32];
    size_t enabled = 0;

    if (!mode || !out_master_key)
    {
        return PM_ERR_INVALID_PARAM;
    }

    memset(tmp, 0, sizeof(tmp));

    if (mode->use_password)
    {
        if (!k_pwd)
        {
            return PM_ERR_INVALID_PARAM;
        }
        xor32(tmp, k_pwd);
        enabled++;
    }

    if (mode->use_biometric)
    {
        if (!k_bio)
        {
            return PM_ERR_INVALID_PARAM;
        }
        xor32(tmp, k_bio);
        enabled++;
    }

    if (mode->use_keyfile)
    {
        if (!k_keyfile)
        {
            return PM_ERR_INVALID_PARAM;
        }
        xor32(tmp, k_keyfile);
        enabled++;
    }

    if (mode->use_yubikey)
    {
        if (!k_yubi)
        {
            return PM_ERR_INVALID_PARAM;
        }
        xor32(tmp, k_yubi);
        enabled++;
    }

    if (enabled == 0)
    {
        return PM_ERR_POLICY;
    }

    memcpy(out_master_key, tmp, sizeof(tmp));
    bio_secure_wipe(tmp, sizeof(tmp));
    return PM_OK;
}
