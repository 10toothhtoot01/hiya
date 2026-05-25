/*
 * pm_yubikey.c - YubiKey integration for credential management
 *
 * STATUS: Hardware integration pending.
 * Dependencies required: libykpers-1 (ykpers), libusb-1.0
 * Until these are linked, hardware-facing operations return PM_ERR_UNSUPPORTED.
 *
 * Copyright (C) 2026 BioAuth Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "pm/pm_yubikey.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "bio_common.h"
#include "crypto/bio_crypto.h"

static void yubikey_log_not_supported_once(void)
{
    static bool logged = false;

    if (logged)
    {
        return;
    }

    BIO_WARN("YubiKey: hardware integration not yet implemented. Requires libykpers-1 and libusb-1.0.");
    logged = true;
}

pm_error_t pm_yubikey_detect_devices(pm_yubikey_device_t **devices, size_t *count)
{
    if (!devices || !count)
    {
        return PM_ERR_INVALID_PARAM;
    }

    *devices = NULL;
    *count = 0;
    yubikey_log_not_supported_once();
    return PM_ERR_UNSUPPORTED;
}

pm_error_t pm_yubikey_get_device_info(uint32_t serial, pm_yubikey_device_t **device)
{
    (void)serial;

    if (!device)
    {
        return PM_ERR_INVALID_PARAM;
    }

    *device = NULL;
    yubikey_log_not_supported_once();
    return PM_ERR_UNSUPPORTED;
}

void pm_yubikey_device_free(pm_yubikey_device_t *device)
{
    if (!device)
    {
        return;
    }

    free(device->device_name);
    free(device);
}

pm_error_t pm_yubikey_cred_create(pm_yubikey_cred_t **cred)
{
    if (!cred)
    {
        return PM_ERR_INVALID_PARAM;
    }

    pm_yubikey_cred_t *c = calloc(1, sizeof(pm_yubikey_cred_t));
    if (!c)
    {
        return PM_ERR_NOMEM;
    }

    c->type = PM_YUBIKEY_OTP;
    c->slot = 1;
    c->created = (uint64_t)time(NULL);

    *cred = c;
    return PM_OK;
}

void pm_yubikey_cred_free(pm_yubikey_cred_t *cred)
{
    if (!cred)
    {
        return;
    }

    free(cred->name);
    free(cred->issuer);
    free(cred->notes);

    switch (cred->type)
    {
    case PM_YUBIKEY_OTP:
        free(cred->data.otp.public_id);
        if (cred->data.otp.private_id)
        {
            bio_secure_wipe(cred->data.otp.private_id, 16);
            free(cred->data.otp.private_id);
        }
        if (cred->data.otp.aes_key)
        {
            bio_secure_wipe(cred->data.otp.aes_key, 32);
            free(cred->data.otp.aes_key);
        }
        break;

    case PM_YUBIKEY_STATIC:
        if (cred->data.static_pwd.password)
        {
            bio_secure_wipe(cred->data.static_pwd.password,
                            strlen(cred->data.static_pwd.password));
            free(cred->data.static_pwd.password);
        }
        break;

    case PM_YUBIKEY_HOTP:
    case PM_YUBIKEY_TOTP:
        if (cred->data.oath.secret)
        {
            bio_secure_wipe(cred->data.oath.secret, cred->data.oath.secret_len);
            free(cred->data.oath.secret);
        }
        break;

    case PM_YUBIKEY_CHALLENGE:
        free(cred->data.challenge_resp.challenge);
        free(cred->data.challenge_resp.response);
        break;

    case PM_YUBIKEY_PIV:
        free(cred->data.piv.cert);
        free(cred->data.piv.subject);
        if (cred->data.piv.pin)
        {
            bio_secure_wipe(cred->data.piv.pin, strlen(cred->data.piv.pin));
            free(cred->data.piv.pin);
        }
        break;

    case PM_YUBIKEY_FIDO2:
        free(cred->data.fido2.cred_id);
        free(cred->data.fido2.rp_id);
        free(cred->data.fido2.user_name);
        break;

    default:
        break;
    }

    bio_secure_wipe(cred, sizeof(*cred));
    free(cred);
}

pm_error_t pm_yubikey_program_otp(uint32_t serial, uint8_t slot,
                                  const char *public_id,
                                  const char *private_id,
                                  const char *aes_key)
{
    (void)serial;

    if (!public_id || !private_id || !aes_key || (slot != 1 && slot != 2))
    {
        return PM_ERR_INVALID_PARAM;
    }

    if (strlen(public_id) != 12 || strlen(private_id) != 12 || strlen(aes_key) != 32)
    {
        return PM_ERR_INVALID_PARAM;
    }

    yubikey_log_not_supported_once();
    return PM_ERR_UNSUPPORTED;
}

pm_error_t pm_yubikey_program_static(uint32_t serial, uint8_t slot,
                                     const char *password,
                                     bool require_touch)
{
    (void)serial;
    (void)require_touch;

    if (!password || (slot != 1 && slot != 2))
    {
        return PM_ERR_INVALID_PARAM;
    }

    if (strlen(password) > 64)
    {
        return PM_ERR_INVALID_PARAM;
    }

    yubikey_log_not_supported_once();
    return PM_ERR_UNSUPPORTED;
}

pm_error_t pm_yubikey_program_oath(uint32_t serial, const char *name,
                                   const uint8_t *secret, size_t secret_len,
                                   pm_yubikey_type_t type, uint32_t digits,
                                   uint32_t period, bool require_touch)
{
    (void)serial;
    (void)period;
    (void)require_touch;

    if (!name || !secret || secret_len == 0 ||
        (type != PM_YUBIKEY_HOTP && type != PM_YUBIKEY_TOTP) ||
        (digits != 6 && digits != 8))
    {
        return PM_ERR_INVALID_PARAM;
    }

    yubikey_log_not_supported_once();
    return PM_ERR_UNSUPPORTED;
}

pm_error_t pm_yubikey_generate_otp(const pm_yubikey_cred_t *cred, char **code)
{
    if (!cred || !code || cred->type != PM_YUBIKEY_OTP)
    {
        return PM_ERR_INVALID_PARAM;
    }

    *code = NULL;
    yubikey_log_not_supported_once();
    return PM_ERR_UNSUPPORTED;
}

pm_error_t pm_yubikey_challenge_response(uint32_t serial, uint8_t slot,
                                         const uint8_t *challenge, size_t challenge_len,
                                         uint8_t **response, size_t *response_len)
{
    (void)serial;

    if (!challenge || challenge_len == 0 || !response || !response_len ||
        (slot != 1 && slot != 2))
    {
        return PM_ERR_INVALID_PARAM;
    }

    *response = NULL;
    *response_len = 0;
    yubikey_log_not_supported_once();
    return PM_ERR_UNSUPPORTED;
}

pm_error_t pm_yubikey_list_oath_creds(uint32_t serial, char ***creds, size_t *count)
{
    (void)serial;

    if (!creds || !count)
    {
        return PM_ERR_INVALID_PARAM;
    }

    *creds = NULL;
    *count = 0;
    yubikey_log_not_supported_once();
    return PM_ERR_UNSUPPORTED;
}

pm_error_t pm_yubikey_calculate_oath(uint32_t serial, const char *name,
                                     const uint8_t *challenge,
                                     char **code)
{
    (void)serial;
    (void)challenge;

    if (!name || !code)
    {
        return PM_ERR_INVALID_PARAM;
    }

    *code = NULL;
    yubikey_log_not_supported_once();
    return PM_ERR_UNSUPPORTED;
}

pm_error_t pm_yubikey_factory_reset(uint32_t serial)
{
    (void)serial;

    yubikey_log_not_supported_once();
    return PM_ERR_UNSUPPORTED;
}

pm_error_t pm_yubikey_set_config(uint32_t serial, uint8_t slot, uint32_t flags)
{
    (void)serial;
    (void)flags;

    if (slot != 1 && slot != 2)
    {
        return PM_ERR_INVALID_PARAM;
    }

    yubikey_log_not_supported_once();
    return PM_ERR_UNSUPPORTED;
}

pm_error_t pm_yubikey_cred_validate(const pm_yubikey_cred_t *cred)
{
    if (!cred)
    {
        return PM_ERR_INVALID_PARAM;
    }

    if (!cred->name || strlen(cred->name) == 0)
    {
        return PM_ERR_INVALID_PARAM;
    }

    if (cred->slot != 1 && cred->slot != 2)
    {
        return PM_ERR_INVALID_PARAM;
    }

    switch (cred->type)
    {
    case PM_YUBIKEY_OTP:
        if (!cred->data.otp.public_id || !cred->data.otp.private_id || !cred->data.otp.aes_key)
        {
            return PM_ERR_INVALID_PARAM;
        }
        break;

    case PM_YUBIKEY_STATIC:
        if (!cred->data.static_pwd.password)
        {
            return PM_ERR_INVALID_PARAM;
        }
        break;

    case PM_YUBIKEY_HOTP:
    case PM_YUBIKEY_TOTP:
        if (!cred->data.oath.secret || cred->data.oath.secret_len == 0)
        {
            return PM_ERR_INVALID_PARAM;
        }
        if (cred->data.oath.digits != 6 && cred->data.oath.digits != 8)
        {
            return PM_ERR_INVALID_PARAM;
        }
        break;

    case PM_YUBIKEY_FIDO2:
        if (!cred->data.fido2.cred_id || !cred->data.fido2.rp_id)
        {
            return PM_ERR_INVALID_PARAM;
        }
        break;

    default:
        break;
    }

    return PM_OK;
}

pm_error_t pm_yubikey_cred_update_usage(pm_yubikey_cred_t *cred)
{
    if (!cred)
    {
        return PM_ERR_INVALID_PARAM;
    }

    cred->last_used = (uint64_t)time(NULL);
    cred->use_count++;
    return PM_OK;
}
