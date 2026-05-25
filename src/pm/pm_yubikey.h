/*
 * pm_yubikey.h - YubiKey integration for credential management
 *
 * Copyright (C) 2026 BioAuth Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef PM_YUBIKEY_H
#define PM_YUBIKEY_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "pm/pm_errors.h"

#ifdef __cplusplus
extern "C"
{
#endif

    /* YubiKey credential types */
    typedef enum
    {
        PM_YUBIKEY_OTP = 0,       /* Yubico OTP */
        PM_YUBIKEY_STATIC = 1,    /* Static password */
        PM_YUBIKEY_HOTP = 2,      /* OATH-HOTP */
        PM_YUBIKEY_TOTP = 3,      /* OATH-TOTP */
        PM_YUBIKEY_CHALLENGE = 4, /* Challenge-Response */
        PM_YUBIKEY_PIV = 5,       /* PIV smart card */
        PM_YUBIKEY_FIDO2 = 6,     /* FIDO2/WebAuthn */
    } pm_yubikey_type_t;

    /* YubiKey device information */
    typedef struct
    {
        uint32_t serial;       /* Device serial number */
        uint8_t major_version; /* Firmware major version */
        uint8_t minor_version; /* Firmware minor version */
        uint8_t patch_version; /* Firmware patch version */
        bool touch_level;      /* Touch button capability */
        bool supports_otp;     /* Supports Yubico OTP */
        bool supports_ccid;    /* Supports CCID (PIV/OATH) */
        bool supports_fido;    /* Supports FIDO U2F */
        bool supports_fido2;   /* Supports FIDO2/WebAuthn */
        char *device_name;     /* Product name */
    } pm_yubikey_device_t;

    /* YubiKey credential entry */
    typedef struct
    {
        char *name;             /* User-friendly name */
        char *issuer;           /* Service issuer */
        pm_yubikey_type_t type; /* Credential type */
        uint8_t slot;           /* YubiKey slot number (1 or 2) */

        /* Type-specific data */
        union
        {
            struct
            {
                char *public_id;     /* Public identifier */
                uint8_t *private_id; /* AES encrypted private ID */
                uint8_t *aes_key;    /* AES key for encryption */
            } otp;

            struct
            {
                char *password;     /* Static password */
                bool require_touch; /* Require touch for activation */
            } static_pwd;

            struct
            {
                uint8_t *secret; /* OATH secret */
                size_t secret_len;
                uint32_t digits;    /* Code digits (6 or 8) */
                uint64_t counter;   /* HOTP counter */
                uint32_t period;    /* TOTP period */
                bool require_touch; /* Require touch */
            } oath;

            struct
            {
                uint8_t *challenge; /* Challenge data */
                size_t challenge_len;
                uint8_t *response; /* Expected response */
                size_t response_len;
            } challenge_resp;

            struct
            {
                uint8_t key_id; /* PIV key slot */
                uint8_t *cert;  /* X.509 certificate */
                size_t cert_len;
                char *pin;     /* PIV PIN */
                char *subject; /* Certificate subject */
            } piv;

            struct
            {
                uint8_t *cred_id; /* FIDO2 credential ID */
                size_t cred_id_len;
                char *rp_id;     /* Relying party ID */
                char *user_name; /* User name */
            } fido2;
        } data;

        uint64_t created;   /* Creation timestamp */
        uint64_t last_used; /* Last used timestamp */
        uint32_t use_count; /* Usage counter */
        char *notes;        /* User notes */
    } pm_yubikey_cred_t;

    /**
     * Detect connected YubiKey devices.
     *
     * @param devices    Output: array of detected devices (caller must free)
     * @param count      Output: number of devices found
     * @return PM_OK on success, PM_ERR_* on failure
     */
    pm_error_t pm_yubikey_detect_devices(pm_yubikey_device_t **devices, size_t *count);

    /**
     * Get device information from specific YubiKey.
     *
     * @param serial     Device serial number (0 for first available)
     * @param device     Output: device information (caller must free)
     * @return PM_OK on success, PM_ERR_* on failure
     */
    pm_error_t pm_yubikey_get_device_info(uint32_t serial, pm_yubikey_device_t **device);

    /**
     * Free YubiKey device information.
     */
    void pm_yubikey_device_free(pm_yubikey_device_t *device);

    /**
     * Create a new YubiKey credential entry.
     *
     * @param cred       Output: new credential structure (caller must free)
     * @return PM_OK on success, PM_ERR_* on failure
     */
    pm_error_t pm_yubikey_cred_create(pm_yubikey_cred_t **cred);

    /**
     * Free YubiKey credential and securely wipe sensitive data.
     */
    void pm_yubikey_cred_free(pm_yubikey_cred_t *cred);

    /**
     * Program YubiKey OTP credential.
     *
     * @param serial     Target YubiKey serial (0 for first available)
     * @param slot       Slot number (1 or 2)
     * @param public_id  Public identifier (12 hex chars)
     * @param private_id Private identifier (12 hex chars)
     * @param aes_key    AES key (32 hex chars)
     * @return PM_OK on success, PM_ERR_* on failure
     */
    pm_error_t pm_yubikey_program_otp(uint32_t serial, uint8_t slot,
                                      const char *public_id,
                                      const char *private_id,
                                      const char *aes_key);

    /**
     * Program YubiKey static password.
     *
     * @param serial     Target YubiKey serial
     * @param slot       Slot number (1 or 2)
     * @param password   Static password to program
     * @param require_touch  Require touch for activation
     * @return PM_OK on success, PM_ERR_* on failure
     */
    pm_error_t pm_yubikey_program_static(uint32_t serial, uint8_t slot,
                                         const char *password,
                                         bool require_touch);

    /**
     * Program YubiKey OATH credential.
     *
     * @param serial     Target YubiKey serial
     * @param name       Credential name
     * @param secret     OATH secret
     * @param secret_len Secret length
     * @param type       OATH type (HOTP/TOTP)
     * @param digits     Code digits (6 or 8)
     * @param period     TOTP period (if TOTP)
     * @param require_touch  Require touch
     * @return PM_OK on success, PM_ERR_* on failure
     */
    pm_error_t pm_yubikey_program_oath(uint32_t serial, const char *name,
                                       const uint8_t *secret, size_t secret_len,
                                       pm_yubikey_type_t type, uint32_t digits,
                                       uint32_t period, bool require_touch);

    /**
     * Generate OTP code from YubiKey.
     *
     * @param cred       YubiKey credential
     * @param code       Output: generated code (caller must free)
     * @return PM_OK on success, PM_ERR_* on failure
     */
    pm_error_t pm_yubikey_generate_otp(const pm_yubikey_cred_t *cred, char **code);

    /**
     * Perform challenge-response operation.
     *
     * @param serial     Target YubiKey serial
     * @param slot       Slot number (1 or 2)
     * @param challenge  Challenge data
     * @param challenge_len  Challenge length
     * @param response   Output: response data (caller must free)
     * @param response_len   Output: response length
     * @return PM_OK on success, PM_ERR_* on failure
     */
    pm_error_t pm_yubikey_challenge_response(uint32_t serial, uint8_t slot,
                                             const uint8_t *challenge, size_t challenge_len,
                                             uint8_t **response, size_t *response_len);

    /**
     * List OATH credentials stored on YubiKey.
     *
     * @param serial     Target YubiKey serial
     * @param creds      Output: array of credential names (caller must free)
     * @param count      Output: number of credentials
     * @return PM_OK on success, PM_ERR_* on failure
     */
    pm_error_t pm_yubikey_list_oath_creds(uint32_t serial, char ***creds, size_t *count);

    /**
     * Calculate OATH code from YubiKey.
     *
     * @param serial     Target YubiKey serial
     * @param name       Credential name
     * @param challenge  Challenge/timestamp for TOTP (NULL for HOTP)
     * @param code       Output: calculated code (caller must free)
     * @return PM_OK on success, PM_ERR_* on failure
     */
    pm_error_t pm_yubikey_calculate_oath(uint32_t serial, const char *name,
                                         const uint8_t *challenge,
                                         char **code);

    /**
     * Reset YubiKey to factory defaults (requires physical touch).
     *
     * @param serial     Target YubiKey serial
     * @return PM_OK on success, PM_ERR_* on failure
     */
    pm_error_t pm_yubikey_factory_reset(uint32_t serial);

    /**
     * Set YubiKey configuration flags.
     *
     * @param serial     Target YubiKey serial
     * @param slot       Slot number (1 or 2)
     * @param flags      Configuration flags
     * @return PM_OK on success, PM_ERR_* on failure
     */
    pm_error_t pm_yubikey_set_config(uint32_t serial, uint8_t slot, uint32_t flags);

    /**
     * Validate YubiKey credential consistency.
     */
    pm_error_t pm_yubikey_cred_validate(const pm_yubikey_cred_t *cred);

    /**
     * Update YubiKey credential usage statistics.
     */
    pm_error_t pm_yubikey_cred_update_usage(pm_yubikey_cred_t *cred);

/* YubiKey configuration flags */
#define PM_YUBIKEY_CFG_SEND_REF 0x01             /* Send reference string */
#define PM_YUBIKEY_CFG_TICKET_FIRST 0x02         /* Ticket flag first */
#define PM_YUBIKEY_CFG_PACING_10MS 0x04          /* 10ms pacing */
#define PM_YUBIKEY_CFG_PACING_20MS 0x08          /* 20ms pacing */
#define PM_YUBIKEY_CFG_ALLOW_HIDTRIG 0x10        /* Allow HID trigger */
#define PM_YUBIKEY_CFG_STATIC_TICKET 0x20        /* Static ticket */
#define PM_YUBIKEY_CFG_SHORT_TICKET 0x40         /* Short ticket */
#define PM_YUBIKEY_CFG_STRONG_PW1 0x80           /* Strong password policy */
#define PM_YUBIKEY_CFG_STRONG_PW2 0x100          /* Enhanced strong password */
#define PM_YUBIKEY_CFG_MAN_UPDATE 0x200          /* Manual update */
#define PM_YUBIKEY_CFG_OATH_HOTP8 0x400          /* OATH-HOTP 8-digit */
#define PM_YUBIKEY_CFG_OATH_FIXED_MODHEX1 0x800  /* OATH fixed ModHex1 */
#define PM_YUBIKEY_CFG_OATH_FIXED_MODHEX2 0x1000 /* OATH fixed ModHex2 */
#define PM_YUBIKEY_CFG_OATH_FIXED_MODHEX 0x1800  /* OATH fixed ModHex */

#ifdef __cplusplus
}
#endif

#endif /* PM_YUBIKEY_H */