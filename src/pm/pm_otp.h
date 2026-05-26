/*
 * pm_otp.h - TOTP/HOTP RFC 6238/4226 implementation
 *
 * Copyright (C) 2026 Hiya Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef PM_OTP_H
#define PM_OTP_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#include "pm/pm_errors.h"
#include "pm/pm_payload.h" /* For pm_entry_t */

#ifdef __cplusplus
extern "C"
{
#endif

    /* OTP algorithm (RFC 4226 HOTP, RFC 6238 TOTP) */
    typedef enum
    {
        PM_OTP_HOTP = 0,
        PM_OTP_TOTP = 1,
    } pm_otp_algorithm_t;

    /* OTP digest algorithm */
    typedef enum
    {
        PM_OTP_SHA1 = 0,
        PM_OTP_SHA256 = 1,
        PM_OTP_SHA512 = 2,
    } pm_otp_digest_t;

    /* OTP parameters */
    typedef struct
    {
        pm_otp_algorithm_t algorithm;
        pm_otp_digest_t digest;
        uint8_t *secret;
        size_t secret_len;
        uint32_t digits;  /* 6 or 8 */
        uint32_t period;  /* TOTP time step (default 30s) */
        uint64_t counter; /* HOTP counter */
    } pm_otp_params_t;

    /**
     * Generate HOTP code (RFC 4226).
     *
     * @param params    OTP parameters (algorithm must be PM_OTP_HOTP)
     * @param code_out  Output: generated code as decimal string (null-terminated)
     * @param code_size Size of code_out buffer (must be >= 9 bytes for 8-digit codes)
     * @return PM_OK on success, PM_ERR_* on failure
     */
    pm_error_t pm_otp_hotp_generate(const pm_otp_params_t *params,
                                    char *code_out,
                                    size_t code_size);

    /**
     * Generate TOTP code (RFC 6238).
     *
     * @param params        OTP parameters (algorithm must be PM_OTP_TOTP)
     * @param current_time  Current Unix timestamp (use time(NULL))
     * @param code_out      Output: generated code as decimal string (null-terminated)
     * @param code_size     Size of code_out buffer (must be >= 9 bytes)
     * @return PM_OK on success, PM_ERR_* on failure
     */
    pm_error_t pm_otp_totp_generate(const pm_otp_params_t *params,
                                    time_t current_time,
                                    char *code_out,
                                    size_t code_size);

    /**
     * Calculate remaining time until next TOTP period.
     *
     * @param period        TOTP period in seconds (default 30)
     * @param current_time  Current Unix timestamp
     * @return Remaining seconds until next period (0..period-1)
     */
    uint32_t pm_otp_totp_remaining_seconds(uint32_t period, time_t current_time);

    /**
     * Parse otpauth:// URI and extract OTP parameters.
     *
     * Supports:
     *   otpauth://totp/Label?secret=BASE32&issuer=Issuer&digits=6&period=30
     *   otpauth://hotp/Label?secret=BASE32&counter=0
     *
     * @param uri       otpauth:// URI string
     * @param params    Output: parsed parameters (caller must free params->secret)
     * @return PM_OK on success, PM_ERR_* on failure
     */
    pm_error_t pm_otp_parse_uri(const char *uri, pm_otp_params_t *params);

    /**
     * Free OTP parameters (frees secret buffer).
     */
    void pm_otp_params_free(pm_otp_params_t *params);

    /**
     * Import TOTP from QR code text and create a vault entry.
     *
     * @param qr_text       Text content extracted from QR code (otpauth:// URI)
     * @param entry_out     Output: populated entry structure (caller owns)
     * @return PM_OK on success, PM_ERR_* on failure
     */
    pm_error_t pm_otp_import_from_qr(const char *qr_text, pm_entry_t *entry_out);

    /**
     * Get live TOTP status (current code and remaining time).
     *
     * @param totp_uri         TOTP URI (otpauth:// format)
     * @param current_time     Current Unix timestamp (use time(NULL))
     * @param code_out         Output: current 6-8 digit code (null-terminated)
     * @param code_size        Size of code_out buffer (must be >= 9 bytes)
     * @param remaining_out    Output: seconds remaining until next period
     * @return PM_OK on success, PM_ERR_* on failure
     */
    pm_error_t pm_otp_get_live_status(const char *totp_uri,
                                      time_t current_time,
                                      char *code_out,
                                      size_t code_size,
                                      uint32_t *remaining_out);

#ifdef __cplusplus
}
#endif

#endif /* PM_OTP_H */
