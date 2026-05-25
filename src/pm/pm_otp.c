/*
 * pm_otp.c - TOTP/HOTP RFC 6238/4226 implementation
 *
 * Copyright (C) 2026 BioAuth Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "pm/pm_otp.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mbedtls/md.h>

#include "crypto/bio_crypto.h"

static pm_error_t hotp_truncate(const uint8_t *hmac, size_t hmac_len,
                                uint32_t digits, uint32_t *code_out)
{
    uint32_t offset, code, divisor;

    if (!hmac || hmac_len < 20 || !code_out)
    {
        return PM_ERR_INVALID_PARAM;
    }

    offset = hmac[hmac_len - 1] & 0x0F;
    if (offset + 4 > hmac_len)
    {
        return PM_ERR_CRYPTO;
    }

    code = ((uint32_t)(hmac[offset] & 0x7F) << 24) |
           ((uint32_t)hmac[offset + 1] << 16) |
           ((uint32_t)hmac[offset + 2] << 8) |
           ((uint32_t)hmac[offset + 3]);

    divisor = 1;
    for (uint32_t i = 0; i < digits; i++)
    {
        divisor *= 10;
    }

    *code_out = code % divisor;
    return PM_OK;
}

static pm_error_t otp_hmac(const pm_otp_params_t *params,
                           uint64_t counter,
                           uint8_t *hmac_out,
                           size_t *hmac_len)
{
    mbedtls_md_type_t md_type;
    const mbedtls_md_info_t *md_info;
    uint8_t counter_bytes[8];
    int ret;

    if (!params || !hmac_out || !hmac_len)
    {
        return PM_ERR_INVALID_PARAM;
    }

    switch (params->digest)
    {
    case PM_OTP_SHA1:
        md_type = MBEDTLS_MD_SHA1;
        *hmac_len = 20;
        break;
    case PM_OTP_SHA256:
        md_type = MBEDTLS_MD_SHA256;
        *hmac_len = 32;
        break;
    case PM_OTP_SHA512:
        md_type = MBEDTLS_MD_SHA512;
        *hmac_len = 64;
        break;
    default:
        return PM_ERR_UNSUPPORTED;
    }

    md_info = mbedtls_md_info_from_type(md_type);
    if (!md_info)
    {
        return PM_ERR_CRYPTO;
    }

    for (int i = 7; i >= 0; i--)
    {
        counter_bytes[i] = (uint8_t)(counter & 0xFF);
        counter >>= 8;
    }

    ret = mbedtls_md_hmac(md_info, params->secret, params->secret_len,
                          counter_bytes, sizeof(counter_bytes),
                          hmac_out);
    bio_secure_wipe(counter_bytes, sizeof(counter_bytes));

    if (ret != 0)
    {
        return PM_ERR_CRYPTO;
    }

    return PM_OK;
}

pm_error_t pm_otp_hotp_generate(const pm_otp_params_t *params,
                                char *code_out,
                                size_t code_size)
{
    uint8_t hmac[64];
    size_t hmac_len = sizeof(hmac);
    uint32_t code;
    pm_error_t rc;

    if (!params || !code_out || code_size < 9)
    {
        return PM_ERR_INVALID_PARAM;
    }

    if (params->algorithm != PM_OTP_HOTP)
    {
        return PM_ERR_INVALID_PARAM;
    }

    if (params->digits != 6 && params->digits != 8)
    {
        return PM_ERR_INVALID_PARAM;
    }

    rc = otp_hmac(params, params->counter, hmac, &hmac_len);
    if (rc != PM_OK)
    {
        bio_secure_wipe(hmac, sizeof(hmac));
        return rc;
    }

    rc = hotp_truncate(hmac, hmac_len, params->digits, &code);
    bio_secure_wipe(hmac, sizeof(hmac));
    if (rc != PM_OK)
    {
        return rc;
    }

    snprintf(code_out, code_size, "%0*u", (int)params->digits, code);
    return PM_OK;
}

pm_error_t pm_otp_totp_generate(const pm_otp_params_t *params,
                                time_t current_time,
                                char *code_out,
                                size_t code_size)
{
    uint64_t time_counter;
    pm_otp_params_t hotp_params;
    pm_error_t rc;

    if (!params || !code_out || code_size < 9)
    {
        return PM_ERR_INVALID_PARAM;
    }

    if (params->algorithm != PM_OTP_TOTP)
    {
        return PM_ERR_INVALID_PARAM;
    }

    if (params->period == 0)
    {
        return PM_ERR_INVALID_PARAM;
    }

    time_counter = (uint64_t)current_time / params->period;

    hotp_params = *params;
    hotp_params.algorithm = PM_OTP_HOTP;
    hotp_params.counter = time_counter;

    rc = pm_otp_hotp_generate(&hotp_params, code_out, code_size);
    return rc;
}

uint32_t pm_otp_totp_remaining_seconds(uint32_t period, time_t current_time)
{
    if (period == 0)
    {
        return 0;
    }

    return (uint32_t)(period - ((uint64_t)current_time % period));
}

static int base32_decode(const char *encoded, uint8_t **out, size_t *out_len)
{
    static const char base32_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    size_t encoded_len, decoded_len, i, j;
    uint8_t *decoded;
    uint64_t buffer;
    int bits_left;

    if (!encoded || !out || !out_len)
    {
        return -1;
    }

    encoded_len = strlen(encoded);
    decoded_len = (encoded_len * 5) / 8;
    decoded = calloc(1, decoded_len + 1);
    if (!decoded)
    {
        return -1;
    }

    buffer = 0;
    bits_left = 0;
    j = 0;

    for (i = 0; i < encoded_len; i++)
    {
        char c = toupper((unsigned char)encoded[i]);
        const char *pos;
        int val;

        if (c == '=' || c == ' ' || c == '\n' || c == '\r')
        {
            continue;
        }

        pos = strchr(base32_alphabet, c);
        if (!pos)
        {
            free(decoded);
            return -1;
        }

        val = (int)(pos - base32_alphabet);
        buffer = (buffer << 5) | (uint64_t)val;
        bits_left += 5;

        if (bits_left >= 8)
        {
            bits_left -= 8;
            if (j >= decoded_len)
            {
                uint8_t *tmp = realloc(decoded, decoded_len + 8);
                if (!tmp)
                {
                    free(decoded);
                    return -1;
                }
                decoded = tmp;
                decoded_len += 8;
            }
            decoded[j++] = (uint8_t)((buffer >> bits_left) & 0xFF);
        }
    }

    *out = decoded;
    *out_len = j;
    return 0;
}

pm_error_t pm_otp_parse_uri(const char *uri, pm_otp_params_t *params)
{
    char *secret_b32 = NULL;
    char *uri_copy = NULL;
    char *query, *token, *saveptr;

    if (!uri || !params)
    {
        return PM_ERR_INVALID_PARAM;
    }

    memset(params, 0, sizeof(*params));
    params->digits = 6;
    params->period = 30;

    if (strncmp(uri, "otpauth://", 10) != 0)
    {
        return PM_ERR_FORMAT;
    }

    if (strncmp(uri + 10, "totp/", 5) == 0)
    {
        params->algorithm = PM_OTP_TOTP;
    }
    else if (strncmp(uri + 10, "hotp/", 5) == 0)
    {
        params->algorithm = PM_OTP_HOTP;
    }
    else
    {
        return PM_ERR_FORMAT;
    }

    uri_copy = strdup(uri);
    if (!uri_copy)
    {
        return PM_ERR_NOMEM;
    }

    query = strchr(uri_copy, '?');
    if (!query)
    {
        free(uri_copy);
        return PM_ERR_FORMAT;
    }
    query++;

    params->digest = PM_OTP_SHA1;

    for (token = strtok_r(query, "&", &saveptr); token; token = strtok_r(NULL, "&", &saveptr))
    {
        char *eq = strchr(token, '=');
        if (!eq)
        {
            continue;
        }
        *eq = '\0';
        eq++;

        if (strcmp(token, "secret") == 0)
        {
            secret_b32 = strdup(eq);
        }
        else if (strcmp(token, "digits") == 0)
        {
            params->digits = (uint32_t)atoi(eq);
        }
        else if (strcmp(token, "period") == 0)
        {
            params->period = (uint32_t)atoi(eq);
        }
        else if (strcmp(token, "counter") == 0)
        {
            params->counter = (uint64_t)strtoull(eq, NULL, 10);
        }
        else if (strcmp(token, "algorithm") == 0)
        {
            if (strcmp(eq, "SHA256") == 0)
            {
                params->digest = PM_OTP_SHA256;
            }
            else if (strcmp(eq, "SHA512") == 0)
            {
                params->digest = PM_OTP_SHA512;
            }
        }
    }

    free(uri_copy);

    if (!secret_b32)
    {
        return PM_ERR_FORMAT;
    }

    if (base32_decode(secret_b32, &params->secret, &params->secret_len) != 0)
    {
        free(secret_b32);
        return PM_ERR_FORMAT;
    }

    free(secret_b32);

    if (params->secret_len == 0 || params->digits == 0)
    {
        pm_otp_params_free(params);
        return PM_ERR_FORMAT;
    }

    return PM_OK;
}

void pm_otp_params_free(pm_otp_params_t *params)
{
    if (!params)
    {
        return;
    }

    if (params->secret)
    {
        bio_secure_wipe(params->secret, params->secret_len);
        free(params->secret);
        params->secret = NULL;
        params->secret_len = 0;
    }
}

pm_error_t pm_otp_import_from_qr(const char *qr_text, pm_entry_t *entry_out)
{
    pm_otp_params_t otp_params;
    pm_error_t rc;
    char *uri_copy = NULL;
    char *issuer = NULL;
    char *account = NULL;
    char totp_uri[1024];

    if (!qr_text || !entry_out)
    {
        return PM_ERR_INVALID_PARAM;
    }

    /* Initialize entry */
    pm_entry_init(entry_out);

    /* Parse the QR text as otpauth URI */
    rc = pm_otp_parse_uri(qr_text, &otp_params);
    if (rc != PM_OK)
    {
        return rc;
    }

    /* Only support TOTP for now */
    if (otp_params.algorithm != PM_OTP_TOTP)
    {
        pm_otp_params_free(&otp_params);
        return PM_ERR_UNSUPPORTED;
    }

    /* Extract issuer and account from the URI path and query parameters */
    uri_copy = strdup(qr_text);
    if (!uri_copy)
    {
        pm_otp_params_free(&otp_params);
        return PM_ERR_NOMEM;
    }

    /* Parse URI to extract label: otpauth://totp/[Issuer:]Account?... */
    char *path_start = strstr(uri_copy, "://totp/");
    if (path_start)
    {
        path_start += 8; /* Skip "://totp/" */
        char *query_start = strchr(path_start, '?');
        if (query_start)
        {
            *query_start = '\0'; /* Terminate path part */
        }

        /* Decode URL-encoded path */
        char *colon = strchr(path_start, ':');
        if (colon)
        {
            *colon = '\0';
            issuer = strdup(path_start);
            account = strdup(colon + 1);
        }
        else
        {
            account = strdup(path_start);
        }

        /* Also check for issuer in query parameters */
        if (!issuer && query_start)
        {
            char *issuer_param = strstr(query_start + 1, "issuer=");
            if (issuer_param)
            {
                issuer_param += 7; /* Skip "issuer=" */
                char *issuer_end = strchr(issuer_param, '&');
                if (issuer_end)
                {
                    issuer = strndup(issuer_param, issuer_end - issuer_param);
                }
                else
                {
                    issuer = strdup(issuer_param);
                }
            }
        }
    }

    /* Populate entry fields */
    if (issuer && account)
    {
        char title[256];
        snprintf(title, sizeof(title), "%s (%s)", account, issuer);
        entry_out->title = strdup(title);
        entry_out->username = strdup(account);
    }
    else if (account)
    {
        entry_out->title = strdup(account);
        entry_out->username = strdup(account);
    }
    else
    {
        entry_out->title = strdup("TOTP Entry");
        entry_out->username = strdup("");
    }

    entry_out->password = strdup(""); /* No password for TOTP entries */
    entry_out->notes = strdup("Imported from QR code");
    entry_out->created_at_ms = (uint64_t)time(NULL) * 1000;
    entry_out->updated_at_ms = entry_out->created_at_ms;

    /* Add TOTP as custom field */
    entry_out->custom_fields = malloc(sizeof(pm_custom_field_t));
    if (!entry_out->custom_fields)
    {
        rc = PM_ERR_NOMEM;
        goto cleanup;
    }

    entry_out->custom_field_count = 1;
    pm_custom_field_t *totp_field = &entry_out->custom_fields[0];
    totp_field->name = strdup("TOTP");
    totp_field->type = PM_FIELD_TOTP;

    /* Store the original URI as the TOTP value */
    totp_field->text_value = strdup(qr_text);

    /* Generate unique entry ID */
    snprintf(totp_uri, sizeof(totp_uri), "totp-%lu", (unsigned long)time(NULL));
    entry_out->id = strdup(totp_uri);

    rc = PM_OK;

cleanup:
    pm_otp_params_free(&otp_params);
    free(uri_copy);
    free(issuer);
    free(account);

    if (rc != PM_OK)
    {
        pm_entry_free(entry_out);
    }

    return rc;
}

pm_error_t pm_otp_get_live_status(const char *totp_uri,
                                  time_t current_time,
                                  char *code_out,
                                  size_t code_size,
                                  uint32_t *remaining_out)
{
    pm_otp_params_t params;
    pm_error_t rc;

    if (!totp_uri || !code_out || !remaining_out || code_size < 9)
    {
        return PM_ERR_INVALID_PARAM;
    }

    /* Parse the TOTP URI */
    rc = pm_otp_parse_uri(totp_uri, &params);
    if (rc != PM_OK)
    {
        return rc;
    }

    /* Only support TOTP */
    if (params.algorithm != PM_OTP_TOTP)
    {
        pm_otp_params_free(&params);
        return PM_ERR_UNSUPPORTED;
    }

    /* Generate current TOTP code */
    rc = pm_otp_totp_generate(&params, current_time, code_out, code_size);
    if (rc != PM_OK)
    {
        pm_otp_params_free(&params);
        return rc;
    }

    /* Calculate remaining time */
    *remaining_out = pm_otp_totp_remaining_seconds(params.period, current_time);

    pm_otp_params_free(&params);
    return PM_OK;
}
