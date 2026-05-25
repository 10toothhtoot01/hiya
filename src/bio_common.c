/*
 * bio_common.c — Common utility implementations
 *
 * Copyright (C) 2024 BioAuth Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "bio_common.h"
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

/* ── Error strings ────────────────────────────────────────────── */

typedef struct {
    bio_error_t code;
    const char *msg;
} bio_error_entry_t;

static const bio_error_entry_t error_table[] = {
    { BIO_OK,                       "Success" },

    /* Generic */
    { BIO_ERR_NOMEM,                "Out of memory" },
    { BIO_ERR_INVALID_PARAM,        "Invalid parameter" },
    { BIO_ERR_BUFFER_TOO_SMALL,     "Buffer too small" },
    { BIO_ERR_NOT_FOUND,            "Not found" },
    { BIO_ERR_ALREADY_EXISTS,       "Already exists" },
    { BIO_ERR_PERMISSION,           "Permission denied" },
    { BIO_ERR_TIMEOUT,              "Operation timed out" },
    { BIO_ERR_IO,                   "I/O error" },
    { BIO_ERR_NOT_INITIALIZED,      "Not initialized" },
    { BIO_ERR_INTERNAL,             "Internal error" },

    /* Crypto */
    { BIO_ERR_CRYPTO_INIT,          "Crypto initialization failed" },
    { BIO_ERR_CRYPTO_RANDOM,        "Random number generation failed" },
    { BIO_ERR_CRYPTO_HASH,          "Hash computation failed" },
    { BIO_ERR_CRYPTO_MAC,           "MAC computation failed" },
    { BIO_ERR_CRYPTO_ENCRYPT,       "Encryption failed" },
    { BIO_ERR_CRYPTO_DECRYPT,       "Decryption failed" },
    { BIO_ERR_CRYPTO_SIGN,          "Signature generation failed" },
    { BIO_ERR_CRYPTO_VERIFY,        "Signature verification failed" },
    { BIO_ERR_CRYPTO_KEYGEN,        "Key generation failed" },
    { BIO_ERR_CRYPTO_TAG_MISMATCH,  "Authentication tag mismatch" },

    /* CBOR */
    { BIO_ERR_CBOR_OVERFLOW,        "CBOR buffer overflow" },
    { BIO_ERR_CBOR_INVALID,         "Invalid CBOR data" },
    { BIO_ERR_CBOR_UNEXPECTED_TYPE, "Unexpected CBOR type" },
    { BIO_ERR_CBOR_NESTING,         "CBOR nesting too deep" },
    { BIO_ERR_CBOR_BREAK,           "Unexpected CBOR break" },
    { BIO_ERR_CBOR_DUPLICATE_KEY,   "Duplicate CBOR map key" },

    /* TPM */
    { BIO_ERR_TPM_OPEN,             "TPM device open failed" },
    { BIO_ERR_TPM_COMMAND,          "TPM command failed" },
    { BIO_ERR_TPM_RESPONSE,         "Invalid TPM response" },
    { BIO_ERR_TPM_AUTH,             "TPM authorization failed" },
    { BIO_ERR_TPM_SEALED,           "TPM unseal failed" },
    { BIO_ERR_TPM_PCR,              "TPM PCR operation failed" },
    { BIO_ERR_TPM_HIERARCHY,        "TPM hierarchy error" },
    { BIO_ERR_TPM_HANDLE,           "Invalid TPM handle" },

    /* Fingerprint */
    { BIO_ERR_FP_NO_DEVICE,         "No fingerprint device found" },
    { BIO_ERR_FP_OPEN,              "Fingerprint device open failed" },
    { BIO_ERR_FP_ENROLL,            "Enrollment failed" },
    { BIO_ERR_FP_VERIFY,            "Verification failed" },
    { BIO_ERR_FP_DELETE,            "Fingerprint deletion failed" },
    { BIO_ERR_FP_RATE_LIMIT,        "Rate limit exceeded" },
    { BIO_ERR_FP_RETRY,             "Retry fingerprint scan" },
    { BIO_ERR_FP_NO_MATCH,          "No fingerprint match" },
    { BIO_ERR_FP_CANCELLED,         "Operation cancelled" },
    { BIO_ERR_FP_ALREADY_ENROLLED,  "Finger already enrolled on sensor (on-chip storage)" },

    /* D-Bus */
    { BIO_ERR_DBUS_CONNECT,         "D-Bus connection failed" },
    { BIO_ERR_DBUS_SEND,            "D-Bus send failed" },
    { BIO_ERR_DBUS_REPLY,           "D-Bus reply error" },
    { BIO_ERR_DBUS_TIMEOUT,         "D-Bus timeout" },
    { BIO_ERR_SESSION_INVALID,      "Invalid session" },
    { BIO_ERR_SESSION_EXPIRED,      "Session expired" },

    /* FIDO2/CTAP */
    { BIO_ERR_CTAP_INVALID_CMD,     "Invalid CTAP command" },
    { BIO_ERR_CTAP_CBOR_ERROR,      "CTAP CBOR encoding error" },
    { BIO_ERR_CTAP_MISSING_PARAM,   "Missing CTAP parameter" },
    { BIO_ERR_CTAP_NO_CREDENTIALS,  "No credentials found" },
    { BIO_ERR_CTAP_NOT_ALLOWED,     "Operation not allowed" },
    { BIO_ERR_CTAP_USER_CANCEL,     "User cancelled" },
    { BIO_ERR_CTAP_PIN_REQUIRED,    "PIN required" },
    { BIO_ERR_CTAP_PIN_INVALID,     "Invalid PIN" },
    { BIO_ERR_CTAP_PIN_BLOCKED,     "PIN blocked" },
    { BIO_ERR_CTAP_UP_REQUIRED,     "User presence required" },

    /* PAM */
    { BIO_ERR_PAM_AUTH_FAILED,      "PAM authentication failed" },
    { BIO_ERR_PAM_CONFIG,           "PAM configuration error" },
    { BIO_ERR_PAM_USER_UNKNOWN,     "Unknown user" },
};

const char *bio_error_str(bio_error_t err)
{
    for (size_t i = 0; i < BIO_ARRAY_SIZE(error_table); i++) {
        if (error_table[i].code == err)
            return error_table[i].msg;
    }
    return "Unknown error";
}

/* ── Finger strings ───────────────────────────────────────────── */

static const char *finger_names[] = {
    [BIO_FINGER_UNKNOWN]       = "Unknown",
    [BIO_FINGER_LEFT_THUMB]    = "Left Thumb",
    [BIO_FINGER_LEFT_INDEX]    = "Left Index",
    [BIO_FINGER_LEFT_MIDDLE]   = "Left Middle",
    [BIO_FINGER_LEFT_RING]     = "Left Ring",
    [BIO_FINGER_LEFT_LITTLE]   = "Left Little",
    [BIO_FINGER_RIGHT_THUMB]   = "Right Thumb",
    [BIO_FINGER_RIGHT_INDEX]   = "Right Index",
    [BIO_FINGER_RIGHT_MIDDLE]  = "Right Middle",
    [BIO_FINGER_RIGHT_RING]    = "Right Ring",
    [BIO_FINGER_RIGHT_LITTLE]  = "Right Little",
};

const char *bio_finger_str(bio_finger_t finger)
{
    if (finger < 0 || (size_t)finger >= BIO_ARRAY_SIZE(finger_names))
        return "Invalid";
    return finger_names[finger];
}

/* ── Logging ──────────────────────────────────────────────────── */

static bio_log_level_t g_log_level = BIO_LOG_INFO;
static bio_log_func_t  g_log_func  = NULL;

void bio_log_set_callback(bio_log_func_t func)
{
    g_log_func = func;
}

void bio_log_set_level(bio_log_level_t level)
{
    g_log_level = level;
}

static const char *level_str(bio_log_level_t level)
{
    switch (level) {
    case BIO_LOG_ERROR:   return "ERROR";
    case BIO_LOG_WARNING: return "WARN ";
    case BIO_LOG_INFO:    return "INFO ";
    case BIO_LOG_DEBUG:   return "DEBUG";
    case BIO_LOG_TRACE:   return "TRACE";
    default:              return "?????";
    }
}

void bio_log_impl(bio_log_level_t level,
                  const char *file, int line, const char *func,
                  const char *fmt, ...)
{
    if (level > g_log_level)
        return;

    if (g_log_func) {
        va_list ap;
        va_start(ap, fmt);
        /* Forward to custom callback — callback handles formatting */
        char buf[1024];
        vsnprintf(buf, sizeof(buf), fmt, ap);
        va_end(ap);
        g_log_func(level, file, line, func, "%s", buf);
        return;
    }

    /* Default: print to stderr */
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);

    /* Strip path prefix for readability */
    const char *basename = strrchr(file, '/');
    basename = basename ? basename + 1 : file;

    fprintf(stderr, "[%5ld.%03ld] %s %s:%d %s(): ",
            (long)ts.tv_sec % 100000,
            ts.tv_nsec / 1000000,
            level_str(level),
            basename, line, func);

    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    fputc('\n', stderr);
}

/* ── Structured auth event logging ───────────────────────────── */

void bio_log_auth_event(const char *user, const char *event,
                        const char *result, const char *detail)
{
    /*
     * Structured audit event — logged at INFO level with
     * machine-parseable fields for security auditing.
     *
     * Format: AUTH_EVENT user=<user> event=<event> result=<result> [detail=<detail>]
     *
     * Mirror of Windows Hello's credential provider audit events.
     */
    if (detail && detail[0]) {
        BIO_INFO("AUTH_EVENT user=%s event=%s result=%s detail=%s",
                 user ? user : "(null)",
                 event ? event : "(null)",
                 result ? result : "(null)",
                 detail);
    } else {
        BIO_INFO("AUTH_EVENT user=%s event=%s result=%s",
                 user ? user : "(null)",
                 event ? event : "(null)",
                 result ? result : "(null)");
    }
}
