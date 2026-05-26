/*
 * bio_common.h — Common definitions for Hiya
 *
 * Copyright (C) 2024 Hiya Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef BIO_COMMON_H
#define BIO_COMMON_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Version ──────────────────────────────────────────────────── */
#define HIYA_VERSION_MAJOR  0
#define HIYA_VERSION_MINOR  1
#define HIYA_VERSION_PATCH  0
#define HIYA_VERSION_STRING "0.1.0"

/* ── Error codes ──────────────────────────────────────────────── */
typedef enum {
    BIO_OK                      =  0,

    /* Generic errors (-1 .. -99) */
    BIO_ERR_NOMEM               = -1,
    BIO_ERR_INVALID_PARAM       = -2,
    BIO_ERR_BUFFER_TOO_SMALL    = -3,
    BIO_ERR_NOT_FOUND           = -4,
    BIO_ERR_ALREADY_EXISTS      = -5,
    BIO_ERR_PERMISSION          = -6,
    BIO_ERR_TIMEOUT             = -7,
    BIO_ERR_IO                  = -8,
    BIO_ERR_NOT_INITIALIZED     = -9,
    BIO_ERR_INTERNAL            = -10,

    /* Crypto errors (-100 .. -199) */
    BIO_ERR_CRYPTO_INIT         = -100,
    BIO_ERR_CRYPTO_RANDOM       = -101,
    BIO_ERR_CRYPTO_HASH         = -102,
    BIO_ERR_CRYPTO_MAC          = -103,
    BIO_ERR_CRYPTO_ENCRYPT      = -104,
    BIO_ERR_CRYPTO_DECRYPT      = -105,
    BIO_ERR_CRYPTO_SIGN         = -106,
    BIO_ERR_CRYPTO_VERIFY       = -107,
    BIO_ERR_CRYPTO_KEYGEN       = -108,
    BIO_ERR_CRYPTO_TAG_MISMATCH = -109,

    /* CBOR errors (-200 .. -299) */
    BIO_ERR_CBOR_OVERFLOW       = -200,
    BIO_ERR_CBOR_INVALID        = -201,
    BIO_ERR_CBOR_UNEXPECTED_TYPE = -202,
    BIO_ERR_CBOR_NESTING        = -203,
    BIO_ERR_CBOR_BREAK          = -204,
    BIO_ERR_CBOR_DUPLICATE_KEY  = -205,

    /* TPM errors (-300 .. -399) */
    BIO_ERR_TPM_OPEN            = -300,
    BIO_ERR_TPM_COMMAND         = -301,
    BIO_ERR_TPM_RESPONSE        = -302,
    BIO_ERR_TPM_AUTH            = -303,
    BIO_ERR_TPM_SEALED          = -304,
    BIO_ERR_TPM_PCR             = -305,
    BIO_ERR_TPM_HIERARCHY       = -306,
    BIO_ERR_TPM_HANDLE          = -307,

    /* Fingerprint errors (-400 .. -499) */
    BIO_ERR_FP_NO_DEVICE        = -400,
    BIO_ERR_FP_OPEN             = -401,
    BIO_ERR_FP_ENROLL           = -402,
    BIO_ERR_FP_VERIFY           = -403,
    BIO_ERR_FP_DELETE           = -404,
    BIO_ERR_FP_RATE_LIMIT       = -405,
    BIO_ERR_FP_RETRY            = -406,
    BIO_ERR_FP_NO_MATCH         = -407,
    BIO_ERR_FP_CANCELLED        = -408,
    BIO_ERR_FP_ALREADY_ENROLLED = -409,  /* MOC sensor: template already on chip */

    /* D-Bus / daemon errors (-500 .. -599) */
    BIO_ERR_DBUS_CONNECT        = -500,
    BIO_ERR_DBUS_SEND           = -501,
    BIO_ERR_DBUS_REPLY          = -502,
    BIO_ERR_DBUS_TIMEOUT        = -503,
    BIO_ERR_SESSION_INVALID     = -504,
    BIO_ERR_SESSION_EXPIRED     = -505,

    /* FIDO2/CTAP errors (-600 .. -699) */
    BIO_ERR_CTAP_INVALID_CMD    = -600,
    BIO_ERR_CTAP_CBOR_ERROR     = -601,
    BIO_ERR_CTAP_MISSING_PARAM  = -602,
    BIO_ERR_CTAP_NO_CREDENTIALS = -603,
    BIO_ERR_CTAP_NOT_ALLOWED    = -604,
    BIO_ERR_CTAP_USER_CANCEL    = -605,
    BIO_ERR_CTAP_PIN_REQUIRED   = -606,
    BIO_ERR_CTAP_PIN_INVALID    = -607,
    BIO_ERR_CTAP_PIN_BLOCKED    = -608,
    BIO_ERR_CTAP_UP_REQUIRED    = -609,

    /* PAM errors (-700 .. -799) */
    BIO_ERR_PAM_AUTH_FAILED     = -700,
    BIO_ERR_PAM_CONFIG          = -701,
    BIO_ERR_PAM_USER_UNKNOWN    = -702,

} bio_error_t;

/* ── Error string ─────────────────────────────────────────────── */
const char *bio_error_str(bio_error_t err);

/* ── Finger identifiers ──────────────────────────────────────── */
typedef enum {
    BIO_FINGER_UNKNOWN       = 0,
    BIO_FINGER_LEFT_THUMB    = 1,
    BIO_FINGER_LEFT_INDEX    = 2,
    BIO_FINGER_LEFT_MIDDLE   = 3,
    BIO_FINGER_LEFT_RING     = 4,
    BIO_FINGER_LEFT_LITTLE   = 5,
    BIO_FINGER_RIGHT_THUMB   = 6,
    BIO_FINGER_RIGHT_INDEX   = 7,
    BIO_FINGER_RIGHT_MIDDLE  = 8,
    BIO_FINGER_RIGHT_RING    = 9,
    BIO_FINGER_RIGHT_LITTLE  = 10,
} bio_finger_t;

const char *bio_finger_str(bio_finger_t finger);

/* ── Logging ──────────────────────────────────────────────────── */
typedef enum {
    BIO_LOG_ERROR   = 0,
    BIO_LOG_WARNING = 1,
    BIO_LOG_INFO    = 2,
    BIO_LOG_DEBUG   = 3,
    BIO_LOG_TRACE   = 4,
} bio_log_level_t;

/* Log callback — set by daemon, CLI tools, tests */
typedef void (*bio_log_func_t)(bio_log_level_t level,
                                const char *file,
                                int line,
                                const char *func,
                                const char *fmt, ...);

void bio_log_set_callback(bio_log_func_t func);
void bio_log_set_level(bio_log_level_t level);

/* Logging macros */
#define BIO_LOG(level, fmt, ...) \
    bio_log_impl(level, __FILE__, __LINE__, __func__, fmt, ##__VA_ARGS__)

#define BIO_ERROR(fmt, ...)   BIO_LOG(BIO_LOG_ERROR,   fmt, ##__VA_ARGS__)
#define BIO_WARN(fmt, ...)    BIO_LOG(BIO_LOG_WARNING,  fmt, ##__VA_ARGS__)
#define BIO_INFO(fmt, ...)    BIO_LOG(BIO_LOG_INFO,     fmt, ##__VA_ARGS__)
#define BIO_DEBUG(fmt, ...)   BIO_LOG(BIO_LOG_DEBUG,    fmt, ##__VA_ARGS__)
#define BIO_TRACE(fmt, ...)   BIO_LOG(BIO_LOG_TRACE,    fmt, ##__VA_ARGS__)

void bio_log_impl(bio_log_level_t level,
                  const char *file, int line, const char *func,
                  const char *fmt, ...)
                  __attribute__((format(printf, 5, 6)));

/* ── Utility macros ───────────────────────────────────────────── */
#define BIO_ARRAY_SIZE(a)       (sizeof(a) / sizeof((a)[0]))
#define BIO_ALIGN_UP(x, align)  (((x) + (align) - 1) & ~((align) - 1))
#define BIO_MIN(a, b)           ((a) < (b) ? (a) : (b))
#define BIO_MAX(a, b)           ((a) > (b) ? (a) : (b))

/* Secure memory clearing — guaranteed not optimized away */
static inline void bio_secure_zero(void *ptr, size_t len)
{
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) *p++ = 0;
    __asm__ __volatile__("" ::: "memory");
}

/* ── Structured audit logging ────────────────────────────────── */

/**
 * Log a structured authentication event for audit trail.
 * These events are written to systemd journal with structured fields
 * that can be queried by security auditing tools.
 *
 * @param user    Username or UID string
 * @param event   Event type: "verify", "enroll", "delete", "login", "fido2"
 * @param result  Result: "success", "failure", "error", "rate_limited"
 * @param detail  Additional detail string (can be NULL)
 */
void bio_log_auth_event(const char *user, const char *event,
                        const char *result, const char *detail);

/* ── D-Bus constants ──────────────────────────────────────────── */
#define HIYA_DBUS_NAME       "org.hiya.Manager"
#define HIYA_DBUS_PATH       "/org/hiya/Manager"
#define HIYA_DBUS_INTERFACE  "org.hiya.Manager"

/* ── File system paths ────────────────────────────────────────── */
#define HIYA_STATE_DIR      "/var/lib/hiya"
#define HIYA_CONFIG_DIR     "/etc/hiya"
#define HIYA_CONFIG_FILE    "/etc/hiya/hiya.conf"
#define HIYA_RUN_DIR        "/run/hiya"

#ifdef __cplusplus
}
#endif

#endif /* BIO_COMMON_H */
