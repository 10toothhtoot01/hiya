/*
 * bio_fingerprint.h — Enhanced Fingerprint Wrapper over libfprint-2
 *
 * Copyright (C) 2024 Hiya Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Wraps libfprint-2 with:
 *   - Rate limiting (anti-brute-force)
 *   - Session tokens (bind verify to original enroll)
 *   - Async operation support via GLib main loop
 *   - Clean lifecycle management
 */

#ifndef BIO_FINGERPRINT_H
#define BIO_FINGERPRINT_H

#include "bio_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Forward declarations ────────────────────────────────────── */
typedef struct bio_fp_ctx       bio_fp_ctx_t;
typedef struct bio_fp_device    bio_fp_device_t;

/* ── Device information ──────────────────────────────────────── */
typedef struct {
    char     name[128];         /* Human-readable device name */
    char     driver[64];        /* Driver name (e.g. "goodixmoc") */
    uint16_t usb_vendor;        /* USB vendor ID */
    uint16_t usb_product;       /* USB product ID */
    bool     has_storage;       /* Device supports on-chip storage */
    bool     supports_identify; /* Device can identify (1:N) */
    int      nr_enroll_stages;  /* Number of touches for enrollment */
} bio_fp_device_info_t;

/* ── Enrollment progress callback ────────────────────────────── */
typedef enum {
    BIO_FP_ENROLL_STAGE_PASSED = 0,   /* Touch accepted, more needed */
    BIO_FP_ENROLL_COMPLETE     = 1,   /* Enrollment finished */
    BIO_FP_ENROLL_FAILED       = 2,   /* Enrollment failed */
    BIO_FP_ENROLL_RETRY        = 3,   /* Bad touch, try again */
    BIO_FP_ENROLL_RETRY_TOO_SHORT = 4,
    BIO_FP_ENROLL_RETRY_CENTER  = 5,
    BIO_FP_ENROLL_RETRY_REMOVE  = 6,
} bio_fp_enroll_status_t;

typedef void (*bio_fp_enroll_cb_t)(bio_fp_enroll_status_t status,
                                    int stage,
                                    int total_stages,
                                    void *user_data);

/* ── Verification result callback ────────────────────────────── */
typedef enum {
    BIO_FP_VERIFY_MATCH     = 0,
    BIO_FP_VERIFY_NO_MATCH  = 1,
    BIO_FP_VERIFY_ERROR     = 2,
    BIO_FP_VERIFY_RETRY     = 3,
} bio_fp_verify_status_t;

typedef void (*bio_fp_verify_cb_t)(bio_fp_verify_status_t status,
                                    void *user_data);

/* ── Enrollment result ────────────────────────────────────────── */
typedef struct {
    bio_fp_enroll_status_t status;
    bio_finger_t           finger;
    int                    stages_completed;
    int                    stages_total;
    int                    quality_score;     /* 0-100, -1 if unavailable */
    size_t                 print_data_len;
} bio_fp_enrollment_result_t;

/* ── Verification result ─────────────────────────────────────── */
typedef struct {
    bio_fp_verify_status_t status;
    bio_finger_t           matched_finger;    /* Which finger matched */
    int                    match_score;       /* 0-100, -1 if unavailable */
    int                    attempts_remaining; /* Before rate-limit lockout */
} bio_fp_verify_result_t;

/* ── Identify result ─────────────────────────────────────────── */
typedef struct {
    bool                   matched;
    bio_finger_t           matched_finger;
    int                    match_score;
} bio_fp_identify_result_t;

typedef void (*bio_fp_identify_cb_t)(const bio_fp_identify_result_t *result,
                                     void *user_data);

/* ── Rate limiter configuration ──────────────────────────────── */
typedef struct {
    int      max_attempts;         /* Max failed attempts before lockout */
    int      lockout_seconds;      /* Lockout duration in seconds */
    int      window_seconds;       /* Window for counting failures */
} bio_fp_rate_config_t;

/* Default rate limiter: 5 attempts, 30s lockout, 60s window */
#define BIO_FP_RATE_DEFAULT { .max_attempts = 5, \
                               .lockout_seconds = 30, \
                               .window_seconds = 60 }

/* ── Lifecycle ────────────────────────────────────────────────── */

/**
 * Initialize the fingerprint subsystem.
 * Creates a libfprint context internally.
 *
 * @param ctx_out   Receives the fingerprint context
 * @return BIO_OK on success
 */
int bio_fp_init(bio_fp_ctx_t **ctx_out);

/**
 * Cleanup and free the fingerprint context.
 */
void bio_fp_cleanup(bio_fp_ctx_t *ctx);

/* ── Device management ───────────────────────────────────────── */

/**
 * Enumerate available fingerprint devices.
 *
 * @param ctx        Fingerprint context
 * @param devices    Output array (caller-owned buffer)
 * @param max_devices  Maximum entries in devices array
 * @param count      Output: actual number of devices found
 */
int bio_fp_enumerate_devices(bio_fp_ctx_t *ctx,
                             bio_fp_device_info_t *devices,
                             size_t max_devices,
                             size_t *count);

/**
 * Open the first available fingerprint device.
 *
 * @param ctx        Fingerprint context
 * @param dev_out    Receives the device handle
 */
int bio_fp_open_device(bio_fp_ctx_t *ctx, bio_fp_device_t **dev_out);

/**
 * Close a fingerprint device.
 */
void bio_fp_close_device(bio_fp_device_t *dev);

/**
 * Get device info for an open device.
 */
int bio_fp_get_device_info(bio_fp_device_t *dev, bio_fp_device_info_t *info);

/* ── Enrollment ──────────────────────────────────────────────── */

/**
 * Enroll a fingerprint (blocking).
 *
 * The callback is called for each enrollment stage.
 * On success, the serialized print data is written to out_data.
 *
 * @param dev        Device handle
 * @param finger     Which finger is being enrolled
 * @param callback   Progress callback
 * @param user_data  Opaque pointer passed to callback
 * @param out_data   Output: serialized fingerprint print data
 * @param out_len    In: buffer size, Out: actual data size
 */
int bio_fp_enroll(bio_fp_device_t *dev,
                  bio_finger_t finger,
                  bio_fp_enroll_cb_t callback,
                  void *user_data,
                  uint8_t *out_data, size_t *out_len);

/* ── Verification ────────────────────────────────────────────── */

/**
 * Verify a fingerprint against a stored print (blocking).
 *
 * @param dev         Device handle
 * @param print_data  Serialized print data (from enrollment)
 * @param print_len   Print data length
 * @param callback    Result callback
 * @param user_data   Opaque pointer passed to callback
 */
int bio_fp_verify(bio_fp_device_t *dev,
                  const uint8_t *print_data, size_t print_len,
                  bio_fp_verify_cb_t callback,
                  void *user_data,
                  int timeout_ms);  /* 0 = use default BIO_FP_VERIFY_TIMEOUT_MS */

/* ── Print management ────────────────────────────────────────── */

/**
 * List enrolled prints on the device (for devices with storage).
 *
 * @param dev        Device handle
 * @param fingers    Output array of enrolled finger IDs
 * @param max        Maximum entries
 * @param count      Output: actual count
 */
int bio_fp_list_prints(bio_fp_device_t *dev,
                       bio_finger_t *fingers,
                       size_t max,
                       size_t *count);

/**
 * Delete an enrolled print from the device.
 */
int bio_fp_delete_print(bio_fp_device_t *dev,
                        bio_finger_t finger);

/**
 * Delete all enrolled prints from the device.
 *
 * @param dev        Device handle
 * @return BIO_OK on success
 */
int bio_fp_delete_all_prints(bio_fp_device_t *dev);

/* ── Identification (1:N) ────────────────────────────────────── */

/**
 * Identify a fingerprint against all enrolled prints (1:N matching).
 * The device must support identification (supports_identify = true).
 *
 * @param dev          Device handle
 * @param gallery      Array of serialized prints to match against
 * @param gallery_lens Lengths of each serialized print
 * @param gallery_size Number of prints in gallery
 * @param result       Output: identification result
 * @return BIO_OK if matched, BIO_ERR_FP_NO_MATCH if no match
 */
int bio_fp_identify(bio_fp_device_t *dev,
                    const uint8_t *const *gallery,
                    const size_t *gallery_lens,
                    size_t gallery_size,
                    bio_fp_identify_result_t *result);

/* ── Enhanced enrollment info ────────────────────────────────── */

/**
 * Enroll a fingerprint with detailed result info.
 *
 * @param dev         Device handle
 * @param finger      Which finger
 * @param callback    Progress callback
 * @param user_data   Opaque pointer
 * @param out_data    Output: serialized print data
 * @param out_len     In: buffer size, Out: actual size
 * @param result      Output: detailed enrollment result
 */
int bio_fp_enroll_ex(bio_fp_device_t *dev,
                     bio_finger_t finger,
                     bio_fp_enroll_cb_t callback,
                     void *user_data,
                     uint8_t *out_data, size_t *out_len,
                     bio_fp_enrollment_result_t *result);

/* ── Rate limiting ───────────────────────────────────────────── */

/**
 * Configure rate limiting for a device.
 */
int bio_fp_set_rate_limit(bio_fp_device_t *dev,
                          const bio_fp_rate_config_t *config);

/**
 * Check if rate-limited (locked out).
 * Returns BIO_OK if allowed, BIO_ERR_FP_RATE_LIMIT if locked out.
 * On lockout, remaining_seconds is set to the remaining wait time.
 */
int bio_fp_check_rate_limit(bio_fp_device_t *dev,
                            int *remaining_seconds);

/**
 * Record a failed verification attempt (for rate limiting).
 */
void bio_fp_record_failure(bio_fp_device_t *dev);

/**
 * Reset the rate limiter (e.g., after successful auth).
 */
void bio_fp_reset_rate_limit(bio_fp_device_t *dev);

#ifdef __cplusplus
}
#endif

#endif /* BIO_FINGERPRINT_H */
