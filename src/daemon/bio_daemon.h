/*
 * bio_daemon.h — BioAuth D-Bus Daemon Interface
 *
 * Copyright (C) 2024 BioAuth Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * biometric-authd: system D-Bus service that coordinates
 * fingerprint enrollment/verification, TPM operations,
 * and exposes the org.bioauth.Manager interface.
 */

#ifndef BIO_DAEMON_H
#define BIO_DAEMON_H

#include "bio_common.h"
#include <sys/types.h>
#include <time.h>

#ifdef __cplusplus
extern "C"
{
#endif

    /* ── Session management ──────────────────────────────────────── */

#define BIO_SESSION_TOKEN_SIZE 32
#define BIO_SESSION_MAX_AGE 300 /* 5 minutes */
#define BIO_MAX_SESSIONS 64

    typedef struct
    {
        uint8_t token[BIO_SESSION_TOKEN_SIZE];
        uint8_t session_key[32]; /* Derived key for challenge-response */
        uid_t uid;
        pid_t pid;
        time_t created;
        time_t last_used;
        bool active;
        bool verified;            /* Set to true after successful verification */
        uint8_t verify_token[32]; /* HMAC(session_key, uid||timestamp||nonce) */
        bool has_verify_token;
        char sender[256]; /* D-Bus sender (unique name) */
    } bio_session_t;

    /* ── Enrollment storage ──────────────────────────────────────── */

#define BIO_MAX_ENROLLMENTS_PER_USER 10
#define BIO_MAX_PRINT_DATA_SIZE 8192

    typedef struct
    {
        uid_t uid;
        bio_finger_t finger;
        uint8_t print_data[BIO_MAX_PRINT_DATA_SIZE];
        size_t print_data_len;
        uint8_t sealed_blob[1024]; /* TPM-sealed credential */
        size_t sealed_blob_len;
        char label[64]; /* User-assigned label */
        time_t created;
    } bio_enrollment_t;

    /* ── Daemon configuration ────────────────────────────────────── */

    typedef struct
    {
        int max_sessions;               /* Default: 64 */
        int session_max_age_seconds;    /* Default: 300 */
        int max_enrollments_per_user;   /* Default: 10 */
        int rate_limit_max_attempts;    /* Default: 5 */
        int rate_limit_lockout_seconds; /* Default: 30 */
        int rate_limit_window_seconds;  /* Default: 60 */
        bool tpm_enabled;               /* Default: true */
        bool tpm_fallback_to_plaintext; /* Default: false (H2 fix) */
        bool tpm_require;               /* Default: false */
        bool tpm_pcr_binding;           /* Default: false */
        uint32_t tpm_pcr_index;         /* Default: 7 */
        uint32_t tpm_primary_handle;    /* Default: 0x81000100 */
        char tpm_device[64];            /* Default: /dev/tpmrm0 */
        char howdy_binary[256];         /* Default: howdy */
        int vault_idle_timeout_seconds; /* Default: 1800 (30 min) */
        char state_dir[256];            /* Default: /var/lib/bioauth */
        char config_file[256];          /* Source config file */
        char device_driver[64];         /* Preferred driver or empty */
        bool log_to_journal;            /* Default: true */
        int log_level;                  /* Default: BIO_LOG_DEBUG */
    } bio_daemon_config_t;

    /**
     * Initialize config with defaults.
     */
    void bio_daemon_config_defaults(bio_daemon_config_t *cfg);

    /**
     * Parse a configuration file (INI-style).
     *
     * @param path    Path to config file
     * @param cfg     Config struct to populate
     * @return BIO_OK on success
     */
    int bio_daemon_config_load(const char *path, bio_daemon_config_t *cfg);

    /**
     * Determine whether plaintext template fallback is permitted.
     * Returns false when require_tpm policy is enabled.
     */
    bool bio_daemon_tpm_plaintext_fallback_allowed(
        const bio_daemon_config_t *cfg);

    /* ── Persistent enrollment storage ───────────────────────────── */

    /**
     * Save all enrollments to persistent storage.
     *
     * @param state_dir   Directory for enrollment files
     * @param enrollments Array of enrollments
     * @param count       Number of enrollments
     * @return BIO_OK on success
     */
    int bio_daemon_save_enrollments(const char *state_dir,
                                    const bio_enrollment_t *enrollments,
                                    size_t count);

    /**
     * Load all enrollments from persistent storage.
     *
     * @param state_dir    Directory with enrollment files
     * @param enrollments  Output: dynamically allocated array
     * @param count        Output: number of enrollments loaded
     * @return BIO_OK on success
     */
    int bio_daemon_load_enrollments(const char *state_dir,
                                    bio_enrollment_t **enrollments,
                                    size_t *count);

    /* ── Challenge-response ──────────────────────────────────────── */

    /**
     * Generate a nonce challenge for verification.
     *
     * @param challenge    Output: 32-byte challenge nonce
     * @return BIO_OK on success
     */
    int bio_daemon_generate_challenge(uint8_t challenge[32]);

    /**
     * Verify a challenge response (HMAC-based).
     *
     * @param challenge       The original challenge
     * @param response        The client's HMAC response
     * @param response_len    Response length
     * @param session_key     The session key (from TPM unseal or derived)
     * @param key_len         Key length
     * @return BIO_OK if valid
     */
    int bio_daemon_verify_challenge(const uint8_t challenge[32],
                                    const uint8_t *response, size_t response_len,
                                    const uint8_t *session_key, size_t key_len);

    /* ── Daemon state ────────────────────────────────────────────── */

    typedef struct bio_daemon bio_daemon_t;

    /* ── Lifecycle ────────────────────────────────────────────────── */

    /**
     * Create and initialize the daemon.
     *
     * @param daemon_out  Receives the daemon instance
     * @return BIO_OK on success
     */
    int bio_daemon_create(bio_daemon_t **daemon_out);

    /**
     * Run the daemon main loop (blocking).
     * Returns when the daemon is signaled to stop.
     */
    int bio_daemon_run(bio_daemon_t *daemon);

    /**
     * Request the daemon to stop.
     * Can be called from a signal handler.
     */
    void bio_daemon_stop(bio_daemon_t *daemon);

    /**
     * Destroy the daemon and free all resources.
     */
    void bio_daemon_destroy(bio_daemon_t *daemon);

    /**
     * Main entry point for the daemon process.
     */
    int bio_daemon_main(int argc, char **argv);

    /* ── D-Bus method handlers ───────────────────────────────────── */
    /* These are called by the D-Bus message dispatcher internally.
     * Documented here for API completeness. */

    /**
     * GetDevices() → a(ssbbn)
     * Returns array of (name, driver, has_storage, supports_identify, nr_stages)
     */

    /**
     * CreateSession() → ay
     * Returns a 32-byte session token.
     * Session is bound to the calling UID/PID.
     */

    /**
     * GetEnrolledFingers(uid: u) → an
     * Returns array of enrolled finger IDs for the given user.
     */

    /**
     * Enroll(finger: n, label: s) → b
     * Starts enrollment for the caller's UID.
     * Emits EnrollProgress signals during the process.
     */

    /**
     * DeleteEnrollment(finger: n) → b
     * Deletes an enrollment for the caller's UID.
     */

    /**
     * Verify(session_token: ay) → b
     * Verifies the caller's fingerprint using the session.
     * On success, the session is marked as verified.
     */

    /* ── Signals (emitted by daemon) ─────────────────────────────── */

    /**
     * EnrollProgress(status: n, stage: n, total: n)
     * Enrollment progress notification.
     */

    /**
     * VerifyResult(match: b)
     * Verification result.
     */

    /**
     * DeviceAdded(name: s)
     * DeviceRemoved(name: s)
     * Hotplug notifications.
     */

    /* ── Internal API for fprintd compatibility layer ────────────── */

    /**
     * Verify a user's fingerprint (internal, called by fprintd compat).
     *
     * @param daemon  Daemon instance
     * @param user    Username to verify
     * @return BIO_OK on match, error code otherwise
     */
    int bio_daemon_verify_user(bio_daemon_t *daemon, const char *user);

    /**
     * Enroll a user's fingerprint (internal, called by fprintd compat).
     *
     * @param daemon  Daemon instance
     * @param user    Username to enroll
     * @param finger  Finger name (e.g., "right-index-finger")
     * @return BIO_OK on success
     */
    int bio_daemon_enroll_user(bio_daemon_t *daemon, const char *user,
                               const char *finger);

    /**
     * Delete all enrollments for a user (internal, called by fprintd compat).
     *
     * @param daemon  Daemon instance
     * @param user    Username whose enrollments to delete
     * @return BIO_OK on success
     */
    int bio_daemon_delete_enrollments(bio_daemon_t *daemon, const char *user);

    /**
     * List enrolled fingers for a user (internal, called by fprintd compat).
     *
     * Writes up to max_fingers bio_finger_t values into the fingers array.
     *
     * @param daemon       Daemon instance
     * @param user         Username to query
     * @param fingers      Output array of finger IDs
     * @param max_fingers  Capacity of the fingers array
     * @return Number of enrolled fingers found (>= 0), or negative errno on error
     */
    int bio_daemon_list_enrolled_fingers(bio_daemon_t *daemon, const char *user,
                                         bio_finger_t *fingers, int max_fingers);

    /**
     * Get the fingerprint context from the daemon (for fprintd compat layer).
     * Returns the fp_ctx pointer or NULL if not available.
     */
    struct bio_fp_ctx *bio_daemon_get_fp_ctx(bio_daemon_t *daemon);

#ifdef __cplusplus
}
#endif

#endif /* BIO_DAEMON_H */
