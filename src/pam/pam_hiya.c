/*
 * pam_hiya.c — PAM Authentication Module for Hiya
 *
 * Copyright (C) 2024 Hiya Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Implements pam_sm_authenticate and pam_sm_setcred.
 * Communicates with hiya-authd via system D-Bus.
 *
 * Flow:
 *   1. Parse module options (timeout, debug, fallback, try_first)
 *   2. Get the username via pam_get_user()
 *   3. Resolve UID from username
 *   4. Connect to system D-Bus
 *   5. Check if the daemon has a fingerprint device
 *   6. Check if the user has enrolled fingers (GetEnrolledFingers)
 *   7. Call org.hiya.Manager.CreateSession()
 *   8. Prompt the user to place their finger
 *   9. Call org.hiya.Manager.Verify(session_token)
 *  10. Return PAM_SUCCESS if match, handle try_first / fallback
 */

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT
#define PAM_SM_SESSION

#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <syslog.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <pwd.h>

#include <gio/gio.h>

#include "pam/pam_hiya.h"

/* ── Logging helpers ─────────────────────────────────────────── */

#define pam_dbg(pamh, cfg, fmt, ...)                              \
    do {                                                           \
        if ((cfg)->debug)                                         \
            pam_syslog((pamh), LOG_DEBUG,                         \
                       "pam_hiya: " fmt, ##__VA_ARGS__);       \
    } while (0)

#define pam_err(pamh, fmt, ...)                                   \
    pam_syslog((pamh), LOG_ERR,                                   \
               "pam_hiya: " fmt, ##__VA_ARGS__)

#define pam_inf(pamh, fmt, ...)                                   \
    pam_syslog((pamh), LOG_INFO,                                  \
               "pam_hiya: " fmt, ##__VA_ARGS__)

/* ── Option parsing ──────────────────────────────────────────── */

static void parse_config(pam_hiya_config_t *cfg,
                          int argc, const char **argv)
{
    cfg->timeout_sec = PAM_HIYA_DEFAULT_TIMEOUT;
    cfg->debug = false;
    cfg->try_first = false;
    cfg->fallback = true;

    for (int i = 0; i < argc; i++) {
        if (strncmp(argv[i], "timeout=", 8) == 0) {
            char *endptr;
            errno = 0;
            long t = strtol(argv[i] + 8, &endptr, 10);
            if (endptr != argv[i] + 8 && *endptr == '\0' &&
                errno != ERANGE && t > 0 && t <= 120) {
                cfg->timeout_sec = (int)t;
            }
        } else if (strcmp(argv[i], "debug") == 0) {
            cfg->debug = true;
        } else if (strcmp(argv[i], "try_first") == 0) {
            cfg->try_first = true;
        } else if (strcmp(argv[i], "fallback") == 0) {
            cfg->fallback = true;
        } else if (strcmp(argv[i], "nofallback") == 0) {
            cfg->fallback = false;
        }
    }
}

/* ── D-Bus helpers ───────────────────────────────────────────── */

static GDBusConnection *get_system_bus(void)
{
    GError *err = NULL;
    GDBusConnection *conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &err);
    if (!conn || err) {
        if (err) {
            /* Log the error before discarding it */
            syslog(LOG_ERR, "pam_hiya: D-Bus connect failed: %s",
                   err->message);
            g_error_free(err);
        }
        return NULL;
    }
    return conn;
}

/* Check if the daemon is running and has a fingerprint device */
static bool daemon_has_device(GDBusConnection *conn)
{
    GError *err = NULL;
    GVariant *result = g_dbus_connection_call_sync(
        conn,
        "org.hiya.Manager",
        "/org/hiya/Manager",
        "org.hiya.Manager",
        "GetDevices",
        NULL,
        G_VARIANT_TYPE("(a(ssbbn))"),
        G_DBUS_CALL_FLAGS_NONE,
        5000, /* 5s timeout for device check */
        NULL, &err);

    if (!result || err) {
        if (err) g_error_free(err);
        return false;
    }

    GVariantIter *iter;
    g_variant_get(result, "(a(ssbbn))", &iter);
    bool has = (g_variant_iter_n_children(iter) > 0);
    g_variant_iter_free(iter);
    g_variant_unref(result);

    return has;
}

/* Check if the user has any enrolled fingerprints */
static int get_enrolled_count(GDBusConnection *conn, uid_t uid)
{
    GError *err = NULL;
    GVariant *result = g_dbus_connection_call_sync(
        conn,
        "org.hiya.Manager",
        "/org/hiya/Manager",
        "org.hiya.Manager",
        "GetEnrolledFingers",
        g_variant_new("(u)", (guint32)uid),
        G_VARIANT_TYPE("(an)"),
        G_DBUS_CALL_FLAGS_NONE,
        5000, NULL, &err);

    if (!result || err) {
        if (err) g_error_free(err);
        return -1;  /* Error: cannot determine */
    }

    GVariantIter *iter;
    g_variant_get(result, "(an)", &iter);
    int count = (int)g_variant_iter_n_children(iter);
    g_variant_iter_free(iter);
    g_variant_unref(result);

    return count;
}

/* Create a session and get the token back */
static bool create_session(GDBusConnection *conn,
                            uid_t target_uid,
                            uint8_t *token_out, size_t *token_len,
                            int timeout_ms)
{
    GError *err = NULL;
    GVariant *result = g_dbus_connection_call_sync(
        conn,
        "org.hiya.Manager",
        "/org/hiya/Manager",
        "org.hiya.Manager",
        "CreateSession",
        g_variant_new("(u)", (guint32)target_uid),
        G_VARIANT_TYPE("(ay)"),
        G_DBUS_CALL_FLAGS_NONE,
        timeout_ms,
        NULL, &err);

    if (!result || err) {
        if (err) g_error_free(err);
        return false;
    }

    GVariant *token_var;
    g_variant_get(result, "(@ay)", &token_var);

    gsize len = 0;
    const uint8_t *data = g_variant_get_fixed_array(token_var, &len, 1);

    if (!data || len == 0) {
        g_variant_unref(token_var);
        g_variant_unref(result);
        *token_len = 0;
        return false;
    }
    if (len > *token_len) len = *token_len;
    memcpy(token_out, data, len);
    *token_len = len;

    g_variant_unref(token_var);
    g_variant_unref(result);
    return true;
}

/* Call Verify with the session token */
static int call_verify(GDBusConnection *conn,
                        const uint8_t *token, size_t token_len,
                        int fp_timeout_ms __attribute__((unused)), int dbus_timeout_ms)
{
    /* Build (ay) tuple — daemon Verify method accepts token bytes only. */
    GVariantBuilder builder;
    g_variant_builder_init(&builder, G_VARIANT_TYPE("(ay)"));
    g_variant_builder_open(&builder, G_VARIANT_TYPE("ay"));
    for (size_t i = 0; i < token_len; i++)
        g_variant_builder_add(&builder, "y", token[i]);
    g_variant_builder_close(&builder);
    GVariant *params = g_variant_builder_end(&builder);

    GError *err = NULL;
    GVariant *result = g_dbus_connection_call_sync(
        conn,
        "org.hiya.Manager",
        "/org/hiya/Manager",
        "org.hiya.Manager",
        "Verify",
        params,
        G_VARIANT_TYPE("(b)"),
        G_DBUS_CALL_FLAGS_NONE,
        dbus_timeout_ms,
        NULL, &err);

    if (!result || err) {
        syslog(LOG_ERR, "pam_hiya: Verify D-Bus call failed: %s",
               err ? err->message : "null result, no error");
        if (err) g_error_free(err);
        return -1;
    }

    gboolean matched;
    g_variant_get(result, "(b)", &matched);
    g_variant_unref(result);

    return matched ? 1 : 0;
}

/* ── PAM entry points ────────────────────────────────────────── */

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh,
                                    int flags,
                                    int argc,
                                    const char **argv)
{
    pam_hiya_config_t cfg;
    parse_config(&cfg, argc, argv);

    pam_dbg(pamh, &cfg, "authenticate called (timeout=%d, "
            "try_first=%d, fallback=%d)",
            cfg.timeout_sec, cfg.try_first, cfg.fallback);

    /* Step 1: Get the username being authenticated */
    const char *username = NULL;
    int pam_rc = pam_get_user(pamh, &username, NULL);
    if (pam_rc != PAM_SUCCESS || !username || username[0] == '\0') {
        pam_err(pamh, "cannot determine username: %s",
                pam_strerror(pamh, pam_rc));
        return cfg.fallback ? PAM_IGNORE : PAM_AUTH_ERR;
    }

    pam_dbg(pamh, &cfg, "authenticating user: %s", username);

    /* Step 2: Resolve UID from username (thread-safe) */
    struct passwd pw_buf;
    char pw_str_buf[1024];
    struct passwd *pw = NULL;
    int pw_rc = getpwnam_r(username, &pw_buf, pw_str_buf,
                           sizeof(pw_str_buf), &pw);
    if (pw_rc != 0 || !pw) {
        pam_err(pamh, "user '%s' not found in passwd", username);
        return cfg.fallback ? PAM_IGNORE : PAM_USER_UNKNOWN;
    }
    uid_t uid = pw->pw_uid;
    pam_dbg(pamh, &cfg, "resolved UID: %u", (unsigned)uid);

    /* Step 3: Connect to system bus */
    GDBusConnection *conn = get_system_bus();
    if (!conn) {
        pam_err(pamh, "cannot connect to system D-Bus");
        return cfg.fallback ? PAM_IGNORE : PAM_AUTH_ERR;
    }

    /* Step 4: Check if daemon is alive and has a device */
    if (!daemon_has_device(conn)) {
        pam_dbg(pamh, &cfg, "no fingerprint device available");
        g_object_unref(conn);
        return cfg.fallback ? PAM_IGNORE : PAM_AUTH_ERR;
    }

    /* Step 5: Check if user has any enrolled fingerprints */
    int enrolled = get_enrolled_count(conn, uid);
    if (enrolled == 0) {
        pam_dbg(pamh, &cfg, "user %s has no enrolled fingerprints", username);
        g_object_unref(conn);
        /* No enrollments: if try_first, fail hard; otherwise skip */
        return cfg.try_first ? PAM_AUTH_ERR : PAM_IGNORE;
    } else if (enrolled < 0) {
        pam_dbg(pamh, &cfg, "could not query enrollments for %s", username);
        /* If we can't determine enrollment status, continue to try verify */
    } else {
        pam_dbg(pamh, &cfg, "user %s has %d enrolled finger(s)",
                username, enrolled);
    }

    /* Step 6: Create session */
    uint8_t token[32];
    size_t token_len = sizeof(token);
    /* fp_timeout_ms: how long bio_fp_verify runs on the sensor.
     * dbus_timeout_ms: how long pam_hiya waits for the D-Bus call.
     * dbus > fp by 2s so the daemon always cancels fp_device_verify
     * before the D-Bus call times out — this keeps fp_lock from being
     * held after PAM gives up, which caused the stuck-sensor bug. */
    int fp_timeout_ms   = cfg.timeout_sec * 1000;
    int dbus_timeout_ms = fp_timeout_ms + 2000;

    if (!create_session(conn, uid, token, &token_len, dbus_timeout_ms)) {
        pam_err(pamh, "failed to create Hiya session");
        g_object_unref(conn);
        return cfg.fallback ? PAM_IGNORE : PAM_AUTH_ERR;
    }

    pam_dbg(pamh, &cfg, "session created, starting verification");

    /* Step 7: Tell the user to touch the sensor.
     * PAM_TEXT_INFO is display-only — no input field, no "Password:" label.
     * sudo, SDDM, and polkit all pass it through to the terminal/UI.
     * PAM_PROMPT_ECHO_OFF was wrong: it opens an input field which sudo
     * labels "Password:" and swallows silently or confuses the user.
     * Verify starts immediately after — no input needed from the user. */
    pam_info(pamh, "Touch fingerprint sensor...");

    /* Step 8: Call verify */
    int verify_rc = call_verify(conn, token, token_len, fp_timeout_ms, dbus_timeout_ms);

    /* Securely clear token */
    explicit_bzero(token, sizeof(token));
    g_object_unref(conn);

    /* Step 9: Interpret result */
    if (verify_rc == 1) {
        pam_inf(pamh, "fingerprint authentication succeeded for %s",
                username);
        return PAM_SUCCESS;
    } else if (verify_rc == 0) {
        pam_inf(pamh, "fingerprint did not match for %s", username);
        /*
         * try_first: return AUTH_ERR so the PAM stack does NOT fall
         *            through to password.
         * !try_first: return IGNORE so the PAM stack continues to
         *            the next module (e.g., pam_unix for password).
         */
        return cfg.try_first ? PAM_AUTH_ERR : PAM_IGNORE;
    } else {
        pam_err(pamh, "verification call failed for %s", username);
        return cfg.fallback ? PAM_IGNORE : PAM_AUTH_ERR;
    }
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh,
                                int flags,
                                int argc,
                                const char **argv)
{
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_SUCCESS;
}

/* For static linking support */
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh,
                                  int flags,
                                  int argc,
                                  const char **argv)
{
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh,
                                    int flags,
                                    int argc,
                                    const char **argv)
{
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh,
                                     int flags,
                                     int argc,
                                     const char **argv)
{
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)argv;
    return PAM_SUCCESS;
}
