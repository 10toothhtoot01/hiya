/*
 * bio_daemon.c — BioAuth D-Bus System Daemon Implementation
 *
 * Copyright (C) 2024 BioAuth Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Main daemon process that:
 *   1. Connects to the system D-Bus
 *   2. Owns the org.bioauth.Manager name
 *   3. Handles method calls (GetDevices, Enroll, Verify, etc.)
 *   4. Manages sessions and enrollments
 *   5. Interfaces with fingerprint + TPM subsystems
 *   6. Logs to systemd journal
 */

#include "daemon/bio_daemon.h"
#include "daemon/bio_fprintd_compat.h"
#include "fingerprint/bio_fingerprint.h"
#include "crypto/bio_crypto.h"
#include "pm/pm_bio_wrap.h"
#include "pm/pm_entry_store.h"
#include "pm/pm_otp.h"
#include "pm/pm_secure_mem.h"
#include "pm/pm_vault_store.h"
#include "tpm/bio_tpm.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <pwd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <syslog.h>
#include <dirent.h>
#include <stdio.h>
#include <pthread.h>
#include <limits.h>

#include <gio/gio.h>
#include <systemd/sd-journal.h>

#define BIOAUTH_VAULT_DBUS_NAME "org.bioauth.Vault"
#define BIOAUTH_VAULT_DBUS_INTERFACE "org.bioauth.Vault"
#define BIOAUTH_DAEMON_DBUS_NAME "org.bioauth.Daemon"
#define BIOAUTH_DAEMON_DBUS_PATH "/org/bioauth/Daemon"
#define BIOAUTH_AUTH_DBUS_INTERFACE "org.bioauth.Auth"
#define BIOAUTH_ENROLL_DBUS_INTERFACE "org.bioauth.Enroll"
#define BIO_MAX_VAULTS 64

#define PASSKEY_KIND_VALUE "passkey"
#define PASSKEY_FIELD_KIND "bioauth.kind"
#define PASSKEY_FIELD_RP_ID "passkey.rp_id"
#define PASSKEY_FIELD_USER_ID "passkey.user_id"
#define PASSKEY_FIELD_PRIVATE_KEY_B64 "passkey.private_key_b64"
#define PASSKEY_FIELD_PUBLIC_KEY_B64 "passkey.public_key_b64"

#define BIOAUTH_HOWDY_BIN_ENV "BIOAUTH_HOWDY_BIN"
#define BIO_MAX_FACE_ENROLL_SESSIONS 16
#define BIO_FACE_ENROLL_SESSION_TTL 900

static const char *g_startup_config_path = NULL;
static bool g_startup_force_no_tpm = false;
static bool g_startup_force_debug = false;

static void emit_vault_locked_property_changed(GDBusConnection *connection,
                                               gboolean locked);
static void emit_vault_state_changed(bio_daemon_t *d, const char *state);
static void emit_vault_unlocked(bio_daemon_t *d, uid_t uid);
static void emit_uv_success(bio_daemon_t *d,
                            const char *session_id,
                            const char *username);

/* ── Audit log helper (formats uid + detail) ─────────────────── */

static void daemon_log_auth(uid_t uid, const char *event,
                            const char *result, const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));

static void daemon_log_auth(uid_t uid, const char *event,
                            const char *result, const char *fmt, ...)
{
    char user_str[32];
    snprintf(user_str, sizeof(user_str), "%u", uid);

    char detail[256] = {0};
    if (fmt)
    {
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(detail, sizeof(detail), fmt, ap);
        va_end(ap);
    }

    bio_log_auth_event(user_str, event, result,
                       detail[0] ? detail : NULL);
}

/* ── D-Bus Interface XML ─────────────────────────────────────── */

static const char *introspection_xml =
    "<node>"
    "  <interface name='" BIOAUTH_DBUS_INTERFACE "'>"
    ""
    "    <method name='GetDevices'>"
    "      <arg direction='out' type='a(ssbbn)' name='devices'/>"
    "    </method>"
    ""
    "    <method name='CreateSession'>"
    "      <arg direction='in'  type='u'  name='uid'/>"
    "      <arg direction='out' type='ay' name='session_token'/>"
    "    </method>"
    ""
    "    <method name='GetEnrolledFingers'>"
    "      <arg direction='in'  type='u' name='uid'/>"
    "      <arg direction='out' type='an' name='fingers'/>"
    "    </method>"
    ""
    "    <method name='Enroll'>"
    "      <arg direction='in'  type='n' name='finger'/>"
    "      <arg direction='in'  type='s' name='label'/>"
    "      <arg direction='out' type='b' name='success'/>"
    "    </method>"
    ""
    "    <method name='DeleteEnrollment'>"
    "      <arg direction='in'  type='n' name='finger'/>"
    "      <arg direction='out' type='b' name='success'/>"
    "    </method>"
    ""
    "    <method name='ClearDevice'>"
    "      <arg direction='out' type='b' name='success'/>"
    "    </method>"
    ""
    "    <method name='Verify'>"
    "      <arg direction='in'  type='ay' name='session_token'/>"
    "      <arg direction='out' type='b' name='match'/>"
    "    </method>"
    ""
    "    <method name='VerifyUser'>"
    "      <arg direction='in'  type='s' name='username'/>"
    "      <arg direction='out' type='b' name='authenticated'/>"
    "    </method>"
    ""
    "    <method name='GetPreferences'>"
    "      <arg direction='out' type='s' name='json'/>"
    "    </method>"
    ""
    "    <method name='SetPreferences'>"
    "      <arg direction='in'  type='s' name='json'/>"
    "      <arg direction='out' type='b' name='success'/>"
    "    </method>"
    ""
    "    <signal name='EnrollProgress'>"
    "      <arg type='n' name='status'/>"
    "      <arg type='n' name='stage'/>"
    "      <arg type='n' name='total'/>"
    "    </signal>"
    ""
    "    <signal name='VerifyResult'>"
    "      <arg type='b' name='match'/>"
    "    </signal>"
    ""
    "    <signal name='DeviceAdded'>"
    "      <arg type='s' name='name'/>"
    "    </signal>"
    ""
    "    <signal name='DeviceRemoved'>"
    "      <arg type='s' name='name'/>"
    "    </signal>"
    ""
    "  </interface>"
    ""
    "  <interface name='" BIOAUTH_AUTH_DBUS_INTERFACE "'>"
    "    <method name='Authenticate'>"
    "      <arg direction='in' type='s' name='reason'/>"
    "      <arg direction='out' type='b' name='success'/>"
    "      <arg direction='out' type='s' name='method_used'/>"
    "    </method>"
    ""
    "    <method name='AuthenticateInteractive'>"
    "      <arg direction='in' type='s' name='reason'/>"
    "      <arg direction='in' type='u' name='timeout_ms'/>"
    "      <arg direction='out' type='b' name='success'/>"
    "    </method>"
    ""
    "    <method name='IsAuthenticated'>"
    "      <arg direction='out' type='b' name='authenticated'/>"
    "      <arg direction='out' type='u' name='seconds_remaining'/>"
    "    </method>"
    ""
    "    <method name='ExtendSession'>"
    "      <arg direction='in' type='u' name='seconds'/>"
    "    </method>"
    ""
    "    <method name='RevokeSession'/>"
    ""
    "    <signal name='AuthStateChanged'>"
    "      <arg type='b' name='authenticated'/>"
    "      <arg type='s' name='method'/>"
    "    </signal>"
    ""
    "    <signal name='UV_SUCCESS'>"
    "      <arg type='s' name='session_id'/>"
    "      <arg type='s' name='user'/>"
    "    </signal>"
    "  </interface>"
    ""
    "  <interface name='" BIOAUTH_ENROLL_DBUS_INTERFACE "'>"
    "    <method name='StartFaceEnroll'>"
    "      <arg direction='in' type='s' name='label'/>"
    "      <arg direction='out' type='s' name='session_id'/>"
    "    </method>"
    ""
    "    <method name='GetEnrollFrame'>"
    "      <arg direction='in' type='s' name='session_id'/>"
    "      <arg direction='out' type='ay' name='jpeg_bytes'/>"
    "      <arg direction='out' type='s' name='status'/>"
    "    </method>"
    ""
    "    <method name='CommitFaceEnroll'>"
    "      <arg direction='in' type='s' name='session_id'/>"
    "      <arg direction='out' type='b' name='success'/>"
    "    </method>"
    ""
    "    <method name='AbortEnroll'>"
    "      <arg direction='in' type='s' name='session_id'/>"
    "    </method>"
    ""
    "    <method name='StartFingerEnroll'>"
    "      <arg direction='in' type='s' name='finger_id'/>"
    "      <arg direction='in' type='s' name='label'/>"
    "      <arg direction='out' type='s' name='session_id'/>"
    "    </method>"
    ""
    "    <method name='ListEnrolledFaces'>"
    "      <arg direction='out' type='aa{ss}' name='faces'/>"
    "    </method>"
    ""
    "    <method name='ListEnrolledFingers'>"
    "      <arg direction='out' type='aa{ss}' name='fingers'/>"
    "    </method>"
    ""
    "    <method name='RemoveFace'>"
    "      <arg direction='in' type='s' name='face_id'/>"
    "    </method>"
    ""
    "    <method name='RemoveFinger'>"
    "      <arg direction='in' type='s' name='finger_id'/>"
    "    </method>"
    ""
    "    <signal name='EnrollProgress'>"
    "      <arg type='s' name='session_id'/>"
    "      <arg type='u' name='percent'/>"
    "      <arg type='s' name='hint'/>"
    "    </signal>"
    "  </interface>"
    ""
    "  <interface name='" BIOAUTH_VAULT_DBUS_INTERFACE "'>"
    "    <method name='GetCredential'>"
    "      <arg direction='in'  type='s' name='url'/>"
    "      <arg direction='in'  type='s' name='field'/>"
    "      <arg direction='out' type='s' name='value'/>"
    "    </method>"
    ""
    "    <method name='GetAllCredentials'>"
    "      <arg direction='in'  type='s' name='url'/>"
    "      <arg direction='out' type='a{ss}' name='fields'/>"
    "    </method>"
    ""
    "    <method name='GetTOTP'>"
    "      <arg direction='in'  type='s' name='entry_id'/>"
    "      <arg direction='out' type='s' name='code'/>"
    "      <arg direction='out' type='u' name='remaining_seconds'/>"
    "    </method>"
    ""
    "    <method name='Search'>"
    "      <arg direction='in'  type='s' name='query'/>"
    "      <arg direction='in'  type='s' name='url'/>"
    "      <arg direction='out' type='s' name='json'/>"
    "    </method>"
    ""
    "    <method name='SearchAdvanced'>"
    "      <arg direction='in'  type='s' name='query'/>"
    "      <arg direction='in'  type='s' name='url'/>"
    "      <arg direction='in'  type='s' name='group_id'/>"
    "      <arg direction='in'  type='b' name='include_descendants'/>"
    "      <arg direction='out' type='s' name='json'/>"
    "    </method>"
    ""
    "    <method name='SearchCredentials'>"
    "      <arg direction='in'  type='s' name='query'/>"
    "      <arg direction='out' type='aa{ss}' name='results'/>"
    "    </method>"
    ""
    "    <method name='GetEntry'>"
    "      <arg direction='in'  type='s' name='entry_id'/>"
    "      <arg direction='out' type='s' name='json'/>"
    "    </method>"
    ""
    "    <method name='ListGroups'>"
    "      <arg direction='out' type='s' name='json'/>"
    "    </method>"
    ""
    "    <method name='GetEntryHistory'>"
    "      <arg direction='in'  type='s' name='entry_id'/>"
    "      <arg direction='out' type='s' name='json'/>"
    "    </method>"
    ""
    "    <method name='ListEntryAttachments'>"
    "      <arg direction='in'  type='s' name='entry_id'/>"
    "      <arg direction='out' type='s' name='json'/>"
    "    </method>"
    ""
    "    <method name='SaveCredential'>"
    "      <arg direction='in'  type='s' name='title'/>"
    "      <arg direction='in'  type='s' name='url'/>"
    "      <arg direction='in'  type='s' name='username'/>"
    "      <arg direction='in'  type='s' name='password'/>"
    "      <arg direction='out' type='s' name='entry_id'/>"
    "    </method>"
    ""
    "    <method name='DeleteCredential'>"
    "      <arg direction='in'  type='s' name='entry_id'/>"
    "    </method>"
    ""
    "    <method name='DeleteEntry'>"
    "      <arg direction='in'  type='s' name='entry_id'/>"
    "    </method>"
    ""
    "    <method name='UpdateCredential'>"
    "      <arg direction='in'  type='s' name='entry_id'/>"
    "      <arg direction='in'  type='a{ss}' name='fields'/>"
    "    </method>"
    ""
    "    <method name='UpdateEntry'>"
    "      <arg direction='in'  type='s' name='entry_id'/>"
    "      <arg direction='in'  type='s' name='url'/>"
    "      <arg direction='in'  type='s' name='username'/>"
    "      <arg direction='in'  type='s' name='password'/>"
    "      <arg direction='in'  type='s' name='title'/>"
    "    </method>"
    ""
    "    <method name='RestoreEntryRevision'>"
    "      <arg direction='in'  type='s' name='entry_id'/>"
    "      <arg direction='in'  type='u' name='revision_index'/>"
    "      <arg direction='out' type='b' name='success'/>"
    "    </method>"
    ""
    "    <method name='VaultStatus'>"
    "      <arg direction='out' type='s' name='status'/>"
    "    </method>"
    ""
    "    <method name='ListPasskeys'>"
    "      <arg direction='out' type='aa{ss}' name='passkeys'/>"
    "    </method>"
    ""
    "    <method name='GetPasskey'>"
    "      <arg direction='in'  type='s' name='rp_id'/>"
    "      <arg direction='out' type='ay' name='private_key_bytes'/>"
    "    </method>"
    ""
    "    <method name='SavePasskey'>"
    "      <arg direction='in'  type='s' name='rp_id'/>"
    "      <arg direction='in'  type='s' name='user_id'/>"
    "      <arg direction='in'  type='ay' name='private_key'/>"
    "      <arg direction='in'  type='ay' name='public_key'/>"
    "    </method>"
    ""
    "    <method name='LockVault'>"

    "      <arg direction='out' type='b' name='success'/>"
    "    </method>"
    ""
    "    <method name='ImportTOTP'>"
    "      <arg direction='in'  type='s' name='qr_text'/>"
    "      <arg direction='out' type='s' name='entry_id'/>"
    "    </method>"
    ""
    "    <method name='GetTOTPStatus'>"
    "      <arg direction='in'  type='s' name='entry_id'/>"
    "      <arg direction='out' type='s' name='code'/>"
    "      <arg direction='out' type='u' name='remaining_seconds'/>"
    "    </method>"
    ""
    "    <signal name='VaultStateChanged'>"
    "      <arg type='s' name='state'/>"
    "    </signal>"
    ""
    "    <signal name='VaultUnlocked'>"
    "      <arg type='u' name='uid'/>"
    "    </signal>"
    ""
    "    <property name='Locked' type='b' access='read'/>"
    "  </interface>"
    "</node>";

typedef struct
{
    uid_t uid;
    bool active;
    pm_vault_handle_t *handle;
    char path[PATH_MAX];
    time_t unlocked_at;
} bio_user_vault_t;

typedef struct
{
    bool active;
    uid_t uid;
    char session_id[64];
    char label[128];
    time_t created;
} bio_face_enroll_session_t;

/* ── Daemon internal state ───────────────────────────────────── */

struct bio_daemon
{
    /* D-Bus */
    GDBusConnection *bus;
    GDBusNodeInfo *introspection_data;
    guint bus_name_id;
    bool bus_name_owned;
    guint daemon_bus_name_id;
    bool daemon_bus_name_owned;
    guint registration_id;
    guint vault_bus_name_id;
    bool vault_bus_name_owned;
    guint vault_registration_id;
    guint daemon_auth_registration_id;
    guint daemon_vault_registration_id;
    guint daemon_enroll_registration_id;

    /* Main loop */
    GMainLoop *main_loop;
    volatile bool should_stop;

    /* Configuration */
    bio_daemon_config_t config;

    /* Subsystems */
    bio_fp_ctx_t *fp_ctx;
    bio_fp_device_t *fp_dev;
    bio_tpm_ctx_t tpm_ctx;
    bool tpm_available;

    /* fprintd compatibility layer */
    bio_fprintd_compat_t fprintd_compat;
    bool fprintd_compat_active;

    /* Sessions */
    bio_session_t sessions[BIO_MAX_SESSIONS];
    int session_count;

    /* Enrollments (loaded from disk) */
    bio_enrollment_t *enrollments;
    size_t enrollment_count;
    size_t enrollment_capacity;

    /* Per-user rate limiting for Verify */
    struct
    {
        uid_t uid;
        int failure_count;
        time_t failures[32]; /* Ring buffer of failure timestamps */
        int failure_idx;
        time_t lockout_until;
        int consecutive_lockouts; /* For exponential backoff */
    } rate_limiters[128];
    int rate_limiter_count;

    bio_user_vault_t vaults[BIO_MAX_VAULTS];
    bio_face_enroll_session_t face_enroll_sessions[BIO_MAX_FACE_ENROLL_SESSIONS];

    /* Mutex protecting enrollments and rate_limiters from concurrent
     * access by fprintd compat worker threads. */
    pthread_mutex_t data_lock;

    /* Mutex serializing fingerprint device + TPM access across all
     * code paths (D-Bus handlers and fprintd-compat GTask threads). */
    pthread_mutex_t fp_lock;

    /* Set during shutdown to reject new fp operations */
    volatile bool shutting_down;

    /* Vault idle timeout timer */
    guint vault_idle_timer_id;

    /* Session lock monitoring */
    guint session_lock_subscription_id;
    guint sleep_subscription_id;
};

/* ── Helper: get caller UID from D-Bus ───────────────────────── */

static uid_t get_caller_uid(GDBusConnection *conn,
                            GDBusMethodInvocation *invocation)
{
    const char *sender = g_dbus_method_invocation_get_sender(invocation);
    GError *err = NULL;
    GVariant *result = NULL;

    if (!sender || sender[0] == '\0')
    {
        return (uid_t)-1;
    }

    result = g_dbus_connection_call_sync(
        conn,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
        "GetConnectionUnixUser",
        g_variant_new("(s)", sender),
        G_VARIANT_TYPE("(u)"),
        G_DBUS_CALL_FLAGS_NONE,
        -1, NULL, &err);

    if (!result || err)
    {
        BIO_ERROR("Failed to get caller UID: %s",
                  err ? err->message : "unknown");
        if (err)
            g_error_free(err);
        return (uid_t)-1;
    }

    guint32 uid;
    g_variant_get(result, "(u)", &uid);
    g_variant_unref(result);
    return (uid_t)uid;
}

static uid_t get_sender_uid(GDBusConnection *conn, const char *sender)
{
    GError *err = NULL;
    GVariant *result = g_dbus_connection_call_sync(
        conn,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
        "GetConnectionUnixUser",
        g_variant_new("(s)", sender),
        G_VARIANT_TYPE("(u)"),
        G_DBUS_CALL_FLAGS_NONE,
        -1, NULL, &err);

    if (!result || err)
    {
        BIO_ERROR("Failed to get caller UID: %s",
                  err ? err->message : "unknown");
        if (err)
            g_error_free(err);
        return (uid_t)-1;
    }

    guint32 uid;
    g_variant_get(result, "(u)", &uid);
    g_variant_unref(result);
    return (uid_t)uid;
}

static pid_t get_caller_pid(GDBusConnection *conn,
                            GDBusMethodInvocation *invocation)
{
    const char *sender = g_dbus_method_invocation_get_sender(invocation);
    GError *err = NULL;
    GVariant *result = g_dbus_connection_call_sync(
        conn,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
        "GetConnectionUnixProcessID",
        g_variant_new("(s)", sender),
        G_VARIANT_TYPE("(u)"),
        G_DBUS_CALL_FLAGS_NONE,
        -1, NULL, &err);

    if (!result || err)
    {
        BIO_ERROR("Failed to get caller PID: %s",
                  err ? err->message : "unknown");
        if (err)
            g_error_free(err);
        return (pid_t)-1;
    }

    guint32 pid = 0;
    g_variant_get(result, "(u)", &pid);
    g_variant_unref(result);
    return (pid_t)pid;
}

/*
 * Trusted portal caller policy for VerifyUser:
 *   - binary path must be /usr/libexec/bioauth-portal
 *   - binary must be root-owned and not group/world writable
 */
static bool caller_is_trusted_portal(GDBusConnection *conn,
                                     GDBusMethodInvocation *invocation)
{
    pid_t pid = get_caller_pid(conn, invocation);
    if (pid <= 0)
        return false;

    char proc_exe[64];
    snprintf(proc_exe, sizeof(proc_exe), "/proc/%ld/exe", (long)pid);

    char exe_path[PATH_MAX];
    ssize_t n = readlink(proc_exe, exe_path, sizeof(exe_path) - 1);
    if (n <= 0)
        return false;
    exe_path[n] = '\0';

    if (strcmp(exe_path, "/usr/libexec/bioauth-portal") != 0)
        return false;

    struct stat st;
    if (stat(exe_path, &st) != 0)
        return false;

    if (st.st_uid != 0)
        return false;
    if ((st.st_mode & (S_IWGRP | S_IWOTH)) != 0)
        return false;

    return true;
}

static pm_error_t build_user_vault_path(const bio_daemon_t *d,
                                        uid_t uid,
                                        char out_path[PATH_MAX])
{
    if (!d || !out_path)
    {
        return PM_ERR_INVALID_PARAM;
    }

    if (snprintf(out_path, PATH_MAX, "%s/users/%u/vault.vlt",
                 d->config.state_dir, (unsigned)uid) >= PATH_MAX)
    {
        return PM_ERR_IO;
    }

    return PM_OK;
}

static bio_user_vault_t *find_or_alloc_user_vault_slot(bio_daemon_t *d,
                                                       uid_t uid,
                                                       const char *path)
{
    bio_user_vault_t *free_slot = NULL;

    if (!d)
    {
        return NULL;
    }

    for (size_t i = 0; i < BIO_MAX_VAULTS; i++)
    {
        if (d->vaults[i].active && d->vaults[i].uid == uid)
        {
            return &d->vaults[i];
        }
        if (!d->vaults[i].active && !free_slot)
        {
            free_slot = &d->vaults[i];
        }
    }

    if (!free_slot)
    {
        return NULL;
    }

    memset(free_slot, 0, sizeof(*free_slot));
    free_slot->active = true;
    free_slot->uid = uid;
    if (path)
    {
        snprintf(free_slot->path, sizeof(free_slot->path), "%s", path);
    }
    return free_slot;
}

static void close_user_vault_slot(bio_user_vault_t *slot)
{
    if (!slot)
    {
        return;
    }

    if (slot->handle)
    {
        pm_vault_close(slot->handle);
    }

    memset(slot, 0, sizeof(*slot));
}

static pm_error_t ensure_user_vault_handle(bio_daemon_t *d,
                                           uid_t uid,
                                           bio_user_vault_t **out_slot)
{
    char path[PATH_MAX];
    pm_error_t rc;
    bio_user_vault_t *slot;

    if (!d || !out_slot)
    {
        return PM_ERR_INVALID_PARAM;
    }

    rc = build_user_vault_path(d, uid, path);
    if (rc != PM_OK)
    {
        return rc;
    }

    pthread_mutex_lock(&d->data_lock);
    slot = find_or_alloc_user_vault_slot(d, uid, path);
    if (!slot)
    {
        pthread_mutex_unlock(&d->data_lock);
        return PM_ERR_STATE;
    }

    if (!slot->handle)
    {
        rc = pm_vault_open(path, &slot->handle);
        if (rc != PM_OK)
        {
            close_user_vault_slot(slot);
            pthread_mutex_unlock(&d->data_lock);
            return rc;
        }
        snprintf(slot->path, sizeof(slot->path), "%s", path);
    }

    *out_slot = slot;
    pthread_mutex_unlock(&d->data_lock);
    return PM_OK;
}

static bool contains_case_insensitive(const char *haystack, const char *needle)
{
    size_t hlen;
    size_t nlen;

    if (!haystack || !needle)
    {
        return false;
    }

    hlen = strlen(haystack);
    nlen = strlen(needle);
    if (nlen == 0)
    {
        return true;
    }
    if (nlen > hlen)
    {
        return false;
    }

    for (size_t i = 0; i <= hlen - nlen; i++)
    {
        bool match = true;
        for (size_t j = 0; j < nlen; j++)
        {
            unsigned char a = (unsigned char)haystack[i + j];
            unsigned char b = (unsigned char)needle[j];
            if (tolower(a) != tolower(b))
            {
                match = false;
                break;
            }
        }
        if (match)
        {
            return true;
        }
    }

    return false;
}

static void json_append_escaped_string(GString *json, const char *value)
{
    const char *s = value ? value : "";

    g_string_append_c(json, '"');
    while (*s)
    {
        unsigned char c = (unsigned char)*s++;
        switch (c)
        {
        case '"':
            g_string_append(json, "\\\"");
            break;
        case '\\':
            g_string_append(json, "\\\\");
            break;
        case '\b':
            g_string_append(json, "\\b");
            break;
        case '\f':
            g_string_append(json, "\\f");
            break;
        case '\n':
            g_string_append(json, "\\n");
            break;
        case '\r':
            g_string_append(json, "\\r");
            break;
        case '\t':
            g_string_append(json, "\\t");
            break;
        default:
            if (c < 0x20u)
            {
                g_string_append_printf(json, "\\u%04x", (unsigned)c);
            }
            else
            {
                g_string_append_c(json, (gchar)c);
            }
            break;
        }
    }
    g_string_append_c(json, '"');
}

static bool entry_matches_search(const pm_entry_t *entry,
                                 const char *query,
                                 const char *url)
{
    bool query_ok = true;
    bool url_ok = true;

    if (!entry)
    {
        return false;
    }

    if (query && query[0] != '\0')
    {
        query_ok = contains_case_insensitive(entry->title ? entry->title : "", query) ||
                   contains_case_insensitive(entry->username ? entry->username : "", query) ||
                   contains_case_insensitive(entry->url ? entry->url : "", query) ||
                   contains_case_insensitive(entry->notes ? entry->notes : "", query);

        if (!query_ok && entry->urls)
        {
            for (size_t i = 0; i < entry->url_count; i++)
            {
                if (contains_case_insensitive(entry->urls[i] ? entry->urls[i] : "", query))
                {
                    query_ok = true;
                    break;
                }
            }
        }
    }

    if (url && url[0] != '\0')
    {
        url_ok = contains_case_insensitive(entry->url ? entry->url : "", url);
        if (!url_ok && entry->urls)
        {
            for (size_t i = 0; i < entry->url_count; i++)
            {
                if (contains_case_insensitive(entry->urls[i] ? entry->urls[i] : "", url))
                {
                    url_ok = true;
                    break;
                }
            }
        }
    }

    return query_ok && url_ok;
}

static pm_error_t find_first_entry_matching(const pm_vault_handle_t *handle,
                                            const char *query,
                                            const char *url,
                                            pm_entry_t *out_entry)
{
    char **ids = NULL;
    size_t id_count = 0;
    pm_error_t rc;

    if (!handle || !out_entry)
    {
        return PM_ERR_INVALID_PARAM;
    }

    pm_entry_init(out_entry);
    rc = pm_vault_entry_list_ids(handle, &ids, &id_count);
    if (rc != PM_OK)
    {
        return rc;
    }

    rc = PM_ERR_NOT_FOUND;
    for (size_t i = 0; i < id_count; i++)
    {
        pm_entry_t candidate;
        pm_entry_init(&candidate);

        if (!ids[i])
        {
            pm_entry_free(&candidate);
            continue;
        }

        if (pm_vault_entry_get(handle, ids[i], &candidate) != PM_OK)
        {
            pm_entry_free(&candidate);
            continue;
        }

        if (entry_matches_search(&candidate, query, url))
        {
            *out_entry = candidate;
            rc = PM_OK;
            break;
        }

        pm_entry_free(&candidate);
    }

    pm_vault_entry_id_list_free(ids, id_count);
    return rc;
}

static const char *entry_field_value(const pm_entry_t *entry,
                                     const char *field)
{
    if (!entry || !field || field[0] == '\0')
    {
        return NULL;
    }

    if (strcasecmp(field, "id") == 0)
    {
        return entry->id;
    }
    if (strcasecmp(field, "title") == 0)
    {
        return entry->title;
    }
    if (strcasecmp(field, "username") == 0)
    {
        return entry->username;
    }
    if (strcasecmp(field, "password") == 0)
    {
        return entry->password;
    }
    if (strcasecmp(field, "url") == 0)
    {
        return entry->url;
    }
    if (strcasecmp(field, "notes") == 0)
    {
        return entry->notes;
    }

    for (size_t i = 0; i < entry->custom_field_count; i++)
    {
        if (!entry->custom_fields[i].name)
        {
            continue;
        }
        if (strcasecmp(entry->custom_fields[i].name, field) == 0)
        {
            return entry->custom_fields[i].text_value;
        }
    }

    return NULL;
}

static const char *entry_custom_field_text(const pm_entry_t *entry,
                                           const char *field_name)
{
    if (!entry || !field_name || field_name[0] == '\0')
    {
        return NULL;
    }

    for (size_t i = 0; i < entry->custom_field_count; i++)
    {
        const pm_custom_field_t *field = &entry->custom_fields[i];
        if (!field->name || !field->text_value)
        {
            continue;
        }

        if (strcasecmp(field->name, field_name) == 0)
        {
            return field->text_value;
        }
    }

    return NULL;
}

static bool entry_is_passkey(const pm_entry_t *entry)
{
    const char *kind;

    if (!entry)
    {
        return false;
    }

    kind = entry_custom_field_text(entry, PASSKEY_FIELD_KIND);
    if (kind && strcmp(kind, PASSKEY_KIND_VALUE) == 0)
    {
        return true;
    }

    return entry_custom_field_text(entry, PASSKEY_FIELD_RP_ID) != NULL;
}

static pm_error_t entry_set_custom_text(pm_entry_t *entry,
                                        const char *name,
                                        pm_custom_field_type_t type,
                                        const char *value)
{
    pm_custom_field_t *field;
    char *dup_value;

    if (!entry || !name || name[0] == '\0')
    {
        return PM_ERR_INVALID_PARAM;
    }

    for (size_t i = 0; i < entry->custom_field_count; i++)
    {
        if (entry->custom_fields[i].name &&
            strcasecmp(entry->custom_fields[i].name, name) == 0)
        {
            field = &entry->custom_fields[i];
            dup_value = strdup(value ? value : "");
            if (!dup_value)
            {
                return PM_ERR_NOMEM;
            }

            free(field->text_value);
            free(field->binary_ref);
            field->text_value = dup_value;
            field->binary_ref = NULL;
            field->date_value_ms = 0;
            field->type = type;
            return PM_OK;
        }
    }

    pm_custom_field_t *new_fields = realloc(
        entry->custom_fields,
        (entry->custom_field_count + 1u) * sizeof(pm_custom_field_t));
    if (!new_fields)
    {
        return PM_ERR_NOMEM;
    }

    entry->custom_fields = new_fields;
    field = &entry->custom_fields[entry->custom_field_count];
    pm_custom_field_init(field);

    field->name = strdup(name);
    field->type = type;
    field->text_value = strdup(value ? value : "");
    if (!field->name || !field->text_value)
    {
        pm_custom_field_free(field);
        return PM_ERR_NOMEM;
    }

    entry->custom_field_count++;
    return PM_OK;
}

static pm_error_t find_passkey_entry_by_rp(const pm_vault_handle_t *handle,
                                           const char *rp_id,
                                           pm_entry_t *out_entry)
{
    char **ids = NULL;
    size_t id_count = 0;
    pm_error_t rc;

    if (!handle || !rp_id || rp_id[0] == '\0' || !out_entry)
    {
        return PM_ERR_INVALID_PARAM;
    }

    pm_entry_init(out_entry);
    rc = pm_vault_entry_list_ids(handle, &ids, &id_count);
    if (rc != PM_OK)
    {
        return rc;
    }

    rc = PM_ERR_NOT_FOUND;
    for (size_t i = 0; i < id_count; i++)
    {
        pm_entry_t candidate;
        const char *entry_rp_id;

        pm_entry_init(&candidate);
        if (!ids[i] || pm_vault_entry_get(handle, ids[i], &candidate) != PM_OK)
        {
            pm_entry_free(&candidate);
            continue;
        }

        if (!entry_is_passkey(&candidate))
        {
            pm_entry_free(&candidate);
            continue;
        }

        entry_rp_id = entry_custom_field_text(&candidate, PASSKEY_FIELD_RP_ID);
        if (entry_rp_id && strcmp(entry_rp_id, rp_id) == 0)
        {
            *out_entry = candidate;
            rc = PM_OK;
            break;
        }

        pm_entry_free(&candidate);
    }

    pm_vault_entry_id_list_free(ids, id_count);
    return rc;
}

static uint64_t now_epoch_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
    {
        return (uint64_t)time(NULL) * 1000u;
    }

    return (uint64_t)ts.tv_sec * 1000u +
           (uint64_t)(ts.tv_nsec / 1000000u);
}

static pm_error_t build_search_json_scoped(const pm_vault_handle_t *handle,
                                           const char *query,
                                           const char *url,
                                           const char *group_id,
                                           bool include_descendants,
                                           char **out_json);

static pm_error_t build_search_json(const pm_vault_handle_t *handle,
                                    const char *query,
                                    const char *url,
                                    char **out_json)
{
    return build_search_json_scoped(handle,
                                    query,
                                    url,
                                    NULL,
                                    false,
                                    out_json);
}

static pm_error_t build_entry_json(const pm_vault_handle_t *handle,
                                   const char *entry_id,
                                   char **out_json)
{
    pm_entry_t entry;
    GString *json;
    pm_error_t rc;
    const char *totp_value = NULL;

    if (!handle || !entry_id || !out_json)
    {
        return PM_ERR_INVALID_PARAM;
    }

    *out_json = NULL;
    pm_entry_init(&entry);
    rc = pm_vault_entry_get(handle, entry_id, &entry);
    if (rc != PM_OK)
    {
        return rc;
    }

    for (size_t i = 0; i < entry.custom_field_count; i++)
    {
        if (entry.custom_fields[i].type == PM_FIELD_TOTP &&
            entry.custom_fields[i].text_value)
        {
            totp_value = entry.custom_fields[i].text_value;
            break;
        }
    }

    json = g_string_new("{\"id\":");
    json_append_escaped_string(json, entry.id ? entry.id : "");
    g_string_append(json, ",\"title\":");
    json_append_escaped_string(json, entry.title ? entry.title : "");
    g_string_append(json, ",\"username\":");
    json_append_escaped_string(json, entry.username ? entry.username : "");
    g_string_append(json, ",\"password\":");
    json_append_escaped_string(json, entry.password ? entry.password : "");
    g_string_append(json, ",\"url\":");
    json_append_escaped_string(json, entry.url ? entry.url : "");
    g_string_append(json, ",\"notes\":");
    json_append_escaped_string(json, entry.notes ? entry.notes : "");
    g_string_append(json, ",\"requiresFreshBiometric\":");
    g_string_append(json, entry.requires_fresh_biometric ? "true" : "false");
    g_string_append(json, ",\"totp\":");
    json_append_escaped_string(json, totp_value ? totp_value : "");
    g_string_append_c(json, '}');

    pm_entry_free(&entry);
    *out_json = g_string_free(json, FALSE);
    return PM_OK;
}

static int payload_find_group_index_by_id(const pm_payload_t *payload,
                                          const char *group_id)
{
    if (!payload || !group_id || group_id[0] == '\0')
    {
        return -1;
    }

    for (size_t i = 0; i < payload->group_count; i++)
    {
        const pm_group_t *group = &payload->groups[i];
        if (group->id && strcmp(group->id, group_id) == 0)
        {
            return (int)i;
        }
    }

    return -1;
}

static size_t payload_count_entries_for_group(const pm_payload_t *payload,
                                              const char *group_id)
{
    size_t count = 0;

    if (!payload || !group_id || group_id[0] == '\0')
    {
        return 0;
    }

    for (size_t i = 0; i < payload->entry_count; i++)
    {
        const pm_entry_t *entry = &payload->entries[i];
        if (!entry->group_id)
        {
            continue;
        }

        if (strcmp(entry->group_id, group_id) == 0)
        {
            count++;
        }
    }

    return count;
}

static bool payload_entry_group_matches_scope(const pm_payload_t *payload,
                                              const char *entry_group_id,
                                              const char *scope_group_id,
                                              bool include_descendants)
{
    int current_idx;
    size_t remaining;

    if (!payload)
    {
        return false;
    }

    if (!scope_group_id || scope_group_id[0] == '\0')
    {
        return true;
    }

    if (!entry_group_id || entry_group_id[0] == '\0')
    {
        return false;
    }

    if (strcmp(entry_group_id, scope_group_id) == 0)
    {
        return true;
    }

    if (!include_descendants)
    {
        return false;
    }

    current_idx = payload_find_group_index_by_id(payload, entry_group_id);
    remaining = payload->group_count + 1u;

    while (current_idx >= 0 && remaining-- > 0)
    {
        const pm_group_t *group = &payload->groups[current_idx];

        if (!group->parent_id || group->parent_id[0] == '\0')
        {
            return false;
        }

        if (strcmp(group->parent_id, scope_group_id) == 0)
        {
            return true;
        }

        current_idx = payload_find_group_index_by_id(payload, group->parent_id);
    }

    return false;
}

static pm_error_t build_search_json_scoped(const pm_vault_handle_t *handle,
                                           const char *query,
                                           const char *url,
                                           const char *group_id,
                                           bool include_descendants,
                                           char **out_json)
{
    pm_payload_t payload;
    GString *json;
    bool first = true;
    pm_error_t rc;

    if (!handle || !out_json)
    {
        return PM_ERR_INVALID_PARAM;
    }

    *out_json = NULL;
    pm_payload_init(&payload);
    rc = pm_vault_get_payload_model(handle, &payload);
    if (rc != PM_OK)
    {
        return rc;
    }

    json = g_string_new("[");
    for (size_t i = 0; i < payload.entry_count; i++)
    {
        const pm_entry_t *entry = &payload.entries[i];
        const char *primary_url = entry->url ? entry->url : ((entry->urls && entry->url_count > 0 && entry->urls[0]) ? entry->urls[0] : "");
        bool has_totp = false;

        if (!entry_matches_search(entry, query, url))
        {
            continue;
        }

        if (!payload_entry_group_matches_scope(&payload,
                                               entry->group_id,
                                               group_id,
                                               include_descendants))
        {
            continue;
        }

        for (size_t cf = 0; cf < entry->custom_field_count; cf++)
        {
            if (entry->custom_fields[cf].type == PM_FIELD_TOTP &&
                entry->custom_fields[cf].text_value &&
                entry->custom_fields[cf].text_value[0] != '\0')
            {
                has_totp = true;
                break;
            }
        }

        if (!first)
        {
            g_string_append_c(json, ',');
        }
        first = false;

        g_string_append(json, "{\"id\":");
        json_append_escaped_string(json, entry->id ? entry->id : "");
        g_string_append(json, ",\"title\":");
        json_append_escaped_string(json, entry->title ? entry->title : "");
        g_string_append(json, ",\"username\":");
        json_append_escaped_string(json, entry->username ? entry->username : "");
        g_string_append(json, ",\"url\":");
        json_append_escaped_string(json, primary_url);
        g_string_append(json, ",\"group_id\":");
        json_append_escaped_string(json, entry->group_id ? entry->group_id : "");
        g_string_append(json, ",\"has_totp\":");
        g_string_append(json, has_totp ? "true" : "false");
        g_string_append_c(json, '}');
    }
    g_string_append_c(json, ']');

    pm_payload_free(&payload);
    *out_json = g_string_free(json, FALSE);
    return PM_OK;
}

static void append_group_node_json(GString *json,
                                   const pm_payload_t *payload,
                                   size_t group_index,
                                   bool *emitted,
                                   size_t depth)
{
    const pm_group_t *group;
    const char *group_id;
    bool first_child = true;

    if (!json || !payload || !emitted ||
        group_index >= payload->group_count ||
        depth > payload->group_count + 1u)
    {
        return;
    }

    if (emitted[group_index])
    {
        return;
    }

    group = &payload->groups[group_index];
    group_id = group->id ? group->id : "";
    emitted[group_index] = true;

    g_string_append(json, "{\"id\":");
    json_append_escaped_string(json, group_id);
    g_string_append(json, ",\"parent_id\":");
    json_append_escaped_string(json, group->parent_id ? group->parent_id : "");
    g_string_append(json, ",\"title\":");
    json_append_escaped_string(json, group->title ? group->title : "");
    g_string_append(json, ",\"notes\":");
    json_append_escaped_string(json, group->notes ? group->notes : "");
    g_string_append(json, ",\"color\":");
    json_append_escaped_string(json, group->color ? group->color : "");
    g_string_append_printf(json,
                           ",\"entry_count\":%zu",
                           payload_count_entries_for_group(payload, group_id));
    g_string_append(json, ",\"children\":[");

    for (size_t i = 0; i < payload->group_count; i++)
    {
        const pm_group_t *candidate = &payload->groups[i];
        if (!candidate->parent_id || candidate->parent_id[0] == '\0')
        {
            continue;
        }

        if (strcmp(candidate->parent_id, group_id) != 0)
        {
            continue;
        }

        if (!first_child)
        {
            g_string_append_c(json, ',');
        }
        first_child = false;

        append_group_node_json(json, payload, i, emitted, depth + 1u);
    }

    g_string_append(json, "]}");
}

static pm_error_t build_groups_json(const pm_vault_handle_t *handle,
                                    char **out_json)
{
    pm_payload_t payload;
    GString *json;
    bool *emitted = NULL;
    bool first = true;
    pm_error_t rc;

    if (!handle || !out_json)
    {
        return PM_ERR_INVALID_PARAM;
    }

    *out_json = NULL;
    pm_payload_init(&payload);
    rc = pm_vault_get_payload_model(handle, &payload);
    if (rc != PM_OK)
    {
        return rc;
    }

    if (payload.group_count > 0)
    {
        emitted = calloc(payload.group_count, sizeof(bool));
        if (!emitted)
        {
            pm_payload_free(&payload);
            return PM_ERR_NOMEM;
        }
    }

    json = g_string_new("[");

    for (size_t i = 0; i < payload.group_count; i++)
    {
        const pm_group_t *group = &payload.groups[i];
        int parent_index;

        if (!group->parent_id || group->parent_id[0] == '\0')
        {
            parent_index = -1;
        }
        else
        {
            parent_index = payload_find_group_index_by_id(&payload, group->parent_id);
        }

        if (parent_index >= 0 && (size_t)parent_index != i)
        {
            continue;
        }

        if (!first)
        {
            g_string_append_c(json, ',');
        }
        first = false;
        append_group_node_json(json, &payload, i, emitted, 0u);
    }

    for (size_t i = 0; i < payload.group_count; i++)
    {
        if (emitted && emitted[i])
        {
            continue;
        }

        if (!first)
        {
            g_string_append_c(json, ',');
        }
        first = false;
        append_group_node_json(json, &payload, i, emitted, 0u);
    }

    g_string_append_c(json, ']');

    free(emitted);
    pm_payload_free(&payload);

    *out_json = g_string_free(json, FALSE);
    return PM_OK;
}

static pm_error_t build_entry_history_json(const pm_vault_handle_t *handle,
                                           const char *entry_id,
                                           char **out_json)
{
    pm_entry_t entry;
    GString *json;
    pm_error_t rc;
    bool first = true;

    if (!handle || !entry_id || !out_json)
    {
        return PM_ERR_INVALID_PARAM;
    }

    *out_json = NULL;
    pm_entry_init(&entry);
    rc = pm_vault_entry_get(handle, entry_id, &entry);
    if (rc != PM_OK)
    {
        return rc;
    }

    json = g_string_new("[");
    for (size_t i = 0; i < entry.history_count; i++)
    {
        const pm_history_revision_t *rev = &entry.history[i];

        if (!first)
        {
            g_string_append_c(json, ',');
        }
        first = false;

        g_string_append(json, "{\"revision_ts_ms\":");
        g_string_append_printf(json, "%" G_GUINT64_FORMAT, rev->revision_ts_ms);
        g_string_append(json, ",\"updated_at_ms\":");
        g_string_append_printf(json, "%" G_GUINT64_FORMAT, rev->updated_at_ms);
        g_string_append(json, ",\"favorite\":");
        g_string_append(json, rev->favorite ? "true" : "false");
        g_string_append(json, ",\"source\":");
        json_append_escaped_string(json, rev->source ? rev->source : "");
        g_string_append(json, ",\"actor\":");
        json_append_escaped_string(json, rev->actor ? rev->actor : "");
        g_string_append(json, ",\"id\":");
        json_append_escaped_string(json, rev->id ? rev->id : "");
        g_string_append(json, ",\"title\":");
        json_append_escaped_string(json, rev->title ? rev->title : "");
        g_string_append(json, ",\"username\":");
        json_append_escaped_string(json, rev->username ? rev->username : "");
        g_string_append(json, ",\"url\":");
        json_append_escaped_string(json, rev->url ? rev->url : "");
        g_string_append(json, ",\"notes\":");
        json_append_escaped_string(json, rev->notes ? rev->notes : "");
        g_string_append(json, ",\"group_id\":");
        json_append_escaped_string(json, rev->group_id ? rev->group_id : "");
        g_string_append_c(json, '}');
    }
    g_string_append_c(json, ']');

    pm_entry_free(&entry);
    *out_json = g_string_free(json, FALSE);
    return PM_OK;
}

static const pm_attachment_t *payload_find_attachment_by_id(const pm_payload_t *payload,
                                                            const char *attachment_id)
{
    if (!payload || !attachment_id || attachment_id[0] == '\0')
    {
        return NULL;
    }

    for (size_t i = 0; i < payload->attachment_count; i++)
    {
        const pm_attachment_t *attachment = &payload->attachments[i];
        if (attachment->id && strcmp(attachment->id, attachment_id) == 0)
        {
            return attachment;
        }
    }

    return NULL;
}

static void digest_to_hex32(const uint8_t digest[32], char out[65])
{
    static const char hexdigits[] = "0123456789abcdef";

    if (!digest || !out)
    {
        return;
    }

    for (size_t i = 0; i < 32; i++)
    {
        out[i * 2] = hexdigits[(digest[i] >> 4) & 0x0f];
        out[i * 2 + 1] = hexdigits[digest[i] & 0x0f];
    }
    out[64] = '\0';
}

static pm_error_t build_entry_attachments_json(const pm_vault_handle_t *handle,
                                               const char *entry_id,
                                               char **out_json)
{
    pm_payload_t payload;
    pm_entry_t entry;
    GString *json;
    pm_error_t rc;
    bool first = true;

    if (!handle || !entry_id || !out_json)
    {
        return PM_ERR_INVALID_PARAM;
    }

    *out_json = NULL;
    pm_payload_init(&payload);
    pm_entry_init(&entry);

    rc = pm_vault_get_payload_model(handle, &payload);
    if (rc != PM_OK)
    {
        return rc;
    }

    rc = pm_vault_entry_get(handle, entry_id, &entry);
    if (rc != PM_OK)
    {
        pm_payload_free(&payload);
        return rc;
    }

    json = g_string_new("[");
    for (size_t i = 0; i < entry.attachment_ref_count; i++)
    {
        const pm_attachment_ref_t *ref = &entry.attachment_refs[i];
        const char *attachment_id = ref->attachment_id ? ref->attachment_id : "";
        const pm_attachment_t *attachment = payload_find_attachment_by_id(&payload, attachment_id);

        if (!first)
        {
            g_string_append_c(json, ',');
        }
        first = false;

        g_string_append(json, "{\"id\":");
        json_append_escaped_string(json, attachment_id);
        g_string_append(json, ",\"found\":");
        g_string_append(json, attachment ? "true" : "false");

        if (attachment)
        {
            g_string_append(json, ",\"name\":");
            json_append_escaped_string(json, attachment->name ? attachment->name : "");
            g_string_append(json, ",\"mime\":");
            json_append_escaped_string(json, attachment->mime ? attachment->mime : "");
            g_string_append(json, ",\"size\":");
            g_string_append_printf(json, "%" G_GUINT64_FORMAT, attachment->size);

            if (attachment->has_sha256)
            {
                char digest_hex[65];
                digest_to_hex32(attachment->sha256, digest_hex);
                g_string_append(json, ",\"sha256\":");
                json_append_escaped_string(json, digest_hex);
            }
        }

        g_string_append_c(json, '}');
    }
    g_string_append_c(json, ']');

    pm_entry_free(&entry);
    pm_payload_free(&payload);
    *out_json = g_string_free(json, FALSE);
    return PM_OK;
}

static pm_error_t replace_entry_string_field(char **dst,
                                             const char *src)
{
    char *dup;

    if (!dst)
    {
        return PM_ERR_INVALID_PARAM;
    }

    dup = strdup(src ? src : "");
    if (!dup)
    {
        return PM_ERR_NOMEM;
    }

    free(*dst);
    *dst = dup;
    return PM_OK;
}

static void free_entry_tags(pm_entry_t *entry)
{
    if (!entry || !entry->tags)
    {
        if (entry)
        {
            entry->tag_count = 0;
        }
        return;
    }

    for (size_t i = 0; i < entry->tag_count; i++)
    {
        free(entry->tags[i]);
    }

    free(entry->tags);
    entry->tags = NULL;
    entry->tag_count = 0;
}

static pm_error_t replace_entry_tags(pm_entry_t *entry,
                                     char *const *tags,
                                     size_t tag_count)
{
    char **new_tags = NULL;

    if (!entry)
    {
        return PM_ERR_INVALID_PARAM;
    }

    if (tag_count > 0)
    {
        new_tags = calloc(tag_count, sizeof(char *));
        if (!new_tags)
        {
            return PM_ERR_NOMEM;
        }

        for (size_t i = 0; i < tag_count; i++)
        {
            new_tags[i] = strdup(tags && tags[i] ? tags[i] : "");
            if (!new_tags[i])
            {
                for (size_t j = 0; j < i; j++)
                {
                    free(new_tags[j]);
                }
                free(new_tags);
                return PM_ERR_NOMEM;
            }
        }
    }

    free_entry_tags(entry);
    entry->tags = new_tags;
    entry->tag_count = tag_count;
    return PM_OK;
}

static pm_error_t restore_entry_from_revision(pm_entry_t *entry,
                                              const pm_history_revision_t *revision,
                                              uint64_t now_ms)
{
    pm_error_t rc;

    if (!entry || !revision)
    {
        return PM_ERR_INVALID_PARAM;
    }

    rc = replace_entry_string_field(&entry->title, revision->title);
    if (rc != PM_OK)
    {
        return rc;
    }

    rc = replace_entry_string_field(&entry->username, revision->username);
    if (rc != PM_OK)
    {
        return rc;
    }

    rc = replace_entry_string_field(&entry->password, revision->password);
    if (rc != PM_OK)
    {
        return rc;
    }

    rc = replace_entry_string_field(&entry->url, revision->url);
    if (rc != PM_OK)
    {
        return rc;
    }

    rc = replace_entry_string_field(&entry->notes, revision->notes);
    if (rc != PM_OK)
    {
        return rc;
    }

    rc = replace_entry_string_field(&entry->group_id, revision->group_id);
    if (rc != PM_OK)
    {
        return rc;
    }

    rc = replace_entry_tags(entry, revision->tags, revision->tag_count);
    if (rc != PM_OK)
    {
        return rc;
    }

    if (entry->urls)
    {
        for (size_t i = 0; i < entry->url_count; i++)
        {
            free(entry->urls[i]);
        }
        free(entry->urls);
    }
    entry->urls = NULL;
    entry->url_count = 0;

    if (entry->url && entry->url[0] != '\0')
    {
        char **new_urls = calloc(1, sizeof(char *));
        if (!new_urls)
        {
            return PM_ERR_NOMEM;
        }

        new_urls[0] = strdup(entry->url);
        if (!new_urls[0])
        {
            free(new_urls);
            return PM_ERR_NOMEM;
        }

        entry->urls = new_urls;
        entry->url_count = 1;
    }

    entry->favorite = revision->favorite;
    entry->updated_at_ms = now_ms;
    entry->accessed_at_ms = now_ms;

    return PM_OK;
}

/*
 * Auto-unlock vault after successful biometric verification.
 * Handles 3 unlock modes based on vault's composite mode:
 * 1. Password-only: Cannot auto-unlock, requires explicit password
 * 2. Biometric-only: Auto-unlock with TPM-sealed wrapping key
 * 3. Password+biometric: Cannot auto-unlock, requires both factors
 */
static pm_error_t auto_unlock_user_vault(bio_daemon_t *d, uid_t uid)
{
    bio_user_vault_t *slot = NULL;
    uint8_t wrapping_key[PM_BIO_WRAP_KEY_SIZE];
    pm_unlock_factors_t factors;
    pm_error_t rc;

    if (!d)
    {
        return PM_ERR_INVALID_PARAM;
    }

    rc = ensure_user_vault_handle(d, uid, &slot);
    if (rc != PM_OK)
    {
        return rc;
    }

    if (slot && slot->handle && !pm_vault_is_locked(slot->handle))
    {
        return PM_OK; /* Already unlocked */
    }

    if (!slot || !slot->handle)
    {
        return PM_ERR_NOT_FOUND; /* No vault handle loaded */
    }

    /* Check vault's composite mode to determine unlock strategy */
    pm_composite_mode_t mode;
    rc = pm_vault_get_mode(slot->handle, &mode);
    if (rc != PM_OK)
    {
        return rc;
    }

    /* Password-only mode: Cannot auto-unlock, requires explicit user password */
    if (mode.use_password && !mode.use_biometric && !mode.use_keyfile && !mode.use_yubikey)
    {
        BIO_DEBUG("Vault for UID %u is password-only, cannot auto-unlock", uid);
        return PM_ERR_KEY_UNAVAILABLE;
    }

    /* Password+biometric mode: Cannot auto-unlock, requires both factors */
    if (mode.use_password && mode.use_biometric)
    {
        BIO_DEBUG("Vault for UID %u requires password+biometric, cannot auto-unlock", uid);
        return PM_ERR_KEY_UNAVAILABLE;
    }

    /* Biometric-only mode: Proceed with TPM wrapping key unlock */
    if (!mode.use_biometric)
    {
        BIO_DEBUG("Vault for UID %u has no biometric factor, cannot auto-unlock", uid);
        return PM_ERR_KEY_UNAVAILABLE;
    }

    if (!d->tpm_available)
    {
        BIO_WARN("TPM unavailable for biometric vault unlock (UID %u)", uid);
        return PM_ERR_TPM;
    }

    memset(wrapping_key, 0, sizeof(wrapping_key));
    if (bio_mlock_sensitive_strict(wrapping_key, sizeof(wrapping_key)) != BIO_OK)
    {
        return PM_ERR_DENIED;
    }

    pthread_mutex_lock(&d->fp_lock);
    if (d->shutting_down)
    {
        pthread_mutex_unlock(&d->fp_lock);
        pm_secure_zero(wrapping_key, sizeof(wrapping_key));
        bio_munlock_sensitive(wrapping_key, sizeof(wrapping_key));
        return PM_ERR_IO;
    }

    rc = pm_bio_wrap_unseal_vault_key(slot->path, wrapping_key);
    pthread_mutex_unlock(&d->fp_lock);

    if (rc != PM_OK)
    {
        pm_secure_zero(wrapping_key, sizeof(wrapping_key));
        bio_munlock_sensitive(wrapping_key, sizeof(wrapping_key));
        return rc;
    }

    /* Build unlock factors based on vault mode */
    memset(&factors, 0, sizeof(factors));

    if (mode.use_biometric)
    {
        factors.has_wrapping_key = true;
        memcpy(factors.wrapping_key, wrapping_key, sizeof(factors.wrapping_key));
    }

    /* TODO: Add keyfile and YubiKey factor support when required */
    if (mode.use_keyfile)
    {
        BIO_WARN("Keyfile factor not yet implemented for auto-unlock");
        pm_secure_zero(wrapping_key, sizeof(wrapping_key));
        bio_munlock_sensitive(wrapping_key, sizeof(wrapping_key));
        return PM_ERR_UNSUPPORTED;
    }

    if (mode.use_yubikey)
    {
        BIO_WARN("YubiKey authentication is not yet available. Use password or biometric unlock.");
        pm_secure_zero(wrapping_key, sizeof(wrapping_key));
        bio_munlock_sensitive(wrapping_key, sizeof(wrapping_key));
        return PM_ERR_UNSUPPORTED;
    }

    rc = pm_vault_unlock(slot->handle, &factors);
    pm_secure_zero(&factors, sizeof(factors));
    pm_secure_zero(wrapping_key, sizeof(wrapping_key));
    bio_munlock_sensitive(wrapping_key, sizeof(wrapping_key));

    if (rc == PM_OK)
    {
        pthread_mutex_lock(&d->data_lock);
        slot->unlocked_at = time(NULL);
        pthread_mutex_unlock(&d->data_lock);
        BIO_INFO("Biometric-only vault auto-unlocked for UID %u", uid);
    }
    else
    {
        BIO_WARN("Vault unlock failed for UID %u: %s", uid, pm_error_str(rc));
    }

    return rc;
}

/*
 * Check all unlocked vaults for idle timeout and lock them if needed.
 * Called periodically by GLib timer.
 */
static gboolean check_vault_idle_timeout(gpointer user_data)
{
    bio_daemon_t *d = (bio_daemon_t *)user_data;
    time_t now = time(NULL);
    int locked_count = 0;

    if (!d || d->shutting_down)
    {
        return G_SOURCE_REMOVE;
    }

    if (d->config.vault_idle_timeout_seconds <= 0)
    {
        return G_SOURCE_CONTINUE; /* Timeout disabled */
    }

    pthread_mutex_lock(&d->data_lock);

    for (size_t i = 0; i < BIO_MAX_VAULTS; i++)
    {
        bio_user_vault_t *slot = &d->vaults[i];

        if (!slot->active || !slot->handle)
        {
            continue; /* Slot not in use */
        }

        if (pm_vault_is_locked(slot->handle))
        {
            continue; /* Already locked */
        }

        /* Check if vault has been idle for too long */
        time_t idle_time = now - slot->unlocked_at;
        if (idle_time >= d->config.vault_idle_timeout_seconds)
        {
            BIO_INFO("Locking idle vault for UID %u (idle for %ld seconds)",
                     slot->uid, (long)idle_time);

            pm_error_t rc = pm_vault_lock(slot->handle, PM_LOCK_REASON_IDLE);
            if (rc == PM_OK)
            {
                locked_count++;
            }
            else
            {
                BIO_WARN("Failed to lock idle vault for UID %u: %s",
                         slot->uid, pm_error_str(rc));
            }
        }
    }

    pthread_mutex_unlock(&d->data_lock);

    if (locked_count > 0)
    {
        BIO_INFO("Auto-locked %d idle vault(s)", locked_count);
        emit_vault_locked_property_changed(d->bus, TRUE);
        emit_vault_state_changed(d, "locked");
    }

    return G_SOURCE_CONTINUE; /* Keep timer running */
}

static int lock_unlocked_vaults_for_reason(bio_daemon_t *d,
                                           pm_lock_reason_t lock_reason,
                                           const char *reason_str)
{
    int locked_count = 0;

    if (!d || !reason_str)
    {
        return 0;
    }

    pthread_mutex_lock(&d->data_lock);
    for (size_t i = 0; i < BIO_MAX_VAULTS; i++)
    {
        bio_user_vault_t *slot = &d->vaults[i];

        if (!slot->active || !slot->handle)
        {
            continue;
        }

        if (pm_vault_is_locked(slot->handle))
        {
            continue;
        }

        BIO_INFO("Locking vault for UID %u due to %s", slot->uid, reason_str);

        pm_error_t rc = pm_vault_lock(slot->handle, lock_reason);
        if (rc == PM_OK)
        {
            locked_count++;
        }
        else
        {
            BIO_WARN("Failed to lock vault for UID %u on %s: %s",
                     slot->uid, reason_str, pm_error_str(rc));
        }
    }
    pthread_mutex_unlock(&d->data_lock);

    if (locked_count > 0)
    {
        emit_vault_locked_property_changed(d->bus, TRUE);
        emit_vault_state_changed(d, "locked");
    }

    return locked_count;
}

/*
 * Handle systemd-logind session lock/unlock and suspend signals.
 * Lock all vaults when the session is locked or system goes to sleep.
 */
static void handle_session_lock_signal(GDBusConnection *connection,
                                       const gchar *sender_name,
                                       const gchar *object_path,
                                       const gchar *interface_name,
                                       const gchar *signal_name,
                                       GVariant *parameters,
                                       gpointer user_data)
{
    bio_daemon_t *d = (bio_daemon_t *)user_data;
    gboolean locked = FALSE;
    pm_lock_reason_t lock_reason;
    int locked_count = 0;

    (void)connection;
    (void)sender_name;
    (void)object_path;
    (void)interface_name;

    if (!d || d->shutting_down)
    {
        return;
    }

    if (g_strcmp0(signal_name, "Lock") == 0)
    {
        locked = TRUE;
        lock_reason = PM_LOCK_REASON_SESSION_LOCK;
        BIO_INFO("Session locked, locking all unlocked vaults");
    }
    else if (g_strcmp0(signal_name, "Unlock") == 0)
    {
        locked = FALSE;
        BIO_DEBUG("Session unlocked, vaults remain as they were");
        return; /* Only lock vaults, don't unlock them automatically */
    }
    else if (g_strcmp0(signal_name, "PrepareForSleep") == 0)
    {
        /* System going to sleep (lid close, suspend, etc.) */
        if (parameters && g_variant_n_children(parameters) > 0)
        {
            g_variant_get_child(parameters, 0, "b", &locked);
            if (locked)
            {
                lock_reason = PM_LOCK_REASON_LID_CLOSE;
                BIO_INFO("System suspending (lid close), locking all unlocked vaults");
            }
            else
            {
                BIO_DEBUG("System waking up, vaults remain as they were");
                return; /* Only lock on sleep, not on wake */
            }
        }
        else
        {
            return; /* Invalid PrepareForSleep signal */
        }
    }
    else
    {
        return; /* Not a signal we care about */
    }

    if (!locked)
    {
        return; /* Only lock vaults, don't unlock them */
    }

    const char *reason_str = (lock_reason == PM_LOCK_REASON_SESSION_LOCK)
                                 ? "session lock"
                                 : "lid close/suspend";
    locked_count = lock_unlocked_vaults_for_reason(d, lock_reason, reason_str);

    if (locked_count > 0)
    {
        BIO_INFO("%s: locked %d vault(s)", reason_str, locked_count);
    }
}

static void emit_vault_locked_property_changed(GDBusConnection *connection,
                                               gboolean locked)
{
    static const char *paths[] = {
        BIOAUTH_DBUS_PATH,
        BIOAUTH_DAEMON_DBUS_PATH,
    };

    if (!connection)
    {
        return;
    }

    for (size_t i = 0; i < BIO_ARRAY_SIZE(paths); i++)
    {
        GError *err = NULL;
        GVariantBuilder changed_builder;
        GVariantBuilder invalidated_builder;

        g_variant_builder_init(&changed_builder, G_VARIANT_TYPE("a{sv}"));
        g_variant_builder_add(&changed_builder,
                              "{sv}",
                              "Locked",
                              g_variant_new_boolean(locked));
        g_variant_builder_init(&invalidated_builder, G_VARIANT_TYPE("as"));

        g_dbus_connection_emit_signal(
            connection,
            NULL,
            paths[i],
            "org.freedesktop.DBus.Properties",
            "PropertiesChanged",
            g_variant_new("(sa{sv}as)",
                          BIOAUTH_VAULT_DBUS_INTERFACE,
                          &changed_builder,
                          &invalidated_builder),
            &err);
        if (err)
        {
            BIO_WARN("Failed to emit Locked property change on %s: %s",
                     paths[i],
                     err->message);
            g_error_free(err);
        }
    }
}

/* ── Session management ──────────────────────────────────────── */

static int session_capacity(const bio_daemon_t *d)
{
    int cap = BIO_MAX_SESSIONS;
    if (d)
    {
        cap = d->config.max_sessions;
    }
    if (cap < 1)
        cap = 1;
    if (cap > BIO_MAX_SESSIONS)
        cap = BIO_MAX_SESSIONS;
    return cap;
}

static void prune_sessions_to_capacity(bio_daemon_t *d)
{
    if (!d)
        return;

    int cap = session_capacity(d);
    for (int i = cap; i < BIO_MAX_SESSIONS; i++)
    {
        if (!d->sessions[i].active)
            continue;

        bio_secure_wipe(d->sessions[i].session_key, 32);
        bio_munlock_sensitive(d->sessions[i].session_key, 32);
        d->sessions[i].active = false;
        if (d->session_count > 0)
            d->session_count--;
    }
}

static bio_session_t *find_session(bio_daemon_t *d,
                                   const uint8_t *token, size_t len)
{
    if (len != BIO_SESSION_TOKEN_SIZE)
        return NULL;

    time_t now = time(NULL);
    int cap = session_capacity(d);
    for (int i = 0; i < cap; i++)
    {
        if (!d->sessions[i].active)
            continue;

        /* Check expiry */
        if (now - d->sessions[i].created > d->config.session_max_age_seconds)
        {
            bio_secure_wipe(d->sessions[i].session_key, 32);
            bio_munlock_sensitive(d->sessions[i].session_key, 32);
            d->sessions[i].active = false;
            if (d->session_count > 0)
                d->session_count--;
            continue;
        }

        if (bio_constant_time_compare(d->sessions[i].token,
                                      token, BIO_SESSION_TOKEN_SIZE) == 0)
        {
            d->sessions[i].last_used = now;
            return &d->sessions[i];
        }
    }
    return NULL;
}

static bio_session_t *find_verified_session_for_sender(bio_daemon_t *d,
                                                       uid_t uid,
                                                       const char *sender,
                                                       guint *seconds_remaining)
{
    time_t now = time(NULL);
    int cap = session_capacity(d);

    if (seconds_remaining)
    {
        *seconds_remaining = 0;
    }

    for (int i = 0; i < cap; i++)
    {
        bio_session_t *sess = &d->sessions[i];
        if (!sess->active)
        {
            continue;
        }

        if (now - sess->created > d->config.session_max_age_seconds)
        {
            bio_secure_wipe(sess->session_key, 32);
            bio_munlock_sensitive(sess->session_key, 32);
            sess->active = false;
            if (d->session_count > 0)
            {
                d->session_count--;
            }
            continue;
        }

        if ((uid_t)sess->uid != uid)
        {
            continue;
        }
        if (!sess->verified)
        {
            continue;
        }
        if (sender && sess->sender[0] && strcmp(sender, sess->sender) != 0)
        {
            continue;
        }

        if (seconds_remaining)
        {
            time_t age = now - sess->created;
            if (age < d->config.session_max_age_seconds)
            {
                *seconds_remaining = (guint)(d->config.session_max_age_seconds - age);
            }
            else
            {
                *seconds_remaining = 0;
            }
        }

        sess->last_used = now;
        return sess;
    }

    return NULL;
}

static size_t revoke_sessions_for_sender(bio_daemon_t *d,
                                         uid_t uid,
                                         const char *sender)
{
    size_t revoked = 0;
    int cap = session_capacity(d);

    for (int i = 0; i < cap; i++)
    {
        bio_session_t *sess = &d->sessions[i];
        if (!sess->active)
        {
            continue;
        }
        if ((uid_t)sess->uid != uid)
        {
            continue;
        }
        if (sender && sess->sender[0] && strcmp(sender, sess->sender) != 0)
        {
            continue;
        }

        bio_secure_wipe(sess->session_key, 32);
        bio_munlock_sensitive(sess->session_key, 32);
        bio_secure_wipe(sess, sizeof(*sess));
        if (d->session_count > 0)
        {
            d->session_count--;
        }
        revoked++;
    }

    return revoked;
}

static bio_session_t *create_session(bio_daemon_t *d, uid_t uid,
                                     const char *sender)
{
    /* Find free slot */
    time_t now = time(NULL);
    bio_session_t *slot = NULL;
    int cap = session_capacity(d);

    for (int i = 0; i < cap; i++)
    {
        if (!d->sessions[i].active)
        {
            slot = &d->sessions[i];
            break;
        }
        if (now - d->sessions[i].created > d->config.session_max_age_seconds)
        {
            /* Expired session — wipe key, munlock, decrement count */
            bio_secure_wipe(d->sessions[i].session_key, 32);
            bio_munlock_sensitive(d->sessions[i].session_key, 32);
            d->sessions[i].active = false;
            if (d->session_count > 0)
                d->session_count--;
            slot = &d->sessions[i];
            break;
        }
    }

    if (!slot)
    {
        BIO_WARN("Session table full (cap=%d), cleaning oldest", cap);
        time_t oldest = now;
        for (int i = 0; i < cap; i++)
        {
            if (d->sessions[i].created < oldest)
            {
                oldest = d->sessions[i].created;
                slot = &d->sessions[i];
            }
        }
        /* Decrement for the evicted active session */
        if (slot && slot->active)
        {
            bio_secure_wipe(slot->session_key, 32);
            bio_munlock_sensitive(slot->session_key, 32);
            if (d->session_count > 0)
                d->session_count--;
        }
    }

    if (!slot)
        return NULL;

    bio_secure_wipe(slot, sizeof(*slot));
    if (bio_random_bytes(slot->token, BIO_SESSION_TOKEN_SIZE) != BIO_OK)
        return NULL;
    if (bio_random_bytes(slot->session_key, 32) != BIO_OK)
    {
        bio_secure_wipe(slot->token, BIO_SESSION_TOKEN_SIZE);
        return NULL;
    }
    if (bio_mlock_sensitive_strict(slot->session_key, 32) != BIO_OK)
    {
        bio_secure_wipe(slot, sizeof(*slot));
        return NULL;
    }
    slot->uid = uid;
    slot->created = now;
    slot->last_used = now;
    slot->active = true;
    slot->verified = false;
    if (sender)
    {
        strncpy(slot->sender, sender, sizeof(slot->sender) - 1);
    }

    d->session_count++;
    return slot;
}

/* ── Enrollment storage ──────────────────────────────────────── */

static int mkdir_p_secure(const char *path, mode_t mode)
{
    if (!path || path[0] != '/')
        return BIO_ERR_INVALID_PARAM;

    char tmp[PATH_MAX];
    size_t len = strnlen(path, sizeof(tmp));
    if (len == 0 || len >= sizeof(tmp))
        return BIO_ERR_INVALID_PARAM;

    memcpy(tmp, path, len + 1);

    for (char *p = tmp + 1; *p; p++)
    {
        if (*p != '/')
            continue;

        *p = '\0';
        if (mkdir(tmp, mode) != 0 && errno != EEXIST)
        {
            BIO_ERROR("Failed to create %s: %s", tmp, strerror(errno));
            return BIO_ERR_IO;
        }
        *p = '/';
    }

    if (mkdir(tmp, mode) != 0 && errno != EEXIST)
    {
        BIO_ERROR("Failed to create %s: %s", tmp, strerror(errno));
        return BIO_ERR_IO;
    }

    return BIO_OK;
}

static int ensure_state_dir(const char *state_dir)
{
    if (!state_dir || state_dir[0] != '/')
        return BIO_ERR_INVALID_PARAM;

    struct stat st;
    if (stat(state_dir, &st) == 0)
    {
        if (!S_ISDIR(st.st_mode))
        {
            BIO_ERROR("State path exists but is not a directory: %s", state_dir);
            return BIO_ERR_IO;
        }
        return BIO_OK;
    }

    int rc = mkdir_p_secure(state_dir, 0700);
    if (rc != BIO_OK)
        return rc;

    return BIO_OK;
}

static int add_enrollment(bio_daemon_t *d, const bio_enrollment_t *enroll)
{
    /* Check if already exists */
    for (size_t i = 0; i < d->enrollment_count; i++)
    {
        if (d->enrollments[i].uid == enroll->uid &&
            d->enrollments[i].finger == enroll->finger)
        {
            /* Replace */
            d->enrollments[i] = *enroll;
            return BIO_OK;
        }
    }

    /* Add new */
    if (d->enrollment_count >= d->enrollment_capacity)
    {
        size_t new_cap = d->enrollment_capacity
                             ? d->enrollment_capacity * 2
                             : 16;
        bio_enrollment_t *new_arr = realloc(d->enrollments,
                                            new_cap * sizeof(*new_arr));
        if (!new_arr)
            return BIO_ERR_NOMEM;
        d->enrollments = new_arr;
        d->enrollment_capacity = new_cap;
    }

    d->enrollments[d->enrollment_count++] = *enroll;
    return BIO_OK;
}

/* ── Configuration ───────────────────────────────────────────── */

static bool parse_config_bool(const char *val, bool *out)
{
    if (!val || !out)
        return false;

    if (strcmp(val, "1") == 0 ||
        strcasecmp(val, "true") == 0 ||
        strcasecmp(val, "yes") == 0 ||
        strcasecmp(val, "on") == 0)
    {
        *out = true;
        return true;
    }

    if (strcmp(val, "0") == 0 ||
        strcasecmp(val, "false") == 0 ||
        strcasecmp(val, "no") == 0 ||
        strcasecmp(val, "off") == 0)
    {
        *out = false;
        return true;
    }

    return false;
}

static bool parse_config_u32(const char *val, uint32_t *out)
{
    if (!val || !out)
        return false;

    char *end = NULL;
    errno = 0;
    unsigned long v = strtoul(val, &end, 0);
    while (*end == ' ' || *end == '\t')
        end++;

    if (end == val || *end != '\0' || errno == ERANGE || v > UINT32_MAX)
        return false;

    *out = (uint32_t)v;
    return true;
}

static bool parse_config_log_level(const char *val, int *level)
{
    if (!val || !level)
        return false;

    if (strcasecmp(val, "error") == 0)
        *level = BIO_LOG_ERROR;
    else if (strcasecmp(val, "warning") == 0)
        *level = BIO_LOG_WARNING;
    else if (strcasecmp(val, "info") == 0)
        *level = BIO_LOG_INFO;
    else if (strcasecmp(val, "debug") == 0)
        *level = BIO_LOG_DEBUG;
    else if (strcasecmp(val, "trace") == 0)
        *level = BIO_LOG_TRACE;
    else
        return false;

    return true;
}

void bio_daemon_config_defaults(bio_daemon_config_t *cfg)
{
    if (!cfg)
        return;
    memset(cfg, 0, sizeof(*cfg));
    cfg->max_sessions = BIO_MAX_SESSIONS;
    cfg->session_max_age_seconds = BIO_SESSION_MAX_AGE;
    cfg->max_enrollments_per_user = BIO_MAX_ENROLLMENTS_PER_USER;
    cfg->rate_limit_max_attempts = 5;
    cfg->rate_limit_lockout_seconds = 30;
    cfg->rate_limit_window_seconds = 60;
    cfg->tpm_enabled = true;
    cfg->tpm_fallback_to_plaintext = false; /* H2 fix: default secure */
    cfg->tpm_require = false;
    cfg->tpm_pcr_binding = false;
    cfg->tpm_pcr_index = 7;
    cfg->tpm_primary_handle = BIOAUTH_TPM_PRIMARY_HANDLE;
    strncpy(cfg->tpm_device, "/dev/tpmrm0", sizeof(cfg->tpm_device) - 1);
    strncpy(cfg->howdy_binary, "howdy", sizeof(cfg->howdy_binary) - 1);
    cfg->vault_idle_timeout_seconds = 1800; /* 30 minutes */
    strncpy(cfg->state_dir, BIOAUTH_STATE_DIR,
            sizeof(cfg->state_dir) - 1);
    strncpy(cfg->config_file, BIOAUTH_CONFIG_FILE,
            sizeof(cfg->config_file) - 1);
    cfg->log_to_journal = true;
    cfg->log_level = BIO_LOG_DEBUG;
}

/* Simple INI parser: key=value lines, # comments, [sections] skipped */
int bio_daemon_config_load(const char *path, bio_daemon_config_t *cfg)
{
    if (!path || !cfg)
        return BIO_ERR_INVALID_PARAM;

    FILE *f = fopen(path, "r");
    if (!f)
    {
        BIO_WARN("Config file not found: %s (using defaults)", path);
        return BIO_OK; /* Not fatal */
    }

    strncpy(cfg->config_file, path, sizeof(cfg->config_file) - 1);

    char line[512];
    int lineno = 0;
    while (fgets(line, sizeof(line), f))
    {
        lineno++;
        /* Strip trailing newline */
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
            line[--len] = '\0';

        /* Skip comments and empty lines */
        const char *p = line;
        while (*p == ' ' || *p == '\t')
            p++;
        if (*p == '#' || *p == ';' || *p == '\0')
            continue;

        /* Skip [section] headers */
        if (*p == '[')
            continue;

        /* Parse key=value */
        const char *eq = strchr(p, '=');
        if (!eq)
        {
            BIO_WARN("Config line %d: no '=' found", lineno);
            continue;
        }

        /* Extract key (trim trailing whitespace) */
        char key[128] = {0};
        size_t key_len = (size_t)(eq - p);
        if (key_len >= sizeof(key))
            key_len = sizeof(key) - 1;
        memcpy(key, p, key_len);
        while (key_len > 0 &&
               (key[key_len - 1] == ' ' || key[key_len - 1] == '\t'))
            key[--key_len] = '\0';

        /* Extract value (trim leading whitespace) */
        const char *val = eq + 1;
        while (*val == ' ' || *val == '\t')
            val++;

        /* Match known keys — use strtol for robust int parsing */
        if (strcmp(key, "max_sessions") == 0)
        {
            char *end;
            errno = 0;
            long v = strtol(val, &end, 10);
            while (*end == ' ' || *end == '\t')
                end++;
            if (*end == '\0' && errno != ERANGE && v > 0 && v <= BIO_MAX_SESSIONS)
                cfg->max_sessions = (int)v;
        }
        else if (strcmp(key, "session_max_age") == 0 ||
                 strcmp(key, "session_timeout") == 0)
        {
            char *end;
            errno = 0;
            long v = strtol(val, &end, 10);
            while (*end == ' ' || *end == '\t')
                end++;
            if (*end == '\0' && errno != ERANGE && v >= 10 && v <= 86400)
                cfg->session_max_age_seconds = (int)v;
        }
        else if (strcmp(key, "max_enrollments_per_user") == 0 ||
                 strcmp(key, "max_enrollments") == 0 ||
                 strcmp(key, "max_enroll_attempts") == 0)
        {
            char *end;
            errno = 0;
            long v = strtol(val, &end, 10);
            while (*end == ' ' || *end == '\t')
                end++;
            if (*end == '\0' && errno != ERANGE && v > 0 && v <= 100)
                cfg->max_enrollments_per_user = (int)v;
        }
        else if (strcmp(key, "rate_limit_max_attempts") == 0)
        {
            char *end;
            errno = 0;
            long v = strtol(val, &end, 10);
            while (*end == ' ' || *end == '\t')
                end++;
            if (*end == '\0' && errno != ERANGE && v >= 2 && v <= 100)
                cfg->rate_limit_max_attempts = (int)v;
        }
        else if (strcmp(key, "rate_limit_lockout_seconds") == 0 ||
                 strcmp(key, "rate_limit_lockout") == 0)
        {
            char *end;
            errno = 0;
            long v = strtol(val, &end, 10);
            while (*end == ' ' || *end == '\t')
                end++;
            if (*end == '\0' && errno != ERANGE && v >= 1 && v <= 3600)
                cfg->rate_limit_lockout_seconds = (int)v;
        }
        else if (strcmp(key, "rate_limit_window_seconds") == 0 ||
                 strcmp(key, "rate_limit_window") == 0)
        {
            char *end;
            errno = 0;
            long v = strtol(val, &end, 10);
            while (*end == ' ' || *end == '\t')
                end++;
            if (*end == '\0' && errno != ERANGE && v >= 1 && v <= 3600)
                cfg->rate_limit_window_seconds = (int)v;
        }
        else if (strcmp(key, "tpm_enabled") == 0)
        {
            bool parsed = false;
            if (parse_config_bool(val, &parsed))
                cfg->tpm_enabled = parsed;
            else
                BIO_WARN("Config line %d: invalid boolean for tpm_enabled: '%s'",
                         lineno, val);
        }
        else if (strcmp(key, "tpm_fallback_to_plaintext") == 0)
        {
            bool parsed = false;
            if (parse_config_bool(val, &parsed))
                cfg->tpm_fallback_to_plaintext = parsed;
            else
                BIO_WARN("Config line %d: invalid boolean for tpm_fallback_to_plaintext: '%s'",
                         lineno, val);
        }
        else if (strcmp(key, "tpm_require") == 0 ||
                 strcmp(key, "require_tpm") == 0)
        {
            bool parsed = false;
            if (parse_config_bool(val, &parsed))
                cfg->tpm_require = parsed;
            else
                BIO_WARN("Config line %d: invalid boolean for require_tpm: '%s'",
                         lineno, val);
        }
        else if (strcmp(key, "tpm_pcr_binding") == 0)
        {
            bool parsed = false;
            if (parse_config_bool(val, &parsed))
                cfg->tpm_pcr_binding = parsed;
            else
                BIO_WARN("Config line %d: invalid boolean for tpm_pcr_binding: '%s'",
                         lineno, val);
        }
        else if (strcmp(key, "tpm_pcr_index") == 0)
        {
            uint32_t v = 0;
            if (!parse_config_u32(val, &v) || v > 23)
            {
                BIO_WARN("Config line %d: tpm_pcr_index out of range "
                         "(0-23): '%s'",
                         lineno, val);
            }
            else
            {
                cfg->tpm_pcr_index = v;
            }
        }
        else if (strcmp(key, "tpm_device") == 0 ||
                 strcmp(key, "device") == 0)
        {
            if (val[0] != '/' || strstr(val, "..") != NULL)
            {
                BIO_WARN("Config line %d: TPM device must be an absolute path "
                         "without '..': '%s'",
                         lineno, val);
            }
            else
            {
                strncpy(cfg->tpm_device, val, sizeof(cfg->tpm_device) - 1);
            }
        }
        else if (strcmp(key, "howdy_binary") == 0 ||
                 strcmp(key, "face_howdy_binary") == 0)
        {
            if (strstr(val, "..") != NULL)
            {
                BIO_WARN("Config line %d: howdy_binary must not include '..': '%s'",
                         lineno, val);
            }
            else
            {
                strncpy(cfg->howdy_binary, val,
                        sizeof(cfg->howdy_binary) - 1);
            }
        }
        else if (strcmp(key, "tpm_primary_handle") == 0 ||
                 strcmp(key, "primary_handle") == 0)
        {
            uint32_t handle = 0;
            if (!parse_config_u32(val, &handle) ||
                handle < TPM2_PERSISTENT_FIRST ||
                handle > TPM2_PERSISTENT_LAST)
            {
                BIO_WARN("Config line %d: invalid tpm primary handle '%s' "
                         "(must be in 0x%08X-0x%08X)",
                         lineno, val,
                         TPM2_PERSISTENT_FIRST,
                         TPM2_PERSISTENT_LAST);
            }
            else
            {
                cfg->tpm_primary_handle = handle;
            }
        }
        else if (strcmp(key, "state_dir") == 0)
        {
            if (val[0] != '/' || strstr(val, "..") != NULL)
            {
                BIO_WARN("Config line %d: state_dir must be an "
                         "absolute path without '..': '%s'",
                         lineno, val);
            }
            else
            {
                strncpy(cfg->state_dir, val,
                        sizeof(cfg->state_dir) - 1);
            }
        }
        else if (strcmp(key, "device_driver") == 0)
        {
            strncpy(cfg->device_driver, val,
                    sizeof(cfg->device_driver) - 1);
        }
        else if (strcmp(key, "vault_idle_timeout") == 0 ||
                 strcmp(key, "vault_idle_timeout_seconds") == 0)
        {
            char *end;
            errno = 0;
            long v = strtol(val, &end, 10);
            while (*end == ' ' || *end == '\t')
                end++;
            if (*end == '\0' && errno != ERANGE && v >= 0 && v <= 86400)
                cfg->vault_idle_timeout_seconds = (int)v;
        }
        else if (strcmp(key, "log_to_journal") == 0)
        {
            bool parsed = false;
            if (parse_config_bool(val, &parsed))
                cfg->log_to_journal = parsed;
            else
                BIO_WARN("Config line %d: invalid boolean for log_to_journal: '%s'",
                         lineno, val);
        }
        else if (strcmp(key, "log_level") == 0)
        {
            int parsed_level = BIO_LOG_INFO;
            if (parse_config_log_level(val, &parsed_level))
            {
                cfg->log_level = parsed_level;
            }
            else
            {
                BIO_WARN("Config line %d: unknown log_level '%s' "
                         "(expected: error/warning/info/debug/trace)",
                         lineno, val);
            }
        }
        else
        {
            BIO_WARN("Config line %d: unknown key '%s'", lineno, key);
        }
    }

    fclose(f);
    BIO_INFO("Configuration loaded from %s", path);
    return BIO_OK;
}

bool bio_daemon_tpm_plaintext_fallback_allowed(const bio_daemon_config_t *cfg)
{
    if (!cfg)
        return false;
    return cfg->tpm_fallback_to_plaintext && !cfg->tpm_require;
}

static int daemon_tpm_seal_template(bio_daemon_t *d,
                                    const uint8_t *template_data,
                                    size_t template_len,
                                    uint8_t *sealed_blob,
                                    size_t *sealed_blob_len)
{
    if (!d || !template_data || !sealed_blob || !sealed_blob_len)
        return BIO_ERR_INVALID_PARAM;

    if (d->config.tpm_pcr_binding)
    {
        return bio_tpm_seal_for_user_pcr(&d->tpm_ctx,
                                         template_data,
                                         template_len,
                                         NULL,
                                         0,
                                         d->config.tpm_pcr_index,
                                         sealed_blob,
                                         sealed_blob_len);
    }

    return bio_tpm_seal_for_user(&d->tpm_ctx,
                                 template_data,
                                 template_len,
                                 NULL,
                                 0,
                                 sealed_blob,
                                 sealed_blob_len);
}

static int daemon_tpm_unseal_template(bio_daemon_t *d,
                                      const uint8_t *sealed_blob,
                                      size_t sealed_blob_len,
                                      uint8_t *template_data,
                                      size_t *template_len)
{
    if (!d || !sealed_blob || !template_data || !template_len)
        return BIO_ERR_INVALID_PARAM;

    if (d->config.tpm_pcr_binding)
    {
        return bio_tpm_unseal_for_user_pcr(&d->tpm_ctx,
                                           sealed_blob,
                                           sealed_blob_len,
                                           NULL,
                                           0,
                                           d->config.tpm_pcr_index,
                                           template_data,
                                           template_len);
    }

    return bio_tpm_unseal_for_user(&d->tpm_ctx,
                                   sealed_blob,
                                   sealed_blob_len,
                                   NULL,
                                   0,
                                   template_data,
                                   template_len);
}

/* ── Persistent enrollment storage ───────────────────────────── */

/*
 * Enrollment file format (per-user binary file):
 *   Path: <state_dir>/users/<uid>/enrollments.bin
 *   Header: magic(4) + version(2) + count(2)
 *   Per-entry: finger(1) + label(64) + created(8) +
 *              print_data_len(4) + print_data(var) +
 *              sealed_blob_len(4) + sealed_blob(var)
 */

#define ENROLLMENT_MAGIC 0x42415554 /* "BAUT" */
#define ENROLLMENT_VERSION 2        /* v2: HMAC-SHA-256 trailer */
#define ENROLLMENT_HMAC_KEY_LEN 32

/**
 * Load or generate the per-installation enrollment HMAC key.
 * Stored at <state_dir>/enrollment_hmac.key (mode 0600).
 * Returns BIO_OK on success, fills hmac_key with 32 bytes.
 */
static int get_enrollment_hmac_key(const char *state_dir,
                                   uint8_t hmac_key[32])
{
    char path[512];
    snprintf(path, sizeof(path), "%s/enrollment_hmac.key", state_dir);

    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd >= 0)
    {
        ssize_t n = read(fd, hmac_key, 32);
        close(fd);
        if (n == 32)
            return BIO_OK;
        BIO_WARN("HMAC key file truncated, regenerating");
    }

    /* Generate new key */
    int rc = bio_random_bytes(hmac_key, 32);
    if (rc != BIO_OK)
        return rc;

    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
    {
        BIO_ERROR("Cannot create HMAC key file %s: %s",
                  path, strerror(errno));
        return BIO_ERR_IO;
    }
    ssize_t n = write(fd, hmac_key, 32);
    fsync(fd);
    close(fd);
    if (n != 32)
    {
        BIO_ERROR("Failed to write HMAC key");
        return BIO_ERR_IO;
    }
    BIO_INFO("Generated new enrollment HMAC key at %s", path);
    return BIO_OK;
}

static int ensure_user_dir(const char *state_dir, uid_t uid)
{
    char path[512];
    /* D7 fix: Just call mkdir() and handle EEXIST — avoids TOCTOU race */
    snprintf(path, sizeof(path), "%s/users", state_dir);
    if (mkdir(path, 0700) != 0 && errno != EEXIST)
    {
        BIO_ERROR("Failed to create %s: %s", path, strerror(errno));
        return BIO_ERR_IO;
    }

    snprintf(path, sizeof(path), "%s/users/%u", state_dir, uid);
    if (mkdir(path, 0700) != 0 && errno != EEXIST)
    {
        BIO_ERROR("Failed to create %s: %s", path, strerror(errno));
        return BIO_ERR_IO;
    }

    return BIO_OK;
}

int bio_daemon_save_enrollments(const char *state_dir,
                                const bio_enrollment_t *enrollments,
                                size_t count)
{
    if (!state_dir || (!enrollments && count > 0))
        return BIO_ERR_INVALID_PARAM;

    /* Collect unique UIDs */
    uid_t uids[128];
    size_t uid_count = 0;

    for (size_t i = 0; i < count; i++)
    {
        bool found = false;
        for (size_t j = 0; j < uid_count; j++)
        {
            if (uids[j] == enrollments[i].uid)
            {
                found = true;
                break;
            }
        }
        if (!found && uid_count < 128)
        {
            uids[uid_count++] = enrollments[i].uid;
        }
    }

    int save_failures = 0;

    for (size_t u = 0; u < uid_count; u++)
    {
        uid_t uid = uids[u];
        int rc = ensure_user_dir(state_dir, uid);
        if (rc != BIO_OK)
            return rc;

        char path[512];
        snprintf(path, sizeof(path), "%s/users/%u/enrollments.bin",
                 state_dir, uid);

        /* H3 fix: Write to temp file, fsync, then rename atomically.
         * Prevents data loss if process crashes mid-write. */
        char tmp_path[520];
        snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", path);

        FILE *fp = NULL;
        {
            int fd = open(tmp_path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
            if (fd < 0)
            {
                BIO_ERROR("Cannot write %s: %s", tmp_path, strerror(errno));
                return BIO_ERR_IO;
            }
            fp = fdopen(fd, "w+b");
            if (!fp)
            {
                close(fd);
                BIO_ERROR("Cannot fdopen %s: %s", tmp_path, strerror(errno));
                return BIO_ERR_IO;
            }
        }

        /* Count this user's enrollments */
        uint16_t user_count = 0;
        for (size_t i = 0; i < count; i++)
        {
            if (enrollments[i].uid == uid)
                user_count++;
        }

        /* Header */
        uint32_t magic = ENROLLMENT_MAGIC;
        uint16_t version = ENROLLMENT_VERSION;
        bool write_ok = true;
        write_ok = write_ok && fwrite(&magic, 4, 1, fp) == 1;
        write_ok = write_ok && fwrite(&version, 2, 1, fp) == 1;
        write_ok = write_ok && fwrite(&user_count, 2, 1, fp) == 1;

        /* Entries */
        for (size_t i = 0; i < count && write_ok; i++)
        {
            if (enrollments[i].uid != uid)
                continue;

            const bio_enrollment_t *e = &enrollments[i];
            uint8_t finger = (uint8_t)e->finger;
            write_ok = write_ok && fwrite(&finger, 1, 1, fp) == 1;
            write_ok = write_ok && fwrite(e->label, 64, 1, fp) == 1;

            int64_t ts = (int64_t)e->created;
            write_ok = write_ok && fwrite(&ts, 8, 1, fp) == 1;

            uint32_t pd_len = (uint32_t)e->print_data_len;
            write_ok = write_ok && fwrite(&pd_len, 4, 1, fp) == 1;
            if (pd_len > 0)
                write_ok = write_ok && fwrite(e->print_data, 1, pd_len, fp) == pd_len;

            uint32_t sb_len = (uint32_t)e->sealed_blob_len;
            write_ok = write_ok && fwrite(&sb_len, 4, 1, fp) == 1;
            if (sb_len > 0)
            {
                write_ok = write_ok && fwrite(e->sealed_blob, 1, sb_len, fp) == sb_len;
            }
        }

        /* H1 fix: Compute HMAC-SHA-256 over all file content and append */
        if (write_ok)
        {
            fflush(fp);

            /* Read back what we wrote to compute HMAC */
            long file_len = ftell(fp);
            if (file_len <= 0)
            {
                write_ok = false;
            }
            else
            {
                uint8_t hmac_key[32];
                if (get_enrollment_hmac_key(state_dir, hmac_key) != BIO_OK)
                {
                    write_ok = false;
                }
                else
                {
                    /* Re-read the file content for HMAC */
                    rewind(fp);
                    uint8_t *file_buf = malloc((size_t)file_len);
                    if (!file_buf)
                    {
                        write_ok = false;
                    }
                    else
                    {
                        if (fread(file_buf, 1, (size_t)file_len, fp) !=
                            (size_t)file_len)
                        {
                            write_ok = false;
                        }
                        else
                        {
                            uint8_t mac[32];
                            bio_hmac_sha256(hmac_key, 32,
                                            file_buf, (size_t)file_len, mac);
                            /* Seek to end and append HMAC */
                            fseek(fp, 0, SEEK_END);
                            write_ok = fwrite(mac, 32, 1, fp) == 1;
                        }
                        free(file_buf);
                    }
                    bio_secure_wipe(hmac_key, 32);
                }
            }
        }

        /* H3 fix: Flush + fsync + atomic rename */
        if (write_ok)
        {
            fflush(fp);
            fsync(fileno(fp));
        }
        fclose(fp);
        if (!write_ok)
        {
            BIO_ERROR("Write error saving enrollments for UID %u", uid);
            unlink(tmp_path);
            save_failures++;
        }
        else
        {
            /* Atomic rename: either the full new file or the old file persists */
            if (rename(tmp_path, path) != 0)
            {
                BIO_ERROR("Failed to rename %s -> %s: %s",
                          tmp_path, path, strerror(errno));
                unlink(tmp_path);
                save_failures++;
            }
        }
        BIO_DEBUG("Saved %u enrollment(s) for UID %u", user_count, uid);
    }

    return (save_failures > 0) ? BIO_ERR_IO : BIO_OK;
}

int bio_daemon_load_enrollments(const char *state_dir,
                                bio_enrollment_t **enrollments,
                                size_t *count)
{
    if (!state_dir || !enrollments || !count)
        return BIO_ERR_INVALID_PARAM;

    *enrollments = NULL;
    *count = 0;

    char users_dir[512];
    snprintf(users_dir, sizeof(users_dir), "%s/users", state_dir);

    DIR *dir = opendir(users_dir);
    if (!dir)
    {
        BIO_DEBUG("No users directory: %s", users_dir);
        return BIO_OK; /* Not fatal */
    }

    size_t capacity = 16;
    bio_enrollment_t *arr = calloc(capacity, sizeof(bio_enrollment_t));
    if (!arr)
    {
        closedir(dir);
        return BIO_ERR_NOMEM;
    }

    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL)
    {
        if (ent->d_name[0] == '.')
            continue;

        char *end;
        errno = 0;
        unsigned long ul = strtoul(ent->d_name, &end, 10);
        if (*end != '\0' || errno == ERANGE)
            continue;
        if (end == ent->d_name)
            continue;
        if (ul > (unsigned long)(uid_t)-1)
            continue;
        uid_t uid = (uid_t)ul;

        char path[512];
        snprintf(path, sizeof(path), "%s/%s/enrollments.bin",
                 users_dir, ent->d_name);

        FILE *fp = fopen(path, "rbe"); /* 'e' = O_CLOEXEC */
        if (!fp)
            continue;

        /* H1 fix: Verify HMAC-SHA-256 before parsing enrollment data.
         * File format v2: [data...][HMAC-SHA-256(32 bytes)] */
        {
            fseek(fp, 0, SEEK_END);
            long file_len = ftell(fp);
            rewind(fp);

            /* File must be at least header(8) + HMAC(32) = 40 bytes */
            if (file_len < 40)
            {
                BIO_WARN("Enrollment file too small: %s", path);
                fclose(fp);
                continue;
            }

            size_t data_len = (size_t)file_len - 32;
            uint8_t *file_buf = malloc((size_t)file_len);
            if (!file_buf)
            {
                fclose(fp);
                closedir(dir);
                free(arr);
                return BIO_ERR_NOMEM;
            }

            if (fread(file_buf, 1, (size_t)file_len, fp) !=
                (size_t)file_len)
            {
                BIO_WARN("Short read on enrollment file: %s", path);
                free(file_buf);
                fclose(fp);
                continue;
            }

            uint8_t hmac_key[32];
            if (get_enrollment_hmac_key(state_dir, hmac_key) != BIO_OK)
            {
                BIO_ERROR("Cannot load HMAC key for enrollment verification");
                free(file_buf);
                fclose(fp);
                closedir(dir);
                free(arr);
                bio_secure_wipe(hmac_key, 32);
                return BIO_ERR_CRYPTO_INIT;
            }

            uint8_t expected_mac[32];
            bio_hmac_sha256(hmac_key, 32, file_buf, data_len, expected_mac);
            bio_secure_wipe(hmac_key, 32);

            if (bio_constant_time_compare(expected_mac, file_buf + data_len,
                                          32) != 0)
            {
                BIO_ERROR("HMAC verification failed for %s — "
                          "enrollment file may be tampered!",
                          path);
                free(file_buf);
                fclose(fp);
                continue;
            }
            free(file_buf);

            /* Rewind to parse the verified data */
            rewind(fp);
        }

        uint32_t magic;
        uint16_t version, file_count;

        if (fread(&magic, 4, 1, fp) != 1 ||
            magic != ENROLLMENT_MAGIC)
        {
            BIO_WARN("Invalid enrollment file: %s", path);
            fclose(fp);
            continue;
        }
        if (fread(&version, 2, 1, fp) != 1 ||
            version != ENROLLMENT_VERSION)
        {
            BIO_WARN("Unsupported enrollment version in %s", path);
            fclose(fp);
            continue;
        }
        if (fread(&file_count, 2, 1, fp) != 1)
        {
            fclose(fp);
            continue;
        }

        for (uint16_t i = 0; i < file_count; i++)
        {
            if (*count >= capacity)
            {
                capacity *= 2;
                bio_enrollment_t *new_arr = realloc(
                    arr, capacity * sizeof(*arr));
                if (!new_arr)
                {
                    fclose(fp);
                    closedir(dir);
                    free(arr);
                    return BIO_ERR_NOMEM;
                }
                arr = new_arr;
            }

            bio_enrollment_t *e = &arr[*count];
            memset(e, 0, sizeof(*e));
            e->uid = uid;

            uint8_t finger;
            if (fread(&finger, 1, 1, fp) != 1)
                break;
            e->finger = (bio_finger_t)finger;

            if (fread(e->label, 64, 1, fp) != 1)
                break;

            int64_t ts;
            if (fread(&ts, 8, 1, fp) != 1)
                break;
            e->created = (time_t)ts;

            uint32_t pd_len;
            if (fread(&pd_len, 4, 1, fp) != 1)
                break;
            if (pd_len > BIO_MAX_PRINT_DATA_SIZE)
                break;
            e->print_data_len = pd_len;
            if (fread(e->print_data, 1, pd_len, fp) != pd_len)
                break;

            uint32_t sb_len;
            if (fread(&sb_len, 4, 1, fp) != 1)
                break;
            if (sb_len > sizeof(e->sealed_blob))
                break;
            e->sealed_blob_len = sb_len;
            if (sb_len > 0)
            {
                if (fread(e->sealed_blob, 1, sb_len, fp) != sb_len)
                    break;
            }

            (*count)++;
        }

        fclose(fp);
        BIO_DEBUG("Loaded enrollments for UID %u from %s", uid, path);
    }

    closedir(dir);
    *enrollments = arr;
    BIO_INFO("Loaded %zu enrollment(s) from %s", *count, state_dir);
    return BIO_OK;
}

/* ── Challenge-Response ──────────────────────────────────────── */

int bio_daemon_generate_challenge(uint8_t challenge[32])
{
    if (!challenge)
        return BIO_ERR_INVALID_PARAM;
    return bio_random_bytes(challenge, 32);
}

int bio_daemon_verify_challenge(const uint8_t challenge[32],
                                const uint8_t *response,
                                size_t response_len,
                                const uint8_t *session_key,
                                size_t key_len)
{
    if (!challenge || !response || !session_key)
        return BIO_ERR_INVALID_PARAM;

    /* Compute expected HMAC-SHA256(session_key, challenge) */
    uint8_t expected[32];
    int rc = bio_hmac_sha256(session_key, key_len,
                             challenge, 32, expected);
    if (rc != BIO_OK)
        return rc;

    /* Constant-time comparison */
    if (response_len != 32 ||
        bio_constant_time_compare(expected, response, 32) != 0)
    {
        bio_secure_wipe(expected, 32);
        return BIO_ERR_CRYPTO_MAC;
    }

    bio_secure_wipe(expected, 32);
    return BIO_OK;
}

/* ── Signal emission helpers ──────────────────────────────────── */

static void emit_enroll_progress(bio_daemon_t *d,
                                 int16_t status, int16_t stage,
                                 int16_t total)
{
    if (!d || !d->bus)
        return;

    GError *err = NULL;
    g_dbus_connection_emit_signal(
        d->bus, NULL,
        BIOAUTH_DBUS_PATH, BIOAUTH_DBUS_INTERFACE,
        "EnrollProgress",
        g_variant_new("(nnn)", status, stage, total),
        &err);
    if (err)
    {
        BIO_WARN("Failed to emit EnrollProgress: %s", err->message);
        g_error_free(err);
    }
}

static void emit_device_added(bio_daemon_t *d, const char *name)
{
    if (!d || !d->bus)
        return;
    GError *err = NULL;
    g_dbus_connection_emit_signal(
        d->bus, NULL,
        BIOAUTH_DBUS_PATH, BIOAUTH_DBUS_INTERFACE,
        "DeviceAdded", g_variant_new("(s)", name), &err);
    if (err)
    {
        BIO_WARN("Failed to emit DeviceAdded: %s", err->message);
        g_error_free(err);
    }
}

static void emit_device_removed(bio_daemon_t *d, const char *name)
{
    if (!d || !d->bus)
        return;
    GError *err = NULL;
    g_dbus_connection_emit_signal(
        d->bus, NULL,
        BIOAUTH_DBUS_PATH, BIOAUTH_DBUS_INTERFACE,
        "DeviceRemoved", g_variant_new("(s)", name), &err);
    if (err)
    {
        BIO_WARN("Failed to emit DeviceRemoved: %s", err->message);
        g_error_free(err);
    }
}

static bool object_path_is_daemon_api(const gchar *object_path)
{
    return object_path && strcmp(object_path, BIOAUTH_DAEMON_DBUS_PATH) == 0;
}

static void session_token_to_hex(const uint8_t *token,
                                 size_t token_len,
                                 char *out,
                                 size_t out_len)
{
    static const char hex[] = "0123456789abcdef";

    if (!token || !out || out_len < (token_len * 2u) + 1u)
    {
        if (out && out_len > 0)
        {
            out[0] = '\0';
        }
        return;
    }

    for (size_t i = 0; i < token_len; i++)
    {
        out[(i * 2u)] = hex[(token[i] >> 4) & 0x0Fu];
        out[(i * 2u) + 1u] = hex[token[i] & 0x0Fu];
    }
    out[token_len * 2u] = '\0';
}

static void emit_auth_state_changed(bio_daemon_t *d,
                                    gboolean authenticated,
                                    const char *method)
{
    if (!d || !d->bus)
    {
        return;
    }

    GError *err = NULL;
    g_dbus_connection_emit_signal(
        d->bus,
        NULL,
        BIOAUTH_DAEMON_DBUS_PATH,
        BIOAUTH_AUTH_DBUS_INTERFACE,
        "AuthStateChanged",
        g_variant_new("(bs)", authenticated, method ? method : "unknown"),
        &err);
    if (err)
    {
        BIO_WARN("Failed to emit AuthStateChanged: %s", err->message);
        g_error_free(err);
    }
}

static void emit_uv_success(bio_daemon_t *d,
                            const char *session_id,
                            const char *username)
{
    if (!d || !d->bus)
    {
        return;
    }

    GError *err = NULL;
    g_dbus_connection_emit_signal(
        d->bus,
        NULL,
        BIOAUTH_DAEMON_DBUS_PATH,
        BIOAUTH_AUTH_DBUS_INTERFACE,
        "UV_SUCCESS",
        g_variant_new("(ss)",
                      session_id ? session_id : "",
                      username ? username : ""),
        &err);
    if (err)
    {
        BIO_WARN("Failed to emit UV_SUCCESS: %s", err->message);
        g_error_free(err);
    }
}

static void emit_enroll_progress_v2(bio_daemon_t *d,
                                    const char *session_id,
                                    guint percent,
                                    const char *hint)
{
    if (!d || !d->bus)
    {
        return;
    }

    GError *err = NULL;
    g_dbus_connection_emit_signal(
        d->bus,
        NULL,
        BIOAUTH_DAEMON_DBUS_PATH,
        BIOAUTH_ENROLL_DBUS_INTERFACE,
        "EnrollProgress",
        g_variant_new("(sus)",
                      session_id ? session_id : "",
                      percent,
                      hint ? hint : ""),
        &err);
    if (err)
    {
        BIO_WARN("Failed to emit EnrollProgress v2: %s", err->message);
        g_error_free(err);
    }
}

static void emit_vault_state_changed(bio_daemon_t *d, const char *state)
{
    static const char *paths[] = {
        BIOAUTH_DBUS_PATH,
        BIOAUTH_DAEMON_DBUS_PATH,
    };

    if (!d || !d->bus)
    {
        return;
    }

    for (size_t i = 0; i < BIO_ARRAY_SIZE(paths); i++)
    {
        GError *err = NULL;
        g_dbus_connection_emit_signal(
            d->bus,
            NULL,
            paths[i],
            BIOAUTH_VAULT_DBUS_INTERFACE,
            "VaultStateChanged",
            g_variant_new("(s)", state ? state : "unknown"),
            &err);
        if (err)
        {
            BIO_WARN("Failed to emit VaultStateChanged on %s: %s",
                     paths[i],
                     err->message);
            g_error_free(err);
        }
    }
}

static void emit_vault_unlocked(bio_daemon_t *d, uid_t uid)
{
    static const char *paths[] = {
        BIOAUTH_DBUS_PATH,
        BIOAUTH_DAEMON_DBUS_PATH,
    };

    if (!d || !d->bus)
    {
        return;
    }

    for (size_t i = 0; i < BIO_ARRAY_SIZE(paths); i++)
    {
        GError *err = NULL;
        g_dbus_connection_emit_signal(
            d->bus,
            NULL,
            paths[i],
            BIOAUTH_VAULT_DBUS_INTERFACE,
            "VaultUnlocked",
            g_variant_new("(u)", (guint32)uid),
            &err);
        if (err)
        {
            BIO_WARN("Failed to emit VaultUnlocked on %s: %s",
                     paths[i],
                     err->message);
            g_error_free(err);
        }
    }
}

static int username_for_uid(uid_t uid, char *out, size_t out_len)
{
    struct passwd pw_buf;
    struct passwd *pw = NULL;
    char pw_storage[512];

    if (!out || out_len == 0)
    {
        return BIO_ERR_INVALID_PARAM;
    }

    if (getpwuid_r(uid, &pw_buf, pw_storage, sizeof(pw_storage), &pw) != 0 ||
        !pw ||
        !pw->pw_name)
    {
        return BIO_ERR_NOT_FOUND;
    }

    if (snprintf(out, out_len, "%s", pw->pw_name) >= (int)out_len)
    {
        return BIO_ERR_BUFFER_TOO_SMALL;
    }

    return BIO_OK;
}

static const char *howdy_binary_path(const bio_daemon_t *d)
{
    const char *override = getenv(BIOAUTH_HOWDY_BIN_ENV);

    if (override && override[0] != '\0')
    {
        return override;
    }

    if (d && d->config.howdy_binary[0] != '\0')
    {
        return d->config.howdy_binary;
    }

    return "howdy";
}

static bool howdy_binary_available(const bio_daemon_t *d)
{
    const char *binary = howdy_binary_path(d);

    if (!binary || binary[0] == '\0')
    {
        return false;
    }

    if (binary[0] == '/')
    {
        return access(binary, X_OK) == 0;
    }

    char *resolved = g_find_program_in_path(binary);
    bool found = resolved != NULL;
    g_free(resolved);
    return found;
}

static int run_howdy_command(const char *username,
                             const bio_daemon_t *d,
                             const char *subcommand,
                             const char *arg1,
                             const char *arg2,
                             const char *arg3,
                             gchar **out_stdout,
                             gchar **out_stderr,
                             gchar **out_error_text)
{
    gchar *argv[12] = {0};
    int argc = 0;
    gint wait_status = 0;
    gboolean spawned;
    GError *err = NULL;
    gchar *stdout_text = NULL;
    gchar *stderr_text = NULL;
    int rc = BIO_ERR_IO;

    if (!subcommand || subcommand[0] == '\0')
    {
        return BIO_ERR_INVALID_PARAM;
    }

    argv[argc++] = g_strdup(howdy_binary_path(d));
    if (username && username[0] != '\0')
    {
        argv[argc++] = g_strdup("-U");
        argv[argc++] = g_strdup(username);
    }
    argv[argc++] = g_strdup(subcommand);

    if (arg1 && arg1[0] != '\0')
    {
        argv[argc++] = g_strdup(arg1);
    }
    if (arg2 && arg2[0] != '\0')
    {
        argv[argc++] = g_strdup(arg2);
    }
    if (arg3 && arg3[0] != '\0')
    {
        argv[argc++] = g_strdup(arg3);
    }
    argv[argc] = NULL;

    spawned = g_spawn_sync(NULL,
                           argv,
                           NULL,
                           G_SPAWN_SEARCH_PATH,
                           NULL,
                           NULL,
                           &stdout_text,
                           &stderr_text,
                           &wait_status,
                           &err);
    if (!spawned)
    {
        if (out_error_text)
        {
            *out_error_text = g_strdup(err ? err->message : "failed to execute howdy command");
        }
        rc = (err && g_error_matches(err, G_SPAWN_ERROR, G_SPAWN_ERROR_NOENT))
                 ? BIO_ERR_NOT_FOUND
                 : BIO_ERR_IO;
    }
    else if (!WIFEXITED(wait_status) || WEXITSTATUS(wait_status) != 0)
    {
        if (out_error_text)
        {
            if (!WIFEXITED(wait_status))
            {
                *out_error_text = g_strdup("howdy command exited abnormally");
            }
            else
            {
                *out_error_text = g_strdup_printf("howdy exited with status %d", WEXITSTATUS(wait_status));
            }
        }
        rc = BIO_ERR_PERMISSION;
    }
    else
    {
        rc = BIO_OK;
    }

    if (err)
    {
        g_error_free(err);
    }

    for (int i = 0; i < argc; i++)
    {
        g_free(argv[i]);
    }

    if (out_stdout)
    {
        *out_stdout = stdout_text;
    }
    else
    {
        g_free(stdout_text);
    }

    if (out_stderr)
    {
        *out_stderr = stderr_text;
    }
    else
    {
        g_free(stderr_text);
    }

    return rc;
}

static void prune_face_enroll_sessions_locked(bio_daemon_t *d, time_t now)
{
    if (!d)
    {
        return;
    }

    for (size_t i = 0; i < BIO_MAX_FACE_ENROLL_SESSIONS; i++)
    {
        bio_face_enroll_session_t *slot = &d->face_enroll_sessions[i];
        if (!slot->active)
        {
            continue;
        }

        if (now - slot->created > BIO_FACE_ENROLL_SESSION_TTL)
        {
            memset(slot, 0, sizeof(*slot));
        }
    }
}

static bool create_face_enroll_session(bio_daemon_t *d,
                                       uid_t uid,
                                       const char *session_id,
                                       const char *label)
{
    bool created = false;

    if (!d || !session_id || session_id[0] == '\0')
    {
        return false;
    }

    pthread_mutex_lock(&d->data_lock);
    prune_face_enroll_sessions_locked(d, time(NULL));

    for (size_t i = 0; i < BIO_MAX_FACE_ENROLL_SESSIONS; i++)
    {
        bio_face_enroll_session_t *slot = &d->face_enroll_sessions[i];
        if (slot->active)
        {
            continue;
        }

        memset(slot, 0, sizeof(*slot));
        slot->active = true;
        slot->uid = uid;
        slot->created = time(NULL);
        snprintf(slot->session_id, sizeof(slot->session_id), "%s", session_id);
        if (label)
        {
            snprintf(slot->label, sizeof(slot->label), "%s", label);
        }
        created = true;
        break;
    }

    pthread_mutex_unlock(&d->data_lock);
    return created;
}

static bool get_face_enroll_session_label(bio_daemon_t *d,
                                          uid_t uid,
                                          const char *session_id,
                                          char *out_label,
                                          size_t out_label_len)
{
    bool found = false;

    if (!d || !session_id || session_id[0] == '\0')
    {
        return false;
    }

    pthread_mutex_lock(&d->data_lock);
    prune_face_enroll_sessions_locked(d, time(NULL));

    for (size_t i = 0; i < BIO_MAX_FACE_ENROLL_SESSIONS; i++)
    {
        bio_face_enroll_session_t *slot = &d->face_enroll_sessions[i];
        if (!slot->active || slot->uid != uid)
        {
            continue;
        }

        if (strcmp(slot->session_id, session_id) != 0)
        {
            continue;
        }

        if (out_label && out_label_len > 0)
        {
            snprintf(out_label, out_label_len, "%s", slot->label);
        }
        found = true;
        break;
    }

    pthread_mutex_unlock(&d->data_lock);
    return found;
}

static bool clear_face_enroll_session(bio_daemon_t *d,
                                      uid_t uid,
                                      const char *session_id)
{
    bool cleared = false;

    if (!d || !session_id || session_id[0] == '\0')
    {
        return false;
    }

    pthread_mutex_lock(&d->data_lock);
    for (size_t i = 0; i < BIO_MAX_FACE_ENROLL_SESSIONS; i++)
    {
        bio_face_enroll_session_t *slot = &d->face_enroll_sessions[i];
        if (!slot->active || slot->uid != uid)
        {
            continue;
        }

        if (strcmp(slot->session_id, session_id) == 0)
        {
            memset(slot, 0, sizeof(*slot));
            cleared = true;
            break;
        }
    }
    pthread_mutex_unlock(&d->data_lock);

    return cleared;
}

static int howdy_verify_user(const bio_daemon_t *d,
                             const char *username,
                             gchar **out_detail)
{
    gchar *stdout_text = NULL;
    gchar *stderr_text = NULL;
    gchar *err_text = NULL;
    int rc;

    if (!username || username[0] == '\0')
    {
        return BIO_ERR_INVALID_PARAM;
    }

    rc = run_howdy_command(username,
                           d,
                           "test",
                           NULL,
                           NULL,
                           NULL,
                           &stdout_text,
                           &stderr_text,
                           &err_text);
    if (rc != BIO_OK)
    {
        g_free(stdout_text);
        g_free(stderr_text);
        g_free(err_text);
        stdout_text = NULL;
        stderr_text = NULL;
        err_text = NULL;

        /* Compatibility fallback for installations using a different verb. */
        rc = run_howdy_command(username,
                               d,
                               "verify",
                               NULL,
                               NULL,
                               NULL,
                               &stdout_text,
                               &stderr_text,
                               &err_text);
    }

    if (out_detail)
    {
        if (rc == BIO_OK)
        {
            if (stdout_text && stdout_text[0] != '\0')
            {
                *out_detail = g_strdup(stdout_text);
            }
            else if (stderr_text && stderr_text[0] != '\0')
            {
                *out_detail = g_strdup(stderr_text);
            }
            else
            {
                *out_detail = g_strdup("howdy verification succeeded");
            }
        }
        else
        {
            if (stderr_text && stderr_text[0] != '\0')
            {
                *out_detail = g_strdup(stderr_text);
            }
            else if (err_text && err_text[0] != '\0')
            {
                *out_detail = g_strdup(err_text);
            }
            else
            {
                *out_detail = g_strdup("howdy verification failed");
            }
        }
    }

    g_free(stdout_text);
    g_free(stderr_text);
    g_free(err_text);
    return rc;
}

static int howdy_enroll_face(const bio_daemon_t *d,
                             const char *username,
                             const char *label,
                             gchar **out_detail)
{
    gchar *stdout_text = NULL;
    gchar *stderr_text = NULL;
    gchar *err_text = NULL;
    int rc;

    if (!username || username[0] == '\0')
    {
        return BIO_ERR_INVALID_PARAM;
    }

    rc = run_howdy_command(username,
                           d,
                           "add",
                           (label && label[0] != '\0') ? label : NULL,
                           NULL,
                           NULL,
                           &stdout_text,
                           &stderr_text,
                           &err_text);
    if (rc != BIO_OK && label && label[0] != '\0')
    {
        g_free(stdout_text);
        g_free(stderr_text);
        g_free(err_text);
        stdout_text = NULL;
        stderr_text = NULL;
        err_text = NULL;

        /* Some Howdy builds accept add without a label argument. */
        rc = run_howdy_command(username,
                               d,
                               "add",
                               NULL,
                               NULL,
                               NULL,
                               &stdout_text,
                               &stderr_text,
                               &err_text);
    }

    if (out_detail)
    {
        if (rc == BIO_OK)
        {
            if (stdout_text && stdout_text[0] != '\0')
            {
                *out_detail = g_strdup(stdout_text);
            }
            else
            {
                *out_detail = g_strdup("howdy enrollment completed");
            }
        }
        else if (stderr_text && stderr_text[0] != '\0')
        {
            *out_detail = g_strdup(stderr_text);
        }
        else if (err_text && err_text[0] != '\0')
        {
            *out_detail = g_strdup(err_text);
        }
        else
        {
            *out_detail = g_strdup("howdy enrollment failed");
        }
    }

    g_free(stdout_text);
    g_free(stderr_text);
    g_free(err_text);
    return rc;
}

static bool parse_howdy_face_list_line(const char *line,
                                       char *out_face_id,
                                       size_t out_face_id_len,
                                       char *out_label,
                                       size_t out_label_len)
{
    const char *cursor;
    char *endptr = NULL;
    long id_value;

    if (!line || !out_face_id || out_face_id_len == 0 ||
        !out_label || out_label_len == 0)
    {
        return false;
    }

    cursor = line;
    while (*cursor && (g_ascii_isspace(*cursor) || *cursor == '-' || *cursor == '*'))
    {
        cursor++;
    }

    if (!g_ascii_isdigit(*cursor))
    {
        return false;
    }

    errno = 0;
    id_value = strtol(cursor, &endptr, 10);
    if (errno != 0 || endptr == cursor || id_value < 0)
    {
        return false;
    }

    while (*endptr &&
           (g_ascii_isspace(*endptr) || *endptr == ':' ||
            *endptr == '.' || *endptr == ')' || *endptr == '-'))
    {
        endptr++;
    }

    if (snprintf(out_face_id, out_face_id_len, "%ld", id_value) >= (int)out_face_id_len)
    {
        return false;
    }

    snprintf(out_label, out_label_len, "%s", *endptr ? endptr : "Face model");
    g_strstrip(out_label);
    if (out_label[0] == '\0')
    {
        snprintf(out_label, out_label_len, "Face model %ld", id_value);
    }

    return true;
}

static const char *finger_id_to_string(bio_finger_t finger)
{
    switch (finger)
    {
    case BIO_FINGER_LEFT_THUMB:
        return "left-thumb";
    case BIO_FINGER_LEFT_INDEX:
        return "left-index-finger";
    case BIO_FINGER_LEFT_MIDDLE:
        return "left-middle-finger";
    case BIO_FINGER_LEFT_RING:
        return "left-ring-finger";
    case BIO_FINGER_LEFT_LITTLE:
        return "left-little-finger";
    case BIO_FINGER_RIGHT_THUMB:
        return "right-thumb";
    case BIO_FINGER_RIGHT_INDEX:
        return "right-index-finger";
    case BIO_FINGER_RIGHT_MIDDLE:
        return "right-middle-finger";
    case BIO_FINGER_RIGHT_RING:
        return "right-ring-finger";
    case BIO_FINGER_RIGHT_LITTLE:
        return "right-little-finger";
    default:
        return "unknown";
    }
}

static bool parse_finger_id_string(const char *finger_id,
                                   bio_finger_t *out_finger)
{
    long numeric = 0;
    char *endptr = NULL;

    if (!finger_id || !out_finger || finger_id[0] == '\0')
    {
        return false;
    }

    errno = 0;
    numeric = strtol(finger_id, &endptr, 10);
    if (errno == 0 && endptr && *endptr == '\0' && numeric >= 1 && numeric <= 10)
    {
        *out_finger = (bio_finger_t)numeric;
        return true;
    }

    if (strcasecmp(finger_id, "left-thumb") == 0 ||
        strcasecmp(finger_id, "left_thumb") == 0 ||
        strcasecmp(finger_id, "left thumb") == 0)
    {
        *out_finger = BIO_FINGER_LEFT_THUMB;
        return true;
    }
    if (strcasecmp(finger_id, "left-index-finger") == 0 ||
        strcasecmp(finger_id, "left_index_finger") == 0 ||
        strcasecmp(finger_id, "left index") == 0)
    {
        *out_finger = BIO_FINGER_LEFT_INDEX;
        return true;
    }
    if (strcasecmp(finger_id, "left-middle-finger") == 0 ||
        strcasecmp(finger_id, "left_middle_finger") == 0 ||
        strcasecmp(finger_id, "left middle") == 0)
    {
        *out_finger = BIO_FINGER_LEFT_MIDDLE;
        return true;
    }
    if (strcasecmp(finger_id, "left-ring-finger") == 0 ||
        strcasecmp(finger_id, "left_ring_finger") == 0 ||
        strcasecmp(finger_id, "left ring") == 0)
    {
        *out_finger = BIO_FINGER_LEFT_RING;
        return true;
    }
    if (strcasecmp(finger_id, "left-little-finger") == 0 ||
        strcasecmp(finger_id, "left_little_finger") == 0 ||
        strcasecmp(finger_id, "left little") == 0)
    {
        *out_finger = BIO_FINGER_LEFT_LITTLE;
        return true;
    }
    if (strcasecmp(finger_id, "right-thumb") == 0 ||
        strcasecmp(finger_id, "right_thumb") == 0 ||
        strcasecmp(finger_id, "right thumb") == 0)
    {
        *out_finger = BIO_FINGER_RIGHT_THUMB;
        return true;
    }
    if (strcasecmp(finger_id, "right-index-finger") == 0 ||
        strcasecmp(finger_id, "right_index_finger") == 0 ||
        strcasecmp(finger_id, "right index") == 0)
    {
        *out_finger = BIO_FINGER_RIGHT_INDEX;
        return true;
    }
    if (strcasecmp(finger_id, "right-middle-finger") == 0 ||
        strcasecmp(finger_id, "right_middle_finger") == 0 ||
        strcasecmp(finger_id, "right middle") == 0)
    {
        *out_finger = BIO_FINGER_RIGHT_MIDDLE;
        return true;
    }
    if (strcasecmp(finger_id, "right-ring-finger") == 0 ||
        strcasecmp(finger_id, "right_ring_finger") == 0 ||
        strcasecmp(finger_id, "right ring") == 0)
    {
        *out_finger = BIO_FINGER_RIGHT_RING;
        return true;
    }
    if (strcasecmp(finger_id, "right-little-finger") == 0 ||
        strcasecmp(finger_id, "right_little_finger") == 0 ||
        strcasecmp(finger_id, "right little") == 0)
    {
        *out_finger = BIO_FINGER_RIGHT_LITTLE;
        return true;
    }

    return false;
}

/* Enroll callback that emits D-Bus signals */
typedef struct
{
    bio_daemon_t *daemon;
} daemon_enroll_ctx_t;

static void daemon_enroll_cb(bio_fp_enroll_status_t status,
                             int stage, int total_stages,
                             void *user_data)
{
    daemon_enroll_ctx_t *ec = user_data;
    if (!ec || !ec->daemon)
        return;

    emit_enroll_progress(ec->daemon, (int16_t)status,
                         (int16_t)stage, (int16_t)total_stages);
}

/* ── Per-user rate limiting ───────────────────────────────────── */

/*
 * Find or create a rate limiter slot for a given UID.
 * Returns pointer to the slot, or NULL if the table is full.
 */
static typeof(((bio_daemon_t *)0)->rate_limiters[0]) *
find_rate_limiter(bio_daemon_t *d, uid_t uid)
{
    /* Search existing */
    for (int i = 0; i < d->rate_limiter_count; i++)
    {
        if (d->rate_limiters[i].uid == uid)
        {
            return &d->rate_limiters[i];
        }
    }

    /* Allocate new slot */
    if (d->rate_limiter_count < 128)
    {
        int idx = d->rate_limiter_count++;
        memset(&d->rate_limiters[idx], 0, sizeof(d->rate_limiters[idx]));
        d->rate_limiters[idx].uid = uid;
        return &d->rate_limiters[idx];
    }

    /* Table full — evict the entry with the oldest last-activity.
     * Use the latest failure timestamp as the activity indicator. */
    int oldest_idx = 0;
    time_t oldest_time = d->rate_limiters[0].failures[0];
    for (int i = 0; i < 128; i++)
    {
        /* Find the most recent failure for this entry */
        time_t latest = 0;
        for (int j = 0; j < 32; j++)
        {
            if (d->rate_limiters[i].failures[j] > latest)
                latest = d->rate_limiters[i].failures[j];
        }
        if (d->rate_limiters[i].lockout_until > latest)
            latest = d->rate_limiters[i].lockout_until;
        if (i == 0 || latest < oldest_time)
        {
            oldest_time = latest;
            oldest_idx = i;
        }
    }
    memset(&d->rate_limiters[oldest_idx], 0,
           sizeof(d->rate_limiters[oldest_idx]));
    d->rate_limiters[oldest_idx].uid = uid;
    return &d->rate_limiters[oldest_idx];
}

/*
 * Monotonic clock for rate limiting (immune to NTP adjustments).
 */
static time_t monotonic_seconds(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec;
}

/*
 * Check whether a user is currently rate-limited.
 * Returns BIO_OK if allowed, BIO_ERR_FP_RATE_LIMIT if locked out.
 * Sets *lockout_remaining to seconds remaining in lockout.
 */
static int check_verify_rate_limit(bio_daemon_t *d, uid_t uid,
                                   int *lockout_remaining)
{
    typeof(((bio_daemon_t *)0)->rate_limiters[0]) *rl =
        find_rate_limiter(d, uid);
    if (!rl)
    {
        /* Table full — fail closed to prevent bypass via table exhaustion */
        BIO_WARN("Rate limiter table full, denying UID %u", uid);
        if (lockout_remaining)
            *lockout_remaining = 60;
        return BIO_ERR_FP_RATE_LIMIT;
    }

    time_t now = monotonic_seconds();

    /* Check active lockout */
    if (rl->lockout_until > now)
    {
        if (lockout_remaining)
        {
            *lockout_remaining = (int)(rl->lockout_until - now);
        }
        return BIO_ERR_FP_RATE_LIMIT;
    }

    /* Lockout expired — reset */
    if (rl->lockout_until > 0 && rl->lockout_until <= now)
    {
        rl->lockout_until = 0;
        rl->failure_count = 0;
        rl->failure_idx = 0;
    }

    if (lockout_remaining)
        *lockout_remaining = 0;
    return BIO_OK;
}

/*
 * Record a verify failure for exponential backoff.
 * After max_attempts failures within window_seconds, the user is
 * locked out for lockout_seconds * 2^consecutive_lockouts (capped at 1 hour).
 */
static void record_verify_failure(bio_daemon_t *d, uid_t uid)
{
    typeof(((bio_daemon_t *)0)->rate_limiters[0]) *rl =
        find_rate_limiter(d, uid);
    if (!rl)
        return;

    time_t now = monotonic_seconds();

    /* Count recent failures within the window */
    int window = d->config.rate_limit_window_seconds;
    int recent = 0;
    for (int i = 0; i < rl->failure_count && i < 32; i++)
    {
        if (now - rl->failures[i] <= window)
        {
            recent++;
        }
    }

    /* Record this failure in ring buffer */
    rl->failures[rl->failure_idx % 32] = now;
    rl->failure_idx++;
    if (rl->failure_count < 32)
        rl->failure_count++;
    recent++;

    /* Trigger lockout if threshold exceeded */
    if (recent >= d->config.rate_limit_max_attempts)
    {
        int base_lockout = d->config.rate_limit_lockout_seconds;
        /* Exponential backoff: lockout * 2^consecutive_lockouts, cap at 3600s */
        int multiplier = 1 << (rl->consecutive_lockouts < 6
                                   ? rl->consecutive_lockouts
                                   : 6);
        int lockout = base_lockout * multiplier;
        if (lockout > 3600)
            lockout = 3600;

        rl->lockout_until = now + lockout;
        rl->consecutive_lockouts++;

        BIO_WARN("Rate limit for UID %u: locked out for %d seconds "
                 "(lockout #%d)",
                 uid, lockout, rl->consecutive_lockouts);
        daemon_log_auth(uid, "verify", "rate_limited",
                        "locked %ds (attempt #%d)",
                        lockout, rl->consecutive_lockouts);
    }
}

/*
 * Reset rate limiter on successful verification.
 */
static void reset_verify_rate_limit(bio_daemon_t *d, uid_t uid)
{
    typeof(((bio_daemon_t *)0)->rate_limiters[0]) *rl =
        find_rate_limiter(d, uid);
    if (!rl)
        return;

    rl->failure_count = 0;
    rl->failure_idx = 0;
    rl->lockout_until = 0;
    rl->consecutive_lockouts = 0;
    memset(rl->failures, 0, sizeof(rl->failures));
}

/* ── D-Bus method handler ────────────────────────────────────── */

static void handle_method_call(GDBusConnection *connection,
                               const gchar *sender,
                               const gchar *object_path,
                               const gchar *interface_name,
                               const gchar *method_name,
                               GVariant *parameters,
                               GDBusMethodInvocation *invocation,
                               gpointer user_data)
{
    bio_daemon_t *d = user_data;
    bool daemon_api_path = object_path_is_daemon_api(object_path);

    uid_t caller_uid = get_caller_uid(connection, invocation);
    if (caller_uid == (uid_t)-1)
    {
        g_dbus_method_invocation_return_error(
            invocation,
            G_DBUS_ERROR, G_DBUS_ERROR_AUTH_FAILED,
            "Failed to determine caller identity");
        return;
    }

    /* ── org.bioauth.Auth methods ───────────────────────────── */
    if (g_strcmp0(interface_name, BIOAUTH_AUTH_DBUS_INTERFACE) == 0 &&
        g_strcmp0(method_name, "Authenticate") == 0)
    {
        const gchar *reason = NULL;
        char username[256];
        int auth_rc;
        const char *method_used = "fingerprint";
        gchar *howdy_detail = NULL;

        g_variant_get(parameters, "(&s)", &reason);
        (void)reason;

        if (username_for_uid(caller_uid, username, sizeof(username)) != BIO_OK)
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_FAILED,
                "Unable to resolve caller username");
            return;
        }

        auth_rc = bio_daemon_verify_user(d, username);
        if (auth_rc != BIO_OK && howdy_binary_available(d))
        {
            int face_rc = howdy_verify_user(d, username, &howdy_detail);
            if (face_rc == BIO_OK)
            {
                auth_rc = BIO_OK;
                method_used = "face";
                daemon_log_auth(caller_uid,
                                "face_verify",
                                "success",
                                "%s",
                                howdy_detail ? howdy_detail : "howdy");
            }
        }

        if (auth_rc == BIO_OK)
        {
            bio_session_t *sess = create_session(d, caller_uid, sender);
            char session_id_hex[(BIO_SESSION_TOKEN_SIZE * 2) + 1] = {0};
            if (sess)
            {
                sess->verified = true;
                sess->has_verify_token = false;
                session_token_to_hex(sess->token,
                                     BIO_SESSION_TOKEN_SIZE,
                                     session_id_hex,
                                     sizeof(session_id_hex));
            }

            emit_uv_success(d, session_id_hex, username);

            pm_error_t vault_rc = auto_unlock_user_vault(d, caller_uid);
            if (vault_rc == PM_OK)
            {
                emit_vault_locked_property_changed(connection, FALSE);
                emit_vault_state_changed(d, "unlocked");
                emit_vault_unlocked(d, caller_uid);
            }

            emit_auth_state_changed(d, TRUE, method_used);
            g_dbus_method_invocation_return_value(
                invocation,
                g_variant_new("(bs)", TRUE, method_used));
            g_free(howdy_detail);
            return;
        }

        emit_auth_state_changed(d, FALSE, "none");
        g_dbus_method_invocation_return_value(
            invocation,
            g_variant_new("(bs)", FALSE, "none"));
        g_free(howdy_detail);
        return;
    }

    else if (g_strcmp0(interface_name, BIOAUTH_AUTH_DBUS_INTERFACE) == 0 &&
             g_strcmp0(method_name, "AuthenticateInteractive") == 0)
    {
        const gchar *reason = NULL;
        guint32 timeout_ms = 0;
        char username[256];
        int auth_rc;
        const char *method_used = "fingerprint";
        gchar *howdy_detail = NULL;

        g_variant_get(parameters, "(&su)", &reason, &timeout_ms);
        (void)reason;
        (void)timeout_ms;

        if (username_for_uid(caller_uid, username, sizeof(username)) != BIO_OK)
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_FAILED,
                "Unable to resolve caller username");
            return;
        }

        auth_rc = bio_daemon_verify_user(d, username);
        if (auth_rc != BIO_OK && howdy_binary_available(d))
        {
            int face_rc = howdy_verify_user(d, username, &howdy_detail);
            if (face_rc == BIO_OK)
            {
                auth_rc = BIO_OK;
                method_used = "face";
                daemon_log_auth(caller_uid,
                                "face_verify",
                                "success",
                                "%s",
                                howdy_detail ? howdy_detail : "howdy");
            }
        }

        if (auth_rc == BIO_OK)
        {
            bio_session_t *sess = create_session(d, caller_uid, sender);
            char session_id_hex[(BIO_SESSION_TOKEN_SIZE * 2) + 1] = {0};
            if (sess)
            {
                sess->verified = true;
                sess->has_verify_token = false;
                session_token_to_hex(sess->token,
                                     BIO_SESSION_TOKEN_SIZE,
                                     session_id_hex,
                                     sizeof(session_id_hex));
            }

            emit_uv_success(d, session_id_hex, username);

            pm_error_t vault_rc = auto_unlock_user_vault(d, caller_uid);
            if (vault_rc == PM_OK)
            {
                emit_vault_locked_property_changed(connection, FALSE);
                emit_vault_state_changed(d, "unlocked");
                emit_vault_unlocked(d, caller_uid);
            }

            emit_auth_state_changed(d, TRUE, method_used);
            g_dbus_method_invocation_return_value(
                invocation,
                g_variant_new("(b)", TRUE));
            g_free(howdy_detail);
            return;
        }

        emit_auth_state_changed(d, FALSE, "none");
        g_dbus_method_invocation_return_value(
            invocation,
            g_variant_new("(b)", FALSE));
        g_free(howdy_detail);
        return;
    }

    else if (g_strcmp0(interface_name, BIOAUTH_AUTH_DBUS_INTERFACE) == 0 &&
             g_strcmp0(method_name, "IsAuthenticated") == 0)
    {
        guint seconds_remaining = 0;
        bool authenticated =
            find_verified_session_for_sender(d,
                                             caller_uid,
                                             sender,
                                             &seconds_remaining) != NULL;

        g_dbus_method_invocation_return_value(
            invocation,
            g_variant_new("(bu)", authenticated, seconds_remaining));
        return;
    }

    else if (g_strcmp0(interface_name, BIOAUTH_AUTH_DBUS_INTERFACE) == 0 &&
             g_strcmp0(method_name, "ExtendSession") == 0)
    {
        guint32 extend_seconds = 0;
        time_t now = time(NULL);
        size_t extended_count = 0;
        int cap = session_capacity(d);

        g_variant_get(parameters, "(u)", &extend_seconds);

        for (int i = 0; i < cap; i++)
        {
            bio_session_t *sess = &d->sessions[i];
            if (!sess->active || !sess->verified)
            {
                continue;
            }
            if ((uid_t)sess->uid != caller_uid)
            {
                continue;
            }
            if (sender && sess->sender[0] && strcmp(sender, sess->sender) != 0)
            {
                continue;
            }

            if (now - sess->created > d->config.session_max_age_seconds)
            {
                bio_secure_wipe(sess->session_key, 32);
                bio_munlock_sensitive(sess->session_key, 32);
                sess->active = false;
                if (d->session_count > 0)
                {
                    d->session_count--;
                }
                continue;
            }

            guint remaining = (guint)(d->config.session_max_age_seconds -
                                      (now - sess->created));
            guint target_remaining = remaining + extend_seconds;
            if (target_remaining > (guint)d->config.session_max_age_seconds)
            {
                target_remaining = (guint)d->config.session_max_age_seconds;
            }

            sess->created = now -
                            (time_t)((guint)d->config.session_max_age_seconds -
                                     target_remaining);
            sess->last_used = now;
            extended_count++;
        }

        if (extended_count == 0)
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_AUTH_FAILED,
                "No authenticated session to extend");
            return;
        }

        g_dbus_method_invocation_return_value(invocation, NULL);
        return;
    }

    else if (g_strcmp0(interface_name, BIOAUTH_AUTH_DBUS_INTERFACE) == 0 &&
             g_strcmp0(method_name, "RevokeSession") == 0)
    {
        size_t revoked = revoke_sessions_for_sender(d, caller_uid, sender);
        if (revoked > 0)
        {
            emit_auth_state_changed(d, FALSE, "revoked");
        }
        g_dbus_method_invocation_return_value(invocation, NULL);
        return;
    }

    /* ── org.bioauth.Enroll methods ─────────────────────────── */
    else if (g_strcmp0(interface_name, BIOAUTH_ENROLL_DBUS_INTERFACE) == 0 &&
             g_strcmp0(method_name, "StartFingerEnroll") == 0)
    {
        const gchar *finger_id = NULL;
        const gchar *label = NULL;
        bio_finger_t finger = BIO_FINGER_UNKNOWN;
        char username[256];
        int rc;
        gchar *session_id = g_uuid_string_random();

        g_variant_get(parameters, "(&s&s)", &finger_id, &label);
        (void)label;

        if (!session_id)
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_NO_MEMORY,
                "Failed to generate enrollment session id");
            return;
        }

        if (!parse_finger_id_string(finger_id, &finger))
        {
            emit_enroll_progress_v2(d, session_id, 0, "invalid finger id");
            g_free(session_id);
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_INVALID_ARGS,
                "Invalid finger_id: %s",
                finger_id ? finger_id : "(null)");
            return;
        }

        if (username_for_uid(caller_uid, username, sizeof(username)) != BIO_OK)
        {
            emit_enroll_progress_v2(d, session_id, 0, "caller resolution failed");
            g_free(session_id);
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_FAILED,
                "Unable to resolve caller username");
            return;
        }

        emit_enroll_progress_v2(d, session_id, 5, "starting fingerprint enrollment");

        rc = bio_daemon_enroll_user(d, username, finger_id_to_string(finger));
        if (rc != BIO_OK)
        {
            emit_enroll_progress_v2(d, session_id, 100, "fingerprint enrollment failed");
            g_free(session_id);
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_FAILED,
                "Fingerprint enrollment failed: %s",
                bio_error_str(rc));
            return;
        }

        emit_enroll_progress_v2(d, session_id, 100, "fingerprint enrollment complete");

        g_dbus_method_invocation_return_value(
            invocation,
            g_variant_new("(s)", session_id));
        g_free(session_id);
        return;
    }

    else if (g_strcmp0(interface_name, BIOAUTH_ENROLL_DBUS_INTERFACE) == 0 &&
             g_strcmp0(method_name, "ListEnrolledFingers") == 0)
    {
        GVariantBuilder list_builder;
        g_variant_builder_init(&list_builder, G_VARIANT_TYPE("aa{ss}"));

        pthread_mutex_lock(&d->data_lock);
        for (size_t i = 0; i < d->enrollment_count; i++)
        {
            const bio_enrollment_t *e = &d->enrollments[i];
            if ((uid_t)e->uid != caller_uid)
            {
                continue;
            }

            char created_buf[32];
            GVariantBuilder row_builder;
            g_variant_builder_init(&row_builder, G_VARIANT_TYPE("a{ss}"));

            snprintf(created_buf,
                     sizeof(created_buf),
                     "%llu",
                     (unsigned long long)e->created);

            g_variant_builder_add(&row_builder,
                                  "{ss}",
                                  "finger_id",
                                  finger_id_to_string(e->finger));
            g_variant_builder_add(&row_builder,
                                  "{ss}",
                                  "label",
                                  e->label[0] ? e->label : "");
            g_variant_builder_add(&row_builder,
                                  "{ss}",
                                  "created_at",
                                  created_buf);

            g_variant_builder_add_value(&list_builder,
                                        g_variant_builder_end(&row_builder));
        }
        pthread_mutex_unlock(&d->data_lock);

        g_dbus_method_invocation_return_value(
            invocation,
            g_variant_new("(aa{ss})", &list_builder));
        return;
    }

    else if (g_strcmp0(interface_name, BIOAUTH_ENROLL_DBUS_INTERFACE) == 0 &&
             g_strcmp0(method_name, "RemoveFinger") == 0)
    {
        const gchar *finger_id = NULL;
        bio_finger_t finger = BIO_FINGER_UNKNOWN;
        bool removed = false;

        g_variant_get(parameters, "(&s)", &finger_id);
        if (!parse_finger_id_string(finger_id, &finger))
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_INVALID_ARGS,
                "Invalid finger_id: %s",
                finger_id ? finger_id : "(null)");
            return;
        }

        pthread_mutex_lock(&d->data_lock);
        for (size_t i = 0; i < d->enrollment_count; i++)
        {
            if ((uid_t)d->enrollments[i].uid == caller_uid &&
                d->enrollments[i].finger == finger)
            {
                bio_secure_wipe(&d->enrollments[i], sizeof(bio_enrollment_t));
                memmove(&d->enrollments[i],
                        &d->enrollments[i + 1],
                        (d->enrollment_count - i - 1) * sizeof(bio_enrollment_t));
                d->enrollment_count--;
                removed = true;
                break;
            }
        }

        if (removed)
        {
            bio_daemon_save_enrollments(
                d->config.state_dir,
                d->enrollments,
                d->enrollment_count);
        }
        pthread_mutex_unlock(&d->data_lock);

        if (!removed)
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_UNKNOWN_OBJECT,
                "No enrollment found for %s",
                finger_id);
            return;
        }

        g_dbus_method_invocation_return_value(invocation, NULL);
        return;
    }

    else if (g_strcmp0(interface_name, BIOAUTH_ENROLL_DBUS_INTERFACE) == 0 &&
             g_strcmp0(method_name, "StartFaceEnroll") == 0)
    {
        const gchar *label = NULL;
        gchar *session_id = NULL;

        g_variant_get(parameters, "(&s)", &label);

        if (!howdy_binary_available(d))
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_NOT_SUPPORTED,
                "Howdy is not available (set %s if installed in a custom location)",
                BIOAUTH_HOWDY_BIN_ENV);
            return;
        }

        session_id = g_uuid_string_random();
        if (!session_id)
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_NO_MEMORY,
                "Failed to generate face enrollment session id");
            return;
        }

        if (!create_face_enroll_session(d, caller_uid, session_id, label))
        {
            g_free(session_id);
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_LIMITS_EXCEEDED,
                "Too many active face enrollment sessions");
            return;
        }

        emit_enroll_progress_v2(d, session_id, 5, "ready for howdy enrollment");

        g_dbus_method_invocation_return_value(
            invocation,
            g_variant_new("(s)", session_id));

        g_free(session_id);
        return;
    }

    else if (g_strcmp0(interface_name, BIOAUTH_ENROLL_DBUS_INTERFACE) == 0 &&
             g_strcmp0(method_name, "GetEnrollFrame") == 0)
    {
        const gchar *session_id = NULL;
        GVariantBuilder jpeg_builder;

        g_variant_get(parameters, "(&s)", &session_id);
        if (!get_face_enroll_session_label(d,
                                           caller_uid,
                                           session_id,
                                           NULL,
                                           0))
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_UNKNOWN_OBJECT,
                "Unknown face enrollment session");
            return;
        }

        g_variant_builder_init(&jpeg_builder, G_VARIANT_TYPE("ay"));
        g_dbus_method_invocation_return_value(
            invocation,
            g_variant_new("(ays)",
                          &jpeg_builder,
                          "howdy_external_capture_required"));
        return;
    }

    else if (g_strcmp0(interface_name, BIOAUTH_ENROLL_DBUS_INTERFACE) == 0 &&
             g_strcmp0(method_name, "CommitFaceEnroll") == 0)
    {
        const gchar *session_id = NULL;
        char username[256];
        char label[128] = {0};
        gchar *detail = NULL;
        int rc;

        g_variant_get(parameters, "(&s)", &session_id);

        if (!session_id || session_id[0] == '\0')
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_INVALID_ARGS,
                "session_id is required");
            return;
        }

        if (!howdy_binary_available(d))
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_NOT_SUPPORTED,
                "Howdy is not available (set %s if installed in a custom location)",
                BIOAUTH_HOWDY_BIN_ENV);
            return;
        }

        if (!get_face_enroll_session_label(d,
                                           caller_uid,
                                           session_id,
                                           label,
                                           sizeof(label)))
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_UNKNOWN_OBJECT,
                "Unknown face enrollment session");
            return;
        }

        if (username_for_uid(caller_uid, username, sizeof(username)) != BIO_OK)
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_FAILED,
                "Unable to resolve caller username");
            return;
        }

        emit_enroll_progress_v2(d, session_id, 15, "starting howdy enrollment");

        rc = howdy_enroll_face(d, username, label, &detail);
        if (rc != BIO_OK)
        {
            emit_enroll_progress_v2(d, session_id, 100, "face enrollment failed");
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_FAILED,
                "Howdy enrollment failed: %s",
                detail ? detail : "unknown error");
            g_free(detail);
            return;
        }

        clear_face_enroll_session(d, caller_uid, session_id);
        emit_enroll_progress_v2(d, session_id, 100, "face enrollment complete");
        daemon_log_auth(caller_uid,
                        "face_enroll",
                        "success",
                        "session=%s label=%s",
                        session_id,
                        label[0] ? label : "(default)");

        g_dbus_method_invocation_return_value(
            invocation,
            g_variant_new("(b)", TRUE));
        g_free(detail);
        return;
    }

    else if (g_strcmp0(interface_name, BIOAUTH_ENROLL_DBUS_INTERFACE) == 0 &&
             g_strcmp0(method_name, "ListEnrolledFaces") == 0)
    {
        char username[256];
        gchar *stdout_text = NULL;
        gchar *stderr_text = NULL;
        gchar *err_text = NULL;
        int rc;
        GVariantBuilder list_builder;

        if (!howdy_binary_available(d))
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_NOT_SUPPORTED,
                "Howdy is not available (set %s if installed in a custom location)",
                BIOAUTH_HOWDY_BIN_ENV);
            return;
        }

        if (username_for_uid(caller_uid, username, sizeof(username)) != BIO_OK)
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_FAILED,
                "Unable to resolve caller username");
            return;
        }

        rc = run_howdy_command(username,
                               d,
                               "list",
                               NULL,
                               NULL,
                               NULL,
                               &stdout_text,
                               &stderr_text,
                               &err_text);
        if (rc != BIO_OK)
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_FAILED,
                "Failed to list enrolled faces: %s",
                (stderr_text && stderr_text[0] != '\0')
                    ? stderr_text
                    : (err_text ? err_text : "unknown error"));
            g_free(stdout_text);
            g_free(stderr_text);
            g_free(err_text);
            return;
        }

        g_variant_builder_init(&list_builder, G_VARIANT_TYPE("aa{ss}"));

        if (stdout_text)
        {
            gchar **lines = g_strsplit(stdout_text, "\n", -1);
            if (lines)
            {
                for (size_t i = 0; lines[i] != NULL; i++)
                {
                    char face_id[32];
                    char face_label[256];
                    GVariantBuilder row_builder;

                    if (!parse_howdy_face_list_line(lines[i],
                                                    face_id,
                                                    sizeof(face_id),
                                                    face_label,
                                                    sizeof(face_label)))
                    {
                        continue;
                    }

                    g_variant_builder_init(&row_builder, G_VARIANT_TYPE("a{ss}"));
                    g_variant_builder_add(&row_builder, "{ss}", "face_id", face_id);
                    g_variant_builder_add(&row_builder, "{ss}", "label", face_label);
                    g_variant_builder_add(&row_builder, "{ss}", "backend", "howdy");

                    g_variant_builder_add_value(&list_builder,
                                                g_variant_builder_end(&row_builder));
                }
                g_strfreev(lines);
            }
        }

        g_dbus_method_invocation_return_value(
            invocation,
            g_variant_new("(aa{ss})", &list_builder));

        g_free(stdout_text);
        g_free(stderr_text);
        g_free(err_text);
        return;
    }

    else if (g_strcmp0(interface_name, BIOAUTH_ENROLL_DBUS_INTERFACE) == 0 &&
             g_strcmp0(method_name, "RemoveFace") == 0)
    {
        const gchar *face_id = NULL;
        char username[256];
        gchar *stdout_text = NULL;
        gchar *stderr_text = NULL;
        gchar *err_text = NULL;
        int rc;

        g_variant_get(parameters, "(&s)", &face_id);

        if (!face_id || face_id[0] == '\0')
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_INVALID_ARGS,
                "face_id is required");
            return;
        }

        if (!howdy_binary_available(d))
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_NOT_SUPPORTED,
                "Howdy is not available (set %s if installed in a custom location)",
                BIOAUTH_HOWDY_BIN_ENV);
            return;
        }

        if (username_for_uid(caller_uid, username, sizeof(username)) != BIO_OK)
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_FAILED,
                "Unable to resolve caller username");
            return;
        }

        rc = run_howdy_command(username,
                               d,
                               "remove",
                               face_id,
                               NULL,
                               NULL,
                               &stdout_text,
                               &stderr_text,
                               &err_text);

        if (rc != BIO_OK)
        {
            g_free(stdout_text);
            g_free(stderr_text);
            g_free(err_text);
            stdout_text = NULL;
            stderr_text = NULL;
            err_text = NULL;

            rc = run_howdy_command(username,
                                   d,
                                   "remove",
                                   "--yes",
                                   face_id,
                                   NULL,
                                   &stdout_text,
                                   &stderr_text,
                                   &err_text);
        }

        if (rc != BIO_OK)
        {
            g_free(stdout_text);
            g_free(stderr_text);
            g_free(err_text);
            stdout_text = NULL;
            stderr_text = NULL;
            err_text = NULL;

            rc = run_howdy_command(username,
                                   d,
                                   "remove",
                                   "-y",
                                   face_id,
                                   NULL,
                                   &stdout_text,
                                   &stderr_text,
                                   &err_text);
        }

        if (rc != BIO_OK)
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_FAILED,
                "Failed to remove face %s: %s",
                face_id,
                (stderr_text && stderr_text[0] != '\0')
                    ? stderr_text
                    : (err_text ? err_text : "unknown error"));
            g_free(stdout_text);
            g_free(stderr_text);
            g_free(err_text);
            return;
        }

        daemon_log_auth(caller_uid,
                        "face_remove",
                        "success",
                        "face_id=%s",
                        face_id);

        g_dbus_method_invocation_return_value(invocation, NULL);
        g_free(stdout_text);
        g_free(stderr_text);
        g_free(err_text);
        return;
    }

    else if (g_strcmp0(interface_name, BIOAUTH_ENROLL_DBUS_INTERFACE) == 0 &&
             g_strcmp0(method_name, "AbortEnroll") == 0)
    {
        const gchar *session_id = NULL;

        if (parameters && g_variant_n_children(parameters) == 1)
        {
            g_variant_get(parameters, "(&s)", &session_id);
            if (session_id && session_id[0] != '\0')
            {
                clear_face_enroll_session(d, caller_uid, session_id);
            }
        }

        g_dbus_method_invocation_return_value(invocation, NULL);
        return;
    }

    /* ── GetDevices ─────────────────────────────────────────── */
    if (g_strcmp0(method_name, "GetDevices") == 0)
    {
        bio_fp_device_info_t devs[8];
        size_t count = 0;
        bio_fp_enumerate_devices(d->fp_ctx, devs, 8, &count);

        GVariantBuilder builder;
        g_variant_builder_init(&builder, G_VARIANT_TYPE("a(ssbbn)"));

        for (size_t i = 0; i < count; i++)
        {
            g_variant_builder_add(&builder, "(ssbbn)",
                                  devs[i].name,
                                  devs[i].driver,
                                  devs[i].has_storage,
                                  devs[i].supports_identify,
                                  devs[i].nr_enroll_stages);
        }

        g_dbus_method_invocation_return_value(
            invocation,
            g_variant_new("(a(ssbbn))", &builder));
    }

    /* ── CreateSession ─────────────────────────────────────── */
    else if (g_strcmp0(method_name, "CreateSession") == 0)
    {
        /* PAM modules run as root but authenticate a non-root user.
         * If root passes a uid parameter, use that uid for the session.
         * Non-root callers can only create sessions for themselves. */
        uid_t session_uid = caller_uid;
        if (caller_uid == 0 && parameters != NULL &&
            g_variant_is_of_type(parameters, G_VARIANT_TYPE("(u)")))
        {
            guint32 requested_uid = 0;
            g_variant_get(parameters, "(u)", &requested_uid);
            session_uid = (uid_t)requested_uid;
            BIO_DEBUG("CreateSession: root requesting session for uid %u", requested_uid);
        }
        bio_session_t *sess = create_session(d, session_uid, sender);
        if (!sess)
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR, G_DBUS_ERROR_LIMITS_EXCEEDED,
                "Session limit exceeded");
            return;
        }

        GVariant *token = g_variant_new_fixed_array(
            G_VARIANT_TYPE_BYTE,
            sess->token, BIO_SESSION_TOKEN_SIZE, 1);

        g_dbus_method_invocation_return_value(
            invocation, g_variant_new_tuple(&token, 1));
    }

    /* ── GetEnrolledFingers ────────────────────────────────── */
    else if (g_strcmp0(method_name, "GetEnrolledFingers") == 0)
    {
        guint32 uid;
        g_variant_get(parameters, "(u)", &uid);

        /* Only allow querying own enrollments, or root */
        if (caller_uid != 0 && caller_uid != (uid_t)uid)
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR, G_DBUS_ERROR_ACCESS_DENIED,
                "Cannot query other user's enrollments");
            return;
        }

        GVariantBuilder builder;
        g_variant_builder_init(&builder, G_VARIANT_TYPE("an"));

        pthread_mutex_lock(&d->data_lock);
        for (size_t i = 0; i < d->enrollment_count; i++)
        {
            if ((uid_t)d->enrollments[i].uid == (uid_t)uid)
            {
                g_variant_builder_add(&builder, "n",
                                      (gint16)d->enrollments[i].finger);
            }
        }
        pthread_mutex_unlock(&d->data_lock);

        g_dbus_method_invocation_return_value(
            invocation, g_variant_new("(an)", &builder));
    }

    /* ── Enroll ────────────────────────────────────────────── */
    else if (g_strcmp0(method_name, "Enroll") == 0)
    {
        gint16 finger;
        const gchar *label;
        g_variant_get(parameters, "(n&s)", &finger, &label);

        /* D4 fix: Validate finger range (1-10 per FIDO2 spec) */
        if (finger < 1 || finger > 10)
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR, G_DBUS_ERROR_INVALID_ARGS,
                "Invalid finger index %d (must be 1-10)", finger);
            return;
        }

        if (!d->fp_dev)
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR, G_DBUS_ERROR_FAILED,
                "No fingerprint device available");
            return;
        }

        /* Check max enrollments per user */
        pthread_mutex_lock(&d->data_lock);
        int user_count = 0;
        bool tpm_require = d->config.tpm_require;
        bool tpm_avail = d->tpm_available;
        for (size_t i = 0; i < d->enrollment_count; i++)
        {
            if ((uid_t)d->enrollments[i].uid == caller_uid)
                user_count++;
        }
        if (user_count >= d->config.max_enrollments_per_user)
        {
            pthread_mutex_unlock(&d->data_lock);
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR, G_DBUS_ERROR_LIMITS_EXCEEDED,
                "Maximum enrollments reached for this user");
            return;
        }

        if (tpm_require && !tpm_avail)
        {
            pthread_mutex_unlock(&d->data_lock);
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR, G_DBUS_ERROR_FAILED,
                "TPM is required by policy, but unavailable");
            return;
        }
        pthread_mutex_unlock(&d->data_lock);

        /* Perform enrollment with progress callback */
        bio_enrollment_t enrl;
        memset(&enrl, 0, sizeof(enrl));
        enrl.uid = caller_uid;
        enrl.finger = (bio_finger_t)finger;
        enrl.created = time(NULL);
        strncpy(enrl.label, label, sizeof(enrl.label) - 1);
        /* D5 fix: Sanitize label — replace non-printable chars */
        for (size_t i = 0; enrl.label[i]; i++)
        {
            unsigned char c = (unsigned char)enrl.label[i];
            if (c < 0x20 || c == 0x7F)
                enrl.label[i] = '_';
        }

        daemon_enroll_ctx_t ec = {.daemon = d};
        enrl.print_data_len = sizeof(enrl.print_data);

        /* Serialize fingerprint device access (D-Bus + fprintd-compat) */
        pthread_mutex_lock(&d->fp_lock);
        if (d->shutting_down)
        {
            pthread_mutex_unlock(&d->fp_lock);
            g_dbus_method_invocation_return_error(
                invocation, G_DBUS_ERROR, G_DBUS_ERROR_FAILED,
                "Daemon shutting down");
            return;
        }
        int rc = bio_fp_enroll(d->fp_dev,
                               enrl.finger, daemon_enroll_cb, &ec,
                               enrl.print_data, &enrl.print_data_len);

        if (rc == BIO_ERR_FP_ALREADY_ENROLLED)
        {
            /*
             * MOC sensor has a stale on-chip template — the daemon DB
             * was wiped without clearing the chip, or another tool wrote
             * a template directly. Clear all on-chip templates and retry
             * once. Clearing all (not just this finger) is intentional:
             * after a DB wipe the chip state is unknown, and any
             * remaining chip templates are orphaned (no matching DB
             * record), so they cannot be used for verification anyway.
             */
            BIO_WARN("MOC sensor has stale on-chip template for finger=%s "
                     "-- clearing chip and retrying",
                     bio_finger_str((bio_finger_t)finger));

            int clear_rc = bio_fp_delete_all_prints(d->fp_dev);
            if (clear_rc != BIO_OK) {
                pthread_mutex_unlock(&d->fp_lock);
                BIO_ERROR("Cannot clear chip storage (rc=%d)", clear_rc);
                g_dbus_method_invocation_return_error(
                    invocation, G_DBUS_ERROR, G_DBUS_ERROR_FAILED,
                    "Finger already enrolled on sensor and chip clear "
                    "failed. Clear manually: sudo dbus-send --system "
                    "--print-reply --dest=org.bioauth.Manager "
                    "/org/bioauth/Manager "
                    "org.bioauth.Manager.ClearDevice");
                return;
            }

            enrl.print_data_len = sizeof(enrl.print_data);
            rc = bio_fp_enroll(d->fp_dev,
                               enrl.finger, daemon_enroll_cb, &ec,
                               enrl.print_data, &enrl.print_data_len);
        }

        if (rc != BIO_OK)
        {
            pthread_mutex_unlock(&d->fp_lock);
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR, G_DBUS_ERROR_FAILED,
                "Enrollment failed: %s", bio_error_str(rc));
            return;
        }

        /* Seal fingerprint template with TPM if available */
        if (d->tpm_available)
        {
            enrl.sealed_blob_len = sizeof(enrl.sealed_blob);
            rc = daemon_tpm_seal_template(
                d,
                enrl.print_data,
                enrl.print_data_len,
                enrl.sealed_blob,
                &enrl.sealed_blob_len);
            if (rc != BIO_OK)
            {
                if (tpm_require)
                {
                    pthread_mutex_unlock(&d->fp_lock);
                    g_dbus_method_invocation_return_error(
                        invocation,
                        G_DBUS_ERROR, G_DBUS_ERROR_FAILED,
                        "TPM is required by policy, and template sealing failed: %s",
                        bio_error_str(rc));
                    bio_secure_wipe(&enrl, sizeof(enrl));
                    return;
                }
                BIO_WARN("TPM seal failed (continuing without): %s",
                         bio_error_str(rc));
                enrl.sealed_blob_len = 0;
            }
        }
        pthread_mutex_unlock(&d->fp_lock);

        /* Store enrollment */
        pthread_mutex_lock(&d->data_lock);
        /* TOCTOU re-check: verify capacity under lock after bio_fp_enroll */
        user_count = 0;
        for (size_t i = 0; i < d->enrollment_count; i++)
        {
            if ((uid_t)d->enrollments[i].uid == caller_uid)
                user_count++;
        }
        if (user_count >= d->config.max_enrollments_per_user)
        {
            pthread_mutex_unlock(&d->data_lock);
            bio_secure_wipe(&enrl, sizeof(enrl));
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR, G_DBUS_ERROR_LIMITS_EXCEEDED,
                "Maximum enrollments reached (concurrent enroll)");
            return;
        }
        rc = add_enrollment(d, &enrl);
        bio_secure_wipe(&enrl, sizeof(enrl));

        /* Persist to disk */
        if (rc == BIO_OK)
        {
            bio_daemon_save_enrollments(
                d->config.state_dir,
                d->enrollments, d->enrollment_count);
        }
        pthread_mutex_unlock(&d->data_lock);

        if (rc == BIO_OK)
        {
            daemon_log_auth(caller_uid, "enroll", "success",
                            "finger=%s label=%s",
                            bio_finger_str((bio_finger_t)finger),
                            label);
        }
        else
        {
            daemon_log_auth(caller_uid, "enroll", "failure",
                            "store failed: %s", bio_error_str(rc));
        }

        g_dbus_method_invocation_return_value(
            invocation, g_variant_new("(b)", rc == BIO_OK));
    }

    /* ── DeleteEnrollment ──────────────────────────────────── */
    else if (g_strcmp0(method_name, "DeleteEnrollment") == 0)
    {
        gint16 finger;
        g_variant_get(parameters, "(n)", &finger);

        bool found = false;
        pthread_mutex_lock(&d->data_lock);
        for (size_t i = 0; i < d->enrollment_count; i++)
        {
            if ((uid_t)d->enrollments[i].uid == caller_uid &&
                d->enrollments[i].finger == (bio_finger_t)finger)
            {
                /* Securely wipe and remove */
                bio_secure_wipe(&d->enrollments[i],
                                sizeof(bio_enrollment_t));
                /* Shift remaining entries */
                memmove(&d->enrollments[i],
                        &d->enrollments[i + 1],
                        (d->enrollment_count - i - 1) *
                            sizeof(bio_enrollment_t));
                d->enrollment_count--;
                found = true;
                break;
            }
        }

        /* Persist deletion to disk */
        if (found)
        {
            bio_daemon_save_enrollments(
                d->config.state_dir,
                d->enrollments, d->enrollment_count);
        }
        pthread_mutex_unlock(&d->data_lock);

        if (found)
        {
            daemon_log_auth(caller_uid, "delete_enrollment",
                            "success",
                            "finger=%s",
                            bio_finger_str((bio_finger_t)finger));
        }

        g_dbus_method_invocation_return_value(
            invocation, g_variant_new("(b)", found));
    }

    /* ── ClearDevice ───────────────────────────────────────── */
    else if (g_strcmp0(method_name, "ClearDevice") == 0)
    {
        /* Only root can clear the device */
        if (caller_uid != 0)
        {
            g_dbus_method_invocation_return_error(
                invocation, G_DBUS_ERROR, G_DBUS_ERROR_ACCESS_DENIED,
                "Only root may clear the fingerprint device");
            return;
        }

        if (!d->fp_dev)
        {
            g_dbus_method_invocation_return_error(
                invocation, G_DBUS_ERROR, G_DBUS_ERROR_FAILED,
                "No fingerprint device available");
            return;
        }

        pthread_mutex_lock(&d->fp_lock);
        int rc = bio_fp_delete_all_prints(d->fp_dev);
        pthread_mutex_unlock(&d->fp_lock);

        if (rc == BIO_OK)
        {
            daemon_log_auth(caller_uid, "clear_device",
                            "success", "all prints cleared from sensor");
        }
        else
        {
            daemon_log_auth(caller_uid, "clear_device",
                            "failure", "rc=%d", rc);
        }

        g_dbus_method_invocation_return_value(
            invocation, g_variant_new("(b)", rc == BIO_OK));
    }

    /* ── Verify ────────────────────────────────────────────── */
    else if (g_strcmp0(method_name, "Verify") == 0)
    {
        GVariant *token_var;
        guint32 verify_timeout_ms = 0;
        /* Parse parameters. PAM sends (ayu) — token bytes + timeout.
         * Older/simple clients may send just (ay) with no timeout.
         * Use correct GVariant type strings (no @ prefix in type checks). */
        if (g_variant_is_of_type(parameters, G_VARIANT_TYPE("(ayu)")))
            g_variant_get(parameters, "(@ayu)", &token_var, &verify_timeout_ms);
        else
            g_variant_get(parameters, "(@ay)", &token_var);
        /* Clamp to sane range; 0 = let bio_fp_verify use its default */
        if (verify_timeout_ms > 120000) verify_timeout_ms = 0;

        gsize token_len = 0;
        const uint8_t *token = g_variant_get_fixed_array(
            token_var, &token_len, 1);

        bio_session_t *sess = find_session(d, token, token_len);
        g_variant_unref(token_var);

        if (!sess)
        {
            daemon_log_auth(caller_uid, "verify",
                            "rejected", "invalid/expired session");
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR, G_DBUS_ERROR_AUTH_FAILED,
                "Invalid or expired session");
            return;
        }

        /* Verify caller matches session owner.
         * Root (PAM modules) may verify sessions belonging to any user. */
        if (caller_uid != 0 && (uid_t)sess->uid != caller_uid)
        {
            daemon_log_auth(caller_uid, "verify",
                            "rejected", "session owner mismatch");
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR, G_DBUS_ERROR_ACCESS_DENIED,
                "Session belongs to another user");
            return;
        }

        /* Defense-in-depth: D-Bus sender must match session creator */
        if (sender && sess->sender[0] &&
            strcmp(sender, sess->sender) != 0)
        {
            daemon_log_auth(caller_uid, "verify",
                            "rejected", "session sender mismatch");
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR, G_DBUS_ERROR_ACCESS_DENIED,
                "Session bound to different connection");
            return;
        }

        /* ── Rate limiting check ────────────────────────────── */
        pthread_mutex_lock(&d->data_lock);
        int lockout_remaining = 0;
        if (check_verify_rate_limit(d, caller_uid,
                                    &lockout_remaining) != BIO_OK)
        {
            pthread_mutex_unlock(&d->data_lock);
            daemon_log_auth(caller_uid, "verify",
                            "rate_limited",
                            "locked for %ds", lockout_remaining);
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR, G_DBUS_ERROR_LIMITS_EXCEEDED,
                "Rate limited: try again in %d seconds",
                lockout_remaining);
            return;
        }

        if (!d->fp_dev)
        {
            pthread_mutex_unlock(&d->data_lock);
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR, G_DBUS_ERROR_FAILED,
                "No fingerprint device");
            return;
        }

        /* Copy enrollment data under lock for thread safety */
        typedef struct
        {
            uint8_t print_data[BIO_MAX_PRINT_DATA_SIZE];
            size_t print_data_len;
            uint8_t sealed_blob[1024];
            size_t sealed_blob_len;
            bio_finger_t finger_id;
        } verify_local_t;

        size_t user_enroll_count = 0;
        for (size_t i = 0; i < d->enrollment_count; i++)
        {
            if ((uid_t)d->enrollments[i].uid == (uid_t)sess->uid)
                user_enroll_count++;
        }

        verify_local_t *vlocals = NULL;
        if (user_enroll_count > 0)
        {
            vlocals = calloc(user_enroll_count, sizeof(*vlocals));
            if (!vlocals)
            {
                pthread_mutex_unlock(&d->data_lock);
                g_dbus_method_invocation_return_error(
                    invocation, G_DBUS_ERROR, G_DBUS_ERROR_FAILED,
                    "Out of memory");
                return;
            }
            size_t vi = 0;
            for (size_t i = 0; i < d->enrollment_count && vi < user_enroll_count; i++)
            {
                if ((uid_t)d->enrollments[i].uid == (uid_t)sess->uid)
                {
                    const bio_enrollment_t *e = &d->enrollments[i];
                    memcpy(vlocals[vi].print_data, e->print_data, e->print_data_len);
                    vlocals[vi].print_data_len = e->print_data_len;
                    memcpy(vlocals[vi].sealed_blob, e->sealed_blob, e->sealed_blob_len);
                    vlocals[vi].sealed_blob_len = e->sealed_blob_len;
                    vlocals[vi].finger_id = e->finger;
                    vi++;
                }
            }
        }
        bool tpm_avail = d->tpm_available;
        bool tpm_fb = d->config.tpm_fallback_to_plaintext;
        bool tpm_require = d->config.tpm_require;
        pthread_mutex_unlock(&d->data_lock);

        /* ── Set up verification timeout ────────────────────── */
        /* (GLib timeout will be managed by fingerprint subsystem's
         *  internal main loop — the fp_device_verify call has its
         *  own GCancellable; here we just log the total elapsed.) */
        time_t verify_start = time(NULL);

        /* ── Try to verify against each enrolled print ──────── */
        bool matched = false;
        bool policy_denied = false;
        uint8_t unsealed_template[BIO_MAX_PRINT_DATA_SIZE];
        size_t unsealed_len = 0;
        const char *matched_finger_str = NULL;

        /* Serialize fingerprint/TPM device access */
        pthread_mutex_lock(&d->fp_lock);
        if (d->shutting_down)
        {
            pthread_mutex_unlock(&d->fp_lock);
            for (size_t wi = 0; wi < user_enroll_count; wi++)
            {
                bio_secure_wipe(&vlocals[wi], sizeof(vlocals[wi]));
            }
            free(vlocals);
            g_dbus_method_invocation_return_error(
                invocation, G_DBUS_ERROR, G_DBUS_ERROR_FAILED,
                "Daemon shutting down");
            return;
        }

        for (size_t vi = 0; vi < user_enroll_count && !matched; vi++)
        {
            const uint8_t *verify_data = NULL;
            size_t verify_len = 0;

            if (vlocals[vi].sealed_blob_len > 0)
            {
                if (!tpm_avail)
                {
                    if (tpm_require)
                    {
                        policy_denied = true;
                        BIO_ERROR("TPM required by policy but unavailable for enrollment %zu",
                                  vi);
                        continue;
                    }
                    verify_data = vlocals[vi].print_data;
                    verify_len = vlocals[vi].print_data_len;
                }
                else
                {
                    unsealed_len = sizeof(unsealed_template);
                    if (bio_mlock_sensitive_strict(unsealed_template,
                                                   sizeof(unsealed_template)) != BIO_OK)
                    {
                        policy_denied = true;
                        BIO_ERROR("Failed to lock unsealed template buffer");
                        continue;
                    }

                    int tpm_rc = daemon_tpm_unseal_template(
                        d,
                        vlocals[vi].sealed_blob,
                        vlocals[vi].sealed_blob_len,
                        unsealed_template,
                        &unsealed_len);

                    if (tpm_rc == BIO_OK && unsealed_len > 0)
                    {
                        verify_data = unsealed_template;
                        verify_len = unsealed_len;
                        BIO_DEBUG("TPM unseal succeeded for enrollment %zu", vi);
                    }
                    else if (tpm_fb && !tpm_require)
                    {
                        BIO_WARN("TPM unseal failed for enrollment %zu: %s, "
                                 "falling back (tpm_fallback_to_plaintext=true)",
                                 vi, bio_error_str(tpm_rc));
                        verify_data = vlocals[vi].print_data;
                        verify_len = vlocals[vi].print_data_len;
                    }
                    else
                    {
                        policy_denied = true;
                        BIO_ERROR("TPM unseal failed for enrollment %zu: %s, "
                                  "plaintext fallback DENIED",
                                  vi, bio_error_str(tpm_rc));
                        bio_secure_wipe(unsealed_template, sizeof(unsealed_template));
                        bio_munlock_sensitive(unsealed_template, sizeof(unsealed_template));
                        continue;
                    }
                }
            }
            else
            {
                if (tpm_require)
                {
                    policy_denied = true;
                    BIO_ERROR("TPM required by policy but enrollment %zu has no sealed blob",
                              vi);
                    continue;
                }
                verify_data = vlocals[vi].print_data;
                verify_len = vlocals[vi].print_data_len;
            }

            int rc = bio_fp_verify(d->fp_dev,
                                   verify_data, verify_len,
                                   NULL, NULL,
                                   (int)verify_timeout_ms);

            if (verify_data == unsealed_template)
            {
                bio_secure_wipe(unsealed_template, sizeof(unsealed_template));
                bio_munlock_sensitive(unsealed_template,
                                      sizeof(unsealed_template));
            }

            if (rc == BIO_OK)
            {
                matched = true;
                sess->verified = true;
                matched_finger_str = bio_finger_str(vlocals[vi].finger_id);

                uint8_t token_input[sizeof(uid_t) + sizeof(time_t) + 16];
                memcpy(token_input, &sess->uid, sizeof(uid_t));
                time_t ts = time(NULL);
                memcpy(token_input + sizeof(uid_t), &ts, sizeof(time_t));
                if (bio_random_bytes(token_input + sizeof(uid_t) + sizeof(time_t),
                                     16) != BIO_OK)
                {
                    matched = false;
                    sess->verified = false;
                    matched_finger_str = NULL;
                }
                else if (bio_hmac_sha256(sess->session_key, 32,
                                         token_input, sizeof(token_input),
                                         sess->verify_token) != BIO_OK)
                {
                    matched = false;
                    sess->verified = false;
                    matched_finger_str = NULL;
                }
                else
                {
                    sess->has_verify_token = true;
                }
                bio_secure_wipe(token_input, sizeof(token_input));
            }
        }
        pthread_mutex_unlock(&d->fp_lock);

        /* Wipe and free local enrollment copies */
        if (vlocals)
        {
            bio_secure_wipe(vlocals, user_enroll_count * sizeof(*vlocals));
            free(vlocals);
        }

        if (!matched && policy_denied)
        {
            daemon_log_auth(caller_uid, "verify", "denied",
                            "require_tpm policy denied plaintext fallback");
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR, G_DBUS_ERROR_FAILED,
                "TPM is required by policy; verification denied without TPM-sealed data");
            return;
        }

        /* ── Post-verification bookkeeping ──────────────────── */
        time_t verify_elapsed = time(NULL) - verify_start;

        pthread_mutex_lock(&d->data_lock);
        if (matched)
        {
            reset_verify_rate_limit(d, caller_uid);
        }
        else
        {
            record_verify_failure(d, caller_uid);
        }
        pthread_mutex_unlock(&d->data_lock);

        if (matched)
        {
            char session_id_hex[(BIO_SESSION_TOKEN_SIZE * 2) + 1] = {0};
            char verify_username[256] = {0};
            session_token_to_hex(sess->token,
                                 BIO_SESSION_TOKEN_SIZE,
                                 session_id_hex,
                                 sizeof(session_id_hex));
            if (username_for_uid(caller_uid,
                                 verify_username,
                                 sizeof(verify_username)) != BIO_OK)
            {
                snprintf(verify_username,
                         sizeof(verify_username),
                         "%u",
                         caller_uid);
            }
            emit_uv_success(d, session_id_hex, verify_username);

            daemon_log_auth(caller_uid, "verify", "success",
                            "finger=%s elapsed=%lds",
                            matched_finger_str ? matched_finger_str : "unknown",
                            (long)verify_elapsed);
            BIO_INFO("User %u verified with finger %s (%lds)",
                     caller_uid,
                     matched_finger_str ? matched_finger_str : "?",
                     (long)verify_elapsed);

            pm_error_t vault_rc = auto_unlock_user_vault(d, caller_uid);
            if (vault_rc == PM_OK)
            {
                BIO_INFO("Vault auto-unlocked for UID %u", caller_uid);
                emit_vault_locked_property_changed(connection, FALSE);
                emit_vault_state_changed(d, "unlocked");
                emit_vault_unlocked(d, caller_uid);
            }
            else if (vault_rc != PM_ERR_NOT_FOUND &&
                     vault_rc != PM_ERR_DENIED &&
                     vault_rc != PM_ERR_KEY_UNAVAILABLE)
            {
                BIO_WARN("Vault auto-unlock failed for UID %u: %s",
                         caller_uid, pm_error_str(vault_rc));
            }
        }
        else
        {
            daemon_log_auth(caller_uid, "verify", "failure",
                            "no match, elapsed=%lds",
                            (long)verify_elapsed);
            BIO_INFO("Verification failed for user %u (%lds)",
                     caller_uid, (long)verify_elapsed);
        }

        if (matched)
        {
            emit_auth_state_changed(d, TRUE, "fingerprint");
        }

        /* Check timeout (warn but don't fail — the result is valid) */
        if (verify_elapsed > d->config.session_max_age_seconds)
        {
            BIO_WARN("Verification for UID %u took %lds "
                     "(exceeds session max age %ds)",
                     caller_uid, (long)verify_elapsed,
                     d->config.session_max_age_seconds);
        }

        /* Emit VerifyResult signal */
        GError *sig_err = NULL;
        g_dbus_connection_emit_signal(
            d->bus, NULL,
            BIOAUTH_DBUS_PATH, BIOAUTH_DBUS_INTERFACE,
            "VerifyResult",
            g_variant_new("(b)", matched),
            &sig_err);
        if (sig_err)
        {
            BIO_WARN("Failed to emit VerifyResult: %s",
                     sig_err->message);
            g_error_free(sig_err);
        }

        g_dbus_method_invocation_return_value(
            invocation, g_variant_new("(b)", matched));
    }

    /* ── VerifyUser (for portal / privileged callers) ──────── */
    else if (g_strcmp0(method_name, "VerifyUser") == 0)
    {
        guint32 verify_timeout_ms = 0;  /* default: bio_fp_verify uses its own default */
        const gchar *username = NULL;
        g_variant_get(parameters, "(&s)", &username);

        if (!username || username[0] == '\0')
        {
            g_dbus_method_invocation_return_error(
                invocation, G_DBUS_ERROR, G_DBUS_ERROR_INVALID_ARGS,
                "Username is required");
            return;
        }

        /* Resolve target UID */
        struct passwd pwd_buf;
        char pw_storage[512];
        struct passwd *pw = NULL;
        getpwnam_r(username, &pwd_buf, pw_storage,
                   sizeof(pw_storage), &pw);
        if (!pw)
        {
            g_dbus_method_invocation_return_error(
                invocation, G_DBUS_ERROR, G_DBUS_ERROR_INVALID_ARGS,
                "Unknown user: %s", username);
            return;
        }
        uid_t target_uid = pw->pw_uid;

        /* Authorization: only root or trusted portal service may call this.
         * Regular users must use CreateSession + Verify. */
        bool trusted_portal = caller_is_trusted_portal(connection, invocation);
        if (caller_uid != 0 && !(trusted_portal && caller_uid == target_uid))
        {
            daemon_log_auth(caller_uid, "verify_user",
                            "rejected", "unauthorized caller for %s",
                            username);
            g_dbus_method_invocation_return_error(
                invocation, G_DBUS_ERROR, G_DBUS_ERROR_ACCESS_DENIED,
                "Not authorized for VerifyUser (root or trusted portal only)");
            return;
        }

        /* Rate limiting */
        pthread_mutex_lock(&d->data_lock);
        int lockout_remaining = 0;
        if (check_verify_rate_limit(d, target_uid,
                                    &lockout_remaining) != BIO_OK)
        {
            pthread_mutex_unlock(&d->data_lock);
            g_dbus_method_invocation_return_error(
                invocation, G_DBUS_ERROR, G_DBUS_ERROR_LIMITS_EXCEEDED,
                "Rate limited: try again in %d seconds",
                lockout_remaining);
            return;
        }

        if (!d->fp_dev)
        {
            pthread_mutex_unlock(&d->data_lock);
            g_dbus_method_invocation_return_error(
                invocation, G_DBUS_ERROR, G_DBUS_ERROR_FAILED,
                "No fingerprint device");
            return;
        }

        /* Copy enrollment data under lock for thread safety */
        typedef struct
        {
            uint8_t print_data[BIO_MAX_PRINT_DATA_SIZE];
            size_t print_data_len;
            uint8_t sealed_blob[1024];
            size_t sealed_blob_len;
        } vu_local_t;

        size_t vu_enroll_count = 0;
        for (size_t i = 0; i < d->enrollment_count; i++)
        {
            if ((uid_t)d->enrollments[i].uid == target_uid)
                vu_enroll_count++;
        }

        vu_local_t *vu_locals = NULL;
        if (vu_enroll_count > 0)
        {
            vu_locals = calloc(vu_enroll_count, sizeof(*vu_locals));
            if (!vu_locals)
            {
                pthread_mutex_unlock(&d->data_lock);
                g_dbus_method_invocation_return_error(
                    invocation, G_DBUS_ERROR, G_DBUS_ERROR_FAILED,
                    "Out of memory");
                return;
            }
            size_t vi = 0;
            for (size_t i = 0; i < d->enrollment_count && vi < vu_enroll_count; i++)
            {
                if ((uid_t)d->enrollments[i].uid == target_uid)
                {
                    const bio_enrollment_t *e = &d->enrollments[i];
                    memcpy(vu_locals[vi].print_data, e->print_data, e->print_data_len);
                    vu_locals[vi].print_data_len = e->print_data_len;
                    memcpy(vu_locals[vi].sealed_blob, e->sealed_blob, e->sealed_blob_len);
                    vu_locals[vi].sealed_blob_len = e->sealed_blob_len;
                    vi++;
                }
            }
        }
        bool vu_tpm_avail = d->tpm_available;
        bool vu_tpm_fb = d->config.tpm_fallback_to_plaintext;
        bool vu_tpm_require = d->config.tpm_require;
        pthread_mutex_unlock(&d->data_lock);

        /* Verify against copied enrollment data (no data_lock held) */
        bool matched = false;
        bool policy_denied = false;
        uint8_t unsealed_template[BIO_MAX_PRINT_DATA_SIZE];
        size_t unsealed_len = 0;

        /* Serialize fingerprint/TPM device access */
        pthread_mutex_lock(&d->fp_lock);
        if (d->shutting_down)
        {
            pthread_mutex_unlock(&d->fp_lock);
            if (vu_locals)
            {
                bio_secure_wipe(vu_locals, vu_enroll_count * sizeof(*vu_locals));
                free(vu_locals);
            }
            g_dbus_method_invocation_return_error(
                invocation, G_DBUS_ERROR, G_DBUS_ERROR_FAILED,
                "Daemon shutting down");
            return;
        }

        for (size_t vi = 0; vi < vu_enroll_count && !matched; vi++)
        {
            const uint8_t *verify_data = NULL;
            size_t verify_len = 0;

            if (vu_locals[vi].sealed_blob_len > 0)
            {
                if (!vu_tpm_avail)
                {
                    if (vu_tpm_require)
                    {
                        policy_denied = true;
                        BIO_ERROR("VerifyUser: TPM required by policy but unavailable");
                        continue;
                    }
                    verify_data = vu_locals[vi].print_data;
                    verify_len = vu_locals[vi].print_data_len;
                }
                else
                {
                    unsealed_len = sizeof(unsealed_template);
                    if (bio_mlock_sensitive_strict(unsealed_template,
                                                   sizeof(unsealed_template)) != BIO_OK)
                    {
                        policy_denied = true;
                        BIO_ERROR("VerifyUser: failed to lock unsealed template buffer");
                        continue;
                    }
                    int tpm_rc = daemon_tpm_unseal_template(
                        d,
                        vu_locals[vi].sealed_blob,
                        vu_locals[vi].sealed_blob_len,
                        unsealed_template,
                        &unsealed_len);
                    if (tpm_rc == BIO_OK && unsealed_len > 0)
                    {
                        verify_data = unsealed_template;
                        verify_len = unsealed_len;
                    }
                    else if (vu_tpm_fb && !vu_tpm_require)
                    {
                        BIO_WARN("VerifyUser: TPM unseal failed, "
                                 "falling back (tpm_fallback_to_plaintext=true)");
                        verify_data = vu_locals[vi].print_data;
                        verify_len = vu_locals[vi].print_data_len;
                    }
                    else
                    {
                        policy_denied = true;
                        BIO_ERROR("VerifyUser: TPM unseal failed, "
                                  "plaintext fallback DENIED");
                        bio_secure_wipe(unsealed_template, sizeof(unsealed_template));
                        bio_munlock_sensitive(unsealed_template, sizeof(unsealed_template));
                        continue;
                    }
                }
            }
            else
            {
                if (vu_tpm_require)
                {
                    policy_denied = true;
                    BIO_ERROR("VerifyUser: TPM required by policy but enrollment has no sealed blob");
                    continue;
                }
                verify_data = vu_locals[vi].print_data;
                verify_len = vu_locals[vi].print_data_len;
            }

            int rc = bio_fp_verify(d->fp_dev,
                                   verify_data, verify_len,
                                   NULL, NULL,
                                   (int)verify_timeout_ms);

            if (verify_data == unsealed_template)
            {
                bio_secure_wipe(unsealed_template,
                                sizeof(unsealed_template));
                bio_munlock_sensitive(unsealed_template,
                                      sizeof(unsealed_template));
            }

            if (rc == BIO_OK)
                matched = true;
        }
        pthread_mutex_unlock(&d->fp_lock);

        /* Wipe and free local copies */
        if (vu_locals)
        {
            bio_secure_wipe(vu_locals, vu_enroll_count * sizeof(*vu_locals));
            free(vu_locals);
        }

        if (!matched && policy_denied)
        {
            daemon_log_auth(target_uid, "verify_user", "denied",
                            "require_tpm policy denied plaintext fallback");
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR, G_DBUS_ERROR_FAILED,
                "TPM is required by policy; VerifyUser denied without TPM-sealed data");
            return;
        }

        pthread_mutex_lock(&d->data_lock);
        if (matched)
        {
            reset_verify_rate_limit(d, target_uid);
        }
        else
        {
            record_verify_failure(d, target_uid);
        }
        pthread_mutex_unlock(&d->data_lock);

        if (matched)
        {
            char verify_user_session_id[64] = {0};
            snprintf(verify_user_session_id,
                     sizeof(verify_user_session_id),
                     "verifyuser-%u",
                     target_uid);
            emit_uv_success(d, verify_user_session_id, username);

            daemon_log_auth(target_uid, "verify_user", "success",
                            "caller=%u", caller_uid);

            pm_error_t vault_rc = auto_unlock_user_vault(d, target_uid);
            if (vault_rc == PM_OK)
            {
                BIO_INFO("Vault auto-unlocked for UID %u via VerifyUser", target_uid);
                emit_vault_locked_property_changed(connection, FALSE);
                emit_vault_state_changed(d, "unlocked");
                emit_vault_unlocked(d, target_uid);
            }
            else if (vault_rc != PM_ERR_NOT_FOUND &&
                     vault_rc != PM_ERR_DENIED &&
                     vault_rc != PM_ERR_KEY_UNAVAILABLE)
            {
                BIO_WARN("Vault auto-unlock failed for UID %u via VerifyUser: %s",
                         target_uid, pm_error_str(vault_rc));
            }
        }
        else
        {
            daemon_log_auth(target_uid, "verify_user", "failure",
                            "caller=%u", caller_uid);
        }

        if (matched)
        {
            emit_auth_state_changed(d, TRUE, "fingerprint");
        }

        g_dbus_method_invocation_return_value(
            invocation, g_variant_new("(b)", matched));
    }

    else if (g_strcmp0(method_name, "GetPreferences") == 0)
    {
        char path[PATH_MAX];
        if (snprintf(path,
                     sizeof(path),
                     "%s/users/%u/preferences.json",
                     d->config.state_dir,
                     caller_uid) >= (int)sizeof(path))
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_FAILED,
                "Preferences path too long");
            return;
        }

        char *json = NULL;
        GError *err = NULL;
        if (g_file_get_contents(path, &json, NULL, &err))
        {
            g_dbus_method_invocation_return_value(invocation, g_variant_new("(s)", json));
            g_free(json);
        }
        else
        {
            // Default preferences if file doesn't exist
            g_dbus_method_invocation_return_value(invocation, g_variant_new("(s)", "{}"));
            if (err)
                g_error_free(err);
        }
    }
    else if (g_strcmp0(method_name, "SetPreferences") == 0)
    {
        const gchar *json = NULL;
        g_variant_get(parameters, "(&s)", &json);

        char path[PATH_MAX];
        char dir_path[PATH_MAX];
        if (snprintf(path,
                     sizeof(path),
                     "%s/users/%u/preferences.json",
                     d->config.state_dir,
                     caller_uid) >= (int)sizeof(path) ||
            snprintf(dir_path,
                     sizeof(dir_path),
                     "%s/users/%u",
                     d->config.state_dir,
                     caller_uid) >= (int)sizeof(dir_path))
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_FAILED,
                "Preferences path too long");
            return;
        }

        // Ensure directory exists
        g_mkdir_with_parents(dir_path, 0700);

        GError *err = NULL;
        gboolean success = g_file_set_contents(path, json, -1, &err);
        if (success)
        {
            chmod(path, 0600); // Secure the file
            if (chown(path, caller_uid, caller_uid) < 0)
            { /* ignore */
            }
            if (chown(dir_path, caller_uid, caller_uid) < 0)
            { /* ignore */
            }
            g_dbus_method_invocation_return_value(invocation, g_variant_new("(b)", TRUE));
        }
        else
        {
            g_dbus_method_invocation_return_error(invocation,
                                                  G_DBUS_ERROR,
                                                  G_DBUS_ERROR_FAILED,
                                                  "Failed to save preferences: %s",
                                                  err ? err->message : "unknown");
            if (err)
                g_error_free(err);
        }
    }

    else if (g_strcmp0(method_name, "SearchCredentials") == 0)
    {
        const gchar *query = NULL;
        bio_user_vault_t *slot = NULL;
        pm_error_t rc;
        char **ids = NULL;
        size_t id_count = 0;
        GVariantBuilder list_builder;

        g_variant_get(parameters, "(&s)", &query);

        rc = ensure_user_vault_handle(d, caller_uid, &slot);
        if (rc != PM_OK)
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_FAILED,
                "Vault unavailable: %s",
                pm_error_str(rc));
            return;
        }

        if (!slot->handle || pm_vault_is_locked(slot->handle))
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_ACCESS_DENIED,
                "Vault is locked");
            return;
        }

        g_variant_builder_init(&list_builder, G_VARIANT_TYPE("aa{ss}"));

        rc = pm_vault_entry_list_ids(slot->handle, &ids, &id_count);
        if (rc != PM_OK)
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_FAILED,
                "Vault search failed: %s",
                pm_error_str(rc));
            return;
        }

        for (size_t i = 0; i < id_count; i++)
        {
            pm_entry_t entry;
            pm_entry_init(&entry);

            if (!ids[i] || pm_vault_entry_get(slot->handle, ids[i], &entry) != PM_OK)
            {
                pm_entry_free(&entry);
                continue;
            }

            if (entry_matches_search(&entry, query, NULL))
            {
                bool has_totp = false;
                GVariantBuilder row_builder;
                g_variant_builder_init(&row_builder, G_VARIANT_TYPE("a{ss}"));

                for (size_t cf = 0; cf < entry.custom_field_count; cf++)
                {
                    if (entry.custom_fields[cf].type == PM_FIELD_TOTP &&
                        entry.custom_fields[cf].text_value)
                    {
                        has_totp = true;
                        break;
                    }
                }

                g_variant_builder_add(&row_builder,
                                      "{ss}",
                                      "id",
                                      entry.id ? entry.id : "");
                g_variant_builder_add(&row_builder,
                                      "{ss}",
                                      "title",
                                      entry.title ? entry.title : "");
                g_variant_builder_add(&row_builder,
                                      "{ss}",
                                      "username",
                                      entry.username ? entry.username : "");
                g_variant_builder_add(&row_builder,
                                      "{ss}",
                                      "url",
                                      entry.url ? entry.url : "");
                g_variant_builder_add(&row_builder,
                                      "{ss}",
                                      "group_id",
                                      entry.group_id ? entry.group_id : "");
                g_variant_builder_add(&row_builder,
                                      "{ss}",
                                      "has_totp",
                                      has_totp ? "true" : "false");

                g_variant_builder_add_value(&list_builder,
                                            g_variant_builder_end(&row_builder));
            }

            pm_entry_free(&entry);
        }

        pm_vault_entry_id_list_free(ids, id_count);

        pthread_mutex_lock(&d->data_lock);
        slot->unlocked_at = time(NULL);
        pthread_mutex_unlock(&d->data_lock);

        g_dbus_method_invocation_return_value(
            invocation,
            g_variant_new("(aa{ss})", &list_builder));
    }

    else if (g_strcmp0(method_name, "GetCredential") == 0)
    {
        const gchar *url = NULL;
        const gchar *field = NULL;
        bio_user_vault_t *slot = NULL;
        pm_entry_t entry;
        pm_error_t rc;
        const char *value = NULL;

        g_variant_get(parameters, "(&s&s)", &url, &field);

        if (!url || url[0] == '\0' || !field || field[0] == '\0')
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_INVALID_ARGS,
                "url and field are required");
            return;
        }

        rc = ensure_user_vault_handle(d, caller_uid, &slot);
        if (rc != PM_OK)
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_FAILED,
                "Vault unavailable: %s",
                pm_error_str(rc));
            return;
        }

        if (!slot->handle || pm_vault_is_locked(slot->handle))
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_ACCESS_DENIED,
                "Vault is locked");
            return;
        }

        rc = find_first_entry_matching(slot->handle, NULL, url, &entry);
        if (rc != PM_OK)
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                rc == PM_ERR_NOT_FOUND ? G_DBUS_ERROR_UNKNOWN_OBJECT : G_DBUS_ERROR_FAILED,
                "Credential not found for URL");
            return;
        }

        value = entry_field_value(&entry, field);
        if (!value)
        {
            pm_entry_free(&entry);
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_INVALID_ARGS,
                "Unknown field: %s",
                field);
            return;
        }

        pthread_mutex_lock(&d->data_lock);
        slot->unlocked_at = time(NULL);
        pthread_mutex_unlock(&d->data_lock);

        g_dbus_method_invocation_return_value(
            invocation,
            g_variant_new("(s)", value));
        pm_entry_free(&entry);
    }

    else if (g_strcmp0(method_name, "GetAllCredentials") == 0)
    {
        const gchar *url = NULL;
        bio_user_vault_t *slot = NULL;
        pm_entry_t entry;
        pm_error_t rc;
        GVariantBuilder fields_builder;

        g_variant_get(parameters, "(&s)", &url);

        rc = ensure_user_vault_handle(d, caller_uid, &slot);
        if (rc != PM_OK)
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_FAILED,
                "Vault unavailable: %s",
                pm_error_str(rc));
            return;
        }

        if (!slot->handle || pm_vault_is_locked(slot->handle))
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_ACCESS_DENIED,
                "Vault is locked");
            return;
        }

        g_variant_builder_init(&fields_builder, G_VARIANT_TYPE("a{ss}"));

        rc = find_first_entry_matching(slot->handle,
                                       NULL,
                                       (url && url[0] != '\0') ? url : NULL,
                                       &entry);
        if (rc == PM_OK)
        {
            g_variant_builder_add(&fields_builder,
                                  "{ss}",
                                  "id",
                                  entry.id ? entry.id : "");
            g_variant_builder_add(&fields_builder,
                                  "{ss}",
                                  "title",
                                  entry.title ? entry.title : "");
            g_variant_builder_add(&fields_builder,
                                  "{ss}",
                                  "username",
                                  entry.username ? entry.username : "");
            g_variant_builder_add(&fields_builder,
                                  "{ss}",
                                  "password",
                                  entry.password ? entry.password : "");
            g_variant_builder_add(&fields_builder,
                                  "{ss}",
                                  "url",
                                  entry.url ? entry.url : "");
            g_variant_builder_add(&fields_builder,
                                  "{ss}",
                                  "notes",
                                  entry.notes ? entry.notes : "");

            for (size_t i = 0; i < entry.custom_field_count; i++)
            {
                if (!entry.custom_fields[i].name || !entry.custom_fields[i].text_value)
                {
                    continue;
                }

                g_variant_builder_add(&fields_builder,
                                      "{ss}",
                                      entry.custom_fields[i].name,
                                      entry.custom_fields[i].text_value);
            }

            pm_entry_free(&entry);
        }
        else if (rc != PM_ERR_NOT_FOUND)
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_FAILED,
                "Credential lookup failed: %s",
                pm_error_str(rc));
            return;
        }

        pthread_mutex_lock(&d->data_lock);
        slot->unlocked_at = time(NULL);
        pthread_mutex_unlock(&d->data_lock);

        g_dbus_method_invocation_return_value(
            invocation,
            g_variant_new("(a{ss})", &fields_builder));
    }

    else if (g_strcmp0(method_name, "VaultStatus") == 0)
    {
        bio_user_vault_t *slot = NULL;
        pm_error_t rc;
        const char *status = "no_vault";

        rc = ensure_user_vault_handle(d, caller_uid, &slot);
        if (rc == PM_OK && slot && slot->handle)
        {
            status = pm_vault_is_locked(slot->handle) ? "locked" : "unlocked";
        }
        else if (rc != PM_OK && rc != PM_ERR_NOT_FOUND)
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_FAILED,
                "Vault status failed: %s",
                pm_error_str(rc));
            return;
        }

        g_dbus_method_invocation_return_value(
            invocation,
            g_variant_new("(s)", status));
    }

    else if (g_strcmp0(method_name, "ListPasskeys") == 0)
    {
        bio_user_vault_t *slot = NULL;
        pm_error_t rc;
        char **ids = NULL;
        size_t id_count = 0;
        GVariantBuilder list_builder;

        rc = ensure_user_vault_handle(d, caller_uid, &slot);
        if (rc != PM_OK)
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_FAILED,
                "Vault unavailable: %s",
                pm_error_str(rc));
            return;
        }

        if (!slot->handle || pm_vault_is_locked(slot->handle))
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_ACCESS_DENIED,
                "Vault is locked");
            return;
        }

        g_variant_builder_init(&list_builder, G_VARIANT_TYPE("aa{ss}"));

        rc = pm_vault_entry_list_ids(slot->handle, &ids, &id_count);
        if (rc != PM_OK)
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_FAILED,
                "Passkey list failed: %s",
                pm_error_str(rc));
            return;
        }

        for (size_t i = 0; i < id_count; i++)
        {
            pm_entry_t entry;
            const char *rp_id;
            const char *user_id;
            GVariantBuilder row_builder;

            pm_entry_init(&entry);
            if (!ids[i] || pm_vault_entry_get(slot->handle, ids[i], &entry) != PM_OK)
            {
                pm_entry_free(&entry);
                continue;
            }

            if (!entry_is_passkey(&entry))
            {
                pm_entry_free(&entry);
                continue;
            }

            rp_id = entry_custom_field_text(&entry, PASSKEY_FIELD_RP_ID);
            if (!rp_id || rp_id[0] == '\0')
            {
                rp_id = entry.url ? entry.url : "";
            }

            user_id = entry_custom_field_text(&entry, PASSKEY_FIELD_USER_ID);
            if (!user_id)
            {
                user_id = entry.username ? entry.username : "";
            }

            g_variant_builder_init(&row_builder, G_VARIANT_TYPE("a{ss}"));
            g_variant_builder_add(&row_builder,
                                  "{ss}",
                                  "entry_id",
                                  entry.id ? entry.id : "");
            g_variant_builder_add(&row_builder,
                                  "{ss}",
                                  "rp_id",
                                  rp_id);
            g_variant_builder_add(&row_builder,
                                  "{ss}",
                                  "user_id",
                                  user_id);
            g_variant_builder_add(&row_builder,
                                  "{ss}",
                                  "title",
                                  entry.title ? entry.title : "");

            g_variant_builder_add_value(&list_builder,
                                        g_variant_builder_end(&row_builder));
            pm_entry_free(&entry);
        }

        pm_vault_entry_id_list_free(ids, id_count);

        pthread_mutex_lock(&d->data_lock);
        slot->unlocked_at = time(NULL);
        pthread_mutex_unlock(&d->data_lock);

        g_dbus_method_invocation_return_value(
            invocation,
            g_variant_new("(aa{ss})", &list_builder));
    }

    else if (g_strcmp0(method_name, "GetPasskey") == 0)
    {
        const gchar *rp_id = NULL;
        bio_user_vault_t *slot = NULL;
        pm_entry_t entry;
        pm_error_t rc;
        const char *private_key_b64;
        gsize private_key_len = 0;
        guchar *private_key = NULL;
        GBytes *private_bytes = NULL;
        GVariant *private_variant = NULL;

        g_variant_get(parameters, "(&s)", &rp_id);
        if (!rp_id || rp_id[0] == '\0')
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_INVALID_ARGS,
                "rp_id is required");
            return;
        }

        rc = ensure_user_vault_handle(d, caller_uid, &slot);
        if (rc != PM_OK)
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_FAILED,
                "Vault unavailable: %s",
                pm_error_str(rc));
            return;
        }

        if (!slot->handle || pm_vault_is_locked(slot->handle))
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_ACCESS_DENIED,
                "Vault is locked");
            return;
        }

        rc = find_passkey_entry_by_rp(slot->handle, rp_id, &entry);
        if (rc != PM_OK)
        {
            daemon_log_auth(caller_uid,
                            "passkey_get",
                            "failure",
                            "rp_id=%s rc=%s",
                            rp_id,
                            pm_error_str(rc));
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                rc == PM_ERR_NOT_FOUND ? G_DBUS_ERROR_UNKNOWN_OBJECT : G_DBUS_ERROR_FAILED,
                "Passkey not found for rp_id: %s",
                rp_id);
            return;
        }

        private_key_b64 = entry_custom_field_text(&entry, PASSKEY_FIELD_PRIVATE_KEY_B64);
        if (!private_key_b64 || private_key_b64[0] == '\0')
        {
            pm_entry_free(&entry);
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_FAILED,
                "Passkey entry is missing private key material");
            return;
        }

        private_key = g_base64_decode(private_key_b64, &private_key_len);
        if (!private_key || private_key_len == 0)
        {
            pm_entry_free(&entry);
            if (private_key)
            {
                g_free(private_key);
            }
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_FAILED,
                "Stored passkey private key is invalid");
            return;
        }

        private_bytes = g_bytes_new_take(private_key, private_key_len);
        private_variant = g_variant_new_from_bytes(G_VARIANT_TYPE("ay"),
                                                   private_bytes,
                                                   TRUE);
        g_bytes_unref(private_bytes);

        pthread_mutex_lock(&d->data_lock);
        slot->unlocked_at = time(NULL);
        pthread_mutex_unlock(&d->data_lock);

        daemon_log_auth(caller_uid,
                        "passkey_get",
                        "success",
                        "rp_id=%s bytes=%zu",
                        rp_id,
                        (size_t)private_key_len);

        g_dbus_method_invocation_return_value(
            invocation,
            g_variant_new("(@ay)", private_variant));
        pm_entry_free(&entry);
    }

    else if (g_strcmp0(method_name, "SavePasskey") == 0)
    {
        const gchar *rp_id = NULL;
        const gchar *user_id = NULL;
        GVariant *private_key_variant = NULL;
        GVariant *public_key_variant = NULL;
        const guint8 *private_key = NULL;
        const guint8 *public_key = NULL;
        gsize private_key_len = 0;
        gsize public_key_len = 0;
        gchar *private_key_b64 = NULL;
        gchar *public_key_b64 = NULL;
        gchar *title_tmp = NULL;
        gchar *uuid_tmp = NULL;
        bio_user_vault_t *slot = NULL;
        pm_entry_t entry;
        pm_error_t rc;
        bool existing = false;
        uint64_t ts_ms = now_epoch_ms();

        pm_entry_init(&entry);

        g_variant_get(parameters,
                      "(&s&s@ay@ay)",
                      &rp_id,
                      &user_id,
                      &private_key_variant,
                      &public_key_variant);

        private_key = g_variant_get_fixed_array(private_key_variant,
                                                &private_key_len,
                                                1);
        public_key = g_variant_get_fixed_array(public_key_variant,
                                               &public_key_len,
                                               1);

        if (!rp_id || rp_id[0] == '\0' ||
            !private_key || private_key_len == 0 ||
            !public_key || public_key_len == 0)
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_INVALID_ARGS,
                "rp_id, private_key, and public_key are required");
            goto save_passkey_cleanup;
        }

        private_key_b64 = g_base64_encode(private_key, private_key_len);
        public_key_b64 = g_base64_encode(public_key, public_key_len);
        if (!private_key_b64 || !public_key_b64)
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_NO_MEMORY,
                "Failed to encode passkey material");
            goto save_passkey_cleanup;
        }

        rc = ensure_user_vault_handle(d, caller_uid, &slot);
        if (rc != PM_OK)
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_FAILED,
                "Vault unavailable: %s",
                pm_error_str(rc));
            goto save_passkey_cleanup;
        }

        if (!slot->handle || pm_vault_is_locked(slot->handle))
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_ACCESS_DENIED,
                "Vault is locked");
            goto save_passkey_cleanup;
        }

        rc = find_passkey_entry_by_rp(slot->handle, rp_id, &entry);
        if (rc == PM_OK)
        {
            existing = true;
        }
        else if (rc != PM_ERR_NOT_FOUND)
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_FAILED,
                "Passkey lookup failed: %s",
                pm_error_str(rc));
            goto save_passkey_cleanup;
        }

        if (!existing)
        {
            uuid_tmp = g_uuid_string_random();
            if (!uuid_tmp)
            {
                g_dbus_method_invocation_return_error(
                    invocation,
                    G_DBUS_ERROR,
                    G_DBUS_ERROR_NO_MEMORY,
                    "Failed to allocate passkey id");
                goto save_passkey_cleanup;
            }

            entry.id = strdup(uuid_tmp);
            g_free(uuid_tmp);
            uuid_tmp = NULL;

            entry.url = strdup(rp_id);
            entry.urls = calloc(1, sizeof(char *));
            entry.url_count = 1;
            if (entry.urls)
            {
                entry.urls[0] = strdup(rp_id);
            }

            entry.username = strdup(user_id ? user_id : "");
            entry.password = strdup("");

            title_tmp = g_strdup_printf("Passkey for %s", rp_id);
            entry.title = strdup(title_tmp ? title_tmp : rp_id);
            g_free(title_tmp);
            title_tmp = NULL;

            entry.created_at_ms = ts_ms;
            entry.updated_at_ms = ts_ms;
            entry.accessed_at_ms = ts_ms;
        }
        else
        {
            if (!entry.url || entry.url[0] == '\0')
            {
                free(entry.url);
                entry.url = strdup(rp_id);
            }
            if ((!entry.urls || entry.url_count == 0) && entry.url)
            {
                free(entry.urls);
                entry.urls = calloc(1, sizeof(char *));
                entry.url_count = 1;
                if (entry.urls)
                {
                    entry.urls[0] = strdup(entry.url);
                }
            }
            if (user_id)
            {
                free(entry.username);
                entry.username = strdup(user_id);
            }
            if (!entry.title || entry.title[0] == '\0')
            {
                title_tmp = g_strdup_printf("Passkey for %s", rp_id);
                free(entry.title);
                entry.title = strdup(title_tmp ? title_tmp : rp_id);
                g_free(title_tmp);
                title_tmp = NULL;
            }

            entry.updated_at_ms = ts_ms;
            entry.accessed_at_ms = ts_ms;
        }

        if (!entry.id || !entry.url || !entry.urls || !entry.urls[0] ||
            !entry.username || !entry.password || !entry.title)
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_NO_MEMORY,
                "Failed to allocate passkey entry fields");
            goto save_passkey_cleanup;
        }

        rc = entry_set_custom_text(&entry,
                                   PASSKEY_FIELD_KIND,
                                   PM_FIELD_TEXT,
                                   PASSKEY_KIND_VALUE);
        if (rc == PM_OK)
        {
            rc = entry_set_custom_text(&entry,
                                       PASSKEY_FIELD_RP_ID,
                                       PM_FIELD_TEXT,
                                       rp_id);
        }
        if (rc == PM_OK)
        {
            rc = entry_set_custom_text(&entry,
                                       PASSKEY_FIELD_USER_ID,
                                       PM_FIELD_TEXT,
                                       user_id ? user_id : "");
        }
        if (rc == PM_OK)
        {
            rc = entry_set_custom_text(&entry,
                                       PASSKEY_FIELD_PRIVATE_KEY_B64,
                                       PM_FIELD_HIDDEN,
                                       private_key_b64);
        }
        if (rc == PM_OK)
        {
            rc = entry_set_custom_text(&entry,
                                       PASSKEY_FIELD_PUBLIC_KEY_B64,
                                       PM_FIELD_TEXT,
                                       public_key_b64);
        }

        if (rc != PM_OK)
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_NO_MEMORY,
                "Failed to store passkey fields: %s",
                pm_error_str(rc));
            goto save_passkey_cleanup;
        }

        rc = existing
                 ? pm_vault_entry_update(slot->handle, entry.id, &entry)
                 : pm_vault_entry_add(slot->handle, &entry, false);
        if (rc != PM_OK)
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_FAILED,
                "Failed to save passkey entry: %s",
                pm_error_str(rc));
            goto save_passkey_cleanup;
        }

        rc = pm_vault_save(slot->handle);
        if (rc != PM_OK)
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_FAILED,
                "Failed to persist passkey entry: %s",
                pm_error_str(rc));
            goto save_passkey_cleanup;
        }

        pthread_mutex_lock(&d->data_lock);
        slot->unlocked_at = time(NULL);
        pthread_mutex_unlock(&d->data_lock);

        daemon_log_auth(caller_uid,
                        "passkey_save",
                        "success",
                        "rp_id=%s mode=%s",
                        rp_id,
                        existing ? "update" : "create");

        g_dbus_method_invocation_return_value(invocation, NULL);

    save_passkey_cleanup:
        if (private_key_variant)
        {
            g_variant_unref(private_key_variant);
        }
        if (public_key_variant)
        {
            g_variant_unref(public_key_variant);
        }
        if (private_key_b64)
        {
            g_free(private_key_b64);
        }
        if (public_key_b64)
        {
            g_free(public_key_b64);
        }
        if (title_tmp)
        {
            g_free(title_tmp);
        }
        if (uuid_tmp)
        {
            g_free(uuid_tmp);
        }
        pm_entry_free(&entry);
    }

    else if (g_strcmp0(method_name, "SearchAdvanced") == 0)
    {
        const gchar *query = NULL;
        const gchar *url = NULL;
        const gchar *group_id = NULL;
        gboolean include_descendants = FALSE;
        bio_user_vault_t *slot = NULL;
        char *json = NULL;
        pm_error_t rc;

        g_variant_get(parameters,
                      "(&s&s&sb)",
                      &query,
                      &url,
                      &group_id,
                      &include_descendants);

        rc = ensure_user_vault_handle(d, caller_uid, &slot);
        if (rc != PM_OK)
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_FAILED,
                "Vault unavailable: %s",
                pm_error_str(rc));
            return;
        }

        if (!slot->handle || pm_vault_is_locked(slot->handle))
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_ACCESS_DENIED,
                "Vault is locked");
            return;
        }

        rc = build_search_json_scoped(slot->handle,
                                      query,
                                      url,
                                      group_id,
                                      include_descendants,
                                      &json);
        if (rc != PM_OK)
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_FAILED,
                "Vault advanced search failed: %s",
                pm_error_str(rc));
            return;
        }

        pthread_mutex_lock(&d->data_lock);
        slot->unlocked_at = time(NULL);
        pthread_mutex_unlock(&d->data_lock);

        g_dbus_method_invocation_return_value(
            invocation,
            g_variant_new("(s)", json ? json : "[]"));
        g_free(json);
    }

    else if (g_strcmp0(method_name, "Search") == 0)
    {
        const gchar *query = NULL;
        const gchar *url = NULL;
        bio_user_vault_t *slot = NULL;
        char *json = NULL;
        pm_error_t rc;

        g_variant_get(parameters, "(&s&s)", &query, &url);

        rc = ensure_user_vault_handle(d, caller_uid, &slot);
        if (rc != PM_OK)
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_FAILED,
                "Vault unavailable: %s",
                pm_error_str(rc));
            return;
        }

        if (!slot->handle || pm_vault_is_locked(slot->handle))
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_ACCESS_DENIED,
                "Vault is locked");
            return;
        }

        rc = build_search_json(slot->handle, query, url, &json);
        if (rc != PM_OK)
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_FAILED,
                "Vault search failed: %s",
                pm_error_str(rc));
            return;
        }

        /* Update vault access time for idle timeout tracking */
        pthread_mutex_lock(&d->data_lock);
        slot->unlocked_at = time(NULL);
        pthread_mutex_unlock(&d->data_lock);

        g_dbus_method_invocation_return_value(
            invocation,
            g_variant_new("(s)", json ? json : "[]"));
        g_free(json);
    }

    else if (g_strcmp0(method_name, "GetEntry") == 0)
    {
        const gchar *entry_id = NULL;
        bio_user_vault_t *slot = NULL;
        char *json = NULL;
        pm_error_t rc;

        g_variant_get(parameters, "(&s)", &entry_id);
        if (!entry_id || entry_id[0] == '\0')
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_INVALID_ARGS,
                "entry_id is required");
            return;
        }

        rc = ensure_user_vault_handle(d, caller_uid, &slot);
        if (rc != PM_OK)
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_FAILED,
                "Vault unavailable: %s",
                pm_error_str(rc));
            return;
        }

        if (!slot->handle || pm_vault_is_locked(slot->handle))
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_ACCESS_DENIED,
                "Vault is locked");
            return;
        }

        rc = build_entry_json(slot->handle, entry_id, &json);
        if (rc != PM_OK)
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                rc == PM_ERR_NOT_FOUND ? G_DBUS_ERROR_UNKNOWN_OBJECT : G_DBUS_ERROR_FAILED,
                "GetEntry failed: %s",
                pm_error_str(rc));
            return;
        }

        /* Update vault access time for idle timeout tracking */
        pthread_mutex_lock(&d->data_lock);
        slot->unlocked_at = time(NULL);
        pthread_mutex_unlock(&d->data_lock);

        g_dbus_method_invocation_return_value(
            invocation,
            g_variant_new("(s)", json ? json : "{}"));
        g_free(json);
    }

    else if (g_strcmp0(method_name, "ListGroups") == 0)
    {
        bio_user_vault_t *slot = NULL;
        char *json = NULL;
        pm_error_t rc;

        rc = ensure_user_vault_handle(d, caller_uid, &slot);
        if (rc != PM_OK)
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_FAILED,
                "Vault unavailable: %s",
                pm_error_str(rc));
            return;
        }

        if (!slot->handle || pm_vault_is_locked(slot->handle))
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_ACCESS_DENIED,
                "Vault is locked");
            return;
        }

        rc = build_groups_json(slot->handle, &json);
        if (rc != PM_OK)
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_FAILED,
                "ListGroups failed: %s",
                pm_error_str(rc));
            return;
        }

        pthread_mutex_lock(&d->data_lock);
        slot->unlocked_at = time(NULL);
        pthread_mutex_unlock(&d->data_lock);

        g_dbus_method_invocation_return_value(
            invocation,
            g_variant_new("(s)", json ? json : "[]"));
        g_free(json);
    }

    else if (g_strcmp0(method_name, "GetEntryHistory") == 0)
    {
        const gchar *entry_id = NULL;
        bio_user_vault_t *slot = NULL;
        char *json = NULL;
        pm_error_t rc;

        g_variant_get(parameters, "(&s)", &entry_id);
        if (!entry_id || entry_id[0] == '\0')
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_INVALID_ARGS,
                "entry_id is required");
            return;
        }

        rc = ensure_user_vault_handle(d, caller_uid, &slot);
        if (rc != PM_OK)
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_FAILED,
                "Vault unavailable: %s",
                pm_error_str(rc));
            return;
        }

        if (!slot->handle || pm_vault_is_locked(slot->handle))
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_ACCESS_DENIED,
                "Vault is locked");
            return;
        }

        rc = build_entry_history_json(slot->handle, entry_id, &json);
        if (rc != PM_OK)
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                rc == PM_ERR_NOT_FOUND ? G_DBUS_ERROR_UNKNOWN_OBJECT : G_DBUS_ERROR_FAILED,
                "GetEntryHistory failed: %s",
                pm_error_str(rc));
            return;
        }

        pthread_mutex_lock(&d->data_lock);
        slot->unlocked_at = time(NULL);
        pthread_mutex_unlock(&d->data_lock);

        g_dbus_method_invocation_return_value(
            invocation,
            g_variant_new("(s)", json ? json : "[]"));
        g_free(json);
    }

    else if (g_strcmp0(method_name, "ListEntryAttachments") == 0)
    {
        const gchar *entry_id = NULL;
        bio_user_vault_t *slot = NULL;
        char *json = NULL;
        pm_error_t rc;

        g_variant_get(parameters, "(&s)", &entry_id);
        if (!entry_id || entry_id[0] == '\0')
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_INVALID_ARGS,
                "entry_id is required");
            return;
        }

        rc = ensure_user_vault_handle(d, caller_uid, &slot);
        if (rc != PM_OK)
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_FAILED,
                "Vault unavailable: %s",
                pm_error_str(rc));
            return;
        }

        if (!slot->handle || pm_vault_is_locked(slot->handle))
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_ACCESS_DENIED,
                "Vault is locked");
            return;
        }

        rc = build_entry_attachments_json(slot->handle, entry_id, &json);
        if (rc != PM_OK)
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                rc == PM_ERR_NOT_FOUND ? G_DBUS_ERROR_UNKNOWN_OBJECT : G_DBUS_ERROR_FAILED,
                "ListEntryAttachments failed: %s",
                pm_error_str(rc));
            return;
        }

        pthread_mutex_lock(&d->data_lock);
        slot->unlocked_at = time(NULL);
        pthread_mutex_unlock(&d->data_lock);

        g_dbus_method_invocation_return_value(
            invocation,
            g_variant_new("(s)", json ? json : "[]"));
        g_free(json);
    }

    else if (g_strcmp0(method_name, "SaveCredential") == 0)
    {
        const gchar *url = NULL;
        const gchar *username = NULL;
        const gchar *password = NULL;
        const gchar *title = NULL;
        bio_user_vault_t *slot = NULL;
        pm_entry_t entry;
        pm_error_t rc;
        uint64_t ts_ms;
        char *saved_entry_id = NULL;

        if (daemon_api_path)
        {
            /* New API ordering on /org/bioauth/Daemon:
             * SaveCredential(title, url, username, password) */
            g_variant_get(parameters, "(&s&s&s&s)",
                          &title, &url, &username, &password);
        }
        else
        {
            /* Legacy ordering on /org/bioauth/Manager:
             * SaveCredential(url, username, password, title) */
            g_variant_get(parameters, "(&s&s&s&s)",
                          &url, &username, &password, &title);
        }

        if (!url || url[0] == '\0' || !password || password[0] == '\0')
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_INVALID_ARGS,
                "url and password are required");
            return;
        }

        rc = ensure_user_vault_handle(d, caller_uid, &slot);
        if (rc != PM_OK)
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_FAILED,
                "Vault unavailable: %s",
                pm_error_str(rc));
            return;
        }

        if (!slot->handle || pm_vault_is_locked(slot->handle))
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_ACCESS_DENIED,
                "Vault is locked");
            return;
        }

        pm_entry_init(&entry);
        ts_ms = now_epoch_ms();

        gchar *uuid_tmp = g_uuid_string_random();
        if (!uuid_tmp)
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_NO_MEMORY,
                "Failed to allocate entry id");
            return;
        }

        entry.id = strdup(uuid_tmp);
        g_free(uuid_tmp);
        entry.url = strdup(url);
        entry.urls = calloc(1, sizeof(char *));
        entry.url_count = 1;
        if (entry.urls)
        {
            entry.urls[0] = strdup(url);
        }
        entry.username = strdup(username ? username : "");
        entry.password = strdup(password);
        entry.title = strdup((title && title[0] != '\0') ? title : url);
        entry.created_at_ms = ts_ms;
        entry.updated_at_ms = ts_ms;
        entry.accessed_at_ms = ts_ms;

        if (!entry.id || !entry.url || !entry.urls || !entry.urls[0] ||
            !entry.username || !entry.password || !entry.title)
        {
            pm_entry_free(&entry);
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_NO_MEMORY,
                "Failed to allocate credential fields");
            return;
        }

        rc = pm_vault_entry_add(slot->handle, &entry, false);
        if (rc != PM_OK)
        {
            pm_entry_free(&entry);
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_FAILED,
                "Failed to save credential: %s",
                pm_error_str(rc));
            return;
        }

        rc = pm_vault_save(slot->handle);
        if (rc != PM_OK)
        {
            pm_entry_free(&entry);
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_FAILED,
                "Failed to persist credential: %s",
                pm_error_str(rc));
            return;
        }

        saved_entry_id = strdup(entry.id ? entry.id : "");
        pm_entry_free(&entry);

        if (!saved_entry_id)
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_NO_MEMORY,
                "Failed to allocate response");
            return;
        }

        /* Update vault access time for idle timeout tracking */
        pthread_mutex_lock(&d->data_lock);
        slot->unlocked_at = time(NULL);
        pthread_mutex_unlock(&d->data_lock);

        BIO_INFO("Credential saved to vault for UID %u", caller_uid);

        g_dbus_method_invocation_return_value(
            invocation,
            g_variant_new("(s)", saved_entry_id));
        free(saved_entry_id);
    }

    else if (g_strcmp0(method_name, "DeleteEntry") == 0 ||
             g_strcmp0(method_name, "DeleteCredential") == 0)
    {
        const gchar *entry_id = NULL;
        bio_user_vault_t *slot = NULL;
        pm_error_t rc;

        g_variant_get(parameters, "(&s)", &entry_id);
        if (!entry_id || entry_id[0] == '\0')
        {
            g_dbus_method_invocation_return_error(
                invocation, G_DBUS_ERROR, G_DBUS_ERROR_INVALID_ARGS, "entry_id is required");
            return;
        }

        rc = ensure_user_vault_handle(d, caller_uid, &slot);
        if (rc != PM_OK)
        {
            g_dbus_method_invocation_return_error(
                invocation, G_DBUS_ERROR, G_DBUS_ERROR_FAILED, "Vault unavailable: %s", pm_error_str(rc));
            return;
        }

        if (!slot->handle || pm_vault_is_locked(slot->handle))
        {
            g_dbus_method_invocation_return_error(
                invocation, G_DBUS_ERROR, G_DBUS_ERROR_ACCESS_DENIED, "Vault is locked");
            return;
        }

        rc = pm_vault_entry_remove(slot->handle, entry_id);
        if (rc != PM_OK)
        {
            g_dbus_method_invocation_return_error(
                invocation, G_DBUS_ERROR, G_DBUS_ERROR_FAILED, "Delete failed: %s", pm_error_str(rc));
            return;
        }

        rc = pm_vault_save(slot->handle);
        if (rc != PM_OK)
        {
            g_dbus_method_invocation_return_error(
                invocation, G_DBUS_ERROR, G_DBUS_ERROR_FAILED, "Persist failed: %s", pm_error_str(rc));
            return;
        }

        pthread_mutex_lock(&d->data_lock);
        slot->unlocked_at = time(NULL);
        pthread_mutex_unlock(&d->data_lock);

        g_dbus_method_invocation_return_value(invocation, NULL);
    }
    else if (g_strcmp0(method_name, "UpdateEntry") == 0 ||
             g_strcmp0(method_name, "UpdateCredential") == 0)
    {
        bool update_with_dict = (g_strcmp0(method_name, "UpdateCredential") == 0);
        const gchar *entry_id = NULL;
        const gchar *url = NULL;
        const gchar *username = NULL;
        const gchar *password = NULL;
        const gchar *title = NULL;
        const gchar *notes = NULL;
        GVariant *fields = NULL;
        bio_user_vault_t *slot = NULL;
        pm_entry_t entry;
        pm_error_t rc;

        if (update_with_dict)
        {
            g_variant_get(parameters, "(&s@a{ss})", &entry_id, &fields);
        }
        else
        {
            g_variant_get(parameters,
                          "(&s&s&s&s&s)",
                          &entry_id,
                          &url,
                          &username,
                          &password,
                          &title);
        }

        if (!entry_id || entry_id[0] == '\0')
        {
            if (fields)
            {
                g_variant_unref(fields);
            }
            g_dbus_method_invocation_return_error(
                invocation, G_DBUS_ERROR, G_DBUS_ERROR_INVALID_ARGS, "entry_id is required");
            return;
        }

        rc = ensure_user_vault_handle(d, caller_uid, &slot);
        if (rc != PM_OK)
        {
            if (fields)
            {
                g_variant_unref(fields);
            }
            g_dbus_method_invocation_return_error(
                invocation, G_DBUS_ERROR, G_DBUS_ERROR_FAILED, "Vault unavailable: %s", pm_error_str(rc));
            return;
        }

        if (!slot->handle || pm_vault_is_locked(slot->handle))
        {
            if (fields)
            {
                g_variant_unref(fields);
            }
            g_dbus_method_invocation_return_error(
                invocation, G_DBUS_ERROR, G_DBUS_ERROR_ACCESS_DENIED, "Vault is locked");
            return;
        }

        pm_entry_init(&entry);
        rc = pm_vault_entry_get(slot->handle, entry_id, &entry);
        if (rc != PM_OK)
        {
            if (fields)
            {
                g_variant_unref(fields);
            }
            g_dbus_method_invocation_return_error(
                invocation, G_DBUS_ERROR, G_DBUS_ERROR_FAILED, "Entry not found: %s", pm_error_str(rc));
            return;
        }

        if (update_with_dict && fields)
        {
            GVariantIter iter;
            const gchar *k = NULL;
            const gchar *v = NULL;

            g_variant_iter_init(&iter, fields);
            while (g_variant_iter_next(&iter, "{&s&s}", &k, &v))
            {
                if (strcasecmp(k, "url") == 0)
                {
                    url = v;
                }
                else if (strcasecmp(k, "username") == 0)
                {
                    username = v;
                }
                else if (strcasecmp(k, "password") == 0)
                {
                    password = v;
                }
                else if (strcasecmp(k, "title") == 0)
                {
                    title = v;
                }
                else if (strcasecmp(k, "notes") == 0)
                {
                    notes = v;
                }
            }

            g_variant_unref(fields);
            fields = NULL;
        }

        if (url && url[0] != '\0')
        {
            free((void *)entry.url);
            entry.url = strdup(url);
        }
        if (username)
        {
            free((void *)entry.username);
            entry.username = strdup(username);
        }
        if (password && password[0] != '\0')
        {
            free((void *)entry.password);
            entry.password = strdup(password);
        }
        if (title && title[0] != '\0')
        {
            free((void *)entry.title);
            entry.title = strdup(title);
        }
        if (notes)
        {
            free((void *)entry.notes);
            entry.notes = strdup(notes);
        }

        entry.updated_at_ms = now_epoch_ms();

        rc = pm_vault_entry_update(slot->handle, entry_id, &entry);
        pm_entry_free(&entry);

        if (rc != PM_OK)
        {
            g_dbus_method_invocation_return_error(
                invocation, G_DBUS_ERROR, G_DBUS_ERROR_FAILED, "Update failed: %s", pm_error_str(rc));
            return;
        }

        rc = pm_vault_save(slot->handle);
        if (rc != PM_OK)
        {
            g_dbus_method_invocation_return_error(
                invocation, G_DBUS_ERROR, G_DBUS_ERROR_FAILED, "Persist failed: %s", pm_error_str(rc));
            return;
        }

        pthread_mutex_lock(&d->data_lock);
        slot->unlocked_at = time(NULL);
        pthread_mutex_unlock(&d->data_lock);

        g_dbus_method_invocation_return_value(invocation, NULL);
    }

    else if (g_strcmp0(method_name, "RestoreEntryRevision") == 0)
    {
        const gchar *entry_id = NULL;
        guint32 revision_index = 0;
        bio_user_vault_t *slot = NULL;
        pm_entry_t entry;
        pm_error_t rc;
        uint64_t now_ms = now_epoch_ms();

        pm_entry_init(&entry);
        g_variant_get(parameters, "(&su)", &entry_id, &revision_index);

        if (!entry_id || entry_id[0] == '\0')
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_INVALID_ARGS,
                "entry_id is required");
            return;
        }

        rc = ensure_user_vault_handle(d, caller_uid, &slot);
        if (rc != PM_OK)
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_FAILED,
                "Vault unavailable: %s",
                pm_error_str(rc));
            return;
        }

        if (!slot->handle || pm_vault_is_locked(slot->handle))
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_ACCESS_DENIED,
                "Vault is locked");
            return;
        }

        rc = pm_vault_entry_get(slot->handle, entry_id, &entry);
        if (rc != PM_OK)
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                rc == PM_ERR_NOT_FOUND ? G_DBUS_ERROR_UNKNOWN_OBJECT : G_DBUS_ERROR_FAILED,
                "RestoreEntryRevision failed: %s",
                pm_error_str(rc));
            return;
        }

        if ((size_t)revision_index >= entry.history_count)
        {
            pm_entry_free(&entry);
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_INVALID_ARGS,
                "revision_index out of range");
            return;
        }

        rc = restore_entry_from_revision(&entry,
                                         &entry.history[revision_index],
                                         now_ms);
        if (rc != PM_OK)
        {
            pm_entry_free(&entry);
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_FAILED,
                "Revision restore build failed: %s",
                pm_error_str(rc));
            return;
        }

        rc = pm_vault_entry_update(slot->handle, entry_id, &entry);
        if (rc != PM_OK)
        {
            pm_entry_free(&entry);
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_FAILED,
                "Revision restore update failed: %s",
                pm_error_str(rc));
            return;
        }

        rc = pm_vault_save(slot->handle);
        pm_entry_free(&entry);
        if (rc != PM_OK)
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_FAILED,
                "Revision restore persist failed: %s",
                pm_error_str(rc));
            return;
        }

        pthread_mutex_lock(&d->data_lock);
        slot->unlocked_at = time(NULL);
        pthread_mutex_unlock(&d->data_lock);

        daemon_log_auth(caller_uid,
                        "entry_restore_revision",
                        "success",
                        "entry_id=%s revision_index=%u",
                        entry_id,
                        revision_index);

        g_dbus_method_invocation_return_value(
            invocation,
            g_variant_new("(b)", TRUE));
    }

    else if (g_strcmp0(method_name, "LockVault") == 0)
    {
        bio_user_vault_t *slot = NULL;
        pm_error_t rc;
        bool success = false;

        rc = ensure_user_vault_handle(d, caller_uid, &slot);
        if (rc != PM_OK)
        {
            BIO_DEBUG("LockVault: no vault handle for UID %u", caller_uid);
            /* Return success even if no vault - nothing to lock */
            success = true;
        }
        else if (!slot->handle)
        {
            BIO_DEBUG("LockVault: no vault loaded for UID %u", caller_uid);
            success = true; /* No vault loaded, nothing to lock */
        }
        else if (pm_vault_is_locked(slot->handle))
        {
            BIO_DEBUG("LockVault: vault already locked for UID %u", caller_uid);
            success = true; /* Already locked */
        }
        else
        {
            /* Lock the vault */
            rc = pm_vault_lock(slot->handle, PM_LOCK_REASON_EXPLICIT);
            if (rc == PM_OK)
            {
                BIO_INFO("Vault explicitly locked for UID %u", caller_uid);
                success = true;
                emit_vault_locked_property_changed(connection, TRUE);
                emit_vault_state_changed(d, "locked");
            }
            else
            {
                BIO_WARN("Failed to lock vault for UID %u: %s", caller_uid, pm_error_str(rc));
                success = false;
            }
        }

        g_dbus_method_invocation_return_value(
            invocation,
            g_variant_new("(b)", success));
    }

    else if (g_strcmp0(method_name, "ImportTOTP") == 0)
    {
        const gchar *qr_text = NULL;
        bio_user_vault_t *slot = NULL;
        pm_entry_t entry;
        pm_error_t rc;
        char *entry_id = NULL;

        g_variant_get(parameters, "(&s)", &qr_text);
        if (!qr_text || qr_text[0] == '\0')
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_INVALID_ARGS,
                "qr_text is required");
            return;
        }

        rc = ensure_user_vault_handle(d, caller_uid, &slot);
        if (rc != PM_OK)
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_FAILED,
                "Vault unavailable: %s",
                pm_error_str(rc));
            return;
        }

        if (!slot->handle || pm_vault_is_locked(slot->handle))
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_ACCESS_DENIED,
                "Vault is locked");
            return;
        }

        /* Import TOTP from QR code */
        pm_entry_init(&entry);
        rc = pm_otp_import_from_qr(qr_text, &entry);
        if (rc != PM_OK)
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_INVALID_ARGS,
                "Failed to parse QR code: %s",
                pm_error_str(rc));
            pm_entry_free(&entry);
            return;
        }

        /* Add entry to vault */
        rc = pm_vault_entry_add(slot->handle, &entry, true);
        if (rc != PM_OK)
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_FAILED,
                "Failed to add TOTP entry: %s",
                pm_error_str(rc));
            pm_entry_free(&entry);
            return;
        }

        rc = pm_vault_save(slot->handle);
        if (rc != PM_OK)
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_FAILED,
                "Failed to persist TOTP entry: %s",
                pm_error_str(rc));
            pm_entry_free(&entry);
            return;
        }

        /* Update vault access time */
        pthread_mutex_lock(&d->data_lock);
        slot->unlocked_at = time(NULL);
        pthread_mutex_unlock(&d->data_lock);

        BIO_INFO("TOTP entry imported from QR code for UID %u: %s", caller_uid, entry.title);

        /* Return the entry ID */
        entry_id = strdup(entry.id ? entry.id : "");
        pm_entry_free(&entry);

        g_dbus_method_invocation_return_value(
            invocation,
            g_variant_new("(s)", entry_id ? entry_id : ""));
        free(entry_id);
    }

    else if (g_strcmp0(method_name, "GetTOTPStatus") == 0 ||
             g_strcmp0(method_name, "GetTOTP") == 0)
    {
        const gchar *entry_id = NULL;
        bio_user_vault_t *slot = NULL;
        pm_entry_t entry;
        pm_error_t rc;
        char totp_code[16];
        uint32_t remaining_seconds = 0;
        const char *totp_uri = NULL;

        g_variant_get(parameters, "(&s)", &entry_id);
        if (!entry_id || entry_id[0] == '\0')
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_INVALID_ARGS,
                "entry_id is required");
            return;
        }

        rc = ensure_user_vault_handle(d, caller_uid, &slot);
        if (rc != PM_OK)
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_FAILED,
                "Vault unavailable: %s",
                pm_error_str(rc));
            return;
        }

        if (!slot->handle || pm_vault_is_locked(slot->handle))
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_ACCESS_DENIED,
                "Vault is locked");
            return;
        }

        /* Get the entry */
        pm_entry_init(&entry);
        rc = pm_vault_entry_get(slot->handle, entry_id, &entry);
        if (rc != PM_OK)
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                rc == PM_ERR_NOT_FOUND ? G_DBUS_ERROR_UNKNOWN_OBJECT : G_DBUS_ERROR_FAILED,
                "Entry not found: %s",
                pm_error_str(rc));
            return;
        }

        /* Find TOTP custom field */
        for (size_t i = 0; i < entry.custom_field_count; i++)
        {
            if (entry.custom_fields[i].type == PM_FIELD_TOTP &&
                entry.custom_fields[i].text_value)
            {
                totp_uri = entry.custom_fields[i].text_value;
                break;
            }
        }

        if (!totp_uri)
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_FAILED,
                "Entry has no TOTP field");
            pm_entry_free(&entry);
            return;
        }

        /* Get live TOTP status */
        rc = pm_otp_get_live_status(totp_uri, time(NULL), totp_code, sizeof(totp_code), &remaining_seconds);
        if (rc != PM_OK)
        {
            g_dbus_method_invocation_return_error(
                invocation,
                G_DBUS_ERROR,
                G_DBUS_ERROR_FAILED,
                "Failed to generate TOTP: %s",
                pm_error_str(rc));
            pm_entry_free(&entry);
            return;
        }

        /* Update vault access time */
        pthread_mutex_lock(&d->data_lock);
        slot->unlocked_at = time(NULL);
        pthread_mutex_unlock(&d->data_lock);

        pm_entry_free(&entry);

        g_dbus_method_invocation_return_value(
            invocation,
            g_variant_new("(su)", totp_code, remaining_seconds));
    }

    else
    {
        g_dbus_method_invocation_return_error(
            invocation,
            G_DBUS_ERROR, G_DBUS_ERROR_UNKNOWN_METHOD,
            "Unknown method: %s", method_name);
    }
}

static GVariant *handle_get_property(GDBusConnection *connection,
                                     const gchar *sender,
                                     const gchar *object_path,
                                     const gchar *interface_name,
                                     const gchar *property_name,
                                     GError **error,
                                     gpointer user_data)
{
    bio_daemon_t *d = user_data;
    uid_t caller_uid;
    bio_user_vault_t *slot = NULL;
    pm_error_t rc;
    (void)object_path;
    (void)error;

    if (!d || !sender || !interface_name || !property_name)
    {
        return NULL;
    }

    if (strcmp(interface_name, BIOAUTH_VAULT_DBUS_INTERFACE) != 0 ||
        strcmp(property_name, "Locked") != 0)
    {
        return NULL;
    }

    caller_uid = get_sender_uid(connection, sender);
    if (caller_uid == (uid_t)-1)
    {
        return g_variant_new_boolean(true);
    }

    rc = ensure_user_vault_handle(d, caller_uid, &slot);
    if (rc != PM_OK || !slot || !slot->handle)
    {
        return g_variant_new_boolean(true);
    }

    return g_variant_new_boolean(pm_vault_is_locked(slot->handle));
}

/* ── D-Bus vtable ────────────────────────────────────────────── */

static const GDBusInterfaceVTable interface_vtable = {
    .method_call = handle_method_call,
    .get_property = handle_get_property,
    .set_property = NULL,
};

/* ── Bus name acquired/lost callbacks ────────────────────────── */

static void on_name_acquired(GDBusConnection *connection,
                             const gchar *name,
                             gpointer user_data);

static void on_name_lost(GDBusConnection *connection,
                         const gchar *name,
                         gpointer user_data);

static void on_bus_acquired(GDBusConnection *connection,
                            const gchar *name,
                            gpointer user_data)
{
    bio_daemon_t *d = user_data;
    if (d->bus)
    {
        g_object_unref(d->bus);
    }
    d->bus = g_object_ref(connection);
    GError *err = NULL;
    (void)name;

    GDBusInterfaceInfo *iface =
        g_dbus_node_info_lookup_interface(d->introspection_data,
                                          BIOAUTH_DBUS_INTERFACE);
    GDBusInterfaceInfo *vault_iface =
        g_dbus_node_info_lookup_interface(d->introspection_data,
                                          BIOAUTH_VAULT_DBUS_INTERFACE);
    GDBusInterfaceInfo *auth_iface =
        g_dbus_node_info_lookup_interface(d->introspection_data,
                                          BIOAUTH_AUTH_DBUS_INTERFACE);
    GDBusInterfaceInfo *enroll_iface =
        g_dbus_node_info_lookup_interface(d->introspection_data,
                                          BIOAUTH_ENROLL_DBUS_INTERFACE);

    if (!iface || !vault_iface || !auth_iface || !enroll_iface)
    {
        BIO_ERROR("Failed to resolve D-Bus interface metadata");
        bio_daemon_stop(d);
        return;
    }

    d->registration_id = g_dbus_connection_register_object(
        connection,
        BIOAUTH_DBUS_PATH,
        iface,
        &interface_vtable,
        d, NULL, &err);

    if (d->registration_id == 0)
    {
        BIO_ERROR("Failed to register D-Bus object: %s",
                  err ? err->message : "unknown");
        if (err)
            g_error_free(err);
        bio_daemon_stop(d);
        return;
    }

    d->vault_registration_id = g_dbus_connection_register_object(
        connection,
        BIOAUTH_DBUS_PATH,
        vault_iface,
        &interface_vtable,
        d, NULL, &err);

    if (d->vault_registration_id == 0)
    {
        BIO_ERROR("Failed to register Vault D-Bus object: %s",
                  err ? err->message : "unknown");
        if (err)
            g_error_free(err);
        bio_daemon_stop(d);
        return;
    }

    d->daemon_auth_registration_id = g_dbus_connection_register_object(
        connection,
        BIOAUTH_DAEMON_DBUS_PATH,
        auth_iface,
        &interface_vtable,
        d, NULL, &err);

    if (d->daemon_auth_registration_id == 0)
    {
        BIO_ERROR("Failed to register Auth D-Bus object on %s: %s",
                  BIOAUTH_DAEMON_DBUS_PATH,
                  err ? err->message : "unknown");
        if (err)
            g_error_free(err);
        bio_daemon_stop(d);
        return;
    }

    d->daemon_vault_registration_id = g_dbus_connection_register_object(
        connection,
        BIOAUTH_DAEMON_DBUS_PATH,
        vault_iface,
        &interface_vtable,
        d, NULL, &err);

    if (d->daemon_vault_registration_id == 0)
    {
        BIO_ERROR("Failed to register Vault D-Bus object on %s: %s",
                  BIOAUTH_DAEMON_DBUS_PATH,
                  err ? err->message : "unknown");
        if (err)
            g_error_free(err);
        bio_daemon_stop(d);
        return;
    }

    d->daemon_enroll_registration_id = g_dbus_connection_register_object(
        connection,
        BIOAUTH_DAEMON_DBUS_PATH,
        enroll_iface,
        &interface_vtable,
        d, NULL, &err);

    if (d->daemon_enroll_registration_id == 0)
    {
        BIO_ERROR("Failed to register Enroll D-Bus object on %s: %s",
                  BIOAUTH_DAEMON_DBUS_PATH,
                  err ? err->message : "unknown");
        if (err)
            g_error_free(err);
        bio_daemon_stop(d);
        return;
    }

    d->vault_bus_name_id = g_bus_own_name_on_connection(
        connection,
        BIOAUTH_VAULT_DBUS_NAME,
        G_BUS_NAME_OWNER_FLAGS_NONE,
        on_name_acquired,
        on_name_lost,
        d,
        NULL);

    d->daemon_bus_name_id = g_bus_own_name_on_connection(
        connection,
        BIOAUTH_DAEMON_DBUS_NAME,
        G_BUS_NAME_OWNER_FLAGS_NONE,
        on_name_acquired,
        on_name_lost,
        d,
        NULL);

    BIO_INFO("D-Bus objects registered at %s and %s",
             BIOAUTH_DBUS_PATH,
             BIOAUTH_DAEMON_DBUS_PATH);

    /* Initialize fprintd compatibility layer — provides
     * net.reactivated.Fprint.Manager and net.reactivated.Fprint.Device
     * so that pam_fprintd.so, GDM, and KDE Settings work seamlessly. */
    memset(&d->fprintd_compat, 0, sizeof(d->fprintd_compat));
    int fpc_rc = bio_fprintd_compat_init(&d->fprintd_compat, connection, d);
    if (fpc_rc == 0)
    {
        d->fprintd_compat_active = true;
        BIO_INFO("fprintd compatibility layer active");
    }
    else
    {
        d->fprintd_compat_active = false;
        BIO_WARN("fprintd compatibility layer failed (rc=%d) — "
                 "pam_fprintd.so will not work",
                 fpc_rc);
    }

    /* If fingerprint device is already available, emit DeviceAdded */
    if (d->fp_dev)
    {
        bio_fp_device_info_t dev_info;
        if (bio_fp_get_device_info(d->fp_dev, &dev_info) == BIO_OK)
        {
            emit_device_added(d, dev_info.name);
        }
    }
}

static void on_name_acquired(GDBusConnection *connection,
                             const gchar *name,
                             gpointer user_data)
{
    bio_daemon_t *d = user_data;
    (void)connection;

    if (d)
    {
        if (g_strcmp0(name, BIOAUTH_DBUS_NAME) == 0)
        {
            d->bus_name_owned = true;
        }
        else if (g_strcmp0(name, BIOAUTH_VAULT_DBUS_NAME) == 0)
        {
            d->vault_bus_name_owned = true;
        }
        else if (g_strcmp0(name, BIOAUTH_DAEMON_DBUS_NAME) == 0)
        {
            d->daemon_bus_name_owned = true;
        }
    }

    BIO_INFO("Acquired D-Bus name: %s", name);
}

static void on_name_lost(GDBusConnection *connection,
                         const gchar *name,
                         gpointer user_data)
{
    bio_daemon_t *d = user_data;
    (void)connection;

    if (d)
    {
        if (g_strcmp0(name, BIOAUTH_DBUS_NAME) == 0)
        {
            d->bus_name_owned = false;
        }
        else if (g_strcmp0(name, BIOAUTH_VAULT_DBUS_NAME) == 0)
        {
            d->vault_bus_name_owned = false;
        }
        else if (g_strcmp0(name, BIOAUTH_DAEMON_DBUS_NAME) == 0)
        {
            d->daemon_bus_name_owned = false;
        }
    }

    BIO_ERROR("Lost D-Bus name: %s, another instance running?", name);
    bio_daemon_stop(d);
}

/* ── Signal handling ─────────────────────────────────────────── */

static bio_daemon_t *g_daemon_instance = NULL;
static volatile sig_atomic_t g_signal_stop_requested = 0;
static volatile sig_atomic_t g_signal_reload_requested = 0;

static void signal_handler(int sig)
{
    if (sig == SIGHUP)
    {
        g_signal_reload_requested = 1;
    }
    else
    {
        g_signal_stop_requested = 1;
    }
}

static void reload_daemon_config(bio_daemon_t *d)
{
    if (!d)
        return;

    const char *path = d->config.config_file[0]
                           ? d->config.config_file
                           : BIOAUTH_CONFIG_FILE;

    bio_daemon_config_t next;
    bio_daemon_config_defaults(&next);
    if (bio_daemon_config_load(path, &next) != BIO_OK)
    {
        BIO_WARN("SIGHUP reload failed: unable to load %s", path);
        return;
    }

    if (strcmp(next.state_dir, d->config.state_dir) != 0 ||
        next.tpm_enabled != d->config.tpm_enabled ||
        strcmp(next.tpm_device, d->config.tpm_device) != 0 ||
        next.tpm_primary_handle != d->config.tpm_primary_handle)
    {
        BIO_WARN("SIGHUP reload applied runtime-safe options only; "
                 "TPM/state path changes require daemon restart");
    }

    pthread_mutex_lock(&d->data_lock);
    d->config.max_sessions = next.max_sessions;
    d->config.session_max_age_seconds = next.session_max_age_seconds;
    d->config.max_enrollments_per_user = next.max_enrollments_per_user;
    d->config.rate_limit_max_attempts = next.rate_limit_max_attempts;
    d->config.rate_limit_lockout_seconds = next.rate_limit_lockout_seconds;
    d->config.rate_limit_window_seconds = next.rate_limit_window_seconds;
    d->config.tpm_fallback_to_plaintext = next.tpm_fallback_to_plaintext;
    d->config.tpm_require = next.tpm_require;
    d->config.tpm_pcr_binding = next.tpm_pcr_binding;
    d->config.tpm_pcr_index = next.tpm_pcr_index;
    strncpy(d->config.howdy_binary,
            next.howdy_binary,
            sizeof(d->config.howdy_binary) - 1);
    d->config.howdy_binary[sizeof(d->config.howdy_binary) - 1] = '\0';
    d->config.vault_idle_timeout_seconds = next.vault_idle_timeout_seconds;
    d->config.log_to_journal = next.log_to_journal;
    d->config.log_level = next.log_level;
    prune_sessions_to_capacity(d);
    pthread_mutex_unlock(&d->data_lock);

    bio_log_set_level((bio_log_level_t)d->config.log_level);
    BIO_INFO("Reloaded daemon configuration from %s", path);
}

static gboolean check_signal_flag(gpointer user_data)
{
    (void)user_data;

    if (g_signal_reload_requested && g_daemon_instance)
    {
        g_signal_reload_requested = 0;
        BIO_INFO("SIGHUP received, reloading daemon configuration");
        reload_daemon_config(g_daemon_instance);
    }

    if (g_signal_stop_requested && g_daemon_instance)
    {
        BIO_INFO("Shutdown signal received, stopping daemon");
        bio_daemon_stop(g_daemon_instance);
        return G_SOURCE_REMOVE;
    }
    return G_SOURCE_CONTINUE;
}

/* ── systemd journal logging callback ────────────────────────── */

static void journal_log(bio_log_level_t level,
                        const char *file, int line,
                        const char *func,
                        const char *fmt, ...)
{
    int priority;
    switch (level)
    {
    case BIO_LOG_ERROR:
        priority = LOG_ERR;
        break;
    case BIO_LOG_WARNING:
        priority = LOG_WARNING;
        break;
    case BIO_LOG_INFO:
        priority = LOG_INFO;
        break;
    case BIO_LOG_DEBUG:
        priority = LOG_DEBUG;
        break;
    case BIO_LOG_TRACE:
        priority = LOG_DEBUG;
        break;
    default:
        priority = LOG_INFO;
        break;
    }

    va_list ap;
    va_start(ap, fmt);
    char msg[1024];
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    sd_journal_print(priority, "[%s:%d] %s(): %s",
                     file, line, func, msg);
}

/* ── Lifecycle ────────────────────────────────────────────────── */

int bio_daemon_create(bio_daemon_t **daemon_out)
{
    if (!daemon_out)
        return BIO_ERR_INVALID_PARAM;

    bio_daemon_t *d = calloc(1, sizeof(*d));
    if (!d)
        return BIO_ERR_NOMEM;

    pthread_mutex_init(&d->data_lock, NULL);
    pthread_mutex_init(&d->fp_lock, NULL);
    d->shutting_down = false;

    /* Set up journal logging */
    bio_log_set_callback(journal_log);
    bio_log_set_level(BIO_LOG_DEBUG);

    /* Load configuration */
    bio_daemon_config_defaults(&d->config);
    const char *config_path = (g_startup_config_path && g_startup_config_path[0])
                                  ? g_startup_config_path
                                  : BIOAUTH_CONFIG_FILE;
    bio_daemon_config_load(config_path, &d->config);

    if (g_startup_force_no_tpm)
        d->config.tpm_enabled = false;
    if (g_startup_force_debug)
        d->config.log_level = BIO_LOG_DEBUG;

    bio_log_set_level((bio_log_level_t)d->config.log_level);

    /* Initialize crypto */
    int rc = bio_crypto_init();
    if (rc != BIO_OK)
    {
        BIO_ERROR("Crypto init failed: %s", bio_error_str(rc));
        pthread_mutex_destroy(&d->data_lock);
        pthread_mutex_destroy(&d->fp_lock);
        free(d);
        return rc;
    }

    /* Ensure state directory exists */
    rc = ensure_state_dir(d->config.state_dir);
    if (rc != BIO_OK)
    {
        BIO_ERROR("State directory setup failed: %s", bio_error_str(rc));
        bio_crypto_cleanup();
        pthread_mutex_destroy(&d->data_lock);
        pthread_mutex_destroy(&d->fp_lock);
        free(d);
        return rc;
    }

    /* Load persistent enrollments */
    rc = bio_daemon_load_enrollments(d->config.state_dir,
                                     &d->enrollments,
                                     &d->enrollment_count);
    if (rc != BIO_OK)
    {
        BIO_WARN("Failed to load enrollments: %s", bio_error_str(rc));
    }
    /* Ensure capacity is at least 16 and uses same doubling strategy
     * as bio_daemon_load_enrollments */
    {
        size_t cap = 16;
        while (cap < d->enrollment_count)
            cap *= 2;
        d->enrollment_capacity = cap;
        /* Ensure the enrollments array is actually allocated */
        if (!d->enrollments)
        {
            d->enrollments = calloc(cap, sizeof(bio_enrollment_t));
            if (!d->enrollments)
            {
                BIO_ERROR("Failed to allocate enrollment array");
                d->enrollment_capacity = 0;
            }
        }
    }

    /* Initialize fingerprint subsystem */
    rc = bio_fp_init(&d->fp_ctx);
    if (rc != BIO_OK)
    {
        BIO_ERROR("Fingerprint init failed: %s", bio_error_str(rc));
    }

    /* Try to open fingerprint device */
    if (d->fp_ctx)
    {
        rc = bio_fp_open_device(d->fp_ctx, &d->fp_dev);
        if (rc != BIO_OK)
        {
            BIO_WARN("No fingerprint device available: %s",
                     bio_error_str(rc));
            d->fp_dev = NULL;
        }
    }

    /* Initialize TPM */
    if (d->config.tpm_enabled)
    {
        rc = bio_tpm_init(&d->tpm_ctx, d->config.tpm_device);
        if (rc == BIO_OK)
        {
            int hrc = bio_tpm_set_primary_handle(&d->tpm_ctx,
                                                 d->config.tpm_primary_handle);
            if (hrc != BIO_OK)
            {
                BIO_WARN("Invalid TPM primary handle configured (0x%08X), "
                         "using default 0x%08X",
                         d->config.tpm_primary_handle,
                         BIOAUTH_TPM_PRIMARY_HANDLE);
                bio_tpm_set_primary_handle(&d->tpm_ctx,
                                           BIOAUTH_TPM_PRIMARY_HANDLE);
            }
            d->tpm_available = true;
            BIO_INFO("TPM 2.0 available and initialized");
        }
        else
        {
            d->tpm_available = false;
            BIO_WARN("TPM 2.0 not available: %s", bio_error_str(rc));
        }
    }
    else
    {
        d->tpm_available = false;
        BIO_INFO("TPM disabled by configuration");
    }

    /* Parse D-Bus introspection XML */
    GError *err = NULL;
    d->introspection_data = g_dbus_node_info_new_for_xml(
        introspection_xml, &err);
    if (!d->introspection_data || err)
    {
        BIO_ERROR("Failed to parse D-Bus introspection: %s",
                  err ? err->message : "unknown");
        if (err)
            g_error_free(err);
        bio_daemon_destroy(d);
        return BIO_ERR_INTERNAL;
    }

    /* Create main loop */
    d->main_loop = g_main_loop_new(NULL, FALSE);

    *daemon_out = d;
    BIO_INFO("BioAuth daemon created");
    return BIO_OK;
}

/* ── Proactive session sweep ─────────────────────────────────── */

static gboolean sweep_expired_sessions(gpointer user_data)
{
    bio_daemon_t *d = user_data;
    if (!d)
        return G_SOURCE_REMOVE;

    time_t now = time(NULL);
    int swept = 0;
    int cap = session_capacity(d);

    pthread_mutex_lock(&d->data_lock);
    for (int i = 0; i < cap; i++)
    {
        if (!d->sessions[i].active)
            continue;
        if (now - d->sessions[i].created >
            d->config.session_max_age_seconds)
        {
            bio_secure_wipe(d->sessions[i].session_key, 32);
            bio_munlock_sensitive(d->sessions[i].session_key, 32);
            d->sessions[i].active = false;
            if (d->session_count > 0)
                d->session_count--;
            swept++;
        }
    }
    pthread_mutex_unlock(&d->data_lock);

    if (swept > 0)
        BIO_DEBUG("Session sweep: cleaned %d expired sessions", swept);

    return G_SOURCE_CONTINUE;
}

int bio_daemon_run(bio_daemon_t *d)
{
    if (!d)
        return BIO_ERR_INVALID_PARAM;

    GDBusConnection *system_bus = NULL;
    GError *bus_err = NULL;

    /* Install signal handlers */
    g_daemon_instance = d;
    {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = signal_handler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0; /* No SA_RESTART — allow main loop to notice */
        sigaction(SIGINT, &sa, NULL);
        sigaction(SIGTERM, &sa, NULL);
        sigaction(SIGHUP, &sa, NULL);
    }

    /* Own the D-Bus name */
    d->bus_name_id = g_bus_own_name(
        G_BUS_TYPE_SYSTEM,
        BIOAUTH_DBUS_NAME,
        G_BUS_NAME_OWNER_FLAGS_NONE,
        on_bus_acquired,
        on_name_acquired,
        on_name_lost,
        d, NULL);

    system_bus = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &bus_err);
    if (!system_bus)
    {
        BIO_WARN("Failed to connect to system bus for lock/suspend subscriptions: %s",
                 bus_err ? bus_err->message : "unknown");
        if (bus_err)
        {
            g_error_free(bus_err);
            bus_err = NULL;
        }
        d->session_lock_subscription_id = 0;
        d->sleep_subscription_id = 0;
    }
    else
    {
        /* Subscribe to systemd-logind session lock signals */
        d->session_lock_subscription_id = g_dbus_connection_signal_subscribe(
            system_bus,
            "org.freedesktop.login1",
            "org.freedesktop.login1.Session",
            NULL, /* Subscribe to all signals */
            NULL, /* Any object path */
            NULL, /* Any argument0 */
            G_DBUS_SIGNAL_FLAGS_NONE,
            handle_session_lock_signal,
            d,
            NULL);

        /* Also subscribe to PrepareForSleep signals for lid close detection */
        d->sleep_subscription_id = g_dbus_connection_signal_subscribe(
            system_bus,
            "org.freedesktop.login1",
            "org.freedesktop.login1.Manager",
            "PrepareForSleep",
            "/org/freedesktop/login1",
            NULL, /* Any argument0 */
            G_DBUS_SIGNAL_FLAGS_NONE,
            handle_session_lock_signal,
            d,
            NULL);
    }

    if (system_bus && d->session_lock_subscription_id > 0 && d->sleep_subscription_id > 0)
    {
        BIO_INFO("Subscribed to session lock and suspend signals");
    }
    else
    {
        BIO_WARN("Failed to subscribe to session lock/suspend signals");
    }

    BIO_INFO("Starting main loop...");

    /* Poll for signal flag from GLib main loop (async-signal-safe) */
    guint signal_check_id = g_timeout_add(200, check_signal_flag, NULL);

    /* Sweep expired sessions every 60 seconds */
    guint session_sweep_id = g_timeout_add_seconds(60,
                                                   sweep_expired_sessions, d);

    /* Check for idle vaults every 5 minutes */
    d->vault_idle_timer_id = 0;
    if (d->config.vault_idle_timeout_seconds > 0)
    {
        d->vault_idle_timer_id = g_timeout_add_seconds(300, /* 5 minutes */
                                                       check_vault_idle_timeout, d);
        BIO_INFO("Vault idle timeout enabled: %d seconds", d->config.vault_idle_timeout_seconds);
    }

    g_main_loop_run(d->main_loop);

    g_source_remove(session_sweep_id);
    g_source_remove(signal_check_id);
    if (d->vault_idle_timer_id != 0)
    {
        g_source_remove(d->vault_idle_timer_id);
    }
    if (system_bus && d->session_lock_subscription_id != 0)
    {
        g_dbus_connection_signal_unsubscribe(system_bus, d->session_lock_subscription_id);
    }
    if (system_bus && d->sleep_subscription_id != 0)
    {
        g_dbus_connection_signal_unsubscribe(system_bus, d->sleep_subscription_id);
    }
    if (system_bus)
    {
        g_object_unref(system_bus);
        system_bus = NULL;
    }

    /* Cleanup name ownership */
    if (d->vault_bus_name_id != 0 && d->vault_bus_name_owned)
    {
        g_bus_unown_name(d->vault_bus_name_id);
    }
    d->vault_bus_name_id = 0;
    d->vault_bus_name_owned = false;

    if (d->daemon_bus_name_id != 0 && d->daemon_bus_name_owned)
    {
        g_bus_unown_name(d->daemon_bus_name_id);
    }
    d->daemon_bus_name_id = 0;
    d->daemon_bus_name_owned = false;

    if (d->bus_name_id != 0 && d->bus_name_owned)
    {
        g_bus_unown_name(d->bus_name_id);
    }
    d->bus_name_id = 0;
    d->bus_name_owned = false;

    BIO_INFO("BioAuth daemon stopped");
    return BIO_OK;
}

void bio_daemon_stop(bio_daemon_t *d)
{
    if (!d)
        return;
    d->should_stop = true;
    if (d->main_loop)
    {
        g_main_loop_quit(d->main_loop);
    }
}

void bio_daemon_destroy(bio_daemon_t *d)
{
    if (!d)
        return;

    /* Shutdown fprintd compat layer first (releases bus name) */
    if (d->fprintd_compat_active)
    {
        bio_fprintd_compat_cleanup(&d->fprintd_compat);
        d->fprintd_compat_active = false;
    }

    /* Signal shutdown to reject new fp/tpm operations, then wait for
     * any in-flight operation to finish by acquiring fp_lock. */
    d->shutting_down = true;
    pthread_mutex_lock(&d->fp_lock);
    pthread_mutex_unlock(&d->fp_lock);

    /* Emit device removal signal before closing */
    if (d->fp_dev)
    {
        bio_fp_device_info_t info;
        if (bio_fp_get_device_info(d->fp_dev, &info) == BIO_OK)
        {
            emit_device_removed(d, info.name);
        }
    }

    if (d->fp_dev)
    {
        bio_fp_close_device(d->fp_dev);
        d->fp_dev = NULL;
    }

    if (d->fp_ctx)
    {
        bio_fp_cleanup(d->fp_ctx);
        d->fp_ctx = NULL;
    }

    if (d->tpm_available)
    {
        bio_tpm_cleanup(&d->tpm_ctx);
    }

    for (size_t i = 0; i < BIO_MAX_VAULTS; i++)
    {
        close_user_vault_slot(&d->vaults[i]);
    }

    if (d->bus && G_IS_DBUS_CONNECTION(d->bus) && d->registration_id != 0)
    {
        g_dbus_connection_unregister_object(d->bus, d->registration_id);
    }

    if (d->bus && G_IS_DBUS_CONNECTION(d->bus) && d->vault_registration_id != 0)
    {
        g_dbus_connection_unregister_object(d->bus, d->vault_registration_id);
    }

    if (d->bus && G_IS_DBUS_CONNECTION(d->bus) && d->daemon_auth_registration_id != 0)
    {
        g_dbus_connection_unregister_object(d->bus, d->daemon_auth_registration_id);
    }

    if (d->bus && G_IS_DBUS_CONNECTION(d->bus) && d->daemon_vault_registration_id != 0)
    {
        g_dbus_connection_unregister_object(d->bus, d->daemon_vault_registration_id);
    }

    if (d->bus && G_IS_DBUS_CONNECTION(d->bus) && d->daemon_enroll_registration_id != 0)
    {
        g_dbus_connection_unregister_object(d->bus, d->daemon_enroll_registration_id);
    }

    if (d->bus)
    {
        g_object_unref(d->bus);
        d->bus = NULL;
    }

    if (d->introspection_data)
    {
        g_dbus_node_info_unref(d->introspection_data);
    }

    if (d->main_loop)
    {
        g_main_loop_unref(d->main_loop);
    }

    /* Securely wipe sessions (including session keys) —
     * munlock ALL sessions, not just active ones, in case some
     * expired sessions still have locked pages. */
    for (int i = 0; i < BIO_MAX_SESSIONS; i++)
    {
        bio_munlock_sensitive(d->sessions[i].session_key, 32);
    }
    bio_secure_wipe(d->sessions, sizeof(d->sessions));

    /* Securely wipe rate limiter state */
    bio_secure_wipe(d->rate_limiters, sizeof(d->rate_limiters));

    /* Securely wipe enrollments */
    if (d->enrollments)
    {
        bio_secure_wipe(d->enrollments,
                        d->enrollment_count * sizeof(bio_enrollment_t));
        free(d->enrollments);
    }

    bio_crypto_cleanup();

    pthread_mutex_destroy(&d->data_lock);
    pthread_mutex_destroy(&d->fp_lock);

    free(d);
    g_daemon_instance = NULL;
}

/* ── Internal API for fprintd compatibility layer ────────────── */

int bio_daemon_verify_user(bio_daemon_t *daemon, const char *user)
{
    if (!daemon || !user)
        return BIO_ERR_INVALID_PARAM;

    /* Look up user UID (thread-safe) */
    struct passwd pw_buf;
    char pw_strbuf[512];
    struct passwd *pw = NULL;
    if (getpwnam_r(user, &pw_buf, pw_strbuf, sizeof(pw_strbuf), &pw) != 0 || !pw)
    {
        BIO_WARN("verify_user: unknown user '%s'", user);
        return BIO_ERR_NOT_FOUND;
    }
    uid_t uid = pw->pw_uid;

    pthread_mutex_lock(&daemon->data_lock);

    /* H4 fix: Apply rate limiting (was missing in fprintd-compat path) */
    int lockout_remaining = 0;
    if (check_verify_rate_limit(daemon, uid, &lockout_remaining) != BIO_OK)
    {
        pthread_mutex_unlock(&daemon->data_lock);
        BIO_WARN("verify_user: rate limited for '%s' (%ds remaining)",
                 user, lockout_remaining);
        daemon_log_auth(uid, "verify", "rate_limited",
                        "fprintd-compat locked %ds", lockout_remaining);
        return BIO_ERR_FP_RATE_LIMIT;
    }

    /* Collect ALL enrollments for this user (copy data under lock) */
    typedef struct
    {
        uint8_t print_data[BIO_MAX_PRINT_DATA_SIZE];
        size_t print_data_len;
        uint8_t sealed_blob[1024];
        size_t sealed_blob_len;
    } local_enrollment_t;

    size_t user_enrollment_count = 0;
    for (size_t i = 0; i < daemon->enrollment_count; i++)
    {
        if (daemon->enrollments[i].uid == uid)
            user_enrollment_count++;
    }

    if (user_enrollment_count == 0)
    {
        pthread_mutex_unlock(&daemon->data_lock);
        BIO_INFO("verify_user: no enrollments for '%s' (uid=%u)",
                 user, (unsigned)uid);
        return BIO_ERR_NOT_FOUND;
    }

    /* Allocate local copies so we can release the lock during verification */
    local_enrollment_t *locals = calloc(user_enrollment_count, sizeof(*locals));
    if (!locals)
    {
        pthread_mutex_unlock(&daemon->data_lock);
        return BIO_ERR_NOMEM;
    }

    size_t idx = 0;
    for (size_t i = 0; i < daemon->enrollment_count && idx < user_enrollment_count; i++)
    {
        if (daemon->enrollments[i].uid == uid)
        {
            const bio_enrollment_t *e = &daemon->enrollments[i];
            memcpy(locals[idx].print_data, e->print_data, e->print_data_len);
            locals[idx].print_data_len = e->print_data_len;
            memcpy(locals[idx].sealed_blob, e->sealed_blob, e->sealed_blob_len);
            locals[idx].sealed_blob_len = e->sealed_blob_len;
            idx++;
        }
    }
    bool tpm_avail = daemon->tpm_available;
    bool tpm_fallback = daemon->config.tpm_fallback_to_plaintext;
    bool tpm_require = daemon->config.tpm_require;

    pthread_mutex_unlock(&daemon->data_lock);

    /* Perform fingerprint verification via libfprint */
    if (!daemon->fp_dev)
    {
        bio_secure_wipe(locals, user_enrollment_count * sizeof(*locals));
        free(locals);
        BIO_ERROR("verify_user: no fingerprint device available");
        return BIO_ERR_IO;
    }

    /* Try each enrolled finger — serialize fp/tpm device access */
    pthread_mutex_lock(&daemon->fp_lock);
    if (daemon->shutting_down)
    {
        pthread_mutex_unlock(&daemon->fp_lock);
        bio_secure_wipe(locals, user_enrollment_count * sizeof(*locals));
        free(locals);
        return BIO_ERR_IO;
    }

    int rc = BIO_ERR_FP_NO_MATCH;
    bool policy_denied = false;
    for (size_t i = 0; i < user_enrollment_count; i++)
    {
        const uint8_t *print_data = locals[i].print_data;
        size_t print_len = locals[i].print_data_len;
        uint8_t unsealed[BIO_MAX_PRINT_DATA_SIZE];
        size_t unsealed_len = sizeof(unsealed);

        if (locals[i].sealed_blob_len > 0)
        {
            if (!tpm_avail)
            {
                if (tpm_require)
                {
                    policy_denied = true;
                    BIO_ERROR("verify_user: TPM required by policy but unavailable");
                    continue;
                }
            }
            else
            {
                int trc = daemon_tpm_unseal_template(daemon,
                                                     locals[i].sealed_blob,
                                                     locals[i].sealed_blob_len,
                                                     unsealed,
                                                     &unsealed_len);
                if (trc == BIO_OK && unsealed_len > 0)
                {
                    print_data = unsealed;
                    print_len = unsealed_len;
                }
                else if (tpm_fallback && !tpm_require)
                {
                    BIO_WARN("verify_user: TPM unseal failed, "
                             "falling back (tpm_fallback_to_plaintext=true)");
                }
                else
                {
                    policy_denied = true;
                    BIO_ERROR("verify_user: TPM unseal failed, "
                              "plaintext fallback DENIED");
                    bio_secure_wipe(unsealed, sizeof(unsealed));
                    continue; /* Try next enrollment */
                }
            }
        }
        else if (tpm_require)
        {
            policy_denied = true;
            BIO_ERROR("verify_user: TPM required by policy but enrollment has no sealed blob");
            continue;
        }

        int vrc = bio_fp_verify(daemon->fp_dev,
                                print_data, print_len,
                                NULL, NULL,
                                0); /* 0 = use default timeout */
        bio_secure_wipe(unsealed, sizeof(unsealed));

        if (vrc == BIO_OK)
        {
            rc = BIO_OK;
            break;
        }
    }
    pthread_mutex_unlock(&daemon->fp_lock);

    bio_secure_wipe(locals, user_enrollment_count * sizeof(*locals));
    free(locals);

    if (policy_denied && rc != BIO_OK)
    {
        daemon_log_auth(uid, "verify", "denied",
                        "fprintd-compat require_tpm policy denied plaintext fallback");
        return BIO_ERR_PERMISSION;
    }

    pthread_mutex_lock(&daemon->data_lock);
    if (rc == BIO_OK)
    {
        reset_verify_rate_limit(daemon, uid); /* H4 fix: reset on success */
        pthread_mutex_unlock(&daemon->data_lock);
        daemon_log_auth(uid, "verify", "success",
                        "fprintd-compat verify");
        return BIO_OK;
    }

    record_verify_failure(daemon, uid); /* H4 fix: record failure */
    pthread_mutex_unlock(&daemon->data_lock);
    daemon_log_auth(uid, "verify", "failure",
                    "fprintd-compat verify no-match");
    return BIO_ERR_FP_NO_MATCH;
}

int bio_daemon_enroll_user(bio_daemon_t *daemon, const char *user,
                           const char *finger)
{
    if (!daemon || !user || !finger)
        return BIO_ERR_INVALID_PARAM;

    struct passwd pw_buf;
    char pw_strbuf[512];
    struct passwd *pw = NULL;
    if (getpwnam_r(user, &pw_buf, pw_strbuf, sizeof(pw_strbuf), &pw) != 0 || !pw)
        return BIO_ERR_NOT_FOUND;
    uid_t uid = pw->pw_uid;

    if (!daemon->fp_dev)
    {
        BIO_ERROR("enroll_user: no fingerprint device available");
        return BIO_ERR_IO;
    }

    /* Map finger name to enum */
    bio_finger_t finger_id = BIO_FINGER_RIGHT_INDEX;
    if (strcmp(finger, "left-thumb") == 0)
        finger_id = BIO_FINGER_LEFT_THUMB;
    else if (strcmp(finger, "left-index-finger") == 0)
        finger_id = BIO_FINGER_LEFT_INDEX;
    else if (strcmp(finger, "left-middle-finger") == 0)
        finger_id = BIO_FINGER_LEFT_MIDDLE;
    else if (strcmp(finger, "left-ring-finger") == 0)
        finger_id = BIO_FINGER_LEFT_RING;
    else if (strcmp(finger, "left-little-finger") == 0)
        finger_id = BIO_FINGER_LEFT_LITTLE;
    else if (strcmp(finger, "right-thumb") == 0)
        finger_id = BIO_FINGER_RIGHT_THUMB;
    else if (strcmp(finger, "right-index-finger") == 0)
        finger_id = BIO_FINGER_RIGHT_INDEX;
    else if (strcmp(finger, "right-middle-finger") == 0)
        finger_id = BIO_FINGER_RIGHT_MIDDLE;
    else if (strcmp(finger, "right-ring-finger") == 0)
        finger_id = BIO_FINGER_RIGHT_RING;
    else if (strcmp(finger, "right-little-finger") == 0)
        finger_id = BIO_FINGER_RIGHT_LITTLE;

    /* Check capacity */
    pthread_mutex_lock(&daemon->data_lock);
    int user_count = 0;
    bool tpm_require = daemon->config.tpm_require;
    bool tpm_avail = daemon->tpm_available;
    for (size_t i = 0; i < daemon->enrollment_count; i++)
    {
        if (daemon->enrollments[i].uid == uid)
            user_count++;
    }
    if (user_count >= daemon->config.max_enrollments_per_user)
    {
        pthread_mutex_unlock(&daemon->data_lock);
        BIO_WARN("enroll_user: max enrollments reached for '%s'", user);
        return BIO_ERR_ALREADY_EXISTS;
    }

    if (tpm_require && !tpm_avail)
    {
        pthread_mutex_unlock(&daemon->data_lock);
        BIO_ERROR("enroll_user: TPM required by policy but unavailable");
        return BIO_ERR_PERMISSION;
    }
    pthread_mutex_unlock(&daemon->data_lock);

    /* Perform enrollment via libfprint — serialize device access */
    uint8_t print_data[BIO_MAX_PRINT_DATA_SIZE];
    size_t print_len = sizeof(print_data);

    pthread_mutex_lock(&daemon->fp_lock);
    if (daemon->shutting_down)
    {
        pthread_mutex_unlock(&daemon->fp_lock);
        return BIO_ERR_IO;
    }
    int rc = bio_fp_enroll(daemon->fp_dev, finger_id,
                           NULL, NULL,
                           print_data, &print_len);
    pthread_mutex_unlock(&daemon->fp_lock);

    if (rc != BIO_OK)
    {
        BIO_WARN("enroll_user: enrollment failed (rc=%d)", rc);
        return rc;
    }

    /* Grow enrollment array if needed */
    pthread_mutex_lock(&daemon->data_lock);

    /* TOCTOU re-check: capacity may have changed while we were enrolling */
    user_count = 0;
    for (size_t i = 0; i < daemon->enrollment_count; i++)
    {
        if (daemon->enrollments[i].uid == uid)
            user_count++;
    }
    if (user_count >= daemon->config.max_enrollments_per_user)
    {
        pthread_mutex_unlock(&daemon->data_lock);
        bio_secure_wipe(print_data, sizeof(print_data));
        BIO_WARN("enroll_user: max enrollments reached for '%s' (post-enroll check)", user);
        return BIO_ERR_ALREADY_EXISTS;
    }

    if (daemon->enrollment_count >= daemon->enrollment_capacity)
    {
        size_t new_cap = daemon->enrollment_capacity ? daemon->enrollment_capacity * 2 : 16;
        bio_enrollment_t *new_arr = realloc(daemon->enrollments,
                                            new_cap * sizeof(bio_enrollment_t));
        if (!new_arr)
        {
            pthread_mutex_unlock(&daemon->data_lock);
            return BIO_ERR_NOMEM;
        }
        daemon->enrollments = new_arr;
        daemon->enrollment_capacity = new_cap;
    }

    /* Store enrollment */
    bio_enrollment_t *e = &daemon->enrollments[daemon->enrollment_count];
    memset(e, 0, sizeof(*e));
    e->uid = uid;
    e->finger = finger_id;
    memcpy(e->print_data, print_data, print_len);
    e->print_data_len = print_len;
    strncpy(e->label, finger, sizeof(e->label) - 1);
    e->created = time(NULL);

    /* Seal to TPM if available — serialize device access */
    if (daemon->tpm_available)
    {
        e->sealed_blob_len = sizeof(e->sealed_blob);
        pthread_mutex_lock(&daemon->fp_lock);
        rc = daemon_tpm_seal_template(daemon,
                                      print_data,
                                      print_len,
                                      e->sealed_blob,
                                      &e->sealed_blob_len);
        pthread_mutex_unlock(&daemon->fp_lock);
        if (rc != BIO_OK)
        {
            if (tpm_require)
            {
                bio_secure_wipe(e, sizeof(*e));
                pthread_mutex_unlock(&daemon->data_lock);
                bio_secure_wipe(print_data, sizeof(print_data));
                BIO_ERROR("enroll_user: TPM required by policy and seal failed");
                return BIO_ERR_PERMISSION;
            }
            BIO_WARN("enroll_user: TPM seal failed, storing software-only");
            e->sealed_blob_len = 0;
        }
    }

    daemon->enrollment_count++;

    /* Persist */
    bio_daemon_save_enrollments(daemon->config.state_dir,
                                daemon->enrollments,
                                daemon->enrollment_count);
    pthread_mutex_unlock(&daemon->data_lock);

    /* Wipe sensitive data from stack */
    bio_secure_wipe(print_data, sizeof(print_data));

    daemon_log_auth(uid, "enroll", "success",
                    "fprintd-compat enroll %s", finger);
    BIO_INFO("enroll_user: enrolled %s for '%s'", finger, user);
    return BIO_OK;
}

int bio_daemon_delete_enrollments(bio_daemon_t *daemon, const char *user)
{
    if (!daemon || !user)
        return BIO_ERR_INVALID_PARAM;

    struct passwd pw_buf;
    char pw_strbuf[512];
    struct passwd *pw = NULL;
    if (getpwnam_r(user, &pw_buf, pw_strbuf, sizeof(pw_strbuf), &pw) != 0 || !pw)
        return BIO_ERR_NOT_FOUND;
    uid_t uid = pw->pw_uid;

    /* Remove all enrollments for this user */
    pthread_mutex_lock(&daemon->data_lock);
    size_t write_idx = 0;
    for (size_t i = 0; i < daemon->enrollment_count; i++)
    {
        if (daemon->enrollments[i].uid == uid)
        {
            /* Wipe the removed enrollment */
            bio_secure_wipe(&daemon->enrollments[i],
                            sizeof(bio_enrollment_t));
        }
        else
        {
            if (write_idx != i)
            {
                daemon->enrollments[write_idx] = daemon->enrollments[i];
            }
            write_idx++;
        }
    }
    daemon->enrollment_count = write_idx;

    /* Persist */
    bio_daemon_save_enrollments(daemon->config.state_dir,
                                daemon->enrollments,
                                daemon->enrollment_count);
    pthread_mutex_unlock(&daemon->data_lock);

    /* Also clear fingerprints from on-device storage (MOC sensors
     * like Goodix store templates on-chip; without this the sensor
     * rejects re-enrollment with "finger already enrolled"). */
    if (daemon->fp_dev)
    {
        int fp_rc = bio_fp_delete_all_prints(daemon->fp_dev);
        if (fp_rc != BIO_OK)
        {
            BIO_WARN("delete_enrollments: failed to clear device storage "
                     "(rc=%d) — prints may remain on sensor",
                     fp_rc);
        }
    }

    daemon_log_auth(uid, "delete-all-enrollments", "success",
                    "fprintd-compat delete-all for %s", user);
    BIO_INFO("delete_enrollments: removed all enrollments for '%s'", user);
    return BIO_OK;
}

struct bio_fp_ctx *bio_daemon_get_fp_ctx(bio_daemon_t *daemon)
{
    return daemon ? daemon->fp_ctx : NULL;
}

int bio_daemon_list_enrolled_fingers(bio_daemon_t *daemon, const char *user,
                                     bio_finger_t *fingers, int max_fingers)
{
    if (!daemon || !user || !fingers || max_fingers <= 0)
        return -EINVAL;

    struct passwd pw_buf;
    char pw_strbuf[512];
    struct passwd *pw = NULL;
    if (getpwnam_r(user, &pw_buf, pw_strbuf, sizeof(pw_strbuf), &pw) != 0 || !pw)
        return -ENOENT;
    uid_t uid = pw->pw_uid;

    pthread_mutex_lock(&daemon->data_lock);
    int count = 0;
    for (size_t i = 0; i < daemon->enrollment_count && count < max_fingers; i++)
    {
        if (daemon->enrollments[i].uid == uid)
        {
            fingers[count++] = daemon->enrollments[i].finger;
        }
    }
    pthread_mutex_unlock(&daemon->data_lock);
    return count;
}

/* ── Daemon entry point ──────────────────────────────────────── */

int bio_daemon_main(int argc, char **argv)
{
    g_startup_config_path = BIOAUTH_CONFIG_FILE;
    g_startup_force_no_tpm = false;
    g_startup_force_debug = false;

    for (int i = 1; i < argc; i++)
    {
        const char *arg = argv[i];
        if (strcmp(arg, "--config") == 0)
        {
            if (i + 1 >= argc)
            {
                fprintf(stderr, "--config requires a file path\n");
                return 2;
            }
            g_startup_config_path = argv[++i];
            continue;
        }

        if (strcmp(arg, "--debug") == 0)
        {
            g_startup_force_debug = true;
            continue;
        }

        if (strcmp(arg, "--no-tpm") == 0)
        {
            g_startup_force_no_tpm = true;
            continue;
        }

        if (strcmp(arg, "--version") == 0)
        {
            printf("biometric-authd %s\n", BIOAUTH_VERSION_STRING);
            return 0;
        }

        if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0)
        {
            printf("Usage: biometric-authd [--config FILE] [--debug] [--no-tpm] [--version] [--help]\n");
            return 0;
        }

        fprintf(stderr, "Unknown option: %s\n", arg);
        return 2;
    }

    sd_journal_print(LOG_INFO,
                     "biometric-authd v%s starting",
                     BIOAUTH_VERSION_STRING);

    bio_daemon_t *daemon;
    int rc = bio_daemon_create(&daemon);
    if (rc != BIO_OK)
    {
        sd_journal_print(LOG_ERR, "Daemon creation failed: %s",
                         bio_error_str(rc));
        return 1;
    }

    rc = bio_daemon_run(daemon);
    bio_daemon_destroy(daemon);

    return (rc == BIO_OK) ? 0 : 1;
}
