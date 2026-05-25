/*
 * bio_fprintd_compat.c — fprintd-compatible D-Bus API Shim
 *
 * Copyright (C) 2025 BioAuth Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Implements the net.reactivated.Fprint.Manager and
 * net.reactivated.Fprint.Device interfaces, translating calls
 * to the internal BioAuth daemon API.
 *
 * This enables GDM, GNOME Settings, SDDM, and KDE to use BioAuth
 * for fingerprint login without any modifications.
 */

#include "bio_fprintd_compat.h"
#include "bio_daemon.h"
#include "bio_common.h"
#include "fingerprint/bio_fingerprint.h"

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>

/* ── D-Bus interface XML (introspection data) ────────────────── */

static const char *FPRINTD_MANAGER_XML =
    "<node>"
    "  <interface name='net.reactivated.Fprint.Manager'>"
    "    <method name='GetDefaultDevice'>"
    "      <arg type='o' name='device' direction='out'/>"
    "    </method>"
    "    <method name='GetDevices'>"
    "      <arg type='ao' name='devices' direction='out'/>"
    "    </method>"
    "  </interface>"
    "</node>";

static const char *FPRINTD_DEVICE_XML =
    "<node>"
    "  <interface name='net.reactivated.Fprint.Device'>"
    /*  Methods  */
    "    <method name='Claim'>"
    "      <arg type='s' name='username' direction='in'/>"
    "    </method>"
    "    <method name='Release'/>"
    "    <method name='EnrollStart'>"
    "      <arg type='s' name='finger_name' direction='in'/>"
    "    </method>"
    "    <method name='EnrollStop'/>"
    "    <method name='VerifyStart'>"
    "      <arg type='s' name='finger_name' direction='in'/>"
    "    </method>"
    "    <method name='VerifyStop'/>"
    "    <method name='DeleteEnrolledFingers'>"
    "      <arg type='s' name='username' direction='in'/>"
    "    </method>"
    "    <method name='DeleteEnrolledFingers2'/>"
    "    <method name='ListEnrolledFingers'>"
    "      <arg type='s' name='username' direction='in'/>"
    "      <arg type='as' name='enrolled_fingers' direction='out'/>"
    "    </method>"
    /*  Signals  */
    "    <signal name='EnrollStatus'>"
    "      <arg type='s' name='result'/>"
    "      <arg type='b' name='done'/>"
    "    </signal>"
    "    <signal name='VerifyStatus'>"
    "      <arg type='s' name='result'/>"
    "      <arg type='b' name='done'/>"
    "    </signal>"
    "    <signal name='VerifyFingerSelected'>"
    "      <arg type='s' name='finger_name'/>"
    "    </signal>"
    /*  Properties  */
    "    <property name='scan-type' type='s' access='read'/>"
    "    <property name='num-enroll-stages' type='i' access='read'/>"
    "    <property name='finger-present' type='b' access='read'/>"
    "    <property name='finger-needed' type='b' access='read'/>"
    "  </interface>"
    "</node>";

/* ── fprintd result strings ──────────────────────────────────── */

/* Enroll results (fprintd API) */
#define ENROLL_COMPLETED "enroll-completed"
#define ENROLL_FAILED "enroll-failed"
#define ENROLL_STAGE_PASSED "enroll-stage-passed"
#define ENROLL_RETRY_SCAN "enroll-retry-scan"
#define ENROLL_SWIPE_TOO_SHORT "enroll-swipe-too-short"
#define ENROLL_FINGER_NOT_CENTERED "enroll-finger-not-centered"
#define ENROLL_REMOVE_AND_RETRY "enroll-remove-and-retry"
#define ENROLL_DATA_FULL "enroll-data-full"
#define ENROLL_DISCONNECTED "enroll-disconnected"
#define ENROLL_UNKNOWN_ERROR "enroll-unknown-error"

/* Verify results (fprintd API) */
#define VERIFY_MATCH "verify-match"
#define VERIFY_NO_MATCH "verify-no-match"
#define VERIFY_RETRY_SCAN "verify-retry-scan"
#define VERIFY_SWIPE_TOO_SHORT "verify-swipe-too-short"
#define VERIFY_FINGER_NOT_CENTERED "verify-finger-not-centered"
#define VERIFY_REMOVE_AND_RETRY "verify-remove-and-retry"
#define VERIFY_DISCONNECTED "verify-disconnected"
#define VERIFY_UNKNOWN_ERROR "verify-unknown-error"

/* ── Helpers ─────────────────────────────────────────────────── */

/*
 * Map bio_finger_t to fprintd finger name strings.
 * fprintd uses lowercase-kebab-case names like "left-thumb".
 */
static const char *finger_to_fprintd_name(bio_finger_t finger)
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
        return "any";
    }
}

/*
 * Get the calling user's UID from D-Bus sender.
 * Returns (uid_t)-1 on failure.
 */
static uid_t get_sender_uid(GDBusConnection *bus, const char *sender)
{
    GError *err = NULL;

    GVariant *result = g_dbus_connection_call_sync(
        bus,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
        "GetConnectionUnixUser",
        g_variant_new("(s)", sender),
        G_VARIANT_TYPE("(u)"),
        G_DBUS_CALL_FLAGS_NONE,
        -1, NULL, &err);

    if (!result)
    {
        BIO_WARN("fprintd-compat: couldn't get sender UID: %s",
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

/*
 * Get the calling user from D-Bus sender.
 * Returns the username for the sender's UID.
 * Uses _Thread_local buffer for thread safety (H1 fix).
 */
static const char *get_sender_user(GDBusConnection *bus, const char *sender)
{
    static _Thread_local char name_buf[64];

    uid_t uid = get_sender_uid(bus, sender);
    if (uid == (uid_t)-1)
        return NULL;

    struct passwd pw_buf;
    char pw_strbuf[512];
    struct passwd *pw = NULL;
    if (getpwuid_r(uid, &pw_buf, pw_strbuf, sizeof(pw_strbuf), &pw) != 0 || !pw)
    {
        return NULL;
    }

    strncpy(name_buf, pw->pw_name, sizeof(name_buf) - 1);
    name_buf[sizeof(name_buf) - 1] = '\0';
    return name_buf;
}

/*
 * Get the fprintd device context from the daemon.
 */
static bio_fprintd_device_t *find_device(bio_fprintd_compat_t *compat,
                                         const char *object_path)
{
    for (int i = 0; i < compat->num_devices; i++)
    {
        if (strcmp(compat->devices[i].object_path, object_path) == 0)
            return &compat->devices[i];
    }
    return NULL;
}

/* ── Manager interface handler ───────────────────────────────── */

static void manager_method_call(GDBusConnection *bus,
                                const gchar *sender,
                                const gchar *object_path,
                                const gchar *interface_name,
                                const gchar *method_name,
                                GVariant *parameters,
                                GDBusMethodInvocation *invocation,
                                gpointer user_data)
{
    bio_fprintd_compat_t *compat = (bio_fprintd_compat_t *)user_data;
    (void)bus;
    (void)sender;
    (void)object_path;
    (void)interface_name;
    (void)parameters;

    if (g_strcmp0(method_name, "GetDefaultDevice") == 0)
    {
        if (compat->num_devices == 0)
        {
            g_dbus_method_invocation_return_dbus_error(
                invocation,
                "net.reactivated.Fprint.Error.NoSuchDevice",
                "No fingerprint devices available");
            return;
        }
        g_dbus_method_invocation_return_value(
            invocation,
            g_variant_new("(o)", compat->devices[0].object_path));
    }
    else if (g_strcmp0(method_name, "GetDevices") == 0)
    {
        GVariantBuilder builder;
        g_variant_builder_init(&builder, G_VARIANT_TYPE("ao"));
        for (int i = 0; i < compat->num_devices; i++)
        {
            g_variant_builder_add(&builder, "o",
                                  compat->devices[i].object_path);
        }
        g_dbus_method_invocation_return_value(
            invocation,
            g_variant_new("(ao)", &builder));
    }
    else
    {
        g_dbus_method_invocation_return_dbus_error(
            invocation,
            "org.freedesktop.DBus.Error.UnknownMethod",
            "Unknown method");
    }
}

static const GDBusInterfaceVTable manager_vtable = {
    .method_call = manager_method_call,
    .get_property = NULL,
    .set_property = NULL,
};

/* ── Async verify/enroll task data ────────────────────────────── */

typedef struct
{
    bio_fprintd_compat_t *compat;
    int device_idx; /* index into compat->devices[] */
    char username[64];
    char finger[48]; /* for enroll only */
    bool is_enroll;  /* false = verify, true = enroll */
} fprintd_async_task_t;

static void fprintd_async_task_free(gpointer data)
{
    g_free(data);
}

/*
 * Thread function: runs bio_daemon_verify_user() or bio_daemon_enroll_user()
 * off the main thread so the GLib main loop stays responsive.
 */
static void fprintd_async_thread_func(GTask *task,
                                      gpointer source_object,
                                      gpointer task_data,
                                      GCancellable *cancellable)
{
    (void)source_object;
    fprintd_async_task_t *td = (fprintd_async_task_t *)task_data;

    if (g_cancellable_is_cancelled(cancellable))
    {
        g_task_return_boolean(task, FALSE);
        return;
    }

    bool success = false;
    if (td->compat->daemon)
    {
        if (td->is_enroll)
        {
            int rc = bio_daemon_enroll_user(td->compat->daemon,
                                            td->username,
                                            td->finger);
            success = (rc == BIO_OK);
        }
        else
        {
            int rc = bio_daemon_verify_user(td->compat->daemon,
                                            td->username);
            success = (rc == BIO_OK);
        }
    }

    g_task_return_boolean(task, success);
}

/*
 * Callback: runs on the main thread when the async task completes.
 * Emits the VerifyStatus or EnrollStatus D-Bus signal and resets
 * device state.
 */
static void fprintd_async_ready_cb(GObject *source_object,
                                   GAsyncResult *res,
                                   gpointer user_data)
{
    (void)source_object;
    (void)user_data;

    GTask *task = G_TASK(res);
    fprintd_async_task_t *td = (fprintd_async_task_t *)g_task_get_task_data(task);

    bio_fprintd_compat_t *compat = td->compat;
    bio_fprintd_device_t *dev = &compat->devices[td->device_idx];

    bool success = g_task_propagate_boolean(task, NULL);

    /* If cancelled (e.g., VerifyStop/EnrollStop/Release called), don't emit signal */
    if (g_cancellable_is_cancelled(g_task_get_cancellable(task)))
    {
        /* Only restore to CLAIMED if not already released to IDLE */
        if (dev->state == FPRINTD_STATE_VERIFYING ||
            dev->state == FPRINTD_STATE_ENROLLING)
        {
            dev->state = FPRINTD_STATE_CLAIMED;
        }
        g_clear_object(&dev->cancellable);
        return;
    }

    const char *signal_name;
    const char *result_str;

    if (td->is_enroll)
    {
        signal_name = "EnrollStatus";
        result_str = success ? ENROLL_COMPLETED : ENROLL_FAILED;
    }
    else
    {
        signal_name = "VerifyStatus";
        result_str = success ? VERIFY_MATCH : VERIFY_NO_MATCH;
    }

    GError *err = NULL;
    g_dbus_connection_emit_signal(
        compat->bus, NULL,
        dev->object_path,
        "net.reactivated.Fprint.Device",
        signal_name,
        g_variant_new("(sb)", result_str, TRUE),
        &err);
    if (err)
    {
        BIO_WARN("fprintd-compat: failed to emit %s: %s",
                 signal_name, err->message);
        g_error_free(err);
    }

    /* Only update state if device is still in VERIFYING/ENROLLING
     * (Release may have reset it to IDLE) */
    if (dev->state == FPRINTD_STATE_VERIFYING ||
        dev->state == FPRINTD_STATE_ENROLLING)
    {
        dev->state = FPRINTD_STATE_CLAIMED;
    }
    g_clear_object(&dev->cancellable);
}

/*
 * Internal device release — shared by Release handler and
 * NameOwnerChanged auto-release.
 */
static void fprintd_device_release(bio_fprintd_compat_t *compat,
                                   bio_fprintd_device_t *dev)
{
    BIO_INFO("fprintd-compat: device %s released (was claimed by %s)",
             dev->object_path, dev->claimed_by);

    /* Cancel any in-progress async operation */
    if (dev->cancellable)
    {
        g_cancellable_cancel(dev->cancellable);
    }

    /* Remove NameOwnerChanged watch */
    if (dev->name_watch_id > 0)
    {
        g_dbus_connection_signal_unsubscribe(compat->bus,
                                             dev->name_watch_id);
        dev->name_watch_id = 0;
    }

    dev->state = FPRINTD_STATE_IDLE;
    dev->claimed_by[0] = '\0';
    dev->claimed_sender[0] = '\0';
    dev->enroll_finger[0] = '\0';
}

/*
 * NameOwnerChanged callback — auto-release device when the
 * claiming D-Bus client disconnects.  The real fprintd does this;
 * without it, a crashed or exited pam_fprintd process leaves the
 * device stuck in CLAIMED state forever.
 */
static void on_claimer_vanished(GDBusConnection *bus,
                                const gchar *sender_name,
                                const gchar *object_path,
                                const gchar *interface_name,
                                const gchar *signal_name,
                                GVariant *parameters,
                                gpointer user_data)
{
    (void)bus;
    (void)sender_name;
    (void)object_path;
    (void)interface_name;
    (void)signal_name;

    bio_fprintd_compat_t *compat = (bio_fprintd_compat_t *)user_data;

    const gchar *name = NULL;
    const gchar *old_owner = NULL;
    const gchar *new_owner = NULL;
    g_variant_get(parameters, "(&s&s&s)", &name, &old_owner, &new_owner);

    /* We only care about names disappearing (new_owner is empty) */
    if (new_owner[0] != '\0')
        return;

    /* Check each device to see if the vanished name was its claimer */
    for (int i = 0; i < compat->num_devices; i++)
    {
        bio_fprintd_device_t *dev = &compat->devices[i];
        if (dev->state != FPRINTD_STATE_IDLE &&
            g_strcmp0(dev->claimed_sender, old_owner) == 0)
        {
            BIO_WARN("fprintd-compat: claimer %s disconnected, "
                     "auto-releasing device %s",
                     old_owner, dev->object_path);
            fprintd_device_release(compat, dev);
        }
    }
}

/* ── Device interface handler ────────────────────────────────── */

static void device_method_call(GDBusConnection *bus,
                               const gchar *sender,
                               const gchar *object_path,
                               const gchar *interface_name,
                               const gchar *method_name,
                               GVariant *parameters,
                               GDBusMethodInvocation *invocation,
                               gpointer user_data)
{
    bio_fprintd_compat_t *compat = (bio_fprintd_compat_t *)user_data;
    (void)interface_name;

    bio_fprintd_device_t *dev = find_device(compat, object_path);
    if (!dev)
    {
        g_dbus_method_invocation_return_dbus_error(
            invocation,
            "net.reactivated.Fprint.Error.NoSuchDevice",
            "Device not found");
        return;
    }

    /* ── Claim ──────────────────────────────────────────────── */
    if (g_strcmp0(method_name, "Claim") == 0)
    {
        const gchar *username = NULL;
        g_variant_get(parameters, "(&s)", &username);

        /* If username is empty, use the calling user */
        if (!username || username[0] == '\0')
        {
            username = get_sender_user(bus, sender);
            if (!username)
            {
                g_dbus_method_invocation_return_dbus_error(
                    invocation,
                    "net.reactivated.Fprint.Error.Internal",
                    "Could not determine calling user");
                return;
            }
        }
        else
        {
            /* Authorization: only root or the target user may claim as
               a specific username. This prevents one user from claiming
               the device as a different user and reading their
               verification results. */
            uid_t caller_uid = get_sender_uid(bus, sender);
            struct passwd pwd_buf;
            char pw_storage[256];
            struct passwd *target_pw = NULL;
            getpwnam_r(username, &pwd_buf, pw_storage,
                       sizeof(pw_storage), &target_pw);
            if (!target_pw || (caller_uid != 0 &&
                               caller_uid != target_pw->pw_uid))
            {
                g_dbus_method_invocation_return_dbus_error(
                    invocation,
                    "net.reactivated.Fprint.Error.PermissionDenied",
                    "Not authorized to claim as another user");
                return;
            }
        }

        if (dev->state != FPRINTD_STATE_IDLE)
        {
            g_dbus_method_invocation_return_dbus_error(
                invocation,
                "net.reactivated.Fprint.Error.AlreadyInUse",
                "Device is already claimed");
            return;
        }

        strncpy(dev->claimed_by, username,
                sizeof(dev->claimed_by) - 1);
        dev->claimed_by[sizeof(dev->claimed_by) - 1] = '\0';
        /* Store claimer's D-Bus unique name for sender verification (C3 fix) */
        strncpy(dev->claimed_sender, sender,
                sizeof(dev->claimed_sender) - 1);
        dev->claimed_sender[sizeof(dev->claimed_sender) - 1] = '\0';
        dev->state = FPRINTD_STATE_CLAIMED;

        /* Watch for claimer disconnecting — auto-release the device
         * if the D-Bus client goes away without calling Release. */
        dev->name_watch_id = g_dbus_connection_signal_subscribe(
            bus,
            "org.freedesktop.DBus",  /* sender */
            "org.freedesktop.DBus",  /* interface */
            "NameOwnerChanged",      /* signal */
            "/org/freedesktop/DBus", /* object path */
            sender,                  /* arg0 (the name to watch) */
            G_DBUS_SIGNAL_FLAGS_NONE,
            on_claimer_vanished,
            compat,
            NULL);

        BIO_INFO("fprintd-compat: device %s claimed by %s (watching %s)",
                 dev->object_path, dev->claimed_by, sender);

        g_dbus_method_invocation_return_value(invocation, NULL);
    }
    /* ── Release ────────────────────────────────────────────── */
    else if (g_strcmp0(method_name, "Release") == 0)
    {
        if (dev->state == FPRINTD_STATE_IDLE)
        {
            g_dbus_method_invocation_return_dbus_error(
                invocation,
                "net.reactivated.Fprint.Error.ClaimDevice",
                "Device is not claimed");
            return;
        }
        /* Verify sender is the claimer (C3 fix) */
        if (g_strcmp0(sender, dev->claimed_sender) != 0)
        {
            g_dbus_method_invocation_return_dbus_error(
                invocation,
                "net.reactivated.Fprint.Error.PermissionDenied",
                "Release denied: device claimed by a different client");
            return;
        }

        BIO_INFO("fprintd-compat: device %s released by %s (explicit)",
                 dev->object_path, dev->claimed_by);

        fprintd_device_release(compat, dev);

        g_dbus_method_invocation_return_value(invocation, NULL);
    }
    /* ── VerifyStart ────────────────────────────────────────── */
    else if (g_strcmp0(method_name, "VerifyStart") == 0)
    {
        if (dev->state != FPRINTD_STATE_CLAIMED)
        {
            g_dbus_method_invocation_return_dbus_error(
                invocation,
                "net.reactivated.Fprint.Error.ClaimDevice",
                "Device must be claimed first");
            return;
        }
        /* Verify sender is the claimer (C3 fix) */
        if (g_strcmp0(sender, dev->claimed_sender) != 0)
        {
            g_dbus_method_invocation_return_dbus_error(
                invocation,
                "net.reactivated.Fprint.Error.PermissionDenied",
                "VerifyStart denied: device claimed by a different client");
            return;
        }

        const gchar *finger = NULL;
        g_variant_get(parameters, "(&s)", &finger);
        (void)finger; /* We accept any enrolled finger */

        dev->state = FPRINTD_STATE_VERIFYING;

        BIO_INFO("fprintd-compat: verify started for %s",
                 dev->claimed_by);

        /* Return immediately — GDM expects this to be async. */
        g_dbus_method_invocation_return_value(invocation, NULL);

        /* Emit VerifyFingerSelected signal — GDM/GNOME Shell uses this
         * to display which finger the user should present. */
        {
            const char *finger_signal = (finger && finger[0] != '\0')
                                            ? finger
                                            : "any";
            GError *sig_err = NULL;
            g_dbus_connection_emit_signal(
                bus, NULL,
                dev->object_path,
                "net.reactivated.Fprint.Device",
                "VerifyFingerSelected",
                g_variant_new("(s)", finger_signal),
                &sig_err);
            if (sig_err)
            {
                BIO_WARN("fprintd-compat: failed to emit "
                         "VerifyFingerSelected: %s",
                         sig_err->message);
                g_error_free(sig_err);
            }
        }

        /* Run verification asynchronously via GTask so the GLib
         * main loop stays responsive for other D-Bus methods. */
        int dev_idx = (int)(dev - compat->devices);
        fprintd_async_task_t *td = g_new0(fprintd_async_task_t, 1);
        td->compat = compat;
        td->device_idx = dev_idx;
        td->is_enroll = false;
        strncpy(td->username, dev->claimed_by, sizeof(td->username) - 1);

        dev->cancellable = g_cancellable_new();

        GTask *task = g_task_new(NULL, dev->cancellable,
                                 fprintd_async_ready_cb, NULL);
        g_task_set_task_data(task, td, fprintd_async_task_free);
        g_task_run_in_thread(task, fprintd_async_thread_func);
        g_object_unref(task);
    }
    /* ── VerifyStop ─────────────────────────────────────────── */
    else if (g_strcmp0(method_name, "VerifyStop") == 0)
    {
        /* S2 fix: Verify sender is the claimer before allowing stop */
        if (g_strcmp0(sender, dev->claimed_sender) != 0)
        {
            g_dbus_method_invocation_return_dbus_error(
                invocation,
                "net.reactivated.Fprint.Error.PermissionDenied",
                "VerifyStop denied: device claimed by a different client");
            return;
        }
        if (dev->state == FPRINTD_STATE_VERIFYING)
        {
            if (dev->cancellable)
            {
                g_cancellable_cancel(dev->cancellable);
            }
            dev->state = FPRINTD_STATE_CLAIMED;
        }
        g_dbus_method_invocation_return_value(invocation, NULL);
    }
    /* ── EnrollStart ────────────────────────────────────────── */
    else if (g_strcmp0(method_name, "EnrollStart") == 0)
    {
        if (dev->state != FPRINTD_STATE_CLAIMED)
        {
            g_dbus_method_invocation_return_dbus_error(
                invocation,
                "net.reactivated.Fprint.Error.ClaimDevice",
                "Device must be claimed first");
            return;
        }
        /* Verify sender is the claimer (C3 fix) */
        if (g_strcmp0(sender, dev->claimed_sender) != 0)
        {
            g_dbus_method_invocation_return_dbus_error(
                invocation,
                "net.reactivated.Fprint.Error.PermissionDenied",
                "EnrollStart denied: device claimed by a different client");
            return;
        }

        const gchar *finger = NULL;
        g_variant_get(parameters, "(&s)", &finger);
        if (finger)
        {
            strncpy(dev->enroll_finger, finger,
                    sizeof(dev->enroll_finger) - 1);
            dev->enroll_finger[sizeof(dev->enroll_finger) - 1] = '\0';
        }

        dev->state = FPRINTD_STATE_ENROLLING;

        BIO_INFO("fprintd-compat: enroll started for %s finger=%s",
                 dev->claimed_by, dev->enroll_finger);

        g_dbus_method_invocation_return_value(invocation, NULL);

        /* Run enrollment asynchronously via GTask */
        int dev_idx = (int)(dev - compat->devices);
        fprintd_async_task_t *td = g_new0(fprintd_async_task_t, 1);
        td->compat = compat;
        td->device_idx = dev_idx;
        td->is_enroll = true;
        strncpy(td->username, dev->claimed_by, sizeof(td->username) - 1);
        strncpy(td->finger, dev->enroll_finger, sizeof(td->finger) - 1);

        dev->cancellable = g_cancellable_new();

        GTask *task = g_task_new(NULL, dev->cancellable,
                                 fprintd_async_ready_cb, NULL);
        g_task_set_task_data(task, td, fprintd_async_task_free);
        g_task_run_in_thread(task, fprintd_async_thread_func);
        g_object_unref(task);
    }
    /* ── EnrollStop ─────────────────────────────────────────── */
    else if (g_strcmp0(method_name, "EnrollStop") == 0)
    {
        /* S2 fix: Verify sender is the claimer before allowing stop */
        if (g_strcmp0(sender, dev->claimed_sender) != 0)
        {
            g_dbus_method_invocation_return_dbus_error(
                invocation,
                "net.reactivated.Fprint.Error.PermissionDenied",
                "EnrollStop denied: device claimed by a different client");
            return;
        }
        if (dev->state == FPRINTD_STATE_ENROLLING)
        {
            if (dev->cancellable)
            {
                g_cancellable_cancel(dev->cancellable);
            }
            dev->state = FPRINTD_STATE_CLAIMED;
        }
        g_dbus_method_invocation_return_value(invocation, NULL);
    }
    /* ── ListEnrolledFingers ────────────────────────────────── */
    else if (g_strcmp0(method_name, "ListEnrolledFingers") == 0)
    {
        const gchar *username = NULL;
        g_variant_get(parameters, "(&s)", &username);

        if (!username || username[0] == '\0')
        {
            username = get_sender_user(bus, sender);
        }

        /* S3 fix: Authorization — caller must be root or the target user.
         * Prevents information disclosure of other users' enrolled fingers. */
        uid_t caller_uid = get_sender_uid(bus, sender);
        if (caller_uid == (uid_t)-1)
        {
            g_dbus_method_invocation_return_dbus_error(
                invocation,
                "net.reactivated.Fprint.Error.Internal",
                "Could not determine calling user");
            return;
        }
        if (caller_uid != 0 && username)
        {
            struct passwd pwd_buf;
            char pw_storage[256];
            struct passwd *target_pw = NULL;
            getpwnam_r(username, &pwd_buf, pw_storage,
                       sizeof(pw_storage), &target_pw);
            if (!target_pw || target_pw->pw_uid != caller_uid)
            {
                g_dbus_method_invocation_return_dbus_error(
                    invocation,
                    "net.reactivated.Fprint.Error.PermissionDenied",
                    "Not authorized to list another user's enrollments");
                return;
            }
        }

        /* Query internal BioAuth daemon enrollment array.
         * Return a list of fprintd finger names.
         */
        GVariantBuilder builder;
        g_variant_builder_init(&builder, G_VARIANT_TYPE("as"));

        if (compat->daemon && username)
        {
            bio_finger_t enrolled[BIO_MAX_ENROLLMENTS_PER_USER];
            int n = bio_daemon_list_enrolled_fingers(
                compat->daemon, username,
                enrolled, BIO_MAX_ENROLLMENTS_PER_USER);
            for (int i = 0; i < n; i++)
            {
                const char *fname = finger_to_fprintd_name(enrolled[i]);
                g_variant_builder_add(&builder, "s", fname);
            }
        }

        g_dbus_method_invocation_return_value(
            invocation,
            g_variant_new("(as)", &builder));
    }
    /* ── DeleteEnrolledFingers ──────────────────────────────── */
    else if (g_strcmp0(method_name, "DeleteEnrolledFingers") == 0)
    {
        const gchar *username = NULL;
        g_variant_get(parameters, "(&s)", &username);

        if (!username || username[0] == '\0')
        {
            username = get_sender_user(bus, sender);
        }

        /* Authorization: caller must be root or the target user */
        uid_t caller_uid = get_sender_uid(bus, sender);
        if (caller_uid == (uid_t)-1)
        {
            g_dbus_method_invocation_return_dbus_error(
                invocation,
                "net.reactivated.Fprint.Error.Internal",
                "Could not determine calling user");
            return;
        }

        if (caller_uid != 0 && username)
        {
            struct passwd pwd_buf;
            char pw_storage[256];
            struct passwd *target_pw = NULL;
            getpwnam_r(username, &pwd_buf, pw_storage,
                       sizeof(pw_storage), &target_pw);
            if (!target_pw || target_pw->pw_uid != caller_uid)
            {
                g_dbus_method_invocation_return_dbus_error(
                    invocation,
                    "net.reactivated.Fprint.Error.PermissionDenied",
                    "Not authorized to delete another user's enrollments");
                return;
            }
        }

        if (username && compat->daemon)
        {
            bio_daemon_delete_enrollments(compat->daemon, username);
        }

        BIO_INFO("fprintd-compat: deleted enrollments for %s",
                 username ? username : "(unknown)");

        g_dbus_method_invocation_return_value(invocation, NULL);
    }
    /* ── DeleteEnrolledFingers2 (self-only, no username arg) ── */
    else if (g_strcmp0(method_name, "DeleteEnrolledFingers2") == 0)
    {
        const char *username = get_sender_user(bus, sender);
        if (username && compat->daemon)
        {
            bio_daemon_delete_enrollments(compat->daemon, username);
        }
        g_dbus_method_invocation_return_value(invocation, NULL);
    }
    else
    {
        g_dbus_method_invocation_return_dbus_error(
            invocation,
            "org.freedesktop.DBus.Error.UnknownMethod",
            "Unknown method");
    }
}

/* ── Device properties ───────────────────────────────────────── */

static GVariant *device_get_property(GDBusConnection *bus,
                                     const gchar *sender,
                                     const gchar *object_path,
                                     const gchar *interface_name,
                                     const gchar *property_name,
                                     GError **error,
                                     gpointer user_data)
{
    (void)bus;
    (void)sender;
    (void)object_path;
    (void)interface_name;

    bio_fprintd_compat_t *compat = (bio_fprintd_compat_t *)user_data;

    if (g_strcmp0(property_name, "scan-type") == 0)
    {
        return g_variant_new_string("press");
    }
    else if (g_strcmp0(property_name, "num-enroll-stages") == 0)
    {
        /* Query actual device enroll stages from daemon if available */
        int stages = 5; /* default fallback */
        if (compat && compat->daemon)
        {
            bio_fp_device_info_t devs[1];
            size_t count = 0;
            bio_fp_enumerate_devices(
                bio_daemon_get_fp_ctx(compat->daemon), devs, 1, &count);
            if (count > 0 && devs[0].nr_enroll_stages > 0)
                stages = devs[0].nr_enroll_stages;
        }
        return g_variant_new_int32(stages);
    }
    else if (g_strcmp0(property_name, "finger-present") == 0)
    {
        return g_variant_new_boolean(FALSE);
    }
    else if (g_strcmp0(property_name, "finger-needed") == 0)
    {
        /* finger-needed = TRUE when device is in VERIFYING or ENROLLING */
        bio_fprintd_device_t *dev = find_device(compat, object_path);
        bool needed = (dev &&
                       (dev->state == FPRINTD_STATE_VERIFYING ||
                        dev->state == FPRINTD_STATE_ENROLLING));
        return g_variant_new_boolean(needed);
    }

    g_set_error(error, G_IO_ERROR, G_IO_ERROR_NOT_FOUND,
                "Property '%s' not found", property_name);
    return NULL;
}

static const GDBusInterfaceVTable device_vtable = {
    .method_call = device_method_call,
    .get_property = device_get_property,
    .set_property = NULL,
};

/* ── Bus name acquired / lost callbacks ──────────────────────── */

static void on_name_acquired(GDBusConnection *bus,
                             const gchar *name,
                             gpointer user_data)
{
    bio_fprintd_compat_t *compat = (bio_fprintd_compat_t *)user_data;
    (void)bus;
    if (compat)
    {
        compat->name_owned = true;
    }
    BIO_INFO("fprintd-compat: acquired D-Bus name '%s'", name);
}

static void on_name_lost(GDBusConnection *bus,
                         const gchar *name,
                         gpointer user_data)
{
    bio_fprintd_compat_t *compat = (bio_fprintd_compat_t *)user_data;
    (void)bus;
    if (compat)
    {
        compat->name_owned = false;
    }
    BIO_WARN("fprintd-compat: lost D-Bus name '%s' "
             "(fprintd may be running)",
             name);
}

/* ── Public API ──────────────────────────────────────────────── */

int bio_fprintd_compat_init(bio_fprintd_compat_t *compat,
                            GDBusConnection *bus,
                            struct bio_daemon *daemon)
{
    if (!compat || !bus)
        return -EINVAL;

    memset(compat, 0, sizeof(*compat));
    compat->bus = g_object_ref(bus);
    compat->daemon = daemon;

    /* Parse introspection XML */
    GError *err = NULL;

    compat->manager_info =
        g_dbus_node_info_new_for_xml(FPRINTD_MANAGER_XML, &err);
    if (!compat->manager_info)
    {
        BIO_ERROR("fprintd-compat: failed to parse Manager XML: %s",
                  err->message);
        g_error_free(err);
        return -EINVAL;
    }

    compat->device_info =
        g_dbus_node_info_new_for_xml(FPRINTD_DEVICE_XML, &err);
    if (!compat->device_info)
    {
        BIO_ERROR("fprintd-compat: failed to parse Device XML: %s",
                  err->message);
        g_error_free(err);
        g_dbus_node_info_unref(compat->manager_info);
        compat->manager_info = NULL;
        return -EINVAL;
    }

    /* Register the Manager object at /net/reactivated/Fprint/Manager */
    compat->manager_reg = g_dbus_connection_register_object(
        bus,
        "/net/reactivated/Fprint/Manager",
        compat->manager_info->interfaces[0],
        &manager_vtable,
        compat,
        NULL,
        &err);

    if (compat->manager_reg == 0)
    {
        BIO_ERROR("fprintd-compat: failed to register Manager: %s",
                  err->message);
        g_error_free(err);
        g_dbus_node_info_unref(compat->manager_info);
        g_dbus_node_info_unref(compat->device_info);
        compat->manager_info = NULL;
        compat->device_info = NULL;
        return -EIO;
    }

    /* Register one virtual device (Device/0).
     * Real multi-device support would enumerate libfprint devices.
     */
    compat->num_devices = 1;
    bio_fprintd_device_t *dev = &compat->devices[0];
    snprintf(dev->object_path, sizeof(dev->object_path),
             "/net/reactivated/Fprint/Device/0");
    dev->state = FPRINTD_STATE_IDLE;

    dev->reg_id = g_dbus_connection_register_object(
        bus,
        dev->object_path,
        compat->device_info->interfaces[0],
        &device_vtable,
        compat,
        NULL,
        &err);

    if (dev->reg_id == 0)
    {
        BIO_ERROR("fprintd-compat: failed to register Device/0: %s",
                  err->message);
        g_error_free(err);
        g_dbus_connection_unregister_object(bus, compat->manager_reg);
        g_dbus_node_info_unref(compat->manager_info);
        g_dbus_node_info_unref(compat->device_info);
        compat->manager_info = NULL;
        compat->device_info = NULL;
        return -EIO;
    }

    /* Acquire the fprintd bus name.
     * Use REPLACE to take over from fprintd if it's running.
     * Do NOT allow replacement — prevents rogue processes from
     * hijacking the fprintd bus name (M7 fix).
     */
    compat->name_id = g_bus_own_name_on_connection(
        bus,
        "net.reactivated.Fprint",
        G_BUS_NAME_OWNER_FLAGS_REPLACE,
        on_name_acquired,
        on_name_lost,
        compat,
        NULL);

    /* Node info is kept alive — g_dbus_connection_register_object
     * holds a reference to the GDBusInterfaceInfo from them.
     * They are freed in bio_fprintd_compat_cleanup().
     */

    BIO_INFO("fprintd-compat: initialised (1 virtual device)");
    return 0;
}

void bio_fprintd_compat_cleanup(bio_fprintd_compat_t *compat)
{
    if (!compat)
        return;

    const bool have_bus = compat->bus && G_IS_DBUS_CONNECTION(compat->bus);

    if (compat->name_id > 0 && compat->name_owned)
    {
        g_bus_unown_name(compat->name_id);
    }
    compat->name_id = 0;
    compat->name_owned = false;

    for (int i = 0; i < compat->num_devices; i++)
    {
        if (have_bus && compat->devices[i].name_watch_id > 0)
        {
            g_dbus_connection_signal_unsubscribe(
                compat->bus, compat->devices[i].name_watch_id);
            compat->devices[i].name_watch_id = 0;
        }
        if (compat->devices[i].cancellable)
        {
            g_cancellable_cancel(compat->devices[i].cancellable);
            g_clear_object(&compat->devices[i].cancellable);
        }
        if (have_bus && compat->devices[i].reg_id > 0)
        {
            g_dbus_connection_unregister_object(
                compat->bus, compat->devices[i].reg_id);
            compat->devices[i].reg_id = 0;
        }
    }

    if (have_bus && compat->manager_reg > 0)
    {
        g_dbus_connection_unregister_object(
            compat->bus, compat->manager_reg);
        compat->manager_reg = 0;
    }

    /* Free introspection data after objects are unregistered */
    if (compat->manager_info)
    {
        g_dbus_node_info_unref(compat->manager_info);
        compat->manager_info = NULL;
    }
    if (compat->device_info)
    {
        g_dbus_node_info_unref(compat->device_info);
        compat->device_info = NULL;
    }

    if (compat->bus)
    {
        g_object_unref(compat->bus);
        compat->bus = NULL;
    }

    BIO_INFO("fprintd-compat: cleaned up");
}
