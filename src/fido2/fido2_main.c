/*
 * fido2_main.c — Hiya FIDO2/CTAP2 Daemon Entry Point
 *
 * Copyright (C) 2025 Hiya Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This is the main entry point for the hiya-fido2d daemon, which
 * provides a Unix domain socket transport for FIDO2/CTAP2 commands.
 * It initialises the cryptographic library, the FIDO2 authenticator
 * context, and the transport layer before entering the event loop.
 *
 * Lifecycle:
 *   1. bio_crypto_init()           — seed DRBG, self-test
 *   2. bio_fido2_init()            — load/create authenticator state
 *   3. bio_fido2_transport_init()  — prepare Unix socket
 *   4. sd_notify("READY=1")        — tell systemd we are live
 *   5. bio_fido2_transport_run()   — block on event loop
 *   6. cleanup & exit
 *
 * Usage:
 *   hiya-fido2d [--socket PATH] [--storage PATH] [--debug]
 *
 * Normally started via:
 *   systemctl start hiya-fido2.service
 */

#include "fido2/bio_fido2.h"
#include "fido2/bio_fido2_uhid.h"
#include "crypto/bio_crypto.h"
#include "bio_common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>
#include <systemd/sd-daemon.h>
#include <gio/gio.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <pwd.h>

/* ── Global transport pointer for signal-driven shutdown ──────── */
static bio_fido2_transport_t *g_transport = NULL;
static volatile sig_atomic_t g_shutdown_requested = 0;

/*
 * User Verification callback — asks hiya-authd via D-Bus
 * to verify the user's fingerprint. Returns true if UV succeeds.
 *
 * Uses hiya's own VerifyUser method on org.hiya.Manager.
 * Queries logind to determine the actual console user (daemon runs as root).
 */

/* ── Resolve the console user via logind ──────────────────────── */
static bool get_session_bool_property(GDBusConnection *conn,
                                      const gchar *session_path,
                                      const gchar *prop,
                                      bool *out)
{
    GError *err = NULL;
    GVariant *result = g_dbus_connection_call_sync(
        conn,
        "org.freedesktop.login1",
        session_path,
        "org.freedesktop.DBus.Properties",
        "Get",
        g_variant_new("(ss)", "org.freedesktop.login1.Session", prop),
        G_VARIANT_TYPE("(v)"),
        G_DBUS_CALL_FLAGS_NONE,
        2000,
        NULL,
        &err);

    if (!result)
    {
        if (err)
            g_error_free(err);
        return false;
    }

    GVariant *boxed = NULL;
    g_variant_get(result, "(@v)", &boxed);
    g_variant_unref(result);

    if (!boxed)
    {
        return false;
    }

    if (!g_variant_is_of_type(boxed, G_VARIANT_TYPE_BOOLEAN))
    {
        g_variant_unref(boxed);
        return false;
    }

    *out = g_variant_get_boolean(boxed);
    g_variant_unref(boxed);
    return true;
}

static bool resolve_console_user(GDBusConnection *conn, char *buf, size_t bufsz)
{
    GError *err = NULL;
    GVariant *sessions = g_dbus_connection_call_sync(
        conn,
        "org.freedesktop.login1",
        "/org/freedesktop/login1",
        "org.freedesktop.login1.Manager",
        "ListSessions",
        NULL,
        G_VARIANT_TYPE("(a(susso))"),
        G_DBUS_CALL_FLAGS_NONE,
        5000, NULL, &err);

    if (!sessions)
    {
        BIO_WARN("FIDO2 UV: cannot query logind: %s",
                 err ? err->message : "unknown");
        if (err)
            g_error_free(err);
        return false;
    }

    bool found = false;
    bool fallback_found = false;
    char fallback_user[256] = {0};
    GVariant *arr = g_variant_get_child_value(sessions, 0);
    GVariantIter *iter = g_variant_iter_new(arr);
    const gchar *sid = NULL, *uname = NULL, *seat = NULL, *opath = NULL;
    guint32 uid = 0;

    while (g_variant_iter_next(iter, "(&su&s&s&o)",
                               &sid, &uid, &uname, &seat, &opath))
    {
        if (!(seat && seat[0] != '\0') || uid < 1000 || !uname || !opath)
        {
            continue;
        }

        bool active = false;
        bool remote = true;
        bool has_active = get_session_bool_property(conn, opath,
                                                    "Active", &active);
        bool has_remote = get_session_bool_property(conn, opath,
                                                    "Remote", &remote);

        if (has_active && has_remote && active && !remote)
        {
            strncpy(buf, uname, bufsz - 1);
            buf[bufsz - 1] = '\0';
            BIO_INFO("FIDO2 UV: active local session user is '%s' (uid=%u, seat=%s)",
                     buf, uid, seat);
            found = true;
            break;
        }

        if (!fallback_found)
        {
            strncpy(fallback_user, uname, sizeof(fallback_user) - 1);
            fallback_found = true;
        }
    }

    if (!found && fallback_found)
    {
        strncpy(buf, fallback_user, bufsz - 1);
        buf[bufsz - 1] = '\0';
        BIO_WARN("FIDO2 UV: no active local session found, falling back to '%s'",
                 buf);
        found = true;
    }

    g_variant_iter_free(iter);
    g_variant_unref(arr);
    g_variant_unref(sessions);
    return found;
}

static bool fido2_uv_callback(void *user_ctx)
{
    (void)user_ctx;

    GError *err = NULL;
    GDBusConnection *conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &err);
    if (!conn)
    {
        BIO_ERROR("FIDO2 UV: cannot connect to system bus: %s",
                  err ? err->message : "unknown");
        if (err)
            g_error_free(err);
        return false;
    }

    /* Determine the console user */
    char username[256] = {0};
    if (!resolve_console_user(conn, username, sizeof(username)))
    {
        BIO_WARN("FIDO2 UV: no console user found, falling back to uid");
        struct passwd *pw = getpwuid(getuid());
        strncpy(username, pw ? pw->pw_name : "root", sizeof(username) - 1);
    }

    /* Send a desktop notification so the user knows to touch the sensor.
     * The daemon runs as root, so we need to connect to the console
     * user's session bus using their runtime directory. */
    {
        struct passwd *console_pw = getpwnam(username);
        if (console_pw)
        {
            char addr[256];
            snprintf(addr, sizeof(addr),
                     "unix:path=/run/user/%u/bus", console_pw->pw_uid);
            GDBusConnection *session = g_dbus_connection_new_for_address_sync(
                addr,
                G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT |
                    G_DBUS_CONNECTION_FLAGS_MESSAGE_BUS_CONNECTION,
                NULL, NULL, NULL);
            if (session)
            {
                g_dbus_connection_call(
                    session,
                    "org.freedesktop.Notifications",
                    "/org/freedesktop/Notifications",
                    "org.freedesktop.Notifications",
                    "Notify",
                    g_variant_new("(susssasa{sv}i)",
                                  "Hiya",                            /* app_name    */
                                  (guint32)0,                           /* replaces_id */
                                  "fingerprint",                        /* app_icon    */
                                  "Passkey — Touch Fingerprint Sensor", /* summary    */
                                  "A website is requesting passkey "
                                  "authentication. Touch your "
                                  "fingerprint sensor to verify.", /* body        */
                                  NULL,                            /* actions     */
                                  NULL,                            /* hints       */
                                  (gint32)15000),                  /* timeout ms  */
                    NULL, G_DBUS_CALL_FLAGS_NONE,
                    1000, NULL, NULL, NULL);
                g_object_unref(session);
            }
            else
            {
                BIO_WARN("FIDO2 UV: could not connect to user session bus "
                         "at %s for notification",
                         addr);
            }
        }
    }

    BIO_INFO("FIDO2 UV: verifying user '%s' via hiya-authd", username);

    /* Call hiya-authd's VerifyUser method */
    GVariant *result = g_dbus_connection_call_sync(
        conn,
        "org.hiya.Manager",
        "/org/hiya/Manager",
        "org.hiya.Manager",
        "VerifyUser",
        g_variant_new("(s)", username),
        G_VARIANT_TYPE("(b)"),
        G_DBUS_CALL_FLAGS_NONE,
        60000, /* 60 second timeout for fingerprint scan */
        NULL, &err);

    g_object_unref(conn);

    if (!result)
    {
        BIO_WARN("FIDO2 UV: hiya-authd VerifyUser failed: %s",
                 err ? err->message : "unknown");
        if (err)
            g_error_free(err);
        return false;
    }

    gboolean verified = FALSE;
    g_variant_get(result, "(b)", &verified);
    g_variant_unref(result);

    BIO_INFO("FIDO2 UV: fingerprint verification for '%s' %s",
             username, verified ? "succeeded" : "failed");
    return verified;
}

static void shutdown_handler(int sig)
{
    (void)sig;
    g_shutdown_requested = 1;
    if (g_transport)
        bio_fido2_transport_stop(g_transport);
}

static void print_usage(const char *argv0)
{
    fprintf(stderr,
            "Usage: %s [OPTIONS]\n"
            "\n"
            "Hiya FIDO2/CTAP2 transport daemon.\n"
            "\n"
            "Options:\n"
            "  --socket PATH    Unix socket path (default: %s)\n"
            "  --storage PATH   Credential storage directory (default: /var/lib/hiya/fido2)\n"
            "  --debug          Enable debug logging\n"
            "  -h, --help       Show this help\n"
            "  --version        Show version\n",
            argv0, HIYA_FIDO2_SOCK_PATH);
}

int main(int argc, char *argv[])
{
    const char *sock_path = NULL; /* NULL → use default */
    const char *storage_path = "/var/lib/hiya/fido2";
    int debug = 0;

    /* ── Argument parsing ─────────────────────────────────────── */
    static const struct option long_opts[] = {
        {"socket", required_argument, NULL, 's'},
        {"storage", required_argument, NULL, 'S'},
        {"debug", no_argument, NULL, 'd'},
        {"help", no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'V'},
        {NULL, 0, NULL, 0},
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "hs:S:d", long_opts, NULL)) != -1)
    {
        switch (opt)
        {
        case 's':
            sock_path = optarg;
            break;
        case 'S':
            storage_path = optarg;
            break;
        case 'd':
            debug = 1;
            break;
        case 'V':
            printf("hiya-fido2d %s\n", "1.0.0");
            return 0;
        case 'h':
        default:
            print_usage(argv[0]);
            return (opt == 'h') ? 0 : 1;
        }
    }

    if (debug)
        BIO_INFO("FIDO2 daemon starting in debug mode");

    /* ── 0. Security hardening ────────────────────────────────── */
    /* Prevent core dumps from leaking key material (VULN-05 fix) */
    prctl(PR_SET_DUMPABLE, 0);
    struct rlimit corelim = {0, 0};
    setrlimit(RLIMIT_CORE, &corelim);

    /* ── 1. Initialise cryptographic library ──────────────────── */
    int rc = bio_crypto_init();
    if (rc != BIO_OK)
    {
        fprintf(stderr, "hiya-fido2d: crypto init failed (rc=%d)\n", rc);
        return 1;
    }
    BIO_INFO("FIDO2 daemon: crypto subsystem initialised");

    /* ── 2. Initialise FIDO2 authenticator ────────────────────── */
    bio_fido2_ctx_t fido2_ctx;
    memset(&fido2_ctx, 0, sizeof(fido2_ctx));

    rc = bio_fido2_init(&fido2_ctx, storage_path);
    if (rc != BIO_OK)
    {
        fprintf(stderr, "hiya-fido2d: FIDO2 init failed (rc=%d)\n", rc);
        bio_crypto_cleanup();
        return 1;
    }
    BIO_INFO("FIDO2 daemon: authenticator context ready (storage=%s)", storage_path);

    /* Set UV callback to verify user via main daemon's fingerprint */
    bio_fido2_set_uv_callback(&fido2_ctx, fido2_uv_callback, NULL);

    /* ── 3. Initialise transport layer ────────────────────────── */
    bio_fido2_transport_t transport;
    memset(&transport, 0, sizeof(transport));
    transport.listen_fd = -1;

    rc = bio_fido2_transport_init(&transport, &fido2_ctx, sock_path);
    if (rc != BIO_OK)
    {
        fprintf(stderr, "hiya-fido2d: transport init failed (rc=%d)\n", rc);
        bio_fido2_cleanup(&fido2_ctx);
        bio_crypto_cleanup();
        return 1;
    }
    g_transport = &transport;

    BIO_INFO("FIDO2 daemon: transport layer ready (socket=%s)",
             sock_path ? sock_path : HIYA_FIDO2_SOCK_PATH);

    /* ── 3b. Initialise UHID (virtual USB HID for browsers) ──── */
    bio_fido2_uhid_t uhid;
    bool uhid_active = false;

    rc = bio_fido2_uhid_init(&uhid, &fido2_ctx);
    if (rc == BIO_OK)
    {
        rc = bio_fido2_uhid_start(&uhid);
        if (rc == BIO_OK)
        {
            uhid_active = true;
            BIO_INFO("FIDO2 daemon: UHID transport active "
                     "(browsers can discover authenticator)");
        }
        else
        {
            BIO_WARN("FIDO2 daemon: UHID thread start failed (rc=%d) "
                     "— browser WebAuthn disabled",
                     rc);
            bio_fido2_uhid_cleanup(&uhid);
        }
    }
    else
    {
        BIO_WARN("FIDO2 daemon: UHID init failed (rc=%d) — "
                 "browser WebAuthn disabled (check /dev/uhid permissions)",
                 rc);
    }

    /* ── Install signal handlers ──────────────────────────────── */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = shutdown_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0; /* No SA_RESTART – we want select() interrupted */
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    /* Ignore SIGPIPE (broken client connections) */
    signal(SIGPIPE, SIG_IGN);

    /* ── 4. Notify systemd we are ready ───────────────────────── */
    sd_notify(0, "READY=1\n"
                 "STATUS=Listening for CTAP2 connections");

    BIO_INFO("FIDO2 daemon: ready, entering event loop");

    /* ── 5. Run transport event loop (blocks) ─────────────────── */
    rc = bio_fido2_transport_run(&transport);

    /* ── 6. Shutdown ──────────────────────────────────────────── */
    sd_notify(0, "STOPPING=1\n"
                 "STATUS=Shutting down");

    BIO_INFO("FIDO2 daemon: shutting down (rc=%d)", rc);

    g_transport = NULL;
    bio_fido2_transport_cleanup(&transport);

    if (uhid_active)
        bio_fido2_uhid_cleanup(&uhid);

    bio_fido2_cleanup(&fido2_ctx);
    bio_crypto_cleanup();

    BIO_INFO("FIDO2 daemon: clean exit");
    return (rc == BIO_OK) ? 0 : 1;
}
