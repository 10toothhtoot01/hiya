/*
 * hiya_enroll.c — CLI Enrollment Tool
 *
 * Copyright (C) 2024 Hiya Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Usage:
 *   hiya-enroll [OPTIONS]
 *
 * Options:
 *   -f, --finger FINGER   Finger to enroll (1-10, default: 1 = left-thumb)
 *   -l, --label  LABEL    Label for the enrollment (default: "Finger N")
 *   -u, --user   USER     Target user for --list (root only)
 *   -d, --delete FINGER   Delete enrollment for finger N
 *   -D, --delete-all      Delete ALL enrollments for user
 *   -L, --list            List enrolled fingers
 *   -q, --quality         Show quality scores during enroll
 *   -v, --verbose         Verbose output
 *   -h, --help            Show help
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <getopt.h>
#include <unistd.h>
#include <pwd.h>
#include <signal.h>
#include <time.h>

#include <gio/gio.h>

static const char *finger_names[] = {
    "unknown",
    "left-thumb", "left-index", "left-middle", "left-ring", "left-little",
    "right-thumb", "right-index", "right-middle", "right-ring", "right-little"
};

static volatile bool g_cancelled = false;
static bool g_verbose = false;
static bool g_show_quality = false;

/* Async D-Bus state for enrollment (shared between callback and caller) */
static GVariant  *g_enroll_result = NULL;
static GError    *g_enroll_err = NULL;
static bool       g_enroll_done = false;

static void enroll_done_cb(GObject *source, GAsyncResult *res, gpointer data)
{
    (void)data;
    GError *local_err = NULL;
    g_enroll_result = g_dbus_connection_call_finish(
        G_DBUS_CONNECTION(source), res, &local_err);
    g_enroll_err = local_err;
    g_enroll_done = true;
}

static void sigint_handler(int sig)
{
    (void)sig;
    g_cancelled = true;
    /* Do not call fprintf here — not async-signal-safe.
       The main loop will detect g_cancelled and print a message. */
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "Hiya Fingerprint Enrollment Tool\n"
        "\n"
        "Usage: %s [OPTIONS]\n"
        "\n"
        "Options:\n"
        "  -f, --finger FINGER   Finger to enroll (1-10, default: 1)\n"
        "                        1=left-thumb   2=left-index   3=left-middle\n"
        "                        4=left-ring    5=left-little  6=right-thumb\n"
        "                        7=right-index  8=right-middle 9=right-ring\n"
        "                        10=right-little\n"
        "  -l, --label  LABEL    Label for this enrollment\n"
        "  -u, --user   USER     Target user for --list (root only)\n"
        "  -d, --delete FINGER   Delete enrollment for finger number\n"
        "  -D, --delete-all      Delete ALL enrollments for user\n"
        "  -L, --list            List enrolled fingers for current user\n"
        "  -q, --quality         Show quality scores during enrollment\n"
        "  -v, --verbose         Verbose output\n"
        "  -h, --help            Show this help\n"
        "\n"
        "Examples:\n"
        "  %s --finger 1 --label \"My left thumb\"\n"
        "  %s --user bob --list\n"
        "  %s --list\n"
        "  %s --delete 1\n"
        "  %s --delete-all\n",
        prog, prog, prog, prog, prog, prog);
}

/*
 * Resolve target UID for commands that support explicit target users.
 * If --user was given (and we are root), look up that user; otherwise
 * use the calling user's UID.
 */
static uid_t resolve_uid(const char *username)
{
    if (!username || username[0] == '\0') {
        return getuid();
    }

    /* Only root can target other users */
    if (getuid() != 0) {
        fprintf(stderr,
                "Error: --user requires root privileges.\n"
                "Run with sudo or as root.\n");
        return (uid_t)-1;
    }

    struct passwd *pw = getpwnam(username);
    if (!pw) {
        fprintf(stderr, "Error: user '%s' not found.\n", username);
        return (uid_t)-1;
    }

    if (g_verbose) {
        fprintf(stderr, "Enrolling for user '%s' (uid=%u)\n",
                username, (unsigned)pw->pw_uid);
    }
    return pw->pw_uid;
}

static GDBusConnection *get_bus(void)
{
    GError *err = NULL;
    GDBusConnection *conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &err);
    if (!conn) {
        fprintf(stderr, "Error: Cannot connect to system D-Bus");
        if (err) {
            fprintf(stderr, ": %s", err->message);
            g_error_free(err);
        }
        fprintf(stderr, "\nIs hiya-authd running?\n");
        return NULL;
    }
    return conn;
}

/* ── Progress display helpers ────────────────────────────────── */

/*
 * Draw a simple progress bar on the terminal.
 *   [########################################] 100% (6/6 captures) quality=85 [GOOD]
 */
static void draw_progress(int current, int total, int quality)
{
    if (total <= 0) total = 1;
    int pct = (current * 100) / total;
    if (pct > 100) pct = 100;

    const int bar_width = 40;
    int filled = (pct * bar_width) / 100;

    fprintf(stderr, "\r  [");
    for (int i = 0; i < bar_width; i++) {
        if (i < filled)
            fputc('#', stderr);
        else
            fputc(' ', stderr);
    }
    fprintf(stderr, "] %3d%% (%d/%d captures)", pct, current, total);

    if (g_show_quality && quality >= 0) {
        fprintf(stderr, " quality=%d", quality);
        if (quality >= 80)
            fprintf(stderr, " [GOOD]");
        else if (quality >= 50)
            fprintf(stderr, " [OK]");
        else
            fprintf(stderr, " [POOR - press harder]");
    }

    fflush(stderr);
}

/*
 * D-Bus signal callback for EnrollProgress.
 * Signal signature: (nnn) = status, stage, total
 */
static void on_enroll_progress(GDBusConnection *conn,
                                const gchar *sender,
                                const gchar *path,
                                const gchar *iface,
                                const gchar *signal,
                                GVariant *params,
                                gpointer user_data)
{
    (void)conn; (void)sender; (void)path; (void)iface; (void)signal;
    (void)user_data;

    gint16 status = 0, stage = 0, total = 0;

    g_variant_get(params, "(nnn)", &status, &stage, &total);

    /* The daemon provides the actual total; use it directly */
    int t = (total > 0) ? (int)total : 6;  /* fallback if zero */
    draw_progress((int)stage, t, (int)status);
}

/*
 * Subscribe to EnrollProgress D-Bus signal for real-time feedback.
 */
static guint subscribe_progress(GDBusConnection *conn)
{
    return g_dbus_connection_signal_subscribe(
        conn,
        "org.hiya.Manager",          /* sender */
        "org.hiya.Manager",          /* interface */
        "EnrollProgress",               /* signal */
        "/org/hiya/Manager",         /* object path */
        NULL,                           /* arg0 */
        G_DBUS_SIGNAL_FLAGS_NONE,
        on_enroll_progress,
        NULL,          /* user_data */
        NULL           /* user_data_free_func */
    );
}

/* ── Commands ────────────────────────────────────────────────── */

static int cmd_list(uid_t uid)
{
    GDBusConnection *conn = get_bus();
    if (!conn) return 1;

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

    if (!result) {
        fprintf(stderr, "Error: %s\n", err ? err->message : "unknown");
        if (err) g_error_free(err);
        g_object_unref(conn);
        return 1;
    }

    GVariantIter *iter;
    g_variant_get(result, "(an)", &iter);

    gint16 finger;
    int count = 0;

    printf("Enrolled fingers for uid %u:\n", (unsigned)uid);
    while (g_variant_iter_loop(iter, "n", &finger)) {
        const char *name = (finger >= 1 && finger <= 10)
                               ? finger_names[finger] : "unknown";
        printf("  [%2d] %s\n", finger, name);
        count++;
    }

    if (count == 0) {
        printf("  (none)\n");
    } else {
        printf("\nTotal: %d enrollment(s)\n", count);
    }

    g_variant_iter_free(iter);
    g_variant_unref(result);
    g_object_unref(conn);
    return 0;
}

static int cmd_enroll(int finger, const char *label, uid_t uid)
{
    GDBusConnection *conn = get_bus();
    if (!conn) return 1;

    if (finger < 1 || finger > 10) {
        fprintf(stderr, "Error: finger must be 1-10\n");
        g_object_unref(conn);
        return 1;
    }

    char default_label[64];
    if (!label || label[0] == '\0') {
        snprintf(default_label, sizeof(default_label),
                 "Finger %d (%s)", finger, finger_names[finger]);
        label = default_label;
    }

    /* Install SIGINT handler for graceful cancellation */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);

    printf("╔══════════════════════════════════════════════════╗\n");
    printf("║         Hiya Fingerprint Enrollment          ║\n");
    printf("╚══════════════════════════════════════════════════╝\n\n");
    printf("  Finger:  %s (#%d)\n", finger_names[finger], finger);
    printf("  Label:   \"%s\"\n", label);
    printf("  User:    uid %u\n\n", (unsigned)uid);
    printf("Place your finger on the sensor.\n");
    printf("You will need to swipe multiple times for a good enrollment.\n");
    printf("Press Ctrl+C to cancel.\n\n");

    /* Subscribe to progress signals */
    guint sub_id = subscribe_progress(conn);

    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);

    /*
     * Use async D-Bus call + main context iteration so EnrollProgress
     * signals can be dispatched while waiting for Enroll to complete.
     * A synchronous call blocks the GLib main context and prevents
     * signal callbacks from firing.
     */
    g_enroll_result = NULL;
    g_enroll_err = NULL;
    g_enroll_done = false;

    g_dbus_connection_call(
        conn,
        "org.hiya.Manager",
        "/org/hiya/Manager",
        "org.hiya.Manager",
        "Enroll",
        g_variant_new("(ns)", (gint16)finger, label),
        G_VARIANT_TYPE("(b)"),
        G_DBUS_CALL_FLAGS_NONE,
        120000,
        NULL,
        enroll_done_cb,
        NULL);

    /* Iterate the main context until the async call completes or cancel */
    GMainContext *ctx = g_main_context_default();
    while (!g_enroll_done && !g_cancelled) {
        g_main_context_iteration(ctx, TRUE);
    }

    GVariant *result = g_enroll_result;
    GError *err = g_enroll_err;

    /* Unsubscribe from progress signal */
    if (sub_id > 0)
        g_dbus_connection_signal_unsubscribe(conn, sub_id);

    if (g_cancelled) {
        if (result) g_variant_unref(result);
        g_object_unref(conn);
        return 1;
    }

    if (!result) {
        fprintf(stderr, "\n  Enrollment failed: %s\n",
                err ? err->message : "unknown error");
        if (err) g_error_free(err);
        g_object_unref(conn);
        return 1;
    }

    gboolean success;
    g_variant_get(result, "(b)", &success);
    g_variant_unref(result);
    g_object_unref(conn);

    if (success) {
        struct timespec end;
        clock_gettime(CLOCK_MONOTONIC, &end);
        double elapsed = (end.tv_sec - start.tv_sec) +
                         (end.tv_nsec - start.tv_nsec) / 1e9;

        printf("\n  ✓ Enrollment successful!\n");
        printf("    %s is now enrolled (%.1fs).\n",
               finger_names[finger], elapsed);
        return 0;
    } else {
        fprintf(stderr, "\n  ✗ Enrollment failed.\n");
        fprintf(stderr, "    Try again with a clean, dry finger.\n");
        return 1;
    }
}

static int cmd_delete(int finger, uid_t uid)
{
    GDBusConnection *conn = get_bus();
    if (!conn) return 1;

    if (finger < 1 || finger > 10) {
        fprintf(stderr, "Error: finger must be 1-10\n");
        g_object_unref(conn);
        return 1;
    }

    if (g_verbose) {
        fprintf(stderr, "Deleting enrollment for %s (uid=%u)...\n",
                finger_names[finger], (unsigned)uid);
    }

    GError *err = NULL;
    GVariant *result = g_dbus_connection_call_sync(
        conn,
        "org.hiya.Manager",
        "/org/hiya/Manager",
        "org.hiya.Manager",
        "DeleteEnrollment",
        g_variant_new("(n)", (gint16)finger),
        G_VARIANT_TYPE("(b)"),
        G_DBUS_CALL_FLAGS_NONE,
        5000, NULL, &err);

    if (!result) {
        fprintf(stderr, "Error: %s\n", err ? err->message : "unknown");
        if (err) g_error_free(err);
        g_object_unref(conn);
        return 1;
    }

    gboolean success;
    g_variant_get(result, "(b)", &success);
    g_variant_unref(result);
    g_object_unref(conn);

    if (success) {
        printf("Enrollment for %s deleted.\n", finger_names[finger]);
        return 0;
    } else {
        fprintf(stderr, "No enrollment found for %s.\n", finger_names[finger]);
        return 1;
    }
}

static int cmd_delete_all(uid_t uid)
{
    GDBusConnection *conn = get_bus();
    if (!conn) return 1;

    printf("Deleting ALL enrollments for uid %u...\n", (unsigned)uid);

    /* Get current enrollments first */
    GError *err = NULL;
    GVariant *list_result = g_dbus_connection_call_sync(
        conn,
        "org.hiya.Manager",
        "/org/hiya/Manager",
        "org.hiya.Manager",
        "GetEnrolledFingers",
        g_variant_new("(u)", (guint32)uid),
        G_VARIANT_TYPE("(an)"),
        G_DBUS_CALL_FLAGS_NONE,
        5000, NULL, &err);

    if (!list_result) {
        fprintf(stderr, "Error listing enrollments: %s\n",
                err ? err->message : "unknown");
        if (err) g_error_free(err);
        g_object_unref(conn);
        return 1;
    }

    GVariantIter *iter;
    g_variant_get(list_result, "(an)", &iter);

    gint16 finger;
    int deleted = 0, failed = 0;

    while (g_variant_iter_loop(iter, "n", &finger)) {
        if (g_verbose)
            fprintf(stderr, "  Deleting finger %d (%s)...\n",
                    finger,
                    (finger >= 1 && finger <= 10) ? finger_names[finger] : "???");

        GError *del_err = NULL;
        GVariant *del_result = g_dbus_connection_call_sync(
            conn,
            "org.hiya.Manager",
            "/org/hiya/Manager",
            "org.hiya.Manager",
            "DeleteEnrollment",
            g_variant_new("(n)", finger),
            G_VARIANT_TYPE("(b)"),
            G_DBUS_CALL_FLAGS_NONE,
            5000, NULL, &del_err);

        if (del_result) {
            gboolean ok;
            g_variant_get(del_result, "(b)", &ok);
            g_variant_unref(del_result);
            if (ok) deleted++; else failed++;
        } else {
            if (del_err) {
                fprintf(stderr, "  Warning: failed to delete finger %d: %s\n",
                        finger, del_err->message);
                g_error_free(del_err);
            }
            failed++;
        }
    }

    g_variant_iter_free(iter);
    g_variant_unref(list_result);
    g_object_unref(conn);

    if (deleted == 0 && failed == 0) {
        printf("No enrollments found.\n");
    } else {
        printf("Deleted %d enrollment(s)", deleted);
        if (failed > 0)
            printf(", %d failed", failed);
        printf(".\n");
    }

    return (failed > 0) ? 1 : 0;
}

int main(int argc, char **argv)
{
    static struct option long_opts[] = {
        {"finger",     required_argument, NULL, 'f'},
        {"label",      required_argument, NULL, 'l'},
        {"user",       required_argument, NULL, 'u'},
        {"delete",     required_argument, NULL, 'd'},
        {"delete-all", no_argument,       NULL, 'D'},
        {"list",       no_argument,       NULL, 'L'},
        {"quality",    no_argument,       NULL, 'q'},
        {"verbose",    no_argument,       NULL, 'v'},
        {"help",       no_argument,       NULL, 'h'},
        {NULL,         0,                 NULL,  0 }
    };

    int finger = 1;
    const char *label = NULL;
    const char *username = NULL;
    int delete_finger = -1;
    bool list = false;
    bool delete_all = false;

    int opt;
    while ((opt = getopt_long(argc, argv, "f:l:u:d:DLqvh",
                              long_opts, NULL)) != -1) {
        switch (opt) {
        case 'f':
            finger = atoi(optarg);
            if (finger < 1 || finger > 10) {
                fprintf(stderr, "Error: --finger must be 1-10\n");
                return 1;
            }
            break;
        case 'l': label = optarg; break;
        case 'u': username = optarg; break;
        case 'd':
            delete_finger = atoi(optarg);
            if (delete_finger < 1 || delete_finger > 10) {
                fprintf(stderr, "Error: --delete must be 1-10\n");
                return 1;
            }
            break;
        case 'D': delete_all = true; break;
        case 'L': list = true; break;
        case 'q': g_show_quality = true; break;
        case 'v': g_verbose = true; break;
        case 'h': usage(argv[0]); return 0;
        default:  usage(argv[0]); return 1;
        }
    }

    if (username && !list) {
        fprintf(stderr,
                "Error: --user is only supported with --list.\n"
                "Enrollment and delete operations are bound to the caller UID by the daemon.\n");
        return 1;
    }

    uid_t uid = resolve_uid(username);
    if (uid == (uid_t)-1)
        return 1;

    if (list) {
        return cmd_list(uid);
    }

    if (delete_all) {
        return cmd_delete_all(uid);
    }

    if (delete_finger > 0) {
        return cmd_delete(delete_finger, uid);
    }

    /* Default action: enroll */
    return cmd_enroll(finger, label, uid);
}
