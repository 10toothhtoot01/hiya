/*
 * bioauth_verify.c — CLI Verification Test Tool
 *
 * Copyright (C) 2024 BioAuth Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Usage:
 *   bioauth-verify
 *
 * Creates a session, triggers verification, prints result.
 * Useful for testing fingerprint auth outside of PAM.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

#include <gio/gio.h>

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    GError *err = NULL;
    GDBusConnection *conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &err);
    if (!conn) {
        fprintf(stderr, "Cannot connect to system D-Bus: %s\n",
                err ? err->message : "unknown");
        if (err) g_error_free(err);
        return 1;
    }

    /* Step 1: Create session */
    GVariant *result = g_dbus_connection_call_sync(
        conn,
        "org.bioauth.Manager",
        "/org/bioauth/Manager",
        "org.bioauth.Manager",
        "CreateSession",
        NULL,
        G_VARIANT_TYPE("(ay)"),
        G_DBUS_CALL_FLAGS_NONE,
        5000, NULL, &err);

    if (!result) {
        fprintf(stderr, "CreateSession failed: %s\n",
                err ? err->message : "unknown");
        if (err) g_error_free(err);
        g_object_unref(conn);
        return 1;
    }

    GVariant *token_var;
    g_variant_get(result, "(@ay)", &token_var);
    g_variant_unref(result);

    printf("Session created. Place your finger on the sensor...\n");

    /* Step 2: Verify */
    result = g_dbus_connection_call_sync(
        conn,
        "org.bioauth.Manager",
        "/org/bioauth/Manager",
        "org.bioauth.Manager",
        "Verify",
        g_variant_new("(@ay)", token_var),
        G_VARIANT_TYPE("(b)"),
        G_DBUS_CALL_FLAGS_NONE,
        30000,  /* 30s timeout */
        NULL, &err);

    if (!result) {
        fprintf(stderr, "Verify failed: %s\n",
                err ? err->message : "unknown");
        if (err) g_error_free(err);
        g_object_unref(conn);
        return 1;
    }

    gboolean matched;
    g_variant_get(result, "(b)", &matched);
    g_variant_unref(result);
    g_object_unref(conn);

    if (matched) {
        printf("✓ Fingerprint verified successfully!\n");
        return 0;
    } else {
        printf("✗ Fingerprint did not match.\n");
        return 1;
    }
}
