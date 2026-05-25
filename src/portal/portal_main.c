/*
 * portal_main.c — BioAuth XDG Desktop Portal Entry Point
 *
 * Copyright (C) 2025 BioAuth Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "bio_common.h"
#include <gio/gio.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* External (defined in bio_portal.c) */
extern int  bio_portal_init(void);
extern void bio_portal_cleanup(void);

static GMainLoop *g_loop = NULL;
static volatile sig_atomic_t g_signal_received = 0;

static void on_signal(int sig)
{
    (void)sig;
    g_signal_received = 1;
    /* Write to self-pipe or use g_idle_add_full from signal context
     * is not safe. Instead, check flag periodically. */
}

static gboolean check_signal_flag(gpointer user_data)
{
    (void)user_data;
    if (g_signal_received && g_loop) {
        g_main_loop_quit(g_loop);
        return G_SOURCE_REMOVE;
    }
    return G_SOURCE_CONTINUE;
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    /* Use sigaction instead of signal() for reliable behavior (L2 fix) */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    if (bio_portal_init() != 0) {
        fprintf(stderr, "bioauth-portal: init failed\n");
        return 1;
    }

    g_loop = g_main_loop_new(NULL, FALSE);
    /* Check for signals every 500ms (H4 async-signal-safe fix) */
    g_timeout_add(500, check_signal_flag, NULL);
    g_main_loop_run(g_loop);
    g_main_loop_unref(g_loop);

    bio_portal_cleanup();
    return 0;
}
