/*
 * pm_clipboard.c - Clipboard auto-clear scheduler
 *
 * Copyright (C) 2026 Hiya Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "pm/pm_clipboard.h"

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

typedef struct
{
    pthread_mutex_t lock;
    pthread_t worker;
    bool worker_running;
    bool worker_join_pending;
    bool cancel_requested;
    int timeout_seconds;
    pm_clipboard_countdown_cb_t countdown_cb;
    pm_clipboard_clear_cb_t clear_cb;
    void *userdata;
} pm_clipboard_state_t;

static pm_clipboard_state_t g_clipboard_state = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .worker_running = false,
    .worker_join_pending = false,
    .cancel_requested = false,
    .timeout_seconds = 30,
    .countdown_cb = NULL,
    .clear_cb = NULL,
    .userdata = NULL,
};

static int pm_clipboard_clamp_timeout(int timeout_seconds)
{
    if (timeout_seconds <= 0)
    {
        return 30;
    }
    if (timeout_seconds < 10)
    {
        return 10;
    }
    if (timeout_seconds > 120)
    {
        return 120;
    }

    return timeout_seconds;
}

static void pm_clipboard_sleep_one_second(void)
{
    struct timespec req = {
        .tv_sec = 1,
        .tv_nsec = 0,
    };

    while (nanosleep(&req, &req) != 0 && errno == EINTR)
    {
    }
}

static void *pm_clipboard_worker_main(void *arg)
{
    int remaining = (int)(intptr_t)arg;

    while (remaining > 0)
    {
        pm_clipboard_sleep_one_second();

        pthread_mutex_lock(&g_clipboard_state.lock);
        if (g_clipboard_state.cancel_requested)
        {
            g_clipboard_state.worker_running = false;
            pthread_mutex_unlock(&g_clipboard_state.lock);
            return NULL;
        }

        remaining--;
        pm_clipboard_countdown_cb_t countdown_cb = g_clipboard_state.countdown_cb;
        void *userdata = g_clipboard_state.userdata;

        if (remaining <= 0)
        {
            pm_clipboard_clear_cb_t clear_cb = g_clipboard_state.clear_cb;
            g_clipboard_state.worker_running = false;
            pthread_mutex_unlock(&g_clipboard_state.lock);

            if (countdown_cb)
            {
                countdown_cb(0, userdata);
            }
            if (clear_cb)
            {
                clear_cb(userdata);
            }
            return NULL;
        }

        pthread_mutex_unlock(&g_clipboard_state.lock);

        if (countdown_cb)
        {
            countdown_cb(remaining, userdata);
        }
    }

    pthread_mutex_lock(&g_clipboard_state.lock);
    g_clipboard_state.worker_running = false;
    pthread_mutex_unlock(&g_clipboard_state.lock);
    return NULL;
}

pm_error_t pm_clipboard_init(pm_clipboard_countdown_cb_t countdown_cb,
                             pm_clipboard_clear_cb_t clear_cb,
                             void *userdata)
{
    pthread_mutex_lock(&g_clipboard_state.lock);
    g_clipboard_state.countdown_cb = countdown_cb;
    g_clipboard_state.clear_cb = clear_cb;
    g_clipboard_state.userdata = userdata;
    pthread_mutex_unlock(&g_clipboard_state.lock);

    return PM_OK;
}

pm_error_t pm_clipboard_schedule_clear(int timeout_seconds)
{
    pthread_t join_target;
    bool have_join_target = false;
    pm_clipboard_countdown_cb_t countdown_cb = NULL;
    void *userdata = NULL;

    timeout_seconds = pm_clipboard_clamp_timeout(timeout_seconds);

    pthread_mutex_lock(&g_clipboard_state.lock);
    if (g_clipboard_state.worker_join_pending)
    {
        if (g_clipboard_state.worker_running)
        {
            g_clipboard_state.cancel_requested = true;
        }
        join_target = g_clipboard_state.worker;
        have_join_target = true;
        g_clipboard_state.worker_join_pending = false;
    }
    pthread_mutex_unlock(&g_clipboard_state.lock);

    if (have_join_target)
    {
        (void)pthread_join(join_target, NULL);
    }

    pthread_mutex_lock(&g_clipboard_state.lock);
    g_clipboard_state.cancel_requested = false;
    g_clipboard_state.timeout_seconds = timeout_seconds;

    if (pthread_create(&g_clipboard_state.worker,
                       NULL,
                       pm_clipboard_worker_main,
                       (void *)(intptr_t)timeout_seconds) != 0)
    {
        g_clipboard_state.worker_running = false;
        pthread_mutex_unlock(&g_clipboard_state.lock);
        return PM_ERR_INTERNAL;
    }

    g_clipboard_state.worker_running = true;
    g_clipboard_state.worker_join_pending = true;
    countdown_cb = g_clipboard_state.countdown_cb;
    userdata = g_clipboard_state.userdata;
    pthread_mutex_unlock(&g_clipboard_state.lock);

    if (countdown_cb)
    {
        countdown_cb(timeout_seconds, userdata);
    }

    return PM_OK;
}

void pm_clipboard_cancel_clear(void)
{
    pthread_t join_target;
    bool have_join_target = false;

    pthread_mutex_lock(&g_clipboard_state.lock);
    if (g_clipboard_state.worker_join_pending)
    {
        if (g_clipboard_state.worker_running)
        {
            g_clipboard_state.cancel_requested = true;
        }
        join_target = g_clipboard_state.worker;
        have_join_target = true;
        g_clipboard_state.worker_join_pending = false;
    }
    pthread_mutex_unlock(&g_clipboard_state.lock);

    if (have_join_target)
    {
        (void)pthread_join(join_target, NULL);
    }

    pthread_mutex_lock(&g_clipboard_state.lock);
    g_clipboard_state.worker_running = false;
    g_clipboard_state.cancel_requested = false;
    pthread_mutex_unlock(&g_clipboard_state.lock);
}

void pm_clipboard_shutdown(void)
{
    pm_clipboard_cancel_clear();

    pthread_mutex_lock(&g_clipboard_state.lock);
    g_clipboard_state.countdown_cb = NULL;
    g_clipboard_state.clear_cb = NULL;
    g_clipboard_state.userdata = NULL;
    pthread_mutex_unlock(&g_clipboard_state.lock);
}

bool pm_clipboard_is_armed(void)
{
    bool armed = false;

    pthread_mutex_lock(&g_clipboard_state.lock);
    armed = g_clipboard_state.worker_running && !g_clipboard_state.cancel_requested;
    pthread_mutex_unlock(&g_clipboard_state.lock);

    return armed;
}

int pm_clipboard_timeout_seconds(void)
{
    int timeout_seconds;

    pthread_mutex_lock(&g_clipboard_state.lock);
    timeout_seconds = g_clipboard_state.timeout_seconds;
    pthread_mutex_unlock(&g_clipboard_state.lock);

    return timeout_seconds;
}
