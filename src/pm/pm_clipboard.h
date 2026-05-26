/*
 * pm_clipboard.h - Clipboard auto-clear scheduler
 *
 * Copyright (C) 2026 Hiya Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef PM_CLIPBOARD_H
#define PM_CLIPBOARD_H

#include <stdbool.h>

#include "pm/pm_errors.h"

#ifdef __cplusplus
extern "C"
{
#endif

    typedef void (*pm_clipboard_countdown_cb_t)(int remaining_seconds,
                                                void *userdata);
    typedef void (*pm_clipboard_clear_cb_t)(void *userdata);

    pm_error_t pm_clipboard_init(pm_clipboard_countdown_cb_t countdown_cb,
                                 pm_clipboard_clear_cb_t clear_cb,
                                 void *userdata);

    pm_error_t pm_clipboard_schedule_clear(int timeout_seconds);

    void pm_clipboard_cancel_clear(void);

    void pm_clipboard_shutdown(void);

    bool pm_clipboard_is_armed(void);

    int pm_clipboard_timeout_seconds(void);

#ifdef __cplusplus
}
#endif

#endif /* PM_CLIPBOARD_H */
