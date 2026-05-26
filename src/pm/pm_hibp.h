/*
 * pm_hibp.h - Have I Been Pwned k-anonymity checks
 *
 * Copyright (C) 2026 Hiya Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef PM_HIBP_H
#define PM_HIBP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "pm/pm_errors.h"

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct
    {
        bool found_in_breach;
        uint64_t breach_count;
        pm_error_t status;
    } pm_hibp_result_t;

    typedef void (*pm_hibp_callback_t)(pm_hibp_result_t result, void *userdata);

    pm_hibp_result_t pm_hibp_check_password(const char *password,
                                            size_t password_len);

    pm_error_t pm_hibp_check_password_async(const char *password,
                                            size_t password_len,
                                            pm_hibp_callback_t cb,
                                            void *userdata);

#ifdef __cplusplus
}
#endif

#endif /* PM_HIBP_H */
