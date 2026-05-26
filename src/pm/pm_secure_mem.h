/*
 * pm_secure_mem.h - Secure allocation helpers for sensitive data
 *
 * Copyright (C) 2026 Hiya Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef PM_SECURE_MEM_H
#define PM_SECURE_MEM_H

#include <stddef.h>
#include <stdint.h>

#include "pm/pm_errors.h"

#ifdef __cplusplus
extern "C"
{
#endif

    /*
     * Allocate zeroed memory for sensitive material and lock it in RAM.
     * Returns PM_ERR_MLOCK_FAILED when the buffer cannot be locked.
     */
    pm_error_t pm_secure_alloc(size_t len, void **ptr_out);

    /*
     * Lock an existing sensitive buffer in memory.
     */
    pm_error_t pm_secure_mlock(void *ptr, size_t len);

    /*
     * Wipe buffer contents with a compiler-barrier-safe routine.
     */
    void pm_secure_zero(void *ptr, size_t len);

    /*
     * Wipe, unlock and free sensitive memory.
     */
    void pm_secure_free(void *ptr, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* PM_SECURE_MEM_H */
