/*
 * pm_secure_mem.c - Secure allocation helpers for sensitive data
 *
 * Copyright (C) 2026 BioAuth Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "pm/pm_secure_mem.h"

#include "crypto/bio_crypto.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

pm_error_t pm_secure_mlock(void *ptr, size_t len)
{
    if (!ptr || len == 0)
    {
        return PM_ERR_INVALID_PARAM;
    }

    if (mlock(ptr, len) != 0)
    {
        return PM_ERR_MLOCK_FAILED;
    }

    /* Best-effort: reduce core dump exposure for containing pages. */
#ifdef MADV_DONTDUMP
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size > 0)
    {
        uintptr_t start = (uintptr_t)ptr;
        uintptr_t page_start = start & ~((uintptr_t)page_size - 1);
        uintptr_t end = start + len;
        uintptr_t page_end = (end + (uintptr_t)page_size - 1) &
                             ~((uintptr_t)page_size - 1);
        size_t adv_len = (size_t)(page_end - page_start);
        (void)madvise((void *)page_start, adv_len, MADV_DONTDUMP);
    }
#endif

    return PM_OK;
}

void pm_secure_zero(void *ptr, size_t len)
{
    if (!ptr || len == 0)
    {
        return;
    }
    bio_secure_wipe(ptr, len);
}

pm_error_t pm_secure_alloc(size_t len, void **ptr_out)
{
    void *p = NULL;

    if (!ptr_out || len == 0)
    {
        return PM_ERR_INVALID_PARAM;
    }

    *ptr_out = NULL;

    p = calloc(1, len);
    if (!p)
    {
        return PM_ERR_NOMEM;
    }

    if (pm_secure_mlock(p, len) != PM_OK)
    {
        pm_secure_zero(p, len);
        free(p);
        return PM_ERR_MLOCK_FAILED;
    }

    *ptr_out = p;
    return PM_OK;
}

void pm_secure_free(void *ptr, size_t len)
{
    if (!ptr)
    {
        return;
    }

    if (len > 0)
    {
        pm_secure_zero(ptr, len);
        (void)munlock(ptr, len);
    }

    free(ptr);
}
