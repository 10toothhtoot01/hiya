/*
 * pm_eff_wordlist.h - Embedded EFF large wordlist
 *
 * Copyright (C) 2026 Hiya Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef PM_EFF_WORDLIST_H
#define PM_EFF_WORDLIST_H

#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define PM_EFF_WORDLIST_SIZE 7776

    extern const char *const pm_eff_wordlist[PM_EFF_WORDLIST_SIZE];

    /* Returns NULL on RNG failure. */
    const char *pm_eff_wordlist_random_word(void);

#ifdef __cplusplus
}
#endif

#endif /* PM_EFF_WORDLIST_H */
