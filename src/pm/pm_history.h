/*
 * pm_history.h - Entry history ring helpers
 *
 * Copyright (C) 2026 BioAuth Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef PM_HISTORY_H
#define PM_HISTORY_H

#include "pm/pm_payload.h"

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct
    {
        pm_entry_revision_t *revisions;
        size_t count;
    } pm_revision_list_t;

    void pm_revision_list_init(pm_revision_list_t *list);
    void pm_revision_list_free(pm_revision_list_t *list);

    pm_error_t pm_entry_revision_from_entry(pm_entry_revision_t *out,
                                            const pm_entry_t *entry,
                                            uint64_t revision_ts_ms,
                                            const char *actor,
                                            const char *source);

    /*
     * Appends a revision to the entry history in oldest-to-newest order.
     * Once the fixed capacity is reached, the oldest revision is dropped.
     */
    pm_error_t pm_history_push(pm_entry_t *entry, const pm_entry_revision_t *rev);

    pm_error_t pm_history_list(const pm_entry_t *entry, pm_revision_list_t *out);

#ifdef __cplusplus
}
#endif

#endif /* PM_HISTORY_H */
