/*
 * pm_history.c - Entry history ring helpers
 *
 * Copyright (C) 2026 BioAuth Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "pm/pm_history.h"

#include <stdlib.h>
#include <string.h>

void pm_revision_list_init(pm_revision_list_t *list)
{
    if (!list)
    {
        return;
    }

    memset(list, 0, sizeof(*list));
}

void pm_revision_list_free(pm_revision_list_t *list)
{
    if (!list)
    {
        return;
    }

    if (list->revisions)
    {
        for (size_t i = 0; i < list->count; i++)
        {
            pm_entry_revision_free(&list->revisions[i]);
        }
        free(list->revisions);
    }

    pm_revision_list_init(list);
}

pm_error_t pm_entry_revision_from_entry(pm_entry_revision_t *out,
                                        const pm_entry_t *entry,
                                        uint64_t revision_ts_ms,
                                        const char *actor,
                                        const char *source)
{
    pm_entry_revision_t snapshot = {0};

    if (!out || !entry)
    {
        return PM_ERR_INVALID_PARAM;
    }

    snapshot.revision_ts_ms = revision_ts_ms;
    snapshot.actor = (char *)(actor ? actor : "");
    snapshot.source = (char *)(source ? source : "");
    snapshot.id = entry->id;
    snapshot.title = entry->title;
    snapshot.username = entry->username;
    snapshot.password = entry->password;
    snapshot.url = entry->url;
    snapshot.notes = entry->notes;
    snapshot.group_id = entry->group_id;
    snapshot.tags = entry->tags;
    snapshot.tag_count = entry->tag_count;
    snapshot.created_at_ms = entry->created_at_ms;
    snapshot.updated_at_ms = entry->updated_at_ms;
    snapshot.favorite = entry->favorite;
    snapshot.unknown_fields = entry->unknown_fields;
    snapshot.unknown_field_count = entry->unknown_field_count;

    pm_entry_revision_init(out);
    return pm_entry_revision_copy(out, &snapshot);
}

pm_error_t pm_history_push(pm_entry_t *entry, const pm_entry_revision_t *rev)
{
    pm_entry_revision_t copy = {0};
    pm_entry_revision_t *new_history;
    pm_error_t rc;

    if (!entry || !rev)
    {
        return PM_ERR_INVALID_PARAM;
    }

    if (entry->history_count > PM_HISTORY_MAX_REVISIONS)
    {
        return PM_ERR_STATE;
    }

    rc = pm_entry_revision_copy(&copy, rev);
    if (rc != PM_OK)
    {
        return rc;
    }

    if (entry->history_count < PM_HISTORY_MAX_REVISIONS)
    {
        new_history = realloc(entry->history,
                              (entry->history_count + 1u) * sizeof(pm_entry_revision_t));
        if (!new_history)
        {
            pm_entry_revision_free(&copy);
            return PM_ERR_NOMEM;
        }

        entry->history = new_history;
        entry->history[entry->history_count] = copy;
        entry->history_count++;
        return PM_OK;
    }

    if (!entry->history) return PM_ERR_STATE;
    pm_entry_revision_free(&entry->history[0]);
    memmove(entry->history,
            entry->history + 1,
            (PM_HISTORY_MAX_REVISIONS - 1u) * sizeof(pm_entry_revision_t));
    pm_entry_revision_init(&entry->history[PM_HISTORY_MAX_REVISIONS - 1u]);
    entry->history[PM_HISTORY_MAX_REVISIONS - 1u] = copy;
    return PM_OK;
}

pm_error_t pm_history_list(const pm_entry_t *entry, pm_revision_list_t *out)
{
    if (!entry || !out)
    {
        return PM_ERR_INVALID_PARAM;
    }

    pm_revision_list_init(out);

    if (entry->history_count == 0)
    {
        return PM_OK;
    }

    out->revisions = calloc(entry->history_count, sizeof(pm_entry_revision_t));
    if (!out->revisions)
    {
        return PM_ERR_NOMEM;
    }

    for (size_t i = 0; i < entry->history_count; i++)
    {
        pm_error_t rc = pm_entry_revision_copy(&out->revisions[i], &entry->history[i]);
        if (rc != PM_OK)
        {
            pm_revision_list_free(out);
            return rc;
        }
    }

    out->count = entry->history_count;
    return PM_OK;
}
