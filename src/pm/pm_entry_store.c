/*
 * pm_entry_store.c - Entry CRUD helpers over unlocked vault payloads
 *
 * Copyright (C) 2026 Hiya Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "pm/pm_entry_store.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "pm/pm_history.h"

static bool valid_entry_id(const char *entry_id)
{
    return entry_id != NULL && entry_id[0] != '\0';
}

static pm_error_t load_payload(const pm_vault_handle_t *h, pm_payload_t *payload)
{
    if (!h || !payload)
    {
        return PM_ERR_INVALID_PARAM;
    }

    pm_payload_init(payload);
    return pm_vault_get_payload_model(h, payload);
}

static char *dup_cstr(const char *s)
{
    size_t len;
    char *out;

    if (!s)
    {
        return NULL;
    }

    len = strlen(s);
    if (len > SIZE_MAX - 1u)
    {
        return NULL;
    }

    out = malloc(len + 1u);
    if (!out)
    {
        return NULL;
    }

    memcpy(out, s, len + 1u);
    return out;
}

static bool contains_case_insensitive(const char *haystack, const char *needle)
{
    size_t hlen;
    size_t nlen;

    if (!haystack || !needle)
    {
        return false;
    }

    hlen = strlen(haystack);
    nlen = strlen(needle);

    if (nlen == 0)
    {
        return true;
    }

    if (nlen > hlen)
    {
        return false;
    }

    for (size_t i = 0; i <= hlen - nlen; i++)
    {
        bool match = true;
        for (size_t j = 0; j < nlen; j++)
        {
            unsigned char a = (unsigned char)haystack[i + j];
            unsigned char b = (unsigned char)needle[j];
            if (tolower(a) != tolower(b))
            {
                match = false;
                break;
            }
        }
        if (match)
        {
            return true;
        }
    }

    return false;
}

static pm_error_t collect_ids_filtered(const pm_payload_t *payload,
                                       bool (*match_fn)(const pm_entry_t *entry, const void *ctx),
                                       const void *ctx,
                                       char ***out_ids,
                                       size_t *out_count)
{
    char **ids = NULL;
    size_t count = 0;

    if (!payload || !match_fn || !out_ids || !out_count)
    {
        return PM_ERR_INVALID_PARAM;
    }

    *out_ids = NULL;
    *out_count = 0;

    if (payload->entry_count > 0)
    {
        ids = calloc(payload->entry_count, sizeof(char *));
        if (!ids)
        {
            return PM_ERR_NOMEM;
        }
    }

    for (size_t i = 0; i < payload->entry_count; i++)
    {
        const pm_entry_t *e = &payload->entries[i];
        const char *id;
        if (!match_fn(e, ctx))
        {
            continue;
        }

        id = e->id ? e->id : "";
        ids[count] = dup_cstr(id);
        if (!ids[count])
        {
            pm_vault_entry_id_list_free(ids, count);
            return PM_ERR_NOMEM;
        }
        count++;
    }

    *out_ids = ids;
    *out_count = count;
    return PM_OK;
}

static bool entry_match_all(const pm_entry_t *entry, const void *ctx)
{
    (void)entry;
    (void)ctx;
    return true;
}

static bool entry_match_title_contains(const pm_entry_t *entry, const void *ctx)
{
    const char *needle = (const char *)ctx;
    const char *title = entry && entry->title ? entry->title : "";
    return contains_case_insensitive(title, needle);
}

static bool entry_match_favorite(const pm_entry_t *entry, const void *ctx)
{
    (void)ctx;
    return entry && entry->favorite;
}

static const pm_group_t *find_group_by_id(const pm_payload_t *payload, const char *group_id)
{
    if (!payload || !group_id)
    {
        return NULL;
    }

    for (size_t i = 0; i < payload->group_count; i++)
    {
        const pm_group_t *g = &payload->groups[i];
        if (g->id && strcmp(g->id, group_id) == 0)
        {
            return g;
        }
    }

    return NULL;
}

static bool group_in_scope(const pm_payload_t *payload,
                           const char *entry_group_id,
                           const char *target_group_id,
                           bool include_descendants)
{
    const pm_group_t *g;
    size_t depth_limit;

    if (!entry_group_id || !target_group_id)
    {
        return false;
    }

    if (strcmp(entry_group_id, target_group_id) == 0)
    {
        return true;
    }

    if (!include_descendants)
    {
        return false;
    }

    g = find_group_by_id(payload, entry_group_id);
    depth_limit = payload ? payload->group_count + 1u : 0u;

    while (g && depth_limit > 0)
    {
        if (g->parent_id && strcmp(g->parent_id, target_group_id) == 0)
        {
            return true;
        }

        if (!g->parent_id || g->parent_id[0] == '\0')
        {
            return false;
        }

        g = find_group_by_id(payload, g->parent_id);
        depth_limit--;
    }

    return false;
}

struct pm_entry_iterator
{
    pm_payload_t payload;
    size_t *entry_order;
    size_t entry_order_count;
    size_t cursor;
};

static bool group_is_root(const pm_payload_t *payload, const pm_group_t *group)
{
    if (!payload || !group)
    {
        return false;
    }

    if (!group->parent_id || group->parent_id[0] == '\0')
    {
        return true;
    }

    return find_group_by_id(payload, group->parent_id) == NULL;
}

static pm_error_t iterator_append_entries_for_group(const pm_payload_t *payload,
                                                    const char *group_id,
                                                    bool *entry_added,
                                                    size_t *entry_order,
                                                    size_t *entry_order_count)
{
    if (!payload || !entry_added || !entry_order || !entry_order_count)
    {
        return PM_ERR_INVALID_PARAM;
    }

    for (size_t i = 0; i < payload->entry_count; i++)
    {
        const pm_entry_t *entry = &payload->entries[i];
        const char *entry_group_id = entry->group_id ? entry->group_id : "";

        if (entry_added[i])
        {
            continue;
        }

        if (!group_id)
        {
            if (entry_group_id[0] != '\0')
            {
                continue;
            }
        }
        else if (strcmp(entry_group_id, group_id) != 0)
        {
            continue;
        }

        entry_order[*entry_order_count] = i;
        (*entry_order_count)++;
        entry_added[i] = true;
    }

    return PM_OK;
}

static pm_error_t iterator_walk_group(const pm_payload_t *payload,
                                      size_t group_index,
                                      bool *group_visited,
                                      bool *entry_added,
                                      size_t *entry_order,
                                      size_t *entry_order_count,
                                      size_t remaining_depth)
{
    if (!payload || !group_visited || !entry_added || !entry_order || !entry_order_count)
    {
        return PM_ERR_INVALID_PARAM;
    }

    if (group_index >= payload->group_count)
    {
        return PM_ERR_INVALID_PARAM;
    }

    if (remaining_depth == 0)
    {
        return PM_ERR_STATE;
    }

    if (group_visited[group_index])
    {
        return PM_OK;
    }

    group_visited[group_index] = true;

    const pm_group_t *group = &payload->groups[group_index];
    const char *group_id = group->id ? group->id : "";

    if (group_id[0] != '\0')
    {
        pm_error_t rc = iterator_append_entries_for_group(payload,
                                                          group_id,
                                                          entry_added,
                                                          entry_order,
                                                          entry_order_count);
        if (rc != PM_OK)
        {
            return rc;
        }
    }

    for (size_t i = 0; i < payload->group_count; i++)
    {
        const pm_group_t *child = &payload->groups[i];
        const char *parent_id = child->parent_id ? child->parent_id : "";

        if (group_id[0] == '\0' || strcmp(parent_id, group_id) != 0)
        {
            continue;
        }

        pm_error_t rc = iterator_walk_group(payload,
                                            i,
                                            group_visited,
                                            entry_added,
                                            entry_order,
                                            entry_order_count,
                                            remaining_depth - 1u);
        if (rc != PM_OK)
        {
            return rc;
        }
    }

    return PM_OK;
}

pm_entry_iterator_t *pm_vault_store_begin(pm_vault_handle_t *vault)
{
    if (!vault)
    {
        return NULL;
    }

    pm_entry_iterator_t *it = calloc(1, sizeof(pm_entry_iterator_t));
    if (!it)
    {
        return NULL;
    }

    pm_payload_init(&it->payload);

    pm_error_t rc = pm_vault_get_payload_model(vault, &it->payload);
    if (rc != PM_OK)
    {
        pm_payload_free(&it->payload);
        free(it);
        return NULL;
    }

    if (it->payload.entry_count == 0)
    {
        return it;
    }

    it->entry_order = calloc(it->payload.entry_count, sizeof(size_t));
    if (!it->entry_order)
    {
        pm_payload_free(&it->payload);
        free(it);
        return NULL;
    }

    bool *entry_added = calloc(it->payload.entry_count, sizeof(bool));
    if (!entry_added)
    {
        free(it->entry_order);
        pm_payload_free(&it->payload);
        free(it);
        return NULL;
    }

    bool *group_visited = NULL;
    if (it->payload.group_count > 0)
    {
        group_visited = calloc(it->payload.group_count, sizeof(bool));
        if (!group_visited)
        {
            free(entry_added);
            free(it->entry_order);
            pm_payload_free(&it->payload);
            free(it);
            return NULL;
        }
    }

    size_t order_count = 0;

    rc = iterator_append_entries_for_group(&it->payload,
                                           NULL,
                                           entry_added,
                                           it->entry_order,
                                           &order_count);
    if (rc != PM_OK)
    {
        free(group_visited);
        free(entry_added);
        free(it->entry_order);
        pm_payload_free(&it->payload);
        free(it);
        return NULL;
    }

    for (size_t i = 0; i < it->payload.group_count; i++)
    {
        if (!group_is_root(&it->payload, &it->payload.groups[i]))
        {
            continue;
        }

        rc = iterator_walk_group(&it->payload,
                                 i,
                                 group_visited,
                                 entry_added,
                                 it->entry_order,
                                 &order_count,
                                 it->payload.group_count + 1u);
        if (rc != PM_OK)
        {
            free(group_visited);
            free(entry_added);
            free(it->entry_order);
            pm_payload_free(&it->payload);
            free(it);
            return NULL;
        }
    }

    for (size_t i = 0; i < it->payload.group_count; i++)
    {
        if (group_visited && group_visited[i])
        {
            continue;
        }

        rc = iterator_walk_group(&it->payload,
                                 i,
                                 group_visited,
                                 entry_added,
                                 it->entry_order,
                                 &order_count,
                                 it->payload.group_count + 1u);
        if (rc != PM_OK)
        {
            free(group_visited);
            free(entry_added);
            free(it->entry_order);
            pm_payload_free(&it->payload);
            free(it);
            return NULL;
        }
    }

    for (size_t i = 0; i < it->payload.entry_count; i++)
    {
        if (entry_added[i])
        {
            continue;
        }

        it->entry_order[order_count] = i;
        order_count++;
        entry_added[i] = true;
    }

    it->entry_order_count = order_count;

    free(group_visited);
    free(entry_added);
    return it;
}

pm_entry_t *pm_entry_iterator_next(pm_entry_iterator_t *it)
{
    if (!it)
    {
        return NULL;
    }

    if (it->cursor >= it->entry_order_count)
    {
        return NULL;
    }

    size_t index = it->entry_order[it->cursor++];
    if (index >= it->payload.entry_count)
    {
        return NULL;
    }

    return &it->payload.entries[index];
}

void pm_entry_iterator_free(pm_entry_iterator_t *it)
{
    if (!it)
    {
        return;
    }

    free(it->entry_order);
    pm_payload_free(&it->payload);
    free(it);
}

void pm_vault_entry_id_list_free(char **ids, size_t count)
{
    if (!ids)
    {
        return;
    }

    for (size_t i = 0; i < count; i++)
    {
        free(ids[i]);
    }
    free(ids);
}

pm_error_t pm_vault_entry_get(const pm_vault_handle_t *h,
                              const char *entry_id,
                              pm_entry_t *out_entry)
{
    pm_payload_t payload;

    if (!h || !out_entry || !valid_entry_id(entry_id))
    {
        return PM_ERR_INVALID_PARAM;
    }

    pm_entry_init(out_entry);

    pm_error_t rc = load_payload(h, &payload);
    if (rc != PM_OK)
    {
        return rc;
    }

    for (size_t i = 0; i < payload.entry_count; i++)
    {
        const pm_entry_t *e = &payload.entries[i];
        if (e->id && strcmp(e->id, entry_id) == 0)
        {
            rc = pm_entry_copy(out_entry, e);
            pm_payload_free(&payload);
            return rc;
        }
    }

    pm_payload_free(&payload);
    return PM_ERR_NOT_FOUND;
}

pm_error_t pm_vault_entry_add(pm_vault_handle_t *h,
                              const pm_entry_t *entry,
                              bool fail_if_exists)
{
    pm_payload_t payload;
    bool found = false;

    if (!h || !entry || !valid_entry_id(entry->id))
    {
        return PM_ERR_INVALID_PARAM;
    }

    pm_error_t rc = load_payload(h, &payload);
    if (rc != PM_OK)
    {
        return rc;
    }

    for (size_t i = 0; i < payload.entry_count; i++)
    {
        const pm_entry_t *e = &payload.entries[i];
        if (e->id && strcmp(e->id, entry->id) == 0)
        {
            found = true;
            break;
        }
    }

    if (found && fail_if_exists)
    {
        pm_payload_free(&payload);
        return PM_ERR_ALREADY_EXISTS;
    }

    if (found)
    {
        rc = pm_vault_entry_update(h, entry->id, entry);
        pm_payload_free(&payload);
        return rc;
    }

    rc = pm_payload_append_entry(&payload, entry);
    if (rc != PM_OK)
    {
        pm_payload_free(&payload);
        return rc;
    }

    rc = pm_vault_set_payload_model(h, &payload);
    pm_payload_free(&payload);
    return rc;
}

pm_error_t pm_vault_entry_update(pm_vault_handle_t *h,
                                 const char *entry_id,
                                 const pm_entry_t *replacement)
{
    pm_payload_t payload;
    pm_payload_t updated;
    bool found = false;

    if (!h || !replacement || !valid_entry_id(entry_id) || !valid_entry_id(replacement->id))
    {
        return PM_ERR_INVALID_PARAM;
    }

    pm_error_t rc = load_payload(h, &payload);
    if (rc != PM_OK)
    {
        return rc;
    }

    pm_payload_init(&updated);
    updated.schema_version = payload.schema_version;
    updated.created_at_ms = payload.created_at_ms;
    updated.updated_at_ms = payload.updated_at_ms;

    for (size_t i = 0; i < payload.entry_count; i++)
    {
        const pm_entry_t *src = &payload.entries[i];
        if (src->id && strcmp(src->id, entry_id) == 0)
        {
            pm_entry_t updated_entry;
            pm_entry_revision_t revision;
            uint64_t revision_ts_ms;

            pm_entry_init(&updated_entry);
            pm_entry_revision_init(&revision);

            rc = pm_entry_copy(&updated_entry, replacement);
            if (rc == PM_OK)
            {
                revision_ts_ms = replacement->updated_at_ms != 0u ? replacement->updated_at_ms : src->updated_at_ms;

                rc = pm_entry_revision_from_entry(&revision,
                                                  src,
                                                  revision_ts_ms,
                                                  "",
                                                  "");
            }

            if (rc == PM_OK)
            {
                rc = pm_history_push(&updated_entry, &revision);
            }

            if (rc == PM_OK)
            {
                rc = pm_payload_append_entry(&updated, &updated_entry);
            }

            pm_entry_revision_free(&revision);
            pm_entry_free(&updated_entry);
            found = true;
        }
        else
        {
            rc = pm_payload_append_entry(&updated, src);
        }

        if (rc != PM_OK)
        {
            pm_payload_free(&updated);
            pm_payload_free(&payload);
            return rc;
        }
    }

    pm_payload_free(&payload);

    if (!found)
    {
        pm_payload_free(&updated);
        return PM_ERR_NOT_FOUND;
    }

    rc = pm_vault_set_payload_model(h, &updated);
    pm_payload_free(&updated);
    return rc;
}

pm_error_t pm_vault_entry_remove(pm_vault_handle_t *h,
                                 const char *entry_id)
{
    pm_payload_t payload;
    pm_payload_t updated;
    bool found = false;

    if (!h || !valid_entry_id(entry_id))
    {
        return PM_ERR_INVALID_PARAM;
    }

    pm_error_t rc = load_payload(h, &payload);
    if (rc != PM_OK)
    {
        return rc;
    }

    pm_payload_init(&updated);
    updated.schema_version = payload.schema_version;
    updated.created_at_ms = payload.created_at_ms;
    updated.updated_at_ms = payload.updated_at_ms;

    for (size_t i = 0; i < payload.entry_count; i++)
    {
        const pm_entry_t *src = &payload.entries[i];
        if (src->id && strcmp(src->id, entry_id) == 0)
        {
            found = true;
            continue;
        }

        rc = pm_payload_append_entry(&updated, src);
        if (rc != PM_OK)
        {
            pm_payload_free(&updated);
            pm_payload_free(&payload);
            return rc;
        }
    }

    pm_payload_free(&payload);

    if (!found)
    {
        pm_payload_free(&updated);
        return PM_ERR_NOT_FOUND;
    }

    rc = pm_vault_set_payload_model(h, &updated);
    pm_payload_free(&updated);
    return rc;
}

pm_error_t pm_vault_entry_list_ids(const pm_vault_handle_t *h,
                                   char ***out_ids,
                                   size_t *out_count)
{
    pm_payload_t payload;

    if (!h || !out_ids || !out_count)
    {
        return PM_ERR_INVALID_PARAM;
    }

    pm_error_t rc = load_payload(h, &payload);
    if (rc != PM_OK)
    {
        return rc;
    }

    rc = collect_ids_filtered(&payload, entry_match_all, NULL, out_ids, out_count);
    pm_payload_free(&payload);
    return rc;
}

pm_error_t pm_vault_entry_find_title_contains(const pm_vault_handle_t *h,
                                              const char *needle,
                                              char ***out_ids,
                                              size_t *out_count)
{
    pm_payload_t payload;

    if (!h || !needle || !out_ids || !out_count)
    {
        return PM_ERR_INVALID_PARAM;
    }

    pm_error_t rc = load_payload(h, &payload);
    if (rc != PM_OK)
    {
        return rc;
    }

    rc = collect_ids_filtered(&payload, entry_match_title_contains, needle, out_ids, out_count);
    pm_payload_free(&payload);
    return rc;
}

pm_error_t pm_vault_entry_list_by_group_id(const pm_vault_handle_t *h,
                                           const char *group_id,
                                           char ***out_ids,
                                           size_t *out_count)
{
    return pm_vault_entry_list_by_group_scope(h,
                                              group_id,
                                              false,
                                              out_ids,
                                              out_count);
}

pm_error_t pm_vault_entry_list_by_group_scope(const pm_vault_handle_t *h,
                                              const char *group_id,
                                              bool include_descendants,
                                              char ***out_ids,
                                              size_t *out_count)
{
    pm_payload_t payload;
    char **ids = NULL;
    size_t count = 0;

    if (!h || !group_id || !out_ids || !out_count)
    {
        return PM_ERR_INVALID_PARAM;
    }

    pm_error_t rc = load_payload(h, &payload);
    if (rc != PM_OK)
    {
        return rc;
    }

    if (payload.entry_count > 0)
    {
        ids = calloc(payload.entry_count, sizeof(char *));
        if (!ids)
        {
            pm_payload_free(&payload);
            return PM_ERR_NOMEM;
        }
    }

    for (size_t i = 0; i < payload.entry_count; i++)
    {
        const pm_entry_t *e = &payload.entries[i];
        const char *entry_group_id = e->group_id ? e->group_id : "";
        const char *id = e->id ? e->id : "";

        if (!group_in_scope(&payload, entry_group_id, group_id, include_descendants))
        {
            continue;
        }

        ids[count] = dup_cstr(id);
        if (!ids[count])
        {
            pm_vault_entry_id_list_free(ids, count);
            pm_payload_free(&payload);
            return PM_ERR_NOMEM;
        }
        count++;
    }

    pm_payload_free(&payload);
    *out_ids = ids;
    *out_count = count;
    return PM_OK;
}

pm_error_t pm_vault_entry_list_favorites(const pm_vault_handle_t *h,
                                         char ***out_ids,
                                         size_t *out_count)
{
    pm_payload_t payload;

    if (!h || !out_ids || !out_count)
    {
        return PM_ERR_INVALID_PARAM;
    }

    pm_error_t rc = load_payload(h, &payload);
    if (rc != PM_OK)
    {
        return rc;
    }

    rc = collect_ids_filtered(&payload, entry_match_favorite, NULL, out_ids, out_count);
    pm_payload_free(&payload);
    return rc;
}
