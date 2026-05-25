/*
 * pm_entry_store.h - Entry CRUD helpers over unlocked vault payloads
 *
 * Copyright (C) 2026 BioAuth Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef PM_ENTRY_STORE_H
#define PM_ENTRY_STORE_H

#include <stdbool.h>

#include "pm/pm_payload.h"
#include "pm/pm_vault_store.h"

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct pm_entry_iterator pm_entry_iterator_t;

    pm_entry_iterator_t *pm_vault_store_begin(pm_vault_handle_t *vault);
    pm_entry_t *pm_entry_iterator_next(pm_entry_iterator_t *it);
    void pm_entry_iterator_free(pm_entry_iterator_t *it);

    pm_error_t pm_vault_entry_get(const pm_vault_handle_t *h,
                                  const char *entry_id,
                                  pm_entry_t *out_entry);

    pm_error_t pm_vault_entry_add(pm_vault_handle_t *h,
                                  const pm_entry_t *entry,
                                  bool fail_if_exists);

    pm_error_t pm_vault_entry_update(pm_vault_handle_t *h,
                                     const char *entry_id,
                                     const pm_entry_t *replacement);

    pm_error_t pm_vault_entry_remove(pm_vault_handle_t *h,
                                     const char *entry_id);

    pm_error_t pm_vault_entry_list_ids(const pm_vault_handle_t *h,
                                       char ***out_ids,
                                       size_t *out_count);

    pm_error_t pm_vault_entry_find_title_contains(const pm_vault_handle_t *h,
                                                  const char *needle,
                                                  char ***out_ids,
                                                  size_t *out_count);

    pm_error_t pm_vault_entry_list_by_group_id(const pm_vault_handle_t *h,
                                               const char *group_id,
                                               char ***out_ids,
                                               size_t *out_count);

    pm_error_t pm_vault_entry_list_by_group_scope(const pm_vault_handle_t *h,
                                                  const char *group_id,
                                                  bool include_descendants,
                                                  char ***out_ids,
                                                  size_t *out_count);

    pm_error_t pm_vault_entry_list_favorites(const pm_vault_handle_t *h,
                                             char ***out_ids,
                                             size_t *out_count);

    void pm_vault_entry_id_list_free(char **ids, size_t count);

#ifdef __cplusplus
}
#endif

#endif /* PM_ENTRY_STORE_H */
