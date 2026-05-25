/*
 * pm_security_audit.c - Security audit and breach detection system
 *
 * Copyright (C) 2026 BioAuth Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "pm/pm_security_audit.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>

#include "crypto/bio_crypto.h"
#include "pm/pm_entry_store.h"
#include "pm/pm_hibp.h"
#include "pm/pm_payload.h"
#include "pm/pm_password_gen.h"

/* Severity level names */
const char *PM_SEVERITY_NAMES[] = {
    "Info",
    "Low",
    "Medium",
    "High",
    "Critical"};

/* Issue type descriptions */
const char *PM_ISSUE_TYPE_DESCRIPTIONS[] = {
    "Unknown",
    "Weak password below strength threshold",
    "Password reused across multiple entries",
    "Exact password duplicates found",
    "Password found in breach database",
    "Password not changed recently",
    "Account missing multi-factor authentication",
    "Insecure HTTP site connection",
    "Password in common password list",
    "Password follows simple pattern",
    "Password below minimum length",
    "Password lacks special characters",
    "Password follows keyboard pattern",
    "Password has sequential characters",
    "Password has repeated characters"};

/* Common keyboard patterns */
static const char *KEYBOARD_PATTERNS[] = {
    "qwerty", "asdf", "zxcv", "123", "abc", "qaz", "wsx", "edc",
    "rfv", "tgb", "yhn", "ujm", "ik", "ol", "p;", "mnb", "vcx"};

pm_error_t pm_audit_config_create_default(pm_audit_config_t **config)
{
    if (!config)
    {
        return PM_ERR_INVALID_PARAM;
    }

    pm_audit_config_t *c = calloc(1, sizeof(pm_audit_config_t));
    if (!c)
    {
        return PM_ERR_NOMEM;
    }

    c->min_password_length = PM_DEFAULT_MIN_PASSWORD_LENGTH;
    c->min_strength_score = PM_DEFAULT_MIN_STRENGTH_SCORE;
    c->max_password_age_days = PM_DEFAULT_MAX_PASSWORD_AGE_DAYS;
    c->check_breaches = false; /* Disabled by default - requires breach DB */
    c->check_common_passwords = true;
    c->check_keyboard_patterns = true;
    c->check_sequential_chars = true;
    c->check_repeated_chars = true;

    *config = c;
    return PM_OK;
}

void pm_audit_config_free(pm_audit_config_t *config)
{
    if (!config)
    {
        return;
    }

    free(config->breach_db_path);
    free(config->common_passwords_path);
    free(config);
}

static pm_error_t create_security_issue(pm_security_issue_type_t type,
                                        pm_security_severity_t severity,
                                        const char *entry_id,
                                        const char *entry_title,
                                        const char *description,
                                        const char *recommendation,
                                        uint32_t score_impact,
                                        pm_security_issue_t **issue)
{
    if (!issue)
    {
        return PM_ERR_INVALID_PARAM;
    }

    pm_security_issue_t *i = calloc(1, sizeof(pm_security_issue_t));
    if (!i)
    {
        return PM_ERR_NOMEM;
    }

    i->type = type;
    i->severity = severity;
    i->entry_id = entry_id ? strdup(entry_id) : NULL;
    i->entry_title = entry_title ? strdup(entry_title) : NULL;
    i->description = description ? strdup(description) : NULL;
    i->recommendation = recommendation ? strdup(recommendation) : NULL;
    i->detected = time(NULL);
    i->score_impact = score_impact;

    *issue = i;
    return PM_OK;
}

static void free_security_issue(pm_security_issue_t *issue)
{
    if (!issue)
    {
        return;
    }

    free(issue->entry_id);
    free(issue->entry_title);
    free(issue->description);
    free(issue->recommendation);
    free(issue->metadata);
    free(issue);
}

pm_error_t pm_detect_keyboard_pattern(const char *password, bool *has_pattern)
{
    if (!password || !has_pattern)
    {
        return PM_ERR_INVALID_PARAM;
    }

    *has_pattern = false;

    /* Convert password to lowercase for pattern matching */
    size_t len = strlen(password);
    char *lower_pwd = malloc(len + 1);
    if (!lower_pwd)
    {
        return PM_ERR_NOMEM;
    }

    for (size_t i = 0; i < len; i++)
    {
        lower_pwd[i] = tolower(password[i]);
    }
    lower_pwd[len] = '\0';

    /* Check against known keyboard patterns */
    for (size_t i = 0; i < sizeof(KEYBOARD_PATTERNS) / sizeof(KEYBOARD_PATTERNS[0]); i++)
    {
        if (strstr(lower_pwd, KEYBOARD_PATTERNS[i]))
        {
            *has_pattern = true;
            break;
        }
    }

    /* Check for sequential keyboard rows */
    const char *qwerty_rows[] = {
        "qwertyuiop",
        "asdfghjkl",
        "zxcvbnm",
        "1234567890"};

    for (size_t i = 0; i < 4; i++)
    {
        const char *row = qwerty_rows[i];
        for (size_t j = 0; j < strlen(row) - 2; j++)
        {
            char pattern[4] = {row[j], row[j + 1], row[j + 2], '\0'};
            if (strstr(lower_pwd, pattern))
            {
                *has_pattern = true;
                break;
            }
        }
    }

    free(lower_pwd);
    return PM_OK;
}

pm_error_t pm_detect_sequential_chars(const char *password,
                                      uint32_t min_length,
                                      bool *has_seq)
{
    if (!password || !has_seq || min_length < 2)
    {
        return PM_ERR_INVALID_PARAM;
    }

    *has_seq = false;
    size_t len = strlen(password);

    if (len < min_length)
    {
        return PM_OK;
    }

    for (size_t i = 0; i <= len - min_length; i++)
    {
        bool is_sequential = true;

        /* Check ascending sequence */
        for (uint32_t j = 1; j < min_length; j++)
        {
            if (password[i + j] != password[i + j - 1] + 1)
            {
                is_sequential = false;
                break;
            }
        }

        if (is_sequential)
        {
            *has_seq = true;
            return PM_OK;
        }

        /* Check descending sequence */
        is_sequential = true;
        for (uint32_t j = 1; j < min_length; j++)
        {
            if (password[i + j] != password[i + j - 1] - 1)
            {
                is_sequential = false;
                break;
            }
        }

        if (is_sequential)
        {
            *has_seq = true;
            return PM_OK;
        }
    }

    return PM_OK;
}

pm_error_t pm_detect_repeated_chars(const char *password,
                                    uint32_t min_count,
                                    bool *has_repeat)
{
    if (!password || !has_repeat || min_count < 2)
    {
        return PM_ERR_INVALID_PARAM;
    }

    *has_repeat = false;
    size_t len = strlen(password);

    if (len < min_count)
    {
        return PM_OK;
    }

    for (size_t i = 0; i <= len - min_count; i++)
    {
        char c = password[i];
        uint32_t count = 1;

        for (size_t j = i + 1; j < len && password[j] == c; j++)
        {
            count++;
        }

        if (count >= min_count)
        {
            *has_repeat = true;
            return PM_OK;
        }
    }

    return PM_OK;
}

pm_error_t pm_check_common_password(const char *password,
                                    const char *list_path,
                                    bool *found)
{
    if (!password || !found)
    {
        return PM_ERR_INVALID_PARAM;
    }

    *found = false;

    /* Built-in common passwords check (simplified) */
    const char *common_passwords[] = {
        "password", "123456", "password123", "admin", "qwerty",
        "letmein", "welcome", "monkey", "1234567890", "abc123",
        "password1", "123123", "000000", "iloveyou", "1234567",
        "superman", "trustno1", "hello", "dragon", "freedom"};

    for (size_t i = 0; i < sizeof(common_passwords) / sizeof(common_passwords[0]); i++)
    {
        if (strcasecmp(password, common_passwords[i]) == 0)
        {
            *found = true;
            return PM_OK;
        }
    }

    /* If list path provided, check external file */
    if (list_path)
    {
        FILE *f = fopen(list_path, "r");
        if (f)
        {
            char line[256];
            while (fgets(line, sizeof(line), f))
            {
                /* Remove newline */
                line[strcspn(line, "\r\n")] = '\0';

                if (strcasecmp(password, line) == 0)
                {
                    *found = true;
                    break;
                }
            }
            fclose(f);
        }
    }

    return PM_OK;
}

pm_error_t pm_check_password_breach(const char *password,
                                    const char *db_path,
                                    bool *found)
{
    if (!password || !found)
    {
        return PM_ERR_INVALID_PARAM;
    }

    (void)db_path;
    *found = false;

    pm_hibp_result_t result = pm_hibp_check_password(password, strlen(password));
    if (result.status == PM_OK)
    {
        *found = result.found_in_breach;
    }

    return result.status;
}

static pm_error_t audit_entry_password(const char *password,
                                       const char *entry_id,
                                       const char *entry_title,
                                       const pm_audit_config_t *config,
                                       pm_security_issue_t ***issues,
                                       size_t *issue_count)
{
    if (!password || !entry_id || !config || !issues || !issue_count)
    {
        return PM_ERR_INVALID_PARAM;
    }

    pm_security_issue_t **issue_list = *issues;
    size_t count = *issue_count;

    /* Check password length */
    if (strlen(password) < config->min_password_length)
    {
        pm_security_issue_t *issue = NULL;
        char desc[256];
        snprintf(desc, sizeof(desc),
                 "Password is only %zu characters, minimum is %u",
                 strlen(password), config->min_password_length);

        create_security_issue(PM_ISSUE_SHORT_PASSWORD, PM_SEVERITY_MEDIUM,
                              entry_id, entry_title, desc,
                              "Use a longer password with more entropy",
                              15, &issue);

        issue_list = realloc(issue_list, (count + 1) * sizeof(pm_security_issue_t *));
        if (issue_list)
        {
            issue_list[count++] = issue;
        }
    }

    /* Check password strength */
    pm_password_strength_t *strength = NULL;
    if (pm_password_assess_strength(password, &strength) == PM_OK)
    {
        if (strength->score < config->min_strength_score)
        {
            pm_security_issue_t *issue = NULL;
            char desc[256];
            snprintf(desc, sizeof(desc),
                     "Password strength score %u is below minimum %u",
                     strength->score, config->min_strength_score);

            create_security_issue(PM_ISSUE_WEAK_PASSWORD, PM_SEVERITY_HIGH,
                                  entry_id, entry_title, desc,
                                  "Generate a stronger password with mixed character types",
                                  20, &issue);

            issue_list = realloc(issue_list, (count + 1) * sizeof(pm_security_issue_t *));
            if (issue_list)
            {
                issue_list[count++] = issue;
            }
        }

        if (!strength->has_symbols)
        {
            pm_security_issue_t *issue = NULL;
            create_security_issue(PM_ISSUE_NO_SYMBOLS, PM_SEVERITY_LOW,
                                  entry_id, entry_title,
                                  "Password lacks special characters",
                                  "Add special characters for better security",
                                  5, &issue);

            issue_list = realloc(issue_list, (count + 1) * sizeof(pm_security_issue_t *));
            if (issue_list)
            {
                issue_list[count++] = issue;
            }
        }

        pm_password_strength_free(strength);
    }

    /* Check for common passwords */
    if (config->check_common_passwords)
    {
        bool is_common = false;
        if (pm_check_common_password(password, config->common_passwords_path, &is_common) == PM_OK && is_common)
        {
            pm_security_issue_t *issue = NULL;
            create_security_issue(PM_ISSUE_COMMON_PASSWORD, PM_SEVERITY_HIGH,
                                  entry_id, entry_title,
                                  "Password found in common password list",
                                  "Choose a unique password not in common lists",
                                  25, &issue);

            issue_list = realloc(issue_list, (count + 1) * sizeof(pm_security_issue_t *));
            if (issue_list)
            {
                issue_list[count++] = issue;
            }
        }
    }

    /* Check for keyboard patterns */
    if (config->check_keyboard_patterns)
    {
        bool has_pattern = false;
        if (pm_detect_keyboard_pattern(password, &has_pattern) == PM_OK && has_pattern)
        {
            pm_security_issue_t *issue = NULL;
            create_security_issue(PM_ISSUE_KEYBOARD_PATTERN, PM_SEVERITY_MEDIUM,
                                  entry_id, entry_title,
                                  "Password contains keyboard patterns",
                                  "Avoid using keyboard patterns like 'qwerty' or '123'",
                                  10, &issue);

            issue_list = realloc(issue_list, (count + 1) * sizeof(pm_security_issue_t *));
            if (issue_list)
            {
                issue_list[count++] = issue;
            }
        }
    }

    /* Check for sequential characters */
    if (config->check_sequential_chars)
    {
        bool has_seq = false;
        if (pm_detect_sequential_chars(password, 3, &has_seq) == PM_OK && has_seq)
        {
            pm_security_issue_t *issue = NULL;
            create_security_issue(PM_ISSUE_SEQUENTIAL_CHARS, PM_SEVERITY_LOW,
                                  entry_id, entry_title,
                                  "Password contains sequential characters",
                                  "Avoid sequences like 'abc' or '123' in passwords",
                                  5, &issue);

            issue_list = realloc(issue_list, (count + 1) * sizeof(pm_security_issue_t *));
            if (issue_list)
            {
                issue_list[count++] = issue;
            }
        }
    }

    /* Check for repeated characters */
    if (config->check_repeated_chars)
    {
        bool has_repeat = false;
        if (pm_detect_repeated_chars(password, 3, &has_repeat) == PM_OK && has_repeat)
        {
            pm_security_issue_t *issue = NULL;
            create_security_issue(PM_ISSUE_REPEATED_CHARS, PM_SEVERITY_LOW,
                                  entry_id, entry_title,
                                  "Password contains repeated characters",
                                  "Avoid repeating the same character multiple times",
                                  5, &issue);

            issue_list = realloc(issue_list, (count + 1) * sizeof(pm_security_issue_t *));
            if (issue_list)
            {
                issue_list[count++] = issue;
            }
        }
    }

    /* Check breach database */
    if (config->check_breaches)
    {
        bool is_breached = false;
        pm_error_t hibp_rc = pm_check_password_breach(password,
                                                      config->breach_db_path,
                                                      &is_breached);

        if (hibp_rc == PM_OK && is_breached)
        {
            pm_security_issue_t *issue = NULL;
            create_security_issue(PM_ISSUE_COMPROMISED_PASSWORD, PM_SEVERITY_CRITICAL,
                                  entry_id, entry_title,
                                  "Password found in known data breaches",
                                  "Change this password immediately - it has been compromised",
                                  50, &issue);

            issue_list = realloc(issue_list, (count + 1) * sizeof(pm_security_issue_t *));
            if (issue_list)
            {
                issue_list[count++] = issue;
            }
        }
        else if (hibp_rc != PM_OK &&
                 hibp_rc != PM_ERR_HIBP_UNAVAILABLE &&
                 hibp_rc != PM_ERR_NETWORK)
        {
            return hibp_rc;
        }
    }

    *issues = issue_list;
    *issue_count = count;
    return PM_OK;
}

static int issue_sort_desc(const void *lhs, const void *rhs)
{
    const pm_security_issue_t *const *a = lhs;
    const pm_security_issue_t *const *b = rhs;

    if (!a || !b || !*a || !*b)
    {
        return 0;
    }

    if ((*a)->severity != (*b)->severity)
    {
        return (int)(*b)->severity - (int)(*a)->severity;
    }

    return (int)(*b)->score_impact - (int)(*a)->score_impact;
}

static void finalize_audit(pm_security_audit_t *audit)
{
    if (!audit)
    {
        return;
    }

    audit->issues_found = (uint32_t)audit->issue_count;
    audit->critical_issues = 0;
    audit->high_issues = 0;
    audit->medium_issues = 0;
    audit->low_issues = 0;

    uint32_t penalty = 0;

    for (size_t i = 0; i < audit->issue_count; i++)
    {
        if (!audit->issues[i])
        {
            continue;
        }

        switch (audit->issues[i]->severity)
        {
        case PM_SEVERITY_CRITICAL:
            audit->critical_issues++;
            break;
        case PM_SEVERITY_HIGH:
            audit->high_issues++;
            break;
        case PM_SEVERITY_MEDIUM:
            audit->medium_issues++;
            break;
        case PM_SEVERITY_LOW:
            audit->low_issues++;
            break;
        default:
            break;
        }

        penalty += audit->issues[i]->score_impact;
    }

    audit->overall_score = (penalty >= 100u) ? 0u : (100u - penalty);

    if (audit->issue_count > 1)
    {
        qsort(audit->issues,
              audit->issue_count,
              sizeof(pm_security_issue_t *),
              issue_sort_desc);
    }
}

static void free_issue_list(pm_security_issue_t **issues, size_t issue_count)
{
    if (!issues)
    {
        return;
    }

    for (size_t i = 0; i < issue_count; i++)
    {
        free_security_issue(issues[i]);
    }

    free(issues);
}

pm_error_t pm_security_audit_perform(const void *entries, size_t count,
                                     const pm_audit_config_t *config,
                                     pm_security_audit_t **audit)
{
    if (!entries || !config || !audit)
    {
        return PM_ERR_INVALID_PARAM;
    }

    pm_security_audit_t *a = calloc(1, sizeof(pm_security_audit_t));
    if (!a)
    {
        return PM_ERR_NOMEM;
    }

    a->entries_audited = (uint32_t)count;
    a->generated = time(NULL);

    pm_security_issue_t **issues = NULL;
    size_t issue_count = 0;

    const pm_entry_t *entry_list = (const pm_entry_t *)entries;

    for (size_t i = 0; i < count; i++)
    {
        const pm_entry_t *entry = &entry_list[i];
        const char *entry_id = entry->id ? entry->id : "";
        const char *entry_title = entry->title ? entry->title : "";
        const char *entry_password = entry->password ? entry->password : "";

        pm_error_t rc = audit_entry_password(entry_password,
                                             entry_id,
                                             entry_title,
                                             config,
                                             &issues,
                                             &issue_count);
        if (rc != PM_OK)
        {
            free_issue_list(issues, issue_count);
            free(a);
            return rc;
        }
    }

    a->issues = issues;
    a->issue_count = issue_count;
    finalize_audit(a);

    *audit = a;
    return PM_OK;
}

pm_error_t pm_security_audit_run(pm_vault_handle_t *vault,
                                 const pm_audit_config_t *config,
                                 pm_security_audit_t **audit)
{
    pm_entry_iterator_t *it = NULL;
    pm_security_audit_t *a = NULL;
    pm_security_issue_t **issues = NULL;
    size_t issue_count = 0;
    size_t entries_audited = 0;

    if (!vault || !config || !audit)
    {
        return PM_ERR_INVALID_PARAM;
    }

    a = calloc(1, sizeof(pm_security_audit_t));
    if (!a)
    {
        return PM_ERR_NOMEM;
    }

    a->generated = time(NULL);

    it = pm_vault_store_begin(vault);
    if (!it)
    {
        free(a);
        return PM_ERR_IO;
    }

    pm_entry_t *entry = NULL;
    while ((entry = pm_entry_iterator_next(it)) != NULL)
    {
        const char *entry_id = entry->id ? entry->id : "";
        const char *entry_title = entry->title ? entry->title : "";
        const char *entry_password = entry->password ? entry->password : "";

        pm_error_t rc = audit_entry_password(entry_password,
                                             entry_id,
                                             entry_title,
                                             config,
                                             &issues,
                                             &issue_count);
        if (rc != PM_OK)
        {
            pm_entry_iterator_free(it);
            free_issue_list(issues, issue_count);
            free(a);
            return rc;
        }

        entries_audited++;
    }

    pm_entry_iterator_free(it);

    a->entries_audited = (uint32_t)entries_audited;
    a->issues = issues;
    a->issue_count = issue_count;
    finalize_audit(a);

    *audit = a;
    return PM_OK;
}

void pm_security_audit_free(pm_security_audit_t *audit)
{
    if (!audit)
    {
        return;
    }

    for (size_t i = 0; i < audit->issue_count; i++)
    {
        free_security_issue(audit->issues[i]);
    }
    free(audit->issues);

    for (size_t i = 0; i < audit->duplicate_group_count; i++)
    {
        free(audit->duplicates[i].password_hash);
        for (size_t j = 0; j < audit->duplicates[i].entry_count; j++)
        {
            free(audit->duplicates[i].entry_ids[j]);
        }
        free(audit->duplicates[i].entry_ids);
    }
    free(audit->duplicates);

    for (size_t i = 0; i < audit->recommendation_count; i++)
    {
        free(audit->recommendations[i]);
    }
    free(audit->recommendations);

    free(audit);
}

pm_error_t pm_calculate_security_score(const void *entries, size_t count,
                                       const pm_audit_config_t *config,
                                       uint32_t *score)
{
    if (!entries || !config || !score)
    {
        return PM_ERR_INVALID_PARAM;
    }

    pm_security_audit_t *audit = NULL;
    pm_error_t ret = pm_security_audit_perform(entries, count, config, &audit);
    if (ret != PM_OK)
    {
        return ret;
    }

    *score = audit->overall_score;
    pm_security_audit_free(audit);

    return PM_OK;
}

pm_error_t pm_audit_export_json(const pm_security_audit_t *audit,
                                char **json_str)
{
    if (!audit || !json_str)
    {
        return PM_ERR_INVALID_PARAM;
    }

    /* Simplified JSON export - in a real implementation would use a JSON library */
    size_t json_size = 4096 + (audit->issue_count * 512);
    char *json = malloc(json_size);
    if (!json)
    {
        return PM_ERR_NOMEM;
    }

    int offset = 0;
    offset += snprintf(json + offset, json_size - offset,
                       "{\n"
                       "  \"overall_score\": %u,\n"
                       "  \"entries_audited\": %u,\n"
                       "  \"issues_found\": %u,\n"
                       "  \"critical_issues\": %u,\n"
                       "  \"high_issues\": %u,\n"
                       "  \"medium_issues\": %u,\n"
                       "  \"low_issues\": %u,\n"
                       "  \"generated\": %ld,\n"
                       "  \"issues\": [\n",
                       audit->overall_score,
                       audit->entries_audited,
                       audit->issues_found,
                       audit->critical_issues,
                       audit->high_issues,
                       audit->medium_issues,
                       audit->low_issues,
                       (long)audit->generated);

    for (size_t i = 0; i < audit->issue_count; i++)
    {
        pm_security_issue_t *issue = audit->issues[i];
        offset += snprintf(json + offset, json_size - offset,
                           "    {\n"
                           "      \"type\": %d,\n"
                           "      \"severity\": %d,\n"
                           "      \"entry_id\": \"%s\",\n"
                           "      \"entry_title\": \"%s\",\n"
                           "      \"description\": \"%s\",\n"
                           "      \"recommendation\": \"%s\",\n"
                           "      \"score_impact\": %u\n"
                           "    }%s\n",
                           issue->type,
                           issue->severity,
                           issue->entry_id ? issue->entry_id : "",
                           issue->entry_title ? issue->entry_title : "",
                           issue->description ? issue->description : "",
                           issue->recommendation ? issue->recommendation : "",
                           issue->score_impact,
                           (i < audit->issue_count - 1) ? "," : "");
    }

    offset += snprintf(json + offset, json_size - offset, "  ]\n}\n");

    *json_str = json;
    return PM_OK;
}