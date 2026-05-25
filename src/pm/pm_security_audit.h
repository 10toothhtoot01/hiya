/*
 * pm_security_audit.h - Security audit and breach detection system
 *
 * Copyright (C) 2026 BioAuth Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef PM_SECURITY_AUDIT_H
#define PM_SECURITY_AUDIT_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#include "pm/pm_errors.h"
#include "pm/pm_vault_store.h"

#ifdef __cplusplus
extern "C"
{
#endif

    /* Security issue severity levels */
    typedef enum
    {
        PM_SEVERITY_INFO = 0,     /* Informational */
        PM_SEVERITY_LOW = 1,      /* Low risk */
        PM_SEVERITY_MEDIUM = 2,   /* Medium risk */
        PM_SEVERITY_HIGH = 3,     /* High risk */
        PM_SEVERITY_CRITICAL = 4, /* Critical risk */
    } pm_security_severity_t;

    /* Security issue types */
    typedef enum
    {
        PM_ISSUE_WEAK_PASSWORD = 1,        /* Password below strength threshold */
        PM_ISSUE_REUSED_PASSWORD = 2,      /* Password used in multiple entries */
        PM_ISSUE_DUPLICATE_PASSWORD = 3,   /* Exact password duplicates */
        PM_ISSUE_COMPROMISED_PASSWORD = 4, /* Password found in breach database */
        PM_ISSUE_OLD_PASSWORD = 5,         /* Password not changed recently */
        PM_ISSUE_NO_MFA = 6,               /* Account without multi-factor auth */
        PM_ISSUE_INSECURE_SITE = 7,        /* HTTP site (no HTTPS) */
        PM_ISSUE_COMMON_PASSWORD = 8,      /* Password in common password list */
        PM_ISSUE_SIMPLE_PATTERN = 9,       /* Password follows simple pattern */
        PM_ISSUE_SHORT_PASSWORD = 10,      /* Password below minimum length */
        PM_ISSUE_NO_SYMBOLS = 11,          /* Password lacks special characters */
        PM_ISSUE_KEYBOARD_PATTERN = 12,    /* Password follows keyboard pattern */
        PM_ISSUE_SEQUENTIAL_CHARS = 13,    /* Password has sequential characters */
        PM_ISSUE_REPEATED_CHARS = 14,      /* Password has repeated characters */
    } pm_security_issue_type_t;

    /* Security issue entry */
    typedef struct
    {
        pm_security_issue_type_t type;   /* Issue type */
        pm_security_severity_t severity; /* Severity level */
        char *entry_id;                  /* Affected entry ID */
        char *entry_title;               /* Human-readable entry name */
        char *description;               /* Issue description */
        char *recommendation;            /* Recommended action */
        time_t detected;                 /* When issue was detected */
        uint32_t score_impact;           /* Impact on security score */
        void *metadata;                  /* Type-specific metadata */
    } pm_security_issue_t;

    /* Duplicate password group */
    typedef struct
    {
        char *password_hash;     /* SHA256 hash of password */
        char **entry_ids;        /* Array of entry IDs using this password */
        size_t entry_count;      /* Number of entries */
        uint32_t strength_score; /* Password strength score */
    } pm_duplicate_group_t;

    /* Security audit report */
    typedef struct
    {
        uint32_t overall_score;   /* Overall security score (0-100) */
        uint32_t entries_audited; /* Number of entries audited */
        uint32_t issues_found;    /* Total issues found */
        uint32_t critical_issues; /* Critical severity issues */
        uint32_t high_issues;     /* High severity issues */
        uint32_t medium_issues;   /* Medium severity issues */
        uint32_t low_issues;      /* Low severity issues */

        /* Issue breakdown */
        pm_security_issue_t **issues; /* Array of pointers to security issues */
        size_t issue_count;           /* Number of issues */

        /* Duplicate password analysis */
        pm_duplicate_group_t *duplicates; /* Array of duplicate groups */
        size_t duplicate_group_count;     /* Number of duplicate groups */

        /* Statistics */
        uint32_t weak_passwords;        /* Count of weak passwords */
        uint32_t reused_passwords;      /* Count of reused passwords */
        uint32_t compromised_passwords; /* Count of compromised passwords */
        uint32_t old_passwords;         /* Count of old passwords */

        /* Recommendations */
        char **recommendations;      /* Array of security recommendations */
        size_t recommendation_count; /* Number of recommendations */

        time_t generated; /* When report was generated */
    } pm_security_audit_t;

    /* Audit configuration */
    typedef struct
    {
        uint32_t min_password_length;   /* Minimum acceptable password length */
        uint32_t min_strength_score;    /* Minimum strength score */
        uint32_t max_password_age_days; /* Maximum password age in days */
        bool check_breaches;            /* Check against breach databases */
        bool check_common_passwords;    /* Check against common password lists */
        bool check_keyboard_patterns;   /* Check for keyboard patterns */
        bool check_sequential_chars;    /* Check for sequential characters */
        bool check_repeated_chars;      /* Check for repeated characters */
        char *breach_db_path;           /* Path to breach database */
        char *common_passwords_path;    /* Path to common passwords list */
    } pm_audit_config_t;

    /**
     * Create default audit configuration.
     *
     * @param config     Output: initialized configuration (caller must free)
     * @return PM_OK on success, PM_ERR_* on failure
     */
    pm_error_t pm_audit_config_create_default(pm_audit_config_t **config);

    /**
     * Free audit configuration.
     */
    void pm_audit_config_free(pm_audit_config_t *config);

    /**
     * Perform comprehensive security audit on vault entries.
     *
     * @param entries    Array of vault entries to audit
     * @param count      Number of entries
     * @param config     Audit configuration
     * @param audit      Output: audit report (caller must free)
     * @return PM_OK on success, PM_ERR_* on failure
     */
    pm_error_t pm_security_audit_perform(const void *entries, size_t count,
                                         const pm_audit_config_t *config,
                                         pm_security_audit_t **audit);

    /**
     * Perform security audit over all entries stored in an unlocked vault.
     *
     * @param vault      Unlocked vault handle
     * @param config     Audit configuration
     * @param audit      Output: audit report (caller must free)
     * @return PM_OK on success, PM_ERR_* on failure
     */
    pm_error_t pm_security_audit_run(pm_vault_handle_t *vault,
                                     const pm_audit_config_t *config,
                                     pm_security_audit_t **audit);

    /**
     * Free security audit report.
     */
    void pm_security_audit_free(pm_security_audit_t *audit);

    /**
     * Check if password is compromised in breach database.
     *
     * @param password   Password to check
     * @param db_path    Path to breach database file
     * @param found      Output: true if password is compromised
     * @return PM_OK on success, PM_ERR_* on failure
     */
    pm_error_t pm_check_password_breach(const char *password,
                                        const char *db_path,
                                        bool *found);

    /**
     * Check if password is in common password list.
     *
     * @param password   Password to check
     * @param list_path  Path to common passwords file
     * @param found      Output: true if password is common
     * @return PM_OK on success, PM_ERR_* on failure
     */
    pm_error_t pm_check_common_password(const char *password,
                                        const char *list_path,
                                        bool *found);

    /**
     * Detect keyboard patterns in password.
     *
     * @param password   Password to analyze
     * @param has_pattern Output: true if keyboard pattern detected
     * @return PM_OK on success, PM_ERR_* on failure
     */
    pm_error_t pm_detect_keyboard_pattern(const char *password, bool *has_pattern);

    /**
     * Detect sequential characters in password.
     *
     * @param password   Password to analyze
     * @param min_length Minimum sequence length to detect
     * @param has_seq    Output: true if sequential chars detected
     * @return PM_OK on success, PM_ERR_* on failure
     */
    pm_error_t pm_detect_sequential_chars(const char *password,
                                          uint32_t min_length,
                                          bool *has_seq);

    /**
     * Detect repeated characters in password.
     *
     * @param password   Password to analyze
     * @param min_count  Minimum repetition count to detect
     * @param has_repeat Output: true if repeated chars detected
     * @return PM_OK on success, PM_ERR_* on failure
     */
    pm_error_t pm_detect_repeated_chars(const char *password,
                                        uint32_t min_count,
                                        bool *has_repeat);

    /**
     * Find duplicate passwords across entries.
     *
     * @param entries    Array of vault entries
     * @param count      Number of entries
     * @param duplicates Output: array of duplicate groups (caller must free)
     * @param group_count Output: number of duplicate groups
     * @return PM_OK on success, PM_ERR_* on failure
     */
    pm_error_t pm_find_duplicate_passwords(const void *entries, size_t count,
                                           pm_duplicate_group_t **duplicates,
                                           size_t *group_count);

    /**
     * Generate security recommendations based on audit results.
     *
     * @param audit      Security audit report
     * @param recommendations Output: array of recommendations (caller must free)
     * @param count      Output: number of recommendations
     * @return PM_OK on success, PM_ERR_* on failure
     */
    pm_error_t pm_generate_security_recommendations(const pm_security_audit_t *audit,
                                                    char ***recommendations,
                                                    size_t *count);

    /**
     * Calculate security score for vault.
     *
     * @param entries    Array of vault entries
     * @param count      Number of entries
     * @param config     Audit configuration
     * @param score      Output: security score (0-100)
     * @return PM_OK on success, PM_ERR_* on failure
     */
    pm_error_t pm_calculate_security_score(const void *entries, size_t count,
                                           const pm_audit_config_t *config,
                                           uint32_t *score);

    /**
     * Export audit report to JSON format.
     *
     * @param audit      Security audit report
     * @param json_str   Output: JSON string (caller must free)
     * @return PM_OK on success, PM_ERR_* on failure
     */
    pm_error_t pm_audit_export_json(const pm_security_audit_t *audit,
                                    char **json_str);

    /**
     * Export audit report to CSV format.
     *
     * @param audit      Security audit report
     * @param csv_str    Output: CSV string (caller must free)
     * @return PM_OK on success, PM_ERR_* on failure
     */
    pm_error_t pm_audit_export_csv(const pm_security_audit_t *audit,
                                   char **csv_str);

    /**
     * Schedule periodic security audits.
     *
     * @param interval_days Audit interval in days
     * @param config     Audit configuration
     * @param callback   Callback function for audit completion
     * @return PM_OK on success, PM_ERR_* on failure
     */
    pm_error_t pm_schedule_security_audit(uint32_t interval_days,
                                          const pm_audit_config_t *config,
                                          void (*callback)(const pm_security_audit_t *audit));

    /* Severity level names */
    extern const char *PM_SEVERITY_NAMES[];

    /* Issue type descriptions */
    extern const char *PM_ISSUE_TYPE_DESCRIPTIONS[];

/* Default audit configuration values */
#define PM_DEFAULT_MIN_PASSWORD_LENGTH 12
#define PM_DEFAULT_MIN_STRENGTH_SCORE 70
#define PM_DEFAULT_MAX_PASSWORD_AGE_DAYS 90

#ifdef __cplusplus
}
#endif

#endif /* PM_SECURITY_AUDIT_H */