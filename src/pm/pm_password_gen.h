/*
 * pm_password_gen.h - Password generator with configurable policies
 *
 * Copyright (C) 2026 Hiya Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef PM_PASSWORD_GEN_H
#define PM_PASSWORD_GEN_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "pm/pm_errors.h"

#ifdef __cplusplus
extern "C"
{
#endif

    /* Character sets for password generation */
    typedef enum
    {
        PM_CHARSET_NONE = 0x00,
        PM_CHARSET_LOWERCASE = 0x01, /* a-z */
        PM_CHARSET_UPPERCASE = 0x02, /* A-Z */
        PM_CHARSET_DIGITS = 0x04,    /* 0-9 */
        PM_CHARSET_SYMBOLS = 0x08,   /* !@#$%^&*()_+-=[]{}|;:,.<>? */
        PM_CHARSET_AMBIGUOUS = 0x10, /* 0O1Il| (easily confused) */
        PM_CHARSET_SPACE = 0x20,     /* Space character */
        PM_CHARSET_EXTENDED = 0x40,  /* Extended ASCII/Unicode */
    } pm_charset_flags_t;

/* Common character set combinations */
#define PM_CHARSET_ALPHA (PM_CHARSET_LOWERCASE | PM_CHARSET_UPPERCASE)
#define PM_CHARSET_ALPHANUM (PM_CHARSET_ALPHA | PM_CHARSET_DIGITS)
#define PM_CHARSET_ALL (PM_CHARSET_ALPHANUM | PM_CHARSET_SYMBOLS)
#define PM_CHARSET_SAFE (PM_CHARSET_ALL & ~PM_CHARSET_AMBIGUOUS)

    /* Password generation policy */
    typedef struct
    {
        uint32_t length;            /* Password length */
        pm_charset_flags_t charset; /* Character sets to use */
        uint32_t min_uppercase;     /* Minimum uppercase letters */
        uint32_t min_lowercase;     /* Minimum lowercase letters */
        uint32_t min_digits;        /* Minimum digits */
        uint32_t min_symbols;       /* Minimum symbols */
        bool exclude_ambiguous;     /* Exclude ambiguous characters */
        bool exclude_similar;       /* Exclude similar looking chars */
        bool require_all_charsets;  /* Require at least one from each enabled set */
        bool no_repeating;          /* No consecutive repeating characters */
        bool no_sequential;         /* No sequential characters (abc, 123) */
        char *custom_charset;       /* Custom character set (overrides flags) */
        char *excluded_chars;       /* Characters to exclude */
        char *required_chars;       /* Characters that must be included */
        uint32_t max_consecutive;   /* Max consecutive chars from same class */
        bool pronounceable;         /* Generate pronounceable passwords */
        bool start_with_letter;     /* Start with alphabetic character */
        bool end_with_letter;       /* End with alphabetic character */
    } pm_password_policy_t;

    /* Password strength assessment */
    typedef enum
    {
        PM_STRENGTH_VERY_WEAK = 0,
        PM_STRENGTH_WEAK = 1,
        PM_STRENGTH_FAIR = 2,
        PM_STRENGTH_STRONG = 3,
        PM_STRENGTH_VERY_STRONG = 4,
    } pm_strength_label_t;

    typedef struct
    {
        uint32_t score;        /* Overall strength score (0-100, derived from zxcvbn score) */
        uint32_t entropy_bits; /* Rounded entropy in bits */
        uint32_t charset_size; /* Character set size used */
        bool has_lowercase;    /* Contains lowercase letters */
        bool has_uppercase;    /* Contains uppercase letters */
        bool has_digits;       /* Contains digits */
        bool has_symbols;      /* Contains symbols */
        bool has_ambiguous;    /* Contains ambiguous characters */
        bool has_repeating;    /* Has repeating patterns */
        bool has_sequential;   /* Has sequential patterns */

        uint32_t zxcvbn_score;         /* Native zxcvbn score (0-4) */
        double entropy_estimate_bits;  /* Raw zxcvbn entropy estimate */
        double guesses_log10;          /* log10(guesses) estimate */
        pm_strength_label_t label;     /* Human-readable strength tier */
        char feedback[256];            /* Aggregated feedback */

        char *weakness_desc;   /* Description of weaknesses */
    } pm_password_strength_t;

    /* Passphrase generation options */
    typedef struct
    {
        uint32_t word_count;      /* Number of words */
        char *separator;          /* Word separator (default: -) */
        bool capitalize_words;    /* Capitalize first letter of each word */
        bool add_numbers;         /* Add numbers to words */
        bool add_symbols;         /* Add symbols to words */
        uint32_t min_word_length; /* Minimum word length */
        uint32_t max_word_length; /* Maximum word length */
        char *wordlist_path;      /* Path to custom wordlist */
    } pm_passphrase_options_t;

    /**
     * Create default password policy.
     *
     * @param policy     Output: initialized policy (caller must free)
     * @return PM_OK on success, PM_ERR_* on failure
     */
    pm_error_t pm_password_policy_create_default(pm_password_policy_t **policy);

    /**
     * Create password policy for specific requirements.
     */
    pm_error_t pm_password_policy_create_custom(pm_password_policy_t **policy,
                                                uint32_t length,
                                                pm_charset_flags_t charset,
                                                bool secure_defaults);

    /**
     * Free password policy.
     */
    void pm_password_policy_free(pm_password_policy_t *policy);

    /**
     * Generate password according to policy.
     *
     * @param policy     Password generation policy
     * @param password   Output: generated password (caller must free)
     * @return PM_OK on success, PM_ERR_* on failure
     */
    pm_error_t pm_password_generate(const pm_password_policy_t *policy, char **password);

    /**
     * Generate multiple passwords and return the strongest.
     *
     * @param policy     Password generation policy
     * @param count      Number of candidates to generate
     * @param password   Output: strongest password (caller must free)
     * @return PM_OK on success, PM_ERR_* on failure
     */
    pm_error_t pm_password_generate_best(const pm_password_policy_t *policy,
                                         uint32_t count,
                                         char **password);

    /**
     * Generate passphrase using word lists.
     *
     * @param options    Passphrase generation options
     * @param passphrase Output: generated passphrase (caller must free)
     * @return PM_OK on success, PM_ERR_* on failure
     */
    pm_error_t pm_passphrase_generate(const pm_passphrase_options_t *options,
                                      char **passphrase);

    /**
     * Assess password strength.
     *
     * @param password   Password to assess
     * @param strength   Output: strength assessment (caller must free)
     * @return PM_OK on success, PM_ERR_* on failure
     */
    pm_error_t pm_password_assess_strength(const char *password,
                                           pm_password_strength_t **strength);

    /**
     * Free password strength assessment.
     */
    void pm_password_strength_free(pm_password_strength_t *strength);

    /**
     * Check if password meets policy requirements.
     *
     * @param password   Password to check
     * @param policy     Policy to check against
     * @param errors     Output: description of policy violations (caller must free)
     * @return PM_OK if password meets policy, PM_ERR_* otherwise
     */
    pm_error_t pm_password_check_policy(const char *password,
                                        const pm_password_policy_t *policy,
                                        char **errors);

    /**
     * Generate PIN (numeric password).
     *
     * @param length     PIN length (4-12 digits)
     * @param pin        Output: generated PIN (caller must free)
     * @return PM_OK on success, PM_ERR_* on failure
     */
    pm_error_t pm_pin_generate(uint32_t length, char **pin);

    /**
     * Generate memorable password using patterns.
     *
     * @param pattern    Pattern string (e.g., "Llnn-Llnn" = Letter+letter+number+number-...)
     * @param password   Output: generated password (caller must free)
     * @return PM_OK on success, PM_ERR_* on failure
     */
    pm_error_t pm_password_generate_pattern(const char *pattern, char **password);

    /**
     * Get entropy estimate for character set and length.
     */
    uint32_t pm_password_entropy_bits(pm_charset_flags_t charset, uint32_t length);

    /**
     * Convert charset flags to character string.
     *
     * @param charset    Character set flags
     * @param charset_str Output: character string (caller must free)
     * @return PM_OK on success, PM_ERR_* on failure
     */
    pm_error_t pm_charset_to_string(pm_charset_flags_t charset, char **charset_str);

    /**
     * Time to crack password estimate (in seconds).
     *
     * @param password   Password to analyze
     * @param hash_rate  Hashes per second (0 for default estimate)
     * @return Time to crack in seconds
     */
    uint64_t pm_password_time_to_crack(const char *password, uint64_t hash_rate);

/* Pattern characters for pm_password_generate_pattern */
#define PM_PATTERN_UPPER_LETTER 'L' /* Uppercase letter */
#define PM_PATTERN_LOWER_LETTER 'l' /* Lowercase letter */
#define PM_PATTERN_ANY_LETTER 'A'   /* Any case letter */
#define PM_PATTERN_DIGIT 'n'        /* Digit 0-9 */
#define PM_PATTERN_SYMBOL 's'       /* Symbol */
#define PM_PATTERN_ANY_CHAR 'x'     /* Any character */
#define PM_PATTERN_VOWEL 'v'        /* Vowel */
#define PM_PATTERN_CONSONANT 'c'    /* Consonant */

    /* Preset password policies */
    extern const pm_password_policy_t PM_POLICY_BASIC;
    extern const pm_password_policy_t PM_POLICY_STRONG;
    extern const pm_password_policy_t PM_POLICY_MAXIMUM;
    extern const pm_password_policy_t PM_POLICY_WIFI;
    extern const pm_password_policy_t PM_POLICY_WINDOWS;
    extern const pm_password_policy_t PM_POLICY_UNIX;

#ifdef __cplusplus
}
#endif

#endif /* PM_PASSWORD_GEN_H */