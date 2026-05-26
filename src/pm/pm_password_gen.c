/*
 * pm_password_gen.c - Password generator with configurable policies
 *
 * Copyright (C) 2026 Hiya Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "pm/pm_password_gen.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <ctype.h>
#include <limits.h>

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

#include "crypto/bio_crypto.h"
#include "pm/pm_eff_wordlist.h"
#include "zxcvbn.h"

/* Character sets */
static const char CHARSET_LOWERCASE[] = "abcdefghijklmnopqrstuvwxyz";
static const char CHARSET_UPPERCASE[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
static const char CHARSET_DIGITS[] = "0123456789";
static const char CHARSET_SYMBOLS[] = "!@#$%^&*()_+-=[]{}|;:,.<>?";
static const char CHARSET_AMBIGUOUS[] = "0O1Il|";
/*
static const char CHARSET_SIMILAR[] = "il1Lo0O";
*/
static const char CHARSET_VOWELS[] = "aeiouAEIOU";
static const char CHARSET_CONSONANTS[] = "bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ";

/* Simple word list for passphrase generation (disabled for now) */
/*
static const char *DEFAULT_WORDS[] = {
    "able", "about", "account", "acid", "across", "add", "address", "admit",
    "adult", "affect", "after", "again", "against", "agent", "agree", "ahead",
    "allow", "almost", "alone", "along", "already", "although", "always",
    "among", "amount", "analysis", "animal", "another", "answer", "appear",
    "apply", "approach", "area", "argue", "around", "arrive", "article",
    "artist", "assume", "attack", "attempt", "attend", "attention", "attitude",
    "attract", "audience", "author", "authority", "available", "avoid", "away",
    "baby", "back", "ball", "bank", "base", "basic", "battle", "beautiful",
    "because", "become", "before", "begin", "behavior", "behind", "believe",
    "benefit", "better", "between", "beyond", "billion", "board", "bottle",
    "bottom", "break", "bring", "brother", "budget", "build", "business"
};
*/
/*
static const size_t DEFAULT_WORDS_COUNT = sizeof(DEFAULT_WORDS) / sizeof(DEFAULT_WORDS[0]);
*/

/* Preset policies */
const pm_password_policy_t PM_POLICY_BASIC = {
    .length = 12,
    .charset = PM_CHARSET_ALPHANUM,
    .min_uppercase = 1,
    .min_lowercase = 1,
    .min_digits = 1,
    .min_symbols = 0,
    .exclude_ambiguous = true,
    .require_all_charsets = true,
    .max_consecutive = 2};

const pm_password_policy_t PM_POLICY_STRONG = {
    .length = 16,
    .charset = PM_CHARSET_ALL,
    .min_uppercase = 2,
    .min_lowercase = 2,
    .min_digits = 2,
    .min_symbols = 2,
    .exclude_ambiguous = true,
    .require_all_charsets = true,
    .max_consecutive = 2,
    .no_repeating = true};

const pm_password_policy_t PM_POLICY_MAXIMUM = {
    .length = 32,
    .charset = PM_CHARSET_ALL,
    .min_uppercase = 4,
    .min_lowercase = 4,
    .min_digits = 4,
    .min_symbols = 4,
    .exclude_ambiguous = true,
    .require_all_charsets = true,
    .max_consecutive = 1,
    .no_repeating = true,
    .no_sequential = true};

static pm_error_t get_secure_random(uint8_t *buffer, size_t size)
{
    static mbedtls_entropy_context entropy;
    static mbedtls_ctr_drbg_context ctr_drbg;
    static bool initialized = false;

    if (!initialized)
    {
        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&ctr_drbg);

        int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                        (const unsigned char *)"hiya_pwgen",
                                        strlen("hiya_pwgen"));
        if (ret != 0)
        {
            return PM_ERR_CRYPTO;
        }
        initialized = true;
    }

    int ret = mbedtls_ctr_drbg_random(&ctr_drbg, buffer, size);
    return (ret == 0) ? PM_OK : PM_ERR_CRYPTO;
}

pm_error_t pm_password_policy_create_default(pm_password_policy_t **policy)
{
    if (!policy)
    {
        return PM_ERR_INVALID_PARAM;
    }

    pm_password_policy_t *p = calloc(1, sizeof(pm_password_policy_t));
    if (!p)
    {
        return PM_ERR_NOMEM;
    }

    *p = PM_POLICY_STRONG;

    /* Allocate copies of strings since the preset is const */
    if (PM_POLICY_STRONG.custom_charset)
    {
        p->custom_charset = strdup(PM_POLICY_STRONG.custom_charset);
    }
    if (PM_POLICY_STRONG.excluded_chars)
    {
        p->excluded_chars = strdup(PM_POLICY_STRONG.excluded_chars);
    }
    if (PM_POLICY_STRONG.required_chars)
    {
        p->required_chars = strdup(PM_POLICY_STRONG.required_chars);
    }

    *policy = p;
    return PM_OK;
}

pm_error_t pm_password_policy_create_custom(pm_password_policy_t **policy,
                                            uint32_t length,
                                            pm_charset_flags_t charset,
                                            bool secure_defaults)
{
    if (!policy || length < 4 || length > 128)
    {
        return PM_ERR_INVALID_PARAM;
    }

    pm_password_policy_t *p = calloc(1, sizeof(pm_password_policy_t));
    if (!p)
    {
        return PM_ERR_NOMEM;
    }

    p->length = length;
    p->charset = charset;

    if (secure_defaults)
    {
        p->min_uppercase = (charset & PM_CHARSET_UPPERCASE) ? 1 : 0;
        p->min_lowercase = (charset & PM_CHARSET_LOWERCASE) ? 1 : 0;
        p->min_digits = (charset & PM_CHARSET_DIGITS) ? 1 : 0;
        p->min_symbols = (charset & PM_CHARSET_SYMBOLS) ? 1 : 0;
        p->exclude_ambiguous = true;
        p->require_all_charsets = true;
        p->max_consecutive = 2;
    }

    *policy = p;
    return PM_OK;
}

void pm_password_policy_free(pm_password_policy_t *policy)
{
    if (!policy)
    {
        return;
    }

    free(policy->custom_charset);
    free(policy->excluded_chars);
    free(policy->required_chars);

    bio_secure_wipe(policy, sizeof(*policy));
    free(policy);
}

static pm_error_t build_charset_string(const pm_password_policy_t *policy, char **charset_str)
{
    if (!policy || !charset_str)
    {
        return PM_ERR_INVALID_PARAM;
    }

    if (policy->custom_charset)
    {
        *charset_str = strdup(policy->custom_charset);
        return *charset_str ? PM_OK : PM_ERR_NOMEM;
    }

    /* Calculate maximum size needed */
    size_t max_size = strlen(CHARSET_LOWERCASE) + strlen(CHARSET_UPPERCASE) +
                      strlen(CHARSET_DIGITS) + strlen(CHARSET_SYMBOLS) + 1;

    char *cs = malloc(max_size);
    if (!cs)
    {
        return PM_ERR_NOMEM;
    }

    cs[0] = '\0';

    if (policy->charset & PM_CHARSET_LOWERCASE)
    {
        strncat(cs, CHARSET_LOWERCASE, max_size - strlen(cs) - 1);
    }
    if (policy->charset & PM_CHARSET_UPPERCASE)
    {
        strncat(cs, CHARSET_UPPERCASE, max_size - strlen(cs) - 1);
    }
    if (policy->charset & PM_CHARSET_DIGITS)
    {
        strncat(cs, CHARSET_DIGITS, max_size - strlen(cs) - 1);
    }
    if (policy->charset & PM_CHARSET_SYMBOLS)
    {
        strncat(cs, CHARSET_SYMBOLS, max_size - strlen(cs) - 1);
    }

    /* Remove excluded characters */
    if (policy->exclude_ambiguous)
    {
        for (const char *c = CHARSET_AMBIGUOUS; *c; c++)
        {
            char *pos = strchr(cs, *c);
            if (pos)
            {
                memmove(pos, pos + 1, strlen(pos));
            }
        }
    }

    if (policy->excluded_chars)
    {
        for (const char *c = policy->excluded_chars; *c; c++)
        {
            char *pos = strchr(cs, *c);
            if (pos)
            {
                memmove(pos, pos + 1, strlen(pos));
            }
        }
    }

    if (strlen(cs) == 0)
    {
        free(cs);
        return PM_ERR_INVALID_PARAM;
    }

    *charset_str = cs;
    return PM_OK;
}

static bool char_in_set(char c, const char *set)
{
    return strchr(set, c) != NULL;
}

static pm_error_t validate_password_policy(const char *password,
                                           const pm_password_policy_t *policy)
{
    if (!password || !policy)
    {
        return PM_ERR_INVALID_PARAM;
    }

    size_t len = strlen(password);
    if (len != policy->length)
    {
        return PM_ERR_POLICY;
    }

    uint32_t uppercase_count = 0, lowercase_count = 0;
    uint32_t digit_count = 0, symbol_count = 0;

    for (size_t i = 0; i < len; i++)
    {
        char c = password[i];

        if (char_in_set(c, CHARSET_LOWERCASE))
            lowercase_count++;
        else if (char_in_set(c, CHARSET_UPPERCASE))
            uppercase_count++;
        else if (char_in_set(c, CHARSET_DIGITS))
            digit_count++;
        else if (char_in_set(c, CHARSET_SYMBOLS))
            symbol_count++;

        /* Check for excluded characters */
        if (policy->exclude_ambiguous && char_in_set(c, CHARSET_AMBIGUOUS))
        {
            return PM_ERR_POLICY;
        }

        if (policy->excluded_chars && char_in_set(c, policy->excluded_chars))
        {
            return PM_ERR_POLICY;
        }

        /* Check for repeating characters */
        if (policy->no_repeating && i > 0 && password[i] == password[i - 1])
        {
            return PM_ERR_POLICY;
        }

        /* Check for consecutive identical characters */
        if (policy->max_consecutive > 0 && i >= policy->max_consecutive)
        {
            bool all_same = true;
            for (uint32_t j = 1; j <= policy->max_consecutive; j++)
            {
                if (password[i - j] != password[i])
                {
                    all_same = false;
                    break;
                }
            }
            if (all_same)
            {
                return PM_ERR_POLICY;
            }
        }
    }

    /* Check minimum counts */
    if (uppercase_count < policy->min_uppercase ||
        lowercase_count < policy->min_lowercase ||
        digit_count < policy->min_digits ||
        symbol_count < policy->min_symbols)
    {
        return PM_ERR_POLICY;
    }

    return PM_OK;
}

pm_error_t pm_password_generate(const pm_password_policy_t *policy, char **password)
{
    if (!policy || !password)
    {
        return PM_ERR_INVALID_PARAM;
    }

    if (policy->length < 1 || policy->length > 128)
    {
        return PM_ERR_INVALID_PARAM;
    }

    char *charset = NULL;
    pm_error_t ret = build_charset_string(policy, &charset);
    if (ret != PM_OK)
    {
        return ret;
    }

    size_t charset_len = strlen(charset);
    if (charset_len == 0)
    {
        free(charset);
        return PM_ERR_INVALID_PARAM;
    }

    /* Allocate password buffer */
    char *pwd = malloc(policy->length + 1);
    if (!pwd)
    {
        free(charset);
        return PM_ERR_NOMEM;
    }

    /* Generate password with retries for policy compliance */
    uint32_t max_attempts = 1000;
    for (uint32_t attempt = 0; attempt < max_attempts; attempt++)
    {
        /* Generate random password */
        for (uint32_t i = 0; i < policy->length; i++)
        {
            uint8_t rand_byte;
            ret = get_secure_random(&rand_byte, 1);
            if (ret != PM_OK)
            {
                bio_secure_wipe(pwd, policy->length);
                free(pwd);
                free(charset);
                return ret;
            }

            pwd[i] = charset[rand_byte % charset_len];
        }
        pwd[policy->length] = '\0';

        /* Check if password meets policy */
        if (validate_password_policy(pwd, policy) == PM_OK)
        {
            /* Add required characters if specified */
            if (policy->required_chars)
            {
                /* Simple approach: replace random positions with required chars */
                size_t req_len = strlen(policy->required_chars);
                for (size_t i = 0; i < req_len && i < policy->length; i++)
                {
                    uint8_t rand_pos;
                    ret = get_secure_random(&rand_pos, 1);
                    if (ret != PM_OK)
                        break;

                    pwd[rand_pos % policy->length] = policy->required_chars[i];
                }
            }

            break;
        }
    }

    free(charset);

    /* Final validation */
    if (validate_password_policy(pwd, policy) != PM_OK)
    {
        bio_secure_wipe(pwd, policy->length);
        free(pwd);
        return PM_ERR_POLICY;
    }

    *password = pwd;
    return PM_OK;
}

pm_error_t pm_password_generate_best(const pm_password_policy_t *policy,
                                     uint32_t count,
                                     char **password)
{
    if (!policy || !password || count == 0 || count > 100)
    {
        return PM_ERR_INVALID_PARAM;
    }

    char **candidates = malloc(count * sizeof(char *));
    if (!candidates)
    {
        return PM_ERR_NOMEM;
    }

    /* Generate candidates */
    for (uint32_t i = 0; i < count; i++)
    {
        candidates[i] = NULL;
        pm_error_t ret = pm_password_generate(policy, &candidates[i]);
        if (ret != PM_OK)
        {
            for (uint32_t j = 0; j < i; j++)
            {
                if (candidates[j])
                {
                    bio_secure_wipe(candidates[j], strlen(candidates[j]));
                    free(candidates[j]);
                }
            }
            free(candidates);
            return ret;
        }
    }

    /* Find strongest candidate */
    char *best = NULL;
    uint32_t best_entropy = 0;

    for (uint32_t i = 0; i < count; i++)
    {
        pm_password_strength_t *strength = NULL;
        if (pm_password_assess_strength(candidates[i], &strength) == PM_OK)
        {
            if (strength->entropy_bits > best_entropy)
            {
                best_entropy = strength->entropy_bits;
                best = candidates[i];
            }
            pm_password_strength_free(strength);
        }
    }

    if (!best)
    {
        best = candidates[0]; /* Fallback to first */
    }

    /* Copy best password */
    *password = strdup(best);

    /* Free all candidates */
    for (uint32_t i = 0; i < count; i++)
    {
        bio_secure_wipe(candidates[i], strlen(candidates[i]));
        free(candidates[i]);
    }
    free(candidates);

    return *password ? PM_OK : PM_ERR_NOMEM;
}

pm_error_t pm_password_assess_strength(const char *password,
                                       pm_password_strength_t **strength)
{
    if (!password || !strength)
    {
        return PM_ERR_INVALID_PARAM;
    }

    pm_password_strength_t *s = calloc(1, sizeof(pm_password_strength_t));
    if (!s)
    {
        return PM_ERR_NOMEM;
    }

    size_t len = strlen(password);
    uint32_t charset_size = 0;

    /* Analyze character composition */
    for (size_t i = 0; i < len; i++)
    {
        char c = password[i];

        if (char_in_set(c, CHARSET_LOWERCASE))
        {
            s->has_lowercase = true;
        }
        else if (char_in_set(c, CHARSET_UPPERCASE))
        {
            s->has_uppercase = true;
        }
        else if (char_in_set(c, CHARSET_DIGITS))
        {
            s->has_digits = true;
        }
        else if (char_in_set(c, CHARSET_SYMBOLS))
        {
            s->has_symbols = true;
        }

        if (char_in_set(c, CHARSET_AMBIGUOUS))
        {
            s->has_ambiguous = true;
        }

        /* Check for patterns */
        if (i > 0 && password[i] == password[i - 1])
        {
            s->has_repeating = true;
        }

        if (i > 0 && abs(password[i] - password[i - 1]) == 1)
        {
            s->has_sequential = true;
        }
    }

    /* Calculate charset size */
    if (s->has_lowercase)
        charset_size += 26;
    if (s->has_uppercase)
        charset_size += 26;
    if (s->has_digits)
        charset_size += 10;
    if (s->has_symbols)
        charset_size += 32;

    s->charset_size = charset_size;

    ZxcMatch_t *matches = NULL;
    double entropy_bits = ZxcvbnMatch(password, NULL, &matches);
    if (entropy_bits < 0.0)
    {
        entropy_bits = 0.0;
    }

    const double guesses_log10 = entropy_bits * log10(2.0);
    uint32_t zxcvbn_score = 0;
    if (guesses_log10 < 3.0)
    {
        zxcvbn_score = 0;
    }
    else if (guesses_log10 < 6.0)
    {
        zxcvbn_score = 1;
    }
    else if (guesses_log10 < 8.0)
    {
        zxcvbn_score = 2;
    }
    else if (guesses_log10 < 10.0)
    {
        zxcvbn_score = 3;
    }
    else
    {
        zxcvbn_score = 4;
    }

    s->zxcvbn_score = zxcvbn_score;
    s->entropy_estimate_bits = entropy_bits;
    s->guesses_log10 = guesses_log10;
    s->entropy_bits = (entropy_bits >= (double)UINT32_MAX)
                          ? UINT32_MAX
                          : (uint32_t)(entropy_bits + 0.5);

    switch (zxcvbn_score)
    {
    case 0:
        s->label = PM_STRENGTH_VERY_WEAK;
        break;
    case 1:
        s->label = PM_STRENGTH_WEAK;
        break;
    case 2:
        s->label = PM_STRENGTH_FAIR;
        break;
    case 3:
        s->label = PM_STRENGTH_STRONG;
        break;
    default:
        s->label = PM_STRENGTH_VERY_STRONG;
        break;
    }

    /* Keep legacy 0-100 score for existing callers/config thresholds. */
    s->score = zxcvbn_score * 25u;

    s->feedback[0] = '\0';
    bool saw_dict = false;
    bool saw_pattern = false;
    bool saw_repeat = false;

    for (ZxcMatch_t *m = matches; m != NULL; m = m->Next)
    {
        size_t remaining = sizeof(s->feedback) - strlen(s->feedback) - 1u;
        if (remaining == 0u)
        {
            break;
        }

        if (!saw_dict &&
            (m->Type == DICTIONARY_MATCH ||
             m->Type == DICT_LEET_MATCH ||
             m->Type == USER_MATCH ||
             m->Type == USER_LEET_MATCH))
        {
            strncat(s->feedback, "Avoid common words. ", remaining);
            saw_dict = true;
            continue;
        }

        if (!saw_pattern &&
            (m->Type == SPATIAL_MATCH || m->Type == SEQUENCE_MATCH))
        {
            strncat(s->feedback, "Avoid keyboard and sequence patterns. ", remaining);
            saw_pattern = true;
            continue;
        }

        if (!saw_repeat && m->Type == REPEATS_MATCH)
        {
            strncat(s->feedback, "Avoid repeated character runs. ", remaining);
            saw_repeat = true;
            continue;
        }
    }

    /* Guardrail: short dictionary/leet passwords must not land in strong tiers. */
    if (saw_dict && len <= 12u && zxcvbn_score > 2u)
    {
        zxcvbn_score = 2u;
        s->zxcvbn_score = zxcvbn_score;
        s->score = zxcvbn_score * 25u;
        s->label = PM_STRENGTH_FAIR;
    }

    if (zxcvbn_score < 3u && s->feedback[0] == '\0')
    {
        size_t remaining = sizeof(s->feedback) - 1u;
        strncat(s->feedback, "Increase length and avoid predictable patterns.", remaining);
    }

    if (s->feedback[0] != '\0')
    {
        s->weakness_desc = strdup(s->feedback);
        if (!s->weakness_desc)
        {
            ZxcvbnFreeInfo(matches);
            free(s);
            return PM_ERR_NOMEM;
        }
    }

    ZxcvbnFreeInfo(matches);

    *strength = s;
    return PM_OK;
}

void pm_password_strength_free(pm_password_strength_t *strength)
{
    if (!strength)
    {
        return;
    }

    free(strength->weakness_desc);
    free(strength);
}

pm_error_t pm_pin_generate(uint32_t length, char **pin)
{
    if (!pin || length < 4 || length > 12)
    {
        return PM_ERR_INVALID_PARAM;
    }

    char *p = malloc(length + 1);
    if (!p)
    {
        return PM_ERR_NOMEM;
    }

    for (uint32_t i = 0; i < length; i++)
    {
        uint8_t rand_byte;
        pm_error_t ret = get_secure_random(&rand_byte, 1);
        if (ret != PM_OK)
        {
            free(p);
            return ret;
        }

        p[i] = '0' + (rand_byte % 10);
    }
    p[length] = '\0';

    *pin = p;
    return PM_OK;
}

pm_error_t pm_password_generate_pattern(const char *pattern, char **password)
{
    if (!pattern || !password)
    {
        return PM_ERR_INVALID_PARAM;
    }

    size_t pattern_len = strlen(pattern);
    if (pattern_len == 0 || pattern_len > 64)
    {
        return PM_ERR_INVALID_PARAM;
    }

    char *pwd = malloc(pattern_len + 1);
    if (!pwd)
    {
        return PM_ERR_NOMEM;
    }

    for (size_t i = 0; i < pattern_len; i++)
    {
        uint8_t rand_byte;
        pm_error_t ret = get_secure_random(&rand_byte, 1);
        if (ret != PM_OK)
        {
            free(pwd);
            return ret;
        }

        switch (pattern[i])
        {
        case PM_PATTERN_UPPER_LETTER:
            pwd[i] = CHARSET_UPPERCASE[rand_byte % strlen(CHARSET_UPPERCASE)];
            break;
        case PM_PATTERN_LOWER_LETTER:
            pwd[i] = CHARSET_LOWERCASE[rand_byte % strlen(CHARSET_LOWERCASE)];
            break;
        case PM_PATTERN_DIGIT:
            pwd[i] = CHARSET_DIGITS[rand_byte % strlen(CHARSET_DIGITS)];
            break;
        case PM_PATTERN_SYMBOL:
            pwd[i] = CHARSET_SYMBOLS[rand_byte % strlen(CHARSET_SYMBOLS)];
            break;
        case PM_PATTERN_VOWEL:
            pwd[i] = CHARSET_VOWELS[rand_byte % strlen(CHARSET_VOWELS)];
            break;
        case PM_PATTERN_CONSONANT:
            pwd[i] = CHARSET_CONSONANTS[rand_byte % strlen(CHARSET_CONSONANTS)];
            break;
        default:
            pwd[i] = pattern[i]; /* Literal character */
            break;
        }
    }
    pwd[pattern_len] = '\0';

    *password = pwd;
    return PM_OK;
}

uint32_t pm_password_entropy_bits(pm_charset_flags_t charset, uint32_t length)
{
    uint32_t charset_size = 0;

    if (charset & PM_CHARSET_LOWERCASE)
        charset_size += 26;
    if (charset & PM_CHARSET_UPPERCASE)
        charset_size += 26;
    if (charset & PM_CHARSET_DIGITS)
        charset_size += 10;
    if (charset & PM_CHARSET_SYMBOLS)
        charset_size += 32;

    if (charset_size == 0)
        return 0;

    return (uint32_t)(length * log2(charset_size));
}

pm_error_t pm_passphrase_generate(const pm_passphrase_options_t *options,
                                  char **passphrase)
{
    uint32_t word_count;
    const char *sep;
    size_t buf_cap, buf_len;
    char *buf;

    if (!options || !passphrase)
    {
        return PM_ERR_INVALID_PARAM;
    }

    word_count = options->word_count;
    if (word_count < 3 || word_count > 20)
    {
        return PM_ERR_INVALID_PARAM;
    }

    sep = options->separator ? options->separator : "-";
    buf_cap = word_count * 40u + (word_count - 1u) * strlen(sep) + 8u;
    buf = calloc(1, buf_cap);
    if (!buf)
    {
        return PM_ERR_NOMEM;
    }

    buf_len = 0;

    for (uint32_t i = 0; i < word_count; i++)
    {
        const char *word = NULL;
        size_t wlen = 0;
        bool selected = false;

        for (size_t attempts = 0; attempts < PM_EFF_WORDLIST_SIZE; attempts++)
        {
            word = pm_eff_wordlist_random_word();
            if (!word)
            {
                bio_secure_wipe(buf, buf_cap);
                free(buf);
                return PM_ERR_CRYPTO;
            }

            wlen = strlen(word);
            if (options->min_word_length > 0 && wlen < options->min_word_length)
            {
                continue;
            }

            if (options->max_word_length > 0 && wlen > options->max_word_length)
            {
                continue;
            }

            if (sep[0] != '\0' && strstr(word, sep) != NULL)
            {
                continue;
            }

            selected = true;
            break;
        }

        if (!selected)
        {
            bio_secure_wipe(buf, buf_cap);
            free(buf);
            return PM_ERR_STATE;
        }

        if (i > 0)
        {
            size_t slen = strlen(sep);
            if (buf_len + slen >= buf_cap)
            {
                bio_secure_wipe(buf, buf_cap);
                free(buf);
                return PM_ERR_NOMEM;
            }
            memcpy(buf + buf_len, sep, slen);
            buf_len += slen;
        }

        if (buf_len + wlen >= buf_cap)
        {
            bio_secure_wipe(buf, buf_cap);
            free(buf);
            return PM_ERR_NOMEM;
        }

        memcpy(buf + buf_len, word, wlen);

        if (options->capitalize_words && wlen > 0)
        {
            buf[buf_len] = (char)toupper((unsigned char)buf[buf_len]);
        }

        buf_len += wlen;
    }

    if (options->add_numbers)
    {
        uint8_t rand_byte = 0;
        pm_error_t ret = get_secure_random(&rand_byte, 1u);
        if (ret != PM_OK)
        {
            bio_secure_wipe(buf, buf_cap);
            free(buf);
            return ret;
        }

        if (buf_len + 1u >= buf_cap)
        {
            bio_secure_wipe(buf, buf_cap);
            free(buf);
            return PM_ERR_NOMEM;
        }

        buf[buf_len++] = (char)('0' + (rand_byte % 10u));
    }

    if (options->add_symbols)
    {
        uint8_t rand_byte = 0;
        pm_error_t ret = get_secure_random(&rand_byte, 1u);
        if (ret != PM_OK)
        {
            bio_secure_wipe(buf, buf_cap);
            free(buf);
            return ret;
        }

        if (buf_len + 1u >= buf_cap)
        {
            bio_secure_wipe(buf, buf_cap);
            free(buf);
            return PM_ERR_NOMEM;
        }

        buf[buf_len++] = CHARSET_SYMBOLS[rand_byte % strlen(CHARSET_SYMBOLS)];
    }

    buf[buf_len] = '\0';

    *passphrase = buf;
    return PM_OK;
}

pm_error_t pm_password_check_policy(const char *password,
                                    const pm_password_policy_t *policy,
                                    char **errors)
{
    if (!password || !policy || !errors)
    {
        return PM_ERR_INVALID_PARAM;
    }

    *errors = NULL;

    size_t len = strlen(password);
    char err_buf[1024];
    size_t err_pos = 0;

    err_buf[0] = '\0';

#define APPEND_ERR(msg)                             \
    do                                              \
    {                                               \
        size_t mlen = strlen(msg);                  \
        if (err_pos + mlen + 2 < sizeof(err_buf))   \
        {                                           \
            if (err_pos > 0)                        \
            {                                       \
                err_buf[err_pos++] = ';';           \
                err_buf[err_pos++] = ' ';           \
            }                                       \
            memcpy(err_buf + err_pos, (msg), mlen); \
            err_pos += mlen;                        \
            err_buf[err_pos] = '\0';                \
        }                                           \
    } while (0)

    if (len < policy->length)
    {
        APPEND_ERR("too short");
    }

    uint32_t uc = 0, lc = 0, dc = 0, sc = 0;
    for (size_t i = 0; i < len; i++)
    {
        char c = password[i];
        if (char_in_set(c, CHARSET_LOWERCASE))
            lc++;
        else if (char_in_set(c, CHARSET_UPPERCASE))
            uc++;
        else if (char_in_set(c, CHARSET_DIGITS))
            dc++;
        else if (char_in_set(c, CHARSET_SYMBOLS))
            sc++;

        if (policy->exclude_ambiguous && char_in_set(c, CHARSET_AMBIGUOUS))
        {
            APPEND_ERR("contains ambiguous character");
        }

        if (policy->no_repeating && i > 0 && password[i] == password[i - 1])
        {
            APPEND_ERR("contains repeating characters");
        }
    }

    if (uc < policy->min_uppercase)
        APPEND_ERR("too few uppercase letters");
    if (lc < policy->min_lowercase)
        APPEND_ERR("too few lowercase letters");
    if (dc < policy->min_digits)
        APPEND_ERR("too few digits");
    if (sc < policy->min_symbols)
        APPEND_ERR("too few symbols");

#undef APPEND_ERR

    if (err_pos > 0)
    {
        *errors = strdup(err_buf);
        if (!*errors)
        {
            return PM_ERR_NOMEM;
        }
        return PM_ERR_POLICY;
    }

    return PM_OK;
}

pm_error_t pm_charset_to_string(pm_charset_flags_t charset, char **charset_str)
{
    if (!charset_str)
    {
        return PM_ERR_INVALID_PARAM;
    }

    size_t max_size = strlen(CHARSET_LOWERCASE) + strlen(CHARSET_UPPERCASE) +
                      strlen(CHARSET_DIGITS) + strlen(CHARSET_SYMBOLS) + 1;

    char *cs = malloc(max_size);
    if (!cs)
    {
        return PM_ERR_NOMEM;
    }

    cs[0] = '\0';

    if (charset & PM_CHARSET_LOWERCASE)
    {
        strncat(cs, CHARSET_LOWERCASE, max_size - strlen(cs) - 1);
    }
    if (charset & PM_CHARSET_UPPERCASE)
    {
        strncat(cs, CHARSET_UPPERCASE, max_size - strlen(cs) - 1);
    }
    if (charset & PM_CHARSET_DIGITS)
    {
        strncat(cs, CHARSET_DIGITS, max_size - strlen(cs) - 1);
    }
    if (charset & PM_CHARSET_SYMBOLS)
    {
        strncat(cs, CHARSET_SYMBOLS, max_size - strlen(cs) - 1);
    }

    if (strlen(cs) == 0)
    {
        free(cs);
        return PM_ERR_INVALID_PARAM;
    }

    *charset_str = cs;
    return PM_OK;
}

uint64_t pm_password_time_to_crack(const char *password, uint64_t hash_rate)
{
    pm_password_strength_t *strength = NULL;
    uint64_t seconds;

    if (!password || strlen(password) == 0)
    {
        return 0;
    }

    if (hash_rate == 0)
    {
        hash_rate = 10000000000ULL; /* 10 billion hashes/sec default */
    }

    if (pm_password_assess_strength(password, &strength) != PM_OK)
    {
        return 0;
    }

    if (strength->entropy_bits >= 64)
    {
        seconds = UINT64_MAX;
    }
    else if (strength->entropy_bits == 0)
    {
        seconds = 0;
    }
    else
    {
        double combinations = pow(2.0, (double)strength->entropy_bits);
        double time_seconds = combinations / (double)hash_rate / 2.0;
        seconds = (time_seconds > (double)UINT64_MAX) ? UINT64_MAX : (uint64_t)time_seconds;
    }

    pm_password_strength_free(strength);
    return seconds;
}

/* Additional preset policies */
const pm_password_policy_t PM_POLICY_WIFI = {
    .length = 20,
    .charset = PM_CHARSET_ALPHANUM,
    .min_uppercase = 1,
    .min_lowercase = 1,
    .min_digits = 1,
    .min_symbols = 0,
    .exclude_ambiguous = true,
    .require_all_charsets = true,
    .max_consecutive = 3};

const pm_password_policy_t PM_POLICY_WINDOWS = {
    .length = 14,
    .charset = PM_CHARSET_ALL,
    .min_uppercase = 1,
    .min_lowercase = 1,
    .min_digits = 1,
    .min_symbols = 1,
    .exclude_ambiguous = false,
    .require_all_charsets = true,
    .max_consecutive = 2};

const pm_password_policy_t PM_POLICY_UNIX = {
    .length = 16,
    .charset = PM_CHARSET_ALL,
    .min_uppercase = 2,
    .min_lowercase = 2,
    .min_digits = 2,
    .min_symbols = 1,
    .exclude_ambiguous = true,
    .require_all_charsets = true,
    .max_consecutive = 2,
    .no_repeating = true};