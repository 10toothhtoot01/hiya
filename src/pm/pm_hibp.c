/*
 * pm_hibp.c - Have I Been Pwned k-anonymity checks
 *
 * Copyright (C) 2026 Hiya Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "pm/pm_hibp.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <curl/curl.h>

#include "bio_common.h"
#include "crypto/bio_crypto.h"
#include "pm/pm_secure_mem.h"

#define PM_HIBP_API_PREFIX "https://api.pwnedpasswords.com/range/"
#define PM_HIBP_TIMEOUT_SECONDS 5L
#define PM_HIBP_CONNECT_TIMEOUT_SECONDS 3L
#define PM_HIBP_MAX_RESPONSE_BYTES (2u * 1024u * 1024u)

typedef struct
{
    char *data;
    size_t len;
    size_t cap;
} pm_hibp_buffer_t;

typedef struct
{
    char *password;
    size_t password_len;
    pm_hibp_callback_t callback;
    void *userdata;
} pm_hibp_async_job_t;

static pthread_once_t g_hibp_curl_once = PTHREAD_ONCE_INIT;
static int g_hibp_curl_global_rc = CURLE_OK;

static void pm_hibp_curl_global_init_once(void)
{
    g_hibp_curl_global_rc = curl_global_init(CURL_GLOBAL_DEFAULT);
}

static size_t pm_hibp_write_callback(void *contents,
                                     size_t size,
                                     size_t nmemb,
                                     void *userdata)
{
    if (!contents || !userdata)
    {
        return 0;
    }

    size_t total = size * nmemb;
    if (total == 0)
    {
        return 0;
    }

    pm_hibp_buffer_t *buffer = (pm_hibp_buffer_t *)userdata;

    if (buffer->len + total + 1u > PM_HIBP_MAX_RESPONSE_BYTES)
    {
        return 0;
    }

    if (buffer->len + total + 1u > buffer->cap)
    {
        size_t new_cap = buffer->cap ? buffer->cap : 4096u;
        while (new_cap < buffer->len + total + 1u)
        {
            new_cap *= 2u;
        }

        char *new_data = realloc(buffer->data, new_cap);
        if (!new_data)
        {
            return 0;
        }

        buffer->data = new_data;
        buffer->cap = new_cap;
    }

    memcpy(buffer->data + buffer->len, contents, total);
    buffer->len += total;
    buffer->data[buffer->len] = '\0';
    return total;
}

static pm_error_t pm_hibp_sha1_upper_hex(const char *password,
                                         size_t password_len,
                                         char hash_hex_out[41])
{
    if (!password || !hash_hex_out || password_len == 0)
    {
        return PM_ERR_INVALID_PARAM;
    }

    if (bio_crypto_init() != BIO_OK)
    {
        return PM_ERR_CRYPTO;
    }

    uint8_t digest[20];
    if (bio_sha1((const uint8_t *)password, password_len, digest) != BIO_OK)
    {
        bio_secure_wipe(digest, sizeof(digest));
        return PM_ERR_CRYPTO;
    }

    for (size_t i = 0; i < sizeof(digest); i++)
    {
        (void)snprintf(hash_hex_out + (i * 2u), 3u, "%02X", digest[i]);
    }

    hash_hex_out[40] = '\0';
    bio_secure_wipe(digest, sizeof(digest));
    return PM_OK;
}

static pm_error_t pm_hibp_fetch_range(const char prefix[6], pm_hibp_buffer_t *out)
{
    if (!prefix || !out)
    {
        return PM_ERR_INVALID_PARAM;
    }

    if (pthread_once(&g_hibp_curl_once, pm_hibp_curl_global_init_once) != 0 ||
        g_hibp_curl_global_rc != CURLE_OK)
    {
        return PM_ERR_HIBP_UNAVAILABLE;
    }

    CURL *curl = curl_easy_init();
    if (!curl)
    {
        return PM_ERR_HIBP_UNAVAILABLE;
    }

    char url[96];
    (void)snprintf(url, sizeof(url), "%s%s", PM_HIBP_API_PREFIX, prefix);

    CURLcode rc = CURLE_OK;
    long http_code = 0;

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "hiya-hibp/1.0");
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, PM_HIBP_TIMEOUT_SECONDS);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, PM_HIBP_CONNECT_TIMEOUT_SECONDS);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, pm_hibp_write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, out);

    rc = curl_easy_perform(curl);
    if (rc == CURLE_OK)
    {
        (void)curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    }

    curl_easy_cleanup(curl);

    if (rc != CURLE_OK)
    {
        return PM_ERR_HIBP_UNAVAILABLE;
    }

    if (http_code != 200)
    {
        return PM_ERR_NETWORK;
    }

    return PM_OK;
}

static bool pm_hibp_parse_response(const char *response,
                                   size_t response_len,
                                   const char *target_suffix,
                                   uint64_t *breach_count_out)
{
    if (!response || !target_suffix || !breach_count_out)
    {
        return false;
    }

    const char *cursor = response;
    const char *end = response + response_len;

    while (cursor < end)
    {
        const char *line_end = memchr(cursor, '\n', (size_t)(end - cursor));
        if (!line_end)
        {
            line_end = end;
        }

        const char *line_stop = line_end;
        if (line_stop > cursor && *(line_stop - 1) == '\r')
        {
            line_stop--;
        }

        const char *colon = memchr(cursor, ':', (size_t)(line_stop - cursor));
        if (colon)
        {
            size_t suffix_len = (size_t)(colon - cursor);
            if (suffix_len == 35u &&
                strncasecmp(cursor, target_suffix, 35u) == 0)
            {
                const char *count_start = colon + 1;
                if (count_start < line_stop)
                {
                    char count_buf[32];
                    size_t count_len = (size_t)(line_stop - count_start);
                    if (count_len >= sizeof(count_buf))
                    {
                        count_len = sizeof(count_buf) - 1u;
                    }

                    memcpy(count_buf, count_start, count_len);
                    count_buf[count_len] = '\0';

                    errno = 0;
                    char *parse_end = NULL;
                    unsigned long long count = strtoull(count_buf, &parse_end, 10);
                    if (errno == 0 && parse_end && *parse_end == '\0')
                    {
                        *breach_count_out = (uint64_t)count;
                        return true;
                    }
                }
            }
        }

        cursor = (line_end < end) ? (line_end + 1) : end;
    }

    return false;
}

pm_hibp_result_t pm_hibp_check_password(const char *password,
                                        size_t password_len)
{
    pm_hibp_result_t result = {
        .found_in_breach = false,
        .breach_count = 0,
        .status = PM_OK,
    };

    if (!password || password_len == 0)
    {
        result.status = PM_ERR_INVALID_PARAM;
        return result;
    }

    char hash_hex[41] = {0};
    pm_error_t rc = pm_hibp_sha1_upper_hex(password, password_len, hash_hex);
    if (rc != PM_OK)
    {
        result.status = rc;
        bio_secure_wipe(hash_hex, sizeof(hash_hex));
        return result;
    }

    char prefix[6] = {0};
    memcpy(prefix, hash_hex, 5u);

    const char *suffix = hash_hex + 5;

    pm_hibp_buffer_t response = {0};
    rc = pm_hibp_fetch_range(prefix, &response);
    if (rc != PM_OK)
    {
        result.status = rc;
        bio_secure_wipe(hash_hex, sizeof(hash_hex));
        free(response.data);
        return result;
    }

    uint64_t breach_count = 0;
    bool found = pm_hibp_parse_response(response.data ? response.data : "",
                                        response.len,
                                        suffix,
                                        &breach_count);

    result.found_in_breach = found;
    result.breach_count = found ? breach_count : 0;
    result.status = PM_OK;

    bio_secure_wipe(hash_hex, sizeof(hash_hex));
    free(response.data);
    return result;
}

static void *pm_hibp_async_worker(void *arg)
{
    pm_hibp_async_job_t *job = (pm_hibp_async_job_t *)arg;
    if (!job)
    {
        return NULL;
    }

    pm_hibp_result_t result = pm_hibp_check_password(job->password,
                                                     job->password_len);

    if (job->callback)
    {
        job->callback(result, job->userdata);
    }

    pm_secure_free(job->password, job->password_len + 1u);
    free(job);
    return NULL;
}

pm_error_t pm_hibp_check_password_async(const char *password,
                                        size_t password_len,
                                        pm_hibp_callback_t cb,
                                        void *userdata)
{
    if (!password || password_len == 0 || !cb)
    {
        return PM_ERR_INVALID_PARAM;
    }

    pm_hibp_async_job_t *job = calloc(1, sizeof(pm_hibp_async_job_t));
    if (!job)
    {
        return PM_ERR_NOMEM;
    }

    pm_error_t alloc_rc = pm_secure_alloc(password_len + 1u,
                                          (void **)&job->password);
    if (alloc_rc != PM_OK)
    {
        free(job);
        return alloc_rc;
    }

    memcpy(job->password, password, password_len);
    job->password[password_len] = '\0';
    job->password_len = password_len;
    job->callback = cb;
    job->userdata = userdata;

    pthread_t worker;
    if (pthread_create(&worker, NULL, pm_hibp_async_worker, job) != 0)
    {
        pm_secure_free(job->password, job->password_len + 1u);
        free(job);
        return PM_ERR_INTERNAL;
    }

    if (pthread_detach(worker) != 0)
    {
        (void)pthread_join(worker, NULL);
        return PM_ERR_INTERNAL;
    }

    return PM_OK;
}
