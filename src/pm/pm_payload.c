/*
 * pm_payload.c - Password manager payload model and CBOR codec
 *
 * Copyright (C) 2026 BioAuth Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "pm/pm_payload.h"

#include <stdlib.h>
#include <string.h>

#include "cbor/bio_cbor.h"

/* Root map keys (uint, ascending for canonical map ordering). */
#define PMK_SCHEMA_VERSION 1u
#define PMK_CREATED_AT_MS 2u
#define PMK_UPDATED_AT_MS 3u
#define PMK_ENTRIES 4u
#define PMK_GROUPS 5u
#define PMK_VAULT_UUID 6u
#define PMK_ATTACHMENTS 7u
#define PMK_RECYCLE_BIN 8u
#define PMK_SECURITY_AUDIT_CACHE 9u

/* Entry map keys (legacy keys 1-11 preserved, additions appended). */
#define PME_ID 1u
#define PME_TITLE 2u
#define PME_USERNAME 3u
#define PME_PASSWORD 4u
#define PME_URL 5u
#define PME_NOTES 6u
#define PME_TAGS 7u
#define PME_GROUP_ID 8u
#define PME_CREATED_AT_MS 9u
#define PME_UPDATED_AT_MS 10u
#define PME_FAVORITE 11u
#define PME_ACCESSED_AT_MS 12u
#define PME_COLOR_LABEL 13u
#define PME_EXPIRY_AT_MS 14u
#define PME_EXPIRY_WARN_DAYS 15u
#define PME_CUSTOM_FIELDS 16u
#define PME_ATTACHMENT_REFS 17u
#define PME_HISTORY 18u
#define PME_REQUIRES_FRESH_BIOMETRIC 19u
#define PME_URL_LIST 20u

/* Group map keys. */
#define PMG_ID 1u
#define PMG_PARENT_ID 2u
#define PMG_TITLE 3u
#define PMG_ICON_ID 4u
#define PMG_COLOR 5u
#define PMG_NOTES 6u
#define PMG_CREATED_AT_MS 7u
#define PMG_UPDATED_AT_MS 8u
#define PMG_ACCESSED_AT_MS 9u
#define PMG_CUSTOM_DATA 10u

/* Custom field map keys. */
#define PMCF_NAME 1u
#define PMCF_TYPE 2u
#define PMCF_TEXT_VALUE 3u
#define PMCF_DATE_VALUE_MS 4u
#define PMCF_BINARY_REF 5u

/* Attachment ref map keys. */
#define PMAR_ATTACHMENT_ID 1u

/* History revision map keys. */
#define PMH_MODIFIED_AT_MS 1u
#define PMH_SOURCE 2u
#define PMH_ACTOR 3u
#define PMH_TITLE 4u
#define PMH_USERNAME 5u
#define PMH_PASSWORD 6u
#define PMH_NOTES 7u
#define PMH_ID 8u
#define PMH_URL 9u
#define PMH_GROUP_ID 10u
#define PMH_TAGS 11u
#define PMH_CREATED_AT_MS 12u
#define PMH_UPDATED_AT_MS 13u
#define PMH_FAVORITE 14u

/* Attachment blob map keys. */
#define PMA_ID 1u
#define PMA_NAME 2u
#define PMA_MIME 3u
#define PMA_SIZE 4u
#define PMA_SHA256 5u
#define PMA_BLOB 6u

/* Recycle bin map keys. */
#define PMR_ENABLED 1u
#define PMR_GROUP_ID 2u
#define PMR_RETENTION_DAYS 3u

static void unknown_fields_free(pm_unknown_field_t *fields, size_t count)
{
    if (!fields)
    {
        return;
    }

    for (size_t i = 0; i < count; i++)
    {
        free(fields[i].value_cbor);
        fields[i].value_cbor = NULL;
        fields[i].value_cbor_len = 0;
        fields[i].key = 0;
    }

    free(fields);
}

static pm_error_t unknown_fields_clone(pm_unknown_field_t **out_fields,
                                       size_t *out_count,
                                       const pm_unknown_field_t *src_fields,
                                       size_t src_count)
{
    pm_unknown_field_t *out = NULL;

    if (!out_fields || !out_count)
    {
        return PM_ERR_INVALID_PARAM;
    }

    *out_fields = NULL;
    *out_count = 0;

    if (src_count == 0)
    {
        return PM_OK;
    }

    out = calloc(src_count, sizeof(pm_unknown_field_t));
    if (!out)
    {
        return PM_ERR_NOMEM;
    }

    for (size_t i = 0; i < src_count; i++)
    {
        out[i].key = src_fields[i].key;
        out[i].value_cbor_len = src_fields[i].value_cbor_len;

        if (out[i].value_cbor_len > 0)
        {
            out[i].value_cbor = malloc(out[i].value_cbor_len);
            if (!out[i].value_cbor)
            {
                unknown_fields_free(out, src_count);
                return PM_ERR_NOMEM;
            }
            memcpy(out[i].value_cbor, src_fields[i].value_cbor, out[i].value_cbor_len);
        }
    }

    *out_fields = out;
    *out_count = src_count;
    return PM_OK;
}

static pm_error_t unknown_fields_append(pm_unknown_field_t **fields,
                                        size_t *count,
                                        uint64_t key,
                                        const uint8_t *value_cbor,
                                        size_t value_cbor_len)
{
    pm_unknown_field_t *new_fields;

    if (!fields || !count || !value_cbor || value_cbor_len == 0)
    {
        return PM_ERR_INVALID_PARAM;
    }

    if (*count >= PM_PAYLOAD_MAX_UNKNOWN_FIELDS)
    {
        return PM_ERR_FORMAT;
    }

    new_fields = realloc(*fields, (*count + 1u) * sizeof(pm_unknown_field_t));
    if (!new_fields)
    {
        return PM_ERR_NOMEM;
    }

    *fields = new_fields;
    (*fields)[*count].key = key;
    (*fields)[*count].value_cbor = malloc(value_cbor_len);
    if (!(*fields)[*count].value_cbor)
    {
        return PM_ERR_NOMEM;
    }

    memcpy((*fields)[*count].value_cbor, value_cbor, value_cbor_len);
    (*fields)[*count].value_cbor_len = value_cbor_len;
    (*count)++;

    return PM_OK;
}

static pm_error_t capture_next_item(bio_cbor_decoder_t *dec,
                                    uint8_t **out,
                                    size_t *out_len)
{
    size_t start;
    size_t end;
    uint8_t *copy;

    if (!dec || !out || !out_len)
    {
        return PM_ERR_INVALID_PARAM;
    }

    *out = NULL;
    *out_len = 0;

    start = bio_cbor_decoder_offset(dec);
    if (bio_cbor_skip(dec) != BIO_OK)
    {
        return PM_ERR_DESERIALIZE;
    }

    end = bio_cbor_decoder_offset(dec);
    if (end <= start || end > dec->size)
    {
        return PM_ERR_DESERIALIZE;
    }

    copy = malloc(end - start);
    if (!copy)
    {
        return PM_ERR_NOMEM;
    }

    memcpy(copy, dec->data + start, end - start);
    *out = copy;
    *out_len = end - start;
    return PM_OK;
}

static char *dup_bytes_as_cstr(const char *src, size_t len)
{
    char *dst;

    if (!src)
    {
        return NULL;
    }

    if (len > SIZE_MAX - 1u)
    {
        return NULL;
    }

    dst = malloc(len + 1u);
    if (!dst)
    {
        return NULL;
    }

    if (len > 0)
    {
        memcpy(dst, src, len);
    }
    dst[len] = '\0';
    return dst;
}

static char *dup_cstr_or_empty(const char *src)
{
    static const char empty[] = "";

    if (!src)
    {
        src = empty;
    }

    return dup_bytes_as_cstr(src, strlen(src));
}

static pm_error_t clone_bytes(uint8_t **dst, size_t *dst_len,
                              const uint8_t *src, size_t src_len)
{
    uint8_t *copy = NULL;

    if (!dst || !dst_len)
    {
        return PM_ERR_INVALID_PARAM;
    }

    *dst = NULL;
    *dst_len = 0;

    if (!src || src_len == 0)
    {
        return PM_OK;
    }

    copy = malloc(src_len);
    if (!copy)
    {
        return PM_ERR_NOMEM;
    }

    memcpy(copy, src, src_len);
    *dst = copy;
    *dst_len = src_len;
    return PM_OK;
}

static void free_string_list(char **items, size_t count)
{
    if (!items)
    {
        return;
    }

    for (size_t i = 0; i < count; i++)
    {
        free(items[i]);
    }

    free(items);
}

static pm_error_t clone_string_list(char ***out_items,
                                    size_t *out_count,
                                    char *const *src_items,
                                    size_t src_count)
{
    char **items = NULL;

    if (!out_items || !out_count)
    {
        return PM_ERR_INVALID_PARAM;
    }

    *out_items = NULL;
    *out_count = 0;

    if (src_count == 0)
    {
        return PM_OK;
    }

    items = calloc(src_count, sizeof(char *));
    if (!items)
    {
        return PM_ERR_NOMEM;
    }

    for (size_t i = 0; i < src_count; i++)
    {
        items[i] = dup_cstr_or_empty(src_items ? src_items[i] : NULL);
        if (!items[i])
        {
            free_string_list(items, src_count);
            return PM_ERR_NOMEM;
        }
    }

    *out_items = items;
    *out_count = src_count;
    return PM_OK;
}

static bool custom_field_type_valid(pm_custom_field_type_t type)
{
    return type >= PM_FIELD_TEXT && type <= PM_FIELD_BINARY_REF;
}

static pm_error_t validate_string_list_shape(char *const *items, size_t count)
{
    if (count > 0 && !items)
    {
        return PM_ERR_FORMAT;
    }

    return PM_OK;
}

static pm_error_t validate_custom_field_model(const pm_custom_field_t *field)
{
    if (!field)
    {
        return PM_ERR_INVALID_PARAM;
    }

    if (!custom_field_type_valid(field->type))
    {
        return PM_ERR_FORMAT;
    }

    return PM_OK;
}

static pm_error_t validate_history_revision_model(const pm_history_revision_t *revision)
{
    if (!revision)
    {
        return PM_ERR_INVALID_PARAM;
    }

    if (revision->tag_count > PM_PAYLOAD_MAX_TAGS_PER_ENTRY)
    {
        return PM_ERR_FORMAT;
    }

    return validate_string_list_shape(revision->tags, revision->tag_count);
}

static pm_error_t validate_entry_model(const pm_entry_t *entry)
{
    if (!entry)
    {
        return PM_ERR_INVALID_PARAM;
    }

    if (entry->tag_count > PM_PAYLOAD_MAX_TAGS_PER_ENTRY ||
        entry->url_count > PM_PAYLOAD_MAX_URLS_PER_ENTRY ||
        entry->custom_field_count > PM_PAYLOAD_MAX_CUSTOM_FIELDS_PER_ENTRY ||
        entry->attachment_ref_count > PM_PAYLOAD_MAX_ATTACHMENT_REFS_PER_ENTRY ||
        entry->history_count > PM_PAYLOAD_MAX_HISTORY_PER_ENTRY)
    {
        return PM_ERR_FORMAT;
    }

    if (validate_string_list_shape(entry->tags, entry->tag_count) != PM_OK ||
        validate_string_list_shape(entry->urls, entry->url_count) != PM_OK)
    {
        return PM_ERR_FORMAT;
    }

    if (entry->custom_field_count > 0 && !entry->custom_fields)
    {
        return PM_ERR_FORMAT;
    }

    if (entry->attachment_ref_count > 0 && !entry->attachment_refs)
    {
        return PM_ERR_FORMAT;
    }

    if (entry->history_count > 0 && !entry->history)
    {
        return PM_ERR_FORMAT;
    }

    for (size_t i = 0; i < entry->custom_field_count; i++)
    {
        pm_error_t rc = validate_custom_field_model(&entry->custom_fields[i]);
        if (rc != PM_OK)
        {
            return rc;
        }
    }

    for (size_t i = 0; i < entry->history_count; i++)
    {
        pm_error_t rc = validate_history_revision_model(&entry->history[i]);
        if (rc != PM_OK)
        {
            return rc;
        }
    }

    return PM_OK;
}

static pm_error_t validate_attachment_model(const pm_attachment_t *attachment)
{
    if (!attachment)
    {
        return PM_ERR_INVALID_PARAM;
    }

    if (attachment->blob_len > 0 && !attachment->blob)
    {
        return PM_ERR_FORMAT;
    }

    return PM_OK;
}

static pm_error_t validate_group_model(const pm_group_t *group)
{
    if (!group)
    {
        return PM_ERR_INVALID_PARAM;
    }

    if (group->custom_data_cbor_len > 0 && !group->custom_data_cbor)
    {
        return PM_ERR_FORMAT;
    }

    return PM_OK;
}

static pm_error_t validate_payload_model(const pm_payload_t *payload)
{
    if (!payload)
    {
        return PM_ERR_INVALID_PARAM;
    }

    if (payload->schema_version != PM_PAYLOAD_SCHEMA_VERSION ||
        payload->entry_count > PM_PAYLOAD_MAX_ENTRIES ||
        payload->group_count > PM_PAYLOAD_MAX_GROUPS ||
        payload->attachment_count > PM_PAYLOAD_MAX_ATTACHMENTS)
    {
        return PM_ERR_FORMAT;
    }

    if ((payload->entry_count > 0 && !payload->entries) ||
        (payload->group_count > 0 && !payload->groups) ||
        (payload->attachment_count > 0 && !payload->attachments) ||
        (payload->security_audit_cache_cbor_len > 0 && !payload->security_audit_cache_cbor))
    {
        return PM_ERR_FORMAT;
    }

    for (size_t i = 0; i < payload->group_count; i++)
    {
        pm_error_t rc = validate_group_model(&payload->groups[i]);
        if (rc != PM_OK)
        {
            return rc;
        }
    }

    for (size_t i = 0; i < payload->entry_count; i++)
    {
        pm_error_t rc = validate_entry_model(&payload->entries[i]);
        if (rc != PM_OK)
        {
            return rc;
        }
    }

    for (size_t i = 0; i < payload->attachment_count; i++)
    {
        pm_error_t rc = validate_attachment_model(&payload->attachments[i]);
        if (rc != PM_OK)
        {
            return rc;
        }
    }

    return PM_OK;
}

static pm_error_t ensure_entry_url_alias(pm_entry_t *entry)
{
    if (!entry)
    {
        return PM_ERR_INVALID_PARAM;
    }

    if (entry->url_count > 0 && !entry->urls)
    {
        return PM_ERR_FORMAT;
    }

    if (!entry->url && entry->url_count > 0)
    {
        entry->url = dup_cstr_or_empty(entry->urls[0]);
        if (!entry->url)
        {
            return PM_ERR_NOMEM;
        }
    }

    if (!entry->url)
    {
        entry->url = dup_cstr_or_empty(NULL);
        if (!entry->url)
        {
            return PM_ERR_NOMEM;
        }
    }

    if (entry->url_count == 0 && entry->url[0] != '\0')
    {
        entry->urls = calloc(1u, sizeof(char *));
        if (!entry->urls)
        {
            return PM_ERR_NOMEM;
        }

        entry->urls[0] = dup_cstr_or_empty(entry->url);
        if (!entry->urls[0])
        {
            free(entry->urls);
            entry->urls = NULL;
            return PM_ERR_NOMEM;
        }
        entry->url_count = 1u;
    }

    if (entry->url_count > 0 && entry->urls && entry->urls[0])
    {
        char *first = dup_cstr_or_empty(entry->urls[0]);
        if (!first)
        {
            return PM_ERR_NOMEM;
        }
        free(entry->url);
        entry->url = first;
    }

    return PM_OK;
}

static int encode_raw_cbor(bio_cbor_encoder_t *enc,
                           const uint8_t *data,
                           size_t data_len)
{
    if (!enc || !data || data_len == 0)
    {
        return BIO_ERR_INVALID_PARAM;
    }

    if (enc->offset > enc->capacity || data_len > enc->capacity - enc->offset)
    {
        enc->error = true;
        return BIO_ERR_NOMEM;
    }

    memcpy(enc->buf + enc->offset, data, data_len);
    enc->offset += data_len;
    return BIO_OK;
}

static int encode_tstr_or_empty(bio_cbor_encoder_t *enc, const char *value)
{
    if (!value)
    {
        value = "";
    }

    return bio_cbor_encode_tstr(enc, value, strlen(value));
}

static int encode_bstr_or_empty(bio_cbor_encoder_t *enc,
                                const uint8_t *data,
                                size_t data_len)
{
    if (!data || data_len == 0)
    {
        return bio_cbor_encode_bstr(enc, NULL, 0);
    }

    return bio_cbor_encode_bstr(enc, data, data_len);
}

static void custom_field_clear(pm_custom_field_t *field)
{
    if (!field)
    {
        return;
    }

    free(field->name);
    free(field->text_value);
    free(field->binary_ref);
    unknown_fields_free(field->unknown_fields, field->unknown_field_count);
    memset(field, 0, sizeof(*field));
}

static pm_error_t custom_field_clone(pm_custom_field_t *dst,
                                     const pm_custom_field_t *src)
{
    pm_custom_field_t out = {0};
    pm_error_t rc;

    if (!dst || !src)
    {
        return PM_ERR_INVALID_PARAM;
    }

    rc = validate_custom_field_model(src);
    if (rc != PM_OK)
    {
        return rc;
    }

    out.name = dup_cstr_or_empty(src->name);
    out.text_value = dup_cstr_or_empty(src->text_value);
    out.binary_ref = dup_cstr_or_empty(src->binary_ref);
    if (!out.name || !out.text_value || !out.binary_ref)
    {
        custom_field_clear(&out);
        return PM_ERR_NOMEM;
    }

    out.type = src->type;
    out.date_value_ms = src->date_value_ms;

    rc = unknown_fields_clone(&out.unknown_fields,
                              &out.unknown_field_count,
                              src->unknown_fields,
                              src->unknown_field_count);
    if (rc != PM_OK)
    {
        custom_field_clear(&out);
        return rc;
    }

    *dst = out;
    return PM_OK;
}

void pm_custom_field_init(pm_custom_field_t *field)
{
    if (!field)
    {
        return;
    }

    memset(field, 0, sizeof(*field));
}

void pm_custom_field_free(pm_custom_field_t *field)
{
    custom_field_clear(field);
}

pm_error_t pm_custom_field_copy(pm_custom_field_t *dst,
                                const pm_custom_field_t *src)
{
    return custom_field_clone(dst, src);
}

static void attachment_ref_clear(pm_attachment_ref_t *ref)
{
    if (!ref)
    {
        return;
    }

    free(ref->attachment_id);
    unknown_fields_free(ref->unknown_fields, ref->unknown_field_count);
    memset(ref, 0, sizeof(*ref));
}

static pm_error_t attachment_ref_clone(pm_attachment_ref_t *dst,
                                       const pm_attachment_ref_t *src)
{
    pm_attachment_ref_t out = {0};
    pm_error_t rc;

    if (!dst || !src)
    {
        return PM_ERR_INVALID_PARAM;
    }

    out.attachment_id = dup_cstr_or_empty(src->attachment_id);
    if (!out.attachment_id)
    {
        return PM_ERR_NOMEM;
    }

    rc = unknown_fields_clone(&out.unknown_fields,
                              &out.unknown_field_count,
                              src->unknown_fields,
                              src->unknown_field_count);
    if (rc != PM_OK)
    {
        attachment_ref_clear(&out);
        return rc;
    }

    *dst = out;
    return PM_OK;
}

void pm_attachment_ref_init(pm_attachment_ref_t *ref)
{
    if (!ref)
    {
        return;
    }

    memset(ref, 0, sizeof(*ref));
}

void pm_attachment_ref_free(pm_attachment_ref_t *ref)
{
    attachment_ref_clear(ref);
}

pm_error_t pm_attachment_ref_copy(pm_attachment_ref_t *dst,
                                  const pm_attachment_ref_t *src)
{
    return attachment_ref_clone(dst, src);
}

static void history_revision_clear(pm_history_revision_t *revision)
{
    if (!revision)
    {
        return;
    }

    free(revision->source);
    free(revision->actor);
    free(revision->id);
    free(revision->title);
    free(revision->username);
    free(revision->password);
    free(revision->url);
    free(revision->notes);
    free(revision->group_id);
    free_string_list(revision->tags, revision->tag_count);
    unknown_fields_free(revision->unknown_fields, revision->unknown_field_count);
    memset(revision, 0, sizeof(*revision));
}

static pm_error_t history_revision_clone(pm_history_revision_t *dst,
                                         const pm_history_revision_t *src)
{
    pm_history_revision_t out = {0};
    pm_error_t rc;

    if (!dst || !src)
    {
        return PM_ERR_INVALID_PARAM;
    }

    rc = validate_history_revision_model(src);
    if (rc != PM_OK)
    {
        return rc;
    }

    out.revision_ts_ms = src->revision_ts_ms;
    out.source = dup_cstr_or_empty(src->source);
    out.actor = dup_cstr_or_empty(src->actor);
    out.id = dup_cstr_or_empty(src->id);
    out.title = dup_cstr_or_empty(src->title);
    out.username = dup_cstr_or_empty(src->username);
    out.password = dup_cstr_or_empty(src->password);
    out.url = dup_cstr_or_empty(src->url);
    out.notes = dup_cstr_or_empty(src->notes);
    out.group_id = dup_cstr_or_empty(src->group_id);

    if (!out.source || !out.actor || !out.id || !out.title || !out.username ||
        !out.password || !out.url || !out.notes || !out.group_id)
    {
        history_revision_clear(&out);
        return PM_ERR_NOMEM;
    }

    rc = clone_string_list(&out.tags, &out.tag_count, src->tags, src->tag_count);
    if (rc != PM_OK)
    {
        history_revision_clear(&out);
        return rc;
    }

    out.created_at_ms = src->created_at_ms;
    out.updated_at_ms = src->updated_at_ms;
    out.favorite = src->favorite;

    rc = unknown_fields_clone(&out.unknown_fields,
                              &out.unknown_field_count,
                              src->unknown_fields,
                              src->unknown_field_count);
    if (rc != PM_OK)
    {
        history_revision_clear(&out);
        return rc;
    }

    *dst = out;
    return PM_OK;
}

void pm_history_revision_init(pm_history_revision_t *revision)
{
    if (!revision)
    {
        return;
    }

    memset(revision, 0, sizeof(*revision));
}

void pm_history_revision_free(pm_history_revision_t *revision)
{
    history_revision_clear(revision);
}

pm_error_t pm_history_revision_copy(pm_history_revision_t *dst,
                                    const pm_history_revision_t *src)
{
    return history_revision_clone(dst, src);
}

static void attachment_clear(pm_attachment_t *attachment)
{
    if (!attachment)
    {
        return;
    }

    free(attachment->id);
    free(attachment->name);
    free(attachment->mime);
    free(attachment->blob);
    unknown_fields_free(attachment->unknown_fields, attachment->unknown_field_count);
    memset(attachment, 0, sizeof(*attachment));
}

static pm_error_t attachment_clone(pm_attachment_t *dst,
                                   const pm_attachment_t *src)
{
    pm_attachment_t out = {0};
    pm_error_t rc;

    if (!dst || !src)
    {
        return PM_ERR_INVALID_PARAM;
    }

    rc = validate_attachment_model(src);
    if (rc != PM_OK)
    {
        return rc;
    }

    out.id = dup_cstr_or_empty(src->id);
    out.name = dup_cstr_or_empty(src->name);
    out.mime = dup_cstr_or_empty(src->mime);
    if (!out.id || !out.name || !out.mime)
    {
        attachment_clear(&out);
        return PM_ERR_NOMEM;
    }

    out.size = src->size != 0 ? src->size : src->blob_len;
    out.has_sha256 = src->has_sha256;
    if (src->has_sha256)
    {
        memcpy(out.sha256, src->sha256, sizeof(out.sha256));
    }

    rc = clone_bytes(&out.blob, &out.blob_len, src->blob, src->blob_len);
    if (rc != PM_OK)
    {
        attachment_clear(&out);
        return rc;
    }

    rc = unknown_fields_clone(&out.unknown_fields,
                              &out.unknown_field_count,
                              src->unknown_fields,
                              src->unknown_field_count);
    if (rc != PM_OK)
    {
        attachment_clear(&out);
        return rc;
    }

    *dst = out;
    return PM_OK;
}

void pm_attachment_init(pm_attachment_t *attachment)
{
    if (!attachment)
    {
        return;
    }

    memset(attachment, 0, sizeof(*attachment));
}

void pm_attachment_free(pm_attachment_t *attachment)
{
    attachment_clear(attachment);
}

pm_error_t pm_attachment_copy(pm_attachment_t *dst,
                              const pm_attachment_t *src)
{
    return attachment_clone(dst, src);
}

static void entry_clear(pm_entry_t *entry)
{
    if (!entry)
    {
        return;
    }

    free(entry->id);
    free(entry->title);
    free(entry->username);
    free(entry->password);
    free(entry->url);
    free(entry->notes);
    free(entry->group_id);
    free(entry->color_label);

    free_string_list(entry->urls, entry->url_count);
    free_string_list(entry->tags, entry->tag_count);

    if (entry->custom_fields)
    {
        for (size_t i = 0; i < entry->custom_field_count; i++)
        {
            custom_field_clear(&entry->custom_fields[i]);
        }
        free(entry->custom_fields);
    }

    if (entry->attachment_refs)
    {
        for (size_t i = 0; i < entry->attachment_ref_count; i++)
        {
            attachment_ref_clear(&entry->attachment_refs[i]);
        }
        free(entry->attachment_refs);
    }

    if (entry->history)
    {
        for (size_t i = 0; i < entry->history_count; i++)
        {
            history_revision_clear(&entry->history[i]);
        }
        free(entry->history);
    }

    unknown_fields_free(entry->unknown_fields, entry->unknown_field_count);
    memset(entry, 0, sizeof(*entry));
}

static pm_error_t entry_clone(pm_entry_t *dst, const pm_entry_t *src)
{
    pm_entry_t out = {0};
    pm_error_t rc;

    if (!dst || !src)
    {
        return PM_ERR_INVALID_PARAM;
    }

    rc = validate_entry_model(src);
    if (rc != PM_OK)
    {
        return rc;
    }

    out.id = dup_cstr_or_empty(src->id);
    out.title = dup_cstr_or_empty(src->title);
    out.username = dup_cstr_or_empty(src->username);
    out.password = dup_cstr_or_empty(src->password);
    out.url = dup_cstr_or_empty(src->url);
    out.notes = dup_cstr_or_empty(src->notes);
    out.group_id = dup_cstr_or_empty(src->group_id);
    out.color_label = dup_cstr_or_empty(src->color_label);
    if (!out.id || !out.title || !out.username || !out.password ||
        !out.url || !out.notes || !out.group_id || !out.color_label)
    {
        entry_clear(&out);
        return PM_ERR_NOMEM;
    }

    rc = clone_string_list(&out.urls, &out.url_count, src->urls, src->url_count);
    if (rc != PM_OK)
    {
        entry_clear(&out);
        return rc;
    }

    rc = clone_string_list(&out.tags, &out.tag_count, src->tags, src->tag_count);
    if (rc != PM_OK)
    {
        entry_clear(&out);
        return rc;
    }

    out.created_at_ms = src->created_at_ms;
    out.updated_at_ms = src->updated_at_ms;
    out.accessed_at_ms = src->accessed_at_ms;
    out.favorite = src->favorite;
    out.expiry_at_ms = src->expiry_at_ms;
    out.expiry_warn_days = src->expiry_warn_days;
    out.requires_fresh_biometric = src->requires_fresh_biometric;

    if (src->custom_field_count > 0)
    {
        out.custom_fields = calloc(src->custom_field_count, sizeof(pm_custom_field_t));
        if (!out.custom_fields)
        {
            entry_clear(&out);
            return PM_ERR_NOMEM;
        }

        for (size_t i = 0; i < src->custom_field_count; i++)
        {
            rc = custom_field_clone(&out.custom_fields[i], &src->custom_fields[i]);
            if (rc != PM_OK)
            {
                entry_clear(&out);
                return rc;
            }
        }
        out.custom_field_count = src->custom_field_count;
    }

    if (src->attachment_ref_count > 0)
    {
        out.attachment_refs = calloc(src->attachment_ref_count, sizeof(pm_attachment_ref_t));
        if (!out.attachment_refs)
        {
            entry_clear(&out);
            return PM_ERR_NOMEM;
        }

        for (size_t i = 0; i < src->attachment_ref_count; i++)
        {
            rc = attachment_ref_clone(&out.attachment_refs[i], &src->attachment_refs[i]);
            if (rc != PM_OK)
            {
                entry_clear(&out);
                return rc;
            }
        }
        out.attachment_ref_count = src->attachment_ref_count;
    }

    if (src->history_count > 0)
    {
        out.history = calloc(src->history_count, sizeof(pm_history_revision_t));
        if (!out.history)
        {
            entry_clear(&out);
            return PM_ERR_NOMEM;
        }

        for (size_t i = 0; i < src->history_count; i++)
        {
            rc = history_revision_clone(&out.history[i], &src->history[i]);
            if (rc != PM_OK)
            {
                entry_clear(&out);
                return rc;
            }
        }
        out.history_count = src->history_count;
    }

    rc = unknown_fields_clone(&out.unknown_fields,
                              &out.unknown_field_count,
                              src->unknown_fields,
                              src->unknown_field_count);
    if (rc != PM_OK)
    {
        entry_clear(&out);
        return rc;
    }

    rc = ensure_entry_url_alias(&out);
    if (rc != PM_OK)
    {
        entry_clear(&out);
        return rc;
    }

    *dst = out;
    return PM_OK;
}

void pm_entry_init(pm_entry_t *entry)
{
    if (!entry)
    {
        return;
    }

    memset(entry, 0, sizeof(*entry));
}

void pm_entry_free(pm_entry_t *entry)
{
    entry_clear(entry);
}

pm_error_t pm_entry_copy(pm_entry_t *dst, const pm_entry_t *src)
{
    return entry_clone(dst, src);
}

static void group_clear(pm_group_t *group)
{
    if (!group)
    {
        return;
    }

    free(group->id);
    free(group->parent_id);
    free(group->title);
    free(group->icon_id);
    free(group->color);
    free(group->notes);
    free(group->custom_data_cbor);
    unknown_fields_free(group->unknown_fields, group->unknown_field_count);
    memset(group, 0, sizeof(*group));
}

static pm_error_t group_clone(pm_group_t *dst, const pm_group_t *src)
{
    pm_group_t out = {0};
    pm_error_t rc;

    if (!dst || !src)
    {
        return PM_ERR_INVALID_PARAM;
    }

    rc = validate_group_model(src);
    if (rc != PM_OK)
    {
        return rc;
    }

    out.id = dup_cstr_or_empty(src->id);
    out.parent_id = dup_cstr_or_empty(src->parent_id);
    out.title = dup_cstr_or_empty(src->title);
    out.icon_id = dup_cstr_or_empty(src->icon_id);
    out.color = dup_cstr_or_empty(src->color);
    out.notes = dup_cstr_or_empty(src->notes);
    if (!out.id || !out.parent_id || !out.title || !out.icon_id || !out.color || !out.notes)
    {
        group_clear(&out);
        return PM_ERR_NOMEM;
    }

    out.created_at_ms = src->created_at_ms;
    out.updated_at_ms = src->updated_at_ms;
    out.accessed_at_ms = src->accessed_at_ms;

    rc = clone_bytes(&out.custom_data_cbor,
                     &out.custom_data_cbor_len,
                     src->custom_data_cbor,
                     src->custom_data_cbor_len);
    if (rc != PM_OK)
    {
        group_clear(&out);
        return rc;
    }

    rc = unknown_fields_clone(&out.unknown_fields,
                              &out.unknown_field_count,
                              src->unknown_fields,
                              src->unknown_field_count);
    if (rc != PM_OK)
    {
        group_clear(&out);
        return rc;
    }

    *dst = out;
    return PM_OK;
}

void pm_group_init(pm_group_t *group)
{
    if (!group)
    {
        return;
    }

    memset(group, 0, sizeof(*group));
}

void pm_group_free(pm_group_t *group)
{
    group_clear(group);
}

pm_error_t pm_group_copy(pm_group_t *dst, const pm_group_t *src)
{
    return group_clone(dst, src);
}

static void recycle_bin_clear(pm_recycle_bin_t *bin)
{
    if (!bin)
    {
        return;
    }

    free(bin->group_id);
    unknown_fields_free(bin->unknown_fields, bin->unknown_field_count);
    memset(bin, 0, sizeof(*bin));
}

static pm_error_t recycle_bin_clone(pm_recycle_bin_t *dst,
                                    const pm_recycle_bin_t *src)
{
    pm_recycle_bin_t out = {0};
    pm_error_t rc;

    if (!dst || !src)
    {
        return PM_ERR_INVALID_PARAM;
    }

    out.enabled = src->enabled;
    out.retention_days = src->retention_days;
    out.group_id = dup_cstr_or_empty(src->group_id);
    if (!out.group_id)
    {
        return PM_ERR_NOMEM;
    }

    rc = unknown_fields_clone(&out.unknown_fields,
                              &out.unknown_field_count,
                              src->unknown_fields,
                              src->unknown_field_count);
    if (rc != PM_OK)
    {
        recycle_bin_clear(&out);
        return rc;
    }

    *dst = out;
    return PM_OK;
}

void pm_recycle_bin_init(pm_recycle_bin_t *bin)
{
    if (!bin)
    {
        return;
    }

    memset(bin, 0, sizeof(*bin));
}

void pm_recycle_bin_free(pm_recycle_bin_t *bin)
{
    recycle_bin_clear(bin);
}

pm_error_t pm_recycle_bin_copy(pm_recycle_bin_t *dst,
                               const pm_recycle_bin_t *src)
{
    return recycle_bin_clone(dst, src);
}

void pm_payload_init(pm_payload_t *payload)
{
    if (!payload)
    {
        return;
    }

    memset(payload, 0, sizeof(*payload));
    payload->schema_version = PM_PAYLOAD_SCHEMA_VERSION;
}

void pm_payload_free(pm_payload_t *payload)
{
    if (!payload)
    {
        return;
    }

    if (payload->entries)
    {
        for (size_t i = 0; i < payload->entry_count; i++)
        {
            entry_clear(&payload->entries[i]);
        }
        free(payload->entries);
    }

    if (payload->groups)
    {
        for (size_t i = 0; i < payload->group_count; i++)
        {
            group_clear(&payload->groups[i]);
        }
        free(payload->groups);
    }

    if (payload->attachments)
    {
        for (size_t i = 0; i < payload->attachment_count; i++)
        {
            attachment_clear(&payload->attachments[i]);
        }
        free(payload->attachments);
    }

    recycle_bin_clear(&payload->recycle_bin);
    free(payload->security_audit_cache_cbor);
    unknown_fields_free(payload->unknown_fields, payload->unknown_field_count);

    pm_payload_init(payload);
}

pm_error_t pm_payload_append_group(pm_payload_t *payload, const pm_group_t *group)
{
    pm_group_t *new_groups;
    pm_group_t copy = {0};
    pm_error_t rc;

    if (!payload || !group)
    {
        return PM_ERR_INVALID_PARAM;
    }

    if (payload->group_count >= PM_PAYLOAD_MAX_GROUPS)
    {
        return PM_ERR_STATE;
    }

    rc = group_clone(&copy, group);
    if (rc != PM_OK)
    {
        return rc;
    }

    new_groups = realloc(payload->groups,
                         (payload->group_count + 1u) * sizeof(pm_group_t));
    if (!new_groups)
    {
        group_clear(&copy);
        return PM_ERR_NOMEM;
    }

    payload->groups = new_groups;
    payload->groups[payload->group_count] = copy;
    payload->group_count++;

    return PM_OK;
}

pm_error_t pm_payload_append_entry(pm_payload_t *payload, const pm_entry_t *entry)
{
    pm_entry_t *new_entries;
    pm_entry_t copy = {0};
    pm_error_t rc;

    if (!payload || !entry)
    {
        return PM_ERR_INVALID_PARAM;
    }

    if (payload->entry_count >= PM_PAYLOAD_MAX_ENTRIES)
    {
        return PM_ERR_STATE;
    }

    rc = entry_clone(&copy, entry);
    if (rc != PM_OK)
    {
        return rc;
    }

    new_entries = realloc(payload->entries,
                          (payload->entry_count + 1u) * sizeof(pm_entry_t));
    if (!new_entries)
    {
        entry_clear(&copy);
        return PM_ERR_NOMEM;
    }

    payload->entries = new_entries;
    payload->entries[payload->entry_count] = copy;
    payload->entry_count++;

    return PM_OK;
}

pm_error_t pm_payload_append_attachment(pm_payload_t *payload,
                                        const pm_attachment_t *attachment)
{
    pm_attachment_t *new_attachments;
    pm_attachment_t copy = {0};
    pm_error_t rc;

    if (!payload || !attachment)
    {
        return PM_ERR_INVALID_PARAM;
    }

    if (payload->attachment_count >= PM_PAYLOAD_MAX_ATTACHMENTS)
    {
        return PM_ERR_STATE;
    }

    rc = attachment_clone(&copy, attachment);
    if (rc != PM_OK)
    {
        return rc;
    }

    new_attachments = realloc(payload->attachments,
                              (payload->attachment_count + 1u) * sizeof(pm_attachment_t));
    if (!new_attachments)
    {
        attachment_clear(&copy);
        return PM_ERR_NOMEM;
    }

    payload->attachments = new_attachments;
    payload->attachments[payload->attachment_count] = copy;
    payload->attachment_count++;

    return PM_OK;
}

static pm_error_t encode_custom_field(bio_cbor_encoder_t *enc,
                                      const pm_custom_field_t *field)
{
    if (!field)
    {
        return PM_ERR_INVALID_PARAM;
    }

    if (!custom_field_type_valid(field->type))
    {
        return PM_ERR_FORMAT;
    }

    if (bio_cbor_encode_map(enc, 5u + field->unknown_field_count) != BIO_OK ||
        bio_cbor_encode_uint(enc, PMCF_NAME) != BIO_OK ||
        encode_tstr_or_empty(enc, field->name) != BIO_OK ||
        bio_cbor_encode_uint(enc, PMCF_TYPE) != BIO_OK ||
        bio_cbor_encode_uint(enc, field->type) != BIO_OK ||
        bio_cbor_encode_uint(enc, PMCF_TEXT_VALUE) != BIO_OK ||
        encode_tstr_or_empty(enc, field->text_value) != BIO_OK ||
        bio_cbor_encode_uint(enc, PMCF_DATE_VALUE_MS) != BIO_OK ||
        bio_cbor_encode_uint(enc, field->date_value_ms) != BIO_OK ||
        bio_cbor_encode_uint(enc, PMCF_BINARY_REF) != BIO_OK ||
        encode_tstr_or_empty(enc, field->binary_ref) != BIO_OK)
    {
        return PM_ERR_SERIALIZE;
    }

    for (size_t i = 0; i < field->unknown_field_count; i++)
    {
        const pm_unknown_field_t *u = &field->unknown_fields[i];
        if (bio_cbor_encode_uint(enc, u->key) != BIO_OK ||
            encode_raw_cbor(enc, u->value_cbor, u->value_cbor_len) != BIO_OK)
        {
            return PM_ERR_SERIALIZE;
        }
    }

    return PM_OK;
}

static pm_error_t encode_attachment_ref(bio_cbor_encoder_t *enc,
                                        const pm_attachment_ref_t *ref)
{
    if (!ref)
    {
        return PM_ERR_INVALID_PARAM;
    }

    if (bio_cbor_encode_map(enc, 1u + ref->unknown_field_count) != BIO_OK ||
        bio_cbor_encode_uint(enc, PMAR_ATTACHMENT_ID) != BIO_OK ||
        encode_tstr_or_empty(enc, ref->attachment_id) != BIO_OK)
    {
        return PM_ERR_SERIALIZE;
    }

    for (size_t i = 0; i < ref->unknown_field_count; i++)
    {
        const pm_unknown_field_t *u = &ref->unknown_fields[i];
        if (bio_cbor_encode_uint(enc, u->key) != BIO_OK ||
            encode_raw_cbor(enc, u->value_cbor, u->value_cbor_len) != BIO_OK)
        {
            return PM_ERR_SERIALIZE;
        }
    }

    return PM_OK;
}

static pm_error_t encode_history_revision(bio_cbor_encoder_t *enc,
                                          const pm_history_revision_t *revision)
{
    if (!revision)
    {
        return PM_ERR_INVALID_PARAM;
    }

    if (validate_history_revision_model(revision) != PM_OK)
    {
        return PM_ERR_FORMAT;
    }

    if (bio_cbor_encode_map(enc, 14u + revision->unknown_field_count) != BIO_OK ||
        bio_cbor_encode_uint(enc, PMH_MODIFIED_AT_MS) != BIO_OK ||
        bio_cbor_encode_uint(enc, revision->revision_ts_ms) != BIO_OK ||
        bio_cbor_encode_uint(enc, PMH_SOURCE) != BIO_OK ||
        encode_tstr_or_empty(enc, revision->source) != BIO_OK ||
        bio_cbor_encode_uint(enc, PMH_ACTOR) != BIO_OK ||
        encode_tstr_or_empty(enc, revision->actor) != BIO_OK ||
        bio_cbor_encode_uint(enc, PMH_ID) != BIO_OK ||
        encode_tstr_or_empty(enc, revision->id) != BIO_OK ||
        bio_cbor_encode_uint(enc, PMH_TITLE) != BIO_OK ||
        encode_tstr_or_empty(enc, revision->title) != BIO_OK ||
        bio_cbor_encode_uint(enc, PMH_USERNAME) != BIO_OK ||
        encode_tstr_or_empty(enc, revision->username) != BIO_OK ||
        bio_cbor_encode_uint(enc, PMH_PASSWORD) != BIO_OK ||
        encode_tstr_or_empty(enc, revision->password) != BIO_OK ||
        bio_cbor_encode_uint(enc, PMH_URL) != BIO_OK ||
        encode_tstr_or_empty(enc, revision->url) != BIO_OK ||
        bio_cbor_encode_uint(enc, PMH_NOTES) != BIO_OK ||
        encode_tstr_or_empty(enc, revision->notes) != BIO_OK ||
        bio_cbor_encode_uint(enc, PMH_GROUP_ID) != BIO_OK ||
        encode_tstr_or_empty(enc, revision->group_id) != BIO_OK ||
        bio_cbor_encode_uint(enc, PMH_TAGS) != BIO_OK ||
        bio_cbor_encode_array(enc, revision->tag_count) != BIO_OK)
    {
        return PM_ERR_SERIALIZE;
    }

    for (size_t i = 0; i < revision->tag_count; i++)
    {
        if (encode_tstr_or_empty(enc, revision->tags[i]) != BIO_OK)
        {
            return PM_ERR_SERIALIZE;
        }
    }

    if (bio_cbor_encode_uint(enc, PMH_CREATED_AT_MS) != BIO_OK ||
        bio_cbor_encode_uint(enc, revision->created_at_ms) != BIO_OK ||
        bio_cbor_encode_uint(enc, PMH_UPDATED_AT_MS) != BIO_OK ||
        bio_cbor_encode_uint(enc, revision->updated_at_ms) != BIO_OK ||
        bio_cbor_encode_uint(enc, PMH_FAVORITE) != BIO_OK ||
        bio_cbor_encode_bool(enc, revision->favorite) != BIO_OK)
    {
        return PM_ERR_SERIALIZE;
    }

    for (size_t i = 0; i < revision->unknown_field_count; i++)
    {
        const pm_unknown_field_t *u = &revision->unknown_fields[i];
        if (bio_cbor_encode_uint(enc, u->key) != BIO_OK ||
            encode_raw_cbor(enc, u->value_cbor, u->value_cbor_len) != BIO_OK)
        {
            return PM_ERR_SERIALIZE;
        }
    }

    return PM_OK;
}

static pm_error_t encode_attachment(bio_cbor_encoder_t *enc,
                                    const pm_attachment_t *attachment)
{
    uint64_t size_value;

    if (!attachment)
    {
        return PM_ERR_INVALID_PARAM;
    }

    if (validate_attachment_model(attachment) != PM_OK)
    {
        return PM_ERR_FORMAT;
    }

    size_value = attachment->size != 0 ? attachment->size : attachment->blob_len;

    if (bio_cbor_encode_map(enc, 6u + attachment->unknown_field_count) != BIO_OK ||
        bio_cbor_encode_uint(enc, PMA_ID) != BIO_OK ||
        encode_tstr_or_empty(enc, attachment->id) != BIO_OK ||
        bio_cbor_encode_uint(enc, PMA_NAME) != BIO_OK ||
        encode_tstr_or_empty(enc, attachment->name) != BIO_OK ||
        bio_cbor_encode_uint(enc, PMA_MIME) != BIO_OK ||
        encode_tstr_or_empty(enc, attachment->mime) != BIO_OK ||
        bio_cbor_encode_uint(enc, PMA_SIZE) != BIO_OK ||
        bio_cbor_encode_uint(enc, size_value) != BIO_OK ||
        bio_cbor_encode_uint(enc, PMA_SHA256) != BIO_OK ||
        encode_bstr_or_empty(enc,
                             attachment->has_sha256 ? attachment->sha256 : NULL,
                             attachment->has_sha256 ? sizeof(attachment->sha256) : 0u) != BIO_OK ||
        bio_cbor_encode_uint(enc, PMA_BLOB) != BIO_OK ||
        encode_bstr_or_empty(enc, attachment->blob, attachment->blob_len) != BIO_OK)
    {
        return PM_ERR_SERIALIZE;
    }

    for (size_t i = 0; i < attachment->unknown_field_count; i++)
    {
        const pm_unknown_field_t *u = &attachment->unknown_fields[i];
        if (bio_cbor_encode_uint(enc, u->key) != BIO_OK ||
            encode_raw_cbor(enc, u->value_cbor, u->value_cbor_len) != BIO_OK)
        {
            return PM_ERR_SERIALIZE;
        }
    }

    return PM_OK;
}

static pm_error_t encode_entry(bio_cbor_encoder_t *enc,
                               const pm_entry_t *entry)
{
    const char *legacy_url;
    size_t url_count;

    if (!entry)
    {
        return PM_ERR_INVALID_PARAM;
    }

    if (validate_entry_model(entry) != PM_OK)
    {
        return PM_ERR_FORMAT;
    }

    legacy_url = (entry->url_count > 0 && entry->urls && entry->urls[0])
                     ? entry->urls[0]
                     : entry->url;
    url_count = entry->url_count;

    if (bio_cbor_encode_map(enc, 20u + entry->unknown_field_count) != BIO_OK ||
        bio_cbor_encode_uint(enc, PME_ID) != BIO_OK ||
        encode_tstr_or_empty(enc, entry->id) != BIO_OK ||
        bio_cbor_encode_uint(enc, PME_TITLE) != BIO_OK ||
        encode_tstr_or_empty(enc, entry->title) != BIO_OK ||
        bio_cbor_encode_uint(enc, PME_USERNAME) != BIO_OK ||
        encode_tstr_or_empty(enc, entry->username) != BIO_OK ||
        bio_cbor_encode_uint(enc, PME_PASSWORD) != BIO_OK ||
        encode_tstr_or_empty(enc, entry->password) != BIO_OK ||
        bio_cbor_encode_uint(enc, PME_URL) != BIO_OK ||
        encode_tstr_or_empty(enc, legacy_url) != BIO_OK ||
        bio_cbor_encode_uint(enc, PME_NOTES) != BIO_OK ||
        encode_tstr_or_empty(enc, entry->notes) != BIO_OK ||
        bio_cbor_encode_uint(enc, PME_TAGS) != BIO_OK ||
        bio_cbor_encode_array(enc, entry->tag_count) != BIO_OK)
    {
        return PM_ERR_SERIALIZE;
    }

    for (size_t i = 0; i < entry->tag_count; i++)
    {
        if (encode_tstr_or_empty(enc, entry->tags[i]) != BIO_OK)
        {
            return PM_ERR_SERIALIZE;
        }
    }

    if (bio_cbor_encode_uint(enc, PME_GROUP_ID) != BIO_OK ||
        encode_tstr_or_empty(enc, entry->group_id) != BIO_OK ||
        bio_cbor_encode_uint(enc, PME_CREATED_AT_MS) != BIO_OK ||
        bio_cbor_encode_uint(enc, entry->created_at_ms) != BIO_OK ||
        bio_cbor_encode_uint(enc, PME_UPDATED_AT_MS) != BIO_OK ||
        bio_cbor_encode_uint(enc, entry->updated_at_ms) != BIO_OK ||
        bio_cbor_encode_uint(enc, PME_FAVORITE) != BIO_OK ||
        bio_cbor_encode_bool(enc, entry->favorite) != BIO_OK ||
        bio_cbor_encode_uint(enc, PME_ACCESSED_AT_MS) != BIO_OK ||
        bio_cbor_encode_uint(enc, entry->accessed_at_ms) != BIO_OK ||
        bio_cbor_encode_uint(enc, PME_COLOR_LABEL) != BIO_OK ||
        encode_tstr_or_empty(enc, entry->color_label) != BIO_OK ||
        bio_cbor_encode_uint(enc, PME_EXPIRY_AT_MS) != BIO_OK ||
        bio_cbor_encode_uint(enc, entry->expiry_at_ms) != BIO_OK ||
        bio_cbor_encode_uint(enc, PME_EXPIRY_WARN_DAYS) != BIO_OK ||
        bio_cbor_encode_uint(enc, entry->expiry_warn_days) != BIO_OK ||
        bio_cbor_encode_uint(enc, PME_CUSTOM_FIELDS) != BIO_OK ||
        bio_cbor_encode_array(enc, entry->custom_field_count) != BIO_OK)
    {
        return PM_ERR_SERIALIZE;
    }

    for (size_t i = 0; i < entry->custom_field_count; i++)
    {
        pm_error_t rc = encode_custom_field(enc, &entry->custom_fields[i]);
        if (rc != PM_OK)
        {
            return rc;
        }
    }

    if (bio_cbor_encode_uint(enc, PME_ATTACHMENT_REFS) != BIO_OK ||
        bio_cbor_encode_array(enc, entry->attachment_ref_count) != BIO_OK)
    {
        return PM_ERR_SERIALIZE;
    }

    for (size_t i = 0; i < entry->attachment_ref_count; i++)
    {
        pm_error_t rc = encode_attachment_ref(enc, &entry->attachment_refs[i]);
        if (rc != PM_OK)
        {
            return rc;
        }
    }

    if (bio_cbor_encode_uint(enc, PME_HISTORY) != BIO_OK ||
        bio_cbor_encode_array(enc, entry->history_count) != BIO_OK)
    {
        return PM_ERR_SERIALIZE;
    }

    for (size_t i = 0; i < entry->history_count; i++)
    {
        pm_error_t rc = encode_history_revision(enc, &entry->history[i]);
        if (rc != PM_OK)
        {
            return rc;
        }
    }

    if (bio_cbor_encode_uint(enc, PME_REQUIRES_FRESH_BIOMETRIC) != BIO_OK ||
        bio_cbor_encode_bool(enc, entry->requires_fresh_biometric) != BIO_OK ||
        bio_cbor_encode_uint(enc, PME_URL_LIST) != BIO_OK ||
        bio_cbor_encode_array(enc, url_count) != BIO_OK)
    {
        return PM_ERR_SERIALIZE;
    }

    for (size_t i = 0; i < url_count; i++)
    {
        if (encode_tstr_or_empty(enc, entry->urls[i]) != BIO_OK)
        {
            return PM_ERR_SERIALIZE;
        }
    }

    for (size_t i = 0; i < entry->unknown_field_count; i++)
    {
        const pm_unknown_field_t *u = &entry->unknown_fields[i];
        if (bio_cbor_encode_uint(enc, u->key) != BIO_OK ||
            encode_raw_cbor(enc, u->value_cbor, u->value_cbor_len) != BIO_OK)
        {
            return PM_ERR_SERIALIZE;
        }
    }

    return PM_OK;
}

static pm_error_t encode_group(bio_cbor_encoder_t *enc,
                               const pm_group_t *group)
{
    size_t map_count;

    if (!group)
    {
        return PM_ERR_INVALID_PARAM;
    }

    if (validate_group_model(group) != PM_OK)
    {
        return PM_ERR_FORMAT;
    }

    map_count = 9u + group->unknown_field_count;
    if (group->custom_data_cbor_len > 0)
    {
        map_count++;
    }

    if (bio_cbor_encode_map(enc, map_count) != BIO_OK ||
        bio_cbor_encode_uint(enc, PMG_ID) != BIO_OK ||
        encode_tstr_or_empty(enc, group->id) != BIO_OK ||
        bio_cbor_encode_uint(enc, PMG_PARENT_ID) != BIO_OK ||
        encode_tstr_or_empty(enc, group->parent_id) != BIO_OK ||
        bio_cbor_encode_uint(enc, PMG_TITLE) != BIO_OK ||
        encode_tstr_or_empty(enc, group->title) != BIO_OK ||
        bio_cbor_encode_uint(enc, PMG_ICON_ID) != BIO_OK ||
        encode_tstr_or_empty(enc, group->icon_id) != BIO_OK ||
        bio_cbor_encode_uint(enc, PMG_COLOR) != BIO_OK ||
        encode_tstr_or_empty(enc, group->color) != BIO_OK ||
        bio_cbor_encode_uint(enc, PMG_NOTES) != BIO_OK ||
        encode_tstr_or_empty(enc, group->notes) != BIO_OK ||
        bio_cbor_encode_uint(enc, PMG_CREATED_AT_MS) != BIO_OK ||
        bio_cbor_encode_uint(enc, group->created_at_ms) != BIO_OK ||
        bio_cbor_encode_uint(enc, PMG_UPDATED_AT_MS) != BIO_OK ||
        bio_cbor_encode_uint(enc, group->updated_at_ms) != BIO_OK ||
        bio_cbor_encode_uint(enc, PMG_ACCESSED_AT_MS) != BIO_OK ||
        bio_cbor_encode_uint(enc, group->accessed_at_ms) != BIO_OK)
    {
        return PM_ERR_SERIALIZE;
    }

    if (group->custom_data_cbor_len > 0)
    {
        if (bio_cbor_encode_uint(enc, PMG_CUSTOM_DATA) != BIO_OK ||
            encode_raw_cbor(enc, group->custom_data_cbor, group->custom_data_cbor_len) != BIO_OK)
        {
            return PM_ERR_SERIALIZE;
        }
    }

    for (size_t i = 0; i < group->unknown_field_count; i++)
    {
        const pm_unknown_field_t *u = &group->unknown_fields[i];
        if (bio_cbor_encode_uint(enc, u->key) != BIO_OK ||
            encode_raw_cbor(enc, u->value_cbor, u->value_cbor_len) != BIO_OK)
        {
            return PM_ERR_SERIALIZE;
        }
    }

    return PM_OK;
}

static pm_error_t encode_recycle_bin(bio_cbor_encoder_t *enc,
                                     const pm_recycle_bin_t *bin)
{
    if (!bin)
    {
        return PM_ERR_INVALID_PARAM;
    }

    if (bio_cbor_encode_map(enc, 3u + bin->unknown_field_count) != BIO_OK ||
        bio_cbor_encode_uint(enc, PMR_ENABLED) != BIO_OK ||
        bio_cbor_encode_bool(enc, bin->enabled) != BIO_OK ||
        bio_cbor_encode_uint(enc, PMR_GROUP_ID) != BIO_OK ||
        encode_tstr_or_empty(enc, bin->group_id) != BIO_OK ||
        bio_cbor_encode_uint(enc, PMR_RETENTION_DAYS) != BIO_OK ||
        bio_cbor_encode_uint(enc, bin->retention_days) != BIO_OK)
    {
        return PM_ERR_SERIALIZE;
    }

    for (size_t i = 0; i < bin->unknown_field_count; i++)
    {
        const pm_unknown_field_t *u = &bin->unknown_fields[i];
        if (bio_cbor_encode_uint(enc, u->key) != BIO_OK ||
            encode_raw_cbor(enc, u->value_cbor, u->value_cbor_len) != BIO_OK)
        {
            return PM_ERR_SERIALIZE;
        }
    }

    return PM_OK;
}

static pm_error_t encode_payload_into(const pm_payload_t *payload,
                                      uint8_t *buf,
                                      size_t cap,
                                      size_t *out_len)
{
    bio_cbor_encoder_t enc;
    size_t map_count;

    if (!payload || !buf || !out_len)
    {
        return PM_ERR_INVALID_PARAM;
    }

    if (validate_payload_model(payload) != PM_OK)
    {
        return PM_ERR_FORMAT;
    }

    bio_cbor_encoder_init(&enc, buf, cap);

    map_count = 7u + payload->unknown_field_count;
    if (payload->has_vault_uuid)
    {
        map_count++;
    }
    if (payload->security_audit_cache_cbor_len > 0)
    {
        map_count++;
    }

    if (bio_cbor_encode_map(&enc, map_count) != BIO_OK ||
        bio_cbor_encode_uint(&enc, PMK_SCHEMA_VERSION) != BIO_OK ||
        bio_cbor_encode_uint(&enc, payload->schema_version) != BIO_OK ||
        bio_cbor_encode_uint(&enc, PMK_CREATED_AT_MS) != BIO_OK ||
        bio_cbor_encode_uint(&enc, payload->created_at_ms) != BIO_OK ||
        bio_cbor_encode_uint(&enc, PMK_UPDATED_AT_MS) != BIO_OK ||
        bio_cbor_encode_uint(&enc, payload->updated_at_ms) != BIO_OK ||
        bio_cbor_encode_uint(&enc, PMK_ENTRIES) != BIO_OK ||
        bio_cbor_encode_array(&enc, payload->entry_count) != BIO_OK)
    {
        return PM_ERR_SERIALIZE;
    }

    for (size_t i = 0; i < payload->entry_count; i++)
    {
        pm_error_t rc = encode_entry(&enc, &payload->entries[i]);
        if (rc != PM_OK)
        {
            return rc;
        }
    }

    if (bio_cbor_encode_uint(&enc, PMK_GROUPS) != BIO_OK ||
        bio_cbor_encode_array(&enc, payload->group_count) != BIO_OK)
    {
        return PM_ERR_SERIALIZE;
    }

    for (size_t i = 0; i < payload->group_count; i++)
    {
        pm_error_t rc = encode_group(&enc, &payload->groups[i]);
        if (rc != PM_OK)
        {
            return rc;
        }
    }

    if (payload->has_vault_uuid)
    {
        if (bio_cbor_encode_uint(&enc, PMK_VAULT_UUID) != BIO_OK ||
            bio_cbor_encode_bstr(&enc, payload->vault_uuid, sizeof(payload->vault_uuid)) != BIO_OK)
        {
            return PM_ERR_SERIALIZE;
        }
    }

    if (bio_cbor_encode_uint(&enc, PMK_ATTACHMENTS) != BIO_OK ||
        bio_cbor_encode_array(&enc, payload->attachment_count) != BIO_OK)
    {
        return PM_ERR_SERIALIZE;
    }

    for (size_t i = 0; i < payload->attachment_count; i++)
    {
        pm_error_t rc = encode_attachment(&enc, &payload->attachments[i]);
        if (rc != PM_OK)
        {
            return rc;
        }
    }

    if (bio_cbor_encode_uint(&enc, PMK_RECYCLE_BIN) != BIO_OK)
    {
        return PM_ERR_SERIALIZE;
    }

    {
        pm_error_t rc = encode_recycle_bin(&enc, &payload->recycle_bin);
        if (rc != PM_OK)
        {
            return rc;
        }
    }

    if (payload->security_audit_cache_cbor_len > 0)
    {
        if (bio_cbor_encode_uint(&enc, PMK_SECURITY_AUDIT_CACHE) != BIO_OK ||
            encode_raw_cbor(&enc,
                            payload->security_audit_cache_cbor,
                            payload->security_audit_cache_cbor_len) != BIO_OK)
        {
            return PM_ERR_SERIALIZE;
        }
    }

    for (size_t i = 0; i < payload->unknown_field_count; i++)
    {
        const pm_unknown_field_t *u = &payload->unknown_fields[i];
        if (bio_cbor_encode_uint(&enc, u->key) != BIO_OK ||
            encode_raw_cbor(&enc, u->value_cbor, u->value_cbor_len) != BIO_OK)
        {
            return PM_ERR_SERIALIZE;
        }
    }

    if (bio_cbor_encoder_has_error(&enc))
    {
        return PM_ERR_SERIALIZE;
    }

    *out_len = bio_cbor_encoder_len(&enc);
    return PM_OK;
}

pm_error_t pm_payload_encode_cbor(const pm_payload_t *payload,
                                  uint8_t **out,
                                  size_t *out_len)
{
    uint8_t *buf = NULL;
    size_t cap = 4096u;
    size_t encoded_len = 0;

    if (!payload || !out || !out_len)
    {
        return PM_ERR_INVALID_PARAM;
    }

    *out = NULL;
    *out_len = 0;

    for (unsigned attempt = 0; attempt < 20u; attempt++)
    {
        free(buf);
        buf = calloc(1u, cap);
        if (!buf)
        {
            return PM_ERR_NOMEM;
        }

        pm_error_t rc = encode_payload_into(payload, buf, cap, &encoded_len);
        if (rc == PM_OK)
        {
            *out = malloc(encoded_len);
            if (!*out)
            {
                free(buf);
                return PM_ERR_NOMEM;
            }

            memcpy(*out, buf, encoded_len);
            *out_len = encoded_len;
            free(buf);
            return PM_OK;
        }

        if (rc != PM_ERR_SERIALIZE)
        {
            free(buf);
            return rc;
        }

        if (cap > SIZE_MAX / 2u)
        {
            break;
        }

        cap *= 2u;
    }

    free(buf);
    return PM_ERR_SERIALIZE;
}

static pm_error_t decode_custom_field(bio_cbor_decoder_t *dec,
                                      pm_custom_field_t *out)
{
    size_t map_count = 0;
    pm_custom_field_t field = {0};

    if (bio_cbor_decode_map(dec, &map_count) != BIO_OK)
    {
        return PM_ERR_DESERIALIZE;
    }

    for (size_t i = 0; i < map_count; i++)
    {
        uint64_t key = 0;

        if (bio_cbor_decode_uint(dec, &key) != BIO_OK)
        {
            custom_field_clear(&field);
            return PM_ERR_DESERIALIZE;
        }

        switch (key)
        {
        case PMCF_NAME:
        case PMCF_TEXT_VALUE:
        case PMCF_BINARY_REF:
        {
            const char *s = NULL;
            size_t len = 0;
            char **target = NULL;

            if (bio_cbor_decode_tstr(dec, &s, &len) != BIO_OK)
            {
                custom_field_clear(&field);
                return PM_ERR_DESERIALIZE;
            }

            target = (key == PMCF_NAME) ? &field.name
                                        : (key == PMCF_TEXT_VALUE) ? &field.text_value
                                                                   : &field.binary_ref;
            if (*target)
            {
                custom_field_clear(&field);
                return PM_ERR_FORMAT;
            }

            *target = dup_bytes_as_cstr(s, len);
            if (!*target)
            {
                custom_field_clear(&field);
                return PM_ERR_NOMEM;
            }
            break;
        }

        case PMCF_TYPE:
        {
            uint64_t v = 0;
            if (bio_cbor_decode_uint(dec, &v) != BIO_OK || v > PM_FIELD_BINARY_REF)
            {
                custom_field_clear(&field);
                return PM_ERR_DESERIALIZE;
            }
            field.type = (pm_custom_field_type_t)v;
            break;
        }

        case PMCF_DATE_VALUE_MS:
            if (bio_cbor_decode_uint(dec, &field.date_value_ms) != BIO_OK)
            {
                custom_field_clear(&field);
                return PM_ERR_DESERIALIZE;
            }
            break;

        default:
        {
            uint8_t *raw = NULL;
            size_t raw_len = 0;
            pm_error_t rc = capture_next_item(dec, &raw, &raw_len);
            if (rc != PM_OK)
            {
                custom_field_clear(&field);
                return rc;
            }

            rc = unknown_fields_append(&field.unknown_fields,
                                       &field.unknown_field_count,
                                       key,
                                       raw,
                                       raw_len);
            free(raw);
            if (rc != PM_OK)
            {
                custom_field_clear(&field);
                return rc;
            }
            break;
        }
        }
    }

    if (!field.name)
    {
        field.name = dup_cstr_or_empty(NULL);
    }
    if (!field.text_value)
    {
        field.text_value = dup_cstr_or_empty(NULL);
    }
    if (!field.binary_ref)
    {
        field.binary_ref = dup_cstr_or_empty(NULL);
    }

    if (!field.name || !field.text_value || !field.binary_ref)
    {
        custom_field_clear(&field);
        return PM_ERR_NOMEM;
    }

    *out = field;
    return PM_OK;
}

static pm_error_t decode_attachment_ref(bio_cbor_decoder_t *dec,
                                        pm_attachment_ref_t *out)
{
    size_t map_count = 0;
    pm_attachment_ref_t ref = {0};

    if (bio_cbor_decode_map(dec, &map_count) != BIO_OK)
    {
        return PM_ERR_DESERIALIZE;
    }

    for (size_t i = 0; i < map_count; i++)
    {
        uint64_t key = 0;

        if (bio_cbor_decode_uint(dec, &key) != BIO_OK)
        {
            attachment_ref_clear(&ref);
            return PM_ERR_DESERIALIZE;
        }

        if (key == PMAR_ATTACHMENT_ID)
        {
            const char *s = NULL;
            size_t len = 0;

            if (bio_cbor_decode_tstr(dec, &s, &len) != BIO_OK)
            {
                attachment_ref_clear(&ref);
                return PM_ERR_DESERIALIZE;
            }

            if (ref.attachment_id)
            {
                attachment_ref_clear(&ref);
                return PM_ERR_FORMAT;
            }

            ref.attachment_id = dup_bytes_as_cstr(s, len);
            if (!ref.attachment_id)
            {
                attachment_ref_clear(&ref);
                return PM_ERR_NOMEM;
            }
        }
        else
        {
            uint8_t *raw = NULL;
            size_t raw_len = 0;
            pm_error_t rc = capture_next_item(dec, &raw, &raw_len);
            if (rc != PM_OK)
            {
                attachment_ref_clear(&ref);
                return rc;
            }

            rc = unknown_fields_append(&ref.unknown_fields,
                                       &ref.unknown_field_count,
                                       key,
                                       raw,
                                       raw_len);
            free(raw);
            if (rc != PM_OK)
            {
                attachment_ref_clear(&ref);
                return rc;
            }
        }
    }

    if (!ref.attachment_id)
    {
        ref.attachment_id = dup_cstr_or_empty(NULL);
        if (!ref.attachment_id)
        {
            attachment_ref_clear(&ref);
            return PM_ERR_NOMEM;
        }
    }

    *out = ref;
    return PM_OK;
}

static pm_error_t decode_history_revision(bio_cbor_decoder_t *dec,
                                          pm_history_revision_t *out)
{
    size_t map_count = 0;
    pm_history_revision_t revision = {0};

    if (bio_cbor_decode_map(dec, &map_count) != BIO_OK)
    {
        return PM_ERR_DESERIALIZE;
    }

    for (size_t i = 0; i < map_count; i++)
    {
        uint64_t key = 0;

        if (bio_cbor_decode_uint(dec, &key) != BIO_OK)
        {
            history_revision_clear(&revision);
            return PM_ERR_DESERIALIZE;
        }

        switch (key)
        {
        case PMH_MODIFIED_AT_MS:
            if (bio_cbor_decode_uint(dec, &revision.revision_ts_ms) != BIO_OK)
            {
                history_revision_clear(&revision);
                return PM_ERR_DESERIALIZE;
            }
            break;

        case PMH_SOURCE:
        case PMH_ACTOR:
        case PMH_ID:
        case PMH_TITLE:
        case PMH_USERNAME:
        case PMH_PASSWORD:
        case PMH_URL:
        case PMH_NOTES:
        case PMH_GROUP_ID:
        {
            const char *s = NULL;
            size_t len = 0;
            char **target = NULL;

            if (bio_cbor_decode_tstr(dec, &s, &len) != BIO_OK)
            {
                history_revision_clear(&revision);
                return PM_ERR_DESERIALIZE;
            }

            switch (key)
            {
            case PMH_SOURCE:
                target = &revision.source;
                break;
            case PMH_ACTOR:
                target = &revision.actor;
                break;
            case PMH_ID:
                target = &revision.id;
                break;
            case PMH_TITLE:
                target = &revision.title;
                break;
            case PMH_USERNAME:
                target = &revision.username;
                break;
            case PMH_PASSWORD:
                target = &revision.password;
                break;
            case PMH_URL:
                target = &revision.url;
                break;
            case PMH_NOTES:
                target = &revision.notes;
                break;
            case PMH_GROUP_ID:
                target = &revision.group_id;
                break;
            default:
                break;
            }

            if (*target)
            {
                history_revision_clear(&revision);
                return PM_ERR_FORMAT;
            }

            *target = dup_bytes_as_cstr(s, len);
            if (!*target)
            {
                history_revision_clear(&revision);
                return PM_ERR_NOMEM;
            }
            break;
        }

        case PMH_TAGS:
        {
            size_t count = 0;
            if (bio_cbor_decode_array(dec, &count) != BIO_OK ||
                count > PM_PAYLOAD_MAX_TAGS_PER_ENTRY)
            {
                history_revision_clear(&revision);
                return PM_ERR_DESERIALIZE;
            }

            if (count > 0)
            {
                revision.tags = calloc(count, sizeof(char *));
                if (!revision.tags)
                {
                    history_revision_clear(&revision);
                    return PM_ERR_NOMEM;
                }
            }

            revision.tag_count = count;
            for (size_t j = 0; j < count; j++)
            {
                const char *s = NULL;
                size_t len = 0;
                if (bio_cbor_decode_tstr(dec, &s, &len) != BIO_OK)
                {
                    history_revision_clear(&revision);
                    return PM_ERR_DESERIALIZE;
                }

                revision.tags[j] = dup_bytes_as_cstr(s, len);
                if (!revision.tags[j])
                {
                    history_revision_clear(&revision);
                    return PM_ERR_NOMEM;
                }
            }
            break;
        }

        case PMH_CREATED_AT_MS:
            if (bio_cbor_decode_uint(dec, &revision.created_at_ms) != BIO_OK)
            {
                history_revision_clear(&revision);
                return PM_ERR_DESERIALIZE;
            }
            break;

        case PMH_UPDATED_AT_MS:
            if (bio_cbor_decode_uint(dec, &revision.updated_at_ms) != BIO_OK)
            {
                history_revision_clear(&revision);
                return PM_ERR_DESERIALIZE;
            }
            break;

        case PMH_FAVORITE:
            if (bio_cbor_decode_bool(dec, &revision.favorite) != BIO_OK)
            {
                history_revision_clear(&revision);
                return PM_ERR_DESERIALIZE;
            }
            break;

        default:
        {
            uint8_t *raw = NULL;
            size_t raw_len = 0;
            pm_error_t rc = capture_next_item(dec, &raw, &raw_len);
            if (rc != PM_OK)
            {
                history_revision_clear(&revision);
                return rc;
            }

            rc = unknown_fields_append(&revision.unknown_fields,
                                       &revision.unknown_field_count,
                                       key,
                                       raw,
                                       raw_len);
            free(raw);
            if (rc != PM_OK)
            {
                history_revision_clear(&revision);
                return rc;
            }
            break;
        }
        }
    }

    if (!revision.source)
    {
        revision.source = dup_cstr_or_empty(NULL);
    }
    if (!revision.actor)
    {
        revision.actor = dup_cstr_or_empty(NULL);
    }
    if (!revision.id)
    {
        revision.id = dup_cstr_or_empty(NULL);
    }
    if (!revision.title)
    {
        revision.title = dup_cstr_or_empty(NULL);
    }
    if (!revision.username)
    {
        revision.username = dup_cstr_or_empty(NULL);
    }
    if (!revision.password)
    {
        revision.password = dup_cstr_or_empty(NULL);
    }
    if (!revision.url)
    {
        revision.url = dup_cstr_or_empty(NULL);
    }
    if (!revision.notes)
    {
        revision.notes = dup_cstr_or_empty(NULL);
    }
    if (!revision.group_id)
    {
        revision.group_id = dup_cstr_or_empty(NULL);
    }

    if (!revision.source || !revision.actor || !revision.id || !revision.title ||
        !revision.username || !revision.password || !revision.url ||
        !revision.notes || !revision.group_id)
    {
        history_revision_clear(&revision);
        return PM_ERR_NOMEM;
    }

    *out = revision;
    return PM_OK;
}

static pm_error_t decode_attachment(bio_cbor_decoder_t *dec,
                                    pm_attachment_t *out)
{
    size_t map_count = 0;
    pm_attachment_t attachment = {0};

    if (bio_cbor_decode_map(dec, &map_count) != BIO_OK)
    {
        return PM_ERR_DESERIALIZE;
    }

    for (size_t i = 0; i < map_count; i++)
    {
        uint64_t key = 0;

        if (bio_cbor_decode_uint(dec, &key) != BIO_OK)
        {
            attachment_clear(&attachment);
            return PM_ERR_DESERIALIZE;
        }

        switch (key)
        {
        case PMA_ID:
        case PMA_NAME:
        case PMA_MIME:
        {
            const char *s = NULL;
            size_t len = 0;
            char **target = NULL;

            if (bio_cbor_decode_tstr(dec, &s, &len) != BIO_OK)
            {
                attachment_clear(&attachment);
                return PM_ERR_DESERIALIZE;
            }

            target = (key == PMA_ID) ? &attachment.id
                                     : (key == PMA_NAME) ? &attachment.name
                                                         : &attachment.mime;
            if (*target)
            {
                attachment_clear(&attachment);
                return PM_ERR_FORMAT;
            }

            *target = dup_bytes_as_cstr(s, len);
            if (!*target)
            {
                attachment_clear(&attachment);
                return PM_ERR_NOMEM;
            }
            break;
        }

        case PMA_SIZE:
            if (bio_cbor_decode_uint(dec, &attachment.size) != BIO_OK)
            {
                attachment_clear(&attachment);
                return PM_ERR_DESERIALIZE;
            }
            break;

        case PMA_SHA256:
        {
            const uint8_t *b = NULL;
            size_t len = 0;

            if (bio_cbor_decode_bstr(dec, &b, &len) != BIO_OK)
            {
                attachment_clear(&attachment);
                return PM_ERR_DESERIALIZE;
            }

            if (len != 0 && len != sizeof(attachment.sha256))
            {
                attachment_clear(&attachment);
                return PM_ERR_FORMAT;
            }

            if (len == sizeof(attachment.sha256))
            {
                memcpy(attachment.sha256, b, sizeof(attachment.sha256));
                attachment.has_sha256 = true;
            }
            break;
        }

        case PMA_BLOB:
        {
            const uint8_t *b = NULL;
            size_t len = 0;

            if (bio_cbor_decode_bstr(dec, &b, &len) != BIO_OK)
            {
                attachment_clear(&attachment);
                return PM_ERR_DESERIALIZE;
            }

            if (attachment.blob)
            {
                attachment_clear(&attachment);
                return PM_ERR_FORMAT;
            }

            if (len > 0)
            {
                attachment.blob = malloc(len);
                if (!attachment.blob)
                {
                    attachment_clear(&attachment);
                    return PM_ERR_NOMEM;
                }
                memcpy(attachment.blob, b, len);
                attachment.blob_len = len;
            }
            break;
        }

        default:
        {
            uint8_t *raw = NULL;
            size_t raw_len = 0;
            pm_error_t rc = capture_next_item(dec, &raw, &raw_len);
            if (rc != PM_OK)
            {
                attachment_clear(&attachment);
                return rc;
            }

            rc = unknown_fields_append(&attachment.unknown_fields,
                                       &attachment.unknown_field_count,
                                       key,
                                       raw,
                                       raw_len);
            free(raw);
            if (rc != PM_OK)
            {
                attachment_clear(&attachment);
                return rc;
            }
            break;
        }
        }
    }

    if (!attachment.id)
    {
        attachment.id = dup_cstr_or_empty(NULL);
    }
    if (!attachment.name)
    {
        attachment.name = dup_cstr_or_empty(NULL);
    }
    if (!attachment.mime)
    {
        attachment.mime = dup_cstr_or_empty(NULL);
    }
    if (!attachment.id || !attachment.name || !attachment.mime)
    {
        attachment_clear(&attachment);
        return PM_ERR_NOMEM;
    }

    if (attachment.size == 0u)
    {
        attachment.size = attachment.blob_len;
    }

    *out = attachment;
    return PM_OK;
}

static pm_error_t decode_entry(bio_cbor_decoder_t *dec, pm_entry_t *out)
{
    size_t map_count = 0;
    pm_entry_t entry = {0};

    if (bio_cbor_decode_map(dec, &map_count) != BIO_OK)
    {
        return PM_ERR_DESERIALIZE;
    }

    for (size_t i = 0; i < map_count; i++)
    {
        uint64_t key = 0;

        if (bio_cbor_decode_uint(dec, &key) != BIO_OK)
        {
            entry_clear(&entry);
            return PM_ERR_DESERIALIZE;
        }

        switch (key)
        {
        case PME_ID:
        case PME_TITLE:
        case PME_USERNAME:
        case PME_PASSWORD:
        case PME_URL:
        case PME_NOTES:
        case PME_GROUP_ID:
        case PME_COLOR_LABEL:
        {
            const char *s = NULL;
            size_t len = 0;
            char **target = NULL;

            if (bio_cbor_decode_tstr(dec, &s, &len) != BIO_OK)
            {
                entry_clear(&entry);
                return PM_ERR_DESERIALIZE;
            }

            switch (key)
            {
            case PME_ID:
                target = &entry.id;
                break;
            case PME_TITLE:
                target = &entry.title;
                break;
            case PME_USERNAME:
                target = &entry.username;
                break;
            case PME_PASSWORD:
                target = &entry.password;
                break;
            case PME_URL:
                target = &entry.url;
                break;
            case PME_NOTES:
                target = &entry.notes;
                break;
            case PME_GROUP_ID:
                target = &entry.group_id;
                break;
            case PME_COLOR_LABEL:
                target = &entry.color_label;
                break;
            default:
                break;
            }

            if (*target)
            {
                entry_clear(&entry);
                return PM_ERR_FORMAT;
            }

            *target = dup_bytes_as_cstr(s, len);
            if (!*target)
            {
                entry_clear(&entry);
                return PM_ERR_NOMEM;
            }
            break;
        }

        case PME_TAGS:
        case PME_URL_LIST:
        {
            size_t count = 0;
            char ***target_items = NULL;
            size_t *target_count = NULL;
            size_t max_count = (key == PME_TAGS) ? PM_PAYLOAD_MAX_TAGS_PER_ENTRY
                                                 : PM_PAYLOAD_MAX_URLS_PER_ENTRY;

            if (bio_cbor_decode_array(dec, &count) != BIO_OK || count > max_count)
            {
                entry_clear(&entry);
                return PM_ERR_DESERIALIZE;
            }

            target_items = (key == PME_TAGS) ? &entry.tags : &entry.urls;
            target_count = (key == PME_TAGS) ? &entry.tag_count : &entry.url_count;
            if (*target_items)
            {
                entry_clear(&entry);
                return PM_ERR_FORMAT;
            }

            if (count > 0)
            {
                *target_items = calloc(count, sizeof(char *));
                if (!*target_items)
                {
                    entry_clear(&entry);
                    return PM_ERR_NOMEM;
                }
            }

            *target_count = count;
            for (size_t j = 0; j < count; j++)
            {
                const char *s = NULL;
                size_t len = 0;
                if (bio_cbor_decode_tstr(dec, &s, &len) != BIO_OK)
                {
                    entry_clear(&entry);
                    return PM_ERR_DESERIALIZE;
                }

                (*target_items)[j] = dup_bytes_as_cstr(s, len);
                if (!(*target_items)[j])
                {
                    entry_clear(&entry);
                    return PM_ERR_NOMEM;
                }
            }
            break;
        }

        case PME_CREATED_AT_MS:
            if (bio_cbor_decode_uint(dec, &entry.created_at_ms) != BIO_OK)
            {
                entry_clear(&entry);
                return PM_ERR_DESERIALIZE;
            }
            break;

        case PME_UPDATED_AT_MS:
            if (bio_cbor_decode_uint(dec, &entry.updated_at_ms) != BIO_OK)
            {
                entry_clear(&entry);
                return PM_ERR_DESERIALIZE;
            }
            break;

        case PME_ACCESSED_AT_MS:
            if (bio_cbor_decode_uint(dec, &entry.accessed_at_ms) != BIO_OK)
            {
                entry_clear(&entry);
                return PM_ERR_DESERIALIZE;
            }
            break;

        case PME_EXPIRY_AT_MS:
        {
            uint64_t v = 0;
            if (bio_cbor_decode_uint(dec, &v) != BIO_OK)
            {
                entry_clear(&entry);
                return PM_ERR_DESERIALIZE;
            }
            entry.expiry_at_ms = v;
            break;
        }

        case PME_EXPIRY_WARN_DAYS:
        {
            uint64_t v = 0;
            if (bio_cbor_decode_uint(dec, &v) != BIO_OK || v > UINT16_MAX)
            {
                entry_clear(&entry);
                return PM_ERR_DESERIALIZE;
            }
            entry.expiry_warn_days = (uint16_t)v;
            break;
        }

        case PME_FAVORITE:
            if (bio_cbor_decode_bool(dec, &entry.favorite) != BIO_OK)
            {
                entry_clear(&entry);
                return PM_ERR_DESERIALIZE;
            }
            break;

        case PME_REQUIRES_FRESH_BIOMETRIC:
            if (bio_cbor_decode_bool(dec, &entry.requires_fresh_biometric) != BIO_OK)
            {
                entry_clear(&entry);
                return PM_ERR_DESERIALIZE;
            }
            break;

        case PME_CUSTOM_FIELDS:
        {
            size_t count = 0;
            if (bio_cbor_decode_array(dec, &count) != BIO_OK ||
                count > PM_PAYLOAD_MAX_CUSTOM_FIELDS_PER_ENTRY)
            {
                entry_clear(&entry);
                return PM_ERR_DESERIALIZE;
            }

            if (count > 0)
            {
                entry.custom_fields = calloc(count, sizeof(pm_custom_field_t));
                if (!entry.custom_fields)
                {
                    entry_clear(&entry);
                    return PM_ERR_NOMEM;
                }
            }

            entry.custom_field_count = count;
            for (size_t j = 0; j < count; j++)
            {
                pm_error_t rc = decode_custom_field(dec, &entry.custom_fields[j]);
                if (rc != PM_OK)
                {
                    entry_clear(&entry);
                    return rc;
                }
            }
            break;
        }

        case PME_ATTACHMENT_REFS:
        {
            size_t count = 0;
            if (bio_cbor_decode_array(dec, &count) != BIO_OK ||
                count > PM_PAYLOAD_MAX_ATTACHMENT_REFS_PER_ENTRY)
            {
                entry_clear(&entry);
                return PM_ERR_DESERIALIZE;
            }

            if (count > 0)
            {
                entry.attachment_refs = calloc(count, sizeof(pm_attachment_ref_t));
                if (!entry.attachment_refs)
                {
                    entry_clear(&entry);
                    return PM_ERR_NOMEM;
                }
            }

            entry.attachment_ref_count = count;
            for (size_t j = 0; j < count; j++)
            {
                pm_error_t rc = decode_attachment_ref(dec, &entry.attachment_refs[j]);
                if (rc != PM_OK)
                {
                    entry_clear(&entry);
                    return rc;
                }
            }
            break;
        }

        case PME_HISTORY:
        {
            size_t count = 0;
            if (bio_cbor_decode_array(dec, &count) != BIO_OK ||
                count > PM_PAYLOAD_MAX_HISTORY_PER_ENTRY)
            {
                entry_clear(&entry);
                return PM_ERR_DESERIALIZE;
            }

            if (count > 0)
            {
                entry.history = calloc(count, sizeof(pm_history_revision_t));
                if (!entry.history)
                {
                    entry_clear(&entry);
                    return PM_ERR_NOMEM;
                }
            }

            entry.history_count = count;
            for (size_t j = 0; j < count; j++)
            {
                pm_error_t rc = decode_history_revision(dec, &entry.history[j]);
                if (rc != PM_OK)
                {
                    entry_clear(&entry);
                    return rc;
                }
            }
            break;
        }

        default:
        {
            uint8_t *raw = NULL;
            size_t raw_len = 0;
            pm_error_t rc = capture_next_item(dec, &raw, &raw_len);
            if (rc != PM_OK)
            {
                entry_clear(&entry);
                return rc;
            }

            rc = unknown_fields_append(&entry.unknown_fields,
                                       &entry.unknown_field_count,
                                       key,
                                       raw,
                                       raw_len);
            free(raw);
            if (rc != PM_OK)
            {
                entry_clear(&entry);
                return rc;
            }
            break;
        }
        }
    }

    if (!entry.id)
    {
        entry.id = dup_cstr_or_empty(NULL);
    }
    if (!entry.title)
    {
        entry.title = dup_cstr_or_empty(NULL);
    }
    if (!entry.username)
    {
        entry.username = dup_cstr_or_empty(NULL);
    }
    if (!entry.password)
    {
        entry.password = dup_cstr_or_empty(NULL);
    }
    if (!entry.notes)
    {
        entry.notes = dup_cstr_or_empty(NULL);
    }
    if (!entry.group_id)
    {
        entry.group_id = dup_cstr_or_empty(NULL);
    }
    if (!entry.color_label)
    {
        entry.color_label = dup_cstr_or_empty(NULL);
    }

    if (!entry.id || !entry.title || !entry.username || !entry.password ||
        !entry.notes || !entry.group_id || !entry.color_label)
    {
        entry_clear(&entry);
        return PM_ERR_NOMEM;
    }

    {
        pm_error_t rc = ensure_entry_url_alias(&entry);
        if (rc != PM_OK)
        {
            entry_clear(&entry);
            return rc;
        }
    }

    *out = entry;
    return PM_OK;
}

static pm_error_t decode_group(bio_cbor_decoder_t *dec, pm_group_t *out)
{
    size_t map_count = 0;
    pm_group_t group = {0};

    if (bio_cbor_decode_map(dec, &map_count) != BIO_OK)
    {
        return PM_ERR_DESERIALIZE;
    }

    for (size_t i = 0; i < map_count; i++)
    {
        uint64_t key = 0;

        if (bio_cbor_decode_uint(dec, &key) != BIO_OK)
        {
            group_clear(&group);
            return PM_ERR_DESERIALIZE;
        }

        switch (key)
        {
        case PMG_ID:
        case PMG_PARENT_ID:
        case PMG_TITLE:
        case PMG_ICON_ID:
        case PMG_COLOR:
        case PMG_NOTES:
        {
            const char *s = NULL;
            size_t len = 0;
            char **target = NULL;

            if (bio_cbor_decode_tstr(dec, &s, &len) != BIO_OK)
            {
                group_clear(&group);
                return PM_ERR_DESERIALIZE;
            }

            switch (key)
            {
            case PMG_ID:
                target = &group.id;
                break;
            case PMG_PARENT_ID:
                target = &group.parent_id;
                break;
            case PMG_TITLE:
                target = &group.title;
                break;
            case PMG_ICON_ID:
                target = &group.icon_id;
                break;
            case PMG_COLOR:
                target = &group.color;
                break;
            case PMG_NOTES:
                target = &group.notes;
                break;
            default:
                break;
            }

            if (*target)
            {
                group_clear(&group);
                return PM_ERR_FORMAT;
            }

            *target = dup_bytes_as_cstr(s, len);
            if (!*target)
            {
                group_clear(&group);
                return PM_ERR_NOMEM;
            }
            break;
        }

        case PMG_CREATED_AT_MS:
            if (bio_cbor_decode_uint(dec, &group.created_at_ms) != BIO_OK)
            {
                group_clear(&group);
                return PM_ERR_DESERIALIZE;
            }
            break;

        case PMG_UPDATED_AT_MS:
            if (bio_cbor_decode_uint(dec, &group.updated_at_ms) != BIO_OK)
            {
                group_clear(&group);
                return PM_ERR_DESERIALIZE;
            }
            break;

        case PMG_ACCESSED_AT_MS:
            if (bio_cbor_decode_uint(dec, &group.accessed_at_ms) != BIO_OK)
            {
                group_clear(&group);
                return PM_ERR_DESERIALIZE;
            }
            break;

        case PMG_CUSTOM_DATA:
        {
            pm_error_t rc = capture_next_item(dec,
                                              &group.custom_data_cbor,
                                              &group.custom_data_cbor_len);
            if (rc != PM_OK)
            {
                group_clear(&group);
                return rc;
            }
            break;
        }

        default:
        {
            uint8_t *raw = NULL;
            size_t raw_len = 0;
            pm_error_t rc = capture_next_item(dec, &raw, &raw_len);
            if (rc != PM_OK)
            {
                group_clear(&group);
                return rc;
            }

            rc = unknown_fields_append(&group.unknown_fields,
                                       &group.unknown_field_count,
                                       key,
                                       raw,
                                       raw_len);
            free(raw);
            if (rc != PM_OK)
            {
                group_clear(&group);
                return rc;
            }
            break;
        }
        }
    }

    if (!group.id)
    {
        group.id = dup_cstr_or_empty(NULL);
    }
    if (!group.parent_id)
    {
        group.parent_id = dup_cstr_or_empty(NULL);
    }
    if (!group.title)
    {
        group.title = dup_cstr_or_empty(NULL);
    }
    if (!group.icon_id)
    {
        group.icon_id = dup_cstr_or_empty(NULL);
    }
    if (!group.color)
    {
        group.color = dup_cstr_or_empty(NULL);
    }
    if (!group.notes)
    {
        group.notes = dup_cstr_or_empty(NULL);
    }

    if (!group.id || !group.parent_id || !group.title || !group.icon_id ||
        !group.color || !group.notes)
    {
        group_clear(&group);
        return PM_ERR_NOMEM;
    }

    *out = group;
    return PM_OK;
}

static pm_error_t decode_recycle_bin(bio_cbor_decoder_t *dec,
                                     pm_recycle_bin_t *out)
{
    size_t map_count = 0;
    pm_recycle_bin_t bin = {0};

    if (bio_cbor_decode_map(dec, &map_count) != BIO_OK)
    {
        return PM_ERR_DESERIALIZE;
    }

    for (size_t i = 0; i < map_count; i++)
    {
        uint64_t key = 0;

        if (bio_cbor_decode_uint(dec, &key) != BIO_OK)
        {
            recycle_bin_clear(&bin);
            return PM_ERR_DESERIALIZE;
        }

        switch (key)
        {
        case PMR_ENABLED:
            if (bio_cbor_decode_bool(dec, &bin.enabled) != BIO_OK)
            {
                recycle_bin_clear(&bin);
                return PM_ERR_DESERIALIZE;
            }
            break;

        case PMR_GROUP_ID:
        {
            const char *s = NULL;
            size_t len = 0;
            if (bio_cbor_decode_tstr(dec, &s, &len) != BIO_OK)
            {
                recycle_bin_clear(&bin);
                return PM_ERR_DESERIALIZE;
            }
            if (bin.group_id)
            {
                recycle_bin_clear(&bin);
                return PM_ERR_FORMAT;
            }
            bin.group_id = dup_bytes_as_cstr(s, len);
            if (!bin.group_id)
            {
                recycle_bin_clear(&bin);
                return PM_ERR_NOMEM;
            }
            break;
        }

        case PMR_RETENTION_DAYS:
        {
            uint64_t v = 0;
            if (bio_cbor_decode_uint(dec, &v) != BIO_OK || v > UINT32_MAX)
            {
                recycle_bin_clear(&bin);
                return PM_ERR_DESERIALIZE;
            }
            bin.retention_days = (uint32_t)v;
            break;
        }

        default:
        {
            uint8_t *raw = NULL;
            size_t raw_len = 0;
            pm_error_t rc = capture_next_item(dec, &raw, &raw_len);
            if (rc != PM_OK)
            {
                recycle_bin_clear(&bin);
                return rc;
            }

            rc = unknown_fields_append(&bin.unknown_fields,
                                       &bin.unknown_field_count,
                                       key,
                                       raw,
                                       raw_len);
            free(raw);
            if (rc != PM_OK)
            {
                recycle_bin_clear(&bin);
                return rc;
            }
            break;
        }
        }
    }

    if (!bin.group_id)
    {
        bin.group_id = dup_cstr_or_empty(NULL);
        if (!bin.group_id)
        {
            recycle_bin_clear(&bin);
            return PM_ERR_NOMEM;
        }
    }

    *out = bin;
    return PM_OK;
}

pm_error_t pm_payload_decode_cbor(const uint8_t *data,
                                  size_t data_len,
                                  pm_payload_t *out)
{
    bio_cbor_decoder_t dec;
    pm_payload_t payload;
    size_t map_count = 0;
    bool has_schema = false;
    bool has_created = false;
    bool has_updated = false;
    bool has_entries = false;

    if (!data || data_len == 0 || !out)
    {
        return PM_ERR_INVALID_PARAM;
    }

    pm_payload_init(&payload);
    bio_cbor_decoder_init(&dec, data, data_len);

    if (bio_cbor_decode_map(&dec, &map_count) != BIO_OK)
    {
        return PM_ERR_DESERIALIZE;
    }

    for (size_t i = 0; i < map_count; i++)
    {
        uint64_t key = 0;

        if (bio_cbor_decode_uint(&dec, &key) != BIO_OK)
        {
            pm_payload_free(&payload);
            return PM_ERR_DESERIALIZE;
        }

        switch (key)
        {
        case PMK_SCHEMA_VERSION:
        {
            uint64_t v = 0;
            if (bio_cbor_decode_uint(&dec, &v) != BIO_OK)
            {
                pm_payload_free(&payload);
                return PM_ERR_DESERIALIZE;
            }
            if (v != PM_PAYLOAD_SCHEMA_VERSION)
            {
                pm_payload_free(&payload);
                return PM_ERR_FORMAT_VERSION;
            }
            payload.schema_version = (uint32_t)v;
            has_schema = true;
            break;
        }

        case PMK_CREATED_AT_MS:
            if (bio_cbor_decode_uint(&dec, &payload.created_at_ms) != BIO_OK)
            {
                pm_payload_free(&payload);
                return PM_ERR_DESERIALIZE;
            }
            has_created = true;
            break;

        case PMK_UPDATED_AT_MS:
            if (bio_cbor_decode_uint(&dec, &payload.updated_at_ms) != BIO_OK)
            {
                pm_payload_free(&payload);
                return PM_ERR_DESERIALIZE;
            }
            has_updated = true;
            break;

        case PMK_ENTRIES:
        {
            size_t count = 0;
            if (bio_cbor_decode_array(&dec, &count) != BIO_OK || count > PM_PAYLOAD_MAX_ENTRIES)
            {
                pm_payload_free(&payload);
                return PM_ERR_DESERIALIZE;
            }

            for (size_t j = 0; j < count; j++)
            {
                pm_entry_t entry = {0};
                pm_error_t rc = decode_entry(&dec, &entry);
                if (rc != PM_OK)
                {
                    pm_payload_free(&payload);
                    return rc;
                }

                rc = pm_payload_append_entry(&payload, &entry);
                entry_clear(&entry);
                if (rc != PM_OK)
                {
                    pm_payload_free(&payload);
                    return rc;
                }
            }
            has_entries = true;
            break;
        }

        case PMK_GROUPS:
        {
            size_t count = 0;
            if (bio_cbor_decode_array(&dec, &count) != BIO_OK || count > PM_PAYLOAD_MAX_GROUPS)
            {
                pm_payload_free(&payload);
                return PM_ERR_DESERIALIZE;
            }

            for (size_t j = 0; j < count; j++)
            {
                pm_group_t group = {0};
                pm_error_t rc = decode_group(&dec, &group);
                if (rc != PM_OK)
                {
                    pm_payload_free(&payload);
                    return rc;
                }

                rc = pm_payload_append_group(&payload, &group);
                group_clear(&group);
                if (rc != PM_OK)
                {
                    pm_payload_free(&payload);
                    return rc;
                }
            }
            break;
        }

        case PMK_VAULT_UUID:
        {
            const uint8_t *b = NULL;
            size_t len = 0;
            if (bio_cbor_decode_bstr(&dec, &b, &len) != BIO_OK || len != sizeof(payload.vault_uuid))
            {
                pm_payload_free(&payload);
                return PM_ERR_DESERIALIZE;
            }
            memcpy(payload.vault_uuid, b, sizeof(payload.vault_uuid));
            payload.has_vault_uuid = true;
            break;
        }

        case PMK_ATTACHMENTS:
        {
            size_t count = 0;
            if (bio_cbor_decode_array(&dec, &count) != BIO_OK || count > PM_PAYLOAD_MAX_ATTACHMENTS)
            {
                pm_payload_free(&payload);
                return PM_ERR_DESERIALIZE;
            }

            for (size_t j = 0; j < count; j++)
            {
                pm_attachment_t attachment = {0};
                pm_error_t rc = decode_attachment(&dec, &attachment);
                if (rc != PM_OK)
                {
                    pm_payload_free(&payload);
                    return rc;
                }

                rc = pm_payload_append_attachment(&payload, &attachment);
                attachment_clear(&attachment);
                if (rc != PM_OK)
                {
                    pm_payload_free(&payload);
                    return rc;
                }
            }
            break;
        }

        case PMK_RECYCLE_BIN:
        {
            pm_recycle_bin_t bin = {0};
            pm_error_t rc = decode_recycle_bin(&dec, &bin);
            if (rc != PM_OK)
            {
                pm_payload_free(&payload);
                return rc;
            }

            recycle_bin_clear(&payload.recycle_bin);
            payload.recycle_bin = bin;
            break;
        }

        case PMK_SECURITY_AUDIT_CACHE:
        {
            pm_error_t rc = capture_next_item(&dec,
                                              &payload.security_audit_cache_cbor,
                                              &payload.security_audit_cache_cbor_len);
            if (rc != PM_OK)
            {
                pm_payload_free(&payload);
                return rc;
            }
            break;
        }

        default:
        {
            uint8_t *raw = NULL;
            size_t raw_len = 0;
            pm_error_t rc = capture_next_item(&dec, &raw, &raw_len);
            if (rc != PM_OK)
            {
                pm_payload_free(&payload);
                return rc;
            }

            rc = unknown_fields_append(&payload.unknown_fields,
                                       &payload.unknown_field_count,
                                       key,
                                       raw,
                                       raw_len);
            free(raw);
            if (rc != PM_OK)
            {
                pm_payload_free(&payload);
                return rc;
            }
            break;
        }
        }
    }

    if (!has_schema || !has_created || !has_updated || !has_entries)
    {
        pm_payload_free(&payload);
        return PM_ERR_FORMAT;
    }

    if (!bio_cbor_decoder_at_end(&dec))
    {
        pm_payload_free(&payload);
        return PM_ERR_FORMAT;
    }

    pm_payload_free(out);
    *out = payload;
    return PM_OK;
}
