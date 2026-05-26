/*
 * pm_payload.h - Password manager payload model and CBOR codec
 *
 * Copyright (C) 2026 Hiya Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef PM_PAYLOAD_H
#define PM_PAYLOAD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "pm/pm_errors.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define PM_PAYLOAD_SCHEMA_VERSION 1u
#define PM_PAYLOAD_MAX_ENTRIES 4096u
#define PM_PAYLOAD_MAX_GROUPS 4096u
#define PM_PAYLOAD_MAX_TAGS_PER_ENTRY 128u
#define PM_PAYLOAD_MAX_URLS_PER_ENTRY 64u
#define PM_PAYLOAD_MAX_CUSTOM_FIELDS_PER_ENTRY 128u
#define PM_PAYLOAD_MAX_ATTACHMENT_REFS_PER_ENTRY 128u
#define PM_PAYLOAD_MAX_HISTORY_PER_ENTRY 50u
#define PM_PAYLOAD_MAX_ATTACHMENTS 2048u
#define PM_PAYLOAD_MAX_UNKNOWN_FIELDS 512u

    typedef struct
    {
        uint64_t key;
        uint8_t *value_cbor;
        size_t value_cbor_len;
    } pm_unknown_field_t;

    typedef enum
    {
        PM_FIELD_TEXT = 0,
        PM_FIELD_HIDDEN = 1,
        PM_FIELD_TOTP = 2,
        PM_FIELD_URL = 3,
        PM_FIELD_DATE = 4,
        PM_FIELD_BINARY_REF = 5,
    } pm_custom_field_type_t;

    typedef struct
    {
        char *name;
        pm_custom_field_type_t type;
        char *text_value;
        uint64_t date_value_ms;
        char *binary_ref;

        pm_unknown_field_t *unknown_fields;
        size_t unknown_field_count;
    } pm_custom_field_t;

    void pm_custom_field_init(pm_custom_field_t *field);
    void pm_custom_field_free(pm_custom_field_t *field);
    pm_error_t pm_custom_field_copy(pm_custom_field_t *dst,
                                    const pm_custom_field_t *src);

    typedef struct
    {
        char *attachment_id;

        pm_unknown_field_t *unknown_fields;
        size_t unknown_field_count;
    } pm_attachment_ref_t;

    void pm_attachment_ref_init(pm_attachment_ref_t *ref);
    void pm_attachment_ref_free(pm_attachment_ref_t *ref);
    pm_error_t pm_attachment_ref_copy(pm_attachment_ref_t *dst,
                                      const pm_attachment_ref_t *src);

    typedef struct
    {
        union
        {
            uint64_t revision_ts_ms;
            uint64_t modified_at_ms;
        };
        char *source;
        char *actor;
        char *id;
        char *title;
        char *username;
        char *password;
        char *url;
        char *notes;
        char *group_id;
        char **tags;
        size_t tag_count;
        uint64_t created_at_ms;
        uint64_t updated_at_ms;
        bool favorite;

        pm_unknown_field_t *unknown_fields;
        size_t unknown_field_count;
    } pm_history_revision_t;

#define PM_HISTORY_MAX_REVISIONS PM_PAYLOAD_MAX_HISTORY_PER_ENTRY
    typedef pm_history_revision_t pm_entry_revision_t;

    void pm_history_revision_init(pm_history_revision_t *revision);
    void pm_history_revision_free(pm_history_revision_t *revision);
    pm_error_t pm_history_revision_copy(pm_history_revision_t *dst,
                                        const pm_history_revision_t *src);

#define pm_entry_revision_init pm_history_revision_init
#define pm_entry_revision_free pm_history_revision_free
#define pm_entry_revision_copy pm_history_revision_copy

    typedef struct
    {
        char *id;
        char *name;
        char *mime;
        uint64_t size;
        bool has_sha256;
        uint8_t sha256[32];
        uint8_t *blob;
        size_t blob_len;

        pm_unknown_field_t *unknown_fields;
        size_t unknown_field_count;
    } pm_attachment_t;

    void pm_attachment_init(pm_attachment_t *attachment);
    void pm_attachment_free(pm_attachment_t *attachment);
    pm_error_t pm_attachment_copy(pm_attachment_t *dst,
                                  const pm_attachment_t *src);

    typedef struct
    {
        char *id;
        char *title;
        char *username;
        char *password;
        char *url;
        char **urls;
        size_t url_count;
        char *notes;
        char *group_id;

        char **tags;
        size_t tag_count;

        uint64_t created_at_ms;
        uint64_t updated_at_ms;
        uint64_t accessed_at_ms;
        bool favorite;
        char *color_label;
        uint64_t expiry_at_ms;
        uint16_t expiry_warn_days;
        bool requires_fresh_biometric;

        pm_custom_field_t *custom_fields;
        size_t custom_field_count;

        pm_attachment_ref_t *attachment_refs;
        size_t attachment_ref_count;

        pm_history_revision_t *history;
        size_t history_count;

        pm_unknown_field_t *unknown_fields;
        size_t unknown_field_count;
    } pm_entry_t;

    void pm_entry_init(pm_entry_t *entry);
    void pm_entry_free(pm_entry_t *entry);
    pm_error_t pm_entry_copy(pm_entry_t *dst, const pm_entry_t *src);

    typedef struct
    {
        char *id;
        char *parent_id;
        char *title;
        char *icon_id;
        char *color;
        char *notes;

        uint64_t created_at_ms;
        uint64_t updated_at_ms;
        uint64_t accessed_at_ms;

        uint8_t *custom_data_cbor;
        size_t custom_data_cbor_len;

        pm_unknown_field_t *unknown_fields;
        size_t unknown_field_count;
    } pm_group_t;

    void pm_group_init(pm_group_t *group);
    void pm_group_free(pm_group_t *group);
    pm_error_t pm_group_copy(pm_group_t *dst, const pm_group_t *src);

    typedef struct
    {
        bool enabled;
        char *group_id;
        uint32_t retention_days;

        pm_unknown_field_t *unknown_fields;
        size_t unknown_field_count;
    } pm_recycle_bin_t;

    void pm_recycle_bin_init(pm_recycle_bin_t *bin);
    void pm_recycle_bin_free(pm_recycle_bin_t *bin);
    pm_error_t pm_recycle_bin_copy(pm_recycle_bin_t *dst,
                                   const pm_recycle_bin_t *src);

    typedef struct
    {
        uint32_t schema_version;
        uint64_t created_at_ms;
        uint64_t updated_at_ms;

        bool has_vault_uuid;
        uint8_t vault_uuid[16];

        pm_group_t *groups;
        size_t group_count;

        pm_entry_t *entries;
        size_t entry_count;

        pm_attachment_t *attachments;
        size_t attachment_count;

        pm_recycle_bin_t recycle_bin;

        uint8_t *security_audit_cache_cbor;
        size_t security_audit_cache_cbor_len;

        pm_unknown_field_t *unknown_fields;
        size_t unknown_field_count;
    } pm_payload_t;

    void pm_payload_init(pm_payload_t *payload);
    void pm_payload_free(pm_payload_t *payload);

    pm_error_t pm_payload_append_group(pm_payload_t *payload, const pm_group_t *group);
    pm_error_t pm_payload_append_entry(pm_payload_t *payload, const pm_entry_t *entry);
    pm_error_t pm_payload_append_attachment(pm_payload_t *payload,
                                            const pm_attachment_t *attachment);

    pm_error_t pm_payload_encode_cbor(const pm_payload_t *payload,
                                      uint8_t **out,
                                      size_t *out_len);

    pm_error_t pm_payload_decode_cbor(const uint8_t *data,
                                      size_t data_len,
                                      pm_payload_t *out);

#ifdef __cplusplus
}
#endif

#endif /* PM_PAYLOAD_H */
