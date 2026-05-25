/*
 * bio_fido2_bio_cred.c — CTAP2 BioEnrollment + CredentialManagement
 *
 * Copyright (C) 2024 BioAuth Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Implements:
 *   0x09 authenticatorBioEnrollment
 *        Sub-commands for managing biometric templates on-device.
 *   0x0A authenticatorCredentialManagement
 *        Sub-commands for managing discoverable (resident) credentials.
 *
 * References:
 *   FIDO CTAP 2.1 §6.7 (BioEnrollment), §6.8 (CredentialManagement)
 */

#include "fido2/bio_fido2.h"
#include "cbor/bio_cbor.h"
#include "crypto/bio_crypto.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

/* ══════════════════════════════════════════════════════════════
 *  authenticatorBioEnrollment (0x09)
 * ══════════════════════════════════════════════════════════════ */

/*
 * BioEnrollment sub-commands:
 *   0x01  enrollBegin          — Start a new fingerprint enrollment
 *   0x02  enrollCaptureNext    — Capture next sample
 *   0x03  cancelCurrentEnrollment
 *   0x04  enumerateEnrollments — List all enrolled templates
 *   0x05  setFriendlyName      — Rename a template
 *   0x06  removeEnrollment     — Delete a template
 *   0x07  getFingerprintSensorInfo — Query sensor capabilities
 *
 * Parameters (CBOR map):
 *   0x01: modality (uint)          — 1 = fingerprint
 *   0x02: subCommand (uint)        — one of the above
 *   0x03: subCommandParams (map)   — sub-command-specific parameters
 *   0x04: pinUvAuthProtocol (uint) — PIN protocol version
 *   0x05: pinUvAuthParam (bstr)    — HMAC over subCommand params
 *   0x06: getModality (bool)       — if true, return modality info only
 */

#define BIO_SUBCMD_ENROLL_BEGIN           0x01
#define BIO_SUBCMD_ENROLL_CAPTURE_NEXT    0x02
#define BIO_SUBCMD_CANCEL_ENROLLMENT      0x03
#define BIO_SUBCMD_ENUMERATE_ENROLLMENTS  0x04
#define BIO_SUBCMD_SET_FRIENDLY_NAME      0x05
#define BIO_SUBCMD_REMOVE_ENROLLMENT      0x06
#define BIO_SUBCMD_GET_SENSOR_INFO        0x07

/* Maximum bio templates that can be stored */
#define CTAP2_MAX_BIO_TEMPLATES           10

/* In-memory bio template registry
 * In production this would interface with the fingerprint driver;
 * here we model the CTAP2 protocol layer faithfully. */
typedef struct {
    bool           in_use;
    uint8_t        template_id[32]; /* Random opaque identifier */
    size_t         template_id_len;
    char           friendly_name[64];
    uint32_t       samples_remaining;
    uint64_t       created;
} bio_template_entry_t;

/* We store these inside the file-scoped state for simplicity.
 * A production authenticator would use persistent storage.
 *
 * THREAD SAFETY: these globals are protected by ctx->mutex which
 * serializes all CTAP2 commands.  This assumes a single bio_fido2_ctx_t
 * instance per process — do NOT create multiple FIDO2 contexts. */
static bio_template_entry_t g_bio_templates[CTAP2_MAX_BIO_TEMPLATES];
static size_t               g_bio_template_count = 0;
static int                  g_bio_enroll_active = -1; /* slot index or -1 */

/* Forward declaration for g_cred_enum wipe */
static void cred_enum_reset(void);

/* Reset all bio enrollment and credential enumeration state
 * (called from ctap2_reset and bio_fido2_cleanup) */
void bio_fido2_bio_reset(void)
{
    bio_secure_wipe(g_bio_templates, sizeof(g_bio_templates));
    g_bio_template_count = 0;
    g_bio_enroll_active = -1;
    cred_enum_reset();
}

typedef struct {
    uint32_t  modality;
    uint32_t  sub_command;
    bool      get_modality;
    uint32_t  pin_protocol;

    /* subCommandParams fields */
    uint8_t   template_id[32];
    size_t    template_id_len;
    bool      has_template_id;
    char      friendly_name[64];
    bool      has_friendly_name;
    uint8_t   pin_uv_auth_param[32];
    size_t    pin_uv_auth_param_len;
    bool      has_pin_auth;
    size_t    timeout_ms;
} bio_enroll_params_t;

static uint8_t parse_bio_enroll_params(const uint8_t *req, size_t req_len,
                                        bio_enroll_params_t *p)
{
    memset(p, 0, sizeof(*p));
    p->modality = 1;      /* default: fingerprint */
    p->pin_protocol = 1;
    p->timeout_ms = 30000; /* 30s default */

    bio_cbor_decoder_t dec;
    bio_cbor_decoder_init(&dec, req, req_len);

    uint64_t map_cnt;
    if (bio_cbor_decode_map(&dec, &map_cnt) != BIO_OK)
        return CTAP2_ERR_INVALID_CBOR;

    for (uint64_t i = 0; i < map_cnt; i++) {
        uint64_t key;
        if (bio_cbor_decode_uint(&dec, &key) != BIO_OK)
            return CTAP2_ERR_INVALID_CBOR;

        switch (key) {
        case 0x01: { /* modality */
            uint64_t v;
            if (bio_cbor_decode_uint(&dec, &v) != BIO_OK)
                return CTAP2_ERR_INVALID_CBOR;
            p->modality = (uint32_t)v;
            break;
        }
        case 0x02: { /* subCommand */
            uint64_t v;
            if (bio_cbor_decode_uint(&dec, &v) != BIO_OK)
                return CTAP2_ERR_INVALID_CBOR;
            p->sub_command = (uint32_t)v;
            break;
        }
        case 0x03: { /* subCommandParams (map) */
            uint64_t sc_cnt;
            if (bio_cbor_decode_map(&dec, &sc_cnt) != BIO_OK)
                return CTAP2_ERR_INVALID_CBOR;

            for (uint64_t j = 0; j < sc_cnt; j++) {
                uint64_t sk;
                if (bio_cbor_decode_uint(&dec, &sk) != BIO_OK)
                    return CTAP2_ERR_INVALID_CBOR;

                switch (sk) {
                case 0x01: { /* templateId (bstr) */
                    bio_cbor_item_t val;
                    if (bio_cbor_decode_next(&dec, &val) != BIO_OK)
                        return CTAP2_ERR_INVALID_CBOR;
                    if (val.type == BIO_CBOR_BSTR) {
                        p->template_id_len = val.bstr.len < sizeof(p->template_id)
                                                 ? val.bstr.len
                                                 : sizeof(p->template_id);
                        memcpy(p->template_id, val.bstr.data,
                               p->template_id_len);
                        p->has_template_id = true;
                    }
                    break;
                }
                case 0x02: { /* templateFriendlyName (string) */
                    bio_cbor_item_t val;
                    if (bio_cbor_decode_next(&dec, &val) != BIO_OK)
                        return CTAP2_ERR_INVALID_CBOR;
                    if (val.type == BIO_CBOR_TSTR) {
                        size_t cp = val.tstr.len < sizeof(p->friendly_name) - 1
                                        ? val.tstr.len
                                        : sizeof(p->friendly_name) - 1;
                        memcpy(p->friendly_name, val.tstr.data, cp);
                        p->friendly_name[cp] = '\0';
                        p->has_friendly_name = true;
                    }
                    break;
                }
                case 0x03: { /* timeoutMilliseconds (uint) */
                    uint64_t v;
                    if (bio_cbor_decode_uint(&dec, &v) != BIO_OK)
                        return CTAP2_ERR_INVALID_CBOR;
                    p->timeout_ms = (size_t)v;
                    break;
                }
                default:
                    bio_cbor_skip(&dec);
                    break;
                }
            }
            break;
        }
        case 0x04: { /* pinUvAuthProtocol */
            uint64_t v;
            if (bio_cbor_decode_uint(&dec, &v) != BIO_OK)
                return CTAP2_ERR_INVALID_CBOR;
            p->pin_protocol = (uint32_t)v;
            break;
        }
        case 0x05: { /* pinUvAuthParam */
            bio_cbor_item_t val;
            if (bio_cbor_decode_next(&dec, &val) != BIO_OK)
                return CTAP2_ERR_INVALID_CBOR;
            if (val.type == BIO_CBOR_BSTR && val.bstr.len >= 16) {
                size_t cp = val.bstr.len < sizeof(p->pin_uv_auth_param)
                                ? val.bstr.len
                                : sizeof(p->pin_uv_auth_param);
                memcpy(p->pin_uv_auth_param, val.bstr.data, cp);
                p->pin_uv_auth_param_len = cp;
                p->has_pin_auth = true;
            }
            break;
        }
        case 0x06: { /* getModality */
            bool v = false;
            bio_cbor_decode_bool(&dec, &v);
            p->get_modality = v;
            break;
        }
        default:
            bio_cbor_skip(&dec);
            break;
        }
    }

    return CTAP2_OK;
}

uint8_t ctap2_bio_enrollment(bio_fido2_ctx_t *ctx,
                              const uint8_t *req, size_t req_len,
                              uint8_t *rsp, size_t *rsp_len)
{
    bio_enroll_params_t p;
    uint8_t rc = parse_bio_enroll_params(req, req_len, &p);
    if (rc != CTAP2_OK) return rc;

    /* Only fingerprint modality supported */
    if (p.modality != 1) return CTAP2_ERR_INVALID_OPTION;

    /* getModality shortcut */
    if (p.get_modality) {
        bio_cbor_encoder_t enc;
        bio_cbor_encoder_init(&enc, rsp, *rsp_len);
        bio_cbor_encode_map(&enc, 1);
        bio_cbor_encode_uint(&enc, 0x01); /* modality */
        bio_cbor_encode_uint(&enc, 1);    /* fingerprint */
        if (enc.error) return CTAP2_ERR_OTHER;
        *rsp_len = enc.offset;
        return CTAP2_OK;
    }

    /* Require PIN/UV auth for enrollment operations (except sensor info) */
    if (p.sub_command != BIO_SUBCMD_GET_SENSOR_INFO) {
        if (p.has_pin_auth && ctx->pin.pin_token_valid) {
            if (p.pin_protocol != 1 && p.pin_protocol != 2)
                return CTAP2_ERR_PIN_AUTH_INVALID;
            if (ctx->pin.pin_token_permissions != 0 &&
                (ctx->pin.pin_token_permissions & CTAP2_PIN_PERM_BIO_ENROLLMENT) == 0) {
                return CTAP2_ERR_PIN_AUTH_INVALID;
            }
            /*
             * Verify: HMAC-SHA256(pinToken, modality(1) || subCommand(1))
             * Per CTAP2.1 §6.7, verify left 16 bytes for protocol 1.
             */
            uint8_t message[2];
            message[0] = (uint8_t)p.modality;
            message[1] = (uint8_t)p.sub_command;

            uint8_t expected[32];
            bio_hmac_sha256(ctx->pin.pin_token, CTAP2_PIN_TOKEN_SIZE,
                            message, sizeof(message), expected);

            if (p.pin_protocol == 2) {
                if (p.pin_uv_auth_param_len < 32 ||
                    bio_constant_time_compare(expected,
                                              p.pin_uv_auth_param, 32) != 0) {
                    bio_secure_wipe(expected, 32);
                    return CTAP2_ERR_PIN_AUTH_INVALID;
                }
            } else {
                if (bio_constant_time_compare(expected,
                                              p.pin_uv_auth_param, 16) != 0) {
                    bio_secure_wipe(expected, 32);
                    return CTAP2_ERR_PIN_AUTH_INVALID;
                }
            }
            bio_secure_wipe(expected, 32);
        } else if (p.has_pin_auth && !ctx->pin.pin_token_valid) {
            /* pinUvAuthParam provided but token expired/invalid */
            return CTAP2_ERR_PIN_AUTH_INVALID;
        } else if (ctx->verify_user) {
            if (!ctx->verify_user(ctx->verify_user_ctx))
                return CTAP2_ERR_OPERATION_DENIED;
        } else {
            /* No pinUvAuth AND no built-in UV → deny */
            return CTAP2_ERR_PIN_AUTH_INVALID;
        }
    }

    bio_cbor_encoder_t enc;

    switch (p.sub_command) {
    case BIO_SUBCMD_GET_SENSOR_INFO: {
        bio_cbor_encoder_init(&enc, rsp, *rsp_len);
        bio_cbor_encode_map(&enc, 3);

        /* 0x01: modality → fingerprint (1) */
        bio_cbor_encode_uint(&enc, 0x01);
        bio_cbor_encode_uint(&enc, 1);

        /* 0x02: fingerprintKind → touch (2) */
        bio_cbor_encode_uint(&enc, 0x02);
        bio_cbor_encode_uint(&enc, 2);

        /* 0x03: maxCaptureSamplesRequiredForEnroll */
        bio_cbor_encode_uint(&enc, 0x03);
        bio_cbor_encode_uint(&enc, 5);

        if (enc.error) return CTAP2_ERR_OTHER;
        *rsp_len = enc.offset;
        return CTAP2_OK;
    }

    case BIO_SUBCMD_ENROLL_BEGIN: {
        /* Clean up any abandoned enrollment */
        if (g_bio_enroll_active >= 0 &&
            g_bio_enroll_active < CTAP2_MAX_BIO_TEMPLATES &&
            g_bio_templates[g_bio_enroll_active].in_use &&
            g_bio_templates[g_bio_enroll_active].samples_remaining > 0) {
            g_bio_templates[g_bio_enroll_active].in_use = false;
            if (g_bio_template_count > 0)
                g_bio_template_count--;
            g_bio_enroll_active = -1;
        }

        /* Find free template slot */
        int slot = -1;
        for (int i = 0; i < CTAP2_MAX_BIO_TEMPLATES; i++) {
            if (!g_bio_templates[i].in_use) {
                slot = i;
                break;
            }
        }
        if (slot < 0) return CTAP2_ERR_KEY_STORE_FULL;

        bio_template_entry_t *tmpl = &g_bio_templates[slot];
        memset(tmpl, 0, sizeof(*tmpl));
        tmpl->in_use = true;
        tmpl->template_id_len = 16;
        if (bio_random_bytes(tmpl->template_id, 16) != BIO_OK) {
            tmpl->in_use = false;
            return CTAP2_ERR_OTHER;
        }
        tmpl->samples_remaining = 4; /* Need 4 more captures */
        tmpl->created = (uint64_t)time(NULL);

        if (p.has_friendly_name) {
            strncpy(tmpl->friendly_name, p.friendly_name,
                    sizeof(tmpl->friendly_name) - 1);
        } else {
            snprintf(tmpl->friendly_name, sizeof(tmpl->friendly_name),
                     "Finger %zu", g_bio_template_count + 1);
        }

        g_bio_enroll_active = slot;
        g_bio_template_count++;

        /* Return templateId + lastEnrollSampleStatus + remainingSamples */
        bio_cbor_encoder_init(&enc, rsp, *rsp_len);
        bio_cbor_encode_map(&enc, 3);

        bio_cbor_encode_uint(&enc, 0x01); /* templateId */
        bio_cbor_encode_bstr(&enc, tmpl->template_id,
                              tmpl->template_id_len);

        bio_cbor_encode_uint(&enc, 0x02); /* lastEnrollSampleStatus */
        bio_cbor_encode_uint(&enc, 0x00); /* good sample */

        bio_cbor_encode_uint(&enc, 0x03); /* remainingSamples */
        bio_cbor_encode_uint(&enc, tmpl->samples_remaining);

        if (enc.error) return CTAP2_ERR_OTHER;
        *rsp_len = enc.offset;
        return CTAP2_OK;
    }

    case BIO_SUBCMD_ENROLL_CAPTURE_NEXT: {
        if (g_bio_enroll_active < 0 ||
            g_bio_enroll_active >= CTAP2_MAX_BIO_TEMPLATES ||
            !g_bio_templates[g_bio_enroll_active].in_use) {
            return CTAP2_ERR_NO_OPERATION_PENDING;
        }

        if (!p.has_template_id) return CTAP2_ERR_MISSING_PARAMETER;

        bio_template_entry_t *tmpl = &g_bio_templates[g_bio_enroll_active];

        /* Verify template ID matches */
        if (p.template_id_len != tmpl->template_id_len ||
            memcmp(p.template_id, tmpl->template_id,
                   tmpl->template_id_len) != 0) {
            return CTAP2_ERR_INVALID_OPTION;
        }

        /* Simulate capture success: decrement remaining */
        if (tmpl->samples_remaining > 0)
            tmpl->samples_remaining--;

        bio_cbor_encoder_init(&enc, rsp, *rsp_len);
        bio_cbor_encode_map(&enc, 2);

        bio_cbor_encode_uint(&enc, 0x02); /* lastEnrollSampleStatus */
        bio_cbor_encode_uint(&enc, 0x00); /* good */

        bio_cbor_encode_uint(&enc, 0x03); /* remainingSamples */
        bio_cbor_encode_uint(&enc, tmpl->samples_remaining);

        /* If enrollment complete, finalize */
        if (tmpl->samples_remaining == 0) {
            g_bio_enroll_active = -1;
        }

        if (enc.error) return CTAP2_ERR_OTHER;
        *rsp_len = enc.offset;
        return CTAP2_OK;
    }

    case BIO_SUBCMD_CANCEL_ENROLLMENT: {
        if (g_bio_enroll_active >= 0 &&
            g_bio_enroll_active < CTAP2_MAX_BIO_TEMPLATES &&
            g_bio_templates[g_bio_enroll_active].in_use &&
            g_bio_templates[g_bio_enroll_active].samples_remaining > 0) {
            /* Cancel: remove incomplete template */
            g_bio_templates[g_bio_enroll_active].in_use = false;
            if (g_bio_template_count > 0)
                g_bio_template_count--;
            g_bio_enroll_active = -1;
        }
        *rsp_len = 0;
        return CTAP2_OK;
    }

    case BIO_SUBCMD_ENUMERATE_ENROLLMENTS: {
        /* Count enrolled (completed) templates */
        size_t completed = 0;
        for (int i = 0; i < CTAP2_MAX_BIO_TEMPLATES; i++) {
            if (g_bio_templates[i].in_use &&
                g_bio_templates[i].samples_remaining == 0) {
                completed++;
            }
        }

        bio_cbor_encoder_init(&enc, rsp, *rsp_len);
        bio_cbor_encode_map(&enc, 1);

        bio_cbor_encode_uint(&enc, 0x01); /* templateInfos (CTAP2.1 §6.7.4 key 0x01) */
        bio_cbor_encode_array(&enc, completed);

        for (int i = 0; i < CTAP2_MAX_BIO_TEMPLATES; i++) {
            if (!g_bio_templates[i].in_use ||
                g_bio_templates[i].samples_remaining > 0) continue;

            bio_cbor_encode_map(&enc, 2);
            bio_cbor_encode_uint(&enc, 0x01); /* templateId */
            bio_cbor_encode_bstr(&enc, g_bio_templates[i].template_id,
                                  g_bio_templates[i].template_id_len);
            bio_cbor_encode_uint(&enc, 0x02); /* templateFriendlyName */
            bio_cbor_encode_tstr_z(&enc,
                                    g_bio_templates[i].friendly_name);
        }

        if (enc.error) return CTAP2_ERR_OTHER;
        *rsp_len = enc.offset;
        return CTAP2_OK;
    }

    case BIO_SUBCMD_SET_FRIENDLY_NAME: {
        if (!p.has_template_id || !p.has_friendly_name)
            return CTAP2_ERR_MISSING_PARAMETER;

        for (int i = 0; i < CTAP2_MAX_BIO_TEMPLATES; i++) {
            if (!g_bio_templates[i].in_use) continue;
            if (p.template_id_len != g_bio_templates[i].template_id_len)
                continue;
            if (memcmp(p.template_id, g_bio_templates[i].template_id,
                       p.template_id_len) == 0) {
                strncpy(g_bio_templates[i].friendly_name,
                        p.friendly_name,
                        sizeof(g_bio_templates[i].friendly_name) - 1);
                *rsp_len = 0;
                return CTAP2_OK;
            }
        }
        return CTAP2_ERR_INVALID_OPTION;
    }

    case BIO_SUBCMD_REMOVE_ENROLLMENT: {
        if (!p.has_template_id) return CTAP2_ERR_MISSING_PARAMETER;

        for (int i = 0; i < CTAP2_MAX_BIO_TEMPLATES; i++) {
            if (!g_bio_templates[i].in_use) continue;
            if (p.template_id_len != g_bio_templates[i].template_id_len)
                continue;
            if (memcmp(p.template_id, g_bio_templates[i].template_id,
                       p.template_id_len) == 0) {
                if (g_bio_enroll_active == i)
                    g_bio_enroll_active = -1;
                bio_secure_wipe(&g_bio_templates[i],
                                sizeof(bio_template_entry_t));
                if (g_bio_template_count > 0)
                    g_bio_template_count--;
                *rsp_len = 0;
                return CTAP2_OK;
            }
        }
        return CTAP2_ERR_INVALID_OPTION;
    }

    default:
        return CTAP2_ERR_INVALID_CBOR;
    }
}

/* ══════════════════════════════════════════════════════════════
 *  authenticatorCredentialManagement (0x0A)
 * ══════════════════════════════════════════════════════════════ */

/*
 * CredentialManagement sub-commands:
 *   0x01  getCredsMetadata       — Get total stored + remaining capacity
 *   0x02  enumerateRPsBegin      — Start iterating RPs
 *   0x03  enumerateRPsGetNextRP
 *   0x04  enumerateCredentialsBegin  — Start iterating creds for an RP
 *   0x05  enumerateCredentialsGetNextCredential
 *   0x06  deleteCredential       — Delete a specific credential
 *   0x07  updateUserInformation  — Update user entity for a credential
 *
 * Parameters (CBOR map):
 *   0x01: subCommand (uint)
 *   0x02: subCommandParams (map)
 *   0x03: pinUvAuthProtocol (uint)
 *   0x04: pinUvAuthParam (bstr)
 */

#define CRED_SUBCMD_GET_METADATA                0x01
#define CRED_SUBCMD_ENUMERATE_RPS_BEGIN         0x02
#define CRED_SUBCMD_ENUMERATE_RPS_NEXT          0x03
#define CRED_SUBCMD_ENUMERATE_CREDS_BEGIN       0x04
#define CRED_SUBCMD_ENUMERATE_CREDS_NEXT        0x05
#define CRED_SUBCMD_DELETE_CREDENTIAL           0x06
#define CRED_SUBCMD_UPDATE_USER_INFO            0x07

/* Enumeration state — kept between enumerateXxxBegin/GetNext calls */
static struct {
    /* RP enumeration */
    size_t    rp_count;
    size_t    rp_index;
    uint8_t   rp_hashes[CTAP2_MAX_CREDENTIALS_STORED][32];
    char      rp_ids[CTAP2_MAX_CREDENTIALS_STORED][CTAP2_MAX_RP_ID_LEN];

    /* Credential enumeration for a specific RP */
    uint8_t   enum_rp_id_hash[32];
    size_t    cred_count;
    size_t    cred_index;
    size_t    cred_slots[CTAP2_MAX_CREDENTIALS_STORED];
} g_cred_enum;

/* Wipe credential enumeration state (called from bio_fido2_bio_reset
 * indirectly via reset/cleanup, and from credMgmt non-getNext) */
static void cred_enum_reset(void)
{
    memset(&g_cred_enum, 0, sizeof(g_cred_enum));
}

typedef struct {
    uint32_t  sub_command;
    uint32_t  pin_protocol;

    /* sub-command params */
    uint8_t   rp_id_hash[32];
    bool      has_rp_id_hash;
    ctap2_credential_id_t cred_id;
    bool      has_cred_id;

    /* For updateUserInformation */
    ctap2_user_t user;
    bool      has_user;

    /* pinUvAuth */
    uint8_t   pin_uv_auth_param[32];
    size_t    pin_uv_auth_param_len;
    bool      has_pin_uv_auth;
} cred_mgmt_params_t;

static uint8_t parse_cred_mgmt_params(const uint8_t *req, size_t req_len,
                                        cred_mgmt_params_t *p)
{
    memset(p, 0, sizeof(*p));
    p->pin_protocol = 1;

    bio_cbor_decoder_t dec;
    bio_cbor_decoder_init(&dec, req, req_len);

    uint64_t map_cnt;
    if (bio_cbor_decode_map(&dec, &map_cnt) != BIO_OK)
        return CTAP2_ERR_INVALID_CBOR;

    for (uint64_t i = 0; i < map_cnt; i++) {
        uint64_t key;
        if (bio_cbor_decode_uint(&dec, &key) != BIO_OK)
            return CTAP2_ERR_INVALID_CBOR;

        switch (key) {
        case 0x01: { /* subCommand */
            uint64_t v;
            if (bio_cbor_decode_uint(&dec, &v) != BIO_OK)
                return CTAP2_ERR_INVALID_CBOR;
            p->sub_command = (uint32_t)v;
            break;
        }
        case 0x02: { /* subCommandParams */
            uint64_t sc_cnt;
            if (bio_cbor_decode_map(&dec, &sc_cnt) != BIO_OK)
                return CTAP2_ERR_INVALID_CBOR;

            for (uint64_t j = 0; j < sc_cnt; j++) {
                uint64_t sk;
                if (bio_cbor_decode_uint(&dec, &sk) != BIO_OK)
                    return CTAP2_ERR_INVALID_CBOR;

                switch (sk) {
                case 0x01: { /* rpIDHash (bstr 32) */
                    bio_cbor_item_t val;
                    if (bio_cbor_decode_next(&dec, &val) != BIO_OK)
                        return CTAP2_ERR_INVALID_CBOR;
                    if (val.type == BIO_CBOR_BSTR && val.bstr.len == 32) {
                        memcpy(p->rp_id_hash, val.bstr.data, 32);
                        p->has_rp_id_hash = true;
                    }
                    break;
                }
                case 0x02: { /* credentialID (map {id:bstr, type:str}) */
                    uint64_t desc_cnt;
                    if (bio_cbor_decode_map(&dec, &desc_cnt) != BIO_OK)
                        return CTAP2_ERR_INVALID_CBOR;
                    for (uint64_t k = 0; k < desc_cnt; k++) {
                        bio_cbor_item_t dk;
                        if (bio_cbor_decode_next(&dec, &dk) != BIO_OK)
                            return CTAP2_ERR_INVALID_CBOR;
                        if (dk.type == BIO_CBOR_TSTR &&
                            dk.tstr.len == 2 &&
                            memcmp(dk.tstr.data, "id", 2) == 0) {
                            bio_cbor_item_t dv;
                            if (bio_cbor_decode_next(&dec, &dv) != BIO_OK)
                                return CTAP2_ERR_INVALID_CBOR;
                            if (dv.type == BIO_CBOR_BSTR) {
                                p->cred_id.id_len =
                                    dv.bstr.len < CTAP2_MAX_CREDENTIAL_ID_LEN
                                        ? dv.bstr.len
                                        : CTAP2_MAX_CREDENTIAL_ID_LEN;
                                memcpy(p->cred_id.id, dv.bstr.data,
                                       p->cred_id.id_len);
                                p->has_cred_id = true;
                            }
                        } else {
                            bio_cbor_skip(&dec);
                        }
                    }
                    break;
                }
                case 0x03: { /* user (map) */
                    uint64_t u_cnt;
                    if (bio_cbor_decode_map(&dec, &u_cnt) != BIO_OK)
                        return CTAP2_ERR_INVALID_CBOR;
                    for (uint64_t k = 0; k < u_cnt; k++) {
                        bio_cbor_item_t uk;
                        if (bio_cbor_decode_next(&dec, &uk) != BIO_OK)
                            return CTAP2_ERR_INVALID_CBOR;
                        if (uk.type == BIO_CBOR_TSTR &&
                            uk.tstr.len == 2 &&
                            memcmp(uk.tstr.data, "id", 2) == 0) {
                            bio_cbor_item_t uv;
                            if (bio_cbor_decode_next(&dec, &uv) != BIO_OK)
                                return CTAP2_ERR_INVALID_CBOR;
                            if (uv.type == BIO_CBOR_BSTR) {
                                p->user.id_len =
                                    uv.bstr.len < sizeof(p->user.id)
                                        ? uv.bstr.len
                                        : sizeof(p->user.id);
                                memcpy(p->user.id, uv.bstr.data,
                                       p->user.id_len);
                                p->has_user = true;
                            }
                        } else if (uk.type == BIO_CBOR_TSTR &&
                                   uk.tstr.len == 4 &&
                                   memcmp(uk.tstr.data, "name", 4) == 0) {
                            bio_cbor_item_t nv;
                            if (bio_cbor_decode_next(&dec, &nv) != BIO_OK)
                                return CTAP2_ERR_INVALID_CBOR;
                            if (nv.type == BIO_CBOR_TSTR) {
                                size_t cp = nv.tstr.len <
                                                sizeof(p->user.name) - 1
                                                ? nv.tstr.len
                                                : sizeof(p->user.name) - 1;
                                memcpy(p->user.name, nv.tstr.data, cp);
                                p->user.name[cp] = '\0';
                            }
                        } else if (uk.type == BIO_CBOR_TSTR &&
                                   uk.tstr.len == 11 &&
                                   memcmp(uk.tstr.data, "displayName",
                                          11) == 0) {
                            bio_cbor_item_t dv;
                            if (bio_cbor_decode_next(&dec, &dv) != BIO_OK)
                                return CTAP2_ERR_INVALID_CBOR;
                            if (dv.type == BIO_CBOR_TSTR) {
                                size_t cp =
                                    dv.tstr.len <
                                        sizeof(p->user.display_name) - 1
                                        ? dv.tstr.len
                                        : sizeof(p->user.display_name) - 1;
                                memcpy(p->user.display_name,
                                       dv.tstr.data, cp);
                                p->user.display_name[cp] = '\0';
                            }
                        } else {
                            bio_cbor_skip(&dec);
                        }
                    }
                    break;
                }
                default:
                    bio_cbor_skip(&dec);
                    break;
                }
            }
            break;
        }
        case 0x03: { /* pinUvAuthProtocol */
            uint64_t v;
            if (bio_cbor_decode_uint(&dec, &v) != BIO_OK)
                return CTAP2_ERR_INVALID_CBOR;
            p->pin_protocol = (uint32_t)v;
            break;
        }
        case 0x04: { /* pinUvAuthParam */
            bio_cbor_item_t val;
            if (bio_cbor_decode_next(&dec, &val) != BIO_OK)
                return CTAP2_ERR_INVALID_CBOR;
            if (val.type == BIO_CBOR_BSTR && val.bstr.len <= 32) {
                memcpy(p->pin_uv_auth_param, val.bstr.data, val.bstr.len);
                p->pin_uv_auth_param_len = val.bstr.len;
                p->has_pin_uv_auth = true;
            }
            break;
        }
        default:
            bio_cbor_skip(&dec);
            break;
        }
    }

    if (p->sub_command == 0) return CTAP2_ERR_MISSING_PARAMETER;
    return CTAP2_OK;
}

/* Helper: encode a credential user entity */
static void encode_user_entity(bio_cbor_encoder_t *enc,
                                const ctap2_user_t *user)
{
    bio_cbor_encode_map(enc, 3);
    bio_cbor_encode_tstr_z(enc, "id");
    bio_cbor_encode_bstr(enc, user->id, user->id_len);
    bio_cbor_encode_tstr_z(enc, "name");
    bio_cbor_encode_tstr_z(enc, user->name);
    bio_cbor_encode_tstr_z(enc, "displayName");
    bio_cbor_encode_tstr_z(enc, user->display_name);
}

/* Helper: encode a credential descriptor */
static void encode_cred_descriptor(bio_cbor_encoder_t *enc,
                                    const ctap2_credential_id_t *cid)
{
    bio_cbor_encode_map(enc, 2);
    bio_cbor_encode_tstr_z(enc, "id");
    bio_cbor_encode_bstr(enc, cid->id, cid->id_len);
    bio_cbor_encode_tstr_z(enc, "type");
    bio_cbor_encode_tstr_z(enc, "public-key");
}

/* Helper: encode COSE public key */
extern int encode_cose_pubkey(bio_cbor_encoder_t *enc,
                                const uint8_t pubkey[65]);

uint8_t ctap2_credential_management(bio_fido2_ctx_t *ctx,
                                     const uint8_t *req, size_t req_len,
                                     uint8_t *rsp, size_t *rsp_len)
{
    cred_mgmt_params_t p;
    uint8_t rc = parse_cred_mgmt_params(req, req_len, &p);
    if (rc != CTAP2_OK) return rc;

    /*
     * pinUvAuthParam verification (CTAP2.1 §6.8):
     * For subcommands that modify state (delete, update) or enumerate
     * credentials, the platform MUST provide pinUvAuthParam.
     *
     * pinUvAuthParam = HMAC-SHA256(pinToken, mergedData)
     * Protocol 1: verify left(hmac, 16) matches param
     *
     * For subcommands that don't require auth (getNext), skip.
     */
    bool requires_auth = (p.sub_command != CRED_SUBCMD_ENUMERATE_RPS_NEXT &&
                          p.sub_command != CRED_SUBCMD_ENUMERATE_CREDS_NEXT);

    if (requires_auth) {
        /* Must have either a valid PIN token or built-in UV */
        if (p.has_pin_uv_auth) {
            if (!ctx->pin.pin_token_valid)
                return CTAP2_ERR_PIN_AUTH_INVALID;
            if (p.pin_protocol != 1 && p.pin_protocol != 2)
                return CTAP2_ERR_PIN_AUTH_INVALID;
            if (ctx->pin.pin_token_permissions != 0 &&
                (ctx->pin.pin_token_permissions & CTAP2_PIN_PERM_CREDENTIAL_MGMT) == 0) {
                return CTAP2_ERR_PIN_AUTH_INVALID;
            }

            /*
             * Verify: HMAC-SHA256(pinToken, 0xFF..0xFF(32) || subCommand(1))
             * For protocol 1, we verify left 16 bytes.
             */
            uint8_t message[33];
            memset(message, 0xFF, 32);  /* 32 bytes of 0xFF */
            message[32] = (uint8_t)p.sub_command;

            uint8_t expected[32];
            bio_hmac_sha256(ctx->pin.pin_token, CTAP2_PIN_TOKEN_SIZE,
                            message, sizeof(message), expected);

            if (p.pin_protocol == 2) {
                if (p.pin_uv_auth_param_len < 32 ||
                    bio_constant_time_compare(expected, p.pin_uv_auth_param,
                                              32) != 0) {
                    bio_secure_wipe(expected, 32);
                    return CTAP2_ERR_PIN_AUTH_INVALID;
                }
            } else {
                if (p.pin_uv_auth_param_len < 16 ||
                    bio_constant_time_compare(expected, p.pin_uv_auth_param,
                                              16) != 0) {
                    bio_secure_wipe(expected, 32);
                    return CTAP2_ERR_PIN_AUTH_INVALID;
                }
            }
            bio_secure_wipe(expected, 32);
        } else if (ctx->verify_user) {
            if (!ctx->verify_user(ctx->verify_user_ctx))
                return CTAP2_ERR_OPERATION_DENIED;
        } else {
            /* No pinUvAuth AND no built-in UV → deny */
            return CTAP2_ERR_PIN_AUTH_INVALID;
        }
    }

    /* Invalidate stale enumeration on non-getNext commands */
    if (p.sub_command != CRED_SUBCMD_ENUMERATE_RPS_NEXT &&
        p.sub_command != CRED_SUBCMD_ENUMERATE_CREDS_NEXT) {
        g_cred_enum.rp_count = 0;
        g_cred_enum.cred_count = 0;
    }

    bio_cbor_encoder_t enc;

    switch (p.sub_command) {

    /* ── getCredsMetadata (0x01) ──────────────────────────── */
    case CRED_SUBCMD_GET_METADATA: {
        size_t existing = ctx->credential_count;
        size_t remaining = CTAP2_MAX_CREDENTIALS_STORED > existing
                               ? CTAP2_MAX_CREDENTIALS_STORED - existing
                               : 0;

        bio_cbor_encoder_init(&enc, rsp, *rsp_len);
        bio_cbor_encode_map(&enc, 2);

        bio_cbor_encode_uint(&enc, 0x01);
        bio_cbor_encode_uint(&enc, existing);

        bio_cbor_encode_uint(&enc, 0x02);
        bio_cbor_encode_uint(&enc, remaining);

        if (enc.error) return CTAP2_ERR_OTHER;
        *rsp_len = enc.offset;
        return CTAP2_OK;
    }

    /* ── enumerateRPsBegin (0x02) ─────────────────────────── */
    case CRED_SUBCMD_ENUMERATE_RPS_BEGIN: {
        /* Collect unique RPs from stored credentials */
        g_cred_enum.rp_count = 0;

        for (size_t i = 0; i < CTAP2_MAX_CREDENTIALS_STORED; i++) {
            if (!ctx->credentials[i].in_use) continue;

            bool seen = false;
            for (size_t j = 0; j < g_cred_enum.rp_count; j++) {
                if (memcmp(g_cred_enum.rp_hashes[j],
                           ctx->credentials[i].rp.id_hash, 32) == 0) {
                    seen = true;
                    break;
                }
            }
            if (!seen && g_cred_enum.rp_count <
                             CTAP2_MAX_CREDENTIALS_STORED) {
                memcpy(g_cred_enum.rp_hashes[g_cred_enum.rp_count],
                       ctx->credentials[i].rp.id_hash, 32);
                strncpy(g_cred_enum.rp_ids[g_cred_enum.rp_count],
                        ctx->credentials[i].rp.id,
                        CTAP2_MAX_RP_ID_LEN - 1);
                g_cred_enum.rp_count++;
            }
        }

        if (g_cred_enum.rp_count == 0)
            return CTAP2_ERR_NO_CREDENTIALS;

        g_cred_enum.rp_index = 1; /* next call returns [1] */

        /* Return first RP */
        bio_cbor_encoder_init(&enc, rsp, *rsp_len);
        bio_cbor_encode_map(&enc, 3);

        /* 0x03: rp entity */
        bio_cbor_encode_uint(&enc, 0x03);
        bio_cbor_encode_map(&enc, 1);
        bio_cbor_encode_tstr_z(&enc, "id");
        bio_cbor_encode_tstr_z(&enc, g_cred_enum.rp_ids[0]);

        /* 0x04: rpIDHash */
        bio_cbor_encode_uint(&enc, 0x04);
        bio_cbor_encode_bstr(&enc, g_cred_enum.rp_hashes[0], 32);

        /* 0x05: totalRPs */
        bio_cbor_encode_uint(&enc, 0x05);
        bio_cbor_encode_uint(&enc, g_cred_enum.rp_count);

        if (enc.error) return CTAP2_ERR_OTHER;
        *rsp_len = enc.offset;
        return CTAP2_OK;
    }

    /* ── enumerateRPsGetNextRP (0x03) ─────────────────────── */
    case CRED_SUBCMD_ENUMERATE_RPS_NEXT: {
        if (g_cred_enum.rp_index >= g_cred_enum.rp_count)
            return CTAP2_ERR_NO_CREDENTIALS;

        size_t idx = g_cred_enum.rp_index++;

        bio_cbor_encoder_init(&enc, rsp, *rsp_len);
        bio_cbor_encode_map(&enc, 2);

        bio_cbor_encode_uint(&enc, 0x03);
        bio_cbor_encode_map(&enc, 1);
        bio_cbor_encode_tstr_z(&enc, "id");
        bio_cbor_encode_tstr_z(&enc, g_cred_enum.rp_ids[idx]);

        bio_cbor_encode_uint(&enc, 0x04);
        bio_cbor_encode_bstr(&enc, g_cred_enum.rp_hashes[idx], 32);

        if (enc.error) return CTAP2_ERR_OTHER;
        *rsp_len = enc.offset;
        return CTAP2_OK;
    }

    /* ── enumerateCredentialsBegin (0x04) ──────────────────── */
    case CRED_SUBCMD_ENUMERATE_CREDS_BEGIN: {
        if (!p.has_rp_id_hash) return CTAP2_ERR_MISSING_PARAMETER;

        memcpy(g_cred_enum.enum_rp_id_hash, p.rp_id_hash, 32);
        g_cred_enum.cred_count = 0;

        for (size_t i = 0; i < CTAP2_MAX_CREDENTIALS_STORED; i++) {
            if (!ctx->credentials[i].in_use) continue;
            if (memcmp(ctx->credentials[i].rp.id_hash,
                       p.rp_id_hash, 32) != 0) continue;

            g_cred_enum.cred_slots[g_cred_enum.cred_count++] = i;
        }

        if (g_cred_enum.cred_count == 0)
            return CTAP2_ERR_NO_CREDENTIALS;

        g_cred_enum.cred_index = 1;

        /* Return first credential */
        size_t slot = g_cred_enum.cred_slots[0];
        const ctap2_credential_t *c = &ctx->credentials[slot];

        bio_cbor_encoder_init(&enc, rsp, *rsp_len);
        bio_cbor_encode_map(&enc, 5);

        /* 0x06: user */
        bio_cbor_encode_uint(&enc, 0x06);
        encode_user_entity(&enc, &c->user);

        /* 0x07: credentialID */
        bio_cbor_encode_uint(&enc, 0x07);
        encode_cred_descriptor(&enc, &c->cred_id);

        /* 0x08: publicKey (COSE_Key) */
        bio_cbor_encode_uint(&enc, 0x08);
        encode_cose_pubkey(&enc, c->public_key);

        /* 0x09: totalCredentials */
        bio_cbor_encode_uint(&enc, 0x09);
        bio_cbor_encode_uint(&enc, g_cred_enum.cred_count);

        /* 0x0A: credProtect */
        bio_cbor_encode_uint(&enc, 0x0A);
        bio_cbor_encode_uint(&enc, c->cred_protect);

        if (enc.error) return CTAP2_ERR_OTHER;
        *rsp_len = enc.offset;
        return CTAP2_OK;
    }

    /* ── enumerateCredentialsGetNextCredential (0x05) ──────── */
    case CRED_SUBCMD_ENUMERATE_CREDS_NEXT: {
        if (g_cred_enum.cred_index >= g_cred_enum.cred_count)
            return CTAP2_ERR_NO_CREDENTIALS;

        size_t slot = g_cred_enum.cred_slots[g_cred_enum.cred_index++];
        const ctap2_credential_t *c = &ctx->credentials[slot];

        bio_cbor_encoder_init(&enc, rsp, *rsp_len);
        bio_cbor_encode_map(&enc, 4);

        bio_cbor_encode_uint(&enc, 0x06);
        encode_user_entity(&enc, &c->user);

        bio_cbor_encode_uint(&enc, 0x07);
        encode_cred_descriptor(&enc, &c->cred_id);

        bio_cbor_encode_uint(&enc, 0x08);
        encode_cose_pubkey(&enc, c->public_key);

        bio_cbor_encode_uint(&enc, 0x0A);
        bio_cbor_encode_uint(&enc, c->cred_protect);

        if (enc.error) return CTAP2_ERR_OTHER;
        *rsp_len = enc.offset;
        return CTAP2_OK;
    }

    /* ── deleteCredential (0x06) ──────────────────────────── */
    case CRED_SUBCMD_DELETE_CREDENTIAL: {
        if (!p.has_cred_id) return CTAP2_ERR_MISSING_PARAMETER;

        for (size_t i = 0; i < CTAP2_MAX_CREDENTIALS_STORED; i++) {
            if (!ctx->credentials[i].in_use) continue;
            if (ctx->credentials[i].cred_id.id_len != p.cred_id.id_len)
                continue;
            if (memcmp(ctx->credentials[i].cred_id.id,
                       p.cred_id.id, p.cred_id.id_len) == 0) {
                /* Securely wipe and remove */
                bio_secure_wipe(&ctx->credentials[i],
                                sizeof(ctap2_credential_t));
                if (ctx->credential_count > 0)
                    ctx->credential_count--;
                bio_fido2_save_credentials(ctx);
                *rsp_len = 0;
                return CTAP2_OK;
            }
        }
        return CTAP2_ERR_NO_CREDENTIALS;
    }

    /* ── updateUserInformation (0x07) ─────────────────────── */
    case CRED_SUBCMD_UPDATE_USER_INFO: {
        if (!p.has_cred_id || !p.has_user)
            return CTAP2_ERR_MISSING_PARAMETER;

        for (size_t i = 0; i < CTAP2_MAX_CREDENTIALS_STORED; i++) {
            if (!ctx->credentials[i].in_use) continue;
            if (ctx->credentials[i].cred_id.id_len != p.cred_id.id_len)
                continue;
            if (memcmp(ctx->credentials[i].cred_id.id,
                       p.cred_id.id, p.cred_id.id_len) == 0) {
                /*
                 * CTAP2.1 §6.8: user.id is immutable. Only name and
                 * displayName may be updated. If user.id is provided,
                 * it MUST match the existing credential's user.id.
                 */
                if (p.user.id_len > 0 &&
                    (p.user.id_len != ctx->credentials[i].user.id_len ||
                     memcmp(p.user.id, ctx->credentials[i].user.id,
                            p.user.id_len) != 0)) {
                    return CTAP2_ERR_INVALID_OPTION;
                }
                if (p.user.name[0] != '\0') {
                    strncpy(ctx->credentials[i].user.name,
                            p.user.name,
                            sizeof(ctx->credentials[i].user.name) - 1);
                    ctx->credentials[i].user.name[
                        sizeof(ctx->credentials[i].user.name) - 1] = '\0';
                }
                if (p.user.display_name[0] != '\0') {
                    strncpy(ctx->credentials[i].user.display_name,
                            p.user.display_name,
                            sizeof(ctx->credentials[i].user.display_name) - 1);
                    ctx->credentials[i].user.display_name[
                        sizeof(ctx->credentials[i].user.display_name) - 1] = '\0';
                }
                bio_fido2_save_credentials(ctx);
                *rsp_len = 0;
                return CTAP2_OK;
            }
        }
        return CTAP2_ERR_NO_CREDENTIALS;
    }

    default:
        return CTAP2_ERR_INVALID_CBOR;
    }
}
