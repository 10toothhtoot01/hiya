/*
 * bio_fido2_credential.c — CTAP2 MakeCredential + GetAssertion
 *
 * Copyright (C) 2024 Hiya Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Implements the two most complex CTAP2 commands:
 *   0x01 authenticatorMakeCredential
 *   0x02 authenticatorGetAssertion
 *   0x08 authenticatorGetNextAssertion
 */

#include "fido2/bio_fido2.h"
#include "cbor/bio_cbor.h"
#include "crypto/bio_crypto.h"

#include <string.h>
#include <stdlib.h>
#include <time.h>

/* ── DER-encode an ECDSA signature ──────────────────────────── */

/*
 * Encode a raw (r || s) 64-byte ECDSA signature into DER format:
 *   SEQUENCE { INTEGER(r), INTEGER(s) }
 *
 * Each integer is trimmed of leading zeros, and gets a 0x00 pad if
 * the high bit is set (so it is not misinterpreted as negative).
 *
 * Max DER output: 2 + 2 + 33 + 2 + 33 = 72 bytes.
 *
 * Returns the number of bytes written, or 0 on failure.
 */
static size_t ecdsa_sig_to_der(const uint8_t raw_sig[64],
                               uint8_t *der, size_t der_cap)
{
    const uint8_t *r = raw_sig;
    const uint8_t *s = raw_sig + 32;

    /* Strip leading zeros from r */
    size_t r_off = 0;
    while (r_off < 31 && r[r_off] == 0)
        r_off++;
    size_t r_len = 32 - r_off;
    bool r_pad = (r[r_off] & 0x80) != 0;
    size_t r_total = r_len + (r_pad ? 1 : 0);

    /* Strip leading zeros from s */
    size_t s_off = 0;
    while (s_off < 31 && s[s_off] == 0)
        s_off++;
    size_t s_len = 32 - s_off;
    bool s_pad = (s[s_off] & 0x80) != 0;
    size_t s_total = s_len + (s_pad ? 1 : 0);

    /* Total inner length: TAG(1) + LEN(1) + r_total + TAG(1) + LEN(1) + s_total */
    size_t inner_len = 2 + r_total + 2 + s_total;

    /* Total DER length: TAG(1) + LEN(1 or 2) + inner_len */
    size_t total;
    if (inner_len < 128)
    {
        total = 2 + inner_len;
    }
    else
    {
        total = 3 + inner_len; /* long-form length for > 127 */
    }

    if (total > der_cap)
        return 0;

    size_t pos = 0;

    /* SEQUENCE tag */
    der[pos++] = 0x30;
    if (inner_len < 128)
    {
        der[pos++] = (uint8_t)inner_len;
    }
    else
    {
        der[pos++] = 0x81;
        der[pos++] = (uint8_t)inner_len;
    }

    /* INTEGER r */
    der[pos++] = 0x02;
    der[pos++] = (uint8_t)r_total;
    if (r_pad)
        der[pos++] = 0x00;
    memcpy(der + pos, r + r_off, r_len);
    pos += r_len;

    /* INTEGER s */
    der[pos++] = 0x02;
    der[pos++] = (uint8_t)s_total;
    if (s_pad)
        der[pos++] = 0x00;
    memcpy(der + pos, s + s_off, s_len);
    pos += s_len;

    return pos;
}

/* Forward declarations from bio_fido2.c */

/* Forward: build_auth_data, generate_credential_id, encode_cose_pubkey */
extern int build_auth_data(uint8_t *out, size_t *out_len,
                           const uint8_t rp_id_hash[32],
                           uint8_t flags, uint32_t sign_count,
                           const ctap2_credential_id_t *cred_id,
                           const uint8_t *pubkey);

extern int generate_credential_id(ctap2_credential_id_t *cred_id,
                                  const uint8_t privkey[32],
                                  const uint8_t rp_id_hash[32],
                                  const uint8_t wrap_key[32]);

extern int unwrap_credential_id(const ctap2_credential_id_t *cred_id,
                                const uint8_t wrap_key[32],
                                const uint8_t rp_id_hash[32],
                                uint8_t privkey_out[32]);

/* ── Parse helpers ───────────────────────────────────────────── */

/*
 * Parse MakeCredential request parameters (CBOR map):
 *   0x01: clientDataHash (bstr, 32)
 *   0x02: rp (map: "id", "name")
 *   0x03: user (map: "id", "name", "displayName")
 *   0x04: pubKeyCredParams (array of {type, alg})
 *   0x05: excludeList (array of credential descriptors) [optional]
 *   0x07: options (map) [optional]
 */
typedef struct
{
    uint8_t client_data_hash[32];
    ctap2_rp_t rp;
    ctap2_user_t user;
    bool es256_supported;
    bool rk_requested;
    bool uv_requested;

    /* Exclude list */
    ctap2_credential_id_t exclude_list[CTAP2_MAX_ALLOW_LIST];
    size_t exclude_count;

    /* PIN/UV auth (CTAP2 §6.1 keys 0x08, 0x09) */
    uint8_t pin_uv_auth_param[32];
    size_t pin_uv_auth_param_len;
    bool has_pin_uv_auth_param;
    uint32_t pin_uv_auth_protocol;

    /* credProtect extension (CTAP2.1 §12.4) */
    uint8_t cred_protect; /* 0 = not specified, 1/2/3 = level */
    bool hmac_secret_requested;
} make_cred_params_t;

static uint8_t parse_rp_entity(bio_cbor_decoder_t *dec, ctap2_rp_t *rp)
{
    uint64_t map_cnt;
    if (bio_cbor_decode_map(dec, &map_cnt) != BIO_OK)
        return CTAP2_ERR_INVALID_CBOR;

    for (uint64_t i = 0; i < map_cnt; i++)
    {
        bio_cbor_item_t key_item;
        if (bio_cbor_decode_next(dec, &key_item) != BIO_OK)
            return CTAP2_ERR_INVALID_CBOR;

        if (key_item.type != BIO_CBOR_TSTR)
        {
            bio_cbor_skip(dec);
            continue;
        }

        if (key_item.tstr.len == 2 &&
            memcmp(key_item.tstr.data, "id", 2) == 0)
        {
            bio_cbor_item_t val;
            if (bio_cbor_decode_next(dec, &val) != BIO_OK)
                return CTAP2_ERR_INVALID_CBOR;
            if (val.type != BIO_CBOR_TSTR)
                return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
            size_t copy = val.tstr.len < sizeof(rp->id) - 1 ? val.tstr.len : sizeof(rp->id) - 1;
            memcpy(rp->id, val.tstr.data, copy);
            rp->id[copy] = '\0';
        }
        else if (key_item.tstr.len == 4 &&
                 memcmp(key_item.tstr.data, "name", 4) == 0)
        {
            bio_cbor_item_t val;
            if (bio_cbor_decode_next(dec, &val) != BIO_OK)
                return CTAP2_ERR_INVALID_CBOR;
            if (val.type != BIO_CBOR_TSTR)
                return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
            size_t copy = val.tstr.len < sizeof(rp->name) - 1 ? val.tstr.len : sizeof(rp->name) - 1;
            memcpy(rp->name, val.tstr.data, copy);
            rp->name[copy] = '\0';
        }
        else
        {
            bio_cbor_skip(dec);
        }
    }

    /* Compute SHA-256 of RP ID */
    bio_sha256((const uint8_t *)rp->id, strlen(rp->id), rp->id_hash);
    return CTAP2_OK;
}

static uint8_t parse_user_entity(bio_cbor_decoder_t *dec, ctap2_user_t *user)
{
    uint64_t map_cnt;
    if (bio_cbor_decode_map(dec, &map_cnt) != BIO_OK)
        return CTAP2_ERR_INVALID_CBOR;

    for (uint64_t i = 0; i < map_cnt; i++)
    {
        bio_cbor_item_t key_item;
        if (bio_cbor_decode_next(dec, &key_item) != BIO_OK)
            return CTAP2_ERR_INVALID_CBOR;

        if (key_item.type != BIO_CBOR_TSTR)
        {
            bio_cbor_skip(dec);
            continue;
        }

        if (key_item.tstr.len == 2 &&
            memcmp(key_item.tstr.data, "id", 2) == 0)
        {
            bio_cbor_item_t val;
            if (bio_cbor_decode_next(dec, &val) != BIO_OK)
                return CTAP2_ERR_INVALID_CBOR;
            if (val.type != BIO_CBOR_BSTR)
                return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
            user->id_len = val.bstr.len < sizeof(user->id) ? val.bstr.len : sizeof(user->id);
            memcpy(user->id, val.bstr.data, user->id_len);
        }
        else if (key_item.tstr.len == 4 &&
                 memcmp(key_item.tstr.data, "name", 4) == 0)
        {
            bio_cbor_item_t val;
            if (bio_cbor_decode_next(dec, &val) != BIO_OK)
                return CTAP2_ERR_INVALID_CBOR;
            if (val.type != BIO_CBOR_TSTR)
                return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
            size_t copy = val.tstr.len < sizeof(user->name) - 1 ? val.tstr.len : sizeof(user->name) - 1;
            memcpy(user->name, val.tstr.data, copy);
            user->name[copy] = '\0';
        }
        else if (key_item.tstr.len == 11 &&
                 memcmp(key_item.tstr.data, "displayName", 11) == 0)
        {
            bio_cbor_item_t val;
            if (bio_cbor_decode_next(dec, &val) != BIO_OK)
                return CTAP2_ERR_INVALID_CBOR;
            if (val.type != BIO_CBOR_TSTR)
                return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
            size_t copy = val.tstr.len < sizeof(user->display_name) - 1
                              ? val.tstr.len
                              : sizeof(user->display_name) - 1;
            memcpy(user->display_name, val.tstr.data, copy);
            user->display_name[copy] = '\0';
        }
        else
        {
            bio_cbor_skip(dec);
        }
    }

    return CTAP2_OK;
}

static uint8_t parse_make_cred_params(const uint8_t *req, size_t req_len,
                                      make_cred_params_t *params)
{
    memset(params, 0, sizeof(*params));

    bio_cbor_decoder_t dec;
    bio_cbor_decoder_init(&dec, req, req_len);

    uint64_t map_cnt;
    if (bio_cbor_decode_map(&dec, &map_cnt) != BIO_OK)
        return CTAP2_ERR_INVALID_CBOR;

    bool has_cdh = false, has_rp = false, has_user = false, has_alg = false;

    for (uint64_t i = 0; i < map_cnt; i++)
    {
        uint64_t key;
        if (bio_cbor_decode_uint(&dec, &key) != BIO_OK)
            return CTAP2_ERR_INVALID_CBOR;

        switch (key)
        {
        case 0x01:
        { /* clientDataHash */
            bio_cbor_item_t val;
            if (bio_cbor_decode_next(&dec, &val) != BIO_OK)
                return CTAP2_ERR_INVALID_CBOR;
            if (val.type != BIO_CBOR_BSTR || val.bstr.len != 32)
                return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
            memcpy(params->client_data_hash, val.bstr.data, 32);
            has_cdh = true;
            break;
        }
        case 0x02:
        { /* rp */
            uint8_t rc = parse_rp_entity(&dec, &params->rp);
            if (rc != CTAP2_OK)
                return rc;
            has_rp = true;
            break;
        }
        case 0x03:
        { /* user */
            uint8_t rc = parse_user_entity(&dec, &params->user);
            if (rc != CTAP2_OK)
                return rc;
            has_user = true;
            break;
        }
        case 0x04:
        { /* pubKeyCredParams */
            uint64_t arr_cnt;
            if (bio_cbor_decode_array(&dec, &arr_cnt) != BIO_OK)
                return CTAP2_ERR_INVALID_CBOR;

            for (uint64_t j = 0; j < arr_cnt; j++)
            {
                uint64_t inner_cnt;
                if (bio_cbor_decode_map(&dec, &inner_cnt) != BIO_OK)
                    return CTAP2_ERR_INVALID_CBOR;

                int32_t alg = 0;
                char type[16] = {0};

                for (uint64_t k = 0; k < inner_cnt; k++)
                {
                    bio_cbor_item_t mk;
                    if (bio_cbor_decode_next(&dec, &mk) != BIO_OK)
                        return CTAP2_ERR_INVALID_CBOR;

                    if (mk.type == BIO_CBOR_TSTR)
                    {
                        if (mk.tstr.len == 3 &&
                            memcmp(mk.tstr.data, "alg", 3) == 0)
                        {
                            bio_cbor_item_t av;
                            if (bio_cbor_decode_next(&dec, &av) != BIO_OK)
                                return CTAP2_ERR_INVALID_CBOR;
                            if (av.type == BIO_CBOR_NEGINT)
                                alg = (int32_t)av.int_val;
                            else if (av.type == BIO_CBOR_UINT)
                                alg = (int32_t)av.int_val;
                        }
                        else if (mk.tstr.len == 4 &&
                                 memcmp(mk.tstr.data, "type", 4) == 0)
                        {
                            bio_cbor_item_t tv;
                            if (bio_cbor_decode_next(&dec, &tv) != BIO_OK)
                                return CTAP2_ERR_INVALID_CBOR;
                            if (tv.type == BIO_CBOR_TSTR)
                            {
                                size_t cp = tv.tstr.len < 15 ? tv.tstr.len : 15;
                                memcpy(type, tv.tstr.data, cp);
                            }
                        }
                        else
                        {
                            bio_cbor_skip(&dec);
                        }
                    }
                    else
                    {
                        bio_cbor_skip(&dec);
                    }
                }

                if (alg == COSE_ALG_ES256 &&
                    strcmp(type, "public-key") == 0)
                {
                    params->es256_supported = true;
                }
            }
            has_alg = true;
            break;
        }
        case 0x05:
        { /* excludeList */
            uint64_t arr_cnt;
            if (bio_cbor_decode_array(&dec, &arr_cnt) != BIO_OK)
                return CTAP2_ERR_INVALID_CBOR;

            for (uint64_t j = 0; j < arr_cnt; j++)
            {
                uint64_t desc_cnt;
                if (bio_cbor_decode_map(&dec, &desc_cnt) != BIO_OK)
                    return CTAP2_ERR_INVALID_CBOR;

                if (params->exclude_count >= CTAP2_MAX_ALLOW_LIST)
                {
                    /* List full — skip remaining descriptor fields */
                    for (uint64_t k = 0; k < desc_cnt; k++)
                    {
                        bio_cbor_skip(&dec); /* key */
                        bio_cbor_skip(&dec); /* value */
                    }
                    continue;
                }

                for (uint64_t k = 0; k < desc_cnt; k++)
                {
                    bio_cbor_item_t dk;
                    if (bio_cbor_decode_next(&dec, &dk) != BIO_OK)
                        return CTAP2_ERR_INVALID_CBOR;

                    if (dk.type == BIO_CBOR_TSTR &&
                        dk.tstr.len == 2 &&
                        memcmp(dk.tstr.data, "id", 2) == 0)
                    {
                        bio_cbor_item_t dv;
                        if (bio_cbor_decode_next(&dec, &dv) != BIO_OK)
                            return CTAP2_ERR_INVALID_CBOR;
                        if (dv.type == BIO_CBOR_BSTR)
                        {
                            ctap2_credential_id_t *cid =
                                &params->exclude_list[params->exclude_count];
                            cid->id_len = dv.bstr.len < CTAP2_MAX_CREDENTIAL_ID_LEN
                                              ? dv.bstr.len
                                              : CTAP2_MAX_CREDENTIAL_ID_LEN;
                            memcpy(cid->id, dv.bstr.data, cid->id_len);
                            params->exclude_count++;
                        }
                    }
                    else
                    {
                        bio_cbor_skip(&dec);
                    }
                }
            }
            break;
        }
        case 0x06:
        { /* extensions (map) */
            uint64_t ext_cnt;
            if (bio_cbor_decode_map(&dec, &ext_cnt) != BIO_OK)
                return CTAP2_ERR_INVALID_CBOR;

            for (uint64_t j = 0; j < ext_cnt; j++)
            {
                bio_cbor_item_t ek;
                if (bio_cbor_decode_next(&dec, &ek) != BIO_OK)
                    return CTAP2_ERR_INVALID_CBOR;

                if (ek.type == BIO_CBOR_TSTR &&
                    ek.tstr.len == 11 &&
                    memcmp(ek.tstr.data, "credProtect", 11) == 0)
                {
                    uint64_t level;
                    if (bio_cbor_decode_uint(&dec, &level) != BIO_OK)
                        return CTAP2_ERR_INVALID_CBOR;
                    if (level < 1 || level > 3)
                        return CTAP2_ERR_INVALID_OPTION;
                    params->cred_protect = (uint8_t)level;
                }
                else if (ek.type == BIO_CBOR_TSTR &&
                         ek.tstr.len == 11 &&
                         memcmp(ek.tstr.data, "hmac-secret", 11) == 0)
                {
                    bool val = false;
                    if (bio_cbor_decode_bool(&dec, &val) != BIO_OK)
                        return CTAP2_ERR_INVALID_CBOR;
                    params->hmac_secret_requested = val;
                }
                else
                {
                    bio_cbor_skip(&dec);
                }
            }
            break;
        }
        case 0x07:
        { /* options */
            uint64_t opt_cnt;
            if (bio_cbor_decode_map(&dec, &opt_cnt) != BIO_OK)
                return CTAP2_ERR_INVALID_CBOR;

            for (uint64_t j = 0; j < opt_cnt; j++)
            {
                bio_cbor_item_t ok;
                if (bio_cbor_decode_next(&dec, &ok) != BIO_OK)
                    return CTAP2_ERR_INVALID_CBOR;

                if (ok.type == BIO_CBOR_TSTR)
                {
                    bool val = false;
                    bio_cbor_decode_bool(&dec, &val);

                    if (ok.tstr.len == 2 &&
                        memcmp(ok.tstr.data, "rk", 2) == 0)
                    {
                        params->rk_requested = val;
                    }
                    else if (ok.tstr.len == 2 &&
                             memcmp(ok.tstr.data, "uv", 2) == 0)
                    {
                        params->uv_requested = val;
                    }
                }
                else
                {
                    bio_cbor_skip(&dec);
                }
            }
            break;
        }
        case 0x08:
        { /* pinUvAuthParam */
            bio_cbor_item_t val;
            if (bio_cbor_decode_next(&dec, &val) != BIO_OK)
                return CTAP2_ERR_INVALID_CBOR;
            if (val.type != BIO_CBOR_BSTR || val.bstr.len < 16)
                return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
            size_t copy_len = val.bstr.len <= sizeof(params->pin_uv_auth_param)
                                  ? val.bstr.len
                                  : sizeof(params->pin_uv_auth_param);
            memcpy(params->pin_uv_auth_param, val.bstr.data, copy_len);
            params->pin_uv_auth_param_len = copy_len;
            params->has_pin_uv_auth_param = true;
            break;
        }
        case 0x09:
        { /* pinUvAuthProtocol (uint) */
            uint64_t proto;
            if (bio_cbor_decode_uint(&dec, &proto) != BIO_OK)
                return CTAP2_ERR_INVALID_CBOR;
            params->pin_uv_auth_protocol = (uint32_t)proto;
            break;
        }
        default:
            bio_cbor_skip(&dec);
            break;
        }
    }

    /* Validate mandatory parameters */
    if (!has_cdh)
        return CTAP2_ERR_MISSING_PARAMETER;
    if (!has_rp)
        return CTAP2_ERR_MISSING_PARAMETER;
    if (!has_user)
        return CTAP2_ERR_MISSING_PARAMETER;
    if (!has_alg)
        return CTAP2_ERR_MISSING_PARAMETER;
    if (!params->es256_supported)
        return CTAP2_ERR_UNSUPPORTED_ALGORITHM;

    return CTAP2_OK;
}

/* ── authenticatorMakeCredential (0x01) ──────────────────────── */

uint8_t ctap2_make_credential(bio_fido2_ctx_t *ctx,
                              const uint8_t *req, size_t req_len,
                              uint8_t *rsp, size_t *rsp_len)
{
    make_cred_params_t params;
    uint8_t rc = parse_make_cred_params(req, req_len, &params);
    if (rc != CTAP2_OK)
        return rc;

    /* Check exclude list — if any credential matches, deny */
    const uint8_t *wrap_key = bio_fido2_get_wrap_key();
    for (size_t i = 0; i < params.exclude_count; i++)
    {
        /* Check resident credentials */
        for (size_t j = 0; j < CTAP2_MAX_CREDENTIALS_STORED; j++)
        {
            if (!ctx->credentials[j].in_use)
                continue;
            if (memcmp(ctx->credentials[j].rp.id_hash,
                       params.rp.id_hash, 32) != 0)
                continue;
            if (ctx->credentials[j].cred_id.id_len == params.exclude_list[i].id_len &&
                memcmp(ctx->credentials[j].cred_id.id,
                       params.exclude_list[i].id,
                       params.exclude_list[i].id_len) == 0)
            {
                return CTAP2_ERR_CREDENTIAL_EXCLUDED;
            }
        }

        /* Check non-resident by trying to unwrap (requires valid wrap key) */
        if (wrap_key)
        {
            uint8_t privkey[32];
            bio_mlock_sensitive(privkey, sizeof(privkey));
            int uw_rc = unwrap_credential_id(&params.exclude_list[i],
                                             wrap_key,
                                             params.rp.id_hash,
                                             privkey);
            bio_secure_wipe(privkey, 32);
            bio_munlock_sensitive(privkey, sizeof(privkey));
            if (uw_rc == CTAP2_OK)
            {
                return CTAP2_ERR_CREDENTIAL_EXCLUDED;
            }
        }
    }

    /* User verification: PIN/UV auth token or biometric (CTAP2 §6.1) */
    bool uv_performed = false;
    if (params.has_pin_uv_auth_param)
    {
        if (!ctx->pin.pin_token_valid)
            return CTAP2_ERR_PIN_AUTH_INVALID;

        if (ctx->pin.pin_token_permissions != 0 &&
            (ctx->pin.pin_token_permissions & CTAP2_PIN_PERM_MAKE_CREDENTIAL) == 0)
        {
            return CTAP2_ERR_PIN_AUTH_INVALID;
        }
        if (ctx->pin.pin_token_rp_id_set &&
            strcmp(ctx->pin.pin_token_rp_id, params.rp.id) != 0)
        {
            return CTAP2_ERR_PIN_AUTH_INVALID;
        }

        if (params.pin_uv_auth_protocol == 2)
        {
            /* Protocol 2: HMAC(pinToken, 0x01 || clientDataHash), full 32 bytes. */
            uint8_t msg[33];
            msg[0] = 0x01;
            memcpy(msg + 1, params.client_data_hash, 32);

            uint8_t expected[32];
            bio_hmac_sha256(ctx->pin.pin_token, CTAP2_PIN_TOKEN_SIZE,
                            msg, sizeof(msg), expected);
            bio_secure_wipe(msg, sizeof(msg));

            if (params.pin_uv_auth_param_len < 32 ||
                bio_constant_time_compare(expected,
                                          params.pin_uv_auth_param, 32) != 0)
            {
                bio_secure_wipe(expected, 32);
                return CTAP2_ERR_PIN_AUTH_INVALID;
            }
            bio_secure_wipe(expected, 32);
        }
        else if (params.pin_uv_auth_protocol == 1)
        {
            /* Protocol 1: left(HMAC-SHA-256(pinToken, clientDataHash), 16). */
            uint8_t expected[32];
            bio_hmac_sha256(ctx->pin.pin_token, CTAP2_PIN_TOKEN_SIZE,
                            params.client_data_hash, 32, expected);

            if (bio_constant_time_compare(expected,
                                          params.pin_uv_auth_param, 16) != 0)
            {
                bio_secure_wipe(expected, 32);
                return CTAP2_ERR_PIN_AUTH_INVALID;
            }
            bio_secure_wipe(expected, 32);
        }
        else
        {
            return CTAP2_ERR_PIN_AUTH_INVALID;
        }
        uv_performed = true;
    }
    else if (ctx->verify_user)
    {
        if (!ctx->verify_user(ctx->verify_user_ctx))
            return CTAP2_ERR_OPERATION_DENIED;
        uv_performed = true;
    }

    /* Generate new credential key pair */
    bio_ecdsa_keypair kp;
    if (bio_ecdsa_keygen(&kp) != BIO_OK)
        return CTAP2_ERR_OTHER;

    /* Generate credential ID (requires valid wrap key) */
    const uint8_t *cred_wrap_key = bio_fido2_get_wrap_key();
    if (!cred_wrap_key)
    {
        bio_secure_wipe(&kp, sizeof(kp));
        BIO_ERROR("FIDO2: no wrap key available for credential generation");
        return CTAP2_ERR_OTHER;
    }

    ctap2_credential_id_t cred_id;
    if (generate_credential_id(&cred_id, kp.private_key,
                               params.rp.id_hash, cred_wrap_key) != BIO_OK)
    {
        bio_secure_wipe(&kp, sizeof(kp));
        return CTAP2_ERR_OTHER;
    }

    bool has_hmac_secret = false;
    uint8_t hmac_secret[32];
    if (params.hmac_secret_requested)
    {
        if (bio_random_bytes(hmac_secret, sizeof(hmac_secret)) != BIO_OK)
        {
            bio_secure_wipe(&kp, sizeof(kp));
            return CTAP2_ERR_OTHER;
        }
        has_hmac_secret = true;
    }

    /* Increment sign count */
    ctx->global_sign_count++;

    /* Build authenticator data */
    uint8_t auth_data[512];
    size_t auth_data_len = sizeof(auth_data);
    uint8_t flags = CTAP2_FLAG_UP | CTAP2_FLAG_AT;
    if (uv_performed)
        flags |= CTAP2_FLAG_UV;
    if (params.cred_protect || has_hmac_secret)
        flags |= CTAP2_FLAG_ED;

    int ad_rc = build_auth_data(auth_data, &auth_data_len,
                                params.rp.id_hash, flags,
                                ctx->global_sign_count,
                                &cred_id, kp.public_key);
    if (ad_rc != BIO_OK)
    {
        bio_secure_wipe(&kp, sizeof(kp));
        return CTAP2_ERR_OTHER;
    }

    /* Append extension output to authData (CTAP2.1 §12.4) */
    if (params.cred_protect || has_hmac_secret)
    {
        bio_cbor_encoder_t ext_enc;
        bio_cbor_encoder_init(&ext_enc, auth_data + auth_data_len,
                              sizeof(auth_data) - auth_data_len);
        int ext_map_count = 0;
        if (params.cred_protect)
            ext_map_count++;
        if (has_hmac_secret)
            ext_map_count++;
        bio_cbor_encode_map(&ext_enc, ext_map_count);
        if (params.cred_protect)
        {
            bio_cbor_encode_tstr_z(&ext_enc, "credProtect");
            bio_cbor_encode_uint(&ext_enc, params.cred_protect);
        }
        if (has_hmac_secret)
        {
            /* hmac-secret extension output in MakeCredential = true (§12.5) */
            bio_cbor_encode_tstr_z(&ext_enc, "hmac-secret");
            bio_cbor_encode_bool(&ext_enc, true);
        }
        if (ext_enc.error)
        {
            bio_secure_wipe(&kp, sizeof(kp));
            return CTAP2_ERR_OTHER;
        }
        auth_data_len += ext_enc.offset;
    }

    /* Sign auth_data || clientDataHash with the new credential key */
    uint8_t sign_input[512 + 32];
    memcpy(sign_input, auth_data, auth_data_len);
    memcpy(sign_input + auth_data_len, params.client_data_hash, 32);

    uint8_t sig_hash[32];
    bio_sha256(sign_input, auth_data_len + 32, sig_hash);
    bio_secure_wipe(sign_input, sizeof(sign_input));

    uint8_t signature[64];
    if (bio_ecdsa_sign_raw(kp.private_key, sig_hash,
                           signature) != BIO_OK)
    {
        bio_secure_wipe(sig_hash, sizeof(sig_hash));
        bio_secure_wipe(&kp, sizeof(kp));
        return CTAP2_ERR_OTHER;
    }
    bio_secure_wipe(sig_hash, sizeof(sig_hash));

    /* If resident key requested, store credential */
    if (params.rk_requested)
    {
        size_t slot = CTAP2_MAX_CREDENTIALS_STORED;

        /* Check for existing credential for same rp+user */
        for (size_t i = 0; i < CTAP2_MAX_CREDENTIALS_STORED; i++)
        {
            if (ctx->credentials[i].in_use &&
                memcmp(ctx->credentials[i].rp.id_hash,
                       params.rp.id_hash, 32) == 0 &&
                ctx->credentials[i].user.id_len == params.user.id_len &&
                memcmp(ctx->credentials[i].user.id,
                       params.user.id, params.user.id_len) == 0)
            {
                slot = i;
                break;
            }
        }

        /* Find free slot if not replacing */
        if (slot == CTAP2_MAX_CREDENTIALS_STORED)
        {
            for (size_t i = 0; i < CTAP2_MAX_CREDENTIALS_STORED; i++)
            {
                if (!ctx->credentials[i].in_use)
                {
                    slot = i;
                    break;
                }
            }
        }

        if (slot == CTAP2_MAX_CREDENTIALS_STORED)
        {
            bio_secure_wipe(&kp, sizeof(kp));
            return CTAP2_ERR_KEY_STORE_FULL;
        }

        ctap2_credential_t *cred = &ctx->credentials[slot];
        bool was_in_use = cred->in_use;
        memset(cred, 0, sizeof(*cred));
        cred->in_use = true;
        cred->rp = params.rp;
        cred->user = params.user;
        cred->cred_id = cred_id;
        memcpy(cred->private_key, kp.private_key, 32);
        memcpy(cred->public_key, kp.public_key, 65);
        cred->sign_count = ctx->global_sign_count;
        cred->created = (uint64_t)time(NULL);
        cred->resident = true;
        cred->cred_protect = params.cred_protect ? params.cred_protect : 1;
        if (has_hmac_secret)
        {
            memcpy(cred->hmac_secret, hmac_secret, sizeof(hmac_secret));
            cred->has_hmac_secret = true;
        }

        if (!was_in_use)
        {
            ctx->credential_count++;
        }

        /* Persist resident credential — failure means data loss on restart */
        if (bio_fido2_save_credentials(ctx) != BIO_OK)
        {
            BIO_ERROR("FIDO2: failed to persist resident credential");
            cred->in_use = false;
            if (!was_in_use)
                ctx->credential_count--;
            bio_secure_wipe(&kp, sizeof(kp));
            return CTAP2_ERR_OTHER;
        }
    }

    bio_secure_wipe(&kp, sizeof(kp));
    if (has_hmac_secret)
    {
        bio_secure_wipe(hmac_secret, sizeof(hmac_secret));
    }

    /* Build response CBOR map */
    bio_cbor_encoder_t enc;
    bio_cbor_encoder_init(&enc, rsp, *rsp_len);

    bio_cbor_encode_map(&enc, 3);

    /* 0x01: fmt - "packed" attestation */
    bio_cbor_encode_uint(&enc, 0x01);
    bio_cbor_encode_tstr_z(&enc, "packed");

    /* 0x02: authData */
    bio_cbor_encode_uint(&enc, 0x02);
    bio_cbor_encode_bstr(&enc, auth_data, auth_data_len);

    /* 0x03: attStmt - self attestation */
    bio_cbor_encode_uint(&enc, 0x03);
    bio_cbor_encode_map(&enc, 2);

    /* attStmt.alg */
    bio_cbor_encode_tstr_z(&enc, "alg");
    bio_cbor_encode_negint(&enc, 6); /* -7 (ES256) */

    /* attStmt.sig - DER-encoded ECDSA signature per FIDO2 packed attestation */
    bio_cbor_encode_tstr_z(&enc, "sig");
    uint8_t der_sig[72];
    size_t der_len = ecdsa_sig_to_der(signature, der_sig, sizeof(der_sig));
    if (der_len == 0)
        return CTAP2_ERR_OTHER;
    bio_cbor_encode_bstr(&enc, der_sig, der_len);

    bio_secure_wipe(der_sig, sizeof(der_sig));
    bio_secure_wipe(signature, sizeof(signature));
    bio_secure_wipe(auth_data, auth_data_len);

    if (enc.error)
        return CTAP2_ERR_OTHER;

    *rsp_len = enc.offset;
    return CTAP2_OK;
}

/* ── authenticatorGetAssertion (0x02) ────────────────────────── */

/*
 * Parse GetAssertion request:
 *   0x01: rpId (string)
 *   0x02: clientDataHash (bstr, 32)
 *   0x03: allowList (array of credential descriptors) [optional]
 *   0x05: options (map) [optional]
 */
typedef struct
{
    uint8_t client_data_hash[32];
    uint8_t rp_id_hash[32];
    char rp_id[CTAP2_MAX_RP_ID_LEN];
    bool uv_requested;
    bool up_requested;

    ctap2_credential_id_t allow_list[CTAP2_MAX_ALLOW_LIST];
    size_t allow_count;

    /* PIN/UV auth (CTAP2 §6.2 keys 0x06, 0x07) */
    uint8_t pin_uv_auth_param[32];
    size_t pin_uv_auth_param_len;
    bool has_pin_uv_auth_param;
    uint32_t pin_uv_auth_protocol;
} get_assertion_params_t;

static uint8_t parse_get_assertion_params(const uint8_t *req, size_t req_len,
                                          get_assertion_params_t *params)
{
    memset(params, 0, sizeof(*params));
    params->up_requested = true; /* Default: user presence required */

    bio_cbor_decoder_t dec;
    bio_cbor_decoder_init(&dec, req, req_len);

    uint64_t map_cnt;
    if (bio_cbor_decode_map(&dec, &map_cnt) != BIO_OK)
        return CTAP2_ERR_INVALID_CBOR;

    bool has_rp = false, has_cdh = false;

    for (uint64_t i = 0; i < map_cnt; i++)
    {
        uint64_t key;
        if (bio_cbor_decode_uint(&dec, &key) != BIO_OK)
            return CTAP2_ERR_INVALID_CBOR;

        switch (key)
        {
        case 0x01:
        { /* rpId */
            bio_cbor_item_t val;
            if (bio_cbor_decode_next(&dec, &val) != BIO_OK)
                return CTAP2_ERR_INVALID_CBOR;
            if (val.type != BIO_CBOR_TSTR)
                return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
            size_t copy = val.tstr.len < sizeof(params->rp_id) - 1
                              ? val.tstr.len
                              : sizeof(params->rp_id) - 1;
            memcpy(params->rp_id, val.tstr.data, copy);
            params->rp_id[copy] = '\0';
            bio_sha256((const uint8_t *)params->rp_id, copy, params->rp_id_hash);
            has_rp = true;
            break;
        }
        case 0x02:
        { /* clientDataHash */
            bio_cbor_item_t val;
            if (bio_cbor_decode_next(&dec, &val) != BIO_OK)
                return CTAP2_ERR_INVALID_CBOR;
            if (val.type != BIO_CBOR_BSTR || val.bstr.len != 32)
                return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
            memcpy(params->client_data_hash, val.bstr.data, 32);
            has_cdh = true;
            break;
        }
        case 0x03:
        { /* allowList */
            uint64_t arr_cnt;
            if (bio_cbor_decode_array(&dec, &arr_cnt) != BIO_OK)
                return CTAP2_ERR_INVALID_CBOR;

            for (uint64_t j = 0; j < arr_cnt; j++)
            {
                uint64_t desc_cnt;
                if (bio_cbor_decode_map(&dec, &desc_cnt) != BIO_OK)
                    return CTAP2_ERR_INVALID_CBOR;

                if (params->allow_count >= CTAP2_MAX_ALLOW_LIST)
                {
                    /* List full — skip remaining descriptor fields */
                    for (uint64_t k = 0; k < desc_cnt; k++)
                    {
                        bio_cbor_skip(&dec); /* key */
                        bio_cbor_skip(&dec); /* value */
                    }
                    continue;
                }

                for (uint64_t k = 0; k < desc_cnt; k++)
                {
                    bio_cbor_item_t dk;
                    if (bio_cbor_decode_next(&dec, &dk) != BIO_OK)
                        return CTAP2_ERR_INVALID_CBOR;

                    if (dk.type == BIO_CBOR_TSTR &&
                        dk.tstr.len == 2 &&
                        memcmp(dk.tstr.data, "id", 2) == 0)
                    {
                        bio_cbor_item_t dv;
                        if (bio_cbor_decode_next(&dec, &dv) != BIO_OK)
                            return CTAP2_ERR_INVALID_CBOR;
                        if (dv.type == BIO_CBOR_BSTR)
                        {
                            ctap2_credential_id_t *cid =
                                &params->allow_list[params->allow_count];
                            cid->id_len = dv.bstr.len < CTAP2_MAX_CREDENTIAL_ID_LEN
                                              ? dv.bstr.len
                                              : CTAP2_MAX_CREDENTIAL_ID_LEN;
                            memcpy(cid->id, dv.bstr.data, cid->id_len);
                            params->allow_count++;
                        }
                    }
                    else
                    {
                        bio_cbor_skip(&dec);
                    }
                }
            }
            break;
        }
        case 0x05:
        { /* options */
            uint64_t opt_cnt;
            if (bio_cbor_decode_map(&dec, &opt_cnt) != BIO_OK)
                return CTAP2_ERR_INVALID_CBOR;

            for (uint64_t j = 0; j < opt_cnt; j++)
            {
                bio_cbor_item_t ok;
                if (bio_cbor_decode_next(&dec, &ok) != BIO_OK)
                    return CTAP2_ERR_INVALID_CBOR;

                if (ok.type == BIO_CBOR_TSTR)
                {
                    bool val = false;
                    bio_cbor_decode_bool(&dec, &val);

                    if (ok.tstr.len == 2 &&
                        memcmp(ok.tstr.data, "uv", 2) == 0)
                    {
                        params->uv_requested = val;
                    }
                    else if (ok.tstr.len == 2 &&
                             memcmp(ok.tstr.data, "up", 2) == 0)
                    {
                        params->up_requested = val;
                    }
                }
                else
                {
                    bio_cbor_skip(&dec);
                }
            }
            break;
        }
        case 0x06:
        { /* pinUvAuthParam */
            bio_cbor_item_t val;
            if (bio_cbor_decode_next(&dec, &val) != BIO_OK)
                return CTAP2_ERR_INVALID_CBOR;
            if (val.type != BIO_CBOR_BSTR || val.bstr.len < 16)
                return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
            size_t copy_len = val.bstr.len <= sizeof(params->pin_uv_auth_param)
                                  ? val.bstr.len
                                  : sizeof(params->pin_uv_auth_param);
            memcpy(params->pin_uv_auth_param, val.bstr.data, copy_len);
            params->pin_uv_auth_param_len = copy_len;
            params->has_pin_uv_auth_param = true;
            break;
        }
        case 0x07:
        { /* pinUvAuthProtocol (uint) */
            uint64_t proto;
            if (bio_cbor_decode_uint(&dec, &proto) != BIO_OK)
                return CTAP2_ERR_INVALID_CBOR;
            params->pin_uv_auth_protocol = (uint32_t)proto;
            break;
        }
        default:
            bio_cbor_skip(&dec);
            break;
        }
    }

    if (!has_rp)
        return CTAP2_ERR_MISSING_PARAMETER;
    if (!has_cdh)
        return CTAP2_ERR_MISSING_PARAMETER;

    return CTAP2_OK;
}

/*
 * Build a single assertion response.
 */
static uint8_t build_assertion_response(bio_fido2_ctx_t *ctx,
                                        ctap2_credential_t *cred,
                                        const uint8_t *privkey,
                                        const ctap2_credential_id_t *cred_id,
                                        const uint8_t rp_id_hash[32],
                                        const uint8_t client_data_hash[32],
                                        uint8_t flags,
                                        size_t total_creds,
                                        bool include_user,
                                        uint8_t *rsp, size_t *rsp_len)
{
    /* Per-credential sign counter (CTAP2 spec compliance):
     * Use the credential's own counter for resident keys,
     * fall back to global counter for non-resident credentials.
     * Snapshot before increment; roll back on encode failure. */
    uint32_t sign_count;
    uint32_t saved_sign_count;
    if (cred)
    {
        /* Resident credential — use and increment per-credential counter. */
        saved_sign_count = cred->sign_count;
        cred->sign_count++;
        sign_count = cred->sign_count;
    }
    else
    {
        /* Non-resident credential — use global counter */
        saved_sign_count = ctx->global_sign_count;
        ctx->global_sign_count++;
        sign_count = ctx->global_sign_count;
    }

    /* Build authData (no attested cred data for assertions) */
    uint8_t auth_data[256];
    size_t auth_data_len = sizeof(auth_data);
    int ad_rc = build_auth_data(auth_data, &auth_data_len,
                                rp_id_hash, flags,
                                sign_count,
                                NULL, NULL);
    if (ad_rc != BIO_OK)
        return CTAP2_ERR_OTHER;

    /* Sign authData || clientDataHash */
    uint8_t sign_input[256 + 32];
    memcpy(sign_input, auth_data, auth_data_len);
    memcpy(sign_input + auth_data_len, client_data_hash, 32);

    uint8_t sig_hash[32];
    bio_sha256(sign_input, auth_data_len + 32, sig_hash);
    bio_secure_wipe(sign_input, sizeof(sign_input));

    uint8_t signature[64];
    if (bio_ecdsa_sign_raw(privkey, sig_hash,
                           signature) != BIO_OK)
    {
        bio_secure_wipe(sig_hash, sizeof(sig_hash));
        return CTAP2_ERR_OTHER;
    }
    bio_secure_wipe(sig_hash, sizeof(sig_hash));

    /* Build response CBOR */
    int map_entries = 3; /* credential, authData, signature */
    if (include_user)
        map_entries++;
    if (total_creds > 1)
        map_entries++;

    bio_cbor_encoder_t enc;
    bio_cbor_encoder_init(&enc, rsp, *rsp_len);
    bio_cbor_encode_map(&enc, map_entries);

    /* 0x01: credential (PublicKeyCredentialDescriptor) */
    bio_cbor_encode_uint(&enc, 0x01);
    bio_cbor_encode_map(&enc, 2);
    bio_cbor_encode_tstr_z(&enc, "id");
    bio_cbor_encode_bstr(&enc, cred_id->id, cred_id->id_len);
    bio_cbor_encode_tstr_z(&enc, "type");
    bio_cbor_encode_tstr_z(&enc, "public-key");

    /* 0x02: authData */
    bio_cbor_encode_uint(&enc, 0x02);
    bio_cbor_encode_bstr(&enc, auth_data, auth_data_len);

    /* 0x03: signature (DER-encoded ECDSA) */
    bio_cbor_encode_uint(&enc, 0x03);
    uint8_t der_sig[72];
    size_t der_len = ecdsa_sig_to_der(signature, der_sig, sizeof(der_sig));
    if (der_len == 0)
        return CTAP2_ERR_OTHER;
    bio_cbor_encode_bstr(&enc, der_sig, der_len);

    bio_secure_wipe(der_sig, sizeof(der_sig));
    bio_secure_wipe(signature, sizeof(signature));
    bio_secure_wipe(auth_data, auth_data_len);

    /* 0x04: user (for resident credentials and multiple matches) */
    if (include_user && cred)
    {
        bio_cbor_encode_uint(&enc, 0x04);
        bio_cbor_encode_map(&enc, 3);

        bio_cbor_encode_tstr_z(&enc, "id");
        bio_cbor_encode_bstr(&enc, cred->user.id, cred->user.id_len);

        bio_cbor_encode_tstr_z(&enc, "name");
        bio_cbor_encode_tstr_z(&enc, cred->user.name);

        bio_cbor_encode_tstr_z(&enc, "displayName");
        bio_cbor_encode_tstr_z(&enc, cred->user.display_name);
    }

    /* 0x05: numberOfCredentials */
    if (total_creds > 1)
    {
        bio_cbor_encode_uint(&enc, 0x05);
        bio_cbor_encode_uint(&enc, total_creds);
    }

    if (enc.error)
    {
        /* Roll back sign counter on encode failure */
        if (cred)
            cred->sign_count = saved_sign_count;
        else
            ctx->global_sign_count = saved_sign_count;
        return CTAP2_ERR_OTHER;
    }

    *rsp_len = enc.offset;
    return CTAP2_OK;
}

uint8_t ctap2_get_assertion(bio_fido2_ctx_t *ctx,
                            const uint8_t *req, size_t req_len,
                            uint8_t *rsp, size_t *rsp_len)
{
    get_assertion_params_t params;
    uint8_t rc = parse_get_assertion_params(req, req_len, &params);
    if (rc != CTAP2_OK)
        return rc;

    /* User verification: PIN/UV auth token or biometric (CTAP2 §6.2) */
    bool uv_performed = false;
    if (params.has_pin_uv_auth_param)
    {
        if (!ctx->pin.pin_token_valid)
            return CTAP2_ERR_PIN_AUTH_INVALID;

        if (ctx->pin.pin_token_permissions != 0 &&
            (ctx->pin.pin_token_permissions & CTAP2_PIN_PERM_GET_ASSERTION) == 0)
        {
            return CTAP2_ERR_PIN_AUTH_INVALID;
        }
        if (ctx->pin.pin_token_rp_id_set &&
            strcmp(ctx->pin.pin_token_rp_id, params.rp_id) != 0)
        {
            return CTAP2_ERR_PIN_AUTH_INVALID;
        }

        if (params.pin_uv_auth_protocol == 2)
        {
            /* Protocol 2: HMAC(pinToken, 0x03 || rpIdHash || clientDataHash), full 32 bytes. */
            uint8_t msg[65];
            msg[0] = 0x03;
            memcpy(msg + 1, params.rp_id_hash, 32);
            memcpy(msg + 33, params.client_data_hash, 32);

            uint8_t expected[32];
            bio_hmac_sha256(ctx->pin.pin_token, CTAP2_PIN_TOKEN_SIZE,
                            msg, sizeof(msg), expected);
            bio_secure_wipe(msg, sizeof(msg));

            if (params.pin_uv_auth_param_len < 32 ||
                bio_constant_time_compare(expected,
                                          params.pin_uv_auth_param, 32) != 0)
            {
                bio_secure_wipe(expected, 32);
                return CTAP2_ERR_PIN_AUTH_INVALID;
            }
            bio_secure_wipe(expected, 32);
        }
        else if (params.pin_uv_auth_protocol == 1)
        {
            /* Protocol 1: left(HMAC-SHA-256(pinToken, clientDataHash), 16). */
            uint8_t expected[32];
            bio_hmac_sha256(ctx->pin.pin_token, CTAP2_PIN_TOKEN_SIZE,
                            params.client_data_hash, 32, expected);

            if (bio_constant_time_compare(expected,
                                          params.pin_uv_auth_param, 16) != 0)
            {
                bio_secure_wipe(expected, 32);
                return CTAP2_ERR_PIN_AUTH_INVALID;
            }
            bio_secure_wipe(expected, 32);
        }
        else
        {
            return CTAP2_ERR_PIN_AUTH_INVALID;
        }
        uv_performed = true;
    }
    else if (ctx->verify_user)
    {
        if (!ctx->verify_user(ctx->verify_user_ctx))
            return CTAP2_ERR_OPERATION_DENIED;
        uv_performed = true;
    }

    /* Collect matching credentials */
    ctx->assertion_match_count = 0;
    ctx->assertion_index = 0;
    memcpy(ctx->assertion_client_data_hash, params.client_data_hash, 32);
    memcpy(ctx->assertion_rp_id_hash, params.rp_id_hash, 32);
    ctx->assertion_flags = CTAP2_FLAG_UP;
    if (uv_performed)
        ctx->assertion_flags |= CTAP2_FLAG_UV;

    /* Record assertion timestamp for GetNextAssertion timeout (CTAP2 §6.2.2) */
    {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        ctx->assertion_timestamp = (uint64_t)ts.tv_sec;
    }

    if (params.allow_count > 0)
    {
        /* Check allow list — try to find matching credentials */
        for (size_t i = 0; i < params.allow_count; i++)
        {
            /* Check resident credentials */
            for (size_t j = 0; j < CTAP2_MAX_CREDENTIALS_STORED; j++)
            {
                if (!ctx->credentials[j].in_use)
                    continue;
                /* Verify RP ID hash matches — prevents cross-RP credential use */
                if (memcmp(ctx->credentials[j].rp.id_hash,
                           params.rp_id_hash, 32) != 0)
                    continue;
                if (ctx->credentials[j].cred_id.id_len == params.allow_list[i].id_len &&
                    memcmp(ctx->credentials[j].cred_id.id,
                           params.allow_list[i].id,
                           params.allow_list[i].id_len) == 0)
                {
                    /* credProtect level 3: require UV even with allowList */
                    if (ctx->credentials[j].cred_protect >= 3 && !uv_performed)
                        continue;
                    if (ctx->assertion_match_count < CTAP2_MAX_CREDENTIALS_STORED)
                    {
                        ctx->assertion_matches[ctx->assertion_match_count++] =
                            &ctx->credentials[j];
                    }
                }
            }

            /* Try unwrapping as non-resident credential */
            {
                const uint8_t *wrap_key = bio_fido2_get_wrap_key();
                if (!wrap_key)
                {
                    BIO_WARN("getAssertion: wrap key not available, "
                             "cannot unwrap non-resident credentials");
                }
                else
                {
                    uint8_t privkey[32];
                    bio_mlock_sensitive(privkey, sizeof(privkey));
                    int uw_rc = unwrap_credential_id(&params.allow_list[i],
                                                     wrap_key,
                                                     params.rp_id_hash,
                                                     privkey);
                    if (uw_rc == CTAP2_OK)
                    {
                        /* Non-resident credential — sign directly.
                         * Clear assertion state to prevent GetNextAssertion
                         * from leaking resident credentials. */
                        ctx->assertion_match_count = 0;
                        ctx->assertion_index = 0;
                        rc = build_assertion_response(
                            ctx, NULL, privkey, &params.allow_list[i],
                            params.rp_id_hash, params.client_data_hash,
                            ctx->assertion_flags, 1, false, rsp, rsp_len);
                        bio_secure_wipe(privkey, 32);
                        bio_munlock_sensitive(privkey, sizeof(privkey));
                        /* Persist updated global sign counter */
                        if (rc == CTAP2_OK)
                        {
                            if (bio_fido2_save_credentials(ctx) != BIO_OK)
                            {
                                BIO_WARN("FIDO2: failed to persist sign counter");
                            }
                        }
                        return rc;
                    }
                    bio_secure_wipe(privkey, 32);
                    bio_munlock_sensitive(privkey, sizeof(privkey));
                }
            }
        }
    }
    else
    {
        /* No allow list — search all resident credentials for this RP */
        for (size_t j = 0; j < CTAP2_MAX_CREDENTIALS_STORED; j++)
        {
            if (!ctx->credentials[j].in_use)
                continue;
            if (memcmp(ctx->credentials[j].rp.id_hash,
                       params.rp_id_hash, 32) == 0)
            {
                /* credProtect enforcement (CTAP2.1 §12.4):
                 * Level 3: MUST NOT be discoverable without allowList
                 * Level 2: MUST NOT be discoverable without UV */
                if (ctx->credentials[j].cred_protect >= 3)
                    continue;
                if (ctx->credentials[j].cred_protect >= 2 && !uv_performed)
                    continue;
                if (ctx->assertion_match_count < CTAP2_MAX_CREDENTIALS_STORED)
                {
                    ctx->assertion_matches[ctx->assertion_match_count++] =
                        &ctx->credentials[j];
                }
            }
        }
    }

    if (ctx->assertion_match_count == 0)
    {
        return CTAP2_ERR_NO_CREDENTIALS;
    }

    /* Return first match */
    ctap2_credential_t *first = ctx->assertion_matches[0];
    ctx->assertion_index = 1;

    uint8_t result = build_assertion_response(
        ctx, first, first->private_key, &first->cred_id,
        params.rp_id_hash, params.client_data_hash,
        ctx->assertion_flags, ctx->assertion_match_count,
        (ctx->assertion_match_count > 1), rsp, rsp_len);

    /* Persist updated sign counter (CTAP2 §6.2.1) */
    if (result == CTAP2_OK)
    {
        if (bio_fido2_save_credentials(ctx) != BIO_OK)
        {
            BIO_WARN("FIDO2: failed to persist sign counter (resident assertion)");
        }
    }

    return result;
}

/* ── authenticatorGetNextAssertion (0x08) ────────────────────── */

uint8_t ctap2_get_next_assertion(bio_fido2_ctx_t *ctx,
                                 uint8_t *rsp, size_t *rsp_len)
{
    /* CTAP2 §6.2.2: GetNextAssertion valid only within 30 seconds */
    {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        uint64_t now = (uint64_t)ts.tv_sec;
        if (now - ctx->assertion_timestamp > 30)
        {
            ctx->assertion_match_count = 0;
            ctx->assertion_index = 0;
            return CTAP2_ERR_NOT_ALLOWED;
        }
    }

    if (ctx->assertion_index >= ctx->assertion_match_count)
    {
        return CTAP2_ERR_NO_CREDENTIALS;
    }

    ctap2_credential_t *cred = ctx->assertion_matches[ctx->assertion_index];
    ctx->assertion_index++;

    uint8_t result = build_assertion_response(
        ctx, cred, cred->private_key, &cred->cred_id,
        ctx->assertion_rp_id_hash, ctx->assertion_client_data_hash,
        ctx->assertion_flags, ctx->assertion_match_count,
        true, rsp, rsp_len);

    /* Persist updated sign counter (CTAP2 §6.2.1) */
    if (result == CTAP2_OK)
    {
        if (bio_fido2_save_credentials(ctx) != BIO_OK)
        {
            BIO_WARN("FIDO2: failed to persist sign counter (next assertion)");
        }
    }

    return result;
}
