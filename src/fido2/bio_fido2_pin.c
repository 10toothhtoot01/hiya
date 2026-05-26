/*
 * bio_fido2_pin.c — CTAP2 ClientPIN + Reset + Selection + Credential Storage
 *
 * Copyright (C) 2024 Hiya Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Implements:
 *   0x06 authenticatorClientPIN (subcommands 1-5)
 *   0x07 authenticatorReset
 *   0x0B authenticatorSelection
 *   Credential persistence (save/load)
 */

#include "fido2/bio_fido2.h"
#include "cbor/bio_cbor.h"
#include "crypto/bio_crypto.h"

#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include <inttypes.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>

/* ── authenticatorClientPIN (0x06) ───────────────────────────── */

/*
 * ClientPIN subcommands:
 *   0x01: getRetries
 *   0x02: getKeyAgreement
 *   0x03: setPIN
 *   0x04: changePIN
 *   0x05: getPinToken
 */

/* PIN subcommand codes */
#define PIN_SUBCMD_GET_RETRIES 0x01
#define PIN_SUBCMD_GET_KEY_AGREEMENT 0x02
#define PIN_SUBCMD_SET_PIN 0x03
#define PIN_SUBCMD_CHANGE_PIN 0x04
#define PIN_SUBCMD_GET_PIN_TOKEN 0x05
#define PIN_SUBCMD_GET_UV_TOKEN_PERM 0x06 /* getPinUvAuthTokenUsingUvWithPermissions */
#define PIN_SUBCMD_GET_UV_RETRIES 0x07
#define PIN_SUBCMD_SET_MIN_PIN_LEN 0x08
#define PIN_SUBCMD_GET_PIN_TOKEN_PERM 0x09 /* getPinUvAuthTokenUsingPinWithPermissions */

/* Runtime min PIN length policy (CTAP2.1 setMinPINLength). */
static uint32_t g_min_pin_length = 4;

typedef struct
{
    uint32_t sub_command;
    uint8_t key_agreement_x[32];
    uint8_t key_agreement_y[32];
    bool has_key_agreement;
    uint8_t pin_uv_auth_param[32];
    size_t pin_uv_auth_param_len;
    bool has_pin_uv_auth_param;
    uint8_t new_pin_enc[256];
    size_t new_pin_enc_len;
    uint8_t pin_hash_enc[64];
    size_t pin_hash_enc_len;
    uint32_t pin_protocol;
    uint32_t permissions; /* 0x09: permissions bitmask */
    bool has_permissions;
    char rp_id[256]; /* 0x0A: rpId (optional) */
    size_t rp_id_len;
    uint32_t new_min_pin_length; /* 0x0B: newMinPINLength */
    bool has_new_min_pin_length;
} client_pin_params_t;

static uint8_t parse_client_pin_params(const uint8_t *req, size_t req_len,
                                       client_pin_params_t *params)
{
    memset(params, 0, sizeof(*params));
    params->pin_protocol = 1; /* Default */

    bio_cbor_decoder_t dec;
    bio_cbor_decoder_init(&dec, req, req_len);

    uint64_t map_cnt;
    if (bio_cbor_decode_map(&dec, &map_cnt) != BIO_OK)
        return CTAP2_ERR_INVALID_CBOR;

    for (uint64_t i = 0; i < map_cnt; i++)
    {
        uint64_t key;
        if (bio_cbor_decode_uint(&dec, &key) != BIO_OK)
            return CTAP2_ERR_INVALID_CBOR;

        switch (key)
        {
        case 0x01:
        { /* pinProtocol */
            uint64_t v;
            if (bio_cbor_decode_uint(&dec, &v) != BIO_OK)
                return CTAP2_ERR_INVALID_CBOR;
            params->pin_protocol = (uint32_t)v;
            break;
        }
        case 0x02:
        { /* subCommand */
            uint64_t v;
            if (bio_cbor_decode_uint(&dec, &v) != BIO_OK)
                return CTAP2_ERR_INVALID_CBOR;
            params->sub_command = (uint32_t)v;
            break;
        }
        case 0x03:
        { /* keyAgreement (COSE_Key) */
            uint64_t km_cnt;
            if (bio_cbor_decode_map(&dec, &km_cnt) != BIO_OK)
                return CTAP2_ERR_INVALID_CBOR;

            for (uint64_t j = 0; j < km_cnt; j++)
            {
                bio_cbor_item_t mk;
                if (bio_cbor_decode_next(&dec, &mk) != BIO_OK)
                    return CTAP2_ERR_INVALID_CBOR;

                /* -2 → x, -3 → y */
                if (mk.type == BIO_CBOR_NEGINT)
                {
                    bio_cbor_item_t mv;
                    if (bio_cbor_decode_next(&dec, &mv) != BIO_OK)
                        return CTAP2_ERR_INVALID_CBOR;

                    if (mk.int_val == -2 && mv.type == BIO_CBOR_BSTR && mv.bstr.len == 32)
                    {
                        /* -2 → x */
                        memcpy(params->key_agreement_x, mv.bstr.data, 32);
                        params->has_key_agreement = true;
                    }
                    else if (mk.int_val == -3 && mv.type == BIO_CBOR_BSTR && mv.bstr.len == 32)
                    {
                        /* -3 → y */
                        memcpy(params->key_agreement_y, mv.bstr.data, 32);
                    }
                }
                else
                {
                    bio_cbor_skip(&dec);
                }
            }
            break;
        }
        case 0x04:
        { /* pinUvAuthParam */
            bio_cbor_item_t val;
            if (bio_cbor_decode_next(&dec, &val) != BIO_OK)
                return CTAP2_ERR_INVALID_CBOR;
            if (val.type == BIO_CBOR_BSTR && val.bstr.len >= 16)
            {
                size_t copy_len = val.bstr.len <= sizeof(params->pin_uv_auth_param)
                                      ? val.bstr.len
                                      : sizeof(params->pin_uv_auth_param);
                memcpy(params->pin_uv_auth_param, val.bstr.data, copy_len);
                params->pin_uv_auth_param_len = copy_len;
                params->has_pin_uv_auth_param = true;
            }
            break;
        }
        case 0x05:
        { /* newPinEnc */
            bio_cbor_item_t val;
            if (bio_cbor_decode_next(&dec, &val) != BIO_OK)
                return CTAP2_ERR_INVALID_CBOR;
            if (val.type == BIO_CBOR_BSTR)
            {
                params->new_pin_enc_len = val.bstr.len < sizeof(params->new_pin_enc)
                                              ? val.bstr.len
                                              : sizeof(params->new_pin_enc);
                memcpy(params->new_pin_enc, val.bstr.data, params->new_pin_enc_len);
            }
            break;
        }
        case 0x06:
        { /* pinHashEnc */
            bio_cbor_item_t val;
            if (bio_cbor_decode_next(&dec, &val) != BIO_OK)
                return CTAP2_ERR_INVALID_CBOR;
            if (val.type == BIO_CBOR_BSTR)
            {
                params->pin_hash_enc_len = val.bstr.len < sizeof(params->pin_hash_enc)
                                               ? val.bstr.len
                                               : sizeof(params->pin_hash_enc);
                memcpy(params->pin_hash_enc, val.bstr.data, params->pin_hash_enc_len);
            }
            break;
        }
        case 0x09:
        { /* permissions (uint) */
            uint64_t v;
            if (bio_cbor_decode_uint(&dec, &v) != BIO_OK)
                return CTAP2_ERR_INVALID_CBOR;
            params->permissions = (uint32_t)v;
            params->has_permissions = true;
            break;
        }
        case 0x0A:
        { /* rpId (tstr) */
            bio_cbor_item_t val;
            if (bio_cbor_decode_next(&dec, &val) != BIO_OK)
                return CTAP2_ERR_INVALID_CBOR;
            if (val.type == BIO_CBOR_TSTR)
            {
                params->rp_id_len = val.tstr.len < sizeof(params->rp_id) - 1
                                        ? val.tstr.len
                                        : sizeof(params->rp_id) - 1;
                memcpy(params->rp_id, val.tstr.data, params->rp_id_len);
                params->rp_id[params->rp_id_len] = '\0';
            }
            break;
        }
        case 0x0B:
        { /* newMinPINLength (uint) */
            uint64_t v;
            if (bio_cbor_decode_uint(&dec, &v) != BIO_OK)
                return CTAP2_ERR_INVALID_CBOR;
            params->new_min_pin_length = (uint32_t)v;
            params->has_new_min_pin_length = true;
            break;
        }
        default:
            bio_cbor_skip(&dec);
            break;
        }
    }

    if (params->sub_command == 0)
        return CTAP2_ERR_MISSING_PARAMETER;
    return CTAP2_OK;
}

/* Encode our ECDH public key as COSE_Key */
static void encode_key_agreement(bio_cbor_encoder_t *enc,
                                 const uint8_t pubkey[65])
{
    /* pubkey[0]=0x04, x=pubkey+1, y=pubkey+33 */
    bio_cbor_encode_map(enc, 5);

    bio_cbor_encode_uint(enc, 1); /* kty */
    bio_cbor_encode_uint(enc, 2); /* EC2 */

    bio_cbor_encode_uint(enc, 3);    /* alg */
    bio_cbor_encode_negint(enc, 24); /* -25 (ECDH-ES+HKDF-256) */

    bio_cbor_encode_negint(enc, 0); /* -1 (crv) */
    bio_cbor_encode_uint(enc, 1);   /* P-256 */

    bio_cbor_encode_negint(enc, 1); /* -2 (x) */
    bio_cbor_encode_bstr(enc, pubkey + 1, 32);

    bio_cbor_encode_negint(enc, 2); /* -3 (y) */
    bio_cbor_encode_bstr(enc, pubkey + 33, 32);
}

/*
 * Regenerate the ECDH key pair after each successful PIN operation.
 * Per CTAP2 §6.5.4, the authenticator must generate a new key
 * agreement key pair after setPIN, changePIN, and getPinToken (VULN-06 fix).
 */
static int regenerate_key_agreement(bio_fido2_ctx_t *ctx)
{
    bio_ecdh_keypair kp;
    if (bio_ecdh_keygen(&kp) != BIO_OK)
    {
        BIO_ERROR("regenerate_key_agreement: keygen failed, wiping old keys");
        bio_secure_wipe(ctx->auth_privkey, 32);
        bio_secure_wipe(ctx->auth_pubkey, 65);
        bio_secure_wipe(ctx->pin.shared_secret, 32);
        return BIO_ERR_CRYPTO_INIT;
    }
    bio_secure_wipe(ctx->auth_privkey, 32);
    memcpy(ctx->auth_privkey, kp.private_key, 32);
    memcpy(ctx->auth_pubkey, kp.public_key, 65);
    bio_secure_wipe(&kp, sizeof(kp));
    /* Wipe shared secret — it's derived from the old key pair */
    bio_secure_wipe(ctx->pin.shared_secret, 32);
    return BIO_OK;
}

static uint8_t derive_client_pin_keys(bio_fido2_ctx_t *ctx,
                                      uint32_t pin_protocol,
                                      const uint8_t peer_x[32],
                                      const uint8_t peer_y[32],
                                      uint8_t key_hmac[32],
                                      uint8_t key_aes[32])
{
    uint8_t peer_pubkey[65];
    peer_pubkey[0] = 0x04;
    memcpy(peer_pubkey + 1, peer_x, 32);
    memcpy(peer_pubkey + 33, peer_y, 32);

    uint8_t shared_raw[32];
    if (bio_ecdh_compute_shared(ctx->auth_privkey, peer_pubkey, shared_raw) != BIO_OK)
    {
        return CTAP2_ERR_OTHER;
    }

    if (pin_protocol == 2)
    {
        static const uint8_t zeros32[32] = {0};
        static const uint8_t info_hmac[] = "CTAP2 HMAC key";
        static const uint8_t info_aes[] = "CTAP2 AES key";

        if (bio_hkdf_sha256(zeros32, sizeof(zeros32),
                            shared_raw, sizeof(shared_raw),
                            info_hmac, sizeof(info_hmac) - 1,
                            key_hmac, 32) != BIO_OK ||
            bio_hkdf_sha256(zeros32, sizeof(zeros32),
                            shared_raw, sizeof(shared_raw),
                            info_aes, sizeof(info_aes) - 1,
                            key_aes, 32) != BIO_OK)
        {
            bio_secure_wipe(shared_raw, sizeof(shared_raw));
            return CTAP2_ERR_OTHER;
        }
    }
    else if (pin_protocol == 1)
    {
        bio_sha256(shared_raw, sizeof(shared_raw), key_hmac);
        memcpy(key_aes, key_hmac, 32);
    }
    else
    {
        bio_secure_wipe(shared_raw, sizeof(shared_raw));
        return CTAP2_ERR_PIN_AUTH_INVALID;
    }

    bio_secure_wipe(shared_raw, sizeof(shared_raw));
    return CTAP2_OK;
}

uint8_t ctap2_client_pin(bio_fido2_ctx_t *ctx,
                         const uint8_t *req, size_t req_len,
                         uint8_t *rsp, size_t *rsp_len)
{
    client_pin_params_t params;
    uint8_t rc = parse_client_pin_params(req, req_len, &params);
    if (rc != CTAP2_OK)
        return rc;

    if (params.pin_protocol != 1 && params.pin_protocol != 2)
        return CTAP2_ERR_PIN_AUTH_INVALID;

    bio_cbor_encoder_t enc;

    switch (params.sub_command)
    {
    case PIN_SUBCMD_GET_RETRIES:
    {
        bio_cbor_encoder_init(&enc, rsp, *rsp_len);
        bio_cbor_encode_map(&enc, 1);
        bio_cbor_encode_uint(&enc, 0x03); /* retries */
        bio_cbor_encode_uint(&enc, ctx->pin.pin_retries);
        if (enc.error)
            return CTAP2_ERR_OTHER;
        *rsp_len = enc.offset;
        return CTAP2_OK;
    }

    case PIN_SUBCMD_GET_KEY_AGREEMENT:
    {
        bio_cbor_encoder_init(&enc, rsp, *rsp_len);
        bio_cbor_encode_map(&enc, 1);
        bio_cbor_encode_uint(&enc, 0x01); /* keyAgreement */
        encode_key_agreement(&enc, ctx->auth_pubkey);
        if (enc.error)
            return CTAP2_ERR_OTHER;
        *rsp_len = enc.offset;
        return CTAP2_OK;
    }

    case PIN_SUBCMD_SET_PIN:
    {
        if (ctx->pin.pin_set)
            return CTAP2_ERR_NOT_ALLOWED;
        if (!params.has_key_agreement)
            return CTAP2_ERR_MISSING_PARAMETER;
        if (params.new_pin_enc_len == 0)
            return CTAP2_ERR_MISSING_PARAMETER;
        if (!params.has_pin_uv_auth_param)
            return CTAP2_ERR_MISSING_PARAMETER;

        uint8_t key_hmac[32];
        uint8_t key_aes[32];
        rc = derive_client_pin_keys(ctx, params.pin_protocol,
                                    params.key_agreement_x,
                                    params.key_agreement_y,
                                    key_hmac, key_aes);
        if (rc != CTAP2_OK)
        {
            return rc;
        }

        /* Verify pinAuth = left(HMAC-SHA-256(sharedSecret, newPinEnc), 16) */
        uint8_t hmac[32];
        bio_hmac_sha256(key_hmac, 32, params.new_pin_enc, params.new_pin_enc_len,
                        hmac);

        if (bio_constant_time_compare(hmac, params.pin_uv_auth_param, 16) != 0)
        {
            bio_secure_wipe(hmac, sizeof(hmac));
            bio_secure_wipe(key_hmac, sizeof(key_hmac));
            bio_secure_wipe(key_aes, sizeof(key_aes));
            return CTAP2_ERR_PIN_AUTH_INVALID;
        }
        bio_secure_wipe(hmac, sizeof(hmac));

        /* Decrypt newPinEnc: AES-256-CBC-Dec(sharedSecret, iv=0, newPinEnc) */
        uint8_t raw_pin[256];
        if (params.new_pin_enc_len > sizeof(raw_pin) ||
            (params.new_pin_enc_len % 16) != 0)
        {
            bio_secure_wipe(key_hmac, sizeof(key_hmac));
            bio_secure_wipe(key_aes, sizeof(key_aes));
            return CTAP2_ERR_PIN_POLICY_VIOLATION;
        }
        if (bio_aes256_cbc_ctap2_pin_decrypt(key_aes, params.new_pin_enc,
                                             params.new_pin_enc_len, raw_pin) != BIO_OK)
        {
            bio_secure_wipe(key_hmac, sizeof(key_hmac));
            bio_secure_wipe(key_aes, sizeof(key_aes));
            return CTAP2_ERR_OTHER;
        }

        /* Find actual PIN length (strip trailing zeros from padding) */
        size_t pin_len = params.new_pin_enc_len;
        while (pin_len > 0 && raw_pin[pin_len - 1] == 0)
            pin_len--;

        if (pin_len < g_min_pin_length || pin_len > 63)
        {
            bio_secure_wipe(raw_pin, sizeof(raw_pin));
            bio_secure_wipe(key_hmac, sizeof(key_hmac));
            bio_secure_wipe(key_aes, sizeof(key_aes));
            return CTAP2_ERR_PIN_POLICY_VIOLATION;
        }

        /* Store left(SHA-256(rawPIN), 16) */
        uint8_t pin_hash[32];
        bio_sha256(raw_pin, pin_len, pin_hash);
        memcpy(ctx->pin.pin_hash, pin_hash, 16); /* left 16 bytes */
        bio_secure_wipe(pin_hash, 32);
        bio_secure_wipe(raw_pin, sizeof(raw_pin));
        bio_secure_wipe(key_hmac, sizeof(key_hmac));
        bio_secure_wipe(key_aes, sizeof(key_aes));

        ctx->pin.pin_set = true;
        ctx->pin.pin_retries = CTAP2_MAX_PIN_RETRIES;

        /* Persist PIN state to disk immediately */
        if (bio_fido2_save_credentials(ctx) != BIO_OK)
        {
            BIO_ERROR("FIDO2: setPIN persistence failed — rolling back");
            ctx->pin.pin_set = false;
            bio_secure_wipe(ctx->pin.pin_hash, 16);
            return CTAP2_ERR_OTHER;
        }

        /* CTAP2 §6.5.4: Regenerate key agreement after setPin */
        if (regenerate_key_agreement(ctx) != BIO_OK)
        {
            BIO_ERROR("FIDO2: key agreement regen failed after setPIN");
            return CTAP2_ERR_OTHER;
        }

        *rsp_len = 0;
        return CTAP2_OK;
    }

    case PIN_SUBCMD_GET_PIN_TOKEN:
    {
        if (!ctx->pin.pin_set)
            return CTAP2_ERR_PIN_NOT_SET;
        if (ctx->pin.pin_blocked)
            return CTAP2_ERR_PIN_BLOCKED;
        if (!params.has_key_agreement)
            return CTAP2_ERR_MISSING_PARAMETER;
        if (params.pin_hash_enc_len == 0)
            return CTAP2_ERR_MISSING_PARAMETER;

        uint8_t key_hmac[32];
        uint8_t key_aes[32];
        rc = derive_client_pin_keys(ctx, params.pin_protocol,
                                    params.key_agreement_x,
                                    params.key_agreement_y,
                                    key_hmac, key_aes);
        if (rc != CTAP2_OK)
        {
            return rc;
        }

        /* Decrypt pinHashEnc: AES-256-CBC-Dec(sharedSecret, iv=0, pinHashEnc)
         * Result should be left(SHA-256(PIN), 16) */
        if (params.pin_hash_enc_len != 16 && params.pin_hash_enc_len != 32 &&
            params.pin_hash_enc_len != 48 && params.pin_hash_enc_len != 64)
        {
            /* Must be a multiple of 16 for AES-CBC */
            bio_secure_wipe(key_hmac, sizeof(key_hmac));
            bio_secure_wipe(key_aes, sizeof(key_aes));
            return CTAP2_ERR_PIN_AUTH_INVALID;
        }
        uint8_t decrypted_hash[64];
        if (bio_aes256_cbc_ctap2_pin_decrypt(key_aes, params.pin_hash_enc,
                                             params.pin_hash_enc_len,
                                             decrypted_hash) != BIO_OK)
        {
            bio_secure_wipe(key_hmac, sizeof(key_hmac));
            bio_secure_wipe(key_aes, sizeof(key_aes));
            return CTAP2_ERR_OTHER;
        }

        /* Compare first 16 bytes against stored PIN hash */
        if (bio_constant_time_compare(decrypted_hash, ctx->pin.pin_hash, 16) != 0)
        {
            bio_secure_wipe(decrypted_hash, sizeof(decrypted_hash));
            ctx->pin.pin_retries--;
            if (ctx->pin.pin_retries <= 0)
                ctx->pin.pin_blocked = true;
            /* PIN-PERSIST fix: persist retry counter and blocked state
             * atomically to prevent brute-force via daemon restart */
            if (bio_fido2_save_credentials(ctx) != BIO_OK)
            {
                BIO_WARN("FIDO2: failed to persist PIN retry counter");
            }
            if (ctx->pin.pin_blocked)
            {
                bio_secure_wipe(key_hmac, sizeof(key_hmac));
                bio_secure_wipe(key_aes, sizeof(key_aes));
                return CTAP2_ERR_PIN_BLOCKED;
            }
            bio_secure_wipe(key_hmac, sizeof(key_hmac));
            bio_secure_wipe(key_aes, sizeof(key_aes));
            return CTAP2_ERR_PIN_INVALID;
        }
        bio_secure_wipe(decrypted_hash, sizeof(decrypted_hash));

        ctx->pin.pin_retries = CTAP2_MAX_PIN_RETRIES;

        /* Generate pin token */
        if (bio_random_bytes(ctx->pin.pin_token, CTAP2_PIN_TOKEN_SIZE) != BIO_OK)
        {
            bio_secure_wipe(key_hmac, sizeof(key_hmac));
            bio_secure_wipe(key_aes, sizeof(key_aes));
            return CTAP2_ERR_OTHER;
        }
        ctx->pin.pin_token_valid = true;
        ctx->pin.pin_token_permissions = 0; /* legacy token: unrestricted */
        bio_secure_wipe(ctx->pin.pin_token_rp_id,
                        sizeof(ctx->pin.pin_token_rp_id));
        ctx->pin.pin_token_rp_id_set = false;

        /* Encrypt pin token: AES-256-CBC-Enc(sharedSecret, iv=0, pinToken) */
        uint8_t enc_token[CTAP2_PIN_TOKEN_SIZE];
        if (bio_aes256_cbc_ctap2_pin_encrypt(key_aes,
                                             ctx->pin.pin_token, CTAP2_PIN_TOKEN_SIZE,
                                             enc_token) != BIO_OK)
        {
            bio_secure_wipe(key_hmac, sizeof(key_hmac));
            bio_secure_wipe(key_aes, sizeof(key_aes));
            return CTAP2_ERR_OTHER;
        }
        bio_secure_wipe(key_hmac, sizeof(key_hmac));
        bio_secure_wipe(key_aes, sizeof(key_aes));

        bio_cbor_encoder_init(&enc, rsp, *rsp_len);
        bio_cbor_encode_map(&enc, 1);
        bio_cbor_encode_uint(&enc, 0x02); /* pinToken */
        bio_cbor_encode_bstr(&enc, enc_token, CTAP2_PIN_TOKEN_SIZE);

        bio_secure_wipe(enc_token, 32);

        /* Check CBOR encoding before proceeding to key regeneration */
        if (enc.error)
            return CTAP2_ERR_OTHER;
        *rsp_len = enc.offset;

        /* CTAP2 §6.5.4: Regenerate key agreement after getPinToken */
        if (regenerate_key_agreement(ctx) != BIO_OK)
        {
            BIO_ERROR("FIDO2: key agreement regen failed after getPinToken");
            return CTAP2_ERR_OTHER;
        }

        return CTAP2_OK;
    }

    case PIN_SUBCMD_CHANGE_PIN:
    {
        if (!ctx->pin.pin_set)
            return CTAP2_ERR_PIN_NOT_SET;
        if (ctx->pin.pin_blocked)
            return CTAP2_ERR_PIN_BLOCKED;
        if (!params.has_key_agreement)
            return CTAP2_ERR_MISSING_PARAMETER;
        if (!params.has_pin_uv_auth_param)
            return CTAP2_ERR_MISSING_PARAMETER;
        if (params.pin_hash_enc_len == 0)
            return CTAP2_ERR_MISSING_PARAMETER;
        if (params.new_pin_enc_len == 0)
            return CTAP2_ERR_MISSING_PARAMETER;

        uint8_t key_hmac[32];
        uint8_t key_aes[32];
        rc = derive_client_pin_keys(ctx, params.pin_protocol,
                                    params.key_agreement_x,
                                    params.key_agreement_y,
                                    key_hmac, key_aes);
        if (rc != CTAP2_OK)
        {
            return rc;
        }

        /* Verify pinAuth = left(HMAC-SHA-256(sharedSecret, newPinEnc || pinHashEnc), 16) */
        size_t msg_len = params.new_pin_enc_len + params.pin_hash_enc_len;
        uint8_t auth_msg[512];
        if (msg_len > sizeof(auth_msg))
        {
            bio_secure_wipe(key_hmac, sizeof(key_hmac));
            bio_secure_wipe(key_aes, sizeof(key_aes));
            return CTAP2_ERR_OTHER;
        }
        memcpy(auth_msg, params.new_pin_enc, params.new_pin_enc_len);
        memcpy(auth_msg + params.new_pin_enc_len, params.pin_hash_enc,
               params.pin_hash_enc_len);

        uint8_t hmac[32];
        bio_hmac_sha256(key_hmac, 32, auth_msg, msg_len, hmac);
        if (bio_constant_time_compare(hmac, params.pin_uv_auth_param, 16) != 0)
        {
            bio_secure_wipe(auth_msg, sizeof(auth_msg));
            bio_secure_wipe(hmac, sizeof(hmac));
            bio_secure_wipe(key_hmac, sizeof(key_hmac));
            bio_secure_wipe(key_aes, sizeof(key_aes));
            return CTAP2_ERR_PIN_AUTH_INVALID;
        }
        bio_secure_wipe(hmac, sizeof(hmac));
        bio_secure_wipe(auth_msg, sizeof(auth_msg));

        /* Decrypt and verify old PIN hash */
        if ((params.pin_hash_enc_len % 16) != 0)
        {
            bio_secure_wipe(key_hmac, sizeof(key_hmac));
            bio_secure_wipe(key_aes, sizeof(key_aes));
            return CTAP2_ERR_PIN_AUTH_INVALID;
        }
        uint8_t old_hash[64];
        if (bio_aes256_cbc_ctap2_pin_decrypt(key_aes, params.pin_hash_enc,
                                             params.pin_hash_enc_len, old_hash) != BIO_OK)
        {
            bio_secure_wipe(key_hmac, sizeof(key_hmac));
            bio_secure_wipe(key_aes, sizeof(key_aes));
            return CTAP2_ERR_OTHER;
        }
        if (bio_constant_time_compare(old_hash, ctx->pin.pin_hash, 16) != 0)
        {
            bio_secure_wipe(old_hash, sizeof(old_hash));
            ctx->pin.pin_retries--;
            if (ctx->pin.pin_retries <= 0)
                ctx->pin.pin_blocked = true;
            /* PIN-PERSIST fix: persist retry counter and blocked state
             * atomically to prevent one-extra-attempt via crash window */
            if (bio_fido2_save_credentials(ctx) != BIO_OK)
            {
                BIO_WARN("FIDO2: failed to persist PIN retry counter");
            }
            bio_secure_wipe(key_hmac, sizeof(key_hmac));
            bio_secure_wipe(key_aes, sizeof(key_aes));
            return ctx->pin.pin_blocked ? CTAP2_ERR_PIN_BLOCKED : CTAP2_ERR_PIN_INVALID;
        }
        bio_secure_wipe(old_hash, sizeof(old_hash));

        /* Decrypt new PIN */
        uint8_t new_pin[256];
        if (params.new_pin_enc_len > sizeof(new_pin) ||
            (params.new_pin_enc_len % 16) != 0)
        {
            bio_secure_wipe(key_hmac, sizeof(key_hmac));
            bio_secure_wipe(key_aes, sizeof(key_aes));
            return CTAP2_ERR_PIN_POLICY_VIOLATION;
        }
        if (bio_aes256_cbc_ctap2_pin_decrypt(key_aes, params.new_pin_enc,
                                             params.new_pin_enc_len, new_pin) != BIO_OK)
        {
            bio_secure_wipe(key_hmac, sizeof(key_hmac));
            bio_secure_wipe(key_aes, sizeof(key_aes));
            return CTAP2_ERR_OTHER;
        }
        bio_secure_wipe(key_hmac, sizeof(key_hmac));
        bio_secure_wipe(key_aes, sizeof(key_aes));

        /* Find actual PIN length (strip trailing zeros) */
        size_t pin_len = params.new_pin_enc_len;
        while (pin_len > 0 && new_pin[pin_len - 1] == 0)
            pin_len--;

        if (pin_len < g_min_pin_length || pin_len > 63)
        {
            bio_secure_wipe(new_pin, sizeof(new_pin));
            return CTAP2_ERR_PIN_POLICY_VIOLATION;
        }

        /* Store left(SHA-256(newPIN), 16) */
        uint8_t prev_pin_hash[16];
        int prev_pin_retries = ctx->pin.pin_retries;
        bool prev_pin_blocked = ctx->pin.pin_blocked;
        memcpy(prev_pin_hash, ctx->pin.pin_hash, sizeof(prev_pin_hash));

        uint8_t new_hash[32];
        bio_sha256(new_pin, pin_len, new_hash);
        memcpy(ctx->pin.pin_hash, new_hash, 16);
        ctx->pin.pin_retries = CTAP2_MAX_PIN_RETRIES;
        ctx->pin.pin_blocked = false;

        bio_secure_wipe(new_pin, sizeof(new_pin));
        bio_secure_wipe(new_hash, 32);

        /* Persist updated PIN hash to disk immediately.
         * On failure, restore the old PIN hash so in-memory and
         * on-disk states remain consistent. */
        if (bio_fido2_save_credentials(ctx) != BIO_OK)
        {
            BIO_ERROR("FIDO2: changePIN persistence failed — rolling back");
            memcpy(ctx->pin.pin_hash, prev_pin_hash, sizeof(prev_pin_hash));
            ctx->pin.pin_retries = prev_pin_retries;
            ctx->pin.pin_blocked = prev_pin_blocked;
            bio_secure_wipe(prev_pin_hash, sizeof(prev_pin_hash));
            return CTAP2_ERR_OTHER;
        }
        bio_secure_wipe(prev_pin_hash, sizeof(prev_pin_hash));

        /* CTAP2 §6.5.4: Regenerate key agreement after changePIN */
        if (regenerate_key_agreement(ctx) != BIO_OK)
        {
            BIO_ERROR("FIDO2: key agreement regen failed after changePIN");
            return CTAP2_ERR_OTHER;
        }

        *rsp_len = 0;
        return CTAP2_OK;
    }

    case PIN_SUBCMD_GET_UV_TOKEN_PERM:
    {
        /* CTAP2.1 §6.5.5.7: getPinUvAuthTokenUsingUvWithPermissions
         * Requires: keyAgreement (0x03), permissions (0x09)
         * Optional: rpId (0x0A) */
        if (!params.has_key_agreement)
            return CTAP2_ERR_MISSING_PARAMETER;
        if (!params.has_permissions)
            return CTAP2_ERR_MISSING_PARAMETER;
        if (params.permissions == 0)
            return CTAP2_ERR_INVALID_OPTION;

        BIO_INFO("FIDO2: getPinUvAuthTokenUsingUvWithPermissions "
                 "(perms=0x%02x, rpId=%s)",
                 params.permissions,
                 params.rp_id_len > 0 ? params.rp_id : "(none)");

        /* Perform user verification (fingerprint scan) */
        if (!ctx->verify_user || !ctx->verify_user(ctx->verify_user_ctx))
        {
            BIO_WARN("FIDO2: UV failed for getPinUvAuthTokenUsingUv");
            return CTAP2_ERR_OPERATION_DENIED;
        }

        BIO_INFO("FIDO2: UV succeeded, generating pinUvAuthToken");

        uint8_t key_hmac[32];
        uint8_t key_aes[32];
        rc = derive_client_pin_keys(ctx, params.pin_protocol,
                                    params.key_agreement_x,
                                    params.key_agreement_y,
                                    key_hmac, key_aes);
        if (rc != CTAP2_OK)
        {
            return rc;
        }

        /* Generate pinUvAuthToken */
        if (bio_random_bytes(ctx->pin.pin_token, CTAP2_PIN_TOKEN_SIZE) != BIO_OK)
        {
            bio_secure_wipe(key_hmac, sizeof(key_hmac));
            bio_secure_wipe(key_aes, sizeof(key_aes));
            return CTAP2_ERR_OTHER;
        }
        ctx->pin.pin_token_valid = true;
        ctx->pin.pin_token_permissions = params.permissions;
        bio_secure_wipe(ctx->pin.pin_token_rp_id,
                        sizeof(ctx->pin.pin_token_rp_id));
        if (params.rp_id_len > 0)
        {
            size_t copy = params.rp_id_len < sizeof(ctx->pin.pin_token_rp_id) - 1
                              ? params.rp_id_len
                              : sizeof(ctx->pin.pin_token_rp_id) - 1;
            memcpy(ctx->pin.pin_token_rp_id, params.rp_id, copy);
            ctx->pin.pin_token_rp_id[copy] = '\0';
            ctx->pin.pin_token_rp_id_set = true;
        }
        else
        {
            ctx->pin.pin_token_rp_id_set = false;
        }

        /* Encrypt pinUvAuthToken: AES-256-CBC-Enc(sharedSecret, iv=0, pinToken) */
        uint8_t enc_token[CTAP2_PIN_TOKEN_SIZE];
        if (bio_aes256_cbc_ctap2_pin_encrypt(key_aes,
                                             ctx->pin.pin_token, CTAP2_PIN_TOKEN_SIZE,
                                             enc_token) != BIO_OK)
        {
            bio_secure_wipe(key_hmac, sizeof(key_hmac));
            bio_secure_wipe(key_aes, sizeof(key_aes));
            return CTAP2_ERR_OTHER;
        }
        bio_secure_wipe(key_hmac, sizeof(key_hmac));
        bio_secure_wipe(key_aes, sizeof(key_aes));

        /* Regenerate key agreement per CTAP2 §6.5.4 */
        if (regenerate_key_agreement(ctx) != BIO_OK)
        {
            BIO_ERROR("FIDO2: key agreement regen failed after UV token");
            return CTAP2_ERR_OTHER;
        }

        /* Encode response: {0x02: pinUvAuthToken} */
        bio_cbor_encoder_init(&enc, rsp, *rsp_len);
        bio_cbor_encode_map(&enc, 1);
        bio_cbor_encode_uint(&enc, 0x02); /* pinUvAuthToken */
        bio_cbor_encode_bstr(&enc, enc_token, CTAP2_PIN_TOKEN_SIZE);
        bio_secure_wipe(enc_token, sizeof(enc_token));
        if (enc.error)
            return CTAP2_ERR_OTHER;
        *rsp_len = enc.offset;
        return CTAP2_OK;
    }

    case PIN_SUBCMD_GET_UV_RETRIES:
    {
        /* CTAP2.1 §6.5.5.6: getUVRetries
         * Returns UV retry count */
        bio_cbor_encoder_init(&enc, rsp, *rsp_len);
        bio_cbor_encode_map(&enc, 1);
        bio_cbor_encode_uint(&enc, 0x05); /* uvRetries */
        bio_cbor_encode_uint(&enc, 3);    /* fixed for now */
        if (enc.error)
            return CTAP2_ERR_OTHER;
        *rsp_len = enc.offset;
        return CTAP2_OK;
    }

    case PIN_SUBCMD_SET_MIN_PIN_LEN:
    {
        /* CTAP2.1 §6.5.5.8: setMinPINLength (policy update).
         * This implementation supports newMinPINLength only. */
        if (!ctx->pin.pin_set)
            return CTAP2_ERR_PIN_NOT_SET;
        if (!params.has_new_min_pin_length)
            return CTAP2_ERR_MISSING_PARAMETER;
        if (params.new_min_pin_length < 4 || params.new_min_pin_length > 63)
            return CTAP2_ERR_PIN_POLICY_VIOLATION;
        if (!params.has_pin_uv_auth_param)
            return CTAP2_ERR_MISSING_PARAMETER;
        if (!ctx->pin.pin_token_valid)
            return CTAP2_ERR_PIN_AUTH_INVALID;
        if (ctx->pin.pin_token_permissions != 0 &&
            (ctx->pin.pin_token_permissions & CTAP2_PIN_PERM_AUTHNR_CFG) == 0)
            return CTAP2_ERR_PIN_AUTH_INVALID;

        /* Verify pinUvAuthParam over [subCommand || newMinPINLength]. */
        uint8_t msg[5];
        msg[0] = PIN_SUBCMD_SET_MIN_PIN_LEN;
        msg[1] = (uint8_t)((params.new_min_pin_length >> 24) & 0xFF);
        msg[2] = (uint8_t)((params.new_min_pin_length >> 16) & 0xFF);
        msg[3] = (uint8_t)((params.new_min_pin_length >> 8) & 0xFF);
        msg[4] = (uint8_t)(params.new_min_pin_length & 0xFF);

        uint8_t expected[32];
        bio_hmac_sha256(ctx->pin.pin_token, CTAP2_PIN_TOKEN_SIZE,
                        msg, sizeof(msg), expected);

        if (params.pin_protocol == 2)
        {
            if (params.pin_uv_auth_param_len < 32 ||
                bio_constant_time_compare(expected,
                                          params.pin_uv_auth_param, 32) != 0)
            {
                bio_secure_wipe(expected, sizeof(expected));
                return CTAP2_ERR_PIN_AUTH_INVALID;
            }
        }
        else
        {
            if (bio_constant_time_compare(expected,
                                          params.pin_uv_auth_param, 16) != 0)
            {
                bio_secure_wipe(expected, sizeof(expected));
                return CTAP2_ERR_PIN_AUTH_INVALID;
            }
        }
        bio_secure_wipe(expected, sizeof(expected));

        g_min_pin_length = params.new_min_pin_length;
        *rsp_len = 0;
        return CTAP2_OK;
    }

    case PIN_SUBCMD_GET_PIN_TOKEN_PERM:
    {
        /* CTAP2.1 §6.5.5.9: getPinUvAuthTokenUsingPinWithPermissions
         * Requires keyAgreement, pinHashEnc and permissions. Optional rpId. */
        if (!ctx->pin.pin_set)
            return CTAP2_ERR_PIN_NOT_SET;
        if (ctx->pin.pin_blocked)
            return CTAP2_ERR_PIN_BLOCKED;
        if (!params.has_key_agreement)
            return CTAP2_ERR_MISSING_PARAMETER;
        if (!params.has_permissions)
            return CTAP2_ERR_MISSING_PARAMETER;
        if (params.permissions == 0)
            return CTAP2_ERR_INVALID_OPTION;
        if (params.pin_hash_enc_len == 0)
            return CTAP2_ERR_MISSING_PARAMETER;

        uint8_t key_hmac[32];
        uint8_t key_aes[32];
        rc = derive_client_pin_keys(ctx, params.pin_protocol,
                                    params.key_agreement_x,
                                    params.key_agreement_y,
                                    key_hmac, key_aes);
        if (rc != CTAP2_OK)
        {
            return rc;
        }

        if (params.pin_hash_enc_len != 16 && params.pin_hash_enc_len != 32 &&
            params.pin_hash_enc_len != 48 && params.pin_hash_enc_len != 64)
        {
            bio_secure_wipe(key_hmac, sizeof(key_hmac));
            bio_secure_wipe(key_aes, sizeof(key_aes));
            return CTAP2_ERR_PIN_AUTH_INVALID;
        }

        uint8_t decrypted_hash[64];
        if (bio_aes256_cbc_ctap2_pin_decrypt(key_aes, params.pin_hash_enc,
                                             params.pin_hash_enc_len,
                                             decrypted_hash) != BIO_OK)
        {
            bio_secure_wipe(key_hmac, sizeof(key_hmac));
            bio_secure_wipe(key_aes, sizeof(key_aes));
            return CTAP2_ERR_OTHER;
        }

        if (bio_constant_time_compare(decrypted_hash, ctx->pin.pin_hash, 16) != 0)
        {
            bio_secure_wipe(decrypted_hash, sizeof(decrypted_hash));
            ctx->pin.pin_retries--;
            if (ctx->pin.pin_retries <= 0)
                ctx->pin.pin_blocked = true;
            if (bio_fido2_save_credentials(ctx) != BIO_OK)
            {
                BIO_WARN("FIDO2: failed to persist PIN retry counter");
            }
            bio_secure_wipe(key_hmac, sizeof(key_hmac));
            bio_secure_wipe(key_aes, sizeof(key_aes));
            return ctx->pin.pin_blocked ? CTAP2_ERR_PIN_BLOCKED : CTAP2_ERR_PIN_INVALID;
        }
        bio_secure_wipe(decrypted_hash, sizeof(decrypted_hash));

        ctx->pin.pin_retries = CTAP2_MAX_PIN_RETRIES;
        ctx->pin.pin_blocked = false;

        if (bio_random_bytes(ctx->pin.pin_token, CTAP2_PIN_TOKEN_SIZE) != BIO_OK)
        {
            bio_secure_wipe(key_hmac, sizeof(key_hmac));
            bio_secure_wipe(key_aes, sizeof(key_aes));
            return CTAP2_ERR_OTHER;
        }
        ctx->pin.pin_token_valid = true;
        ctx->pin.pin_token_permissions = params.permissions;
        bio_secure_wipe(ctx->pin.pin_token_rp_id,
                        sizeof(ctx->pin.pin_token_rp_id));
        if (params.rp_id_len > 0)
        {
            size_t copy = params.rp_id_len < sizeof(ctx->pin.pin_token_rp_id) - 1
                              ? params.rp_id_len
                              : sizeof(ctx->pin.pin_token_rp_id) - 1;
            memcpy(ctx->pin.pin_token_rp_id, params.rp_id, copy);
            ctx->pin.pin_token_rp_id[copy] = '\0';
            ctx->pin.pin_token_rp_id_set = true;
        }
        else
        {
            ctx->pin.pin_token_rp_id_set = false;
        }

        uint8_t enc_token[CTAP2_PIN_TOKEN_SIZE];
        if (bio_aes256_cbc_ctap2_pin_encrypt(key_aes,
                                             ctx->pin.pin_token, CTAP2_PIN_TOKEN_SIZE,
                                             enc_token) != BIO_OK)
        {
            bio_secure_wipe(key_hmac, sizeof(key_hmac));
            bio_secure_wipe(key_aes, sizeof(key_aes));
            return CTAP2_ERR_OTHER;
        }
        bio_secure_wipe(key_hmac, sizeof(key_hmac));
        bio_secure_wipe(key_aes, sizeof(key_aes));

        if (regenerate_key_agreement(ctx) != BIO_OK)
        {
            bio_secure_wipe(enc_token, sizeof(enc_token));
            BIO_ERROR("FIDO2: key agreement regen failed after PIN+perm token");
            return CTAP2_ERR_OTHER;
        }

        bio_cbor_encoder_init(&enc, rsp, *rsp_len);
        bio_cbor_encode_map(&enc, 1);
        bio_cbor_encode_uint(&enc, 0x02); /* pinUvAuthToken */
        bio_cbor_encode_bstr(&enc, enc_token, CTAP2_PIN_TOKEN_SIZE);
        bio_secure_wipe(enc_token, sizeof(enc_token));
        if (enc.error)
            return CTAP2_ERR_OTHER;

        *rsp_len = enc.offset;
        return CTAP2_OK;
    }

    default:
        return CTAP2_ERR_INVALID_CBOR;
    }
}

/* ── authenticatorReset (0x07) ───────────────────────────────── */

uint8_t ctap2_reset(bio_fido2_ctx_t *ctx)
{
    /* CTAP2 §6.6: Reset only allowed within 10 seconds of power-up
     * and requires user presence (VULN-07 fix) */
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t now = (uint64_t)ts.tv_sec;
    if (now - ctx->init_timestamp > 10)
    {
        BIO_WARN("FIDO2: reset denied — more than 10s since startup "
                 "(init=%" PRIu64 ", now=%" PRIu64 ")",
                 ctx->init_timestamp, now);
        return CTAP2_ERR_NOT_ALLOWED;
    }

    /* Require user presence (fingerprint) before destructive reset */
    if (ctx->verify_user)
    {
        if (!ctx->verify_user(ctx->verify_user_ctx))
        {
            return CTAP2_ERR_OPERATION_DENIED;
        }
    }

    /* Wipe all credentials */
    for (size_t i = 0; i < CTAP2_MAX_CREDENTIALS_STORED; i++)
    {
        if (ctx->credentials[i].in_use)
        {
            bio_secure_wipe(ctx->credentials[i].private_key, 32);
        }
        ctx->credentials[i].in_use = false;
    }
    ctx->credential_count = 0;

    /* Wipe all bio templates (CTAP2 §6.6 full reset) */
    bio_fido2_bio_reset();

    /* Reset PIN state */
    bio_secure_wipe(&ctx->pin, sizeof(ctx->pin));
    ctx->pin.pin_retries = CTAP2_MAX_PIN_RETRIES;

    /* Regenerate key agreement key */
    bio_ecdh_keypair kp;
    bio_secure_wipe(ctx->auth_privkey, 32);
    if (bio_ecdh_keygen(&kp) == BIO_OK)
    {
        memcpy(ctx->auth_privkey, kp.private_key, 32);
        memcpy(ctx->auth_pubkey, kp.public_key, 65);
        bio_secure_wipe(&kp, sizeof(kp));
    }
    else
    {
        BIO_ERROR("FIDO2: reset keygen failed — zeroing auth keys");
        bio_secure_wipe(ctx->auth_pubkey, 65);
    }

    /* Reset counters */
    ctx->global_sign_count = 0;
    g_min_pin_length = 4;

    /* Save clean state */
    bio_fido2_save_credentials(ctx);

    BIO_INFO("FIDO2: authenticator reset completed");
    return CTAP2_OK;
}

/* ── authenticatorSelection (0x0B) ───────────────────────────── */

uint8_t ctap2_selection(bio_fido2_ctx_t *ctx)
{
    /* CTAP2 §6.9: authenticatorSelection MUST test user presence.
     * For a platform authenticator, UP is verified via biometric. */
    if (ctx->verify_user)
    {
        if (!ctx->verify_user(ctx->verify_user_ctx))
        {
            return CTAP2_ERR_OPERATION_DENIED;
        }
    }
    else
    {
        /* No user presence method available — deny per spec */
        return CTAP2_ERR_OPERATION_DENIED;
    }
    return CTAP2_OK;
}

/* ── Credential persistence ──────────────────────────────────── */

/*
 * Storage format (encrypted binary — v2):
 *   Header:  "BIOF" (4) + version (4) + count (4) + reserved (4) = 16 bytes
 *   Nonce:   12 bytes (AES-256-GCM IV)
 *   Encrypted payload:
 *     PIN state (sizeof(ctap2_pin_state_t)) +
 *     For each credential:
 *       in_use (1) + rp.id (256) + rp.name (256) + rp.id_hash (32)
 *       user.id (64) + user.id_len (2) + user.name (64) + user.display_name (64)
 *       cred_id.id (128) + cred_id.id_len (2)
 *       private_key (32) + public_key (65)
 *       sign_count (4) + created (8) + resident (1) + cred_protect (1)
 *   GCM tag: 16 bytes
 *
 * The entire credential blob (PIN state + credentials) is encrypted
 * with AES-256-GCM using the authenticator's wrap key, ensuring
 * private keys are NEVER stored in plaintext on disk.
 */

#define CRED_STORE_MAGIC "BIOF"
#define CRED_STORE_VERSION 2

/* Size of a single serialized credential entry */
#define CRED_ENTRY_SERIAL_SIZE (1 + 256 + 256 + 32 + 64 + 2 + 64 + 64 + \
                                128 + 2 + 32 + 65 + 4 + 8 + 1 + 1)

int bio_fido2_save_credentials(bio_fido2_ctx_t *ctx)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/credentials.bin", ctx->storage_path);

    /* Ensure directory exists */
    mkdir(ctx->storage_path, 0700);

    /* Ensure we have a wrap key for encryption */

    /* Build plaintext blob: PIN state + all in-use credentials */
    size_t max_plain = sizeof(ctx->pin) +
                       CTAP2_MAX_CREDENTIALS_STORED * CRED_ENTRY_SERIAL_SIZE;
    uint8_t *plaintext = malloc(max_plain);
    if (!plaintext)
        return BIO_ERR_NOMEM;

    bio_mlock_sensitive(plaintext, max_plain);
    size_t off = 0;

    /* PIN state — wipe session-ephemeral fields before serializing */
    ctap2_pin_state_t pin_persist = ctx->pin;
    bio_secure_wipe(pin_persist.platform_key_agreement_x, 32);
    bio_secure_wipe(pin_persist.platform_key_agreement_y, 32);
    bio_secure_wipe(pin_persist.shared_secret, 32);
    bio_secure_wipe(pin_persist.pin_token, sizeof(pin_persist.pin_token));
    pin_persist.pin_token_valid = false;
    pin_persist.pin_token_permissions = 0;
    bio_secure_wipe(pin_persist.pin_token_rp_id,
                    sizeof(pin_persist.pin_token_rp_id));
    pin_persist.pin_token_rp_id_set = false;
    memcpy(plaintext + off, &pin_persist, sizeof(pin_persist));
    off += sizeof(pin_persist);
    bio_secure_wipe(&pin_persist, sizeof(pin_persist));

    /* Credentials */
    for (size_t i = 0; i < CTAP2_MAX_CREDENTIALS_STORED; i++)
    {
        if (!ctx->credentials[i].in_use)
            continue;

        const ctap2_credential_t *c = &ctx->credentials[i];
        uint8_t flag = 1;
        memcpy(plaintext + off, &flag, 1);
        off += 1;

        memcpy(plaintext + off, c->rp.id, sizeof(c->rp.id));
        off += sizeof(c->rp.id);
        memcpy(plaintext + off, c->rp.name, sizeof(c->rp.name));
        off += sizeof(c->rp.name);
        memcpy(plaintext + off, c->rp.id_hash, 32);
        off += 32;

        memcpy(plaintext + off, c->user.id, sizeof(c->user.id));
        off += sizeof(c->user.id);
        uint16_t id_len16 = (uint16_t)c->user.id_len;
        memcpy(plaintext + off, &id_len16, 2);
        off += 2;
        memcpy(plaintext + off, c->user.name, sizeof(c->user.name));
        off += sizeof(c->user.name);
        memcpy(plaintext + off, c->user.display_name,
               sizeof(c->user.display_name));
        off += sizeof(c->user.display_name);

        memcpy(plaintext + off, c->cred_id.id, sizeof(c->cred_id.id));
        off += sizeof(c->cred_id.id);
        uint16_t cid_len16 = (uint16_t)c->cred_id.id_len;
        memcpy(plaintext + off, &cid_len16, 2);
        off += 2;

        memcpy(plaintext + off, c->private_key, 32);
        off += 32;
        memcpy(plaintext + off, c->public_key, 65);
        off += 65;

        memcpy(plaintext + off, &c->sign_count, 4);
        off += 4;
        memcpy(plaintext + off, &c->created, 8);
        off += 8;
        uint8_t r = c->resident ? 1 : 0;
        memcpy(plaintext + off, &r, 1);
        off += 1;
        /* Encode cred_protect with 0x10 bias to distinguish from
         * old uv_required boolean (0/1) in v2 credential stores. */
        uint8_t cp = (uint8_t)(c->cred_protect + 0x10);
        memcpy(plaintext + off, &cp, 1);
        off += 1;
    }

    /* Atomic write: write to temp file, fsync, then rename */
    char tmp_path[520];
    snprintf(tmp_path, sizeof(tmp_path), "%s/.credentials.tmp", ctx->storage_path);

    int fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0)
    {
        BIO_ERROR("FIDO2: cannot open %s for writing: %s", tmp_path, strerror(errno));
        bio_secure_wipe(plaintext, off);
        bio_munlock_sensitive(plaintext, max_plain);
        free(plaintext);
        return BIO_ERR_IO;
    }

    /* Header */
    uint32_t version = CRED_STORE_VERSION;
    uint32_t count = (uint32_t)ctx->credential_count;
    uint32_t sign_cnt = ctx->global_sign_count;
    ssize_t w;
    w = write(fd, CRED_STORE_MAGIC, 4);
    if (w != 4)
        goto write_err;
    w = write(fd, &version, 4);
    if (w != 4)
        goto write_err;
    w = write(fd, &count, 4);
    if (w != 4)
        goto write_err;
    w = write(fd, &sign_cnt, 4);
    if (w != 4)
        goto write_err;

    if (bio_fido2_wrap_key_valid() && off > 0)
    {
        /* Encrypt the credential blob with AES-256-GCM */
        const uint8_t *wk = bio_fido2_get_wrap_key();
        uint8_t nonce[12];
        int rc = bio_random_bytes(nonce, sizeof(nonce));
        if (rc != BIO_OK)
            goto write_err;

        uint8_t *ciphertext = malloc(off);
        if (!ciphertext)
            goto write_err;
        uint8_t tag[16];

        /* Bind header to GCM authentication to prevent tampering */
        uint8_t aad[16];
        memcpy(aad, CRED_STORE_MAGIC, 4);
        memcpy(aad + 4, &version, 4);
        memcpy(aad + 8, &count, 4);
        memcpy(aad + 12, &sign_cnt, 4);

        rc = bio_aes256_gcm_seal(wk, nonce,
                                 aad, sizeof(aad),
                                 plaintext, off,
                                 ciphertext, tag);

        bio_secure_wipe(plaintext, off);
        bio_munlock_sensitive(plaintext, max_plain);
        free(plaintext);

        if (rc != BIO_OK)
        {
            bio_secure_wipe(ciphertext, off);
            free(ciphertext);
            close(fd);
            return rc;
        }

        /* Write: nonce || ciphertext || tag */
        w = write(fd, nonce, 12);
        if (w != 12)
        {
            bio_secure_wipe(ciphertext, off);
            bio_secure_wipe(tag, sizeof(tag));
            bio_secure_wipe(nonce, sizeof(nonce));
            free(ciphertext);
            goto write_err_nopl;
        }
        w = write(fd, ciphertext, (size_t)off);
        if (w != (ssize_t)off)
        {
            bio_secure_wipe(ciphertext, off);
            bio_secure_wipe(tag, sizeof(tag));
            bio_secure_wipe(nonce, sizeof(nonce));
            free(ciphertext);
            goto write_err_nopl;
        }
        w = write(fd, tag, 16);
        if (w != 16)
        {
            bio_secure_wipe(ciphertext, off);
            bio_secure_wipe(tag, sizeof(tag));
            bio_secure_wipe(nonce, sizeof(nonce));
            free(ciphertext);
            goto write_err_nopl;
        }

        bio_secure_wipe(ciphertext, off);
        free(ciphertext);
        bio_secure_wipe(tag, sizeof(tag));
        bio_secure_wipe(nonce, sizeof(nonce));
    }
    else
    {
        /* SECURITY: refuse to save credentials unencrypted (VULN-03 fix) */
        BIO_ERROR("FIDO2: refusing to save credentials without wrap key "
                  "— no encryption available");
        bio_secure_wipe(plaintext, off);
        bio_munlock_sensitive(plaintext, max_plain);
        free(plaintext);
        close(fd);
        unlink(tmp_path);
        return BIO_ERR_CRYPTO_ENCRYPT;
    }

    fsync(fd);
    close(fd);

    /* Atomic rename to final path */
    if (rename(tmp_path, path) != 0)
    {
        BIO_ERROR("FIDO2: rename %s → %s failed: %s", tmp_path, path, strerror(errno));
        unlink(tmp_path);
        return BIO_ERR_IO;
    }

    BIO_DEBUG("FIDO2: saved %u credentials (encrypted) to %s", count, path);
    return BIO_OK;

write_err:
    bio_secure_wipe(plaintext, off);
    bio_munlock_sensitive(plaintext, max_plain);
    free(plaintext);
write_err_nopl:
    close(fd);
    unlink(tmp_path);
    BIO_ERROR("FIDO2: write error saving credentials to %s", path);
    return BIO_ERR_IO;
}

int bio_fido2_load_credentials(bio_fido2_ctx_t *ctx)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/credentials.bin", ctx->storage_path);

    int fd = open(path, O_RDONLY);
    if (fd < 0)
    {
        /* No stored credentials — fine */
        return BIO_OK;
    }

    /* Header */
    char magic[4];
    if (read(fd, magic, 4) != 4 || memcmp(magic, CRED_STORE_MAGIC, 4) != 0)
    {
        close(fd);
        BIO_WARN("FIDO2: invalid credential store magic");
        return BIO_ERR_IO;
    }

    uint32_t version;
    if (read(fd, &version, 4) != 4)
    {
        close(fd);
        return BIO_ERR_IO;
    }

    uint32_t count;
    if (read(fd, &count, 4) != 4)
    {
        close(fd);
        return BIO_ERR_IO;
    }

    uint32_t sign_cnt;
    if (read(fd, &sign_cnt, 4) != 4)
    {
        close(fd);
        return BIO_ERR_IO;
    }
    ctx->global_sign_count = sign_cnt;

    if (version == 2 && bio_fido2_wrap_key_valid())
    {
        /* ── Encrypted format (v2) ─────────────────────────── */
        /* Read nonce */
        uint8_t nonce[12];
        if (read(fd, nonce, 12) != 12)
        {
            close(fd);
            return BIO_ERR_IO;
        }

        /* Read remaining file = ciphertext + 16-byte tag */
        off_t cur = lseek(fd, 0, SEEK_CUR);
        off_t end = lseek(fd, 0, SEEK_END);
        if (cur < 0 || end < 0 || end - cur < 16)
        {
            close(fd);
            return BIO_ERR_IO;
        }
        size_t blob_len = (size_t)(end - cur);
        size_t ct_len = blob_len - 16;
        lseek(fd, cur, SEEK_SET);

        uint8_t *ciphertext = malloc(ct_len);
        uint8_t tag[16];
        if (!ciphertext)
        {
            close(fd);
            return BIO_ERR_NOMEM;
        }

        if (read(fd, ciphertext, ct_len) != (ssize_t)ct_len ||
            read(fd, tag, 16) != 16)
        {
            bio_secure_wipe(ciphertext, ct_len);
            free(ciphertext);
            close(fd);
            return BIO_ERR_IO;
        }
        /* Reconstruct header for AAD verification */
        uint8_t aad[16];
        memcpy(aad, CRED_STORE_MAGIC, 4);
        memcpy(aad + 4, &version, 4);
        memcpy(aad + 8, &count, 4);
        memcpy(aad + 12, &sign_cnt, 4);

        /* All data read from file — close fd before processing */
        close(fd);
        fd = -1;

        uint8_t *plaintext = malloc(ct_len);
        if (!plaintext)
        {
            bio_secure_wipe(ciphertext, ct_len);
            bio_secure_wipe(tag, sizeof(tag));
            free(ciphertext);
            return BIO_ERR_NOMEM;
        }
        bio_mlock_sensitive(plaintext, ct_len);

        int rc = bio_aes256_gcm_open(bio_fido2_get_wrap_key(), nonce,
                                     aad, sizeof(aad),
                                     ciphertext, ct_len,
                                     tag, plaintext);
        bio_secure_wipe(ciphertext, ct_len);
        free(ciphertext);
        bio_secure_wipe(tag, sizeof(tag));
        bio_secure_wipe(nonce, sizeof(nonce));
        if (rc != BIO_OK)
        {
            BIO_ERROR("FIDO2: credential decryption failed "
                      "(wrong key or tampered file)");
            bio_secure_wipe(plaintext, ct_len);
            bio_munlock_sensitive(plaintext, ct_len);
            free(plaintext);
            return BIO_ERR_CRYPTO_MAC;
        }

        /* Parse plaintext blob */
        size_t off = 0;

        /* PIN state */
        if (off + sizeof(ctx->pin) > ct_len)
        {
            BIO_ERROR("FIDO2: truncated credential store (v2)");
            bio_secure_wipe(plaintext, ct_len);
            bio_munlock_sensitive(plaintext, ct_len);
            free(plaintext);
            return BIO_ERR_IO;
        }
        memcpy(&ctx->pin, plaintext + off, sizeof(ctx->pin));
        off += sizeof(ctx->pin);
        /* Clear session-ephemeral fields that must not survive restart */
        bio_secure_wipe(ctx->pin.platform_key_agreement_x, 32);
        bio_secure_wipe(ctx->pin.platform_key_agreement_y, 32);
        bio_secure_wipe(ctx->pin.shared_secret, 32);
        bio_secure_wipe(ctx->pin.pin_token, sizeof(ctx->pin.pin_token));
        ctx->pin.pin_token_valid = false;
        ctx->pin.pin_token_permissions = 0;
        bio_secure_wipe(ctx->pin.pin_token_rp_id,
                        sizeof(ctx->pin.pin_token_rp_id));
        ctx->pin.pin_token_rp_id_set = false;

        /* Credentials */
        ctx->credential_count = 0;
        for (uint32_t i = 0; i < count && i < CTAP2_MAX_CREDENTIALS_STORED; i++)
        {
            if (off + 1 > ct_len)
                break;
            uint8_t flag = plaintext[off];
            off += 1;
            if (flag != 1)
                continue;

            ctap2_credential_t *c = NULL;
            for (size_t j = 0; j < CTAP2_MAX_CREDENTIALS_STORED; j++)
            {
                if (!ctx->credentials[j].in_use)
                {
                    c = &ctx->credentials[j];
                    break;
                }
            }
            if (!c)
                break;
            /* Defer marking in_use until all fields are parsed */

            if (off + 256 > ct_len)
                break;
            memcpy(c->rp.id, plaintext + off, 256);
            off += 256;
            if (off + 256 > ct_len)
                break;
            memcpy(c->rp.name, plaintext + off, 256);
            off += 256;
            if (off + 32 > ct_len)
                break;
            memcpy(c->rp.id_hash, plaintext + off, 32);
            off += 32;

            if (off + 64 > ct_len)
                break;
            memcpy(c->user.id, plaintext + off, 64);
            off += 64;
            if (off + 2 > ct_len)
                break;
            uint16_t id_len16;
            memcpy(&id_len16, plaintext + off, 2);
            off += 2;
            c->user.id_len = id_len16 <= sizeof(c->user.id)
                                 ? id_len16
                                 : sizeof(c->user.id);
            if (off + 64 > ct_len)
                break;
            memcpy(c->user.name, plaintext + off, 64);
            off += 64;
            if (off + 64 > ct_len)
                break;
            memcpy(c->user.display_name, plaintext + off, 64);
            off += 64;

            if (off + 128 > ct_len)
                break;
            memcpy(c->cred_id.id, plaintext + off, 128);
            off += 128;
            if (off + 2 > ct_len)
                break;
            uint16_t cid_len16;
            memcpy(&cid_len16, plaintext + off, 2);
            off += 2;
            c->cred_id.id_len = cid_len16 <= sizeof(c->cred_id.id)
                                    ? cid_len16
                                    : sizeof(c->cred_id.id);

            if (off + 32 > ct_len)
                break;
            memcpy(c->private_key, plaintext + off, 32);
            off += 32;
            if (off + 65 > ct_len)
                break;
            memcpy(c->public_key, plaintext + off, 65);
            off += 65;

            if (off + 4 > ct_len)
                break;
            memcpy(&c->sign_count, plaintext + off, 4);
            off += 4;
            if (off + 8 > ct_len)
                break;
            memcpy(&c->created, plaintext + off, 8);
            off += 8;
            if (off + 1 > ct_len)
                break;
            c->resident = (plaintext[off] != 0);
            off += 1;
            if (off + 1 > ct_len)
                break;
            {
                uint8_t cp_byte = plaintext[off];
                off += 1;
                /* Backward compat: old format stored uv_required as 0/1.
                 * New format stores cred_protect + 0x10 (0x11-0x13).
                 * Migrate: 0 → level 1, 1 → level 3, ≥0x10 → subtract. */
                if (cp_byte >= 0x10)
                    c->cred_protect = cp_byte - 0x10;
                else if (cp_byte == 0)
                    c->cred_protect = 1;
                else
                    c->cred_protect = 3; /* old uv_required=true → strongest */
            }

            /* All fields parsed successfully — mark credential as valid */
            c->in_use = true;
            ctx->credential_count++;
        }

        bio_secure_wipe(plaintext, ct_len);
        bio_munlock_sensitive(plaintext, ct_len);
        free(plaintext);

        BIO_DEBUG("FIDO2: loaded %zu credentials (v2 encrypted) from %s",
                  ctx->credential_count, path);
        return BIO_OK;
    }
    else if (version == 2 && !bio_fido2_wrap_key_valid())
    {
        /* v2 file but no wrap key — cannot decrypt */
        close(fd);
        BIO_ERROR("FIDO2: encrypted credential store but no wrap key");
        return BIO_ERR_CRYPTO_DECRYPT;
    }
    else
    {
        /* ── Legacy unencrypted format (v1) ── */
        /* PIN state */
        if (read(fd, &ctx->pin, sizeof(ctx->pin)) !=
            (ssize_t)sizeof(ctx->pin))
        {
            close(fd);
            return BIO_ERR_IO;
        }
        /* Clear session-ephemeral fields that must not survive restart */
        bio_secure_wipe(ctx->pin.platform_key_agreement_x, 32);
        bio_secure_wipe(ctx->pin.platform_key_agreement_y, 32);
        bio_secure_wipe(ctx->pin.shared_secret, 32);
        bio_secure_wipe(ctx->pin.pin_token, sizeof(ctx->pin.pin_token));
        ctx->pin.pin_token_valid = false;
        ctx->pin.pin_token_permissions = 0;
        bio_secure_wipe(ctx->pin.pin_token_rp_id,
                        sizeof(ctx->pin.pin_token_rp_id));
        ctx->pin.pin_token_rp_id_set = false;

        /* Credentials */
        ctx->credential_count = 0;
        for (uint32_t i = 0; i < count &&
                             i < CTAP2_MAX_CREDENTIALS_STORED;
             i++)
        {
            uint8_t flag;
            if (read(fd, &flag, 1) != 1)
                break;
            if (flag != 1)
                continue;

            ctap2_credential_t *c = NULL;
            for (size_t j = 0; j < CTAP2_MAX_CREDENTIALS_STORED; j++)
            {
                if (!ctx->credentials[j].in_use)
                {
                    c = &ctx->credentials[j];
                    break;
                }
            }
            if (!c)
                break;

            if (read(fd, c->rp.id, sizeof(c->rp.id)) !=
                (ssize_t)sizeof(c->rp.id))
                break;
            if (read(fd, c->rp.name, sizeof(c->rp.name)) !=
                (ssize_t)sizeof(c->rp.name))
                break;
            if (read(fd, c->rp.id_hash, 32) != 32)
                break;

            if (read(fd, c->user.id, sizeof(c->user.id)) !=
                (ssize_t)sizeof(c->user.id))
                break;
            uint16_t id_len16;
            if (read(fd, &id_len16, 2) != 2)
                break;
            c->user.id_len = id_len16 <= sizeof(c->user.id)
                                 ? id_len16
                                 : sizeof(c->user.id);
            if (read(fd, c->user.name, sizeof(c->user.name)) !=
                (ssize_t)sizeof(c->user.name))
                break;
            if (read(fd, c->user.display_name,
                     sizeof(c->user.display_name)) !=
                (ssize_t)sizeof(c->user.display_name))
                break;

            if (read(fd, c->cred_id.id, sizeof(c->cred_id.id)) !=
                (ssize_t)sizeof(c->cred_id.id))
                break;
            uint16_t cid_len16;
            if (read(fd, &cid_len16, 2) != 2)
                break;
            c->cred_id.id_len = cid_len16 <= sizeof(c->cred_id.id)
                                    ? cid_len16
                                    : sizeof(c->cred_id.id);

            if (read(fd, c->private_key, 32) != 32)
                break;
            if (read(fd, c->public_key, 65) != 65)
                break;

            if (read(fd, &c->sign_count, 4) != 4)
                break;
            if (read(fd, &c->created, 8) != 8)
                break;
            uint8_t r;
            if (read(fd, &r, 1) != 1)
                break;
            c->resident = (r != 0);
            uint8_t uv;
            if (read(fd, &uv, 1) != 1)
                break;
            /* Legacy v1 format: 0 → level 1, 1 → level 3 */
            c->cred_protect = (uv != 0) ? 3 : 1;

            /* All fields parsed successfully — mark credential as valid */
            c->in_use = true;
            ctx->credential_count++;
        }

        close(fd);

        /* Auto-upgrade: re-save as encrypted v2 if wrap key is available */
        if (bio_fido2_wrap_key_valid() && ctx->credential_count > 0)
        {
            BIO_INFO("FIDO2: upgrading credential store from v1 "
                     "(plaintext) to v2 (encrypted)");
            bio_fido2_save_credentials(ctx);
        }

        BIO_DEBUG("FIDO2: loaded %zu credentials (legacy v1) from %s",
                  ctx->credential_count, path);
        return BIO_OK;
    }
}
