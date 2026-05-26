/*
 * bio_fido2.c — FIDO2/CTAP2 Authenticator Engine (Part 1: Core + GetInfo)
 *
 * Copyright (C) 2024 Hiya Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "fido2/bio_fido2.h"
#include "cbor/bio_cbor.h"
#include "crypto/bio_crypto.h"
#include "tpm/bio_tpm.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

/* ── Internal helpers ────────────────────────────────────────── */

static const uint8_t AAGUID[16] = HIYA_AAGUID;

/*
 * Build COSE_Key map for P-256 public key:
 *   { 1: 2 (EC2), 3: -7 (ES256), -1: 1 (P-256), -2: x, -3: y }
 */
int encode_cose_pubkey(bio_cbor_encoder_t *enc,
                       const uint8_t pubkey[65])
{
    /* pubkey[0] == 0x04 (uncompressed), then 32-byte x, 32-byte y */
    if (pubkey[0] != 0x04)
        return BIO_ERR_INVALID_PARAM;

    const uint8_t *x = pubkey + 1;
    const uint8_t *y = pubkey + 33;

    bio_cbor_encode_map(enc, 5);

    /* Key type: 1 → 2 (EC2) */
    bio_cbor_encode_uint(enc, 1);
    bio_cbor_encode_uint(enc, COSE_KTY_EC2);

    /* Algorithm: 3 → -7 (ES256) */
    bio_cbor_encode_uint(enc, 3);
    bio_cbor_encode_negint(enc, 6); /* -7 = -(1+6) */

    /* Curve: -1 → 1 (P-256) */
    bio_cbor_encode_negint(enc, 0); /* -1 = -(1+0) */
    bio_cbor_encode_uint(enc, COSE_CRV_P256);

    /* x-coord: -2 → bstr(32) */
    bio_cbor_encode_negint(enc, 1); /* -2 = -(1+1) */
    bio_cbor_encode_bstr(enc, x, 32);

    /* y-coord: -3 → bstr(32) */
    bio_cbor_encode_negint(enc, 2); /* -3 = -(1+2) */
    bio_cbor_encode_bstr(enc, y, 32);

    return BIO_OK;
}

/*
 * Build authenticatorData:
 *   rpIdHash (32) || flags (1) || signCount (4) || [attestedCredData] || [extensions]
 *
 * attestedCredData:
 *   aaguid (16) || credIdLen (2 BE) || credId || credentialPublicKey (CBOR)
 */
int build_auth_data(uint8_t *out, size_t *out_len,
                    const uint8_t rp_id_hash[32],
                    uint8_t flags,
                    uint32_t sign_count,
                    const ctap2_credential_id_t *cred_id,
                    const uint8_t *pubkey)
{
    size_t pos = 0;
    size_t cap = *out_len;

    /* rpIdHash */
    if (pos + 32 > cap)
        return BIO_ERR_BUFFER_TOO_SMALL;
    memcpy(out + pos, rp_id_hash, 32);
    pos += 32;

    /* flags */
    if (pos + 1 > cap)
        return BIO_ERR_BUFFER_TOO_SMALL;
    out[pos++] = flags;

    /* signCount (big-endian) */
    if (pos + 4 > cap)
        return BIO_ERR_BUFFER_TOO_SMALL;
    out[pos++] = (sign_count >> 24) & 0xFF;
    out[pos++] = (sign_count >> 16) & 0xFF;
    out[pos++] = (sign_count >> 8) & 0xFF;
    out[pos++] = sign_count & 0xFF;

    /* Attested credential data (if AT flag set) */
    if ((flags & CTAP2_FLAG_AT) && cred_id && pubkey)
    {
        /* AAGUID */
        if (pos + 16 > cap)
            return BIO_ERR_BUFFER_TOO_SMALL;
        memcpy(out + pos, AAGUID, 16);
        pos += 16;

        /* credIdLen */
        if (pos + 2 > cap)
            return BIO_ERR_BUFFER_TOO_SMALL;
        out[pos++] = (cred_id->id_len >> 8) & 0xFF;
        out[pos++] = cred_id->id_len & 0xFF;

        /* credId */
        if (pos + cred_id->id_len > cap)
            return BIO_ERR_BUFFER_TOO_SMALL;
        memcpy(out + pos, cred_id->id, cred_id->id_len);
        pos += cred_id->id_len;

        /* credentialPublicKey (COSE_Key as CBOR) */
        bio_cbor_encoder_t enc;
        bio_cbor_encoder_init(&enc, out + pos, cap - pos);
        int rc = encode_cose_pubkey(&enc, pubkey);
        if (rc != BIO_OK)
            return rc;
        if (enc.error)
            return BIO_ERR_BUFFER_TOO_SMALL;
        pos += enc.offset;
    }

    *out_len = pos;
    return BIO_OK;
}

/*
 * Generate a credential ID.
 * We use: AES-256-GCM(random_nonce, private_key || rp_id_hash)
 * This makes credential IDs self-contained — we can decrypt them
 * to recover the private key for non-resident credentials.
 *
 * Format: nonce(12) || ciphertext(64) || tag(16) = 92 bytes
 *   plaintext = private_key(32) || rp_id_hash(32)
 */
int generate_credential_id(ctap2_credential_id_t *cred_id,
                           const uint8_t privkey[32],
                           const uint8_t rp_id_hash[32],
                           const uint8_t wrap_key[32])
{
    uint8_t nonce[12];
    int rc = bio_random_bytes(nonce, sizeof(nonce));
    if (rc != BIO_OK)
        return rc;

    uint8_t plaintext[64];
    bio_mlock_sensitive(plaintext, sizeof(plaintext));
    memcpy(plaintext, privkey, 32);
    memcpy(plaintext + 32, rp_id_hash, 32);

    uint8_t ciphertext[64];
    uint8_t tag[16];

    rc = bio_aes256_gcm_seal(wrap_key, nonce,
                             NULL, 0, /* no AAD */
                             plaintext, sizeof(plaintext),
                             ciphertext, tag);
    bio_secure_wipe(plaintext, sizeof(plaintext));
    bio_munlock_sensitive(plaintext, sizeof(plaintext));
    if (rc != BIO_OK)
        return rc;

    /* Pack: nonce || ciphertext || tag */
    cred_id->id_len = 12 + 64 + 16; /* = 92 bytes */
    memcpy(cred_id->id, nonce, 12);
    memcpy(cred_id->id + 12, ciphertext, 64);
    memcpy(cred_id->id + 76, tag, 16);

    return BIO_OK;
}

/*
 * Recover private key from credential ID.
 * Decrypts the credential ID using the wrap key.
 * Also verifies the embedded rp_id_hash matches.
 */
int unwrap_credential_id(const ctap2_credential_id_t *cred_id,
                         const uint8_t wrap_key[32],
                         const uint8_t rp_id_hash[32],
                         uint8_t privkey_out[32])
{
    if (cred_id->id_len != 92)
        return CTAP2_ERR_INVALID_CREDENTIAL;

    const uint8_t *nonce = cred_id->id;
    const uint8_t *ct = cred_id->id + 12;
    const uint8_t *tag = cred_id->id + 76;

    uint8_t plaintext[64];
    bio_mlock_sensitive(plaintext, sizeof(plaintext));

    int rc = bio_aes256_gcm_open(wrap_key, nonce,
                                 NULL, 0,
                                 ct, 64,
                                 tag, plaintext);
    if (rc != BIO_OK)
    {
        bio_secure_wipe(plaintext, sizeof(plaintext));
        bio_munlock_sensitive(plaintext, sizeof(plaintext));
        return CTAP2_ERR_INVALID_CREDENTIAL;
    }

    /* Verify RP ID hash matches */
    if (bio_constant_time_compare(plaintext + 32, rp_id_hash, 32) != 0)
    {
        bio_secure_wipe(plaintext, sizeof(plaintext));
        bio_munlock_sensitive(plaintext, sizeof(plaintext));
        return CTAP2_ERR_INVALID_CREDENTIAL;
    }

    memcpy(privkey_out, plaintext, 32);
    bio_secure_wipe(plaintext, sizeof(plaintext));
    bio_munlock_sensitive(plaintext, sizeof(plaintext));
    return CTAP2_OK;
}

/* ── Credential storage ──────────────────────────────────────── */

/*
 * Master wrap key: derived from a random seed sealed to TPM.
 * When TPM is available, the wrap key is sealed to the TPM so that
 * it cannot be extracted without the correct platform state (PCRs).
 * The sealed blob is stored in wrap_key.sealed; the raw key is only
 * available in memory after TPM unseal.
 *
 * Without TPM, the key is stored in plaintext at wrap_key.raw,
 * protected only by file permissions (0600).
 *
 * Note: Not static — accessed via extern from bio_fido2_credential.c
 * and bio_fido2_pin.c within the same FIDO2 static library.
 */
/* Wrap key — internal linkage, hidden from dynamic linker (VULN-23 fix) */
static uint8_t g_wrap_key[32];
static bool g_wrap_key_valid = false;

const uint8_t *bio_fido2_get_wrap_key(void) { return g_wrap_key_valid ? g_wrap_key : NULL; }
bool bio_fido2_wrap_key_valid(void) { return g_wrap_key_valid; }

static int ensure_wrap_key(bio_fido2_ctx_t *ctx)
{
    if (g_wrap_key_valid)
        return BIO_OK;

    char raw_path[512], sealed_path[512];
    snprintf(raw_path, sizeof(raw_path), "%s/wrap_key", ctx->storage_path);
    snprintf(sealed_path, sizeof(sealed_path), "%s/wrap_key.sealed",
             ctx->storage_path);

    /* Lock the key memory to prevent swap-out */
    bio_mlock_sensitive(g_wrap_key, sizeof(g_wrap_key));

    /* Try TPM-sealed path first */
    int fd = open(sealed_path, O_RDONLY);
    if (fd >= 0)
    {
        uint8_t sealed_blob[1024];
        ssize_t n = read(fd, sealed_blob, sizeof(sealed_blob));
        close(fd);

        if (n > 0)
        {
            bio_tpm_ctx_t tpm;
            if (bio_tpm_init(&tpm, NULL) == BIO_OK)
            {
                size_t out_len = 32;
                int rc = bio_tpm_unseal_for_user(
                    &tpm, sealed_blob, (size_t)n,
                    NULL, 0, g_wrap_key, &out_len);
                bio_tpm_cleanup(&tpm);

                if (rc == BIO_OK && out_len == 32)
                {
                    bio_secure_wipe(sealed_blob, sizeof(sealed_blob));
                    g_wrap_key_valid = true;
                    BIO_INFO("FIDO2: wrap key unsealed from TPM");
                    return BIO_OK;
                }
                BIO_WARN("FIDO2: TPM unseal of wrap key failed: %s",
                         bio_error_str(rc));
            }
        }
        bio_secure_wipe(sealed_blob, sizeof(sealed_blob));
    }

    /* Try raw key file (legacy / no-TPM path) */
    fd = open(raw_path, O_RDONLY);
    if (fd >= 0)
    {
        ssize_t n = read(fd, g_wrap_key, 32);
        close(fd);
        if (n == 32)
        {
            g_wrap_key_valid = true;

            /* Opportunistically seal to TPM if available */
            bio_tpm_ctx_t tpm;
            if (bio_tpm_init(&tpm, NULL) == BIO_OK)
            {
                uint8_t sealed_blob[1024];
                size_t sealed_len = sizeof(sealed_blob);
                if (bio_tpm_seal_for_user(&tpm, g_wrap_key, 32,
                                          NULL, 0,
                                          sealed_blob, &sealed_len) == BIO_OK)
                {
                    int sfd = open(sealed_path,
                                   O_WRONLY | O_CREAT | O_TRUNC, 0600);
                    if (sfd >= 0)
                    {
                        ssize_t w = write(sfd, sealed_blob, sealed_len);
                        close(sfd);
                        if (w == (ssize_t)sealed_len)
                        {
                            /* Remove plaintext key file */
                            unlink(raw_path);
                            BIO_INFO("FIDO2: wrap key migrated to "
                                     "TPM-sealed storage");
                        }
                    }
                }
                bio_secure_wipe(sealed_blob, sizeof(sealed_blob));
                bio_tpm_cleanup(&tpm);
            }

            return BIO_OK;
        }

        /* Reject and scrub partial key reads. */
        bio_secure_wipe(g_wrap_key, sizeof(g_wrap_key));
    }

    /* Generate new wrap key */
    int rc = bio_random_bytes(g_wrap_key, 32);
    if (rc != BIO_OK)
        return rc;

    /* Ensure directory exists */
    mkdir(ctx->storage_path, 0700);

    /* Try to seal to TPM first */
    bio_tpm_ctx_t tpm;
    if (bio_tpm_init(&tpm, NULL) == BIO_OK)
    {
        uint8_t sealed_blob[1024];
        size_t sealed_len = sizeof(sealed_blob);
        rc = bio_tpm_seal_for_user(&tpm, g_wrap_key, 32,
                                   NULL, 0,
                                   sealed_blob, &sealed_len);
        bio_tpm_cleanup(&tpm);

        if (rc == BIO_OK)
        {
            fd = open(sealed_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
            if (fd >= 0)
            {
                ssize_t w = write(fd, sealed_blob, sealed_len);
                close(fd);
                if (w == (ssize_t)sealed_len)
                {
                    bio_secure_wipe(sealed_blob, sizeof(sealed_blob));
                    g_wrap_key_valid = true;
                    BIO_INFO("FIDO2: new wrap key sealed to TPM");
                    return BIO_OK;
                }
            }
        }
        bio_secure_wipe(sealed_blob, sizeof(sealed_blob));
    }

    /* SECURITY: refuse to store wrap key without TPM (VULN-04 fix).
     * Keep the key in memory only for this session. Without TPM,
     * credentials will be lost on daemon restart — this is intentional
     * to prevent plaintext key material on disk. */
    BIO_ERROR("FIDO2: no TPM available — wrap key exists in memory only. "
              "Credentials will NOT persist across restarts.");
    g_wrap_key_valid = true;
    return BIO_OK;
}

/* ── Init / Cleanup ──────────────────────────────────────────── */

int bio_fido2_init(bio_fido2_ctx_t *ctx, const char *path)
{
    if (!ctx)
        return BIO_ERR_INVALID_PARAM;

    /* Ensure crypto subsystem is initialized (idempotent) */
    int crc = bio_crypto_init();
    if (crc != BIO_OK)
    {
        BIO_ERROR("FIDO2: crypto not initialized");
        return crc;
    }

    memset(ctx, 0, sizeof(*ctx));

    /* Best-effort: keep authenticator state in RAM only (no swap/core dumps). */
    bio_mlock_sensitive(ctx, sizeof(*ctx));

    if (path)
    {
        strncpy(ctx->storage_path, path, sizeof(ctx->storage_path) - 1);
    }
    else
    {
        strncpy(ctx->storage_path, HIYA_STATE_DIR "/fido2",
                sizeof(ctx->storage_path) - 1);
    }

    /* Ensure storage dir */
    mkdir(ctx->storage_path, 0700);

    /* Init PIN state */
    ctx->pin.pin_retries = CTAP2_MAX_PIN_RETRIES;

    /* Reinforce locking on frequently-accessed secret regions. */
    bio_mlock_sensitive(&ctx->pin, sizeof(ctx->pin));
    bio_mlock_sensitive(ctx->auth_privkey, sizeof(ctx->auth_privkey));
    bio_mlock_sensitive(ctx->credentials, sizeof(ctx->credentials));

    /* Init mutex for thread safety (VULN-01 fix) */
    pthread_mutex_init(&ctx->mutex, NULL);

    /* Record init timestamp for reset window (VULN-07 fix) */
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    ctx->init_timestamp = (uint64_t)ts.tv_sec;

    /* Generate authenticator key agreement key pair */
    bio_ecdh_keypair kp;
    int rc = bio_ecdh_keygen(&kp);
    if (rc != BIO_OK)
    {
        BIO_ERROR("FIDO2: ECDH keygen failed: %s", bio_error_str(rc));
        return rc;
    }
    memcpy(ctx->auth_privkey, kp.private_key, 32);
    memcpy(ctx->auth_pubkey, kp.public_key, 65);
    bio_secure_wipe(&kp, sizeof(kp));

    /* Ensure wrap key exists */
    rc = ensure_wrap_key(ctx);
    if (rc != BIO_OK)
    {
        BIO_ERROR("FIDO2: could not initialize wrap key: %s",
                  bio_error_str(rc));
        return rc;
    }

    /* Load stored credentials */
    rc = bio_fido2_load_credentials(ctx);
    if (rc != BIO_OK)
    {
        BIO_WARN("FIDO2: could not load credentials: %s",
                 bio_error_str(rc));
        /* Non-fatal: start with empty store */
    }

    BIO_INFO("FIDO2 authenticator initialized (%zu credentials loaded)",
             ctx->credential_count);
    return BIO_OK;
}

void bio_fido2_cleanup(bio_fido2_ctx_t *ctx)
{
    if (!ctx)
        return;

    /* Save credentials before cleanup */
    bio_fido2_save_credentials(ctx);

    /* Wipe bio enrollment and credential enumeration state */
    bio_fido2_bio_reset();

    /* Wipe global wrap key */
    bio_secure_wipe(g_wrap_key, sizeof(g_wrap_key));
    bio_munlock_sensitive(g_wrap_key, sizeof(g_wrap_key));
    g_wrap_key_valid = false;

    /* Securely wipe all sensitive state */
    for (size_t i = 0; i < CTAP2_MAX_CREDENTIALS_STORED; i++)
    {
        if (ctx->credentials[i].in_use)
        {
            bio_secure_wipe(ctx->credentials[i].private_key, 32);
        }
    }
    bio_secure_wipe(ctx->auth_privkey, 32);
    bio_secure_wipe(&ctx->pin, sizeof(ctx->pin));

    /* Release locked pages before final context wipe. */
    bio_munlock_sensitive(&ctx->pin, sizeof(ctx->pin));
    bio_munlock_sensitive(ctx->auth_privkey, sizeof(ctx->auth_privkey));
    bio_munlock_sensitive(ctx->credentials, sizeof(ctx->credentials));
    bio_munlock_sensitive(ctx, sizeof(*ctx));

    /* Destroy mutex (VULN-01 fix) */
    pthread_mutex_destroy(&ctx->mutex);

    bio_secure_wipe(ctx, sizeof(*ctx));
}

void bio_fido2_set_uv_callback(bio_fido2_ctx_t *ctx,
                               bool (*cb)(void *), void *user_ctx)
{
    if (ctx)
    {
        ctx->verify_user = cb;
        ctx->verify_user_ctx = user_ctx;
    }
}

/* ── authenticatorGetInfo (0x04) ─────────────────────────────── */

uint8_t ctap2_get_info(bio_fido2_ctx_t *ctx,
                       uint8_t *rsp, size_t *rsp_len)
{
    bio_cbor_encoder_t enc;
    bio_cbor_encoder_init(&enc, rsp, *rsp_len);

    /* Response is a CBOR map */
    bio_cbor_encode_map(&enc, 11);

    /* 0x01: versions (array of strings) */
    bio_cbor_encode_uint(&enc, 0x01);
    bio_cbor_encode_array(&enc, 3);
    bio_cbor_encode_tstr_z(&enc, "FIDO_2_0");
    bio_cbor_encode_tstr_z(&enc, "FIDO_2_1_PRE");
    bio_cbor_encode_tstr_z(&enc, "FIDO_2_1");

    /* 0x02: extensions (array of strings) */
    bio_cbor_encode_uint(&enc, 0x02);
    bio_cbor_encode_array(&enc, 3);
    bio_cbor_encode_tstr_z(&enc, "credProtect");
    bio_cbor_encode_tstr_z(&enc, "credentialMgmtPreview");
    bio_cbor_encode_tstr_z(&enc, "hmac-secret");

    /* 0x03: aaguid (bstr 16) */
    bio_cbor_encode_uint(&enc, 0x03);
    bio_cbor_encode_bstr(&enc, AAGUID, 16);

    /* 0x04: options (map) */
    bio_cbor_encode_uint(&enc, 0x04);
    bio_cbor_encode_map(&enc, 10);

    bio_cbor_encode_tstr_z(&enc, "plat"); /* platform authenticator */
    bio_cbor_encode_bool(&enc, true);

    bio_cbor_encode_tstr_z(&enc, "rk"); /* resident key */
    bio_cbor_encode_bool(&enc, true);

    bio_cbor_encode_tstr_z(&enc, "up"); /* user presence */
    bio_cbor_encode_bool(&enc, true);

    bio_cbor_encode_tstr_z(&enc, "uv"); /* user verification */
    bio_cbor_encode_bool(&enc, true);

    bio_cbor_encode_tstr_z(&enc, "clientPin");
    bio_cbor_encode_bool(&enc, ctx->pin.pin_set);

    bio_cbor_encode_tstr_z(&enc, "bioEnroll"); /* bio enrollment */
    bio_cbor_encode_bool(&enc, true);

    bio_cbor_encode_tstr_z(&enc, "credMgmt"); /* credential management */
    bio_cbor_encode_bool(&enc, true);

    bio_cbor_encode_tstr_z(&enc, "pinUvAuthToken"); /* PIN/UV auth token */
    bio_cbor_encode_bool(&enc, true);

    bio_cbor_encode_tstr_z(&enc, "alwaysUv");
    bio_cbor_encode_bool(&enc, true);

    bio_cbor_encode_tstr_z(&enc, "makeCredUvNotRqd");
    bio_cbor_encode_bool(&enc, false);

    /* 0x05: maxMsgSize */
    bio_cbor_encode_uint(&enc, 0x05);
    bio_cbor_encode_uint(&enc, 4096);

    /* 0x06: pinUvAuthProtocols (array) */
    bio_cbor_encode_uint(&enc, 0x06);
    bio_cbor_encode_array(&enc, 1);
    bio_cbor_encode_uint(&enc, 1); /* Protocol 1 only (browser compat) */

    /* 0x07: maxCredentialCountInList */
    bio_cbor_encode_uint(&enc, 0x07);
    bio_cbor_encode_uint(&enc, CTAP2_MAX_ALLOW_LIST);

    /* 0x08: maxCredentialIdLength */
    bio_cbor_encode_uint(&enc, 0x08);
    bio_cbor_encode_uint(&enc, CTAP2_MAX_CREDENTIAL_ID_LEN);

    /* 0x09: transports (array) */
    bio_cbor_encode_uint(&enc, 0x09);
    bio_cbor_encode_array(&enc, 1);
    bio_cbor_encode_tstr_z(&enc, "internal");

    /* 0x0A: algorithms (array of credential params) */
    bio_cbor_encode_uint(&enc, 0x0A);
    bio_cbor_encode_array(&enc, 1);
    bio_cbor_encode_map(&enc, 2);
    bio_cbor_encode_tstr_z(&enc, "alg");
    bio_cbor_encode_negint(&enc, 6); /* ES256 = -7 */
    bio_cbor_encode_tstr_z(&enc, "type");
    bio_cbor_encode_tstr_z(&enc, "public-key");

    /* 0x18: remainingDiscoverableCredentials (CTAP2.1 §6.4 key 24) */
    bio_cbor_encode_uint(&enc, 0x18);
    size_t remaining = CTAP2_MAX_CREDENTIALS_STORED - ctx->credential_count;
    bio_cbor_encode_uint(&enc, remaining);

    if (enc.error)
        return CTAP2_ERR_OTHER;

    *rsp_len = enc.offset;
    return CTAP2_OK;
}

/* ── Command dispatcher ──────────────────────────────────────── */

uint8_t bio_fido2_process(bio_fido2_ctx_t *ctx,
                          uint8_t cmd,
                          const uint8_t *request, size_t request_len,
                          uint8_t *response, size_t *response_len)
{
    /* Serialize all CTAP2 processing (VULN-01 fix) */
    pthread_mutex_lock(&ctx->mutex);

    /* CTAP2 §5.2: Any command other than GetNextAssertion invalidates
       the assertion state to prevent cross-RP information leaks. */
    if (cmd != CTAP2_CMD_GET_NEXT_ASSERTION)
    {
        ctx->assertion_match_count = 0;
        ctx->assertion_index = 0;
        ctx->assertion_timestamp = 0;
    }

    uint8_t result;

    switch (cmd)
    {
    case CTAP2_CMD_MAKE_CREDENTIAL:
        result = ctap2_make_credential(ctx, request, request_len,
                                       response, response_len);
        break;
    case CTAP2_CMD_GET_ASSERTION:
        result = ctap2_get_assertion(ctx, request, request_len,
                                     response, response_len);
        break;
    case CTAP2_CMD_GET_INFO:
        result = ctap2_get_info(ctx, response, response_len);
        break;

    case CTAP2_CMD_CLIENT_PIN:
        result = ctap2_client_pin(ctx, request, request_len,
                                  response, response_len);
        break;

    case CTAP2_CMD_RESET:
        result = ctap2_reset(ctx);
        *response_len = 0;
        break;

    case CTAP2_CMD_GET_NEXT_ASSERTION:
        result = ctap2_get_next_assertion(ctx, response, response_len);
        break;

    case CTAP2_CMD_SELECTION:
        result = ctap2_selection(ctx);
        *response_len = 0;
        break;

    case CTAP2_CMD_BIO_ENROLLMENT:
        result = ctap2_bio_enrollment(ctx, request, request_len,
                                      response, response_len);
        break;

    case CTAP2_CMD_CREDENTIAL_MANAGEMENT:
        result = ctap2_credential_management(ctx, request, request_len,
                                             response, response_len);
        break;

    default:
        result = CTAP1_ERR_INVALID_COMMAND;
        *response_len = 0;
        break;
    }

    pthread_mutex_unlock(&ctx->mutex);
    return result;
}
