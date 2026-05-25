/*
 * bio_crypto.c — Crypto wrapper implementation delegating to mbedtls
 *
 * Copyright (C) 2024 BioAuth Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Every function in this file is a thin wrapper around mbedtls.
 * We translate mbedtls error codes to BIO_ERR_CRYPTO_* codes and
 * ensure proper cleanup (wipe) on every path.
 */

#include "bio_crypto.h"

#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <pthread.h>

/* mbedtls headers — we pull in ONLY what we need */
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <mbedtls/md.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/gcm.h>
#include <mbedtls/aes.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>
#include <mbedtls/bignum.h>
#include <mbedtls/platform_util.h> /* mbedtls_platform_zeroize */

/* ── Global state ─────────────────────────────────────────────── */

static mbedtls_entropy_context g_entropy;
static mbedtls_ctr_drbg_context g_ctr_drbg;
static bool g_initialized = false;

/* Mutex protecting all CTR-DRBG operations — V-CRYPTO-01 fix */
static pthread_mutex_t g_drbg_mutex = PTHREAD_MUTEX_INITIALIZER;

/*
 * Thread-safe DRBG wrapper — all crypto functions use this instead
 * of calling mbedtls_ctr_drbg_random directly.
 */
static int bio_drbg_random(void *p_rng, unsigned char *output,
                           size_t output_len)
{
    (void)p_rng;
    pthread_mutex_lock(&g_drbg_mutex);
    if (!g_initialized)
    {
        pthread_mutex_unlock(&g_drbg_mutex);
        return MBEDTLS_ERR_CTR_DRBG_REQUEST_TOO_BIG;
    }
    int ret = mbedtls_ctr_drbg_random(&g_ctr_drbg, output, output_len);
    pthread_mutex_unlock(&g_drbg_mutex);
    return ret;
}

/* Personalization string for CTR-DRBG */
static const char *DRBG_PERS = "bioauth-crypto-v1";

/* ── Lifecycle ─────────────────────────────────────────────────── */

/*
 * Thread-safe init via mutex — allows re-initialization after cleanup.
 * pthread_once is one-shot and cannot be reset after bio_crypto_cleanup().
 */
static pthread_mutex_t g_init_mutex = PTHREAD_MUTEX_INITIALIZER;

static void do_crypto_init_unlocked(void)
{
    mbedtls_entropy_init(&g_entropy);
    mbedtls_ctr_drbg_init(&g_ctr_drbg);

    int ret = mbedtls_ctr_drbg_seed(&g_ctr_drbg,
                                    mbedtls_entropy_func,
                                    &g_entropy,
                                    (const uint8_t *)DRBG_PERS,
                                    strlen(DRBG_PERS));
    if (ret != 0)
    {
        BIO_ERROR("mbedtls CTR-DRBG seed failed: -0x%04x", (unsigned)-ret);
        mbedtls_ctr_drbg_free(&g_ctr_drbg);
        mbedtls_entropy_free(&g_entropy);
        return;
    }

    /* Enable prediction resistance (reseed from entropy before each generate) */
    mbedtls_ctr_drbg_set_prediction_resistance(&g_ctr_drbg,
                                               MBEDTLS_CTR_DRBG_PR_ON);

    g_initialized = true;
    BIO_DEBUG("Crypto subsystem initialized (mbedtls CTR-DRBG + entropy)");
}

int bio_crypto_init(void)
{
    pthread_mutex_lock(&g_init_mutex);
    if (!g_initialized)
    {
        do_crypto_init_unlocked();
    }
    int rc = g_initialized ? BIO_OK : BIO_ERR_CRYPTO_INIT;
    pthread_mutex_unlock(&g_init_mutex);
    return rc;
}

void bio_crypto_cleanup(void)
{
    pthread_mutex_lock(&g_init_mutex);
    if (!g_initialized)
    {
        pthread_mutex_unlock(&g_init_mutex);
        return;
    }

    /* Mark uninitialized first to reject new callers */
    g_initialized = false;

    /* Acquire DRBG mutex to wait for any in-flight operations */
    pthread_mutex_lock(&g_drbg_mutex);
    mbedtls_ctr_drbg_free(&g_ctr_drbg);
    mbedtls_entropy_free(&g_entropy);
    pthread_mutex_unlock(&g_drbg_mutex);

    pthread_mutex_unlock(&g_init_mutex);
    BIO_DEBUG("Crypto subsystem cleaned up");
}

/* ── Random ────────────────────────────────────────────────────── */

int bio_random_bytes(uint8_t *buf, size_t len)
{
    if (!buf)
        return BIO_ERR_INVALID_PARAM;
    if (len == 0)
        return BIO_ERR_INVALID_PARAM;
    if (!g_initialized)
        return BIO_ERR_NOT_INITIALIZED;

    int ret = bio_drbg_random(NULL, buf, len);
    if (ret != 0)
    {
        BIO_ERROR("CTR-DRBG random failed: -0x%04x", (unsigned)-ret);
        bio_secure_wipe(buf, len);
        return BIO_ERR_CRYPTO_RANDOM;
    }
    return BIO_OK;
}

/* ── SHA-256 ───────────────────────────────────────────────────── */

int bio_sha256(const uint8_t *data, size_t len, uint8_t digest[32])
{
    if (!data || !digest)
        return BIO_ERR_INVALID_PARAM;

    /* mbedtls_sha256: last param 0 = SHA-256 (not SHA-224) */
    int ret = mbedtls_sha256(data, len, digest, 0);
    if (ret != 0)
    {
        BIO_ERROR("SHA-256 failed: -0x%04x", (unsigned)-ret);
        return BIO_ERR_CRYPTO_HASH;
    }
    return BIO_OK;
}

int bio_sha1(const uint8_t *data, size_t len, uint8_t digest[20])
{
    if (!data || !digest)
        return BIO_ERR_INVALID_PARAM;

    int ret = mbedtls_sha1(data, len, digest);
    if (ret != 0)
    {
        BIO_ERROR("SHA-1 failed: -0x%04x", (unsigned)-ret);
        return BIO_ERR_CRYPTO_HASH;
    }
    return BIO_OK;
}

/* ── HMAC-SHA-256 ──────────────────────────────────────────────── */

int bio_hmac_sha256(const uint8_t *key, size_t key_len,
                    const uint8_t *data, size_t data_len,
                    uint8_t mac[32])
{
    if (!key || !data || !mac)
        return BIO_ERR_INVALID_PARAM;

    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md_info)
        return BIO_ERR_CRYPTO_MAC;

    int ret = mbedtls_md_hmac(md_info, key, key_len, data, data_len, mac);
    if (ret != 0)
    {
        BIO_ERROR("HMAC-SHA-256 failed: -0x%04x", (unsigned)-ret);
        bio_secure_wipe(mac, 32);
        return BIO_ERR_CRYPTO_MAC;
    }
    return BIO_OK;
}

/* ── HKDF-SHA-256 ──────────────────────────────────────────────── */

int bio_hkdf_sha256(const uint8_t *salt, size_t salt_len,
                    const uint8_t *ikm, size_t ikm_len,
                    const uint8_t *info, size_t info_len,
                    uint8_t *okm, size_t okm_len)
{
    if (!ikm || !okm)
        return BIO_ERR_INVALID_PARAM;
    if (info_len > 0 && !info)
        return BIO_ERR_INVALID_PARAM;

    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md_info)
        return BIO_ERR_CRYPTO_MAC;

    int ret = mbedtls_hkdf(md_info,
                           salt, salt_len,
                           ikm, ikm_len,
                           info, info_len,
                           okm, okm_len);
    if (ret != 0)
    {
        BIO_ERROR("HKDF-SHA-256 failed: -0x%04x", (unsigned)-ret);
        bio_secure_wipe(okm, okm_len);
        return BIO_ERR_CRYPTO_MAC;
    }
    return BIO_OK;
}

/* ── AES-256-GCM ──────────────────────────────────────────────── */

int bio_aes256_gcm_seal(const uint8_t key[32],
                        const uint8_t iv[12],
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *pt, size_t pt_len,
                        uint8_t *ct, uint8_t tag[16])
{
    if (!key || !iv || !ct || !tag)
        return BIO_ERR_INVALID_PARAM;
    if (pt_len > 0 && !pt)
        return BIO_ERR_INVALID_PARAM;
    if (aad_len > 0 && !aad)
        return BIO_ERR_INVALID_PARAM;

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);

    int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (ret != 0)
    {
        BIO_ERROR("GCM setkey failed: -0x%04x", (unsigned)-ret);
        mbedtls_gcm_free(&gcm);
        return BIO_ERR_CRYPTO_ENCRYPT;
    }

    ret = mbedtls_gcm_crypt_and_tag(&gcm,
                                    MBEDTLS_GCM_ENCRYPT,
                                    pt_len,
                                    iv, 12,
                                    aad, aad_len,
                                    pt, ct,
                                    16, tag);
    mbedtls_gcm_free(&gcm);

    if (ret != 0)
    {
        BIO_ERROR("GCM encrypt failed: -0x%04x", (unsigned)-ret);
        bio_secure_wipe(ct, pt_len);
        bio_secure_wipe(tag, 16);
        return BIO_ERR_CRYPTO_ENCRYPT;
    }
    return BIO_OK;
}

int bio_aes256_gcm_open(const uint8_t key[32],
                        const uint8_t iv[12],
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *ct, size_t ct_len,
                        const uint8_t tag[16],
                        uint8_t *pt)
{
    if (!key || !iv || !tag || !pt)
        return BIO_ERR_INVALID_PARAM;
    if (ct_len > 0 && !ct)
        return BIO_ERR_INVALID_PARAM;
    if (aad_len > 0 && !aad)
        return BIO_ERR_INVALID_PARAM;

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);

    int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (ret != 0)
    {
        BIO_ERROR("GCM setkey failed: -0x%04x", (unsigned)-ret);
        mbedtls_gcm_free(&gcm);
        return BIO_ERR_CRYPTO_DECRYPT;
    }

    ret = mbedtls_gcm_auth_decrypt(&gcm,
                                   ct_len,
                                   iv, 12,
                                   aad, aad_len,
                                   tag, 16,
                                   ct, pt);
    mbedtls_gcm_free(&gcm);

    if (ret == MBEDTLS_ERR_GCM_AUTH_FAILED)
    {
        BIO_WARN("GCM tag verification failed — data may be tampered");
        bio_secure_wipe(pt, ct_len);
        return BIO_ERR_CRYPTO_TAG_MISMATCH;
    }
    if (ret != 0)
    {
        BIO_ERROR("GCM decrypt failed: -0x%04x", (unsigned)-ret);
        bio_secure_wipe(pt, ct_len);
        return BIO_ERR_CRYPTO_DECRYPT;
    }
    return BIO_OK;
}

/* ── AES-256-CBC (for CTAP2 PIN Protocol 1) ──────────────────── */

int bio_aes256_cbc_ctap2_pin_encrypt(const uint8_t key[32],
                                     const uint8_t *pt, size_t pt_len,
                                     uint8_t *ct)
{
    if (!key || !ct)
        return BIO_ERR_INVALID_PARAM;
    if (pt_len > 0 && !pt)
        return BIO_ERR_INVALID_PARAM;
    if (pt_len == 0 || (pt_len % 16) != 0)
        return BIO_ERR_INVALID_PARAM;

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);

    int ret = mbedtls_aes_setkey_enc(&aes, key, 256);
    if (ret != 0)
    {
        BIO_ERROR("AES-CBC setkey_enc failed: -0x%04x", (unsigned)-ret);
        mbedtls_aes_free(&aes);
        return BIO_ERR_CRYPTO_ENCRYPT;
    }

    /* Zero IV per CTAP2 PIN Protocol 1 */
    uint8_t iv[16];
    memset(iv, 0, sizeof(iv));

    ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT,
                                pt_len, iv, pt, ct);
    mbedtls_aes_free(&aes);

    if (ret != 0)
    {
        BIO_ERROR("AES-CBC encrypt failed: -0x%04x", (unsigned)-ret);
        bio_secure_wipe(ct, pt_len);
        return BIO_ERR_CRYPTO_ENCRYPT;
    }
    return BIO_OK;
}

int bio_aes256_cbc_ctap2_pin_decrypt(const uint8_t key[32],
                                     const uint8_t *ct, size_t ct_len,
                                     uint8_t *pt)
{
    if (!key || !pt)
        return BIO_ERR_INVALID_PARAM;
    if (ct_len > 0 && !ct)
        return BIO_ERR_INVALID_PARAM;
    if (ct_len == 0 || (ct_len % 16) != 0)
        return BIO_ERR_INVALID_PARAM;

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);

    int ret = mbedtls_aes_setkey_dec(&aes, key, 256);
    if (ret != 0)
    {
        BIO_ERROR("AES-CBC setkey_dec failed: -0x%04x", (unsigned)-ret);
        mbedtls_aes_free(&aes);
        return BIO_ERR_CRYPTO_DECRYPT;
    }

    /* Zero IV per CTAP2 PIN Protocol 1 */
    uint8_t iv[16];
    memset(iv, 0, sizeof(iv));

    ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT,
                                ct_len, iv, ct, pt);
    mbedtls_aes_free(&aes);

    if (ret != 0)
    {
        BIO_ERROR("AES-CBC decrypt failed: -0x%04x", (unsigned)-ret);
        bio_secure_wipe(pt, ct_len);
        return BIO_ERR_CRYPTO_DECRYPT;
    }
    return BIO_OK;
}

int bio_aes256_cbc_encrypt(const uint8_t key[32],
                           const uint8_t *pt, size_t pt_len,
                           uint8_t *ct)
{
    return bio_aes256_cbc_ctap2_pin_encrypt(key, pt, pt_len, ct);
}

int bio_aes256_cbc_decrypt(const uint8_t key[32],
                           const uint8_t *ct, size_t ct_len,
                           uint8_t *pt)
{
    return bio_aes256_cbc_ctap2_pin_decrypt(key, ct, ct_len, pt);
}

/* ── ECDSA P-256 ──────────────────────────────────────────────── */

int bio_ecdsa_keygen(bio_ecdsa_keypair *kp)
{
    if (!kp)
        return BIO_ERR_INVALID_PARAM;
    if (!g_initialized)
        return BIO_ERR_NOT_INITIALIZED;

    mbedtls_ecdsa_context ctx;
    mbedtls_ecdsa_init(&ctx);

    int ret = mbedtls_ecdsa_genkey(&ctx, MBEDTLS_ECP_DP_SECP256R1,
                                   bio_drbg_random, NULL);
    if (ret != 0)
    {
        BIO_ERROR("ECDSA keygen failed: -0x%04x", (unsigned)-ret);
        mbedtls_ecdsa_free(&ctx);
        return BIO_ERR_CRYPTO_KEYGEN;
    }

    /* Export private key (big-endian, 32 bytes) */
    ret = mbedtls_mpi_write_binary(&ctx.MBEDTLS_PRIVATE(d),
                                   kp->private_key, 32);
    if (ret != 0)
    {
        BIO_ERROR("ECDSA private key export failed: -0x%04x", (unsigned)-ret);
        mbedtls_ecdsa_free(&ctx);
        bio_secure_wipe(kp, sizeof(*kp));
        return BIO_ERR_CRYPTO_KEYGEN;
    }

    /* Export public key (uncompressed: 04 || x || y) */
    size_t olen = 0;
    ret = mbedtls_ecp_point_write_binary(&ctx.MBEDTLS_PRIVATE(grp),
                                         &ctx.MBEDTLS_PRIVATE(Q),
                                         MBEDTLS_ECP_PF_UNCOMPRESSED,
                                         &olen,
                                         kp->public_key, 65);
    if (ret != 0 || olen != 65)
    {
        BIO_ERROR("ECDSA public key export failed: -0x%04x", (unsigned)-ret);
        mbedtls_ecdsa_free(&ctx);
        bio_secure_wipe(kp, sizeof(*kp));
        return BIO_ERR_CRYPTO_KEYGEN;
    }

    mbedtls_ecdsa_free(&ctx);
    return BIO_OK;
}

/*
 * Helper: import private key into mbedtls context
 */
static int import_ecdsa_privkey(mbedtls_ecdsa_context *ctx,
                                const uint8_t private_key[32])
{
    int ret = mbedtls_ecp_group_load(&ctx->MBEDTLS_PRIVATE(grp),
                                     MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0)
        return ret;

    ret = mbedtls_mpi_read_binary(&ctx->MBEDTLS_PRIVATE(d),
                                  private_key, 32);
    return ret;
}

/*
 * Helper: import public key into mbedtls context
 */
static int import_ecdsa_pubkey(mbedtls_ecdsa_context *ctx,
                               const uint8_t public_key[65])
{
    int ret = mbedtls_ecp_group_load(&ctx->MBEDTLS_PRIVATE(grp),
                                     MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0)
        return ret;

    ret = mbedtls_ecp_point_read_binary(&ctx->MBEDTLS_PRIVATE(grp),
                                        &ctx->MBEDTLS_PRIVATE(Q),
                                        public_key, 65);
    if (ret != 0)
        return ret;

    /* Validate public key is on the curve — prevents invalid-curve attacks */
    ret = mbedtls_ecp_check_pubkey(&ctx->MBEDTLS_PRIVATE(grp),
                                   &ctx->MBEDTLS_PRIVATE(Q));
    return ret;
}

int bio_ecdsa_sign(const uint8_t private_key[32],
                   const uint8_t hash[32],
                   uint8_t *sig, size_t *sig_len)
{
    if (!private_key || !hash || !sig || !sig_len)
        return BIO_ERR_INVALID_PARAM;
    if (!g_initialized)
        return BIO_ERR_NOT_INITIALIZED;

    mbedtls_ecdsa_context ctx;
    mbedtls_ecdsa_init(&ctx);

    int ret = import_ecdsa_privkey(&ctx, private_key);
    if (ret != 0)
    {
        mbedtls_ecdsa_free(&ctx);
        return BIO_ERR_CRYPTO_SIGN;
    }

    ret = mbedtls_ecdsa_write_signature(&ctx,
                                        MBEDTLS_MD_SHA256,
                                        hash, 32,
                                        sig, *sig_len, sig_len,
                                        bio_drbg_random,
                                        NULL);
    mbedtls_ecdsa_free(&ctx);

    if (ret != 0)
    {
        BIO_ERROR("ECDSA sign failed: -0x%04x", (unsigned)-ret);
        return BIO_ERR_CRYPTO_SIGN;
    }
    return BIO_OK;
}

int bio_ecdsa_sign_raw(const uint8_t private_key[32],
                       const uint8_t hash[32],
                       uint8_t sig[64])
{
    if (!private_key || !hash || !sig)
        return BIO_ERR_INVALID_PARAM;
    if (!g_initialized)
        return BIO_ERR_NOT_INITIALIZED;

    mbedtls_ecdsa_context ctx;
    mbedtls_mpi r, s;
    mbedtls_ecdsa_init(&ctx);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    int ret = import_ecdsa_privkey(&ctx, private_key);
    if (ret != 0)
        goto fail;

    ret = mbedtls_ecdsa_sign(&ctx.MBEDTLS_PRIVATE(grp),
                             &r, &s,
                             &ctx.MBEDTLS_PRIVATE(d),
                             hash, 32,
                             bio_drbg_random,
                             NULL);
    if (ret != 0)
        goto fail;

    /* Write r and s as fixed 32-byte big-endian */
    ret = mbedtls_mpi_write_binary(&r, sig, 32);
    if (ret != 0)
        goto fail;

    ret = mbedtls_mpi_write_binary(&s, sig + 32, 32);
    if (ret != 0)
        goto fail;

    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r);
    mbedtls_ecdsa_free(&ctx);
    return BIO_OK;

fail:
    BIO_ERROR("ECDSA sign_raw failed: -0x%04x", (unsigned)-ret);
    bio_secure_wipe(sig, 64);
    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r);
    mbedtls_ecdsa_free(&ctx);
    return BIO_ERR_CRYPTO_SIGN;
}

int bio_ecdsa_verify(const uint8_t public_key[65],
                     const uint8_t hash[32],
                     const uint8_t *sig, size_t sig_len)
{
    if (!public_key || !hash || !sig)
        return BIO_ERR_INVALID_PARAM;

    mbedtls_ecdsa_context ctx;
    mbedtls_ecdsa_init(&ctx);

    int ret = import_ecdsa_pubkey(&ctx, public_key);
    if (ret != 0)
    {
        mbedtls_ecdsa_free(&ctx);
        return BIO_ERR_CRYPTO_VERIFY;
    }

    ret = mbedtls_ecdsa_read_signature(&ctx,
                                       hash, 32,
                                       sig, sig_len);
    mbedtls_ecdsa_free(&ctx);

    if (ret != 0)
    {
        BIO_DEBUG("ECDSA verify failed: -0x%04x", (unsigned)-ret);
        return BIO_ERR_CRYPTO_VERIFY;
    }
    return BIO_OK;
}

int bio_ecdsa_verify_raw(const uint8_t public_key[65],
                         const uint8_t hash[32],
                         const uint8_t sig[64])
{
    if (!public_key || !hash || !sig)
        return BIO_ERR_INVALID_PARAM;

    mbedtls_ecdsa_context ctx;
    mbedtls_mpi r, s;
    mbedtls_ecdsa_init(&ctx);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    int ret = import_ecdsa_pubkey(&ctx, public_key);
    if (ret != 0)
        goto fail;

    ret = mbedtls_mpi_read_binary(&r, sig, 32);
    if (ret != 0)
        goto fail;

    ret = mbedtls_mpi_read_binary(&s, sig + 32, 32);
    if (ret != 0)
        goto fail;

    ret = mbedtls_ecdsa_verify(&ctx.MBEDTLS_PRIVATE(grp),
                               hash, 32,
                               &ctx.MBEDTLS_PRIVATE(Q),
                               &r, &s);

    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r);
    mbedtls_ecdsa_free(&ctx);

    if (ret != 0)
    {
        BIO_DEBUG("ECDSA verify_raw failed: -0x%04x", (unsigned)-ret);
        return BIO_ERR_CRYPTO_VERIFY;
    }
    return BIO_OK;

fail:
    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r);
    mbedtls_ecdsa_free(&ctx);
    return BIO_ERR_CRYPTO_VERIFY;
}

/* ── ECDH P-256 ───────────────────────────────────────────────── */

int bio_ecdh_keygen(bio_ecdh_keypair *kp)
{
    if (!kp)
        return BIO_ERR_INVALID_PARAM;
    if (!g_initialized)
        return BIO_ERR_NOT_INITIALIZED;

    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point Q;
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&Q);

    int ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0)
        goto fail;

    ret = mbedtls_ecp_gen_keypair(&grp, &d, &Q,
                                  bio_drbg_random, NULL);
    if (ret != 0)
        goto fail;

    ret = mbedtls_mpi_write_binary(&d, kp->private_key, 32);
    if (ret != 0)
        goto fail;

    size_t olen = 0;
    ret = mbedtls_ecp_point_write_binary(&grp, &Q,
                                         MBEDTLS_ECP_PF_UNCOMPRESSED,
                                         &olen, kp->public_key, 65);
    if (ret != 0 || olen != 65)
        goto fail;

    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    return BIO_OK;

fail:
    BIO_ERROR("ECDH keygen failed: -0x%04x", (unsigned)-ret);
    bio_secure_wipe(kp, sizeof(*kp));
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    return BIO_ERR_CRYPTO_KEYGEN;
}

int bio_ecdh_compute_shared(const uint8_t our_private[32],
                            const uint8_t peer_public[65],
                            uint8_t shared[32])
{
    if (!our_private || !peer_public || !shared)
        return BIO_ERR_INVALID_PARAM;
    if (!g_initialized)
        return BIO_ERR_NOT_INITIALIZED;

    /* Validate peer public key starts with 0x04 (uncompressed) */
    if (peer_public[0] != 0x04)
    {
        BIO_ERROR("ECDH: peer public key not in uncompressed format");
        return BIO_ERR_INVALID_PARAM;
    }

    mbedtls_ecp_group grp;
    mbedtls_mpi d, z;
    mbedtls_ecp_point Q;
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&z);
    mbedtls_ecp_point_init(&Q);

    int ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0)
        goto fail;

    ret = mbedtls_mpi_read_binary(&d, our_private, 32);
    if (ret != 0)
        goto fail;

    ret = mbedtls_ecp_point_read_binary(&grp, &Q, peer_public, 65);
    if (ret != 0)
        goto fail;

    /* Validate peer public key is on curve */
    ret = mbedtls_ecp_check_pubkey(&grp, &Q);
    if (ret != 0)
    {
        BIO_ERROR("ECDH: peer public key not on curve");
        goto fail;
    }

    /* Compute shared secret: z = x-coordinate of d * Q */
    ret = mbedtls_ecdh_compute_shared(&grp, &z, &Q, &d,
                                      bio_drbg_random, NULL);
    if (ret != 0)
        goto fail;

    ret = mbedtls_mpi_write_binary(&z, shared, 32);
    if (ret != 0)
        goto fail;

    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&z);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    return BIO_OK;

fail:
    BIO_ERROR("ECDH compute_shared failed: -0x%04x", (unsigned)-ret);
    bio_secure_wipe(shared, 32);
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&z);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    return BIO_ERR_CRYPTO_KEYGEN;
}

/* ── Utilities ─────────────────────────────────────────────────── */

int bio_constant_time_compare(const uint8_t *a, const uint8_t *b, size_t len)
{
    if (!a || !b)
        return -1;
    if (len == 0)
        return -1; /* Zero-length comparison is a logic error */

    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++)
    {
        diff |= a[i] ^ b[i];
    }
    /* Return 0 on match, 1 on mismatch — no partial info leak */
    return (diff != 0) ? 1 : 0;
}

void bio_secure_wipe(void *ptr, size_t len)
{
    if (!ptr || len == 0)
        return;

    /* Use mbedtls's audited secure zeroing — robust across compilers */
    mbedtls_platform_zeroize(ptr, len);
}

static int bio_mlock_sensitive_impl(void *ptr, size_t len, bool strict)
{
    if (!ptr || len == 0)
        return BIO_ERR_INVALID_PARAM;

    /* Lock pages in RAM — prevents swapping to disk */
    if (mlock(ptr, len) != 0)
    {
        BIO_WARN("mlock() failed for %zu bytes: %s", len, strerror(errno));
        if (strict)
            return BIO_ERR_PERMISSION;
    }

    /* Exclude from core dumps (MADV_DONTDUMP).
     * madvise requires page-aligned addresses on many kernels. */
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size > 0)
    {
        uintptr_t start = (uintptr_t)ptr;
        uintptr_t page_start = start & ~((uintptr_t)page_size - 1);
        uintptr_t end = start + len;
        uintptr_t page_end = (end + (uintptr_t)page_size - 1) &
                             ~((uintptr_t)page_size - 1);
        size_t adv_len = (size_t)(page_end - page_start);

        if (madvise((void *)page_start, adv_len, MADV_DONTDUMP) != 0)
        {
            BIO_WARN("madvise(DONTDUMP) failed: %s", strerror(errno));
        }
    }
    else
    {
        BIO_WARN("madvise(DONTDUMP) failed: %s", strerror(errno));
    }

    return BIO_OK;
}

int bio_mlock_sensitive(void *ptr, size_t len)
{
    return bio_mlock_sensitive_impl(ptr, len, false);
}

int bio_mlock_sensitive_strict(void *ptr, size_t len)
{
    return bio_mlock_sensitive_impl(ptr, len, true);
}

void bio_munlock_sensitive(void *ptr, size_t len)
{
    if (!ptr || len == 0)
        return;
    munlock(ptr, len);
}
