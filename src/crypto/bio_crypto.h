/*
 * bio_crypto.h — Unified crypto API wrapping mbedtls
 *
 * Copyright (C) 2024 BioAuth Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * All crypto operations delegate to mbedtls with constant-time
 * implementations.  The rest of BioAuth NEVER calls mbedtls directly.
 */

#ifndef BIO_CRYPTO_H
#define BIO_CRYPTO_H

#include "bio_common.h"

#ifdef __cplusplus
extern "C"
{
#endif

    /* ── Lifecycle ─────────────────────────────────────────────────── */

    /**
     * Initialize crypto subsystem.
     * Sets up mbedtls entropy source + CTR-DRBG CSPRNG.
     * Must be called once at startup before any other bio_crypto_* call.
     * Returns BIO_OK on success.
     */
    int bio_crypto_init(void);

    /**
     * Cleanup crypto subsystem.
     * Wipes and frees all internal state.
     */
    void bio_crypto_cleanup(void);

    /* ── Random ────────────────────────────────────────────────────── */

    /**
     * Fill buffer with cryptographically secure random bytes.
     * Uses mbedtls CTR-DRBG seeded from platform entropy (/dev/urandom).
     */
    int bio_random_bytes(uint8_t *buf, size_t len);

    /* ── SHA-256 ───────────────────────────────────────────────────── */

    /**
     * Compute SHA-256 hash of data.
     * @param data   Input data
     * @param len    Length of input data
     * @param digest Output buffer (32 bytes)
     */
    int bio_sha256(const uint8_t *data, size_t len, uint8_t digest[32]);

    /**
     * Compute SHA-1 hash of data.
     * Used for Have I Been Pwned k-anonymity lookups.
     * @param data   Input data
     * @param len    Length of input data
     * @param digest Output buffer (20 bytes)
     */
    int bio_sha1(const uint8_t *data, size_t len, uint8_t digest[20]);

    /* ── HMAC-SHA-256 ──────────────────────────────────────────────── */

    /**
     * Compute HMAC-SHA-256.
     * @param key      HMAC key
     * @param key_len  Key length
     * @param data     Input data
     * @param data_len Data length
     * @param mac      Output MAC (32 bytes)
     */
    int bio_hmac_sha256(const uint8_t *key, size_t key_len,
                        const uint8_t *data, size_t data_len,
                        uint8_t mac[32]);

    /* ── HKDF-SHA-256 ──────────────────────────────────────────────── */

    /**
     * HKDF-SHA-256 key derivation (RFC 5869).
     * @param salt     Optional salt (can be NULL → zeroed)
     * @param salt_len Salt length
     * @param ikm      Input keying material
     * @param ikm_len  IKM length
     * @param info     Context/application info
     * @param info_len Info length
     * @param okm      Output keying material
     * @param okm_len  Desired output length
     */
    int bio_hkdf_sha256(const uint8_t *salt, size_t salt_len,
                        const uint8_t *ikm, size_t ikm_len,
                        const uint8_t *info, size_t info_len,
                        uint8_t *okm, size_t okm_len);

    /* ── AES-256-GCM ──────────────────────────────────────────────── */

    /**
     * AES-256-GCM authenticated encryption.
     * @param key     256-bit key
     * @param iv      96-bit IV (MUST be unique per key!)
     * @param aad     Additional authenticated data (can be NULL)
     * @param aad_len AAD length
     * @param pt      Plaintext
     * @param pt_len  Plaintext length
     * @param ct      Output ciphertext (same length as plaintext)
     * @param tag     Output authentication tag (16 bytes)
     */
    int bio_aes256_gcm_seal(const uint8_t key[32],
                            const uint8_t iv[12],
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *pt, size_t pt_len,
                            uint8_t *ct, uint8_t tag[16]);

    /**
     * AES-256-GCM authenticated decryption.
     * Returns BIO_ERR_CRYPTO_TAG_MISMATCH if tag verification fails.
     * On tag mismatch, pt is zeroed.
     */
    int bio_aes256_gcm_open(const uint8_t key[32],
                            const uint8_t iv[12],
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *ct, size_t ct_len,
                            const uint8_t tag[16],
                            uint8_t *pt);

    /* ── AES-256-CBC (for CTAP2 PIN Protocol 1) ──────────────────── */

    /**
     * AES-256-CBC encrypt with zero IV for CTAP2 PIN protocol 1 only.
     * Input must be a multiple of 16 bytes.
     * Output is the same length as input.
     *
     * WARNING: Zero-IV CBC is not suitable for general-purpose encryption.
     */
    int bio_aes256_cbc_ctap2_pin_encrypt(const uint8_t key[32],
                                         const uint8_t *pt, size_t pt_len,
                                         uint8_t *ct);

    /**
     * AES-256-CBC decrypt with zero IV for CTAP2 PIN protocol 1 only.
     * Input must be a multiple of 16 bytes.
     * Output is the same length as input.
     *
     * WARNING: Zero-IV CBC is not suitable for general-purpose encryption.
     */
    int bio_aes256_cbc_ctap2_pin_decrypt(const uint8_t key[32],
                                         const uint8_t *ct, size_t ct_len,
                                         uint8_t *pt);

    /* Compatibility wrappers. Prefer the explicit CTAP2 PIN names above. */
    int bio_aes256_cbc_encrypt(const uint8_t key[32],
                               const uint8_t *pt, size_t pt_len,
                               uint8_t *ct);

    int bio_aes256_cbc_decrypt(const uint8_t key[32],
                               const uint8_t *ct, size_t ct_len,
                               uint8_t *pt);

    /* ── ECDSA P-256 (ES256 for FIDO2) ────────────────────────────── */

    typedef struct
    {
        uint8_t private_key[32];
        uint8_t public_key[65]; /* 0x04 || x(32) || y(32) uncompressed */
    } bio_ecdsa_keypair;

    /**
     * Generate a new ECDSA P-256 keypair.
     */
    int bio_ecdsa_keygen(bio_ecdsa_keypair *kp);

    /**
     * Sign a SHA-256 hash with ECDSA P-256.
     * @param private_key  32-byte private key scalar
     * @param hash         32-byte SHA-256 hash of message
     * @param sig          Output DER-encoded signature
     * @param sig_len      In: buffer size, Out: actual signature length
     */
    int bio_ecdsa_sign(const uint8_t private_key[32],
                       const uint8_t hash[32],
                       uint8_t *sig, size_t *sig_len);

    /**
     * Sign producing raw r||s (64 bytes) for COSE/FIDO2 encoding.
     */
    int bio_ecdsa_sign_raw(const uint8_t private_key[32],
                           const uint8_t hash[32],
                           uint8_t sig[64]);

    /**
     * Verify an ECDSA P-256 signature.
     * @param public_key  65-byte uncompressed public key
     * @param hash        32-byte SHA-256 hash
     * @param sig         DER-encoded signature
     * @param sig_len     Signature length
     */
    int bio_ecdsa_verify(const uint8_t public_key[65],
                         const uint8_t hash[32],
                         const uint8_t *sig, size_t sig_len);

    /**
     * Verify raw r||s signature (64 bytes).
     */
    int bio_ecdsa_verify_raw(const uint8_t public_key[65],
                             const uint8_t hash[32],
                             const uint8_t sig[64]);

    /* ── ECDH P-256 ───────────────────────────────────────────────── */

    typedef struct
    {
        uint8_t private_key[32];
        uint8_t public_key[65]; /* 0x04 || x(32) || y(32) */
    } bio_ecdh_keypair;

    /**
     * Generate a new ECDH P-256 keypair.
     */
    int bio_ecdh_keygen(bio_ecdh_keypair *kp);

    /**
     * Compute ECDH shared secret (x-coordinate of d * Q).
     * @param our_private  Our 32-byte private key
     * @param peer_public  Peer's 65-byte uncompressed public key
     * @param shared       Output 32-byte shared secret
     */
    int bio_ecdh_compute_shared(const uint8_t our_private[32],
                                const uint8_t peer_public[65],
                                uint8_t shared[32]);

    /* ── Utilities ─────────────────────────────────────────────────── */

    /**
     * Constant-time comparison.
     * Returns 0 if equal, non-zero otherwise (NOT timing-dependent).
     */
    int bio_constant_time_compare(const uint8_t *a, const uint8_t *b, size_t len);

    /**
     * Secure memory wipe — guaranteed not to be optimized away.
     * Uses volatile pointer + memory barrier to prevent compiler optimization.
     */
    void bio_secure_wipe(void *ptr, size_t len);

    /**
     * Lock memory pages to prevent swapping and exclude from core dumps.
     * Call on sensitive key material (keys, tokens, PINs).
     * @param ptr   Memory region to lock
     * @param len   Size of region
     * @return BIO_OK on success, warn-only on mlock failure
     */
    int bio_mlock_sensitive(void *ptr, size_t len);

    /**
     * Strict variant of bio_mlock_sensitive.
     * Returns BIO_ERR_PERMISSION if mlock fails.
     */
    int bio_mlock_sensitive_strict(void *ptr, size_t len);

    /**
     * Unlock previously locked memory pages.
     */
    void bio_munlock_sensitive(void *ptr, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* BIO_CRYPTO_H */
