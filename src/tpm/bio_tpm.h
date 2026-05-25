/*
 * bio_tpm.h — Direct TPM 2.0 Interface via /dev/tpmrm0
 *
 * Copyright (C) 2024 BioAuth Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Hand-coded TPM 2.0 command marshaling/unmarshaling.
 * Speaks raw TPM2 command/response packets over the kernel
 * resource manager device (/dev/tpmrm0, Linux 4.0+).
 *
 * No dependency on tpm2-tss or any TSS library.
 *
 * TPM 2.0 command format (Part 1, §18):
 *   [2B tag][4B size][4B command_code][...params...]
 *
 * TPM 2.0 response format:
 *   [2B tag][4B size][4B response_code][...params...]
 */

#ifndef BIO_TPM_H
#define BIO_TPM_H

#include "bio_common.h"

#ifdef __cplusplus
extern "C"
{
#endif

/* ── TPM 2.0 Constants ───────────────────────────────────────── */

/* Tags (TPM_ST) */
#define TPM2_ST_NO_SESSIONS 0x8001
#define TPM2_ST_SESSIONS 0x8002
#define TPM2_ST_HASHCHECK 0x8024

/* Command Codes (TPM_CC) */
#define TPM2_CC_STARTUP 0x00000144
#define TPM2_CC_SHUTDOWN 0x00000145
#define TPM2_CC_SELF_TEST 0x00000143
#define TPM2_CC_GET_RANDOM 0x0000017B
#define TPM2_CC_GET_CAPABILITY 0x0000017A
#define TPM2_CC_PCR_READ 0x0000017E
#define TPM2_CC_CREATE_PRIMARY 0x00000131
#define TPM2_CC_CREATE 0x00000153
#define TPM2_CC_LOAD 0x00000157
#define TPM2_CC_UNSEAL 0x0000015E
#define TPM2_CC_FLUSH_CONTEXT 0x00000165
#define TPM2_CC_NV_READ 0x0000014E
#define TPM2_CC_NV_WRITE 0x00000137
#define TPM2_CC_NV_DEFINE_SPACE 0x0000012A
#define TPM2_CC_NV_UNDEFINE_SPACE 0x00000122
#define TPM2_CC_CONTEXT_SAVE 0x00000162
#define TPM2_CC_CONTEXT_LOAD 0x00000161
#define TPM2_CC_EVICT_CONTROL 0x00000120
#define TPM2_CC_READ_PUBLIC 0x00000173
#define TPM2_CC_START_AUTH_SESSION 0x00000176
#define TPM2_CC_POLICY_PCR 0x0000017F
#define TPM2_CC_POLICY_GET_DIGEST 0x00000189
#define TPM2_CC_SIGN 0x0000015D

/* Session Types */
#define TPM2_SE_POLICY 0x01
#define TPM2_SE_TRIAL 0x03

/* Response Codes (TPM_RC) */
#define TPM2_RC_SUCCESS 0x00000000
#define TPM2_RC_INITIALIZE 0x00000100
#define TPM2_RC_AUTH_FAIL 0x0000008E
#define TPM2_RC_HANDLE 0x0000008B
#define TPM2_RC_BAD_AUTH 0x00000022

/* Algorithm IDs (TPM_ALG_ID) */
#define TPM2_ALG_RSA 0x0001
#define TPM2_ALG_SHA256 0x000B
#define TPM2_ALG_AES 0x0006
#define TPM2_ALG_NULL 0x0010
#define TPM2_ALG_ECC 0x0023
#define TPM2_ALG_KEYEDHASH 0x0008
#define TPM2_ALG_SYMCIPHER 0x0025
#define TPM2_ALG_CFB 0x0043
#define TPM2_ALG_OAEP 0x0017
#define TPM2_ALG_ECDSA 0x0018
#define TPM2_ALG_ECDH 0x0019

/* ECC Curve IDs */
#define TPM2_ECC_NIST_P256 0x0003

/* Handle Ranges */
#define TPM2_RH_OWNER 0x40000001
#define TPM2_RH_NULL 0x40000007
#define TPM2_RH_ENDORSEMENT 0x4000000B
#define TPM2_RH_PLATFORM 0x4000000C
#define TPM2_RH_LOCKOUT 0x4000000A
#define TPM2_RS_PW 0x40000009 /* Password auth session */

/* Persistent handle range */
#define TPM2_PERSISTENT_FIRST 0x81000000
#define TPM2_PERSISTENT_LAST 0x81FFFFFF

/* BioAuth persistent handles */
#define BIOAUTH_TPM_PRIMARY_HANDLE 0x81000100 /* Our primary key */
#define BIOAUTH_TPM_TEMPLATE_BASE 0x81000101  /* Per-user template keys start */

/* Buffer limits */
#define TPM2_MAX_COMMAND_SIZE 4096
#define TPM2_MAX_RESPONSE_SIZE 4096
#define TPM2_SHA256_DIGEST_SIZE 32
#define TPM2_MAX_SEALED_DATA 128

    /* ── TPM Context ─────────────────────────────────────────────── */

    typedef struct
    {
        int fd; /* File descriptor for /dev/tpmrm0 */
        bool is_open;
        char device_path[64];    /* e.g. "/dev/tpmrm0" */
        uint32_t primary_handle; /* Persistent parent handle for BioAuth keys */

        /* Command buffer — reused between calls */
        uint8_t cmd_buf[TPM2_MAX_COMMAND_SIZE];
        size_t cmd_len;

        /* Response buffer */
        uint8_t rsp_buf[TPM2_MAX_RESPONSE_SIZE];
        size_t rsp_len;
    } bio_tpm_ctx_t;

    /* ── TPM Marshal/Unmarshal Helpers ───────────────────────────── */

    /**
     * Command builder — append data to command buffer.
     */
    typedef struct
    {
        uint8_t *buf;
        size_t capacity;
        size_t offset;
        bool error;
    } bio_tpm_marshal_t;

    /**
     * Response parser — read data from response buffer.
     */
    typedef struct
    {
        const uint8_t *buf;
        size_t size;
        size_t offset;
        bool error;
    } bio_tpm_unmarshal_t;

    /* ── Lifecycle ────────────────────────────────────────────────── */

    /**
     * Initialize TPM context.
     * @param ctx         TPM context
     * @param device_path Device path (NULL → "/dev/tpmrm0")
     */
    int bio_tpm_init(bio_tpm_ctx_t *ctx, const char *device_path);

    /**
     * Override the persistent primary handle used by BioAuth convenience
     * seal/unseal APIs. Must be in TPM2 persistent handle range.
     */
    int bio_tpm_set_primary_handle(bio_tpm_ctx_t *ctx, uint32_t handle);

    /**
     * Close TPM device and free resources.
     */
    void bio_tpm_cleanup(bio_tpm_ctx_t *ctx);

    /* ── Low-level command execution ─────────────────────────────── */

    /**
     * Execute a raw TPM2 command.
     * Writes the command buffer to /dev/tpmrm0 and reads the response.
     *
     * @param ctx      TPM context (cmd_buf/cmd_len must be set)
     * @param rc_out   Receives the TPM response code
     * @return BIO_OK if the I/O succeeded (regardless of TPM RC).
     *         Check rc_out for TPM-level success/failure.
     */
    int bio_tpm_execute(bio_tpm_ctx_t *ctx, uint32_t *rc_out);

    /* ── High-level operations ───────────────────────────────────── */

    /**
     * TPM2_GetRandom: Get random bytes from the TPM's hardware RNG.
     * @param ctx       TPM context
     * @param buf       Output buffer
     * @param count     Number of random bytes (max ~32 per call due to TPM limits)
     */
    int bio_tpm_get_random(bio_tpm_ctx_t *ctx, uint8_t *buf, uint16_t count);

    /**
     * TPM2_PCR_Read: Read a PCR value.
     * @param ctx       TPM context
     * @param pcr_index PCR index (0–23)
     * @param digest    Output: 32-byte SHA-256 PCR value
     */
    int bio_tpm_pcr_read(bio_tpm_ctx_t *ctx, uint32_t pcr_index,
                         uint8_t digest[TPM2_SHA256_DIGEST_SIZE]);

    /**
     * TPM2_CreatePrimary: Create a primary key in the owner hierarchy.
     * Creates an ECC P-256 primary key for BioAuth.
     *
     * @param ctx           TPM context
     * @param handle_out    Receives the transient handle of created key
     */
    int bio_tpm_create_primary(bio_tpm_ctx_t *ctx, uint32_t *handle_out);

    /**
     * TPM2_Create: Create a child key under a parent (for sealing).
     *
     * @param ctx           TPM context
     * @param parent_handle Parent key handle
     * @param seal_data     Data to seal (must be ≤ TPM2_MAX_SEALED_DATA)
     * @param seal_len      Length of seal data
     * @param auth          Authorization value for unsealing (password)
     * @param auth_len      Auth length
     * @param out_private   Output: marshaled private portion (TPM2B_PRIVATE)
     * @param priv_len      In: buffer size, Out: actual size
     * @param out_public    Output: marshaled public portion (TPM2B_PUBLIC)
     * @param pub_len       In: buffer size, Out: actual size
     */
    int bio_tpm_create_sealed(bio_tpm_ctx_t *ctx,
                              uint32_t parent_handle,
                              const uint8_t *seal_data, size_t seal_len,
                              const uint8_t *auth, size_t auth_len,
                              uint8_t *out_private, size_t *priv_len,
                              uint8_t *out_public, size_t *pub_len);

    /**
     * TPM2_Load: Load a key into the TPM.
     *
     * @param ctx           TPM context
     * @param parent_handle Parent key handle
     * @param private_data  TPM2B_PRIVATE blob
     * @param priv_len      Private blob length
     * @param public_data   TPM2B_PUBLIC blob
     * @param pub_len       Public blob length
     * @param handle_out    Receives the loaded object handle
     */
    int bio_tpm_load(bio_tpm_ctx_t *ctx,
                     uint32_t parent_handle,
                     const uint8_t *private_data, size_t priv_len,
                     const uint8_t *public_data, size_t pub_len,
                     uint32_t *handle_out);

    /**
     * TPM2_Unseal: Unseal data from a loaded object.
     *
     * @param ctx           TPM context
     * @param item_handle   Handle of the sealed object (loaded)
     * @param auth          Authorization value
     * @param auth_len      Auth length
     * @param out_data      Output: unsealed data
     * @param out_len       In: buffer size, Out: actual size
     */
    int bio_tpm_unseal(bio_tpm_ctx_t *ctx,
                       uint32_t item_handle,
                       const uint8_t *auth, size_t auth_len,
                       uint8_t *out_data, size_t *out_len);

    /**
     * TPM2_FlushContext: Free a transient handle.
     */
    int bio_tpm_flush_context(bio_tpm_ctx_t *ctx, uint32_t handle);

    /**
     * TPM2_EvictControl: Make a transient key persistent (or remove persistence).
     *
     * @param ctx              TPM context
     * @param object_handle    Transient handle to persist
     * @param persistent_handle Desired persistent handle (0x81xxxxxx)
     */
    int bio_tpm_evict_control(bio_tpm_ctx_t *ctx,
                              uint32_t object_handle,
                              uint32_t persistent_handle);

    /**
     * TPM2_ReadPublic: Read the public area of a loaded key.
     *
     * @param ctx           TPM context
     * @param handle        Object handle
     * @param out_public    Output: TPM2B_PUBLIC raw bytes
     * @param pub_len       In: buffer size, Out: actual size
     */
    int bio_tpm_read_public(bio_tpm_ctx_t *ctx,
                            uint32_t handle,
                            uint8_t *out_public, size_t *pub_len);

    /* ── Convenience ─────────────────────────────────────────────── */

    /**
     * TPM2_StartAuthSession: Create a policy session.
     *
     * @param ctx              TPM context
     * @param session_handle   Receives the session handle
     */
    int bio_tpm_start_auth_session(bio_tpm_ctx_t *ctx, uint32_t *session_handle);

    /**
     * TPM2_PolicyPCR: Bind a policy session to PCR values.
     *
     * @param ctx              TPM context
     * @param session_handle   Policy session handle
     * @param pcr_index        PCR index to bind (0–23)
     */
    int bio_tpm_policy_pcr(bio_tpm_ctx_t *ctx, uint32_t session_handle,
                           uint32_t pcr_index);

    /**
     * TPM2_PolicyGetDigest: Get the policy digest from a session.
     *
     * @param ctx              TPM context
     * @param session_handle   Policy session handle
     * @param digest           Output: 32-byte policy digest
     */
    int bio_tpm_policy_get_digest(bio_tpm_ctx_t *ctx, uint32_t session_handle,
                                  uint8_t digest[TPM2_SHA256_DIGEST_SIZE]);

    /**
     * TPM2_Create with PCR-bound policy: Create a sealed object bound to PCR values.
     *
     * @param ctx              TPM context
     * @param parent_handle    Parent key handle
     * @param seal_data        Data to seal
     * @param seal_len         Length of seal data
     * @param auth             Authorization value
     * @param auth_len         Auth length
     * @param pcr_index        PCR index to bind (e.g. 7 for Secure Boot)
     * @param out_private      Output: TPM2B_PRIVATE
     * @param priv_len         In: buffer size, Out: actual size
     * @param out_public       Output: TPM2B_PUBLIC
     * @param pub_len          In: buffer size, Out: actual size
     */
    int bio_tpm_create_sealed_pcr(bio_tpm_ctx_t *ctx,
                                  uint32_t parent_handle,
                                  const uint8_t *seal_data, size_t seal_len,
                                  const uint8_t *auth, size_t auth_len,
                                  uint32_t pcr_index,
                                  uint8_t *out_private, size_t *priv_len,
                                  uint8_t *out_public, size_t *pub_len);

    /**
     * TPM2_Create + Load ECC P-256 signing key.
     *
     * @param ctx              TPM context
     * @param parent_handle    Parent storage key handle
     * @param key_private      Output: TPM2B_PRIVATE (for persistence)
     * @param priv_len         In: buffer size, Out: actual size
     * @param key_public       Output: TPM2B_PUBLIC
     * @param pub_len          In: buffer size, Out: actual size
     * @param public_key_out   Output: 65-byte uncompressed public key
     */
    int bio_tpm_create_ecc_key(bio_tpm_ctx_t *ctx,
                               uint32_t parent_handle,
                               uint8_t *key_private, size_t *priv_len,
                               uint8_t *key_public, size_t *pub_len,
                               uint8_t public_key_out[65]);

    /**
     * TPM2_Sign: ECDSA-SHA256 sign using a loaded TPM key.
     *
     * @param ctx              TPM context
     * @param key_handle       Loaded signing key handle
     * @param hash             32-byte SHA-256 hash to sign
     * @param sig_r            Output: 32-byte R component
     * @param sig_s            Output: 32-byte S component
     */
    int bio_tpm_sign_ecdsa(bio_tpm_ctx_t *ctx,
                           uint32_t key_handle,
                           const uint8_t hash[32],
                           uint8_t sig_r[32], uint8_t sig_s[32]);

    /**
     * TPM2_NV_DefineSpace: Reserve NV storage.
     *
     * @param ctx          TPM context
     * @param nv_index     NV index (0x01000000 range)
     * @param size         Data size to reserve
     */
    int bio_tpm_nv_define_space(bio_tpm_ctx_t *ctx,
                                uint32_t nv_index, uint16_t size);

    /**
     * TPM2_NV_Write: Write data to NV storage.
     *
     * @param ctx          TPM context
     * @param nv_index     NV index
     * @param data         Data to write
     * @param len          Data length
     * @param offset       Byte offset within NV area
     */
    int bio_tpm_nv_write(bio_tpm_ctx_t *ctx, uint32_t nv_index,
                         const uint8_t *data, uint16_t len, uint16_t offset);

    /**
     * TPM2_NV_Read: Read data from NV storage.
     *
     * @param ctx          TPM context
     * @param nv_index     NV index
     * @param out          Output buffer
     * @param len          Bytes to read
     * @param offset       Byte offset within NV area
     */
    int bio_tpm_nv_read(bio_tpm_ctx_t *ctx, uint32_t nv_index,
                        uint8_t *out, uint16_t len, uint16_t offset);

    /**
     * Seal data with PCR binding under the BioAuth primary key.
     * Like bio_tpm_seal_for_user but binds to a PCR index.
     *
     * Note: auth_len must be 0 for this API. PCR mode currently uses
     * policy-only authorization and does not support authValue.
     */
    int bio_tpm_seal_for_user_pcr(bio_tpm_ctx_t *ctx,
                                  const uint8_t *data, size_t data_len,
                                  const uint8_t *auth, size_t auth_len,
                                  uint32_t pcr_index,
                                  uint8_t *sealed_blob, size_t *blob_len);

    /**
     * Unseal a PCR-bound blob.
     * The current PCR values must match what was set at sealing time.
     *
     * Note: auth_len must be 0 for this API. PCR mode currently uses
     * policy-only authorization and does not support authValue.
     */
    int bio_tpm_unseal_for_user_pcr(bio_tpm_ctx_t *ctx,
                                    const uint8_t *sealed_blob, size_t blob_len,
                                    const uint8_t *auth, size_t auth_len,
                                    uint32_t pcr_index,
                                    uint8_t *data, size_t *data_len);

    /**
     * Ensure BioAuth's primary key exists.
     * If already persistent, loads it. Otherwise creates and persists.
     *
     * @param ctx           TPM context
     * @param handle_out    Receives the primary key handle
     */
    int bio_tpm_ensure_primary_key(bio_tpm_ctx_t *ctx, uint32_t *handle_out);

    /**
     * Seal data under the BioAuth primary key.
     * Combines Create + flush of unseeded result.
     */
    int bio_tpm_seal_for_user(bio_tpm_ctx_t *ctx,
                              const uint8_t *data, size_t data_len,
                              const uint8_t *auth, size_t auth_len,
                              uint8_t *sealed_blob, size_t *blob_len);

    /**
     * Unseal a blob previously sealed with bio_tpm_seal_for_user.
     */
    int bio_tpm_unseal_for_user(bio_tpm_ctx_t *ctx,
                                const uint8_t *sealed_blob, size_t blob_len,
                                const uint8_t *auth, size_t auth_len,
                                uint8_t *data, size_t *data_len);

#ifdef __cplusplus
}
#endif

#endif /* BIO_TPM_H */
