/*
 * bio_fido2.h — FIDO2/CTAP2 Authenticator Engine
 *
 * Copyright (C) 2024 BioAuth Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Implements a CTAP2 authenticator (platform authenticator) that:
 *   - Handles all 8 CTAP2 commands
 *   - Uses ECDSA P-256 (ES256) for credential keys
 *   - Supports user verification via fingerprint
 *   - Stores credentials encrypted via AES-256-GCM with TPM-sealed key
 *   - Encodes/decodes all messages in CBOR per CTAP2 spec
 *
 * CTAP2 Commands implemented:
 *   0x01 authenticatorMakeCredential
 *   0x02 authenticatorGetAssertion
 *   0x04 authenticatorGetInfo
 *   0x06 authenticatorClientPIN
 *   0x08 authenticatorGetNextAssertion
 *   0x07 authenticatorReset
 *   0x0A authenticatorCredentialManagement
 *   0x0B authenticatorSelection
 *
 * References:
 *   - FIDO CTAP 2.1: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/
 *   - WebAuthn L2: https://www.w3.org/TR/webauthn-2/
 *   - COSE: RFC 8152
 */

#ifndef BIO_FIDO2_H
#define BIO_FIDO2_H

#include "bio_common.h"
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>

/* ── CTAP2 Constants ─────────────────────────────────────────── */

/* Commands */
#define CTAP2_CMD_MAKE_CREDENTIAL 0x01
#define CTAP2_CMD_GET_ASSERTION 0x02
#define CTAP2_CMD_GET_INFO 0x04
#define CTAP2_CMD_CLIENT_PIN 0x06
#define CTAP2_CMD_RESET 0x07
#define CTAP2_CMD_GET_NEXT_ASSERTION 0x08
#define CTAP2_CMD_BIO_ENROLLMENT 0x09
#define CTAP2_CMD_CREDENTIAL_MANAGEMENT 0x0A
#define CTAP2_CMD_SELECTION 0x0B

/* Status codes */
#define CTAP2_OK 0x00
#define CTAP2_ERR_CBOR_UNEXPECTED_TYPE 0x11
#define CTAP2_ERR_INVALID_CBOR 0x12
#define CTAP2_ERR_MISSING_PARAMETER 0x14
#define CTAP2_ERR_LIMIT_EXCEEDED 0x15
#define CTAP2_ERR_UNSUPPORTED_EXTENSION 0x16
#define CTAP2_ERR_CREDENTIAL_EXCLUDED 0x19
#define CTAP2_ERR_PROCESSING 0x21
#define CTAP2_ERR_INVALID_CREDENTIAL 0x22
#define CTAP2_ERR_USER_ACTION_PENDING 0x23
#define CTAP2_ERR_OPERATION_PENDING 0x24
#define CTAP2_ERR_NO_OPERATIONS 0x25
#define CTAP2_ERR_UNSUPPORTED_ALGORITHM 0x26
#define CTAP2_ERR_OPERATION_DENIED 0x27
#define CTAP2_ERR_KEY_STORE_FULL 0x28
#define CTAP2_ERR_NO_OPERATION_PENDING 0x2A
#define CTAP2_ERR_INVALID_OPTION 0x2C
#define CTAP2_ERR_KEEPALIVE_CANCEL 0x2D
#define CTAP2_ERR_NO_CREDENTIALS 0x2E
#define CTAP2_ERR_USER_ACTION_TIMEOUT 0x2F
#define CTAP2_ERR_NOT_ALLOWED 0x30
#define CTAP2_ERR_PIN_INVALID 0x31
#define CTAP2_ERR_PIN_BLOCKED 0x32
#define CTAP2_ERR_PIN_AUTH_INVALID 0x33
#define CTAP2_ERR_PIN_AUTH_BLOCKED 0x34
#define CTAP2_ERR_PIN_NOT_SET 0x35
#define CTAP2_ERR_PIN_REQUIRED 0x36
#define CTAP2_ERR_PIN_POLICY_VIOLATION 0x37
#define CTAP2_ERR_UV_BLOCKED 0x3C
#define CTAP2_ERR_UV_INVALID 0x3F
#define CTAP2_ERR_OTHER 0x7F

/* CTAP1 error codes */
#define CTAP1_ERR_INVALID_COMMAND 0x01

/* COSE algorithm identifiers */
#define COSE_ALG_ES256 -7 /* ECDSA w/ SHA-256, P-256 */

/* COSE key type */
#define COSE_KTY_EC2 2
#define COSE_CRV_P256 1

/* Flags in authenticatorData */
#define CTAP2_FLAG_UP 0x01 /* User Present */
#define CTAP2_FLAG_UV 0x04 /* User Verified */
#define CTAP2_FLAG_AT 0x40 /* Attested cred data */
#define CTAP2_FLAG_ED 0x80 /* Extensions */

/* Limits */
#define CTAP2_MAX_CREDENTIAL_ID_LEN 128
#define CTAP2_MAX_RP_ID_LEN 256
#define CTAP2_MAX_USER_ID_LEN 64
#define CTAP2_MAX_USER_NAME_LEN 64
#define CTAP2_MAX_DISPLAY_NAME_LEN 64
#define CTAP2_MAX_ALLOW_LIST 16
#define CTAP2_MAX_CREDENTIALS_STORED 64
#define CTAP2_MAX_PIN_RETRIES 8
#define CTAP2_PIN_TOKEN_SIZE 32

/* CTAP2.1 pinUvAuthToken permission bits */
#define CTAP2_PIN_PERM_MAKE_CREDENTIAL 0x01
#define CTAP2_PIN_PERM_GET_ASSERTION 0x02
#define CTAP2_PIN_PERM_CREDENTIAL_MGMT 0x04
#define CTAP2_PIN_PERM_BIO_ENROLLMENT 0x08
#define CTAP2_PIN_PERM_LARGE_BLOB_WRITE 0x10
#define CTAP2_PIN_PERM_AUTHNR_CFG 0x20

/* Our authenticator's AAGUID (16 bytes, unique identifier) */
#define BIOAUTH_AAGUID                               \
    {0xb1, 0x0a, 0x07, 0x42, 0xfe, 0xed, 0x43, 0x21, \
     0x90, 0xab, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55}

/* ── Data Structures ─────────────────────────────────────────── */

/* Relying Party */
typedef struct
{
    char id[CTAP2_MAX_RP_ID_LEN];
    char name[CTAP2_MAX_RP_ID_LEN];
    uint8_t id_hash[32]; /* SHA-256 of RP ID */
} ctap2_rp_t;

/* User entity */
typedef struct
{
    uint8_t id[CTAP2_MAX_USER_ID_LEN];
    size_t id_len;
    char name[CTAP2_MAX_USER_NAME_LEN];
    char display_name[CTAP2_MAX_DISPLAY_NAME_LEN];
} ctap2_user_t;

/* Public key credential parameters */
typedef struct
{
    char type[16]; /* "public-key" */
    int32_t alg;   /* COSE algorithm ID */
} ctap2_pubkey_param_t;

/* Credential ID */
typedef struct
{
    uint8_t id[CTAP2_MAX_CREDENTIAL_ID_LEN];
    size_t id_len;
} ctap2_credential_id_t;

/* Stored credential (resident key) */
typedef struct
{
    bool in_use;
    ctap2_rp_t rp;
    ctap2_user_t user;
    ctap2_credential_id_t cred_id;
    uint8_t private_key[32]; /* ECDSA P-256 private key */
    uint8_t public_key[65];  /* Uncompressed public key */
    uint32_t sign_count;
    uint64_t created;
    bool resident;
    uint8_t cred_protect;    /* CTAP2.1 credProtect level: 1/2/3 */
    uint8_t hmac_secret[32]; /* per-credential HMAC secret (PRF) */
    bool has_hmac_secret;
} ctap2_credential_t;

/* PIN/UV auth protocol state */
typedef struct
{
    bool pin_set;
    uint8_t pin_hash[16]; /* left(SHA-256(pin), 16) */
    int pin_retries;
    bool pin_blocked;

    /* PIN/UV auth protocol 1 key agreement */
    uint8_t platform_key_agreement_x[32];
    uint8_t platform_key_agreement_y[32];
    uint8_t shared_secret[32];
    uint8_t pin_token[CTAP2_PIN_TOKEN_SIZE];
    bool pin_token_valid;
    uint32_t pin_token_permissions; /* 0 = legacy unrestricted token */
    char pin_token_rp_id[CTAP2_MAX_RP_ID_LEN];
    bool pin_token_rp_id_set;
} ctap2_pin_state_t;

/* Authenticator context */
typedef struct bio_fido2_ctx
{
    /* Credential store */
    ctap2_credential_t credentials[CTAP2_MAX_CREDENTIALS_STORED];
    size_t credential_count;

    /* PIN state */
    ctap2_pin_state_t pin;

    /* ECDH key pair for PIN protocol (regenerated per session) */
    uint8_t auth_privkey[32];
    uint8_t auth_pubkey[65];

    /* Get-assertion state for GetNextAssertion */
    ctap2_credential_t *assertion_matches[CTAP2_MAX_CREDENTIALS_STORED];
    size_t assertion_match_count;
    size_t assertion_index;
    uint8_t assertion_client_data_hash[32];
    uint8_t assertion_rp_id_hash[32];
    uint8_t assertion_flags;

    /* Counters */
    uint32_t global_sign_count;

    /* Assertion timeout (monotonic time when assertion state was set) */
    uint64_t assertion_timestamp;

    /* Daemon start time (for reset window enforcement) */
    uint64_t init_timestamp;

    /* Storage path */
    char storage_path[256];

    /* User verification callback (fingerprint) */
    bool (*verify_user)(void *ctx);
    void *verify_user_ctx;

    /* Mutex for thread-safe access (VULN-01 fix) */
    pthread_mutex_t mutex;
} bio_fido2_ctx_t;

/* ── API ─────────────────────────────────────────────────────── */

/*
 * Initialize the FIDO2 authenticator context.
 * Loads stored credentials from disk if present.
 * @param ctx     Authenticator context to initialize
 * @param path    Storage directory (e.g., /var/lib/bioauth/fido2)
 * @return BIO_OK on success
 */
int bio_fido2_init(bio_fido2_ctx_t *ctx, const char *path);

/*
 * Cleanup and securely wipe authenticator state.
 */
void bio_fido2_cleanup(bio_fido2_ctx_t *ctx);

/*
 * Set the user verification callback (fingerprint verify).
 * The callback should return true if user is verified.
 */
void bio_fido2_set_uv_callback(bio_fido2_ctx_t *ctx,
                               bool (*cb)(void *), void *user_ctx);

/*
 * Process a CTAP2 command.
 * @param ctx           Authenticator context
 * @param cmd           CTAP2 command byte
 * @param request       Request CBOR data (after command byte)
 * @param request_len   Length of request data
 * @param response      Output buffer for response CBOR
 * @param response_len  In: capacity; Out: actual response length
 * @return CTAP2 status code (0x00 = success)
 */
uint8_t bio_fido2_process(bio_fido2_ctx_t *ctx,
                          uint8_t cmd,
                          const uint8_t *request, size_t request_len,
                          uint8_t *response, size_t *response_len);

/* Individual command handlers (for testing) */
uint8_t ctap2_make_credential(bio_fido2_ctx_t *ctx,
                              const uint8_t *req, size_t req_len,
                              uint8_t *rsp, size_t *rsp_len);

uint8_t ctap2_get_assertion(bio_fido2_ctx_t *ctx,
                            const uint8_t *req, size_t req_len,
                            uint8_t *rsp, size_t *rsp_len);

uint8_t ctap2_get_info(bio_fido2_ctx_t *ctx,
                       uint8_t *rsp, size_t *rsp_len);

uint8_t ctap2_client_pin(bio_fido2_ctx_t *ctx,
                         const uint8_t *req, size_t req_len,
                         uint8_t *rsp, size_t *rsp_len);

uint8_t ctap2_reset(bio_fido2_ctx_t *ctx);

uint8_t ctap2_get_next_assertion(bio_fido2_ctx_t *ctx,
                                 uint8_t *rsp, size_t *rsp_len);

uint8_t ctap2_selection(bio_fido2_ctx_t *ctx);

/* BioEnroll (0x09) */
uint8_t ctap2_bio_enrollment(bio_fido2_ctx_t *ctx,
                             const uint8_t *req, size_t req_len,
                             uint8_t *rsp, size_t *rsp_len);

/* Reset all bio enrollment templates */
void bio_fido2_bio_reset(void);

/* CredentialManagement (0x0A) */
uint8_t ctap2_credential_management(bio_fido2_ctx_t *ctx,
                                    const uint8_t *req, size_t req_len,
                                    uint8_t *rsp, size_t *rsp_len);

/* Storage helpers */
int bio_fido2_save_credentials(bio_fido2_ctx_t *ctx);
int bio_fido2_load_credentials(bio_fido2_ctx_t *ctx);

/* Wrap key accessors (key is module-private, VULN-23 fix) */
const uint8_t *bio_fido2_get_wrap_key(void);
bool bio_fido2_wrap_key_valid(void);

/* ── Transport Layer ─────────────────────────────────────────── */

/*
 * CTAP2 transport over Unix domain socket.
 *
 * Frame format (request):
 *   [1 byte: command] [2 bytes: payload_len (BE)] [payload_len bytes: CBOR]
 *
 * Frame format (response):
 *   [1 byte: status] [2 bytes: payload_len (BE)] [payload_len bytes: CBOR]
 *
 * The socket path defaults to /run/bioauth/fido2.sock.
 */

#define BIOAUTH_FIDO2_SOCK_PATH "/run/bioauth/fido2.sock"
#define BIOAUTH_FIDO2_MAX_MSG 4096

typedef struct
{
    bio_fido2_ctx_t *fido2_ctx; /* FIDO2 authenticator context      */
    int listen_fd;              /* Listening socket fd               */
    char sock_path[256];        /* Unix socket path                  */
    volatile bool running;      /* Event loop flag                   */
    int max_clients;            /* Max simultaneous clients          */
} bio_fido2_transport_t;

/*
 * Initialize the transport layer.
 * @param tp        Transport context
 * @param fido2_ctx Initialized FIDO2 authenticator context
 * @param sock_path Unix socket path (NULL for default)
 * @return BIO_OK on success
 */
int bio_fido2_transport_init(bio_fido2_transport_t *tp,
                             bio_fido2_ctx_t *fido2_ctx,
                             const char *sock_path);

/*
 * Start listening and processing CTAP2 commands.
 * Blocks until bio_fido2_transport_stop() is called.
 * @return BIO_OK on clean shutdown
 */
int bio_fido2_transport_run(bio_fido2_transport_t *tp);

/*
 * Signal the transport layer to stop accepting connections.
 */
void bio_fido2_transport_stop(bio_fido2_transport_t *tp);

/*
 * Cleanup the transport layer (close sockets, remove socket file).
 */
void bio_fido2_transport_cleanup(bio_fido2_transport_t *tp);

#endif /* BIO_FIDO2_H */
