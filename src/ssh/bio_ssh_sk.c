/*
 * bio_ssh_sk.c — OpenSSH Security Key Middleware for Hiya
 *
 * Copyright (C) 2025 Hiya Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Implements the OpenSSH security key middleware API (sk-api.h),
 * allowing SSH to use Hiya's FIDO2 platform authenticator for
 * ecdsa-sk and ed25519-sk key types.
 *
 * This shared library is loaded by ssh/ssh-agent when the user
 * specifies it via:
 *   ssh-keygen -t ecdsa-sk -w /usr/lib64/libsk-hiya.so
 *   ssh-add -s /usr/lib64/libsk-hiya.so
 *
 * Or system-wide via /etc/ssh/ssh_config:
 *   SecurityKeyProvider /usr/lib64/libsk-hiya.so
 *
 * The middleware communicates with the Hiya FIDO2 daemon over
 * its Unix domain socket at /run/hiya/fido2.sock to perform
 * CTAP2 makeCredential and getAssertion operations.
 *
 * Key flow:
 *   1. ssh-keygen calls sk_enroll() → creates a new FIDO2 credential
 *   2. ssh calls sk_sign() → performs FIDO2 assertion with biometric
 *   3. sk_load_resident_keys() → discovers resident keys on the
 *      authenticator (for ssh-add -K)
 *
 * All operations require fingerprint verification via Hiya.
 *
 * References:
 *   OpenSSH sk-api.h (OPENSSH_SK_VERSION_MAJOR 0x000a0000)
 *   FIDO CTAP 2.1 §6.1 (authenticatorMakeCredential)
 *   FIDO CTAP 2.1 §6.2 (authenticatorGetAssertion)
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "cbor/bio_cbor.h"
#include "crypto/bio_crypto.h"

/* Secure wipe for SSH middleware (avoid optimizer elision) */
static void ssh_secure_wipe(void *p, size_t n)
{
    volatile unsigned char *vp = (volatile unsigned char *)p;
    while (n--)
        *vp++ = 0;
}

/* ── OpenSSH SK API definitions ──────────────────────────────── */
/* These mirror the OpenSSH sk-api.h structures. We define them
 * here to avoid requiring OpenSSH headers at build time. */

#define SSH_SK_VERSION_MAJOR 0x000a0000
#define SSH_SK_VERSION_MAJOR_MASK 0xffff0000

/* Algorithms */
#define SSH_SK_ECDSA 0x00
#define SSH_SK_ED25519 0x01

/* Flags (from FIDO2) */
#define SSH_SK_USER_PRESENCE_REQD 0x01
#define SSH_SK_USER_VERIFICATION_REQD 0x04
#define SSH_SK_RESIDENT_KEY 0x20

/* Enrollment response */
struct sk_enroll_response
{
    uint8_t *public_key;
    size_t public_key_len;
    uint8_t *key_handle;
    size_t key_handle_len;
    uint8_t *signature;
    size_t signature_len;
    uint8_t *attestation_cert;
    size_t attestation_cert_len;
    uint8_t *authdata;
    size_t authdata_len;
};

/* Sign response */
struct sk_sign_response
{
    uint8_t flags;
    uint32_t counter;
    uint8_t *sig_r;
    size_t sig_r_len;
    uint8_t *sig_s;
    size_t sig_s_len;
};

/* Resident key */
struct sk_resident_key
{
    uint32_t alg;
    size_t slot;
    char *application;
    struct sk_enroll_response key;
    uint8_t flags;
    uint8_t *user_id;
    size_t user_id_len;
};

/* Signing options */
struct sk_option
{
    char *name;
    char *value;
    uint8_t required;
};

/* ── CTAP2 wire protocol ─────────────────────────────────────── */

#define CTAP2_CMD_MAKE_CREDENTIAL 0x01
#define CTAP2_CMD_GET_ASSERTION 0x02
#define CTAP2_CMD_GET_INFO 0x04
#define CTAP2_CMD_CREDENTIAL_MGMT 0x0a

#define CTAP2_OK 0x00

/* COSE algorithm identifiers */
#define COSE_ALG_ES256 (-7) /* ECDSA w/ SHA-256, P-256 */

#define FIDO2_SOCK_PATH "/run/hiya/fido2.sock"
#define FIDO2_MAX_MSG 4096

/* ── Internal: Unix socket communication ─────────────────────── */

static int fido2_connect(void)
{
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;

    /* Set 30-second receive timeout to prevent hanging on unresponsive daemon */
    struct timeval tv = {.tv_sec = 30, .tv_usec = 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, FIDO2_SOCK_PATH, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        close(fd);
        return -1;
    }
    return fd;
}

static int fido2_send_recv(uint8_t cmd,
                           const uint8_t *req, size_t req_len,
                           uint8_t *rsp, size_t rsp_max,
                           size_t *rsp_len, uint8_t *status)
{
    int fd = fido2_connect();
    if (fd < 0)
        return -1;

    /* Send: [cmd:1][len:2BE][payload] */
    uint8_t header[3];
    header[0] = cmd;
    header[1] = (uint8_t)((req_len >> 8) & 0xff);
    header[2] = (uint8_t)(req_len & 0xff);

    {
        size_t hdr_sent = 0;
        while (hdr_sent < 3)
        {
            ssize_t w = write(fd, header + hdr_sent, 3 - hdr_sent);
            if (w < 0)
            {
                if (errno == EINTR)
                    continue;
                close(fd);
                return -1;
            }
            hdr_sent += (size_t)w;
        }
    }
    if (req_len > 0)
    {
        size_t sent = 0;
        while (sent < req_len)
        {
            ssize_t w = write(fd, req + sent, req_len - sent);
            if (w < 0)
            {
                if (errno == EINTR)
                    continue;
                close(fd);
                return -1;
            }
            sent += (size_t)w;
        }
    }

    /* Receive: [status:1][len:2BE][payload] */
    uint8_t rsp_header[3];
    {
        size_t hdr_done = 0;
        while (hdr_done < 3)
        {
            ssize_t n = read(fd, rsp_header + hdr_done, 3 - hdr_done);
            if (n < 0)
            {
                if (errno == EINTR)
                    continue;
                close(fd);
                return -1;
            }
            if (n == 0)
            {
                close(fd);
                return -1;
            }
            hdr_done += (size_t)n;
        }
    }

    *status = rsp_header[0];
    size_t plen = ((size_t)rsp_header[1] << 8) | rsp_header[2];

    if (plen > rsp_max)
    {
        close(fd);
        return -1;
    }

    size_t done = 0;
    while (done < plen)
    {
        ssize_t n = read(fd, rsp + done, plen - done);
        if (n < 0)
        {
            if (errno == EINTR)
                continue;
            close(fd);
            return -1;
        }
        if (n == 0)
        {
            close(fd);
            return -1;
        }
        done += (size_t)n;
    }
    *rsp_len = plen;

    close(fd);
    return 0;
}

/* ── Helper: dup bytes ───────────────────────────────────────── */

static uint8_t *dup_bytes(const uint8_t *src, size_t len)
{
    if (!src || len == 0)
        return NULL;
    uint8_t *p = malloc(len);
    if (p)
        memcpy(p, src, len);
    return p;
}

/* ── OpenSSH SK API exports ──────────────────────────────────── */

/*
 * Return the middleware version.
 * OpenSSH checks (version & SSH_SK_VERSION_MAJOR_MASK) == SSH_SK_VERSION_MAJOR.
 */
uint32_t sk_api_version(void)
{
    return SSH_SK_VERSION_MAJOR;
}

/*
 * Enroll a new security key (ssh-keygen -t ecdsa-sk / ed25519-sk).
 *
 * Sends a CTAP2 authenticatorMakeCredential command to the Hiya
 * FIDO2 daemon. The user will be prompted for fingerprint verification.
 */
int sk_enroll(uint32_t alg,
              const uint8_t *challenge, size_t challenge_len,
              const char *application,
              uint8_t flags,
              const char *pin,
              struct sk_option **options,
              struct sk_enroll_response **enroll_response)
{
    (void)pin;
    (void)options;

    if (!challenge || !application || !enroll_response)
        return -1;

    if (alg == SSH_SK_ED25519)
    {
        fprintf(stderr, "Hiya: Ed25519 security keys (ed25519-sk) are not "
                        "supported.\nUse: ssh-keygen -t ecdsa-sk\n");
        return -1;
    }

    fprintf(stderr, "Hiya: enrolling SSH key for '%s' "
                    "(touch your fingerprint reader)\n",
            application);

    /*
     * Build a proper CTAP2 authenticatorMakeCredential CBOR request.
     * CTAP2 §6.1:
     *   Map {
     *     0x01: clientDataHash (bstr, 32 bytes)
     *     0x02: rp (map: { "id": tstr })
     *     0x03: user (map: { "id": bstr, "name": tstr })
     *     0x04: pubKeyCredParams (array of map: { "type": "public-key", "alg": int })
     *     0x07: options (map: { "rk": bool })   [optional]
     *   }
     */
    uint8_t req[FIDO2_MAX_MSG];
    bio_cbor_encoder_t enc;
    bio_cbor_encoder_init(&enc, req, sizeof(req));

    /* clientDataHash: OpenSSH passes a 32-byte challenge that serves
     * as the clientDataHash directly. Pad/truncate if needed. */
    uint8_t client_data_hash[32];
    memset(client_data_hash, 0, sizeof(client_data_hash));
    size_t copy_len = challenge_len < 32 ? challenge_len : 32;
    memcpy(client_data_hash, challenge, copy_len);

    /* Determine if resident key requested */
    bool resident = (flags & SSH_SK_RESIDENT_KEY) != 0;
    int map_items = resident ? 5 : 4; /* 0x01..0x04 + optionally 0x07 */

    /* Top-level CBOR map */
    bio_cbor_encode_map(&enc, map_items);

    /* 0x01: clientDataHash */
    bio_cbor_encode_uint(&enc, 0x01);
    bio_cbor_encode_bstr(&enc, client_data_hash, 32);

    /* 0x02: rp = { "id": application } */
    bio_cbor_encode_uint(&enc, 0x02);
    bio_cbor_encode_map(&enc, 1);
    bio_cbor_encode_tstr_z(&enc, "id");
    bio_cbor_encode_tstr_z(&enc, application);

    /* 0x03: user = { "id": <random 32 bytes>, "name": "ssh:<app>" } */
    bio_cbor_encode_uint(&enc, 0x03);
    bio_cbor_encode_map(&enc, 2);
    {
        /* Generate a random user ID per FIDO2 §6.1 recommendation.
         * Each enrollment gets a unique 32-byte random user handle. */
        uint8_t user_id[32];
        if (bio_random_bytes(user_id, sizeof(user_id)) != BIO_OK)
        {
            fprintf(stderr, "Hiya: RNG failure in sk_enroll\n");
            ssh_secure_wipe(client_data_hash, sizeof(client_data_hash));
            ssh_secure_wipe(req, sizeof(req));
            return -1;
        }

        bio_cbor_encode_tstr_z(&enc, "id");
        bio_cbor_encode_bstr(&enc, user_id, sizeof(user_id));

        char user_name[320];
        snprintf(user_name, sizeof(user_name), "ssh:%s", application);
        bio_cbor_encode_tstr_z(&enc, "name");
        bio_cbor_encode_tstr_z(&enc, user_name);
    }

    /* 0x04: pubKeyCredParams — ES256 only.
     * Ed25519 is rejected above. */
    bio_cbor_encode_uint(&enc, 0x04);
    bio_cbor_encode_array(&enc, 1);
    bio_cbor_encode_map(&enc, 2);
    bio_cbor_encode_tstr_z(&enc, "alg");
    bio_cbor_encode_int(&enc, COSE_ALG_ES256); /* -7 */
    bio_cbor_encode_tstr_z(&enc, "type");
    bio_cbor_encode_tstr_z(&enc, "public-key");

    /* 0x07: options = { "rk": true } (only if resident key) */
    if (resident)
    {
        bio_cbor_encode_uint(&enc, 0x07);
        bio_cbor_encode_map(&enc, 1);
        bio_cbor_encode_tstr_z(&enc, "rk");
        bio_cbor_encode_bool(&enc, true);
    }

    if (bio_cbor_encoder_has_error(&enc))
    {
        fprintf(stderr, "Hiya: CBOR encode error in sk_enroll\n");
        ssh_secure_wipe(client_data_hash, sizeof(client_data_hash));
        ssh_secure_wipe(req, sizeof(req));
        return -1;
    }

    size_t req_len = bio_cbor_encoder_len(&enc);

    uint8_t rsp[FIDO2_MAX_MSG];
    size_t rsp_len = 0;
    uint8_t status = 0;

    int rc = fido2_send_recv(CTAP2_CMD_MAKE_CREDENTIAL,
                             req, req_len,
                             rsp, sizeof(rsp), &rsp_len, &status);
    /* Wipe request buffer containing challenge material */
    ssh_secure_wipe(client_data_hash, sizeof(client_data_hash));
    ssh_secure_wipe(req, sizeof(req));

    if (rc != 0 || status != CTAP2_OK)
    {
        fprintf(stderr, "Hiya: key enrollment failed "
                        "(rc=%d, status=0x%02x)\n",
                rc, status);
        ssh_secure_wipe(rsp, sizeof(rsp));
        return -1;
    }

    /*
     * Parse the CTAP2 MakeCredential CBOR response:
     *   Map {
     *     0x01: fmt (tstr)
     *     0x02: authData (bstr)
     *     0x03: attStmt (map)
     *   }
     * We need authData (which contains rpIdHash + flags + counter +
     * attestedCredentialData with AAGUID + credIdLen + credId + pubKeyCOSE).
     */
    struct sk_enroll_response *resp = calloc(1, sizeof(*resp));
    if (!resp)
        return -1;

    bio_cbor_decoder_t dec;
    bio_cbor_decoder_init(&dec, rsp, rsp_len);

    size_t map_count = 0;
    if (bio_cbor_decode_map(&dec, &map_count) != BIO_OK || map_count == 0)
    {
        /* Fallback: treat as raw authData (pre-CBOR response) */
        resp->authdata = dup_bytes(rsp, rsp_len);
        resp->authdata_len = rsp_len;
        goto parse_authdata;
    }

    /* Walk the response map looking for key 0x02 (authData) */
    const uint8_t *auth_data = NULL;
    size_t auth_data_len = 0;

    for (size_t i = 0; i < map_count; i++)
    {
        bio_cbor_item_t key_item;
        if (bio_cbor_decode_next(&dec, &key_item) != BIO_OK)
            break;

        if (key_item.type == BIO_CBOR_UINT && key_item.uint_val == 0x02)
        {
            /* authData */
            if (bio_cbor_decode_bstr(&dec, &auth_data, &auth_data_len) != BIO_OK)
                break;
        }
        else
        {
            bio_cbor_skip(&dec);
        }
    }

    if (auth_data && auth_data_len > 0)
    {
        resp->authdata = dup_bytes(auth_data, auth_data_len);
        resp->authdata_len = auth_data_len;
    }

parse_authdata:
    /*
     * Extract public key and credential ID from authData:
     *   rpIdHash[32] + flags[1] + counter[4] = 37 bytes
     *   if (flags & 0x40) → attestedCredentialData:
     *     aaguid[16] + credIdLen[2 BE] + credId[N] + pubKeyCOSE[...]
     */
    if (resp->authdata && resp->authdata_len > 37 + 18)
    {
        const uint8_t *ad = resp->authdata;
        uint8_t ad_flags = ad[32];

        if (ad_flags & 0x40)
        { /* AT flag: attested credential data */
            uint16_t cred_id_len = ((uint16_t)ad[53] << 8) | ad[54];
            size_t cred_start = 55;

            if (cred_start + cred_id_len < resp->authdata_len)
            {
                resp->key_handle = dup_bytes(ad + cred_start, cred_id_len);
                resp->key_handle_len = cred_id_len;

                size_t pk_off = cred_start + cred_id_len;
                size_t pk_len = resp->authdata_len - pk_off;
                if (pk_len > 0)
                {
                    resp->public_key = dup_bytes(ad + pk_off, pk_len);
                    resp->public_key_len = pk_len;
                }
            }
        }
    }

    if (!resp->key_handle || !resp->public_key)
    {
        fprintf(stderr, "Hiya: sk_enroll: missing credential data in response\n");
        free(resp->key_handle);
        free(resp->public_key);
        free(resp->signature);
        free(resp->attestation_cert);
        free(resp->authdata);
        free(resp);
        ssh_secure_wipe(rsp, sizeof(rsp));
        return -1;
    }

    *enroll_response = resp;
    fprintf(stderr, "Hiya: SSH key enrolled successfully\n");
    ssh_secure_wipe(rsp, sizeof(rsp));
    return 0;
}

/*
 * Sign a challenge (SSH authentication).
 *
 * Sends a CTAP2 authenticatorGetAssertion command to the Hiya
 * FIDO2 daemon. The user will be prompted for fingerprint verification.
 */
int sk_sign(uint32_t alg,
            const uint8_t *data, size_t data_len,
            const char *application,
            const uint8_t *key_handle, size_t key_handle_len,
            uint8_t flags,
            const char *pin,
            struct sk_option **options,
            struct sk_sign_response **sign_response)
{
    (void)flags;
    (void)pin;
    (void)options;

    if (!data || !application || !sign_response)
        return -1;

    /*
     * Build a proper CTAP2 authenticatorGetAssertion CBOR request.
     * CTAP2 §6.2:
     *   Map {
     *     0x01: rpId (tstr)
     *     0x02: clientDataHash (bstr, 32 bytes)
     *     0x03: allowList (array of map: { "type": "public-key", "id": bstr })
     *   }
     */
    uint8_t req[FIDO2_MAX_MSG];
    bio_cbor_encoder_t enc;
    bio_cbor_encoder_init(&enc, req, sizeof(req));

    /* clientDataHash: OpenSSH passes the 32-byte hash directly */
    uint8_t client_data_hash[32];
    memset(client_data_hash, 0, sizeof(client_data_hash));
    size_t copy_len = data_len < 32 ? data_len : 32;
    memcpy(client_data_hash, data, copy_len);

    bool have_allow_list = (key_handle && key_handle_len > 0);
    int map_items = have_allow_list ? 3 : 2;

    bio_cbor_encode_map(&enc, map_items);

    /* 0x01: rpId */
    bio_cbor_encode_uint(&enc, 0x01);
    bio_cbor_encode_tstr_z(&enc, application);

    /* 0x02: clientDataHash */
    bio_cbor_encode_uint(&enc, 0x02);
    bio_cbor_encode_bstr(&enc, client_data_hash, 32);

    /* 0x03: allowList */
    if (have_allow_list)
    {
        bio_cbor_encode_uint(&enc, 0x03);
        bio_cbor_encode_array(&enc, 1);
        bio_cbor_encode_map(&enc, 2);
        bio_cbor_encode_tstr_z(&enc, "id");
        bio_cbor_encode_bstr(&enc, key_handle, key_handle_len);
        bio_cbor_encode_tstr_z(&enc, "type");
        bio_cbor_encode_tstr_z(&enc, "public-key");
    }

    if (bio_cbor_encoder_has_error(&enc))
    {
        fprintf(stderr, "Hiya: CBOR encode error in sk_sign\n");
        ssh_secure_wipe(client_data_hash, sizeof(client_data_hash));
        ssh_secure_wipe(req, sizeof(req));
        return -1;
    }

    size_t req_len = bio_cbor_encoder_len(&enc);

    uint8_t rsp[FIDO2_MAX_MSG];
    size_t rsp_len = 0;
    uint8_t status = 0;

    int rc = fido2_send_recv(CTAP2_CMD_GET_ASSERTION,
                             req, req_len,
                             rsp, sizeof(rsp), &rsp_len, &status);
    /* Wipe request buffer containing challenge material */
    ssh_secure_wipe(client_data_hash, sizeof(client_data_hash));
    ssh_secure_wipe(req, sizeof(req));

    if (rc != 0 || status != CTAP2_OK)
    {
        fprintf(stderr, "Hiya: SSH sign failed "
                        "(rc=%d, status=0x%02x)\n",
                rc, status);
        ssh_secure_wipe(rsp, sizeof(rsp));
        return -1;
    }

    /*
     * Parse the CTAP2 GetAssertion CBOR response:
     *   Map {
     *     0x01: credential (map)
     *     0x02: authData (bstr)
     *     0x03: signature (bstr)
     *     0x04: user (map, optional)
     *   }
     * We need authData (for flags + counter) and signature.
     */
    struct sk_sign_response *resp = calloc(1, sizeof(*resp));
    if (!resp)
        return -1;

    bio_cbor_decoder_t dec;
    bio_cbor_decoder_init(&dec, rsp, rsp_len);

    size_t map_count = 0;
    if (bio_cbor_decode_map(&dec, &map_count) != BIO_OK || map_count == 0)
    {
        /* Fallback: treat as raw authData + signature (legacy) */
        goto parse_raw;
    }

    const uint8_t *auth_data = NULL;
    size_t auth_data_len = 0;
    const uint8_t *sig_data = NULL;
    size_t sig_len = 0;

    for (size_t i = 0; i < map_count; i++)
    {
        bio_cbor_item_t key_item;
        if (bio_cbor_decode_next(&dec, &key_item) != BIO_OK)
            break;

        if (key_item.type == BIO_CBOR_UINT && key_item.uint_val == 0x02)
        {
            /* authData */
            bio_cbor_decode_bstr(&dec, &auth_data, &auth_data_len);
        }
        else if (key_item.type == BIO_CBOR_UINT && key_item.uint_val == 0x03)
        {
            /* signature */
            bio_cbor_decode_bstr(&dec, &sig_data, &sig_len);
        }
        else
        {
            bio_cbor_skip(&dec);
        }
    }

    /* Extract flags + counter from authData */
    if (auth_data && auth_data_len >= 37)
    {
        resp->flags = auth_data[32];
        resp->counter = ((uint32_t)auth_data[33] << 24) |
                        ((uint32_t)auth_data[34] << 16) |
                        ((uint32_t)auth_data[35] << 8) |
                        (uint32_t)auth_data[36];
    }

    /* Parse signature — DER-encoded for ECDSA */
    if (sig_data && sig_len > 0 && alg == SSH_SK_ECDSA)
    {
        const uint8_t *p = sig_data;
        const uint8_t *end = p + sig_len;
        if (sig_len >= 6 && p[0] == 0x30)
        {
            size_t seq_len = p[1];
            p += 2;
            if (p + seq_len > end)
                seq_len = (size_t)(end - p);
            const uint8_t *seq_end = p + seq_len;
            if (p < seq_end && p[0] == 0x02)
            {
                p++;
                if (p >= seq_end)
                    goto der_done;
                size_t r_len = *p++;
                if (r_len > 0 && p + r_len <= seq_end)
                {
                    const uint8_t *r_data = p;
                    size_t r_out = r_len;
                    if (r_out > 0 && r_data[0] == 0x00)
                    {
                        r_data++;
                        r_out--;
                    }
                    resp->sig_r = dup_bytes(r_data, r_out);
                    resp->sig_r_len = r_out;
                    p += r_len;
                }
            }
            if (p < seq_end && p[0] == 0x02)
            {
                p++;
                if (p >= seq_end)
                    goto der_done;
                size_t s_len = *p++;
                if (s_len > 0 && p + s_len <= seq_end)
                {
                    const uint8_t *s_data = p;
                    size_t s_out = s_len;
                    if (s_out > 0 && s_data[0] == 0x00)
                    {
                        s_data++;
                        s_out--;
                    }
                    resp->sig_s = dup_bytes(s_data, s_out);
                    resp->sig_s_len = s_out;
                }
            }
        }
    der_done:;
    }
    else if (sig_data && sig_len > 0)
    {
        /* Ed25519 or unknown: raw signature, split in half */
        size_t half = sig_len / 2;
        resp->sig_r = dup_bytes(sig_data, half);
        resp->sig_r_len = half;
        resp->sig_s = dup_bytes(sig_data + half, sig_len - half);
        resp->sig_s_len = sig_len - half;
    }

    if (!resp->sig_r || !resp->sig_s)
    {
        free(resp->sig_r);
        free(resp->sig_s);
        free(resp);
        ssh_secure_wipe(rsp, sizeof(rsp));
        return -1;
    }

    *sign_response = resp;
    ssh_secure_wipe(rsp, sizeof(rsp));
    return 0;

parse_raw:
    /* Legacy raw format fallback */
    if (rsp_len >= 37)
    {
        resp->flags = rsp[32];
        resp->counter = ((uint32_t)rsp[33] << 24) |
                        ((uint32_t)rsp[34] << 16) |
                        ((uint32_t)rsp[35] << 8) |
                        (uint32_t)rsp[36];

        size_t sig_off = 37;
        size_t raw_sig_len = rsp_len - sig_off;
        if (raw_sig_len > 0 && alg == SSH_SK_ECDSA)
        {
            const uint8_t *p = rsp + sig_off;
            const uint8_t *end = p + raw_sig_len;
            if (raw_sig_len >= 6 && p[0] == 0x30)
            {
                size_t seq_len = p[1];
                p += 2;
                if (p + seq_len > end)
                    seq_len = (size_t)(end - p);
                const uint8_t *seq_end = p + seq_len;
                if (p < seq_end && p[0] == 0x02)
                {
                    p++;
                    if (p < seq_end)
                    {
                        size_t r_len = *p++;
                        if (r_len > 0 && p + r_len <= seq_end)
                        {
                            const uint8_t *r_data = p;
                            size_t r_out = r_len;
                            if (r_out > 0 && r_data[0] == 0x00)
                            {
                                r_data++;
                                r_out--;
                            }
                            resp->sig_r = dup_bytes(r_data, r_out);
                            resp->sig_r_len = r_out;
                            p += r_len;
                        }
                    }
                }
                if (p < seq_end && p[0] == 0x02)
                {
                    p++;
                    if (p < seq_end)
                    {
                        size_t s_len = *p++;
                        if (s_len > 0 && p + s_len <= seq_end)
                        {
                            const uint8_t *s_data = p;
                            size_t s_out = s_len;
                            if (s_out > 0 && s_data[0] == 0x00)
                            {
                                s_data++;
                                s_out--;
                            }
                            resp->sig_s = dup_bytes(s_data, s_out);
                            resp->sig_s_len = s_out;
                        }
                    }
                }
            }
        }
        else if (raw_sig_len > 0)
        {
            size_t half = raw_sig_len / 2;
            resp->sig_r = dup_bytes(rsp + sig_off, half);
            resp->sig_r_len = half;
            resp->sig_s = dup_bytes(rsp + sig_off + half, raw_sig_len - half);
            resp->sig_s_len = raw_sig_len - half;
        }
    }

    if (!resp->sig_r || !resp->sig_s)
    {
        free(resp->sig_r);
        free(resp->sig_s);
        free(resp);
        ssh_secure_wipe(rsp, sizeof(rsp));
        return -1;
    }

    *sign_response = resp;
    ssh_secure_wipe(rsp, sizeof(rsp));
    return 0;
}
void sk_resident_free(struct sk_resident_key *rk)
{
    if (!rk)
        return;
    free(rk->application);
    free(rk->user_id);
    free(rk->key.public_key);
    free(rk->key.key_handle);
    free(rk->key.signature);
    free(rk->key.attestation_cert);
    free(rk->key.authdata);
    free(rk);
}

/*
 * Load resident keys from the authenticator (ssh-add -K).
 *
 * Queries Hiya's FIDO2 daemon for discoverable credentials
 * and returns them as SSH keys.
 */
int sk_load_resident_keys(const char *pin,
                          struct sk_option **options,
                          struct sk_resident_key ***rks,
                          size_t *nrks)
{
    (void)pin;
    (void)options;

    if (!rks || !nrks)
        return -1;

    *rks = NULL;
    *nrks = 0;

    /* Send credential management enumerate command.
     * CTAP2 §6.8: authenticatorCredentialManagement
     * subCommand 0x02 = enumerateRPsBegin
     */
    uint8_t req[FIDO2_MAX_MSG];
    bio_cbor_encoder_t enc;
    bio_cbor_encoder_init(&enc, req, sizeof(req));

    /* Build CBOR map { 0x01: 0x02 } (subCommand: enumerateRPsBegin) */
    bio_cbor_encode_map(&enc, 1);
    bio_cbor_encode_uint(&enc, 0x01);
    bio_cbor_encode_uint(&enc, 0x02);

    size_t req_len = bio_cbor_encoder_has_error(&enc) ? 0 : bio_cbor_encoder_len(&enc);

    uint8_t rsp[FIDO2_MAX_MSG];
    size_t rsp_len = 0;
    uint8_t status = 0;

    int rc = fido2_send_recv(CTAP2_CMD_CREDENTIAL_MGMT,
                             req, req_len,
                             rsp, sizeof(rsp), &rsp_len, &status);
    if (rc != 0 || status != CTAP2_OK)
    {
        /* No resident keys or not supported — not an error */
        return 0;
    }

    /* Parse resident keys from response.
     * CTAP2 §6.8.3: enumerateRPsBegin returns:
     *   0x03: rp (map with "id")
     *   0x04: rpIDHash (32 bytes)
     *   0x05: totalRPs (uint)
     *
     * We then call enumerateCredentialsBegin for each RP to get
     * the actual credential+key pairs.
     */

    bio_cbor_decoder_t dec;
    bio_cbor_decoder_init(&dec, rsp, rsp_len);

    uint64_t rp_map_cnt;
    if (bio_cbor_decode_map(&dec, &rp_map_cnt) != BIO_OK)
    {
        return 0; /* Can't parse — report no keys */
    }

    uint64_t total_rps = 0;
    char first_rp_id[256] = {0};
    uint8_t first_rp_id_hash[32] = {0};

    for (uint64_t i = 0; i < rp_map_cnt; i++)
    {
        uint64_t key;
        if (bio_cbor_decode_uint(&dec, &key) != BIO_OK)
            break;

        if (key == 0x03)
        {
            /* rp map — extract "id" */
            uint64_t inner_cnt;
            if (bio_cbor_decode_map(&dec, &inner_cnt) != BIO_OK)
                break;
            for (uint64_t j = 0; j < inner_cnt; j++)
            {
                bio_cbor_item_t mk;
                if (bio_cbor_decode_next(&dec, &mk) != BIO_OK)
                    break;
                if (mk.type == BIO_CBOR_TSTR && mk.tstr.len == 2 &&
                    memcmp(mk.tstr.data, "id", 2) == 0)
                {
                    bio_cbor_item_t val;
                    if (bio_cbor_decode_next(&dec, &val) != BIO_OK)
                        break;
                    if (val.type == BIO_CBOR_TSTR)
                    {
                        size_t cp = val.tstr.len < sizeof(first_rp_id) - 1
                                        ? val.tstr.len
                                        : sizeof(first_rp_id) - 1;
                        memcpy(first_rp_id, val.tstr.data, cp);
                    }
                }
                else
                {
                    bio_cbor_skip(&dec);
                }
            }
        }
        else if (key == 0x04)
        {
            bio_cbor_item_t val;
            if (bio_cbor_decode_next(&dec, &val) != BIO_OK)
                break;
            if (val.type == BIO_CBOR_BSTR && val.bstr.len == 32)
                memcpy(first_rp_id_hash, val.bstr.data, 32);
        }
        else if (key == 0x05)
        {
            bio_cbor_decode_uint(&dec, &total_rps);
        }
        else
        {
            bio_cbor_skip(&dec);
        }
    }

    if (total_rps == 0 || first_rp_id[0] == '\0')
    {
        fprintf(stderr, "Hiya: no resident keys found\n");
        return 0;
    }

    /* For each RP, enumerate credentials.
     * For simplicity, we handle the first RP's credentials.
     * Full implementation would iterate all RPs via getNextRP. */
    size_t key_count = 0;
    struct sk_resident_key **keys = NULL;

    /* enumerateCredentialsBegin for the first RP */
    bio_cbor_encoder_init(&enc, req, sizeof(req));
    bio_cbor_encode_map(&enc, 2);
    bio_cbor_encode_uint(&enc, 0x01); /* subCommand */
    bio_cbor_encode_uint(&enc, 0x04); /* enumerateCredentialsBegin */
    bio_cbor_encode_uint(&enc, 0x02); /* subCommandParams */
    bio_cbor_encode_map(&enc, 1);
    bio_cbor_encode_uint(&enc, 0x01); /* rpIDHash */
    bio_cbor_encode_bstr(&enc, first_rp_id_hash, 32);

    req_len = bio_cbor_encoder_has_error(&enc) ? 0 : bio_cbor_encoder_len(&enc);

    rc = fido2_send_recv(CTAP2_CMD_CREDENTIAL_MGMT,
                         req, req_len,
                         rsp, sizeof(rsp), &rsp_len, &status);
    if (rc != 0 || status != CTAP2_OK)
    {
        fprintf(stderr, "Hiya: credential enumeration failed\n");
        return 0;
    }

    /* Parse credential response:
     *   0x06: user (map with "id", "name")
     *   0x07: credentialID (map with "id", "type")
     *   0x08: publicKey (COSE_Key map)
     *   0x09: totalCredentials (uint)
     */
    bio_cbor_decoder_init(&dec, rsp, rsp_len);
    if (bio_cbor_decode_map(&dec, &rp_map_cnt) != BIO_OK)
    {
        return 0;
    }

    uint8_t cred_pubkey[65] = {0};
    uint8_t cred_id_buf[128] = {0};
    size_t cred_id_len = 0;
    uint8_t user_id_buf[64] = {0};
    size_t user_id_len = 0;
    uint64_t total_creds = 0;
    int cred_alg = SSH_SK_ECDSA; /* default; updated from COSE key */

    for (uint64_t i = 0; i < rp_map_cnt; i++)
    {
        uint64_t key;
        if (bio_cbor_decode_uint(&dec, &key) != BIO_OK)
            break;

        if (key == 0x06)
        {
            /* user entity */
            uint64_t ucnt;
            if (bio_cbor_decode_map(&dec, &ucnt) != BIO_OK)
                break;
            for (uint64_t j = 0; j < ucnt; j++)
            {
                bio_cbor_item_t mk;
                if (bio_cbor_decode_next(&dec, &mk) != BIO_OK)
                    break;
                if (mk.type == BIO_CBOR_TSTR && mk.tstr.len == 2 &&
                    memcmp(mk.tstr.data, "id", 2) == 0)
                {
                    bio_cbor_item_t val;
                    if (bio_cbor_decode_next(&dec, &val) != BIO_OK)
                        break;
                    if (val.type == BIO_CBOR_BSTR)
                    {
                        user_id_len = val.bstr.len < 64 ? val.bstr.len : 64;
                        memcpy(user_id_buf, val.bstr.data, user_id_len);
                    }
                }
                else
                {
                    bio_cbor_skip(&dec);
                }
            }
        }
        else if (key == 0x07)
        {
            /* credentialID */
            uint64_t ccnt;
            if (bio_cbor_decode_map(&dec, &ccnt) != BIO_OK)
                break;
            for (uint64_t j = 0; j < ccnt; j++)
            {
                bio_cbor_item_t mk;
                if (bio_cbor_decode_next(&dec, &mk) != BIO_OK)
                    break;
                if (mk.type == BIO_CBOR_TSTR && mk.tstr.len == 2 &&
                    memcmp(mk.tstr.data, "id", 2) == 0)
                {
                    bio_cbor_item_t val;
                    if (bio_cbor_decode_next(&dec, &val) != BIO_OK)
                        break;
                    if (val.type == BIO_CBOR_BSTR)
                    {
                        cred_id_len = val.bstr.len < 128 ? val.bstr.len : 128;
                        memcpy(cred_id_buf, val.bstr.data, cred_id_len);
                    }
                }
                else
                {
                    bio_cbor_skip(&dec);
                }
            }
        }
        else if (key == 0x08)
        {
            /* publicKey (COSE_Key) — extract x, y coordinates */
            uint64_t pcnt;
            if (bio_cbor_decode_map(&dec, &pcnt) != BIO_OK)
                break;
            cred_pubkey[0] = 0x04; /* uncompressed */
            for (uint64_t j = 0; j < pcnt; j++)
            {
                bio_cbor_item_t mk;
                if (bio_cbor_decode_next(&dec, &mk) != BIO_OK)
                    break;
                if (mk.type == BIO_CBOR_NEGINT && mk.int_val == -2)
                {
                    /* x coordinate */
                    bio_cbor_item_t val;
                    if (bio_cbor_decode_next(&dec, &val) != BIO_OK)
                        break;
                    if (val.type == BIO_CBOR_BSTR && val.bstr.len == 32)
                        memcpy(cred_pubkey + 1, val.bstr.data, 32);
                }
                else if (mk.type == BIO_CBOR_NEGINT && mk.int_val == -3)
                {
                    /* y coordinate */
                    bio_cbor_item_t val;
                    if (bio_cbor_decode_next(&dec, &val) != BIO_OK)
                        break;
                    if (val.type == BIO_CBOR_BSTR && val.bstr.len == 32)
                        memcpy(cred_pubkey + 33, val.bstr.data, 32);
                }
                else if (mk.type == BIO_CBOR_UINT && mk.uint_val == 3)
                {
                    /* COSE alg parameter: only ES256 (-7) is supported */
                    bio_cbor_item_t val;
                    if (bio_cbor_decode_next(&dec, &val) != BIO_OK)
                        break;
                    if (val.type == BIO_CBOR_NEGINT && val.int_val == -7)
                        cred_alg = SSH_SK_ECDSA;
                    else
                    {
                        /* Unsupported algorithm — skip this credential */
                        cred_alg = -1;
                    }
                }
                else
                {
                    bio_cbor_skip(&dec);
                }
            }
        }
        else if (key == 0x09)
        {
            bio_cbor_decode_uint(&dec, &total_creds);
        }
        else
        {
            bio_cbor_skip(&dec);
        }
    }

    /* Build SSH resident key structure if we got a valid ES256 credential */
    if (cred_id_len > 0 && cred_pubkey[0] == 0x04 && cred_alg == SSH_SK_ECDSA)
    {
        struct sk_resident_key *rk = calloc(1, sizeof(*rk));
        if (!rk)
            return -1;

        rk->alg = cred_alg;
        rk->application = strdup(first_rp_id);
        if (!rk->application)
        {
            free(rk);
            return -1;
        }
        if (user_id_len > 0)
        {
            rk->user_id = dup_bytes(user_id_buf, user_id_len);
            rk->user_id_len = user_id_len;
        }

        rk->key.public_key = dup_bytes(cred_pubkey, 65);
        rk->key.public_key_len = 65;
        rk->key.key_handle = dup_bytes(cred_id_buf, cred_id_len);
        rk->key.key_handle_len = cred_id_len;

        keys = calloc(1, sizeof(*keys));
        if (!keys)
        {
            sk_resident_free(rk);
            return -1;
        }
        keys[0] = rk;
        key_count = 1;
    }

    *rks = keys;
    *nrks = key_count;

    fprintf(stderr, "Hiya: resident key enumeration complete "
                    "(%zu keys)\n",
            *nrks);
    return 0;
}

/* ── Memory cleanup functions (called by OpenSSH) ────────────── */

void sk_enroll_free(struct sk_enroll_response *resp)
{
    if (!resp)
        return;
    free(resp->public_key);
    free(resp->key_handle);
    free(resp->signature);
    free(resp->attestation_cert);
    free(resp->authdata);
    free(resp);
}

void sk_sign_free(struct sk_sign_response *resp)
{
    if (!resp)
        return;
    if (resp->sig_r)
    {
        ssh_secure_wipe(resp->sig_r, resp->sig_r_len);
        free(resp->sig_r);
    }
    if (resp->sig_s)
    {
        ssh_secure_wipe(resp->sig_s, resp->sig_s_len);
        free(resp->sig_s);
    }
    ssh_secure_wipe(resp, sizeof(*resp));
    free(resp);
}
