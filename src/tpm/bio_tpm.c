/*
 * bio_tpm.c — TPM 2.0 Direct Interface via /dev/tpmrm0
 *
 * Copyright (C) 2024 Hiya Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Implements raw TPM 2.0 command marshaling and execution.
 * All commands are sent as properly formatted TPM2 packets
 * directly to the kernel resource manager.
 *
 * TPM 2.0 command packet layout:
 *   Offset  Size  Field
 *   0       2     tag (TPM_ST_NO_SESSIONS or TPM_ST_SESSIONS)
 *   2       4     commandSize (total packet length)
 *   6       4     commandCode (TPM_CC_*)
 *   10      var   command parameters (0 or more)
 *
 * TPM 2.0 response packet layout:
 *   Offset  Size  Field
 *   0       2     tag
 *   2       4     responseSize
 *   6       4     responseCode (TPM_RC_SUCCESS = 0)
 *   10      var   response parameters
 */

#include "bio_tpm.h"
#include "crypto/bio_crypto.h"

#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>

/* ── Marshal helpers ──────────────────────────────────────────── */

static void marshal_init(bio_tpm_marshal_t *m, uint8_t *buf, size_t cap)
{
    m->buf = buf;
    m->capacity = cap;
    m->offset = 0;
    m->error = false;
}

static void marshal_u8(bio_tpm_marshal_t *m, uint8_t val)
{
    if (m->error || m->offset + 1 > m->capacity)
    {
        m->error = true;
        return;
    }
    m->buf[m->offset++] = val;
}

static void marshal_u16(bio_tpm_marshal_t *m, uint16_t val)
{
    if (m->error || m->offset + 2 > m->capacity)
    {
        m->error = true;
        return;
    }
    m->buf[m->offset++] = (uint8_t)(val >> 8);
    m->buf[m->offset++] = (uint8_t)(val);
}

static void marshal_u32(bio_tpm_marshal_t *m, uint32_t val)
{
    if (m->error || m->offset + 4 > m->capacity)
    {
        m->error = true;
        return;
    }
    m->buf[m->offset++] = (uint8_t)(val >> 24);
    m->buf[m->offset++] = (uint8_t)(val >> 16);
    m->buf[m->offset++] = (uint8_t)(val >> 8);
    m->buf[m->offset++] = (uint8_t)(val);
}

static void marshal_bytes(bio_tpm_marshal_t *m,
                          const uint8_t *data, size_t len)
{
    if (m->error || m->offset + len > m->capacity)
    {
        m->error = true;
        return;
    }
    memcpy(m->buf + m->offset, data, len);
    m->offset += len;
}

/*
 * Marshal a TPM2B: 2-byte size prefix + data bytes.
 */
static void marshal_tpm2b(bio_tpm_marshal_t *m,
                          const uint8_t *data, uint16_t len)
{
    marshal_u16(m, len);
    if (len > 0 && data)
        marshal_bytes(m, data, len);
}

/*
 * Start a command: write tag, placeholder for size, command code.
 * The size field will be patched after the full command is built.
 */
static void marshal_command_header(bio_tpm_marshal_t *m,
                                   uint16_t tag, uint32_t cc)
{
    marshal_u16(m, tag);
    marshal_u32(m, 0); /* size placeholder — patched later */
    marshal_u32(m, cc);
}

/*
 * Finalize command: patch the size field.
 */
static void marshal_command_finalize(bio_tpm_marshal_t *m)
{
    if (m->error)
        return;
    uint32_t size = (uint32_t)m->offset;
    m->buf[2] = (uint8_t)(size >> 24);
    m->buf[3] = (uint8_t)(size >> 16);
    m->buf[4] = (uint8_t)(size >> 8);
    m->buf[5] = (uint8_t)(size);
}

/*
 * Marshal a password authorization area (for TPM_ST_SESSIONS commands).
 *
 * Authorization area format:
 *   [4B authorizationSize]
 *   [4B sessionHandle = TPM_RS_PW]
 *   [2B nonceTpm.size = 0]
 *   [1B sessionAttributes = continueSession]
 *   [2B hmac.size + hmac.buffer = auth password]
 */
static void marshal_password_auth(bio_tpm_marshal_t *m,
                                  const uint8_t *auth, size_t auth_len)
{
    /* Validate: if auth_len > 0, auth must not be NULL */
    if (auth_len > 0 && !auth)
    {
        m->error = true;
        return;
    }
    if (auth_len > UINT16_MAX)
    {
        m->error = true;
        return;
    }

    /* Calculate size of auth area (excluding the 4-byte size prefix):
     * 4 (handle) + 2 (nonce size=0) + 1 (attributes) + 2 (auth size) + auth_len
     */
    uint32_t auth_area_size = 4 + 2 + 1 + 2 + (uint32_t)auth_len;
    marshal_u32(m, auth_area_size);

    marshal_u32(m, TPM2_RS_PW);                 /* Session handle = password */
    marshal_u16(m, 0);                          /* nonceTpm.size = 0 */
    marshal_u8(m, 0x01);                        /* sessionAttributes: continueSession */
    marshal_tpm2b(m, auth, (uint16_t)auth_len); /* hmac = password */
}

/* ── Unmarshal helpers ────────────────────────────────────────── */

static void unmarshal_init(bio_tpm_unmarshal_t *u,
                           const uint8_t *buf, size_t size)
{
    u->buf = buf;
    u->size = size;
    u->offset = 0;
    u->error = false;
}

static uint8_t unmarshal_u8(bio_tpm_unmarshal_t *u)
{
    if (u->error || u->offset + 1 > u->size)
    {
        u->error = true;
        return 0;
    }
    return u->buf[u->offset++];
}

static uint16_t unmarshal_u16(bio_tpm_unmarshal_t *u)
{
    if (u->error || u->offset + 2 > u->size)
    {
        u->error = true;
        return 0;
    }
    uint16_t val = ((uint16_t)u->buf[u->offset] << 8) |
                   u->buf[u->offset + 1];
    u->offset += 2;
    return val;
}

static uint32_t unmarshal_u32(bio_tpm_unmarshal_t *u)
{
    if (u->error || u->offset + 4 > u->size)
    {
        u->error = true;
        return 0;
    }
    uint32_t val = ((uint32_t)u->buf[u->offset] << 24) |
                   ((uint32_t)u->buf[u->offset + 1] << 16) |
                   ((uint32_t)u->buf[u->offset + 2] << 8) |
                   u->buf[u->offset + 3];
    u->offset += 4;
    return val;
}

static void unmarshal_bytes(bio_tpm_unmarshal_t *u,
                            uint8_t *out, size_t len)
{
    if (u->error || u->offset + len > u->size)
    {
        u->error = true;
        return;
    }
    memcpy(out, u->buf + u->offset, len);
    u->offset += len;
}

/*
 * Unmarshal a TPM2B: read 2-byte size, then that many bytes.
 */
static uint16_t unmarshal_tpm2b(bio_tpm_unmarshal_t *u,
                                uint8_t *out, size_t out_cap)
{
    uint16_t size = unmarshal_u16(u);
    if (u->error)
        return 0;

    if (size > out_cap || u->offset + size > u->size)
    {
        u->error = true;
        return 0;
    }
    if (size > 0 && out)
    {
        memcpy(out, u->buf + u->offset, size);
    }
    u->offset += size;
    return size;
}

/* Skip N bytes */
static void unmarshal_skip(bio_tpm_unmarshal_t *u, size_t n)
{
    if (u->error || u->offset + n > u->size)
    {
        u->error = true;
        return;
    }
    u->offset += n;
}

/* ── Lifecycle ────────────────────────────────────────────────── */

int bio_tpm_init(bio_tpm_ctx_t *ctx, const char *device_path)
{
    if (!ctx)
        return BIO_ERR_INVALID_PARAM;

    memset(ctx, 0, sizeof(*ctx));
    ctx->primary_handle = HIYA_TPM_PRIMARY_HANDLE;

    const char *path = device_path ? device_path : "/dev/tpmrm0";
    size_t plen = strlen(path);
    if (plen >= sizeof(ctx->device_path))
    {
        return BIO_ERR_INVALID_PARAM;
    }
    memcpy(ctx->device_path, path, plen + 1);

    ctx->fd = open(path, O_RDWR | O_CLOEXEC);
    if (ctx->fd < 0)
    {
        BIO_ERROR("Failed to open TPM device '%s': %s", path, strerror(errno));
        return BIO_ERR_TPM_OPEN;
    }

    ctx->is_open = true;
    BIO_INFO("TPM 2.0 device opened: %s (fd=%d)", path, ctx->fd);
    return BIO_OK;
}

int bio_tpm_set_primary_handle(bio_tpm_ctx_t *ctx, uint32_t handle)
{
    if (!ctx)
        return BIO_ERR_INVALID_PARAM;
    if (handle < TPM2_PERSISTENT_FIRST || handle > TPM2_PERSISTENT_LAST)
        return BIO_ERR_INVALID_PARAM;

    ctx->primary_handle = handle;
    return BIO_OK;
}

void bio_tpm_cleanup(bio_tpm_ctx_t *ctx)
{
    if (!ctx)
        return;
    if (ctx->is_open && ctx->fd >= 0)
    {
        close(ctx->fd);
        ctx->fd = -1;
    }
    bio_secure_wipe(ctx->cmd_buf, sizeof(ctx->cmd_buf));
    bio_secure_wipe(ctx->rsp_buf, sizeof(ctx->rsp_buf));
    ctx->is_open = false;
}

/* ── Command execution ───────────────────────────────────────── */

int bio_tpm_execute(bio_tpm_ctx_t *ctx, uint32_t *rc_out)
{
    if (!ctx || !ctx->is_open || !rc_out)
        return BIO_ERR_INVALID_PARAM;

    /* Write the command (retry on EINTR, handle partial writes) */
    size_t total_written = 0;
    while (total_written < ctx->cmd_len)
    {
        ssize_t written = write(ctx->fd,
                                ctx->cmd_buf + total_written,
                                ctx->cmd_len - total_written);
        if (written < 0)
        {
            if (errno == EINTR)
                continue;
            BIO_ERROR("TPM write failed: %s (wrote %zu of %zu)",
                      strerror(errno), total_written, ctx->cmd_len);
            return BIO_ERR_TPM_COMMAND;
        }
        /* Partial writes are valid for character devices: advance and retry
         * until the full command frame is transferred. */
        total_written += (size_t)written;
    }

    /* Read the response (retry on EINTR) */
    ssize_t rlen;
    do
    {
        rlen = read(ctx->fd, ctx->rsp_buf, sizeof(ctx->rsp_buf));
    } while (rlen < 0 && errno == EINTR);
    if (rlen < 10)
    {
        BIO_ERROR("TPM read failed: %s (got %zd bytes, need ≥10)",
                  rlen < 0 ? strerror(errno) : "short read", rlen);
        return BIO_ERR_TPM_RESPONSE;
    }
    ctx->rsp_len = (size_t)rlen;

    /* Parse response header */
    bio_tpm_unmarshal_t u;
    unmarshal_init(&u, ctx->rsp_buf, ctx->rsp_len);

    uint16_t rsp_tag = unmarshal_u16(&u);
    uint32_t rsp_size = unmarshal_u32(&u);
    uint32_t rsp_rc = unmarshal_u32(&u);
    (void)rsp_tag;

    if (u.error)
        return BIO_ERR_TPM_RESPONSE;

    if (rsp_size != ctx->rsp_len)
    {
        BIO_WARN("TPM response size mismatch: header says %u, got %zu",
                 rsp_size, ctx->rsp_len);
    }

    *rc_out = rsp_rc;

    if (rsp_rc != TPM2_RC_SUCCESS)
    {
        BIO_DEBUG("TPM command returned RC=0x%08X", rsp_rc);
    }

    return BIO_OK;
}

/* ── TPM2_GetRandom ──────────────────────────────────────────── */

int bio_tpm_get_random(bio_tpm_ctx_t *ctx, uint8_t *buf, uint16_t count)
{
    if (!ctx || !buf || count == 0)
        return BIO_ERR_INVALID_PARAM;

    size_t total = 0;

    /* TPM may return fewer bytes than requested; loop until satisfied */
    while (total < count)
    {
        uint16_t request = count - (uint16_t)total;
        /* TPM typically limits to ~32–48 bytes per call */
        if (request > 48)
            request = 48;

        bio_tpm_marshal_t m;
        marshal_init(&m, ctx->cmd_buf, sizeof(ctx->cmd_buf));
        marshal_command_header(&m, TPM2_ST_NO_SESSIONS, TPM2_CC_GET_RANDOM);
        marshal_u16(&m, request); /* bytesRequested */
        marshal_command_finalize(&m);

        if (m.error)
            return BIO_ERR_TPM_COMMAND;
        ctx->cmd_len = m.offset;

        uint32_t rc;
        int ret = bio_tpm_execute(ctx, &rc);
        if (ret != BIO_OK)
            return ret;
        if (rc != TPM2_RC_SUCCESS)
            return BIO_ERR_TPM_COMMAND;

        /* Parse response: TPM2B_DIGEST */
        bio_tpm_unmarshal_t u;
        unmarshal_init(&u, ctx->rsp_buf + 10, ctx->rsp_len - 10);

        uint16_t got_size = unmarshal_u16(&u);
        if (u.error || got_size == 0 || got_size > request)
            return BIO_ERR_TPM_RESPONSE;

        unmarshal_bytes(&u, buf + total, got_size);
        if (u.error)
            return BIO_ERR_TPM_RESPONSE;

        total += got_size;
    }

    BIO_TRACE("TPM2_GetRandom: got %zu bytes", total);
    return BIO_OK;
}

/* ── TPM2_PCR_Read ───────────────────────────────────────────── */

int bio_tpm_pcr_read(bio_tpm_ctx_t *ctx, uint32_t pcr_index,
                     uint8_t digest[TPM2_SHA256_DIGEST_SIZE])
{
    if (!ctx || !digest)
        return BIO_ERR_INVALID_PARAM;
    if (pcr_index > 23)
        return BIO_ERR_INVALID_PARAM;

    bio_tpm_marshal_t m;
    marshal_init(&m, ctx->cmd_buf, sizeof(ctx->cmd_buf));
    marshal_command_header(&m, TPM2_ST_NO_SESSIONS, TPM2_CC_PCR_READ);

    /*
     * TPML_PCR_SELECTION: count=1, then TPMS_PCR_SELECTION:
     *   hash=SHA-256, sizeOfSelect=3, pcrSelect[3]
     */
    marshal_u32(&m, 1);               /* count = 1 selection */
    marshal_u16(&m, TPM2_ALG_SHA256); /* hash algorithm */
    marshal_u8(&m, 3);                /* sizeOfSelect = 3 bytes */

    /* Set the bit for the requested PCR index */
    uint8_t pcr_select[3] = {0, 0, 0};
    pcr_select[pcr_index / 8] = (uint8_t)(1 << (pcr_index % 8));
    marshal_bytes(&m, pcr_select, 3);

    marshal_command_finalize(&m);
    if (m.error)
        return BIO_ERR_TPM_COMMAND;
    ctx->cmd_len = m.offset;

    uint32_t rc;
    int ret = bio_tpm_execute(ctx, &rc);
    if (ret != BIO_OK)
        return ret;
    if (rc != TPM2_RC_SUCCESS)
        return BIO_ERR_TPM_PCR;

    /* Parse response:
     * [4B pcrUpdateCounter]
     * [TPML_PCR_SELECTION pcrSelectionOut]
     * [4B count of TPML_DIGEST]
     * [TPML_DIGEST: TPM2B_DIGEST entries]
     */
    bio_tpm_unmarshal_t u;
    unmarshal_init(&u, ctx->rsp_buf + 10, ctx->rsp_len - 10);

    uint32_t update_counter = unmarshal_u32(&u);
    (void)update_counter;

    /* Skip pcrSelectionOut (count + one TPMS_PCR_SELECTION) */
    uint32_t sel_count = unmarshal_u32(&u);
    for (uint32_t i = 0; i < sel_count; i++)
    {
        unmarshal_u16(&u); /* hash */
        uint8_t sos = unmarshal_u8(&u);
        unmarshal_skip(&u, sos);
    }

    /* TPML_DIGEST */
    uint32_t digest_count = unmarshal_u32(&u);
    if (digest_count < 1)
        return BIO_ERR_TPM_PCR;

    uint16_t digest_size = unmarshal_u16(&u);
    if (digest_size != TPM2_SHA256_DIGEST_SIZE)
        return BIO_ERR_TPM_PCR;

    unmarshal_bytes(&u, digest, TPM2_SHA256_DIGEST_SIZE);
    if (u.error)
        return BIO_ERR_TPM_RESPONSE;

    BIO_TRACE("TPM2_PCR_Read: PCR[%u] read OK", pcr_index);
    return BIO_OK;
}

/* ── TPM2_CreatePrimary ──────────────────────────────────────── */

int bio_tpm_create_primary(bio_tpm_ctx_t *ctx, uint32_t *handle_out)
{
    if (!ctx || !handle_out)
        return BIO_ERR_INVALID_PARAM;

    bio_tpm_marshal_t m;
    marshal_init(&m, ctx->cmd_buf, sizeof(ctx->cmd_buf));
    marshal_command_header(&m, TPM2_ST_SESSIONS, TPM2_CC_CREATE_PRIMARY);

    /* primaryHandle: owner hierarchy */
    marshal_u32(&m, TPM2_RH_OWNER);

    /* Authorization: empty password for owner hierarchy
     * (requires that owner auth has not been set, or provide it) */
    marshal_password_auth(&m, NULL, 0);

    /* inSensitive: TPM2B_SENSITIVE_CREATE (no auth, no data) */
    /* Size of TPMS_SENSITIVE_CREATE = 2 (userAuth.size=0) + 2 (data.size=0) = 4 */
    marshal_u16(&m, 4); /* overall size */
    marshal_u16(&m, 0); /* userAuth.size = 0 */
    marshal_u16(&m, 0); /* data.size = 0 */

    /*
     * inPublic: TPM2B_PUBLIC — ECC P-256 storage key
     *
     * TPMT_PUBLIC:
     *   type = TPM_ALG_ECC
     *   nameAlg = TPM_ALG_SHA256
     *   objectAttributes:
     *     fixedTPM | fixedParent | sensitiveDataOrigin |
     *     userWithAuth | restricted | decrypt
     *   authPolicy.size = 0
     *   parameters.eccDetail:
     *     symmetric: AES-128-CFB (for child encryption)
     *     scheme: NULL
     *     curveID: P-256
     *     kdfScheme: NULL
     *   unique.ecc: empty point (Qx.size = 0, Qy.size = 0)
     */
    /* Calculate inPublic size */
    /* type(2) + nameAlg(2) + attrs(4) + authPolicy(2+0) +
     * symmetric(alg(2)+keyBits(2)+mode(2)) + scheme(2) +
     * curveID(2) + kdfScheme(2) + unique(2+0 + 2+0) */
    uint16_t pub_size = 2 + 2 + 4 + 2 + (2 + 2 + 2) + 2 + 2 + 2 + (2 + 2);
    marshal_u16(&m, pub_size);

    marshal_u16(&m, TPM2_ALG_ECC);    /* type */
    marshal_u16(&m, TPM2_ALG_SHA256); /* nameAlg */

    /* Object attributes:
     * Bit 1  (0x02)   fixedTPM
     * Bit 2  (0x04)   stClear (0)
     * Bit 4  (0x10)   fixedParent
     * Bit 5  (0x20)   sensitiveDataOrigin
     * Bit 6  (0x40)   userWithAuth
     * Bit 8  (0x100)  noDA (0 for now)
     * Bit 16 (0x10000) restricted
     * Bit 17 (0x20000) decrypt
     */
    uint32_t attrs = 0x00030072;
    /* fixedTPM(0x02) | fixedParent(0x10) | sensitiveDataOrigin(0x20) |
     * userWithAuth(0x40) | restricted(0x10000) | decrypt(0x20000) */
    marshal_u32(&m, attrs);

    marshal_u16(&m, 0); /* authPolicy.size = 0 */

    /* Symmetric: AES-128-CFB (for encrypting children) */
    marshal_u16(&m, TPM2_ALG_AES);
    marshal_u16(&m, 128);
    marshal_u16(&m, TPM2_ALG_CFB);

    marshal_u16(&m, TPM2_ALG_NULL);      /* scheme = NULL */
    marshal_u16(&m, TPM2_ECC_NIST_P256); /* curveID */
    marshal_u16(&m, TPM2_ALG_NULL);      /* kdfScheme = NULL */

    /* unique.ecc: empty points */
    marshal_u16(&m, 0); /* Qx.size = 0 */
    marshal_u16(&m, 0); /* Qy.size = 0 */

    /* outsideInfo = empty */
    marshal_u16(&m, 0);

    /* creationPCR = empty TPML_PCR_SELECTION */
    marshal_u32(&m, 0);

    marshal_command_finalize(&m);
    if (m.error)
        return BIO_ERR_TPM_COMMAND;
    ctx->cmd_len = m.offset;

    uint32_t rc;
    int ret = bio_tpm_execute(ctx, &rc);
    if (ret != BIO_OK)
        return ret;
    if (rc != TPM2_RC_SUCCESS)
    {
        BIO_ERROR("TPM2_CreatePrimary failed: RC=0x%08X", rc);
        return BIO_ERR_TPM_HIERARCHY;
    }

    /* Parse response: handle is first 4 bytes after header+parameterSize */
    bio_tpm_unmarshal_t u;
    unmarshal_init(&u, ctx->rsp_buf + 10, ctx->rsp_len - 10);

    *handle_out = unmarshal_u32(&u);
    if (u.error)
        return BIO_ERR_TPM_RESPONSE;

    BIO_INFO("TPM2_CreatePrimary: handle=0x%08X", *handle_out);
    return BIO_OK;
}

/* ── TPM2_Create (seal data) ─────────────────────────────────── */

int bio_tpm_create_sealed(bio_tpm_ctx_t *ctx,
                          uint32_t parent_handle,
                          const uint8_t *seal_data, size_t seal_len,
                          const uint8_t *auth, size_t auth_len,
                          uint8_t *out_private, size_t *priv_len,
                          uint8_t *out_public, size_t *pub_len)
{
    if (!ctx || !seal_data || !out_private || !priv_len || !out_public || !pub_len)
        return BIO_ERR_INVALID_PARAM;
    if (seal_len > TPM2_MAX_SEALED_DATA)
        return BIO_ERR_INVALID_PARAM;

    bio_tpm_marshal_t m;
    marshal_init(&m, ctx->cmd_buf, sizeof(ctx->cmd_buf));
    marshal_command_header(&m, TPM2_ST_SESSIONS, TPM2_CC_CREATE);

    /* parentHandle */
    marshal_u32(&m, parent_handle);

    /* Authorization for parent (empty password) */
    marshal_password_auth(&m, NULL, 0);

    /* inSensitive: TPM2B_SENSITIVE_CREATE
     * Contains the auth value for unsealing and the data to seal */
    if (auth_len > UINT16_MAX || seal_len > TPM2_MAX_SEALED_DATA)
        return BIO_ERR_INVALID_PARAM;
    uint16_t auth16 = (uint16_t)auth_len;
    uint16_t seal16 = (uint16_t)seal_len;
    uint32_t sensitive_size32 = 2u + (uint32_t)auth16 + 2u + (uint32_t)seal16;
    if (sensitive_size32 > UINT16_MAX)
        return BIO_ERR_INVALID_PARAM;
    uint16_t sensitive_size = (uint16_t)sensitive_size32;
    marshal_u16(&m, sensitive_size);
    marshal_tpm2b(&m, auth, auth16);      /* userAuth */
    marshal_tpm2b(&m, seal_data, seal16); /* data to seal */

    /* inPublic: TPM2B_PUBLIC — keyedHash object for sealing
     *
     * TPMT_PUBLIC:
     *   type = TPM_ALG_KEYEDHASH
     *   nameAlg = SHA-256
     *   attributes: fixedTPM | fixedParent | userWithAuth
     *   authPolicy = empty
     *   parameters.keyedHashDetail.scheme = NULL
     *   unique.keyedHash.size = 0
     */
    uint16_t pub_size2 = 2 + 2 + 4 + 2 + 2 + 2; /* type+nameAlg+attrs+authPol+scheme+unique */
    marshal_u16(&m, pub_size2);

    marshal_u16(&m, TPM2_ALG_KEYEDHASH); /* type */
    marshal_u16(&m, TPM2_ALG_SHA256);    /* nameAlg */

    /* Attributes: fixedTPM(0x02) | fixedParent(0x10) | userWithAuth(0x40) */
    marshal_u32(&m, 0x00000052);

    marshal_u16(&m, 0);             /* authPolicy.size = 0 */
    marshal_u16(&m, TPM2_ALG_NULL); /* scheme = NULL */
    marshal_u16(&m, 0);             /* unique.size = 0 */

    /* outsideInfo */
    marshal_u16(&m, 0);

    /* creationPCR = empty */
    marshal_u32(&m, 0);

    marshal_command_finalize(&m);
    if (m.error)
        return BIO_ERR_TPM_COMMAND;
    ctx->cmd_len = m.offset;

    uint32_t rc;
    int ret = bio_tpm_execute(ctx, &rc);
    if (ret != BIO_OK)
        return ret;
    if (rc != TPM2_RC_SUCCESS)
    {
        BIO_ERROR("TPM2_Create (seal) failed: RC=0x%08X", rc);
        return BIO_ERR_TPM_SEALED;
    }

    /* Parse response:
     * [4B parameterSize]  (only if ST_SESSIONS)
     * [TPM2B_PRIVATE outPrivate]
     * [TPM2B_PUBLIC  outPublic]
     * [TPM2B_CREATION_DATA creationData]
     * [TPM2B_DIGEST creationHash]
     * [TPMT_TK_CREATION creationTicket]
     */
    bio_tpm_unmarshal_t u;
    unmarshal_init(&u, ctx->rsp_buf + 10, ctx->rsp_len - 10);

    uint32_t param_size = unmarshal_u32(&u);
    (void)param_size;

    /* Read outPrivate */
    uint16_t priv_sz = unmarshal_tpm2b(&u, out_private, *priv_len);
    if (u.error || priv_sz == 0)
        return BIO_ERR_TPM_RESPONSE;
    *priv_len = priv_sz;

    /* Read outPublic */
    uint16_t pub_sz = unmarshal_tpm2b(&u, out_public, *pub_len);
    if (u.error || pub_sz == 0)
        return BIO_ERR_TPM_RESPONSE;
    *pub_len = pub_sz;

    BIO_DEBUG("TPM2_Create: sealed %zu bytes (priv=%u, pub=%u)",
              seal_len, priv_sz, pub_sz);
    return BIO_OK;
}

/* ── TPM2_Load ───────────────────────────────────────────────── */

int bio_tpm_load(bio_tpm_ctx_t *ctx,
                 uint32_t parent_handle,
                 const uint8_t *private_data, size_t priv_len,
                 const uint8_t *public_data, size_t pub_len,
                 uint32_t *handle_out)
{
    if (!ctx || !private_data || !public_data || !handle_out)
        return BIO_ERR_INVALID_PARAM;
    if (priv_len > UINT16_MAX || pub_len > UINT16_MAX)
        return BIO_ERR_INVALID_PARAM;

    bio_tpm_marshal_t m;
    marshal_init(&m, ctx->cmd_buf, sizeof(ctx->cmd_buf));
    marshal_command_header(&m, TPM2_ST_SESSIONS, TPM2_CC_LOAD);

    marshal_u32(&m, parent_handle);
    marshal_password_auth(&m, NULL, 0);

    marshal_tpm2b(&m, private_data, (uint16_t)priv_len);
    marshal_tpm2b(&m, public_data, (uint16_t)pub_len);

    marshal_command_finalize(&m);
    if (m.error)
        return BIO_ERR_TPM_COMMAND;
    ctx->cmd_len = m.offset;

    uint32_t rc;
    int ret = bio_tpm_execute(ctx, &rc);
    if (ret != BIO_OK)
        return ret;
    if (rc != TPM2_RC_SUCCESS)
    {
        BIO_ERROR("TPM2_Load failed: RC=0x%08X", rc);
        return BIO_ERR_TPM_HANDLE;
    }

    bio_tpm_unmarshal_t u;
    unmarshal_init(&u, ctx->rsp_buf + 10, ctx->rsp_len - 10);

    *handle_out = unmarshal_u32(&u);
    if (u.error)
        return BIO_ERR_TPM_RESPONSE;

    BIO_DEBUG("TPM2_Load: handle=0x%08X", *handle_out);
    return BIO_OK;
}

/* ── TPM2_Unseal ─────────────────────────────────────────────── */

int bio_tpm_unseal(bio_tpm_ctx_t *ctx,
                   uint32_t item_handle,
                   const uint8_t *auth, size_t auth_len,
                   uint8_t *out_data, size_t *out_len)
{
    if (!ctx || !out_data || !out_len)
        return BIO_ERR_INVALID_PARAM;

    bio_tpm_marshal_t m;
    marshal_init(&m, ctx->cmd_buf, sizeof(ctx->cmd_buf));
    marshal_command_header(&m, TPM2_ST_SESSIONS, TPM2_CC_UNSEAL);

    marshal_u32(&m, item_handle);
    marshal_password_auth(&m, auth, auth_len);

    marshal_command_finalize(&m);
    if (m.error)
        return BIO_ERR_TPM_COMMAND;
    ctx->cmd_len = m.offset;

    uint32_t rc;
    int ret = bio_tpm_execute(ctx, &rc);
    if (ret != BIO_OK)
        return ret;
    if (rc != TPM2_RC_SUCCESS)
    {
        if (rc == TPM2_RC_AUTH_FAIL || rc == TPM2_RC_BAD_AUTH)
        {
            BIO_WARN("TPM2_Unseal: authorization failed");
            return BIO_ERR_TPM_AUTH;
        }
        BIO_ERROR("TPM2_Unseal failed: RC=0x%08X", rc);
        return BIO_ERR_TPM_SEALED;
    }

    /* Parse response: [4B paramSize] [TPM2B_SENSITIVE_DATA] */
    bio_tpm_unmarshal_t u;
    unmarshal_init(&u, ctx->rsp_buf + 10, ctx->rsp_len - 10);

    uint32_t param_size = unmarshal_u32(&u);
    (void)param_size;

    uint16_t data_sz = unmarshal_tpm2b(&u, out_data, *out_len);
    if (u.error)
        return BIO_ERR_TPM_RESPONSE;
    *out_len = data_sz;

    BIO_DEBUG("TPM2_Unseal: got %u bytes", data_sz);
    return BIO_OK;
}

/* ── TPM2_FlushContext ───────────────────────────────────────── */

int bio_tpm_flush_context(bio_tpm_ctx_t *ctx, uint32_t handle)
{
    if (!ctx)
        return BIO_ERR_INVALID_PARAM;

    bio_tpm_marshal_t m;
    marshal_init(&m, ctx->cmd_buf, sizeof(ctx->cmd_buf));
    marshal_command_header(&m, TPM2_ST_NO_SESSIONS, TPM2_CC_FLUSH_CONTEXT);
    marshal_u32(&m, handle);
    marshal_command_finalize(&m);

    if (m.error)
        return BIO_ERR_TPM_COMMAND;
    ctx->cmd_len = m.offset;

    uint32_t rc;
    int ret = bio_tpm_execute(ctx, &rc);
    if (ret != BIO_OK)
        return ret;
    if (rc != TPM2_RC_SUCCESS)
    {
        BIO_ERROR("TPM2_FlushContext(0x%08X) failed: RC=0x%08X", handle, rc);
        return BIO_ERR_TPM_HANDLE;
    }

    BIO_TRACE("TPM2_FlushContext: 0x%08X flushed", handle);
    return BIO_OK;
}

/* ── TPM2_EvictControl ───────────────────────────────────────── */

int bio_tpm_evict_control(bio_tpm_ctx_t *ctx,
                          uint32_t object_handle,
                          uint32_t persistent_handle)
{
    if (!ctx)
        return BIO_ERR_INVALID_PARAM;

    bio_tpm_marshal_t m;
    marshal_init(&m, ctx->cmd_buf, sizeof(ctx->cmd_buf));
    marshal_command_header(&m, TPM2_ST_SESSIONS, TPM2_CC_EVICT_CONTROL);

    /* auth = owner hierarchy */
    marshal_u32(&m, TPM2_RH_OWNER);
    marshal_u32(&m, object_handle);

    /* Authorization for owner */
    marshal_password_auth(&m, NULL, 0);

    /* persistentHandle */
    marshal_u32(&m, persistent_handle);

    marshal_command_finalize(&m);
    if (m.error)
        return BIO_ERR_TPM_COMMAND;
    ctx->cmd_len = m.offset;

    uint32_t rc;
    int ret = bio_tpm_execute(ctx, &rc);
    if (ret != BIO_OK)
        return ret;
    if (rc != TPM2_RC_SUCCESS)
    {
        BIO_ERROR("TPM2_EvictControl(0x%08X → 0x%08X) failed: RC=0x%08X",
                  object_handle, persistent_handle, rc);
        return BIO_ERR_TPM_HIERARCHY;
    }

    BIO_INFO("TPM2_EvictControl: 0x%08X persisted as 0x%08X",
             object_handle, persistent_handle);
    return BIO_OK;
}

/* ── TPM2_ReadPublic ─────────────────────────────────────────── */

int bio_tpm_read_public(bio_tpm_ctx_t *ctx,
                        uint32_t handle,
                        uint8_t *out_public, size_t *pub_len)
{
    if (!ctx || !out_public || !pub_len)
        return BIO_ERR_INVALID_PARAM;

    bio_tpm_marshal_t m;
    marshal_init(&m, ctx->cmd_buf, sizeof(ctx->cmd_buf));
    marshal_command_header(&m, TPM2_ST_NO_SESSIONS, TPM2_CC_READ_PUBLIC);
    marshal_u32(&m, handle);
    marshal_command_finalize(&m);

    if (m.error)
        return BIO_ERR_TPM_COMMAND;
    ctx->cmd_len = m.offset;

    uint32_t rc;
    int ret = bio_tpm_execute(ctx, &rc);
    if (ret != BIO_OK)
        return ret;
    if (rc != TPM2_RC_SUCCESS)
    {
        BIO_ERROR("TPM2_ReadPublic(0x%08X) failed: RC=0x%08X", handle, rc);
        return BIO_ERR_TPM_HANDLE;
    }

    bio_tpm_unmarshal_t u;
    unmarshal_init(&u, ctx->rsp_buf + 10, ctx->rsp_len - 10);

    uint16_t sz = unmarshal_tpm2b(&u, out_public, *pub_len);
    if (u.error)
        return BIO_ERR_TPM_RESPONSE;
    *pub_len = sz;

    return BIO_OK;
}

/* ── TPM2_StartAuthSession ───────────────────────────────────── */

static int tpm_start_auth_session_typed(bio_tpm_ctx_t *ctx,
                                        uint32_t *session_handle,
                                        uint8_t session_type)
{
    if (!ctx || !session_handle)
        return BIO_ERR_INVALID_PARAM;

    bio_tpm_marshal_t m;
    marshal_init(&m, ctx->cmd_buf, sizeof(ctx->cmd_buf));
    marshal_command_header(&m, TPM2_ST_NO_SESSIONS, TPM2_CC_START_AUTH_SESSION);

    /* tpmKey = TPM_RH_NULL (no salt) */
    marshal_u32(&m, TPM2_RH_NULL);

    /* bind = TPM_RH_NULL (unbound) */
    marshal_u32(&m, TPM2_RH_NULL);

    /* nonceCaller: 32 random bytes */
    uint8_t nonce[32];
    int rng_ret = bio_random_bytes(nonce, sizeof(nonce));
    if (rng_ret != BIO_OK)
        return rng_ret;
    marshal_tpm2b(&m, nonce, 32);

    /* encryptedSalt: empty (no salt since tpmKey = NULL) */
    marshal_u16(&m, 0);

    /* sessionType */
    marshal_u8(&m, session_type);

    /* symmetric: TPM_ALG_NULL (no parameter encryption) */
    marshal_u16(&m, TPM2_ALG_NULL);

    /* authHash: SHA-256 */
    marshal_u16(&m, TPM2_ALG_SHA256);

    marshal_command_finalize(&m);
    if (m.error)
        return BIO_ERR_TPM_COMMAND;
    ctx->cmd_len = m.offset;

    uint32_t rc;
    int ret = bio_tpm_execute(ctx, &rc);
    if (ret != BIO_OK)
        return ret;
    if (rc != TPM2_RC_SUCCESS)
    {
        BIO_ERROR("TPM2_StartAuthSession failed: RC=0x%08X", rc);
        return BIO_ERR_TPM_COMMAND;
    }

    /* Response: [4B sessionHandle][TPM2B_NONCE nonceTPM] */
    bio_tpm_unmarshal_t u;
    unmarshal_init(&u, ctx->rsp_buf + 10, ctx->rsp_len - 10);

    *session_handle = unmarshal_u32(&u);
    if (u.error)
        return BIO_ERR_TPM_RESPONSE;

    /* Skip nonceTPM */
    uint8_t nonce_tpm[64];
    unmarshal_tpm2b(&u, nonce_tpm, sizeof(nonce_tpm));

    BIO_DEBUG("TPM2_StartAuthSession: handle=0x%08X", *session_handle);
    return BIO_OK;
}

int bio_tpm_start_auth_session(bio_tpm_ctx_t *ctx, uint32_t *session_handle)
{
    return tpm_start_auth_session_typed(ctx, session_handle, TPM2_SE_POLICY);
}

static int bio_tpm_start_trial_session(bio_tpm_ctx_t *ctx, uint32_t *session_handle)
{
    return tpm_start_auth_session_typed(ctx, session_handle, TPM2_SE_TRIAL);
}

/* ── TPM2_PolicyPCR ──────────────────────────────────────────── */

int bio_tpm_policy_pcr(bio_tpm_ctx_t *ctx, uint32_t session_handle,
                       uint32_t pcr_index)
{
    if (!ctx)
        return BIO_ERR_INVALID_PARAM;
    if (pcr_index > 23)
        return BIO_ERR_INVALID_PARAM;

    bio_tpm_marshal_t m;
    marshal_init(&m, ctx->cmd_buf, sizeof(ctx->cmd_buf));
    marshal_command_header(&m, TPM2_ST_NO_SESSIONS, TPM2_CC_POLICY_PCR);

    /* policySession */
    marshal_u32(&m, session_handle);

    /* pcrDigest: empty (use current PCR values) */
    marshal_u16(&m, 0);

    /* pcrs: TPML_PCR_SELECTION, count=1 */
    marshal_u32(&m, 1);
    marshal_u16(&m, TPM2_ALG_SHA256);
    marshal_u8(&m, 3); /* sizeOfSelect = 3 */

    uint8_t pcr_select[3] = {0, 0, 0};
    pcr_select[pcr_index / 8] = (uint8_t)(1 << (pcr_index % 8));
    marshal_bytes(&m, pcr_select, 3);

    marshal_command_finalize(&m);
    if (m.error)
        return BIO_ERR_TPM_COMMAND;
    ctx->cmd_len = m.offset;

    uint32_t rc;
    int ret = bio_tpm_execute(ctx, &rc);
    if (ret != BIO_OK)
        return ret;
    if (rc != TPM2_RC_SUCCESS)
    {
        BIO_ERROR("TPM2_PolicyPCR failed: RC=0x%08X", rc);
        return BIO_ERR_TPM_PCR;
    }

    BIO_DEBUG("TPM2_PolicyPCR: session=0x%08X, PCR[%u] bound", session_handle, pcr_index);
    return BIO_OK;
}

/* ── TPM2_PolicyGetDigest ────────────────────────────────────── */

int bio_tpm_policy_get_digest(bio_tpm_ctx_t *ctx, uint32_t session_handle,
                              uint8_t digest[TPM2_SHA256_DIGEST_SIZE])
{
    if (!ctx || !digest)
        return BIO_ERR_INVALID_PARAM;

    bio_tpm_marshal_t m;
    marshal_init(&m, ctx->cmd_buf, sizeof(ctx->cmd_buf));
    marshal_command_header(&m, TPM2_ST_NO_SESSIONS, TPM2_CC_POLICY_GET_DIGEST);
    marshal_u32(&m, session_handle);
    marshal_command_finalize(&m);

    if (m.error)
        return BIO_ERR_TPM_COMMAND;
    ctx->cmd_len = m.offset;

    uint32_t rc;
    int ret = bio_tpm_execute(ctx, &rc);
    if (ret != BIO_OK)
        return ret;
    if (rc != TPM2_RC_SUCCESS)
    {
        BIO_ERROR("TPM2_PolicyGetDigest failed: RC=0x%08X", rc);
        return BIO_ERR_TPM_COMMAND;
    }

    /* Response: [TPM2B_DIGEST policyDigest] */
    bio_tpm_unmarshal_t u;
    unmarshal_init(&u, ctx->rsp_buf + 10, ctx->rsp_len - 10);

    uint16_t digest_sz = unmarshal_tpm2b(&u, digest, TPM2_SHA256_DIGEST_SIZE);
    if (u.error || digest_sz != TPM2_SHA256_DIGEST_SIZE)
        return BIO_ERR_TPM_RESPONSE;

    BIO_DEBUG("TPM2_PolicyGetDigest: session=0x%08X OK", session_handle);
    return BIO_OK;
}

/* ── TPM2_Create with PCR policy ─────────────────────────────── */

int bio_tpm_create_sealed_pcr(bio_tpm_ctx_t *ctx,
                              uint32_t parent_handle,
                              const uint8_t *seal_data, size_t seal_len,
                              const uint8_t *auth, size_t auth_len,
                              uint32_t pcr_index,
                              uint8_t *out_private, size_t *priv_len,
                              uint8_t *out_public, size_t *pub_len)
{
    if (!ctx || !seal_data || !out_private || !priv_len || !out_public || !pub_len)
        return BIO_ERR_INVALID_PARAM;
    if (seal_len > TPM2_MAX_SEALED_DATA)
        return BIO_ERR_INVALID_PARAM;

    /*
     * First, compute the policy digest by running a trial policy session:
     *   1. StartAuthSession(trial)
     *   2. PolicyPCR(session, pcr_index)
     *   3. PolicyGetDigest(session) → policy_digest
     *   4. FlushContext(session)
     */
    uint32_t trial_session;
    int ret = bio_tpm_start_trial_session(ctx, &trial_session);
    if (ret != BIO_OK)
        return ret;

    ret = bio_tpm_policy_pcr(ctx, trial_session, pcr_index);
    if (ret != BIO_OK)
    {
        bio_tpm_flush_context(ctx, trial_session);
        return ret;
    }

    uint8_t policy_digest[32];
    ret = bio_tpm_policy_get_digest(ctx, trial_session, policy_digest);
    bio_tpm_flush_context(ctx, trial_session);
    if (ret != BIO_OK)
        return ret;

    /*
     * Now create the sealed object with the policy digest.
     */
    bio_tpm_marshal_t m;
    marshal_init(&m, ctx->cmd_buf, sizeof(ctx->cmd_buf));
    marshal_command_header(&m, TPM2_ST_SESSIONS, TPM2_CC_CREATE);

    marshal_u32(&m, parent_handle);
    marshal_password_auth(&m, NULL, 0);

    /* inSensitive */
    if (auth_len > UINT16_MAX || seal_len > TPM2_MAX_SEALED_DATA)
        return BIO_ERR_INVALID_PARAM;
    uint16_t auth16 = (uint16_t)auth_len;
    uint16_t seal16 = (uint16_t)seal_len;
    uint32_t sensitive_size32 = 2u + (uint32_t)auth16 + 2u + (uint32_t)seal16;
    if (sensitive_size32 > UINT16_MAX)
        return BIO_ERR_INVALID_PARAM;
    uint16_t sensitive_size = (uint16_t)sensitive_size32;
    marshal_u16(&m, sensitive_size);
    marshal_tpm2b(&m, auth, auth16);
    marshal_tpm2b(&m, seal_data, seal16);

    /* inPublic: KEYEDHASH with authPolicy = policy_digest */
    /* type(2) + nameAlg(2) + attrs(4) + authPolicy(2+32) + scheme(2) + unique(2) */
    uint16_t pub_size2 = 2 + 2 + 4 + 2 + 32 + 2 + 2;
    marshal_u16(&m, pub_size2);

    marshal_u16(&m, TPM2_ALG_KEYEDHASH);
    marshal_u16(&m, TPM2_ALG_SHA256);

    /* Attributes: fixedTPM | fixedParent
     * Note: NO userWithAuth — authorization is via policy only */
    marshal_u32(&m, 0x00000012); /* fixedTPM(0x02) | fixedParent(0x10) */

    /* authPolicy = the PCR policy digest */
    marshal_tpm2b(&m, policy_digest, 32);

    marshal_u16(&m, TPM2_ALG_NULL); /* scheme */
    marshal_u16(&m, 0);             /* unique.size = 0 */

    /* outsideInfo = empty */
    marshal_u16(&m, 0);

    /* creationPCR = empty */
    marshal_u32(&m, 0);

    marshal_command_finalize(&m);
    if (m.error)
        return BIO_ERR_TPM_COMMAND;
    ctx->cmd_len = m.offset;

    uint32_t rc;
    ret = bio_tpm_execute(ctx, &rc);
    if (ret != BIO_OK)
        return ret;
    if (rc != TPM2_RC_SUCCESS)
    {
        BIO_ERROR("TPM2_Create (PCR-sealed) failed: RC=0x%08X", rc);
        return BIO_ERR_TPM_SEALED;
    }

    /* Parse: [4B paramSize][TPM2B_PRIVATE][TPM2B_PUBLIC]... */
    bio_tpm_unmarshal_t u;
    unmarshal_init(&u, ctx->rsp_buf + 10, ctx->rsp_len - 10);

    uint32_t param_size = unmarshal_u32(&u);
    (void)param_size;

    uint16_t priv_sz = unmarshal_tpm2b(&u, out_private, *priv_len);
    if (u.error || priv_sz == 0)
        return BIO_ERR_TPM_RESPONSE;
    *priv_len = priv_sz;

    uint16_t pub_sz = unmarshal_tpm2b(&u, out_public, *pub_len);
    if (u.error || pub_sz == 0)
        return BIO_ERR_TPM_RESPONSE;
    *pub_len = pub_sz;

    BIO_DEBUG("TPM2_Create (PCR): sealed %zu bytes (priv=%u, pub=%u)",
              seal_len, priv_sz, pub_sz);
    return BIO_OK;
}

/* ── TPM2_Create ECC signing key ─────────────────────────────── */

int bio_tpm_create_ecc_key(bio_tpm_ctx_t *ctx,
                           uint32_t parent_handle,
                           uint8_t *key_private, size_t *priv_len,
                           uint8_t *key_public, size_t *pub_len,
                           uint8_t public_key_out[65])
{
    if (!ctx || !key_private || !priv_len || !key_public || !pub_len || !public_key_out)
        return BIO_ERR_INVALID_PARAM;

    bio_tpm_marshal_t m;
    marshal_init(&m, ctx->cmd_buf, sizeof(ctx->cmd_buf));
    marshal_command_header(&m, TPM2_ST_SESSIONS, TPM2_CC_CREATE);

    marshal_u32(&m, parent_handle);
    marshal_password_auth(&m, NULL, 0);

    /* inSensitive: empty (TPM generates key) */
    marshal_u16(&m, 4); /* userAuth.size=0 + data.size=0 */
    marshal_u16(&m, 0); /* userAuth */
    marshal_u16(&m, 0); /* data */

    /* inPublic: ECC P-256 signing key
     * type(2) + nameAlg(2) + attrs(4) + authPolicy(2) +
     * scheme(2+2) + curveID(2) + kdfScheme(2) + unique(2+0 + 2+0) */
    uint16_t pub_sz = 2 + 2 + 4 + 2 + (2 + 2) + 2 + 2 + (2 + 2);
    marshal_u16(&m, pub_sz);

    marshal_u16(&m, TPM2_ALG_ECC);
    marshal_u16(&m, TPM2_ALG_SHA256);

    /* Attributes: fixedTPM | fixedParent | sensitiveDataOrigin | userWithAuth | sign */
    /* sign bit = bit 18 = 0x40000 */
    marshal_u32(&m, 0x00040072);
    /* fixedTPM(0x02) | fixedParent(0x10) | sensitiveDataOrigin(0x20) |
     * userWithAuth(0x40) | sign/encrypt(0x40000) */

    marshal_u16(&m, 0); /* authPolicy = empty */

    /* scheme: ECDSA with SHA-256 */
    marshal_u16(&m, TPM2_ALG_ECDSA);
    marshal_u16(&m, TPM2_ALG_SHA256);

    marshal_u16(&m, TPM2_ECC_NIST_P256);
    marshal_u16(&m, TPM2_ALG_NULL); /* kdfScheme */

    /* unique.ecc: empty */
    marshal_u16(&m, 0); /* Qx */
    marshal_u16(&m, 0); /* Qy */

    /* outsideInfo = empty */
    marshal_u16(&m, 0);

    /* creationPCR = empty */
    marshal_u32(&m, 0);

    marshal_command_finalize(&m);
    if (m.error)
        return BIO_ERR_TPM_COMMAND;
    ctx->cmd_len = m.offset;

    uint32_t rc;
    int ret = bio_tpm_execute(ctx, &rc);
    if (ret != BIO_OK)
        return ret;
    if (rc != TPM2_RC_SUCCESS)
    {
        BIO_ERROR("TPM2_Create (ECC) failed: RC=0x%08X", rc);
        return BIO_ERR_TPM_COMMAND;
    }

    /* Parse response */
    bio_tpm_unmarshal_t u;
    unmarshal_init(&u, ctx->rsp_buf + 10, ctx->rsp_len - 10);

    uint32_t param_size = unmarshal_u32(&u);
    (void)param_size;

    uint16_t p_sz = unmarshal_tpm2b(&u, key_private, *priv_len);
    if (u.error || p_sz == 0)
        return BIO_ERR_TPM_RESPONSE;
    *priv_len = p_sz;

    /* Read raw outPublic as bytes, then also parse for the public key */
    uint16_t full_pub_sz = unmarshal_u16(&u);
    if (u.error || full_pub_sz == 0 || u.offset + full_pub_sz > u.size)
        return BIO_ERR_TPM_RESPONSE;

    /* Save raw public blob */
    if (full_pub_sz > *pub_len)
        return BIO_ERR_BUFFER_TOO_SMALL;
    memcpy(key_public, u.buf + u.offset, full_pub_sz);
    *pub_len = full_pub_sz;

    /* Parse the TPMT_PUBLIC to extract x,y coordinates:
     * type(2) + nameAlg(2) + attrs(4) + authPolicy(2+n) +
     * scheme(2+2) + curveID(2) + kdfScheme(2) +
     * unique.ecc: Qx(2+data) + Qy(2+data) */
    bio_tpm_unmarshal_t pu;
    unmarshal_init(&pu, u.buf + u.offset, full_pub_sz);

    unmarshal_u16(&pu); /* type */
    unmarshal_u16(&pu); /* nameAlg */
    unmarshal_u32(&pu); /* attrs */
    uint16_t pol_sz = unmarshal_u16(&pu);
    unmarshal_skip(&pu, pol_sz); /* authPolicy */
    unmarshal_u16(&pu);          /* scheme alg */
    unmarshal_u16(&pu);          /* hash alg */
    unmarshal_u16(&pu);          /* curveID */
    unmarshal_u16(&pu);          /* kdfScheme */

    /* unique.ecc.x */
    uint8_t xbuf[32], ybuf[32];
    uint16_t x_sz = unmarshal_tpm2b(&pu, xbuf, 32);
    uint16_t y_sz = unmarshal_tpm2b(&pu, ybuf, 32);

    if (pu.error || x_sz != 32 || y_sz != 32)
    {
        u.offset += full_pub_sz;
        return BIO_ERR_TPM_RESPONSE;
    }

    /* Build uncompressed public key: 0x04 || x || y */
    public_key_out[0] = 0x04;
    memcpy(public_key_out + 1, xbuf, 32);
    memcpy(public_key_out + 33, ybuf, 32);

    u.offset += full_pub_sz;

    BIO_DEBUG("TPM2_Create (ECC): key created");
    return BIO_OK;
}

/* ── TPM2_Sign (ECDSA) ───────────────────────────────────────── */

int bio_tpm_sign_ecdsa(bio_tpm_ctx_t *ctx,
                       uint32_t key_handle,
                       const uint8_t hash[32],
                       uint8_t sig_r[32], uint8_t sig_s[32])
{
    if (!ctx || !hash || !sig_r || !sig_s)
        return BIO_ERR_INVALID_PARAM;

    bio_tpm_marshal_t m;
    marshal_init(&m, ctx->cmd_buf, sizeof(ctx->cmd_buf));
    marshal_command_header(&m, TPM2_ST_SESSIONS, TPM2_CC_SIGN);

    marshal_u32(&m, key_handle);
    marshal_password_auth(&m, NULL, 0);

    /* digest: TPM2B_DIGEST */
    marshal_tpm2b(&m, hash, 32);

    /* inScheme: ECDSA with SHA-256 */
    marshal_u16(&m, TPM2_ALG_ECDSA);
    marshal_u16(&m, TPM2_ALG_SHA256);

    /* validation: TPMT_TK_HASHCHECK (NULL ticket) */
    marshal_u16(&m, TPM2_ST_HASHCHECK); /* tag: TPM_ST_HASHCHECK */
    marshal_u32(&m, TPM2_RH_NULL);      /* hierarchy: NULL */
    marshal_u16(&m, 0);                 /* digest.size = 0 */

    marshal_command_finalize(&m);
    if (m.error)
        return BIO_ERR_TPM_COMMAND;
    ctx->cmd_len = m.offset;

    uint32_t rc;
    int ret = bio_tpm_execute(ctx, &rc);
    if (ret != BIO_OK)
        return ret;
    if (rc != TPM2_RC_SUCCESS)
    {
        BIO_ERROR("TPM2_Sign failed: RC=0x%08X", rc);
        return BIO_ERR_TPM_COMMAND;
    }

    /* Response: [4B paramSize][TPMT_SIGNATURE]
     * TPMT_SIGNATURE for ECDSA:
     *   sigAlg(2) = ECDSA
     *   hashAlg(2) = SHA256
     *   signatureR: TPM2B(2+32)
     *   signatureS: TPM2B(2+32)
     */
    bio_tpm_unmarshal_t u;
    unmarshal_init(&u, ctx->rsp_buf + 10, ctx->rsp_len - 10);

    uint32_t param_size = unmarshal_u32(&u);
    (void)param_size;

    uint16_t sig_alg = unmarshal_u16(&u);
    uint16_t hash_alg = unmarshal_u16(&u);
    (void)sig_alg;
    (void)hash_alg;

    uint16_t r_sz = unmarshal_tpm2b(&u, sig_r, 32);
    uint16_t s_sz = unmarshal_tpm2b(&u, sig_s, 32);

    if (u.error || r_sz != 32 || s_sz != 32)
    {
        BIO_ERROR("TPM2_Sign: unexpected signature size (r=%u, s=%u)", r_sz, s_sz);
        return BIO_ERR_TPM_RESPONSE;
    }

    BIO_DEBUG("TPM2_Sign: ECDSA signature OK");
    return BIO_OK;
}

/* ── TPM2_NV_DefineSpace ─────────────────────────────────────── */

int bio_tpm_nv_define_space(bio_tpm_ctx_t *ctx,
                            uint32_t nv_index, uint16_t size)
{
    if (!ctx)
        return BIO_ERR_INVALID_PARAM;

    bio_tpm_marshal_t m;
    marshal_init(&m, ctx->cmd_buf, sizeof(ctx->cmd_buf));
    marshal_command_header(&m, TPM2_ST_SESSIONS, TPM2_CC_NV_DEFINE_SPACE);

    /* authHandle = owner */
    marshal_u32(&m, TPM2_RH_OWNER);
    marshal_password_auth(&m, NULL, 0);

    /* auth: empty password for NV area */
    marshal_u16(&m, 0);

    /* publicInfo: TPMS_NV_PUBLIC
     * nvIndex(4) + nameAlg(2) + attributes(4) + authPolicy(2+0) + dataSize(2) */
    uint16_t nv_pub_size = 4 + 2 + 4 + 2 + 2;
    marshal_u16(&m, nv_pub_size);

    marshal_u32(&m, nv_index);
    marshal_u16(&m, TPM2_ALG_SHA256);

    /* TPMA_NV attributes:
     * OWNERWRITE(0x02) | OWNERREAD(0x20000) | WRITTEN(0x20000000 handled by TPM)
     * TPMA_NV_AUTHREAD(bit 18) | TPMA_NV_AUTHWRITE(bit 2) | TPMA_NV_OWNERREAD(bit 17) | TPMA_NV_OWNERWRITE(bit 1)
     * Just use: ownerwrite | ownerread | authwrite | authread
     * = bit 1 | bit 2 | bit 17 | bit 18 = 0x60006 */
    marshal_u32(&m, 0x00060006);

    marshal_u16(&m, 0); /* authPolicy = empty */
    marshal_u16(&m, size);

    marshal_command_finalize(&m);
    if (m.error)
        return BIO_ERR_TPM_COMMAND;
    ctx->cmd_len = m.offset;

    uint32_t rc;
    int ret = bio_tpm_execute(ctx, &rc);
    if (ret != BIO_OK)
        return ret;
    if (rc != TPM2_RC_SUCCESS)
    {
        BIO_ERROR("TPM2_NV_DefineSpace(0x%08X) failed: RC=0x%08X", nv_index, rc);
        return BIO_ERR_TPM_COMMAND;
    }

    BIO_DEBUG("TPM2_NV_DefineSpace: index=0x%08X, size=%u", nv_index, size);
    return BIO_OK;
}

/* ── TPM2_NV_Write ───────────────────────────────────────────── */

int bio_tpm_nv_write(bio_tpm_ctx_t *ctx, uint32_t nv_index,
                     const uint8_t *data, uint16_t len, uint16_t offset)
{
    if (!ctx || !data)
        return BIO_ERR_INVALID_PARAM;

    bio_tpm_marshal_t m;
    marshal_init(&m, ctx->cmd_buf, sizeof(ctx->cmd_buf));
    marshal_command_header(&m, TPM2_ST_SESSIONS, TPM2_CC_NV_WRITE);

    /* authHandle = nv_index (owner auth) */
    marshal_u32(&m, TPM2_RH_OWNER);
    /* nvIndex */
    marshal_u32(&m, nv_index);

    marshal_password_auth(&m, NULL, 0);

    /* data */
    marshal_tpm2b(&m, data, len);

    /* offset */
    marshal_u16(&m, offset);

    marshal_command_finalize(&m);
    if (m.error)
        return BIO_ERR_TPM_COMMAND;
    ctx->cmd_len = m.offset;

    uint32_t rc;
    int ret = bio_tpm_execute(ctx, &rc);
    if (ret != BIO_OK)
        return ret;
    if (rc != TPM2_RC_SUCCESS)
    {
        BIO_ERROR("TPM2_NV_Write(0x%08X) failed: RC=0x%08X", nv_index, rc);
        return BIO_ERR_TPM_COMMAND;
    }

    BIO_DEBUG("TPM2_NV_Write: index=0x%08X, %u bytes at offset %u",
              nv_index, len, offset);
    return BIO_OK;
}

/* ── TPM2_NV_Read ────────────────────────────────────────────── */

int bio_tpm_nv_read(bio_tpm_ctx_t *ctx, uint32_t nv_index,
                    uint8_t *out, uint16_t len, uint16_t offset)
{
    if (!ctx || !out)
        return BIO_ERR_INVALID_PARAM;

    bio_tpm_marshal_t m;
    marshal_init(&m, ctx->cmd_buf, sizeof(ctx->cmd_buf));
    marshal_command_header(&m, TPM2_ST_SESSIONS, TPM2_CC_NV_READ);

    /* authHandle = owner */
    marshal_u32(&m, TPM2_RH_OWNER);
    /* nvIndex */
    marshal_u32(&m, nv_index);

    marshal_password_auth(&m, NULL, 0);

    /* size */
    marshal_u16(&m, len);
    /* offset */
    marshal_u16(&m, offset);

    marshal_command_finalize(&m);
    if (m.error)
        return BIO_ERR_TPM_COMMAND;
    ctx->cmd_len = m.offset;

    uint32_t rc;
    int ret = bio_tpm_execute(ctx, &rc);
    if (ret != BIO_OK)
        return ret;
    if (rc != TPM2_RC_SUCCESS)
    {
        BIO_ERROR("TPM2_NV_Read(0x%08X) failed: RC=0x%08X", nv_index, rc);
        return BIO_ERR_TPM_COMMAND;
    }

    /* Response: [4B paramSize][TPM2B_MAX_NV_BUFFER data] */
    bio_tpm_unmarshal_t u;
    unmarshal_init(&u, ctx->rsp_buf + 10, ctx->rsp_len - 10);

    uint32_t param_size = unmarshal_u32(&u);
    (void)param_size;

    uint16_t data_sz = unmarshal_tpm2b(&u, out, len);
    if (u.error || data_sz != len)
        return BIO_ERR_TPM_RESPONSE;

    BIO_DEBUG("TPM2_NV_Read: index=0x%08X, %u bytes at offset %u",
              nv_index, len, offset);
    return BIO_OK;
}

/* ── Convenience: ensure primary key ─────────────────────────── */

int bio_tpm_ensure_primary_key(bio_tpm_ctx_t *ctx, uint32_t *handle_out)
{
    if (!ctx || !handle_out)
        return BIO_ERR_INVALID_PARAM;

    uint32_t primary_handle = ctx->primary_handle;
    if (primary_handle < TPM2_PERSISTENT_FIRST ||
        primary_handle > TPM2_PERSISTENT_LAST)
    {
        primary_handle = HIYA_TPM_PRIMARY_HANDLE;
    }

    /* Try to read the persistent handle first */
    uint8_t pub_buf[256];
    size_t pub_len = sizeof(pub_buf);
    int ret = bio_tpm_read_public(ctx, primary_handle,
                                  pub_buf, &pub_len);
    if (ret == BIO_OK)
    {
        *handle_out = primary_handle;
        BIO_INFO("Hiya primary key found at 0x%08X",
                 primary_handle);
        return BIO_OK;
    }

    /* Not found — create and persist */
    BIO_INFO("Hiya primary key not found, creating...");

    uint32_t transient;
    ret = bio_tpm_create_primary(ctx, &transient);
    if (ret != BIO_OK)
        return ret;

    ret = bio_tpm_evict_control(ctx, transient, primary_handle);
    if (ret != BIO_OK)
    {
        bio_tpm_flush_context(ctx, transient);
        return ret;
    }

    bio_tpm_flush_context(ctx, transient);
    *handle_out = primary_handle;
    BIO_INFO("Hiya primary key created and persisted at 0x%08X",
             primary_handle);
    return BIO_OK;
}

/* ── Convenience: seal/unseal for user ───────────────────────── */

int bio_tpm_seal_for_user(bio_tpm_ctx_t *ctx,
                          const uint8_t *data, size_t data_len,
                          const uint8_t *auth, size_t auth_len,
                          uint8_t *sealed_blob, size_t *blob_len)
{
    if (!ctx || !data || !sealed_blob || !blob_len)
        return BIO_ERR_INVALID_PARAM;

    uint32_t primary;
    int ret = bio_tpm_ensure_primary_key(ctx, &primary);
    if (ret != BIO_OK)
        return ret;

    /* We store both private and public portions concatenated:
     * [2B priv_len] [priv_data...] [2B pub_len] [pub_data...] */
    uint8_t priv_buf[512], pub_buf[512];
    size_t priv_sz = sizeof(priv_buf), pub_sz = sizeof(pub_buf);

    ret = bio_tpm_create_sealed(ctx, primary,
                                data, data_len,
                                auth, auth_len,
                                priv_buf, &priv_sz,
                                pub_buf, &pub_sz);
    if (ret != BIO_OK)
    {
        bio_secure_wipe(priv_buf, sizeof(priv_buf));
        bio_secure_wipe(pub_buf, sizeof(pub_buf));
        return ret;
    }

    /* Pack into sealed_blob: [2B priv_len][priv][2B pub_len][pub] */
    size_t needed = 2 + priv_sz + 2 + pub_sz;
    if (needed > *blob_len)
    {
        bio_secure_wipe(priv_buf, sizeof(priv_buf));
        bio_secure_wipe(pub_buf, sizeof(pub_buf));
        *blob_len = needed;
        return BIO_ERR_BUFFER_TOO_SMALL;
    }

    size_t off = 0;
    sealed_blob[off++] = (uint8_t)(priv_sz >> 8);
    sealed_blob[off++] = (uint8_t)(priv_sz);
    memcpy(sealed_blob + off, priv_buf, priv_sz);
    off += priv_sz;

    sealed_blob[off++] = (uint8_t)(pub_sz >> 8);
    sealed_blob[off++] = (uint8_t)(pub_sz);
    memcpy(sealed_blob + off, pub_buf, pub_sz);
    off += pub_sz;

    *blob_len = off;
    bio_secure_wipe(priv_buf, sizeof(priv_buf));
    bio_secure_wipe(pub_buf, sizeof(pub_buf));
    return BIO_OK;
}

int bio_tpm_unseal_for_user(bio_tpm_ctx_t *ctx,
                            const uint8_t *sealed_blob, size_t blob_len,
                            const uint8_t *auth, size_t auth_len,
                            uint8_t *data, size_t *data_len)
{
    if (!ctx || !sealed_blob || !data || !data_len)
        return BIO_ERR_INVALID_PARAM;
    if (blob_len < 4)
        return BIO_ERR_INVALID_PARAM;

    uint32_t primary;
    int ret = bio_tpm_ensure_primary_key(ctx, &primary);
    if (ret != BIO_OK)
        return ret;

    /* Unpack sealed_blob */
    size_t off = 0;
    uint16_t priv_sz = ((uint16_t)sealed_blob[off] << 8) | sealed_blob[off + 1];
    off += 2;
    if (off + priv_sz + 2 > blob_len)
        return BIO_ERR_INVALID_PARAM;
    const uint8_t *priv_data = sealed_blob + off;
    off += priv_sz;

    uint16_t pub_sz = ((uint16_t)sealed_blob[off] << 8) | sealed_blob[off + 1];
    off += 2;
    if (off + pub_sz > blob_len)
        return BIO_ERR_INVALID_PARAM;
    const uint8_t *pub_data = sealed_blob + off;

    /* Load the sealed object */
    uint32_t item_handle;
    ret = bio_tpm_load(ctx, primary, priv_data, priv_sz,
                       pub_data, pub_sz, &item_handle);
    if (ret != BIO_OK)
        return ret;

    /* Unseal */
    ret = bio_tpm_unseal(ctx, item_handle, auth, auth_len, data, data_len);

    /* Always flush the loaded object */
    bio_tpm_flush_context(ctx, item_handle);

    return ret;
}

/* ── Convenience: PCR-bound seal/unseal ──────────────────────── */

int bio_tpm_seal_for_user_pcr(bio_tpm_ctx_t *ctx,
                              const uint8_t *data, size_t data_len,
                              const uint8_t *auth, size_t auth_len,
                              uint32_t pcr_index,
                              uint8_t *sealed_blob, size_t *blob_len)
{
    (void)auth;

    if (!ctx || !data || !sealed_blob || !blob_len)
        return BIO_ERR_INVALID_PARAM;

    /* PCR policy path currently supports policy-only authorization. */
    if (auth_len != 0)
        return BIO_ERR_INVALID_PARAM;

    uint32_t primary;
    int ret = bio_tpm_ensure_primary_key(ctx, &primary);
    if (ret != BIO_OK)
        return ret;

    uint8_t priv_buf[512], pub_buf[512];
    size_t priv_sz = sizeof(priv_buf), pub_sz = sizeof(pub_buf);

    ret = bio_tpm_create_sealed_pcr(ctx, primary,
                                    data, data_len,
                                    auth, auth_len,
                                    pcr_index,
                                    priv_buf, &priv_sz,
                                    pub_buf, &pub_sz);
    if (ret != BIO_OK)
    {
        bio_secure_wipe(priv_buf, sizeof(priv_buf));
        bio_secure_wipe(pub_buf, sizeof(pub_buf));
        return ret;
    }

    /* Pack: [1B pcr_index][2B priv_len][priv][2B pub_len][pub] */
    size_t needed = 1 + 2 + priv_sz + 2 + pub_sz;
    if (needed > *blob_len)
    {
        bio_secure_wipe(priv_buf, sizeof(priv_buf));
        bio_secure_wipe(pub_buf, sizeof(pub_buf));
        *blob_len = needed;
        return BIO_ERR_BUFFER_TOO_SMALL;
    }

    size_t off = 0;
    sealed_blob[off++] = (uint8_t)pcr_index;

    sealed_blob[off++] = (uint8_t)(priv_sz >> 8);
    sealed_blob[off++] = (uint8_t)(priv_sz);
    memcpy(sealed_blob + off, priv_buf, priv_sz);
    off += priv_sz;

    sealed_blob[off++] = (uint8_t)(pub_sz >> 8);
    sealed_blob[off++] = (uint8_t)(pub_sz);
    memcpy(sealed_blob + off, pub_buf, pub_sz);
    off += pub_sz;

    *blob_len = off;
    bio_secure_wipe(priv_buf, sizeof(priv_buf));
    bio_secure_wipe(pub_buf, sizeof(pub_buf));
    return BIO_OK;
}

int bio_tpm_unseal_for_user_pcr(bio_tpm_ctx_t *ctx,
                                const uint8_t *sealed_blob, size_t blob_len,
                                const uint8_t *auth, size_t auth_len,
                                uint32_t pcr_index,
                                uint8_t *data, size_t *data_len)
{
    (void)auth;

    if (!ctx || !sealed_blob || !data || !data_len)
        return BIO_ERR_INVALID_PARAM;
    if (blob_len < 5)
        return BIO_ERR_INVALID_PARAM;

    /* PCR policy path currently supports policy-only authorization. */
    if (auth_len != 0)
        return BIO_ERR_INVALID_PARAM;

    uint32_t primary;
    int ret = bio_tpm_ensure_primary_key(ctx, &primary);
    if (ret != BIO_OK)
        return ret;

    /* Unpack: [1B stored_pcr_index][2B priv_len][priv][2B pub_len][pub] */
    size_t off = 0;
    uint8_t stored_pcr = sealed_blob[off++];
    if (stored_pcr != (uint8_t)pcr_index)
    {
        BIO_WARN("Sealed blob PCR index mismatch: stored=%u, requested=%u",
                 stored_pcr, pcr_index);
        return BIO_ERR_INVALID_PARAM;
    }

    uint16_t priv_sz = ((uint16_t)sealed_blob[off] << 8) | sealed_blob[off + 1];
    off += 2;
    if (off + priv_sz + 2 > blob_len)
        return BIO_ERR_INVALID_PARAM;
    const uint8_t *priv_data = sealed_blob + off;
    off += priv_sz;

    uint16_t pub_sz = ((uint16_t)sealed_blob[off] << 8) | sealed_blob[off + 1];
    off += 2;
    if (off + pub_sz > blob_len)
        return BIO_ERR_INVALID_PARAM;
    const uint8_t *pub_data = sealed_blob + off;

    /* Load the sealed object */
    uint32_t item_handle;
    ret = bio_tpm_load(ctx, primary, priv_data, priv_sz,
                       pub_data, pub_sz, &item_handle);
    if (ret != BIO_OK)
        return ret;

    /* Start a real policy session and satisfy the PCR policy */
    uint32_t session;
    ret = bio_tpm_start_auth_session(ctx, &session);
    if (ret != BIO_OK)
    {
        bio_tpm_flush_context(ctx, item_handle);
        return ret;
    }

    ret = bio_tpm_policy_pcr(ctx, session, pcr_index);
    if (ret != BIO_OK)
    {
        bio_tpm_flush_context(ctx, session);
        bio_tpm_flush_context(ctx, item_handle);
        return ret;
    }

    /*
     * Unseal with the policy session instead of password auth.
     * We need to manually construct the Unseal command with policy session auth.
     */
    bio_tpm_marshal_t m;
    marshal_init(&m, ctx->cmd_buf, sizeof(ctx->cmd_buf));
    marshal_command_header(&m, TPM2_ST_SESSIONS, TPM2_CC_UNSEAL);
    marshal_u32(&m, item_handle);

    /* Authorization: use policy session handle instead of password */
    uint32_t auth_block_size = 4 + 2 + 1 + 2; /* sessionHandle + nonce(0) + attrs + hmac(0) */
    marshal_u32(&m, auth_block_size);
    marshal_u32(&m, session);
    marshal_u16(&m, 0);   /* nonce.size = 0 */
    marshal_u8(&m, 0x01); /* sessionAttributes: continueSession */
    marshal_u16(&m, 0);   /* hmac.size = 0 */

    marshal_command_finalize(&m);

    if (m.error)
    {
        bio_tpm_flush_context(ctx, session);
        bio_tpm_flush_context(ctx, item_handle);
        return BIO_ERR_TPM_COMMAND;
    }
    ctx->cmd_len = m.offset;

    uint32_t rc;
    ret = bio_tpm_execute(ctx, &rc);

    /* Flush both handles regardless of result */
    bio_tpm_flush_context(ctx, session);
    bio_tpm_flush_context(ctx, item_handle);

    if (ret != BIO_OK)
        return ret;
    if (rc != TPM2_RC_SUCCESS)
    {
        BIO_ERROR("TPM2_Unseal (PCR policy) failed: RC=0x%08X", rc);
        return BIO_ERR_TPM_SEALED;
    }

    /* Parse: [4B paramSize][TPM2B_SENSITIVE_DATA] */
    bio_tpm_unmarshal_t u;
    unmarshal_init(&u, ctx->rsp_buf + 10, ctx->rsp_len - 10);

    uint32_t param_size = unmarshal_u32(&u);
    (void)param_size;

    uint16_t data_sz = unmarshal_tpm2b(&u, data, *data_len);
    if (u.error)
        return BIO_ERR_TPM_RESPONSE;
    *data_len = data_sz;

    return BIO_OK;
}
