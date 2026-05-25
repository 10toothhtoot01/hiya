/*
 * bio_fido2_uhid.c — CTAPHID Virtual USB Device via /dev/uhid
 *
 * Copyright (C) 2025 BioAuth Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Creates a virtual USB HID device using Linux's /dev/uhid interface.
 * This device appears to Chrome/Firefox as a FIDO2 platform
 * authenticator, allowing WebAuthn operations with fingerprint
 * verification — the Linux equivalent of Windows Hello for browsers.
 *
 * The flow:
 *   1. We open /dev/uhid and send UHID_CREATE2 to register a virtual
 *      USB HID device with a FIDO2 HID report descriptor.
 *   2. The kernel creates /dev/hidrawN and registers it with the HID
 *      subsystem. Chrome/Firefox discover it via hidraw enumeration.
 *   3. When the browser sends a WebAuthn request, the kernel delivers
 *      UHID_INPUT2 events to us (64-byte HID reports).
 *   4. We reassemble CTAPHID frames, extract the CTAP2 CBOR command,
 *      process it via bio_fido2_process(), and send the response
 *      back as UHID_INPUT2 in framed HID reports.
 *
 * References:
 *   FIDO CTAP 2.1 §11.2 (USB HID)
 *   Linux kernel: include/uapi/linux/uhid.h
 */

#include "fido2/bio_fido2_uhid.h"
#include "fido2/bio_fido2.h"
#include "crypto/bio_crypto.h"
#include "bio_common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <signal.h>
#include <linux/uhid.h>

#define CTAPHID_KEEPALIVE_INTERVAL_MS 250
#define CTAPHID_KEEPALIVE_DELAY_MS 200

/* ── FIDO2 USB HID Report Descriptor ────────────────────────── */
/*
 * This is the standard FIDO U2F/FIDO2 HID report descriptor.
 * It defines a single HID usage page (0xF1D0 = FIDO Alliance)
 * with 64-byte input and output reports.
 *
 * From FIDO U2F HID Protocol §2.
 */
static const uint8_t fido2_hid_report_desc[] = {
    0x06,
    0xD0,
    0xF1, /* Usage Page (FIDO Alliance, 0xF1D0) */
    0x09,
    0x01, /* Usage (U2F HID Authenticator Device) */
    0xA1,
    0x01, /* Collection (Application) */
    0x09,
    0x20, /*   Usage (Input Report Data) */
    0x15,
    0x00, /*   Logical Minimum (0) */
    0x26,
    0xFF,
    0x00, /*   Logical Maximum (255) */
    0x75,
    0x08, /*   Report Size (8 bits) */
    0x95,
    0x40, /*   Report Count (64) */
    0x81,
    0x02, /*   Input (Data, Variable, Absolute) */
    0x09,
    0x21, /*   Usage (Output Report Data) */
    0x15,
    0x00, /*   Logical Minimum (0) */
    0x26,
    0xFF,
    0x00, /*   Logical Maximum (255) */
    0x75,
    0x08, /*   Report Size (8 bits) */
    0x95,
    0x40, /*   Report Count (64) */
    0x91,
    0x02, /*   Output (Data, Variable, Absolute) */
    0xC0, /* End Collection */
};

/* ── Helpers ─────────────────────────────────────────────────── */

static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static uint32_t read_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void write_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v);
}

static void write_be16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v);
}

static void sleep_ms(int ms)
{
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR)
    {
        continue;
    }
}

/* ── UHID I/O ────────────────────────────────────────────────── */

/*
 * Send a UHID event to the kernel.
 */
static int uhid_write_event(int fd, const struct uhid_event *ev)
{
    ssize_t n = write(fd, ev, sizeof(*ev));
    if (n < 0)
    {
        BIO_ERROR("uhid: write failed: %s", strerror(errno));
        return -1;
    }
    if ((size_t)n != sizeof(*ev))
    {
        BIO_ERROR("uhid: short write (%zd/%zu)", n, sizeof(*ev));
        return -1;
    }
    return 0;
}

/*
 * Send a 64-byte HID report (device → host) via UHID_INPUT2.
 */
static int uhid_send_report(int fd, const uint8_t report[CTAPHID_REPORT_SIZE])
{
    struct uhid_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.type = UHID_INPUT2;
    ev.u.input2.size = CTAPHID_REPORT_SIZE;
    memcpy(ev.u.input2.data, report, CTAPHID_REPORT_SIZE);
    return uhid_write_event(fd, &ev);
}

/*
 * Create the virtual FIDO2 HID device.
 */
static int uhid_create_device(int fd)
{
    struct uhid_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.type = UHID_CREATE2;
    strncpy((char *)ev.u.create2.name, "BioAuth FIDO2 Authenticator",
            sizeof(ev.u.create2.name) - 1);
    ev.u.create2.rd_size = sizeof(fido2_hid_report_desc);
    memcpy(ev.u.create2.rd_data, fido2_hid_report_desc,
           sizeof(fido2_hid_report_desc));
    ev.u.create2.bus = 0x03;       /* BUS_USB */
    ev.u.create2.vendor = 0xB10A;  /* BioAuth vendor ID (fictional) */
    ev.u.create2.product = 0xF1D0; /* FIDO product ID */
    ev.u.create2.version = 0x0100;
    ev.u.create2.country = 0;

    if (uhid_write_event(fd, &ev) != 0)
        return -1;

    BIO_INFO("uhid: created virtual FIDO2 device");
    return 0;
}

/*
 * Destroy the virtual device.
 */
static int uhid_destroy_device(int fd)
{
    struct uhid_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.type = UHID_DESTROY;
    return uhid_write_event(fd, &ev);
}

/* ── Channel Management ──────────────────────────────────────── */

static ctaphid_channel_t *find_channel(bio_fido2_uhid_t *uhid, uint32_t cid)
{
    for (int i = 0; i < CTAPHID_MAX_CHANNELS; i++)
    {
        if (uhid->channels[i].in_use && uhid->channels[i].cid == cid)
            return &uhid->channels[i];
    }
    return NULL;
}

static ctaphid_channel_t *alloc_channel(bio_fido2_uhid_t *uhid)
{
    for (int i = 0; i < CTAPHID_MAX_CHANNELS; i++)
    {
        if (!uhid->channels[i].in_use)
        {
            memset(&uhid->channels[i], 0, sizeof(uhid->channels[i]));
            /* CTAP2 §11.2.9: Generate random CID to prevent hijacking */
            uint32_t new_cid;
            int cid_attempts = 0;
            do
            {
                if (bio_random_bytes((uint8_t *)&new_cid, sizeof(new_cid)) != BIO_OK)
                {
                    /* Fallback: use monotonic counter if DRBG fails */
                    static uint32_t fallback_cid = 1;
                    new_cid = fallback_cid++;
                    if (new_cid == 0 || new_cid == 0xFFFFFFFF)
                        new_cid = fallback_cid++;
                }
                if (++cid_attempts > 64)
                {
                    BIO_ERROR("uhid: failed to allocate unique CID");
                    return NULL;
                }
                /* CID 0 and 0xFFFFFFFF are reserved */
            } while (new_cid == 0 || new_cid == 0xFFFFFFFF ||
                     find_channel(uhid, new_cid) != NULL);
            uhid->channels[i].cid = new_cid;
            uhid->channels[i].in_use = true;
            uhid->channels[i].last_active = now_ms();
            return &uhid->channels[i];
        }
    }
    /* Evict the oldest channel */
    int oldest = 0;
    uint64_t oldest_time = uhid->channels[0].last_active;
    for (int i = 1; i < CTAPHID_MAX_CHANNELS; i++)
    {
        if (uhid->channels[i].last_active < oldest_time)
        {
            oldest = i;
            oldest_time = uhid->channels[i].last_active;
        }
    }
    memset(&uhid->channels[oldest], 0, sizeof(uhid->channels[oldest]));
    /* Generate random CID for evicted slot too */
    uint32_t new_cid;
    int cid_attempts = 0;
    do
    {
        if (bio_random_bytes((uint8_t *)&new_cid, sizeof(new_cid)) != BIO_OK)
        {
            /* Fallback: use monotonic counter if DRBG fails */
            static uint32_t fallback_evict_cid = 0x80000000;
            new_cid = fallback_evict_cid++;
            if (new_cid == 0 || new_cid == 0xFFFFFFFF)
                new_cid = fallback_evict_cid++;
        }
        if (++cid_attempts > 64)
        {
            BIO_ERROR("uhid: failed to allocate unique CID for eviction");
            return NULL;
        }
        /* CID 0 and 0xFFFFFFFF are reserved */
    } while (new_cid == 0 || new_cid == 0xFFFFFFFF ||
             find_channel(uhid, new_cid) != NULL);
    uhid->channels[oldest].cid = new_cid;
    uhid->channels[oldest].in_use = true;
    uhid->channels[oldest].last_active = now_ms();
    return &uhid->channels[oldest];
}

/* ── CTAPHID Response Framing ────────────────────────────────── */

/*
 * Send a CTAPHID response as framed 64-byte HID reports.
 */
static int ctaphid_send_response(bio_fido2_uhid_t *uhid,
                                 uint32_t cid, uint8_t cmd,
                                 const uint8_t *data, uint16_t data_len)
{
    uint8_t report[CTAPHID_REPORT_SIZE];
    memset(report, 0, sizeof(report));

    /* Initialization packet */
    write_be32(report, cid);
    report[4] = cmd | CTAPHID_INIT_PACKET_FLAG;
    write_be16(report + 5, data_len);

    uint16_t offset = 0;
    uint16_t chunk = data_len < CTAPHID_INIT_DATA_SIZE
                         ? data_len
                         : CTAPHID_INIT_DATA_SIZE;
    if (chunk > 0 && data)
        memcpy(report + 7, data, chunk);
    offset += chunk;

    if (uhid_send_report(uhid->uhid_fd, report) != 0)
        return -1;

    /* Continuation packets */
    uint8_t seq = 0;
    while (offset < data_len)
    {
        memset(report, 0, sizeof(report));
        write_be32(report, cid);
        report[4] = seq++;

        chunk = (data_len - offset);
        if (chunk > CTAPHID_CONT_DATA_SIZE)
            chunk = CTAPHID_CONT_DATA_SIZE;
        memcpy(report + 5, data + offset, chunk);
        offset += chunk;

        if (uhid_send_report(uhid->uhid_fd, report) != 0)
            return -1;
    }

    return 0;
}

/*
 * Send a CTAPHID error response.
 */
static int ctaphid_send_error(bio_fido2_uhid_t *uhid,
                              uint32_t cid, uint8_t error_code)
{
    return ctaphid_send_response(uhid, cid, CTAPHID_ERROR,
                                 &error_code, 1);
}

typedef struct
{
    bio_fido2_uhid_t *uhid;
    uint32_t cid;
    volatile bool running;
    uint8_t status;
} ctaphid_keepalive_ctx_t;

static void *ctaphid_keepalive_thread(void *arg)
{
    ctaphid_keepalive_ctx_t *ctx = (ctaphid_keepalive_ctx_t *)arg;

    sleep_ms(CTAPHID_KEEPALIVE_DELAY_MS);
    while (ctx->running)
    {
        ctaphid_send_response(ctx->uhid, ctx->cid,
                              CTAPHID_KEEPALIVE, &ctx->status, 1);
        sleep_ms(CTAPHID_KEEPALIVE_INTERVAL_MS);
    }

    return NULL;
}

/* ── CTAPHID Command Handlers ────────────────────────────────── */

/*
 * Handle CTAPHID_INIT (channel allocation).
 */
static void handle_ctaphid_init(bio_fido2_uhid_t *uhid,
                                uint32_t cid,
                                const uint8_t *data, uint16_t len)
{
    /* CTAPHID_INIT request: 8-byte nonce */
    if (len < 8)
    {
        ctaphid_send_error(uhid, cid, CTAPHID_ERR_INVALID_LEN);
        return;
    }

    /* Allocate a new channel */
    ctaphid_channel_t *ch = alloc_channel(uhid);
    if (!ch)
    {
        ctaphid_send_error(uhid, cid, CTAPHID_ERR_OTHER);
        return;
    }

    /*
     * CTAPHID_INIT response (17 bytes):
     *   [nonce:8][cid:4][protocol_ver:1][major:1][minor:1][build:1][caps:1]
     */
    uint8_t resp[17];
    memcpy(resp, data, 8);         /* Echo nonce */
    write_be32(resp + 8, ch->cid); /* Allocated CID */
    resp[12] = 2;                  /* CTAPHID protocol version */
    resp[13] = 1;                  /* Major version (BioAuth 1.x) */
    resp[14] = 0;                  /* Minor version */
    resp[15] = 0;                  /* Build number */
    resp[16] = 0x05;               /* Capabilities: WINK (0x01) | CBOR (0x04) */

    /* Respond on broadcast or original CID */
    uint32_t reply_cid = (cid == CTAPHID_BROADCAST_CID)
                             ? CTAPHID_BROADCAST_CID
                             : cid;
    ctaphid_send_response(uhid, reply_cid, CTAPHID_INIT, resp, 17);

    BIO_DEBUG("uhid: INIT → allocated CID 0x%08X", ch->cid);
}

/*
 * Handle CTAPHID_PING (echo test).
 */
static void handle_ctaphid_ping(bio_fido2_uhid_t *uhid,
                                uint32_t cid,
                                const uint8_t *data, uint16_t len)
{
    ctaphid_send_response(uhid, cid, CTAPHID_PING, data, len);
}

/*
 * Handle CTAPHID_CBOR (CTAP2 command).
 * The first byte of data is the CTAP2 command byte.
 * Remaining bytes are the CBOR request payload.
 */
static void handle_ctaphid_cbor(bio_fido2_uhid_t *uhid,
                                uint32_t cid,
                                const uint8_t *data, uint16_t len)
{
    if (len < 1)
    {
        ctaphid_send_error(uhid, cid, CTAPHID_ERR_INVALID_LEN);
        return;
    }

    uint8_t ctap2_cmd = data[0];
    const uint8_t *cbor_req = data + 1;
    size_t cbor_req_len = len - 1;

    BIO_INFO("uhid: CBOR cmd=0x%02X payload=%zu bytes",
             ctap2_cmd, cbor_req_len);

    ctaphid_keepalive_ctx_t keepalive;
    pthread_t keepalive_thread;
    bool keepalive_started = false;

    if (ctap2_cmd == CTAP2_CMD_MAKE_CREDENTIAL ||
        ctap2_cmd == CTAP2_CMD_GET_ASSERTION ||
        ctap2_cmd == CTAP2_CMD_CLIENT_PIN ||
        ctap2_cmd == CTAP2_CMD_BIO_ENROLLMENT ||
        ctap2_cmd == CTAP2_CMD_CREDENTIAL_MANAGEMENT)
    {
        memset(&keepalive, 0, sizeof(keepalive));
        keepalive.uhid = uhid;
        keepalive.cid = cid;
        keepalive.status = CTAPHID_STATUS_UPNEEDED;
        keepalive.running = true;
        if (pthread_create(&keepalive_thread, NULL,
                           ctaphid_keepalive_thread, &keepalive) == 0)
        {
            keepalive_started = true;
        }
        else
        {
            keepalive.running = false;
        }
    }

    /* Process via the CTAP2 engine */
    uint8_t rsp_buf[BIOAUTH_FIDO2_MAX_MSG];
    size_t rsp_len = sizeof(rsp_buf) - 1; /* Reserve 1 byte for status */

    uint8_t status = bio_fido2_process(uhid->fido2_ctx, ctap2_cmd,
                                       cbor_req, cbor_req_len,
                                       rsp_buf + 1, &rsp_len);

    BIO_INFO("uhid: CBOR cmd=0x%02X → status=0x%02X rsp_len=%zu",
             ctap2_cmd, status, rsp_len);

    if (keepalive_started)
    {
        keepalive.running = false;
        pthread_join(keepalive_thread, NULL);
    }

    /* CTAPHID_CBOR response: [status:1][cbor_response] */
    rsp_buf[0] = status;
    uint16_t total_rsp = (uint16_t)(1 + (status == 0x00 ? rsp_len : 0));

    ctaphid_send_response(uhid, cid, CTAPHID_CBOR, rsp_buf, total_rsp);
}

/*
 * Handle CTAPHID_MSG (U2F raw message — not supported, we're CTAP2 only).
 */
static void handle_ctaphid_msg(bio_fido2_uhid_t *uhid,
                               uint32_t cid,
                               const uint8_t *data, uint16_t len)
{
    (void)data;
    (void)len;
    ctaphid_send_error(uhid, cid, CTAPHID_ERR_INVALID_CMD);
}

/* ── CTAPHID Message Dispatch ────────────────────────────────── */

/*
 * Dispatch a fully reassembled CTAPHID message.
 */
static void ctaphid_dispatch(bio_fido2_uhid_t *uhid,
                             uint32_t cid, uint8_t cmd,
                             const uint8_t *data, uint16_t len)
{
    BIO_INFO("uhid: dispatch CID=0x%08X CMD=0x%02X LEN=%u", cid, cmd, len);

    switch (cmd)
    {
    case CTAPHID_INIT:
        handle_ctaphid_init(uhid, cid, data, len);
        break;
    case CTAPHID_PING:
        handle_ctaphid_ping(uhid, cid, data, len);
        break;
    case CTAPHID_CBOR:
        handle_ctaphid_cbor(uhid, cid, data, len);
        break;
    case CTAPHID_MSG:
        handle_ctaphid_msg(uhid, cid, data, len);
        break;
    case CTAPHID_CANCEL:
        /* CTAP2 §11.2.11: Cancel causes ongoing operation to return
         * CTAP2_ERR_KEEPALIVE_CANCEL. Since we process synchronously,
         * respond with the cancel error to acknowledge the request. */
        {
            uint8_t cancel_status = 0x2D; /* CTAP2_ERR_KEEPALIVE_CANCEL */
            ctaphid_send_response(uhid, cid, CTAPHID_CBOR,
                                  &cancel_status, 1);
        }
        break;
    case CTAPHID_WINK:
        /* No LED to blink, just respond with empty */
        ctaphid_send_response(uhid, cid, CTAPHID_WINK, NULL, 0);
        break;
    default:
        ctaphid_send_error(uhid, cid, CTAPHID_ERR_INVALID_CMD);
        break;
    }
}

/* ── HID Report Processing ───────────────────────────────────── */

/*
 * Process a single 64-byte HID report received from the host.
 * Handles CTAPHID framing: reassembles multi-packet messages,
 * then dispatches complete messages.
 */
static void process_hid_report(bio_fido2_uhid_t *uhid,
                               const uint8_t *report, size_t len)
{
    if (len < CTAPHID_REPORT_SIZE)
        return;

    uint32_t cid = read_be32(report);
    uint8_t byte4 = report[4];

    if (byte4 & CTAPHID_INIT_PACKET_FLAG)
    {
        /* ── Initialization packet ────────────────────────── */
        uint8_t cmd = byte4 & 0x7F;
        uint16_t total_len = ((uint16_t)report[5] << 8) | report[6];

        /* INIT on broadcast CID is always allowed */
        if (cmd == CTAPHID_INIT)
        {
            /* If this is a new INIT, process immediately
             * (single-packet for nonce) */
            uint16_t chunk = total_len;
            if (chunk > CTAPHID_INIT_DATA_SIZE)
                chunk = CTAPHID_INIT_DATA_SIZE;

            if (total_len <= CTAPHID_INIT_DATA_SIZE)
            {
                /* Complete in one packet */
                ctaphid_dispatch(uhid, cid, cmd, report + 7, total_len);
                return;
            }
        }

        /* Validate total length */
        if (total_len > CTAPHID_MAX_MSG_SIZE)
        {
            ctaphid_send_error(uhid, cid, CTAPHID_ERR_INVALID_LEN);
            return;
        }

        /* Find or validate channel */
        ctaphid_channel_t *ch = NULL;
        if (cid == CTAPHID_BROADCAST_CID)
        {
            /* Only INIT is allowed on broadcast CID per CTAP2 §11.2.4.
             * Non-INIT commands on broadcast are rejected. */
            if (cmd != CTAPHID_INIT)
            {
                ctaphid_send_error(uhid, cid, CTAPHID_ERR_INVALID_CHANNEL);
                return;
            }
            ch = alloc_channel(uhid);
        }
        else
        {
            ch = find_channel(uhid, cid);
        }

        if (!ch)
        {
            ctaphid_send_error(uhid, cid, CTAPHID_ERR_INVALID_CHANNEL);
            return;
        }

        /* Start new message reassembly */
        ch->cmd = cmd;
        ch->total_len = total_len;
        ch->next_seq = 0;
        ch->last_active = now_ms();

        uint16_t chunk = total_len;
        if (chunk > CTAPHID_INIT_DATA_SIZE)
            chunk = CTAPHID_INIT_DATA_SIZE;

        memcpy(ch->msg_buf, report + 7, chunk);
        ch->received = chunk;

        /* If message is complete in one packet, dispatch now */
        if (ch->received >= ch->total_len)
        {
            ctaphid_dispatch(uhid, ch->cid, ch->cmd,
                             ch->msg_buf, ch->total_len);
            ch->total_len = 0;
            ch->received = 0;
        }
    }
    else
    {
        /* ── Continuation packet ──────────────────────────── */
        uint8_t seq = byte4;

        ctaphid_channel_t *ch = find_channel(uhid, cid);
        if (!ch || ch->total_len == 0)
        {
            ctaphid_send_error(uhid, cid, CTAPHID_ERR_INVALID_CHANNEL);
            return;
        }

        if (seq != ch->next_seq)
        {
            ctaphid_send_error(uhid, cid, CTAPHID_ERR_INVALID_SEQ);
            /* Abort this transaction */
            ch->total_len = 0;
            ch->received = 0;
            return;
        }

        ch->next_seq++;
        ch->last_active = now_ms();

        uint16_t remaining = ch->total_len - ch->received;
        uint16_t chunk = remaining < CTAPHID_CONT_DATA_SIZE
                             ? remaining
                             : CTAPHID_CONT_DATA_SIZE;

        if (ch->received + chunk > CTAPHID_MAX_MSG_SIZE)
        {
            ctaphid_send_error(uhid, cid, CTAPHID_ERR_INVALID_LEN);
            ch->total_len = 0;
            ch->received = 0;
            return;
        }

        memcpy(ch->msg_buf + ch->received, report + 5, chunk);
        ch->received += chunk;

        /* If message is now complete, dispatch */
        if (ch->received >= ch->total_len)
        {
            ctaphid_dispatch(uhid, ch->cid, ch->cmd,
                             ch->msg_buf, ch->total_len);
            ch->total_len = 0;
            ch->received = 0;
        }
    }
}

/* ── Event Loop ──────────────────────────────────────────────── */

/*
 * UHID reader thread: reads events from /dev/uhid and processes
 * OUTPUT reports (host → device) which contain the CTAPHID frames.
 */
static void *uhid_reader_thread(void *arg)
{
    bio_fido2_uhid_t *uhid = (bio_fido2_uhid_t *)arg;

    struct pollfd pfd;
    pfd.fd = uhid->uhid_fd;
    pfd.events = POLLIN;

    while (uhid->running)
    {
        int ret = poll(&pfd, 1, 500); /* 500ms timeout for running check */
        if (ret < 0)
        {
            if (errno == EINTR)
                continue;
            BIO_ERROR("uhid: poll() failed: %s", strerror(errno));
            break;
        }
        if (ret == 0)
        {
            /* Check for stale transactions — CTAP2 §11.2.4 timeout */
            uint64_t now = now_ms();
            for (int i = 0; i < CTAPHID_MAX_CHANNELS; i++)
            {
                ctaphid_channel_t *ch = &uhid->channels[i];
                if (ch->in_use && ch->total_len > 0 &&
                    ch->received < ch->total_len)
                {
                    if (now - ch->last_active > CTAPHID_TRANSACTION_TIMEOUT_MS)
                    {
                        ctaphid_send_error(uhid, ch->cid,
                                           CTAPHID_ERR_MSG_TIMEOUT);
                        ch->total_len = 0;
                        ch->received = 0;
                    }
                }
            }
            continue;
        }

        struct uhid_event ev;
        ssize_t n = read(uhid->uhid_fd, &ev, sizeof(ev));
        if (n == 0)
        {
            BIO_WARN("uhid: read() returned EOF, stopping reader thread");
            break;
        }
        if (n < 0)
        {
            if (errno == EINTR || errno == EAGAIN)
                continue;
            BIO_ERROR("uhid: read() failed: %s", strerror(errno));
            break;
        }
        if ((size_t)n < sizeof(ev))
        {
            BIO_WARN("uhid: short event read (%zd/%zu), ignoring",
                     n, sizeof(ev));
            continue;
        }

        switch (ev.type)
        {
        case UHID_START:
            BIO_INFO("uhid: device started by kernel driver");
            break;
        case UHID_STOP:
            BIO_INFO("uhid: device stopped by kernel driver");
            break;
        case UHID_OPEN:
            BIO_INFO("uhid: device opened by userspace (browser?)");
            break;
        case UHID_CLOSE:
            BIO_INFO("uhid: device closed by userspace");
            break;
        case UHID_OUTPUT:
            /* Host → Device report (contains CTAPHID frame).
             * When userspace writes to hidraw, the kernel passes the full
             * buffer including the HID report ID byte (0x00 for devices
             * without numbered reports) to UHID_OUTPUT. Strip it. */
            {
                const uint8_t *rpt_data = ev.u.output.data;
                size_t rpt_size = ev.u.output.size;

                /* Strip report ID prefix: hidraw write always prepends
                 * report ID byte 0x00 for non-numbered-report devices */
                if (rpt_size == CTAPHID_REPORT_SIZE + 1 &&
                    rpt_data[0] == 0x00)
                {
                    rpt_data++;
                    rpt_size--;
                }

                if (rpt_size < 5)
                {
                    BIO_WARN("uhid: short OUTPUT report (%zu bytes), dropping",
                             rpt_size);
                    break;
                }

                BIO_INFO("uhid: OUTPUT report (%zu bytes) CID=%02x%02x%02x%02x CMD=0x%02x",
                         rpt_size, rpt_data[0], rpt_data[1],
                         rpt_data[2], rpt_data[3], rpt_data[4]);

                if (rpt_size == CTAPHID_REPORT_SIZE)
                {
                    process_hid_report(uhid, rpt_data, rpt_size);
                }
                else
                {
                    BIO_WARN("uhid: invalid report size %zu (expected %u)",
                             rpt_size, CTAPHID_REPORT_SIZE);
                }
            }
            break;
        case UHID_GET_REPORT:
        {
            /* Host requests a report — respond with empty 64-byte report */
            struct uhid_event reply;
            memset(&reply, 0, sizeof(reply));
            reply.type = UHID_GET_REPORT_REPLY;
            reply.u.get_report_reply.id = ev.u.get_report.id;
            reply.u.get_report_reply.err = 0;
            reply.u.get_report_reply.size = CTAPHID_REPORT_SIZE;
            memset(reply.u.get_report_reply.data, 0, CTAPHID_REPORT_SIZE);
            uhid_write_event(uhid->uhid_fd, &reply);
            BIO_INFO("uhid: replied to GET_REPORT (id=%u, rnum=%u, rtype=%u)",
                     ev.u.get_report.id, ev.u.get_report.rnum,
                     ev.u.get_report.rtype);
            break;
        }
        case UHID_SET_REPORT:
        {
            /* Host sets a report — acknowledge */
            struct uhid_event reply;
            memset(&reply, 0, sizeof(reply));
            reply.type = UHID_SET_REPORT_REPLY;
            reply.u.set_report_reply.id = ev.u.set_report.id;
            reply.u.set_report_reply.err = 0;
            uhid_write_event(uhid->uhid_fd, &reply);
            BIO_INFO("uhid: replied to SET_REPORT (id=%u)", ev.u.set_report.id);
            break;
        }
        default:
            BIO_INFO("uhid: unhandled event type %u", ev.type);
            break;
        }
    }

    BIO_INFO("uhid: reader thread exiting");
    return NULL;
}

/* ── Public API ──────────────────────────────────────────────── */

int bio_fido2_uhid_init(bio_fido2_uhid_t *uhid,
                        bio_fido2_ctx_t *fido2_ctx)
{
    if (!uhid || !fido2_ctx)
        return BIO_ERR_INVALID_PARAM;

    memset(uhid, 0, sizeof(*uhid));
    uhid->fido2_ctx = fido2_ctx;
    uhid->uhid_fd = -1;
    /* next_cid unused — CIDs are allocated randomly in alloc_channel() */

    /* Open /dev/uhid */
    uhid->uhid_fd = open("/dev/uhid", O_RDWR | O_CLOEXEC);
    if (uhid->uhid_fd < 0)
    {
        BIO_ERROR("uhid: cannot open /dev/uhid: %s", strerror(errno));
        BIO_ERROR("uhid: ensure the uhid kernel module is loaded and "
                  "you have permission to access /dev/uhid");
        return BIO_ERR_IO;
    }

    /* Create the virtual FIDO2 HID device */
    if (uhid_create_device(uhid->uhid_fd) != 0)
    {
        close(uhid->uhid_fd);
        uhid->uhid_fd = -1;
        return BIO_ERR_IO;
    }

    BIO_INFO("uhid: virtual FIDO2 authenticator initialized");
    return BIO_OK;
}

int bio_fido2_uhid_start(bio_fido2_uhid_t *uhid)
{
    if (!uhid || uhid->uhid_fd < 0)
        return BIO_ERR_INVALID_PARAM;

    uhid->running = true;

    /* Block signals in the reader thread — they should be
     * handled by the main thread only */
    sigset_t all_sigs, old_sigs;
    sigfillset(&all_sigs);
    pthread_sigmask(SIG_SETMASK, &all_sigs, &old_sigs);

    int rc = pthread_create(&uhid->thread, NULL,
                            uhid_reader_thread, uhid);

    pthread_sigmask(SIG_SETMASK, &old_sigs, NULL);
    if (rc != 0)
    {
        BIO_ERROR("uhid: pthread_create failed: %s", strerror(rc));
        uhid->running = false;
        return BIO_ERR_IO;
    }
    uhid->thread_valid = true;

    BIO_INFO("uhid: reader thread started — browsers can now discover "
             "BioAuth FIDO2 authenticator");
    return BIO_OK;
}

void bio_fido2_uhid_stop(bio_fido2_uhid_t *uhid)
{
    if (!uhid)
        return;

    uhid->running = false;

    if (uhid->thread_valid)
    {
        pthread_join(uhid->thread, NULL);
        uhid->thread_valid = false;
        BIO_INFO("uhid: reader thread joined");
    }
}

void bio_fido2_uhid_cleanup(bio_fido2_uhid_t *uhid)
{
    if (!uhid)
        return;

    bio_fido2_uhid_stop(uhid);

    if (uhid->uhid_fd >= 0)
    {
        uhid_destroy_device(uhid->uhid_fd);
        close(uhid->uhid_fd);
        uhid->uhid_fd = -1;
    }

    BIO_INFO("uhid: cleaned up");
}
