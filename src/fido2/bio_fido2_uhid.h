/*
 * bio_fido2_uhid.h — CTAPHID Virtual USB Device via /dev/uhid
 *
 * Copyright (C) 2025 BioAuth Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Creates a virtual USB HID device that browsers (Chrome, Firefox)
 * discover as a FIDO2 platform authenticator. Translates CTAPHID
 * (USB HID transport) frames to internal CTAP2 engine calls.
 *
 * The CTAPHID protocol uses 64-byte HID reports:
 *   Initialization packet:
 *     [CID:4][CMD|0x80:1][BCNT_HI:1][BCNT_LO:1][DATA:57]
 *   Continuation packet:
 *     [CID:4][SEQ:1][DATA:59]
 *
 * Commands handled:
 *   CTAPHID_MSG    (0x03) — U2F raw message (not supported, error)
 *   CTAPHID_CBOR   (0x10) — CTAP2 CBOR command
 *   CTAPHID_INIT   (0x06) — Channel allocation
 *   CTAPHID_PING   (0x01) — Echo test
 *   CTAPHID_CANCEL (0x11) — Cancel ongoing operation
 *   CTAPHID_ERROR  (0x3F) — Error response
 *   CTAPHID_KEEPALIVE (0x3B) — Status during long operations
 *
 * References:
 *   FIDO CTAP 2.1 §11.2 (USB HID)
 *   Linux kernel uhid (Documentation/hid/uhid.rst)
 */

#ifndef BIO_FIDO2_UHID_H
#define BIO_FIDO2_UHID_H

#include "bio_common.h"
#include "fido2/bio_fido2.h"
#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── CTAPHID Constants ───────────────────────────────────────── */

#define CTAPHID_BROADCAST_CID       0xFFFFFFFFu
#define CTAPHID_INIT_PACKET_FLAG    0x80

/* Commands */
#define CTAPHID_PING                0x01
#define CTAPHID_MSG                 0x03
#define CTAPHID_LOCK                0x04
#define CTAPHID_INIT                0x06
#define CTAPHID_WINK                0x08
#define CTAPHID_CBOR                0x10
#define CTAPHID_CANCEL              0x11
#define CTAPHID_ERROR               0x3F
#define CTAPHID_KEEPALIVE           0x3B

/* Error codes */
#define CTAPHID_ERR_INVALID_CMD     0x01
#define CTAPHID_ERR_INVALID_PAR     0x02
#define CTAPHID_ERR_INVALID_LEN     0x03
#define CTAPHID_ERR_INVALID_SEQ     0x04
#define CTAPHID_ERR_MSG_TIMEOUT     0x05
#define CTAPHID_TRANSACTION_TIMEOUT_MS  500   /* CTAP2 §11.2.4 */
#define CTAPHID_ERR_CHANNEL_BUSY    0x06
#define CTAPHID_ERR_LOCK_REQUIRED   0x0A
#define CTAPHID_ERR_INVALID_CHANNEL 0x0B
#define CTAPHID_ERR_OTHER           0x7F

/* Keepalive status */
#define CTAPHID_STATUS_PROCESSING   0x01
#define CTAPHID_STATUS_UPNEEDED     0x02

/* HID report size (USB full-speed interrupt) */
#define CTAPHID_REPORT_SIZE         64
#define CTAPHID_INIT_DATA_SIZE      57   /* 64 - 4(CID) - 1(CMD) - 2(LEN) */
#define CTAPHID_CONT_DATA_SIZE      59   /* 64 - 4(CID) - 1(SEQ) */

/* Maximum CTAPHID message payload */
#define CTAPHID_MAX_MSG_SIZE        7609 /* INIT(57) + 128*CONT(59) */

/* Number of allocated channels */
#define CTAPHID_MAX_CHANNELS        8

/* ── Channel State ───────────────────────────────────────────── */

typedef struct {
    uint32_t    cid;
    bool        in_use;
    uint8_t     cmd;              /* Current command being assembled  */
    uint16_t    total_len;        /* Expected total payload length    */
    uint16_t    received;         /* Bytes received so far            */
    uint8_t     next_seq;         /* Next expected continuation seq   */
    uint8_t     msg_buf[CTAPHID_MAX_MSG_SIZE]; /* Reassembly buffer  */
    uint64_t    last_active;      /* Timestamp for timeout            */
} ctaphid_channel_t;

/* ── UHID Transport Context ──────────────────────────────────── */

typedef struct {
    bio_fido2_ctx_t    *fido2_ctx;     /* The CTAP2 engine              */
    int                 uhid_fd;       /* /dev/uhid file descriptor     */
    volatile bool       running;       /* Event loop flag               */
    pthread_t           thread;        /* Reader thread                 */
    bool                thread_valid;  /* Whether pthread was created   */

    /* Channel allocation */
    ctaphid_channel_t   channels[CTAPHID_MAX_CHANNELS];
    uint32_t            next_cid;      /* Next CID to allocate          */

    /* CTAPHID protocol nonce (from INIT) */
    uint8_t             init_nonce[8];
} bio_fido2_uhid_t;

/*
 * Initialize the UHID transport.
 * Opens /dev/uhid and creates a virtual FIDO2 USB HID device.
 *
 * @param uhid      UHID transport context (caller-allocated)
 * @param fido2_ctx Initialized FIDO2 authenticator context
 * @return BIO_OK on success
 */
int bio_fido2_uhid_init(bio_fido2_uhid_t *uhid,
                         bio_fido2_ctx_t *fido2_ctx);

/*
 * Start the UHID transport in a background thread.
 * Reads HID reports from /dev/uhid and dispatches to the CTAP2 engine.
 *
 * @return BIO_OK on success
 */
int bio_fido2_uhid_start(bio_fido2_uhid_t *uhid);

/*
 * Stop the UHID transport and destroy the virtual device.
 */
void bio_fido2_uhid_stop(bio_fido2_uhid_t *uhid);

/*
 * Cleanup resources.
 */
void bio_fido2_uhid_cleanup(bio_fido2_uhid_t *uhid);

#ifdef __cplusplus
}
#endif

#endif /* BIO_FIDO2_UHID_H */
