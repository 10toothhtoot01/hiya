/*
 * bio_fingerprint.c — Enhanced Fingerprint Wrapper Implementation
 *
 * Copyright (C) 2024 BioAuth Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Wraps libfprint-2 GObject-based API with our clean C interface.
 * Uses GLib main loop internally for async-to-sync bridging.
 */

#include "bio_fingerprint.h"
#include "crypto/bio_crypto.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

/* libfprint-2 headers */
#include <fprint.h>

#define BIO_FP_VERIFY_TIMEOUT_MS 30000

/* ── Internal structures ─────────────────────────────────────── */

struct bio_fp_ctx {
    FpContext *fp_ctx;      /* libfprint context */
    GMainLoop *loop;        /* GLib main loop for blocking ops */
};

/* Rate limiter state */
typedef struct {
    bio_fp_rate_config_t config;
    int      failure_count;
    time_t   failures[32];     /* Ring buffer of failure timestamps */
    int      failure_idx;
    time_t   lockout_until;    /* 0 if not locked out */
} bio_fp_rate_state_t;

struct bio_fp_device {
    bio_fp_ctx_t        *ctx;
    FpDevice            *fp_dev;      /* libfprint device */
    bio_fp_device_info_t info;
    bio_fp_rate_state_t  rate;
    bool                 is_open;
};

/* ── GLib async-to-sync helpers ──────────────────────────────── */

typedef struct {
    GMainLoop           *loop;
    int                  result;      /* BIO_OK or error */
    bio_fp_enroll_cb_t   enroll_cb;
    bio_fp_verify_cb_t   verify_cb;
    void                *user_data;
    FpPrint             *print;       /* Result print from enrollment */
    bool                 match;       /* Verification result */
    GCancellable        *cancellable;
    guint                timeout_id;
    bool                 timed_out;
    int                  stage;       /* Current enrollment stage */
    int                  total_stages;
} bio_fp_async_data_t;

/*
 * Shared structs for GLib async-to-sync callback bridges.
 * These were formerly defined as nested functions (GCC extension);
 * converted to static file-scope functions for portability.
 */
typedef struct {
    GMainLoop  *loop;
    int         result;
    GPtrArray  *prints;
} fp_list_data_t;

typedef struct {
    GMainLoop *loop;
    int        result;
} fp_del_data_t;

typedef struct {
    GMainLoop *loop;
    int        result;
    FpPrint   *match_print;
} fp_ident_data_t;

static void fp_on_list_done(GObject *source, GAsyncResult *res, gpointer data)
{
    fp_list_data_t *d = data;
    GError *err = NULL;
    d->prints = fp_device_list_prints_finish(FP_DEVICE(source), res, &err);
    if (err) {
        BIO_ERROR("list_prints failed: %s", err->message);
        d->result = BIO_ERR_FP_OPEN;
        g_error_free(err);
    } else {
        d->result = BIO_OK;
    }
    g_main_loop_quit(d->loop);
}

static void fp_on_delete_done(GObject *source, GAsyncResult *res, gpointer data)
{
    fp_del_data_t *d = data;
    GError *err = NULL;
    gboolean ok = fp_device_delete_print_finish(FP_DEVICE(source), res, &err);
    if (!ok || err) {
        BIO_ERROR("delete_print failed: %s", err ? err->message : "unknown");
        d->result = BIO_ERR_FP_DELETE;
        if (err) g_error_free(err);
    } else {
        d->result = BIO_OK;
    }
    g_main_loop_quit(d->loop);
}

static void fp_on_clear_done(GObject *source, GAsyncResult *res, gpointer data)
{
    fp_del_data_t *d = data;
    GError *err = NULL;
    gboolean ok = fp_device_clear_storage_finish(FP_DEVICE(source), res, &err);
    if (!ok || err) {
        BIO_WARN("clear_storage failed: %s", err ? err->message : "unknown");
        d->result = BIO_ERR_FP_DELETE;
        if (err) g_error_free(err);
    } else {
        d->result = BIO_OK;
    }
    g_main_loop_quit(d->loop);
}

static void fp_on_identify_done(GObject *source, GAsyncResult *res, gpointer data)
{
    fp_ident_data_t *d = data;
    GError *err = NULL;
    FpPrint *match = NULL;

    gboolean ok = fp_device_identify_finish(FP_DEVICE(source), res,
                                              &match, NULL, &err);
    if (!ok || err) {
        BIO_ERROR("Identify error: %s", err ? err->message : "unknown");
        d->result = BIO_ERR_FP_VERIFY;
        if (err) g_error_free(err);
    } else {
        d->match_print = match;
        d->result = BIO_OK;
    }
    g_main_loop_quit(d->loop);
}

/* ── Lifecycle ────────────────────────────────────────────────── */

int bio_fp_init(bio_fp_ctx_t **ctx_out)
{
    if (!ctx_out) return BIO_ERR_INVALID_PARAM;

    bio_fp_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return BIO_ERR_NOMEM;

    ctx->fp_ctx = fp_context_new();
    if (!ctx->fp_ctx) {
        BIO_ERROR("Failed to create libfprint context");
        free(ctx);
        return BIO_ERR_FP_OPEN;
    }

    *ctx_out = ctx;
    BIO_INFO("Fingerprint subsystem initialized");
    return BIO_OK;
}

void bio_fp_cleanup(bio_fp_ctx_t *ctx)
{
    if (!ctx) return;

    if (ctx->fp_ctx) {
        g_object_unref(ctx->fp_ctx);
        ctx->fp_ctx = NULL;
    }

    free(ctx);
    BIO_DEBUG("Fingerprint subsystem cleaned up");
}

/* ── Device enumeration ──────────────────────────────────────── */

int bio_fp_enumerate_devices(bio_fp_ctx_t *ctx,
                             bio_fp_device_info_t *devices,
                             size_t max_devices,
                             size_t *count)
{
    if (!ctx || !devices || !count)
        return BIO_ERR_INVALID_PARAM;

    /* Refresh device list (synchronous via GLib) */
    GPtrArray *devs = fp_context_get_devices(ctx->fp_ctx);
    if (!devs) {
        *count = 0;
        return BIO_OK;
    }

    *count = 0;
    for (guint i = 0; i < devs->len && *count < max_devices; i++) {
        FpDevice *dev = g_ptr_array_index(devs, i);
        bio_fp_device_info_t *info = &devices[*count];

        memset(info, 0, sizeof(*info));

        const char *name = fp_device_get_name(dev);
        if (name) {
            strncpy(info->name, name, sizeof(info->name) - 1);
        }

        const char *driver = fp_device_get_driver(dev);
        if (driver) {
            strncpy(info->driver, driver, sizeof(info->driver) - 1);
        }

        info->has_storage = fp_device_has_feature(dev,
                                    FP_DEVICE_FEATURE_STORAGE);
        info->supports_identify = fp_device_has_feature(dev,
                                    FP_DEVICE_FEATURE_IDENTIFY);
        info->nr_enroll_stages = fp_device_get_nr_enroll_stages(dev);

        /* Try to get USB VID/PID from the device ID string.
         * libfprint device IDs often encode this as "vid:pid" hex. */
        const char *dev_id = fp_device_get_device_id(dev);
        if (dev_id) {
            unsigned int vid = 0, pid = 0;
            if (sscanf(dev_id, "%x:%x", &vid, &pid) == 2) {
                info->usb_vendor = (uint16_t)vid;
                info->usb_product = (uint16_t)pid;
            }
        }

        (*count)++;
    }

    BIO_DEBUG("Enumerated %zu fingerprint device(s)", *count);
    return BIO_OK;
}

/* ── Device open/close ───────────────────────────────────────── */

static void on_device_opened(GObject *source, GAsyncResult *res, gpointer data)
{
    bio_fp_async_data_t *async = data;
    GError *err = NULL;

    gboolean ok = fp_device_open_finish(FP_DEVICE(source), res, &err);
    if (!ok || err) {
        BIO_ERROR("Failed to open fingerprint device: %s",
                  err ? err->message : "unknown error");
        async->result = BIO_ERR_FP_OPEN;
        if (err) g_error_free(err);
    } else {
        async->result = BIO_OK;
    }

    g_main_loop_quit(async->loop);
}

int bio_fp_open_device(bio_fp_ctx_t *ctx, bio_fp_device_t **dev_out)
{
    if (!ctx || !dev_out)
        return BIO_ERR_INVALID_PARAM;

    GPtrArray *devs = fp_context_get_devices(ctx->fp_ctx);
    if (!devs || devs->len == 0) {
        BIO_ERROR("No fingerprint devices found");
        return BIO_ERR_FP_NO_DEVICE;
    }

    FpDevice *fp_dev = g_ptr_array_index(devs, 0);

    bio_fp_device_t *dev = calloc(1, sizeof(*dev));
    if (!dev) return BIO_ERR_NOMEM;

    dev->ctx = ctx;
    dev->fp_dev = g_object_ref(fp_dev);

    /* Set default rate config */
    dev->rate.config = (bio_fp_rate_config_t)BIO_FP_RATE_DEFAULT;

    /* Open device (async → sync bridge) */
    GMainLoop *loop = g_main_loop_new(NULL, FALSE);
    bio_fp_async_data_t async = {
        .loop = loop,
        .result = BIO_ERR_INTERNAL,
    };

    fp_device_open(dev->fp_dev, NULL, on_device_opened, &async);
    g_main_loop_run(loop);
    g_main_loop_unref(loop);

    if (async.result != BIO_OK) {
        g_object_unref(dev->fp_dev);
        free(dev);
        return async.result;
    }

    dev->is_open = true;

    /* Populate device info */
    bio_fp_get_device_info(dev, &dev->info);

    *dev_out = dev;
    BIO_INFO("Fingerprint device opened: %s (%s)",
             dev->info.name, dev->info.driver);
    return BIO_OK;
}

static void on_device_closed(GObject *source, GAsyncResult *res, gpointer data)
{
    bio_fp_async_data_t *async = data;
    GError *err = NULL;

    fp_device_close_finish(FP_DEVICE(source), res, &err);
    if (err) {
        BIO_WARN("Error closing fingerprint device: %s", err->message);
        g_error_free(err);
    }
    async->result = BIO_OK;
    g_main_loop_quit(async->loop);
}

void bio_fp_close_device(bio_fp_device_t *dev)
{
    if (!dev) return;

    if (dev->is_open && dev->fp_dev) {
        GMainLoop *loop = g_main_loop_new(NULL, FALSE);
        bio_fp_async_data_t async = { .loop = loop };

        fp_device_close(dev->fp_dev, NULL, on_device_closed, &async);
        g_main_loop_run(loop);
        g_main_loop_unref(loop);
    }

    if (dev->fp_dev) {
        g_object_unref(dev->fp_dev);
    }

    free(dev);
    BIO_DEBUG("Fingerprint device closed");
}

int bio_fp_get_device_info(bio_fp_device_t *dev, bio_fp_device_info_t *info)
{
    if (!dev || !info) return BIO_ERR_INVALID_PARAM;

    memset(info, 0, sizeof(*info));

    const char *name = fp_device_get_name(dev->fp_dev);
    if (name) strncpy(info->name, name, sizeof(info->name) - 1);

    const char *driver = fp_device_get_driver(dev->fp_dev);
    if (driver) strncpy(info->driver, driver, sizeof(info->driver) - 1);

    info->has_storage = fp_device_has_feature(dev->fp_dev,
                                FP_DEVICE_FEATURE_STORAGE);
    info->supports_identify = fp_device_has_feature(dev->fp_dev,
                                FP_DEVICE_FEATURE_IDENTIFY);
    info->nr_enroll_stages = fp_device_get_nr_enroll_stages(dev->fp_dev);

    return BIO_OK;
}

/* ── Enrollment ──────────────────────────────────────────────── */

static void on_enroll_progress(FpDevice *device,
                                gint completed_stages,
                                FpPrint *print,
                                gpointer user_data,
                                GError *error)
{
    bio_fp_async_data_t *async = user_data;
    (void)device;
    (void)print;

    if (error) {
        BIO_WARN("Enroll progress error: %s", error->message);
        if (async->enroll_cb) {
            async->enroll_cb(BIO_FP_ENROLL_RETRY, completed_stages,
                              async->total_stages, async->user_data);
        }
        return;
    }

    async->stage = completed_stages;
    if (async->enroll_cb) {
        async->enroll_cb(BIO_FP_ENROLL_STAGE_PASSED,
                          completed_stages,
                          async->total_stages,
                          async->user_data);
    }
}

static void on_enroll_done(GObject *source, GAsyncResult *res, gpointer data)
{
    bio_fp_async_data_t *async = data;
    GError *err = NULL;

    FpPrint *print = fp_device_enroll_finish(FP_DEVICE(source), res, &err);
    if (!print || err) {
        BIO_ERROR("Enrollment failed: %s",
                  err ? err->message : "unknown");
        /*
         * MOC (Match-on-Chip) sensors store templates on the chip.
         * If the chip has a stale template (DB wiped but chip not
         * cleared), libfprint returns "Finger was already enrolled".
         * Return a distinct code so the daemon can auto-recover.
         */
        if (err && err->message &&
            strstr(err->message, "already enrolled") != NULL) {
            async->result = BIO_ERR_FP_ALREADY_ENROLLED;
        } else {
            async->result = BIO_ERR_FP_ENROLL;
        }
        if (err) g_error_free(err);
    } else {
        async->print = print;
        async->result = BIO_OK;

        if (async->enroll_cb) {
            async->enroll_cb(BIO_FP_ENROLL_COMPLETE,
                              async->total_stages,
                              async->total_stages,
                              async->user_data);
        }
    }

    g_main_loop_quit(async->loop);
}

int bio_fp_enroll(bio_fp_device_t *dev,
                  bio_finger_t finger,
                  bio_fp_enroll_cb_t callback,
                  void *user_data,
                  uint8_t *out_data, size_t *out_len)
{
    if (!dev || !dev->is_open || !out_data || !out_len)
        return BIO_ERR_INVALID_PARAM;

    /* Create a template print for enrollment */
    FpPrint *template_print = fp_print_new(dev->fp_dev);
    fp_print_set_finger(template_print, (FpFinger)finger);
    fp_print_set_username(template_print, "bioauth");

    GMainLoop *loop = g_main_loop_new(NULL, FALSE);
    bio_fp_async_data_t async = {
        .loop = loop,
        .result = BIO_ERR_INTERNAL,
        .enroll_cb = callback,
        .user_data = user_data,
        .total_stages = dev->info.nr_enroll_stages,
    };

    fp_device_enroll(dev->fp_dev, template_print, NULL,
                      on_enroll_progress, &async, NULL,
                      on_enroll_done, &async);

    g_main_loop_run(loop);
    g_main_loop_unref(loop);

    /* template_print is consumed by fp_device_enroll — do NOT unref it */

    if (async.result != BIO_OK) {
        if (async.print) g_object_unref(async.print);
        return async.result;
    }

    /* Serialize the enrolled print */
    GError *err = NULL;
    guchar *serial_data = NULL;
    gsize serial_len = 0;

    gboolean ok = fp_print_serialize(async.print, &serial_data, &serial_len, &err);
    g_object_unref(async.print);

    if (!ok || err) {
        BIO_ERROR("Failed to serialize print: %s",
                  err ? err->message : "unknown");
        if (err) g_error_free(err);
        return BIO_ERR_FP_ENROLL;
    }

    if (serial_len > *out_len) {
        bio_secure_wipe(serial_data, serial_len);
        g_free(serial_data);
        /* F2 fix: Wipe any partial data in the output buffer */
        explicit_bzero(out_data, *out_len);
        *out_len = serial_len;
        return BIO_ERR_BUFFER_TOO_SMALL;
    }

    memcpy(out_data, serial_data, serial_len);
    *out_len = serial_len;
    bio_secure_wipe(serial_data, serial_len);
    g_free(serial_data);

    BIO_INFO("Fingerprint enrolled: finger=%s, %zu bytes",
             bio_finger_str(finger), serial_len);
    return BIO_OK;
}

/* ── Verification ────────────────────────────────────────────── */

static void on_verify_done(GObject *source, GAsyncResult *res, gpointer data)
{
    bio_fp_async_data_t *async = data;
    GError *err = NULL;
    gboolean match = FALSE;

    if (async->timeout_id != 0) {
        g_source_remove(async->timeout_id);
        async->timeout_id = 0;
    }

    gboolean ok = fp_device_verify_finish(FP_DEVICE(source), res,
                                           &match, NULL, &err);
    if (!ok || err) {
        if (err && async->timed_out &&
            g_error_matches(err, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
            BIO_WARN("Verification timed out");
            async->result = BIO_ERR_TIMEOUT;
        } else {
            BIO_ERROR("Verification error: %s",
                      err ? err->message : "unknown");
            async->result = BIO_ERR_FP_VERIFY;
        }
        async->match = false;
        if (err) g_error_free(err);
    } else {
        async->match = match;
        async->result = BIO_OK;
    }

    g_main_loop_quit(async->loop);
}

static gboolean on_verify_timeout(gpointer data)
{
    bio_fp_async_data_t *async = data;
    async->timed_out = true;
    if (async->cancellable) {
        g_cancellable_cancel(async->cancellable);
    }
    async->timeout_id = 0;
    return G_SOURCE_REMOVE;
}

int bio_fp_verify(bio_fp_device_t *dev,
                  const uint8_t *print_data, size_t print_len,
                  bio_fp_verify_cb_t callback,
                  void *user_data,
                  int timeout_ms)
{
    if (!dev || !dev->is_open || !print_data)
        return BIO_ERR_INVALID_PARAM;

    /* Check rate limit first */
    int remaining;
    int rc = bio_fp_check_rate_limit(dev, &remaining);
    /* Resolve effective timeout: caller overrides macro default */
    int eff_tms = (timeout_ms > 0 && timeout_ms <= 120000)
        ? timeout_ms : BIO_FP_VERIFY_TIMEOUT_MS;

    if (rc == BIO_ERR_FP_RATE_LIMIT) {
        BIO_WARN("Fingerprint verification rate-limited: %d seconds remaining",
                 remaining);
        if (callback) {
            callback(BIO_FP_VERIFY_ERROR, user_data);
        }
        return BIO_ERR_FP_RATE_LIMIT;
    }

    /* Deserialize the stored print */
    GError *err = NULL;
    FpPrint *print = fp_print_deserialize(print_data, print_len, &err);
    if (!print || err) {
        BIO_ERROR("Failed to deserialize print: %s",
                  err ? err->message : "unknown");
        if (err) g_error_free(err);
        return BIO_ERR_FP_VERIFY;
    }

    GMainContext *verify_ctx = g_main_context_new();
    if (!verify_ctx) {
        g_object_unref(print);
        return BIO_ERR_NOMEM;
    }
    g_main_context_push_thread_default(verify_ctx);

    GMainLoop *loop = g_main_loop_new(verify_ctx, FALSE);
    if (!loop) {
        g_main_context_pop_thread_default(verify_ctx);
        g_main_context_unref(verify_ctx);
        g_object_unref(print);
        return BIO_ERR_NOMEM;
    }

    bio_fp_async_data_t async = {
        .loop = loop,
        .result = BIO_ERR_INTERNAL,
        .verify_cb = callback,
        .user_data = user_data,
        .cancellable = g_cancellable_new(),
        .timeout_id = 0,
        .timed_out = false,
    };

    GSource *timeout_source = g_timeout_source_new(eff_tms);
    g_source_set_callback(timeout_source, on_verify_timeout, &async, NULL);
    async.timeout_id = g_source_attach(timeout_source, verify_ctx);
    g_source_unref(timeout_source);

    fp_device_verify(dev->fp_dev, print, async.cancellable,
                      NULL, NULL, NULL,
                      on_verify_done, &async);

    g_main_loop_run(loop);
    g_main_loop_unref(loop);
    g_main_context_pop_thread_default(verify_ctx);
    g_main_context_unref(verify_ctx);

    if (async.timeout_id != 0) {
        g_source_remove(async.timeout_id);
        async.timeout_id = 0;
    }
    if (async.cancellable) {
        g_object_unref(async.cancellable);
        async.cancellable = NULL;
    }

    g_object_unref(print);

    if (async.result == BIO_OK && async.match) {
        BIO_DEBUG("Fingerprint verification: MATCH");
        bio_fp_reset_rate_limit(dev);
        if (callback) callback(BIO_FP_VERIFY_MATCH, user_data);
        return BIO_OK;
    }
    else if (async.result == BIO_OK && !async.match) {
        BIO_DEBUG("Fingerprint verification: NO MATCH");
        bio_fp_record_failure(dev);
        if (callback) callback(BIO_FP_VERIFY_NO_MATCH, user_data);
        return BIO_ERR_FP_NO_MATCH;
    }

    if (async.result == BIO_ERR_TIMEOUT) {
        if (callback) callback(BIO_FP_VERIFY_ERROR, user_data);
        return BIO_ERR_TIMEOUT;
    }

    /* Device/I/O errors should NOT count against rate limit */
    return async.result;
}

/* ── Rate limiting ───────────────────────────────────────────── */

int bio_fp_set_rate_limit(bio_fp_device_t *dev,
                          const bio_fp_rate_config_t *config)
{
    if (!dev || !config) return BIO_ERR_INVALID_PARAM;
    dev->rate.config = *config;
    return BIO_OK;
}

int bio_fp_check_rate_limit(bio_fp_device_t *dev, int *remaining_seconds)
{
    if (!dev) return BIO_ERR_INVALID_PARAM;

    time_t now = time(NULL);

    /* Check if currently locked out */
    if (dev->rate.lockout_until > now) {
        if (remaining_seconds) {
            *remaining_seconds = (int)(dev->rate.lockout_until - now);
        }
        return BIO_ERR_FP_RATE_LIMIT;
    }

    /* Reset lockout if expired */
    if (dev->rate.lockout_until > 0 && dev->rate.lockout_until <= now) {
        dev->rate.lockout_until = 0;
        dev->rate.failure_count = 0;
        dev->rate.failure_idx = 0;
        memset(dev->rate.failures, 0, sizeof(dev->rate.failures));
    }

    if (remaining_seconds) *remaining_seconds = 0;
    return BIO_OK;
}

void bio_fp_record_failure(bio_fp_device_t *dev)
{
    if (!dev) return;

    time_t now = time(NULL);

    /* Count recent failures within the window */
    int recent = 0;
    for (int i = 0; i < dev->rate.failure_count && i < 32; i++) {
        if (now - dev->rate.failures[i] <= dev->rate.config.window_seconds) {
            recent++;
        }
    }

    /* Record this failure */
    dev->rate.failures[dev->rate.failure_idx % 32] = now;
    dev->rate.failure_idx = (dev->rate.failure_idx + 1) % 32;
    if (dev->rate.failure_count < 32) dev->rate.failure_count++;
    recent++;

    /* Check if lockout threshold exceeded */
    if (recent >= dev->rate.config.max_attempts) {
        dev->rate.lockout_until = now + dev->rate.config.lockout_seconds;
        BIO_WARN("Rate limit triggered: locked out for %d seconds",
                 dev->rate.config.lockout_seconds);
    }
}

void bio_fp_reset_rate_limit(bio_fp_device_t *dev)
{
    if (!dev) return;
    dev->rate.failure_count = 0;
    dev->rate.lockout_until = 0;
    dev->rate.failure_idx = 0;
    memset(dev->rate.failures, 0, sizeof(dev->rate.failures));
}

/* ── Print management (device storage) ───────────────────────── */

int bio_fp_list_prints(bio_fp_device_t *dev,
                       bio_finger_t *fingers,
                       size_t max,
                       size_t *count)
{
    if (!dev || !fingers || !count)
        return BIO_ERR_INVALID_PARAM;

    *count = 0;

    if (!dev->info.has_storage) {
        return BIO_OK;
    }

    /* Async → sync bridge for fp_device_list_prints */
    GMainLoop *loop = g_main_loop_new(NULL, FALSE);
    fp_list_data_t ld = { .loop = loop, .result = BIO_ERR_INTERNAL, .prints = NULL };

    fp_device_list_prints(dev->fp_dev, NULL, fp_on_list_done, &ld);
    g_main_loop_run(loop);
    g_main_loop_unref(loop);

    if (ld.result != BIO_OK)
        return ld.result;

    if (ld.prints) {
        for (guint i = 0; i < ld.prints->len && *count < max; i++) {
            FpPrint *p = g_ptr_array_index(ld.prints, i);
            FpFinger f = fp_print_get_finger(p);
            fingers[*count] = (bio_finger_t)f;
            (*count)++;
        }
        g_ptr_array_unref(ld.prints);
    }

    BIO_DEBUG("Listed %zu enrolled prints", *count);
    return BIO_OK;
}

int bio_fp_delete_print(bio_fp_device_t *dev, bio_finger_t finger)
{
    if (!dev) return BIO_ERR_INVALID_PARAM;

    if (!dev->info.has_storage) {
        return BIO_ERR_FP_DELETE;
    }

    /* First list prints to find the one to delete */
    GMainLoop *loop = g_main_loop_new(NULL, FALSE);
    fp_list_data_t ld = { .loop = loop, .result = BIO_ERR_INTERNAL, .prints = NULL };

    fp_device_list_prints(dev->fp_dev, NULL, fp_on_list_done, &ld);
    g_main_loop_run(loop);
    g_main_loop_unref(loop);

    if (ld.result != BIO_OK)
        return ld.result;

    /* Find the print matching the requested finger */
    FpPrint *target = NULL;
    if (ld.prints) {
        for (guint i = 0; i < ld.prints->len; i++) {
            FpPrint *p = g_ptr_array_index(ld.prints, i);
            if ((bio_finger_t)fp_print_get_finger(p) == finger) {
                target = g_object_ref(p);
                break;
            }
        }
        g_ptr_array_unref(ld.prints);
    }

    if (!target) {
        return BIO_ERR_NOT_FOUND;
    }

    /* Delete the print */
    GMainLoop *loop2 = g_main_loop_new(NULL, FALSE);
    fp_del_data_t dd = { .loop = loop2, .result = BIO_ERR_INTERNAL };

    fp_device_delete_print(dev->fp_dev, target, NULL, fp_on_delete_done, &dd);
    g_main_loop_run(loop2);
    g_main_loop_unref(loop2);

    g_object_unref(target);

    BIO_INFO("Deleted fingerprint: finger=%s", bio_finger_str(finger));
    return dd.result;
}

int bio_fp_delete_all_prints(bio_fp_device_t *dev)
{
    if (!dev) return BIO_ERR_INVALID_PARAM;

    if (!dev->info.has_storage) {
        return BIO_ERR_FP_DELETE;
    }

    /* Use fp_device_clear_storage if supported */
    GMainLoop *loop = g_main_loop_new(NULL, FALSE);
    fp_del_data_t cd = { .loop = loop, .result = BIO_ERR_INTERNAL };

    fp_device_clear_storage(dev->fp_dev, NULL, fp_on_clear_done, &cd);
    g_main_loop_run(loop);
    g_main_loop_unref(loop);

    if (cd.result == BIO_OK)
        BIO_INFO("All fingerprints deleted from device");

    return cd.result;
}

/* ── Identification (1:N) ────────────────────────────────────── */

int bio_fp_identify(bio_fp_device_t *dev,
                    const uint8_t *const *gallery,
                    const size_t *gallery_lens,
                    size_t gallery_size,
                    bio_fp_identify_result_t *result)
{
    if (!dev || !dev->is_open || !result)
        return BIO_ERR_INVALID_PARAM;
    if (gallery_size == 0 || !gallery || !gallery_lens)
        return BIO_ERR_INVALID_PARAM;

    if (!dev->info.supports_identify) {
        BIO_ERROR("Device does not support identification (1:N)");
        return BIO_ERR_FP_VERIFY;
    }

    /* Check rate limit */
    int remaining;
    int rc = bio_fp_check_rate_limit(dev, &remaining);
    if (rc == BIO_ERR_FP_RATE_LIMIT) {
        BIO_WARN("Identification rate-limited: %d seconds remaining", remaining);
        return BIO_ERR_FP_RATE_LIMIT;
    }

    /* Deserialize gallery prints into a GPtrArray */
    GPtrArray *prints = g_ptr_array_new_with_free_func(g_object_unref);

    for (size_t i = 0; i < gallery_size; i++) {
        GError *err = NULL;
        FpPrint *p = fp_print_deserialize(gallery[i], gallery_lens[i], &err);
        if (!p || err) {
            BIO_WARN("Failed to deserialize gallery print %zu: %s",
                     i, err ? err->message : "unknown");
            if (err) g_error_free(err);
            continue;
        }
        g_ptr_array_add(prints, p);
    }

    if (prints->len == 0) {
        g_ptr_array_unref(prints);
        return BIO_ERR_INVALID_PARAM;
    }

    /* Async → sync bridge */
    GMainLoop *loop = g_main_loop_new(NULL, FALSE);
    fp_ident_data_t id = { .loop = loop, .result = BIO_ERR_INTERNAL, .match_print = NULL };

    fp_device_identify(dev->fp_dev, prints, NULL, NULL, NULL, NULL,
                        fp_on_identify_done, &id);

    g_main_loop_run(loop);
    g_main_loop_unref(loop);

    memset(result, 0, sizeof(*result));
    result->match_score = -1;

    if (id.result == BIO_OK && id.match_print) {
        result->matched = true;
        result->matched_finger = (bio_finger_t)fp_print_get_finger(id.match_print);
        bio_fp_reset_rate_limit(dev);
        g_ptr_array_unref(prints);
        BIO_DEBUG("Identify: matched finger %s",
                  bio_finger_str(result->matched_finger));
        return BIO_OK;
    }

    /* No match */
    result->matched = false;
    bio_fp_record_failure(dev);
    g_ptr_array_unref(prints);
    BIO_DEBUG("Identify: no match");
    return BIO_ERR_FP_NO_MATCH;
}

/* ── Enhanced enrollment with result ─────────────────────────── */

int bio_fp_enroll_ex(bio_fp_device_t *dev,
                     bio_finger_t finger,
                     bio_fp_enroll_cb_t callback,
                     void *user_data,
                     uint8_t *out_data, size_t *out_len,
                     bio_fp_enrollment_result_t *result)
{
    if (!result)
        return BIO_ERR_INVALID_PARAM;

    memset(result, 0, sizeof(*result));
    result->quality_score = -1;
    result->finger = finger;
    result->stages_total = dev ? dev->info.nr_enroll_stages : 0;

    int rc = bio_fp_enroll(dev, finger, callback, user_data, out_data, out_len);

    if (rc == BIO_OK) {
        result->status = BIO_FP_ENROLL_COMPLETE;
        result->stages_completed = result->stages_total;
        result->print_data_len = *out_len;
    } else {
        result->status = BIO_FP_ENROLL_FAILED;
    }

    return rc;
}
