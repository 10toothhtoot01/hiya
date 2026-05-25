/*
 * bio_fprintd_compat.h — fprintd-compatible D-Bus API Shim
 *
 * Copyright (C) 2025 BioAuth Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Provides a compatibility layer that exposes the standard fprintd
 * D-Bus interfaces (net.reactivated.Fprint.Manager and
 * net.reactivated.Fprint.Device) on top of the BioAuth daemon.
 *
 * This enables GDM, GNOME Settings, SDDM, KDE System Settings,
 * and any other application that uses the fprintd API to work
 * transparently with BioAuth.
 *
 * D-Bus interfaces implemented:
 *   net.reactivated.Fprint.Manager
 *     - GetDefaultDevice()  → o (object_path)
 *     - GetDevices()        → ao (array of object paths)
 *
 *   net.reactivated.Fprint.Device
 *     - Claim(s user)
 *     - Release()
 *     - EnrollStart(s finger)
 *     - EnrollStop()
 *     - VerifyStart(s finger)
 *     - VerifyStop()
 *     - DeleteEnrolledFingers(s user)
 *     - DeleteEnrolledFingers2()
 *     - ListEnrolledFingers(s user) → as
 *
 *     Signals:
 *     - EnrollStatus(s result, b done)
 *     - VerifyStatus(s result, b done)
 *     - VerifyFingerSelected(s finger)
 *
 *     Properties:
 *     - scan-type: s ("swipe" | "press")
 *     - num-enroll-stages: i
 *     - finger-present: b
 *     - finger-needed: b
 *
 * The shim is loaded by biometric-authd and runs within the same
 * process, forwarding calls to the native BioAuth internal API.
 *
 * References:
 *   https://fprint.freedesktop.org/fprintd-dev/
 *   https://gitlab.freedesktop.org/libfprint/fprintd
 */

#ifndef BIO_FPRINTD_COMPAT_H
#define BIO_FPRINTD_COMPAT_H

#include <gio/gio.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C"
{
#endif

    /* Forward declaration – the daemon context */
    struct bio_daemon;

    /*
     * fprintd device state (mirrors the internal state machine).
     */
    typedef enum
    {
        FPRINTD_STATE_IDLE,
        FPRINTD_STATE_CLAIMED,
        FPRINTD_STATE_ENROLLING,
        FPRINTD_STATE_VERIFYING,
    } bio_fprintd_device_state_t;

    /*
     * Per-device fprintd compatibility context.
     */
    typedef struct
    {
        char object_path[128]; /* /net/reactivated/Fprint/Device/0 */
        bio_fprintd_device_state_t state;
        char claimed_by[64];       /* user who claimed the device */
        char claimed_sender[256];  /* D-Bus unique name of claimer (C3 fix) */
        char enroll_finger[48];    /* finger being enrolled     */
        guint reg_id;              /* D-Bus registration id     */
        guint name_watch_id;       /* NameOwnerChanged subscription */
        GCancellable *cancellable; /* For async verify/enroll   */
    } bio_fprintd_device_t;

    /*
     * Main fprintd compatibility context.
     */
    typedef struct
    {
        GDBusConnection *bus;            /* System bus connection          */
        struct bio_daemon *daemon;       /* Parent BioAuth daemon          */
        guint manager_reg;               /* Manager registration id        */
        bio_fprintd_device_t devices[4]; /* Virtual fprintd devices        */
        int num_devices;                 /* Number of active devices       */
        guint name_id;                   /* Name owner id                  */
        bool name_owned;                 /* True once name is acquired     */
        GDBusNodeInfo *manager_info;     /* Kept alive for registered obj  */
        GDBusNodeInfo *device_info;      /* Kept alive for registered obj  */
    } bio_fprintd_compat_t;

    /*
     * Initialise the fprintd compatibility layer.
     * Registers on the D-Bus system bus as net.reactivated.Fprint.
     *
     * @param compat  Compatibility context (caller-allocated, zeroed)
     * @param bus     Active system bus connection
     * @param daemon  The parent BioAuth daemon context
     * @return 0 on success, negative errno on failure
     */
    int bio_fprintd_compat_init(bio_fprintd_compat_t *compat,
                                GDBusConnection *bus,
                                struct bio_daemon *daemon);

    /*
     * Shut down the fprintd compatibility layer.
     * Unregisters all D-Bus objects and releases the bus name.
     */
    void bio_fprintd_compat_cleanup(bio_fprintd_compat_t *compat);

#ifdef __cplusplus
}
#endif

#endif /* BIO_FPRINTD_COMPAT_H */
