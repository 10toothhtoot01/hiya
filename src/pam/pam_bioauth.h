/*
 * pam_bioauth.h — PAM Module for BioAuth
 *
 * Copyright (C) 2024 BioAuth Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This PAM module authenticates users via the BioAuth D-Bus daemon.
 * It connects to org.bioauth.Manager, creates a session, triggers
 * fingerprint verification, and returns PAM_SUCCESS or PAM_AUTH_ERR.
 *
 * Module options (in pam.d config line):
 *   timeout=N      — verification timeout in seconds (default: 30)
 *   debug          — enable debug logging to syslog
 *   try_first      — return PAM_AUTH_ERR instead of PAM_IGNORE on failure
 *   fallback       — if no fingerprint device, return PAM_IGNORE (default)
 */

#ifndef BIO_PAM_BIOAUTH_H
#define BIO_PAM_BIOAUTH_H

/* PAM module options */
#define PAM_BIOAUTH_DEFAULT_TIMEOUT   30
#define PAM_BIOAUTH_MAX_TIMEOUT       120

/* Module configuration parsed from PAM config line */
typedef struct {
    int   timeout_sec;
    bool  debug;
    bool  try_first;     /* true: fail with AUTH_ERR; false: return IGNORE */
    bool  fallback;      /* true: return IGNORE if no device */
} pam_bioauth_config_t;

#endif /* BIO_PAM_BIOAUTH_H */
