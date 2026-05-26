/*
 * pm_errors.h - Password manager error codes
 *
 * Copyright (C) 2026 Hiya Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef PM_ERRORS_H
#define PM_ERRORS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

    typedef enum
    {
        PM_OK = 0,

        /* Generic errors (-1 .. -99) */
        PM_ERR_INVALID_PARAM = -1,
        PM_ERR_NOMEM = -2,
        PM_ERR_IO = -3,
        PM_ERR_TIMEOUT = -4,
        PM_ERR_NOT_FOUND = -5,
        PM_ERR_ALREADY_EXISTS = -6,
        PM_ERR_PERMISSION = -7,
        PM_ERR_INTERNAL = -8,
        PM_ERR_UNSUPPORTED = -9,

        /* Vault state / policy errors (-100 .. -199) */
        PM_ERR_LOCKED = -100,
        PM_ERR_DENIED = -101,
        PM_ERR_POLICY = -102,
        PM_ERR_STATE = -103,

        /* Format / serialization errors (-200 .. -299) */
        PM_ERR_FORMAT = -200,
        PM_ERR_FORMAT_MAGIC = -201,
        PM_ERR_FORMAT_VERSION = -202,
        PM_ERR_FORMAT_INTEGRITY = -203,
        PM_ERR_SERIALIZE = -204,
        PM_ERR_DESERIALIZE = -205,

        /* Crypto / key errors (-300 .. -399) */
        PM_ERR_CRYPTO = -300,
        PM_ERR_KDF = -301,
        PM_ERR_AEAD_TAG = -302,
        PM_ERR_KEY_INVALID = -303,
        PM_ERR_KEY_UNAVAILABLE = -304,
        PM_ERR_MLOCK_FAILED = -305,

        /* Integration errors (-400 .. -499) */
        PM_ERR_DBUS = -400,
        PM_ERR_TPM = -401,
        PM_ERR_BIO = -402,
        PM_ERR_BROWSER = -403,
        PM_ERR_NETWORK = -404,
        PM_ERR_HIBP_UNAVAILABLE = -405,

    } pm_error_t;

    const char *pm_error_str(pm_error_t err);

#ifdef __cplusplus
}
#endif

#endif /* PM_ERRORS_H */
