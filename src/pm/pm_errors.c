/*
 * pm_errors.c - Password manager error strings
 *
 * Copyright (C) 2026 Hiya Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "pm/pm_errors.h"

const char *pm_error_str(pm_error_t err)
{
    switch (err)
    {
    case PM_OK:
        return "OK";
    case PM_ERR_INVALID_PARAM:
        return "Invalid parameter";
    case PM_ERR_NOMEM:
        return "Out of memory";
    case PM_ERR_IO:
        return "I/O error";
    case PM_ERR_TIMEOUT:
        return "Timeout";
    case PM_ERR_NOT_FOUND:
        return "Not found";
    case PM_ERR_ALREADY_EXISTS:
        return "Already exists";
    case PM_ERR_PERMISSION:
        return "Permission denied";
    case PM_ERR_INTERNAL:
        return "Internal error";
    case PM_ERR_UNSUPPORTED:
        return "Unsupported";

    case PM_ERR_LOCKED:
        return "Vault is locked";
    case PM_ERR_DENIED:
        return "Operation denied";
    case PM_ERR_POLICY:
        return "Policy violation";
    case PM_ERR_STATE:
        return "Invalid state";

    case PM_ERR_FORMAT:
        return "Invalid vault format";
    case PM_ERR_FORMAT_MAGIC:
        return "Invalid vault magic";
    case PM_ERR_FORMAT_VERSION:
        return "Unsupported vault format version";
    case PM_ERR_FORMAT_INTEGRITY:
        return "Vault integrity check failed";
    case PM_ERR_SERIALIZE:
        return "Serialization failed";
    case PM_ERR_DESERIALIZE:
        return "Deserialization failed";

    case PM_ERR_CRYPTO:
        return "Cryptographic error";
    case PM_ERR_KDF:
        return "Key derivation failed";
    case PM_ERR_AEAD_TAG:
        return "AEAD authentication tag mismatch";
    case PM_ERR_KEY_INVALID:
        return "Invalid key material";
    case PM_ERR_KEY_UNAVAILABLE:
        return "Key unavailable";
    case PM_ERR_MLOCK_FAILED:
        return "mlock failed";

    case PM_ERR_DBUS:
        return "D-Bus error";
    case PM_ERR_TPM:
        return "TPM error";
    case PM_ERR_BIO:
        return "Biometric subsystem error";
    case PM_ERR_BROWSER:
        return "Browser integration error";
    case PM_ERR_NETWORK:
        return "Network error";
    case PM_ERR_HIBP_UNAVAILABLE:
        return "HIBP service unavailable";

    default:
        return "Unknown PM error";
    }
}
