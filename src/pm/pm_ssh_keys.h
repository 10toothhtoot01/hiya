/*
 * pm_ssh_keys.h - SSH key credential management
 *
 * Copyright (C) 2026 BioAuth Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef PM_SSH_KEYS_H
#define PM_SSH_KEYS_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "pm/pm_errors.h"

#ifdef __cplusplus
extern "C"
{
#endif

    /* SSH key types */
    typedef enum
    {
        PM_SSH_KEY_RSA = 0,
        PM_SSH_KEY_ECDSA_P256 = 1,
        PM_SSH_KEY_ECDSA_P384 = 2,
        PM_SSH_KEY_ECDSA_P521 = 3,
        PM_SSH_KEY_ED25519 = 4,
        PM_SSH_KEY_DSA = 5,
    } pm_ssh_key_type_t;

    /* SSH key entry */
    typedef struct
    {
        char *name;                 /* User-friendly name */
        char *hostname;             /* Target hostname/IP */
        char *username;             /* SSH username */
        uint16_t port;              /* SSH port (default 22) */
        pm_ssh_key_type_t key_type; /* Key algorithm type */
        uint8_t *private_key;       /* PEM-encoded private key */
        size_t private_key_len;
        uint8_t *public_key; /* OpenSSH public key format */
        size_t public_key_len;
        char *passphrase;    /* Private key passphrase (if any) */
        bool use_agent;      /* Use SSH agent forwarding */
        char *identity_file; /* Path to identity file */
        char *notes;         /* User notes */
        uint64_t last_used;  /* Last used timestamp */
        uint32_t use_count;  /* Usage counter */
    } pm_ssh_key_t;

    /**
     * Create a new SSH key entry.
     *
     * @param ssh_key   Output: new SSH key structure (caller must free with pm_ssh_key_free)
     * @return PM_OK on success, PM_ERR_* on failure
     */
    pm_error_t pm_ssh_key_create(pm_ssh_key_t **ssh_key);

    /**
     * Free SSH key entry and securely wipe sensitive data.
     */
    void pm_ssh_key_free(pm_ssh_key_t *ssh_key);

    /**
     * Set SSH key basic information.
     */
    pm_error_t pm_ssh_key_set_info(pm_ssh_key_t *ssh_key,
                                   const char *name,
                                   const char *hostname,
                                   const char *username,
                                   uint16_t port);

    /**
     * Set SSH key pair (PEM private key + OpenSSH public key).
     */
    pm_error_t pm_ssh_key_set_keypair(pm_ssh_key_t *ssh_key,
                                      pm_ssh_key_type_t key_type,
                                      const uint8_t *private_key, size_t private_key_len,
                                      const uint8_t *public_key, size_t public_key_len,
                                      const char *passphrase);

    /**
     * Generate new SSH key pair of specified type and bits.
     *
     * @param key_type      SSH key algorithm
     * @param bits         Key size in bits (2048, 3072, 4096 for RSA; 256, 384, 521 for ECDSA)
     * @param passphrase   Passphrase to encrypt private key (NULL for no passphrase)
     * @param private_key  Output: PEM-encoded private key (caller must free)
     * @param private_len  Output: private key length
     * @param public_key   Output: OpenSSH public key format (caller must free)
     * @param public_len   Output: public key length
     * @return PM_OK on success, PM_ERR_* on failure
     */
    pm_error_t pm_ssh_key_generate(pm_ssh_key_type_t key_type,
                                   uint32_t bits,
                                   const char *passphrase,
                                   uint8_t **private_key, size_t *private_len,
                                   uint8_t **public_key, size_t *public_len);

    /**
     * Import SSH private key from PEM format.
     *
     * @param pem_data      PEM-encoded private key
     * @param pem_len       PEM data length
     * @param passphrase    Private key passphrase (NULL if none)
     * @param key_type      Output: detected key type
     * @param public_key    Output: derived OpenSSH public key (caller must free)
     * @param public_len    Output: public key length
     * @return PM_OK on success, PM_ERR_* on failure
     */
    pm_error_t pm_ssh_key_import_pem(const uint8_t *pem_data, size_t pem_len,
                                     const char *passphrase,
                                     pm_ssh_key_type_t *key_type,
                                     uint8_t **public_key, size_t *public_len);

    /**
     * Export SSH private key to PEM format.
     */
    pm_error_t pm_ssh_key_export_pem(const pm_ssh_key_t *ssh_key,
                                     uint8_t **pem_data, size_t *pem_len);

    /**
     * Get OpenSSH public key in authorized_keys format.
     */
    pm_error_t pm_ssh_key_get_authorized_key(const pm_ssh_key_t *ssh_key,
                                             char **authorized_key);

    /**
     * Get SSH connection string for this key.
     * Format: ssh [-i identity_file] [-p port] username@hostname
     */
    pm_error_t pm_ssh_key_get_connection_string(const pm_ssh_key_t *ssh_key,
                                                char **connection_string);

    /**
     * Validate SSH key pair consistency.
     */
    pm_error_t pm_ssh_key_validate(const pm_ssh_key_t *ssh_key);

    /**
     * Update SSH key usage statistics.
     */
    pm_error_t pm_ssh_key_update_usage(pm_ssh_key_t *ssh_key);

    /**
     * SSH key fingerprint calculation (SHA256 format).
     */
    pm_error_t pm_ssh_key_fingerprint(const pm_ssh_key_t *ssh_key,
                                      char **fingerprint);

#ifdef __cplusplus
}
#endif

#endif /* PM_SSH_KEYS_H */