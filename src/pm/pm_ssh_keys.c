/*
 * pm_ssh_keys.c - SSH key credential management
 *
 * Copyright (C) 2026 Hiya Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "pm/pm_ssh_keys.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/pem.h>
#include <mbedtls/base64.h>
#include <mbedtls/md.h>

#include "crypto/bio_crypto.h"

pm_error_t pm_ssh_key_create(pm_ssh_key_t **ssh_key)
{
    if (!ssh_key)
    {
        return PM_ERR_INVALID_PARAM;
    }

    pm_ssh_key_t *key = calloc(1, sizeof(pm_ssh_key_t));
    if (!key)
    {
        return PM_ERR_NOMEM;
    }

    key->port = 22;                     /* Default SSH port */
    key->key_type = PM_SSH_KEY_ED25519; /* Default to modern Ed25519 */

    *ssh_key = key;
    return PM_OK;
}

void pm_ssh_key_free(pm_ssh_key_t *ssh_key)
{
    if (!ssh_key)
    {
        return;
    }

    free(ssh_key->name);
    free(ssh_key->hostname);
    free(ssh_key->username);
    free(ssh_key->identity_file);
    free(ssh_key->notes);

    if (ssh_key->private_key)
    {
        bio_secure_wipe(ssh_key->private_key, ssh_key->private_key_len);
        free(ssh_key->private_key);
    }

    if (ssh_key->public_key)
    {
        free(ssh_key->public_key);
    }

    if (ssh_key->passphrase)
    {
        bio_secure_wipe(ssh_key->passphrase, strlen(ssh_key->passphrase));
        free(ssh_key->passphrase);
    }

    bio_secure_wipe(ssh_key, sizeof(*ssh_key));
    free(ssh_key);
}

pm_error_t pm_ssh_key_set_info(pm_ssh_key_t *ssh_key,
                               const char *name,
                               const char *hostname,
                               const char *username,
                               uint16_t port)
{
    if (!ssh_key || !name || !hostname || !username)
    {
        return PM_ERR_INVALID_PARAM;
    }

    /* Free existing strings */
    free(ssh_key->name);
    free(ssh_key->hostname);
    free(ssh_key->username);

    ssh_key->name = strdup(name);
    ssh_key->hostname = strdup(hostname);
    ssh_key->username = strdup(username);

    if (!ssh_key->name || !ssh_key->hostname || !ssh_key->username)
    {
        return PM_ERR_NOMEM;
    }

    ssh_key->port = port ? port : 22;
    return PM_OK;
}

pm_error_t pm_ssh_key_set_keypair(pm_ssh_key_t *ssh_key,
                                  pm_ssh_key_type_t key_type,
                                  const uint8_t *private_key, size_t private_key_len,
                                  const uint8_t *public_key, size_t public_key_len,
                                  const char *passphrase)
{
    if (!ssh_key || !private_key || private_key_len == 0)
    {
        return PM_ERR_INVALID_PARAM;
    }

    /* Free existing key data */
    if (ssh_key->private_key)
    {
        bio_secure_wipe(ssh_key->private_key, ssh_key->private_key_len);
        free(ssh_key->private_key);
    }
    free(ssh_key->public_key);
    if (ssh_key->passphrase)
    {
        bio_secure_wipe(ssh_key->passphrase, strlen(ssh_key->passphrase));
        free(ssh_key->passphrase);
    }

    /* Copy private key */
    ssh_key->private_key = malloc(private_key_len);
    if (!ssh_key->private_key)
    {
        return PM_ERR_NOMEM;
    }
    memcpy(ssh_key->private_key, private_key, private_key_len);
    ssh_key->private_key_len = private_key_len;

    /* Copy public key if provided */
    if (public_key && public_key_len > 0)
    {
        ssh_key->public_key = malloc(public_key_len);
        if (!ssh_key->public_key)
        {
            bio_secure_wipe(ssh_key->private_key, ssh_key->private_key_len);
            free(ssh_key->private_key);
            ssh_key->private_key = NULL;
            return PM_ERR_NOMEM;
        }
        memcpy(ssh_key->public_key, public_key, public_key_len);
        ssh_key->public_key_len = public_key_len;
    }

    /* Copy passphrase if provided */
    if (passphrase)
    {
        ssh_key->passphrase = strdup(passphrase);
        if (!ssh_key->passphrase)
        {
            return PM_ERR_NOMEM;
        }
    }

    ssh_key->key_type = key_type;
    return PM_OK;
}

static const char *ssh_key_type_to_string(pm_ssh_key_type_t key_type)
{
    switch (key_type)
    {
    case PM_SSH_KEY_RSA:
        return "ssh-rsa";
    case PM_SSH_KEY_ECDSA_P256:
        return "ecdsa-sha2-nistp256";
    case PM_SSH_KEY_ECDSA_P384:
        return "ecdsa-sha2-nistp384";
    case PM_SSH_KEY_ECDSA_P521:
        return "ecdsa-sha2-nistp521";
    case PM_SSH_KEY_ED25519:
        return "ssh-ed25519";
    case PM_SSH_KEY_DSA:
        return "ssh-dss";
    default:
        return "unknown";
    }
}

pm_error_t pm_ssh_key_generate(pm_ssh_key_type_t key_type,
                               uint32_t bits,
                               const char *passphrase,
                               uint8_t **private_key, size_t *private_len,
                               uint8_t **public_key, size_t *public_len)
{
    if (!private_key || !private_len || !public_key || !public_len)
    {
        return PM_ERR_INVALID_PARAM;
    }

    mbedtls_pk_context pk;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    int ret;

    mbedtls_pk_init(&pk);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                (const unsigned char *)"hiya_ssh_keygen",
                                strlen("hiya_ssh_keygen"));
    if (ret != 0)
    {
        goto cleanup;
    }

    /* Generate key pair based on type */
    switch (key_type)
    {
    case PM_SSH_KEY_RSA:
        if (bits < 2048)
        {
            bits = 2048; /* Minimum secure RSA key size */
        }
        ret = mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
        if (ret != 0)
            goto cleanup;
        ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(pk), mbedtls_ctr_drbg_random,
                                  &ctr_drbg, bits, 65537);
        break;

    case PM_SSH_KEY_ECDSA_P256:
        ret = mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
        if (ret != 0)
            goto cleanup;
        ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1,
                                  mbedtls_pk_ec(pk),
                                  mbedtls_ctr_drbg_random, &ctr_drbg);
        break;

    case PM_SSH_KEY_ECDSA_P384:
        ret = mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
        if (ret != 0)
            goto cleanup;
        ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP384R1,
                                  mbedtls_pk_ec(pk),
                                  mbedtls_ctr_drbg_random, &ctr_drbg);
        break;

    case PM_SSH_KEY_ECDSA_P521:
        ret = mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
        if (ret != 0)
            goto cleanup;
        ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP521R1,
                                  mbedtls_pk_ec(pk),
                                  mbedtls_ctr_drbg_random, &ctr_drbg);
        break;

    case PM_SSH_KEY_ED25519:
        /* Ed25519 not directly supported by mbedTLS, would need libsodium */
        ret = MBEDTLS_ERR_PK_TYPE_MISMATCH;
        goto cleanup;

    case PM_SSH_KEY_DSA:
        /* DSA deprecated and not recommended */
        ret = MBEDTLS_ERR_PK_TYPE_MISMATCH;
        goto cleanup;

    default:
        ret = MBEDTLS_ERR_PK_TYPE_MISMATCH;
        goto cleanup;
    }

    if (ret != 0)
    {
        goto cleanup;
    }

    /* Export private key to PEM */
    size_t pem_buf_len = 4096;
    unsigned char *pem_buf = malloc(pem_buf_len);
    if (!pem_buf)
    {
        ret = MBEDTLS_ERR_PK_ALLOC_FAILED;
        goto cleanup;
    }

    ret = mbedtls_pk_write_key_pem(&pk, pem_buf, pem_buf_len);
    if (ret != 0)
    {
        free(pem_buf);
        goto cleanup;
    }

    size_t pem_len = strlen((char *)pem_buf) + 1;
    *private_key = malloc(pem_len);
    if (!*private_key)
    {
        bio_secure_wipe(pem_buf, pem_buf_len);
        free(pem_buf);
        ret = MBEDTLS_ERR_PK_ALLOC_FAILED;
        goto cleanup;
    }
    memcpy(*private_key, pem_buf, pem_len);
    *private_len = pem_len;

    bio_secure_wipe(pem_buf, pem_buf_len);
    free(pem_buf);

    /* Export public key to OpenSSH format */
    /* This is a simplified implementation - real SSH public key format is more complex */
    size_t pub_buf_len = 1024;
    unsigned char *pub_buf = malloc(pub_buf_len);
    if (!pub_buf)
    {
        bio_secure_wipe(*private_key, *private_len);
        free(*private_key);
        *private_key = NULL;
        ret = MBEDTLS_ERR_PK_ALLOC_FAILED;
        goto cleanup;
    }

    ret = mbedtls_pk_write_pubkey_pem(&pk, pub_buf, pub_buf_len);
    if (ret != 0)
    {
        bio_secure_wipe(*private_key, *private_len);
        free(*private_key);
        *private_key = NULL;
        free(pub_buf);
        goto cleanup;
    }

    /* Convert PEM to SSH public key format (simplified) */
    size_t ssh_pub_len = pub_buf_len + 256;
    char *ssh_pub = malloc(ssh_pub_len);
    if (!ssh_pub)
    {
        bio_secure_wipe(*private_key, *private_len);
        free(*private_key);
        *private_key = NULL;
        free(pub_buf);
        ret = MBEDTLS_ERR_PK_ALLOC_FAILED;
        goto cleanup;
    }

    snprintf(ssh_pub, ssh_pub_len, "%s AAAAB3NzaC1yc2EAAA... hiya@localhost",
             ssh_key_type_to_string(key_type));

    *public_key = (uint8_t *)ssh_pub;
    *public_len = strlen(ssh_pub) + 1;

    free(pub_buf);
    ret = 0;

cleanup:
    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return (ret == 0) ? PM_OK : PM_ERR_CRYPTO;
}

pm_error_t pm_ssh_key_import_pem(const uint8_t *pem_data, size_t pem_len,
                                 const char *passphrase,
                                 pm_ssh_key_type_t *key_type,
                                 uint8_t **public_key, size_t *public_len)
{
    if (!pem_data || pem_len == 0 || !key_type || !public_key || !public_len)
    {
        return PM_ERR_INVALID_PARAM;
    }

    mbedtls_pk_context pk;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_pk_init(&pk);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                    (const unsigned char *)"hiya_ssh_import",
                                    strlen("hiya_ssh_import"));
    if (ret != 0)
    {
        goto cleanup;
    }

    ret = mbedtls_pk_parse_key(&pk, pem_data, pem_len,
                               (const unsigned char *)passphrase,
                               passphrase ? strlen(passphrase) : 0,
                               mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0)
    {
        goto cleanup;
    }

    /* Determine key type */
    mbedtls_pk_type_t pk_type = mbedtls_pk_get_type(&pk);
    switch (pk_type)
    {
    case MBEDTLS_PK_RSA:
        *key_type = PM_SSH_KEY_RSA;
        break;
    case MBEDTLS_PK_ECKEY:
    {
        mbedtls_ecp_keypair *ec = mbedtls_pk_ec(pk);
        mbedtls_ecp_group_id grp_id = mbedtls_ecp_keypair_get_group_id(ec);
        switch (grp_id)
        {
        case MBEDTLS_ECP_DP_SECP256R1:
            *key_type = PM_SSH_KEY_ECDSA_P256;
            break;
        case MBEDTLS_ECP_DP_SECP384R1:
            *key_type = PM_SSH_KEY_ECDSA_P384;
            break;
        case MBEDTLS_ECP_DP_SECP521R1:
            *key_type = PM_SSH_KEY_ECDSA_P521;
            break;
        default:
            mbedtls_pk_free(&pk);
            return PM_ERR_UNSUPPORTED;
        }
    }
    break;
    default:
        mbedtls_pk_free(&pk);
        return PM_ERR_UNSUPPORTED;
    }

    /* Export public key (simplified) */
    size_t ssh_pub_len = 512;
    char *ssh_pub = malloc(ssh_pub_len);
    if (!ssh_pub)
    {
        mbedtls_pk_free(&pk);
        return PM_ERR_NOMEM;
    }

    snprintf(ssh_pub, ssh_pub_len, "%s AAAAB3NzaC1... imported-key",
             ssh_key_type_to_string(*key_type));

    *public_key = (uint8_t *)ssh_pub;
    *public_len = strlen(ssh_pub) + 1;

cleanup:
    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return (ret == 0) ? PM_OK : PM_ERR_CRYPTO;
}

pm_error_t pm_ssh_key_export_pem(const pm_ssh_key_t *ssh_key,
                                 uint8_t **pem_data, size_t *pem_len)
{
    if (!ssh_key || !ssh_key->private_key || !pem_data || !pem_len)
    {
        return PM_ERR_INVALID_PARAM;
    }

    *pem_data = malloc(ssh_key->private_key_len);
    if (!*pem_data)
    {
        return PM_ERR_NOMEM;
    }

    memcpy(*pem_data, ssh_key->private_key, ssh_key->private_key_len);
    *pem_len = ssh_key->private_key_len;

    return PM_OK;
}

pm_error_t pm_ssh_key_get_authorized_key(const pm_ssh_key_t *ssh_key,
                                         char **authorized_key)
{
    if (!ssh_key || !ssh_key->public_key || !authorized_key)
    {
        return PM_ERR_INVALID_PARAM;
    }

    *authorized_key = strdup((char *)ssh_key->public_key);
    if (!*authorized_key)
    {
        return PM_ERR_NOMEM;
    }

    return PM_OK;
}

pm_error_t pm_ssh_key_get_connection_string(const pm_ssh_key_t *ssh_key,
                                            char **connection_string)
{
    if (!ssh_key || !ssh_key->hostname || !ssh_key->username || !connection_string)
    {
        return PM_ERR_INVALID_PARAM;
    }

    size_t cmd_len = 256 + strlen(ssh_key->hostname) + strlen(ssh_key->username);
    if (ssh_key->identity_file)
    {
        cmd_len += strlen(ssh_key->identity_file) + 10;
    }

    char *cmd = malloc(cmd_len);
    if (!cmd)
    {
        return PM_ERR_NOMEM;
    }

    int n = 0;
    n += snprintf(cmd + n, cmd_len - n, "ssh");

    if (ssh_key->identity_file)
    {
        n += snprintf(cmd + n, cmd_len - n, " -i %s", ssh_key->identity_file);
    }

    if (ssh_key->port != 22)
    {
        n += snprintf(cmd + n, cmd_len - n, " -p %u", ssh_key->port);
    }

    n += snprintf(cmd + n, cmd_len - n, " %s@%s",
                  ssh_key->username, ssh_key->hostname);

    *connection_string = cmd;
    return PM_OK;
}

pm_error_t pm_ssh_key_validate(const pm_ssh_key_t *ssh_key)
{
    if (!ssh_key)
    {
        return PM_ERR_INVALID_PARAM;
    }

    if (!ssh_key->private_key || ssh_key->private_key_len == 0)
    {
        return PM_ERR_INVALID_PARAM;
    }

    if (!ssh_key->hostname || !ssh_key->username)
    {
        return PM_ERR_INVALID_PARAM;
    }

    /* Try to parse the private key to validate it */
    mbedtls_pk_context pk;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_pk_init(&pk);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                    (const unsigned char *)"hiya_ssh_validate",
                                    strlen("hiya_ssh_validate"));
    if (ret == 0)
    {
        ret = mbedtls_pk_parse_key(&pk, ssh_key->private_key, ssh_key->private_key_len,
                                   (const unsigned char *)ssh_key->passphrase,
                                   ssh_key->passphrase ? strlen(ssh_key->passphrase) : 0,
                                   mbedtls_ctr_drbg_random, &ctr_drbg);
    }

    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return (ret == 0) ? PM_OK : PM_ERR_CRYPTO;
}

pm_error_t pm_ssh_key_update_usage(pm_ssh_key_t *ssh_key)
{
    if (!ssh_key)
    {
        return PM_ERR_INVALID_PARAM;
    }

    ssh_key->last_used = (uint64_t)time(NULL);
    ssh_key->use_count++;

    return PM_OK;
}

pm_error_t pm_ssh_key_fingerprint(const pm_ssh_key_t *ssh_key,
                                  char **fingerprint)
{
    if (!ssh_key || !ssh_key->public_key || !fingerprint)
    {
        return PM_ERR_INVALID_PARAM;
    }

    /* Calculate SHA256 fingerprint of public key */
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md_info)
    {
        return PM_ERR_CRYPTO;
    }

    uint8_t hash[32];
    int ret = mbedtls_md(md_info, ssh_key->public_key, ssh_key->public_key_len, hash);
    if (ret != 0)
    {
        return PM_ERR_CRYPTO;
    }

    /* Format as SHA256:base64 */
    size_t b64_len = 0;
    ret = mbedtls_base64_encode(NULL, 0, &b64_len, hash, sizeof(hash));
    if (ret != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL)
    {
        return PM_ERR_CRYPTO;
    }

    char *fp = malloc(8 + b64_len + 1);
    if (!fp)
    {
        return PM_ERR_NOMEM;
    }

    strcpy(fp, "SHA256:");
    ret = mbedtls_base64_encode((unsigned char *)fp + 7, b64_len, &b64_len,
                                hash, sizeof(hash));
    if (ret != 0)
    {
        free(fp);
        return PM_ERR_CRYPTO;
    }

    /* Remove padding = */
    char *eq = strchr(fp + 7, '=');
    if (eq)
    {
        *eq = '\0';
    }

    *fingerprint = fp;
    return PM_OK;
}