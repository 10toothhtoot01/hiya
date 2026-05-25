/*
 * bioauth_config.c — BioAuth Configuration Tool
 *
 * Copyright (C) 2024 BioAuth Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * CLI tool for viewing and modifying BioAuth configuration.
 *
 * Usage:
 *   bioauth-config [COMMAND] [OPTIONS]
 *
 * Commands:
 *   show                Show current configuration
 *   get KEY             Get a specific config value
 *   set KEY VALUE       Set a config value (root only)
 *   status              Show daemon status and device info
 *   reset-config        Reset to default configuration (root only)
 *   fido2-info          Show FIDO2 authenticator info
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <getopt.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <gio/gio.h>

/* ── Default config path ─────────────────────────────────────── */

#define BIOAUTH_CONFIG_FILE "/etc/bioauth/bioauth.conf"
#define BIOAUTH_CONFIG_DIR "/etc/bioauth"

/* ── Config keys and defaults ────────────────────────────────── */

typedef struct
{
    const char *key;
    const char *default_value;
    const char *description;
} config_entry_t;

static const config_entry_t config_defaults[] = {
    {"general.log_level", "info",
     "Log level: error, warning, info, debug, trace"},
    {"general.max_sessions", "64",
     "Maximum concurrent sessions"},
    {"general.session_timeout", "300",
     "Session timeout in seconds"},
    {"general.state_dir", "/var/lib/bioauth",
     "Directory for persistent state"},
    {"general.vault_idle_timeout", "1800",
     "Vault auto-lock timeout in seconds (0 disables)"},

    {"fingerprint.max_enrollments", "10",
     "Maximum enrolled fingerprints per user"},
    {"fingerprint.rate_limit_max_attempts", "5",
     "Failed verification attempts before lockout"},
    {"fingerprint.rate_limit_lockout", "30",
     "Base lockout duration in seconds"},
    {"fingerprint.rate_limit_window", "60",
     "Rate-limit sliding window in seconds"},

    {"tpm.tpm_enabled", "true",
     "Enable TPM 2.0 integration"},
    {"tpm.require_tpm", "false",
     "Require TPM and deny plaintext fallback"},
    {"tpm.tpm_fallback_to_plaintext", "false",
     "Allow software fallback if TPM unseal fails"},
    {"tpm.tpm_pcr_binding", "false",
     "Bind TPM template unseal to PCR policy"},
    {"tpm.tpm_pcr_index", "7",
     "PCR index for TPM binding"},
    {"tpm.device", "/dev/tpmrm0",
     "TPM device path"},
    {"tpm.primary_handle", "0x81000100",
     "Persistent TPM primary handle"},

    {"fido2.enabled", "true",
     "Enable FIDO2/CTAP2 service"},
    {"fido2.storage_path", "/var/lib/bioauth/fido2",
     "FIDO2 credential storage path"},
    {"fido2.max_credentials", "64",
     "Maximum resident credentials"},

    {"pam.verify_timeout", "30",
     "PAM verification timeout in seconds"},
    {"pam.fallback", "true",
     "Allow password fallback when biometric path fails"},

    {NULL, NULL, NULL}};

static const char *normalize_cli_key(const char *key)
{
    if (!key)
        return NULL;

    if (strcmp(key, "tpm.enabled") == 0)
        return "tpm.tpm_enabled";
    if (strcmp(key, "tpm.require") == 0)
        return "tpm.require_tpm";
    if (strcmp(key, "tpm.fallback") == 0)
        return "tpm.tpm_fallback_to_plaintext";
    if (strcmp(key, "tpm.pcr_binding") == 0)
        return "tpm.tpm_pcr_binding";
    if (strcmp(key, "tpm.pcr_index") == 0)
        return "tpm.tpm_pcr_index";

    if (strcmp(key, "fingerprint.timeout") == 0)
        return "general.session_timeout";
    if (strcmp(key, "security.rate_limit") == 0)
        return "fingerprint.rate_limit_max_attempts";
    if (strcmp(key, "security.lockout_time") == 0)
        return "fingerprint.rate_limit_lockout";

    return key;
}

/* ── INI config parser/writer ────────────────────────────────── */

#define MAX_CONFIG_ENTRIES 64
#define MAX_KEY_LEN 128
#define MAX_VALUE_LEN 256

typedef struct
{
    char key[MAX_KEY_LEN];
    char value[MAX_VALUE_LEN];
} kv_pair_t;

typedef struct
{
    kv_pair_t entries[MAX_CONFIG_ENTRIES];
    int count;
    char path[256];
} config_t;

/*
 * Parse an INI-style config file.
 * Supports:
 *   [section]
 *   key = value
 *   # comments
 * Keys are stored as "section.key".
 */
static int config_load(config_t *cfg, const char *path)
{
    memset(cfg, 0, sizeof(*cfg));
    strncpy(cfg->path, path, sizeof(cfg->path) - 1);

    FILE *f = fopen(path, "r");
    if (!f)
    {
        if (errno == ENOENT)
        {
            /* No config file — will use defaults */
            return 0;
        }
        fprintf(stderr, "Error: cannot open %s: %s\n", path, strerror(errno));
        return -1;
    }

    char line[512];
    char section[64] = "";

    while (fgets(line, sizeof(line), f))
    {
        /* Strip trailing newline */
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
            line[--len] = '\0';

        /* Skip empty/comment lines */
        char *p = line;
        while (*p == ' ' || *p == '\t')
            p++;
        if (*p == '\0' || *p == '#' || *p == ';')
            continue;

        /* Section header */
        if (*p == '[')
        {
            char *end = strchr(p, ']');
            if (end)
            {
                *end = '\0';
                strncpy(section, p + 1, sizeof(section) - 1);
                section[sizeof(section) - 1] = '\0';
            }
            continue;
        }

        /* Key = Value */
        char *eq = strchr(p, '=');
        if (!eq)
            continue;

        *eq = '\0';
        char *key = p;
        char *val = eq + 1;

        /* Trim whitespace from key */
        while (*key == ' ' || *key == '\t')
            key++;
        if (*key == '\0')
            continue; /* Skip empty key */
        char *kend = key + strlen(key) - 1;
        while (kend > key && (*kend == ' ' || *kend == '\t'))
            *kend-- = '\0';

        /* Trim whitespace from value */
        while (*val == ' ' || *val == '\t')
            val++;
        if (*val == '\0')
            continue; /* Skip empty value */
        char *vend = val + strlen(val) - 1;
        while (vend > val && (*vend == ' ' || *vend == '\t'))
            *vend-- = '\0';

        if (cfg->count >= MAX_CONFIG_ENTRIES)
            break;

        kv_pair_t *kv = &cfg->entries[cfg->count++];
        if (section[0])
        {
            snprintf(kv->key, sizeof(kv->key), "%s.%s", section, key);
        }
        else
        {
            strncpy(kv->key, key, sizeof(kv->key) - 1);
        }
        strncpy(kv->value, val, sizeof(kv->value) - 1);
    }

    fclose(f);
    return 0;
}

static const char *config_get(const config_t *cfg, const char *key)
{
    /* Search loaded config first */
    for (int i = 0; i < cfg->count; i++)
    {
        if (strcmp(cfg->entries[i].key, key) == 0)
            return cfg->entries[i].value;
    }

    /* Fall back to compile-time defaults */
    for (int i = 0; config_defaults[i].key; i++)
    {
        if (strcmp(config_defaults[i].key, key) == 0)
            return config_defaults[i].default_value;
    }

    return NULL;
}

static int config_set(config_t *cfg, const char *key, const char *value)
{
    /* Update existing entry */
    for (int i = 0; i < cfg->count; i++)
    {
        if (strcmp(cfg->entries[i].key, key) == 0)
        {
            strncpy(cfg->entries[i].value, value,
                    sizeof(cfg->entries[i].value) - 1);
            return 0;
        }
    }

    /* Add new entry */
    if (cfg->count >= MAX_CONFIG_ENTRIES)
        return -1;

    kv_pair_t *kv = &cfg->entries[cfg->count++];
    strncpy(kv->key, key, sizeof(kv->key) - 1);
    strncpy(kv->value, value, sizeof(kv->value) - 1);
    return 0;
}

/*
 * Write config back to file in INI format.
 * Groups entries by section.
 */
static int config_save(const config_t *cfg)
{
    /* Ensure directory exists */
    char dir[256];
    strncpy(dir, cfg->path, sizeof(dir) - 1);
    dir[sizeof(dir) - 1] = '\0';
    char *last_slash = strrchr(dir, '/');
    if (last_slash)
    {
        *last_slash = '\0';
        mkdir(dir, 0755);
    }

    /* Open with explicit permissions to avoid umask issues */
    int fd = open(cfg->path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
    {
        fprintf(stderr, "Error: cannot write %s: %s\n",
                cfg->path, strerror(errno));
        return -1;
    }
    FILE *f = fdopen(fd, "w");
    if (!f)
    {
        fprintf(stderr, "Error: fdopen failed: %s\n", strerror(errno));
        close(fd);
        return -1;
    }

    fprintf(f, "# BioAuth Configuration\n");
    fprintf(f, "# Generated by bioauth-config\n");
    fprintf(f, "# See bioauth-config show --defaults for all options.\n\n");

    /* Collect unique sections */
    char sections[32][64];
    int section_count = 0;

    for (int i = 0; i < cfg->count; i++)
    {
        char *dot = strchr(cfg->entries[i].key, '.');
        if (!dot)
            continue;

        char sec[64] = {0};
        size_t slen = (size_t)(dot - cfg->entries[i].key);
        if (slen >= sizeof(sec))
            slen = sizeof(sec) - 1;
        memcpy(sec, cfg->entries[i].key, slen);

        /* Check if already added */
        bool found = false;
        for (int j = 0; j < section_count; j++)
        {
            if (strcmp(sections[j], sec) == 0)
            {
                found = true;
                break;
            }
        }
        if (!found && section_count < 32)
        {
            strncpy(sections[section_count++], sec,
                    sizeof(sections[0]) - 1);
        }
    }

    /* Write entries grouped by section */
    for (int s = 0; s < section_count; s++)
    {
        fprintf(f, "[%s]\n", sections[s]);

        for (int i = 0; i < cfg->count; i++)
        {
            char *dot = strchr(cfg->entries[i].key, '.');
            if (!dot)
                continue;

            size_t slen = (size_t)(dot - cfg->entries[i].key);
            if (slen != strlen(sections[s]))
                continue;
            if (memcmp(cfg->entries[i].key, sections[s], slen) != 0)
                continue;

            /* Print description comment if known */
            for (int d = 0; config_defaults[d].key; d++)
            {
                if (strcmp(config_defaults[d].key, cfg->entries[i].key) == 0)
                {
                    fprintf(f, "# %s\n", config_defaults[d].description);
                    break;
                }
            }

            fprintf(f, "%s = %s\n", dot + 1, cfg->entries[i].value);
        }
        fprintf(f, "\n");
    }

    fclose(f);
    return 0;
}

/* ── Commands ────────────────────────────────────────────────── */

static int cmd_show(bool show_defaults)
{
    config_t cfg;
    config_load(&cfg, BIOAUTH_CONFIG_FILE);

    printf("╔══════════════════════════════════════════════════╗\n");
    printf("║           BioAuth Configuration                 ║\n");
    printf("╚══════════════════════════════════════════════════╝\n\n");

    if (cfg.count > 0)
    {
        printf("Config file: %s\n\n", BIOAUTH_CONFIG_FILE);
    }
    else
    {
        printf("Config file: %s (not found, using defaults)\n\n",
               BIOAUTH_CONFIG_FILE);
    }

    char prev_section[64] = {0};
    for (int i = 0; config_defaults[i].key; i++)
    {
        const config_entry_t *def = &config_defaults[i];

        /* Print section header */
        const char *dot = strchr(def->key, '.');
        if (dot)
        {
            char section[64] = {0};
            size_t slen = (size_t)(dot - def->key);
            if (slen >= sizeof(section))
                slen = sizeof(section) - 1;
            memcpy(section, def->key, slen);

            if (strcmp(section, prev_section) != 0)
            {
                printf("  [%s]\n", section);
                strncpy(prev_section, section, sizeof(prev_section) - 1);
                prev_section[sizeof(prev_section) - 1] = '\0';
            }
        }

        const char *current = config_get(&cfg, def->key);
        bool is_default = (current == def->default_value) ||
                          (current && strcmp(current, def->default_value) == 0);

        if (show_defaults || !is_default)
        {
            printf("    %-30s = %-15s", def->key, current ? current : "(null)");
            if (!is_default)
                printf("  (default: %s)", def->default_value);
            printf("\n");
        }
        else
        {
            printf("    %-30s = %s\n", def->key, current ? current : "(null)");
        }
    }

    printf("\n");
    return 0;
}

static int cmd_get(const char *key)
{
    config_t cfg;
    config_load(&cfg, BIOAUTH_CONFIG_FILE);

    const char *normalized_key = normalize_cli_key(key);
    const char *val = config_get(&cfg, normalized_key);
    if (val)
    {
        printf("%s\n", val);
        return 0;
    }

    fprintf(stderr, "Error: unknown key '%s'\n", key);
    fprintf(stderr, "\nAvailable keys:\n");
    for (int i = 0; config_defaults[i].key; i++)
    {
        fprintf(stderr, "  %s\n", config_defaults[i].key);
    }
    return 1;
}

static int cmd_set(const char *key, const char *value)
{
    if (getuid() != 0)
    {
        fprintf(stderr, "Error: 'set' requires root privileges.\n");
        return 1;
    }

    const char *normalized_key = normalize_cli_key(key);

    /* Validate key exists in defaults */
    bool valid = false;
    for (int i = 0; config_defaults[i].key; i++)
    {
        if (strcmp(config_defaults[i].key, normalized_key) == 0)
        {
            valid = true;
            break;
        }
    }
    if (!valid)
    {
        fprintf(stderr, "Error: unknown key '%s'\n", key);
        return 1;
    }

    config_t cfg;
    config_load(&cfg, BIOAUTH_CONFIG_FILE);

    /* Reject values containing characters that would corrupt INI format */
    for (const char *p = value; *p; p++)
    {
        if (*p == '\n' || *p == '\r')
        {
            fprintf(stderr, "Error: value contains invalid characters\n");
            return 1;
        }
    }

    config_set(&cfg, normalized_key, value);

    if (config_save(&cfg) != 0)
        return 1;

    printf("Set %s = %s\n", normalized_key, value);
    printf("Apply changes with: systemctl kill -s HUP biometric-authd.service\n");
    return 0;
}

static int cmd_reset(void)
{
    if (getuid() != 0)
    {
        fprintf(stderr, "Error: 'reset-config' requires root privileges.\n");
        return 1;
    }

    config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    strncpy(cfg.path, BIOAUTH_CONFIG_FILE, sizeof(cfg.path) - 1);

    /* Load all defaults */
    for (int i = 0; config_defaults[i].key && cfg.count < MAX_CONFIG_ENTRIES; i++)
    {
        kv_pair_t *kv = &cfg.entries[cfg.count++];
        strncpy(kv->key, config_defaults[i].key, sizeof(kv->key) - 1);
        strncpy(kv->value, config_defaults[i].default_value,
                sizeof(kv->value) - 1);
    }

    if (config_save(&cfg) != 0)
        return 1;

    printf("Configuration reset to defaults.\n");
    printf("Written to %s\n", BIOAUTH_CONFIG_FILE);
    return 0;
}

static int cmd_status(void)
{
    printf("╔══════════════════════════════════════════════════╗\n");
    printf("║           BioAuth System Status                 ║\n");
    printf("╚══════════════════════════════════════════════════╝\n\n");

    /* Check if daemon is running */
    GDBusConnection *conn = NULL;
    GError *err = NULL;
    conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &err);

    printf("  %-30s ", "D-Bus connection:");
    if (conn)
    {
        printf("OK\n");
    }
    else
    {
        printf("FAILED");
        if (err)
        {
            printf(" (%s)", err->message);
            g_error_free(err);
            err = NULL;
        }
        printf("\n");
    }

    /* Try to ping the daemon */
    if (conn)
    {
        GVariant *result = g_dbus_connection_call_sync(
            conn,
            "org.bioauth.Manager",
            "/org/bioauth/Manager",
            "org.freedesktop.DBus.Peer",
            "Ping",
            NULL,
            NULL,
            G_DBUS_CALL_FLAGS_NONE,
            2000, NULL, &err);

        printf("  %-30s ", "biometric-authd:");
        if (result)
        {
            printf("RUNNING\n");
            g_variant_unref(result);
        }
        else
        {
            printf("NOT RUNNING");
            if (err)
            {
                printf(" (%s)", err->message);
                g_error_free(err);
                err = NULL;
            }
            printf("\n");
        }
    }

    /* Check TPM device */
    printf("  %-30s ", "TPM device:");
    if (access("/dev/tpmrm0", R_OK | W_OK) == 0)
        printf("/dev/tpmrm0 (accessible)\n");
    else if (access("/dev/tpmrm0", F_OK) == 0)
        printf("/dev/tpmrm0 (permission denied)\n");
    else
        printf("not found\n");

    /* Check FIDO2 socket */
    printf("  %-30s ", "FIDO2 socket:");
    struct stat st;
    if (stat("/run/bioauth/fido2.sock", &st) == 0 && S_ISSOCK(st.st_mode))
        printf("/run/bioauth/fido2.sock (active)\n");
    else
        printf("not found\n");

    /* Check config file */
    printf("  %-30s ", "Config file:");
    if (access(BIOAUTH_CONFIG_FILE, R_OK) == 0)
        printf("%s\n", BIOAUTH_CONFIG_FILE);
    else
        printf("not found (using defaults)\n");

    config_t cfg;
    config_load(&cfg, BIOAUTH_CONFIG_FILE);
    const char *state_dir = config_get(&cfg, "general.state_dir");
    if (!state_dir)
        state_dir = "/var/lib/bioauth";

    /* Check state directory */
    printf("  %-30s ", "State directory:");
    if (access(state_dir, F_OK) == 0)
        printf("%s\n", state_dir);
    else
        printf("not created\n");

    printf("\n");

    if (conn)
        g_object_unref(conn);
    return 0;
}

static int cmd_fido2_info(void)
{
    printf("╔══════════════════════════════════════════════════╗\n");
    printf("║           FIDO2 Authenticator Info              ║\n");
    printf("╚══════════════════════════════════════════════════╝\n\n");

    printf("  AAGUID:      b10a0742-feed-4321-90ab-001122334455\n");
    printf("  Type:        Platform authenticator\n");
    printf("  Protocols:   FIDO_2_0, FIDO_2_1_PRE, FIDO_2_1\n");
    printf("  Algorithms:  ES256 (ECDSA w/ P-256, SHA-256)\n");
    printf("  Extensions:  credProtect, hmac-secret, credentialMgmtPreview\n");
    printf("  Transport:   internal (Unix domain socket)\n");
    printf("\n");
    printf("  Options:\n");
    printf("    %-20s %s\n", "plat:", "true (platform authenticator)");
    printf("    %-20s %s\n", "rk:", "true (resident key support)");
    printf("    %-20s %s\n", "up:", "true (user presence via fingerprint)");
    printf("    %-20s %s\n", "uv:", "true (user verification via fingerprint)");
    printf("    %-20s %s\n", "bioEnroll:", "true (on-device bio enrollment)");
    printf("    %-20s %s\n", "credMgmt:", "true (credential management)");
    printf("    %-20s %s\n", "pinUvAuthToken:", "true");
    printf("\n");
    printf("  Limits:\n");
    printf("    %-20s %d\n", "maxMsgSize:", 2048);
    printf("    %-20s %d\n", "maxCredIdLen:", 128);
    printf("    %-20s %d\n", "maxCredCount:", 64);
    printf("    %-20s %d\n", "maxAllowList:", 16);
    printf("\n");

    /* Check socket availability */
    struct stat st;
    printf("  Socket:      ");
    if (stat("/run/bioauth/fido2.sock", &st) == 0 && S_ISSOCK(st.st_mode))
        printf("/run/bioauth/fido2.sock (listening)\n");
    else
        printf("not available (daemon not running?)\n");

    printf("\n");
    return 0;
}

/* ── Main ────────────────────────────────────────────────────── */

static void usage(const char *prog)
{
    fprintf(stderr,
            "BioAuth Configuration Tool\n"
            "\n"
            "Usage: %s COMMAND [OPTIONS]\n"
            "\n"
            "Commands:\n"
            "  show [--defaults]    Show current configuration\n"
            "  get KEY              Get a specific config value\n"
            "  set KEY VALUE        Set a config value (root only)\n"
            "  status               Show daemon/device status\n"
            "  fido2-info           Show FIDO2 authenticator information\n"
            "  reset-config         Reset to default config (root only)\n"
            "  help                 Show this help\n"
            "\n"
            "Config file: %s\n"
            "\n"
            "Examples:\n"
            "  %s show\n"
            "  %s get general.session_timeout\n"
            "  %s set tpm.require_tpm true\n"
            "  %s status\n"
            "  %s fido2-info\n",
            prog, BIOAUTH_CONFIG_FILE, prog, prog, prog, prog, prog);
}

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        usage(argv[0]);
        return 1;
    }

    const char *cmd = argv[1];

    if (strcmp(cmd, "show") == 0)
    {
        bool defaults = false;
        if (argc > 2 && (strcmp(argv[2], "--defaults") == 0 ||
                         strcmp(argv[2], "-d") == 0))
            defaults = true;
        return cmd_show(defaults);
    }

    if (strcmp(cmd, "get") == 0)
    {
        if (argc < 3)
        {
            fprintf(stderr, "Usage: %s get KEY\n", argv[0]);
            return 1;
        }
        return cmd_get(argv[2]);
    }

    if (strcmp(cmd, "set") == 0)
    {
        if (argc < 4)
        {
            fprintf(stderr, "Usage: %s set KEY VALUE\n", argv[0]);
            return 1;
        }
        return cmd_set(argv[2], argv[3]);
    }

    if (strcmp(cmd, "status") == 0)
    {
        return cmd_status();
    }

    if (strcmp(cmd, "fido2-info") == 0)
    {
        return cmd_fido2_info();
    }

    if (strcmp(cmd, "reset-config") == 0)
    {
        return cmd_reset();
    }

    if (strcmp(cmd, "help") == 0 || strcmp(cmd, "--help") == 0 ||
        strcmp(cmd, "-h") == 0)
    {
        usage(argv[0]);
        return 0;
    }

    fprintf(stderr, "Unknown command: '%s'\n\n", cmd);
    usage(argv[0]);
    return 1;
}
