/*
 * bio_portal.c — XDG Desktop Portal Biometric Provider
 *
 * Copyright (C) 2025 BioAuth Project
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Implements the org.freedesktop.impl.portal.Access interface for
 * biometric authentication prompts from sandboxed applications
 * (Flatpak, Snap).
 *
 * When a Flatpak app requests biometric authentication, the desktop
 * portal routes the request through this provider, which displays
 * a fingerprint prompt and communicates with biometric-authd.
 *
 * D-Bus interface:
 *   Bus:       Session bus
 *   Name:      org.freedesktop.impl.portal.desktop.bioauth
 *   Path:      /org/freedesktop/portal/desktop
 *   Interface: org.freedesktop.impl.portal.Access
 *
 * Method:
 *   AccessDialog(handle, app_id, parent_window, title, subtitle,
 *                body, options) → response, results
 *
 * The portal provider only activates when the request contains
 * the "bioauth" grant type or when the desktop requests biometric
 * verification for privileged operations.
 */

#include "bio_common.h"

#include <gio/gio.h>
#include <string.h>
#include <stdlib.h>
#include <pwd.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

/* ── D-Bus introspection XML ─────────────────────────────────── */

static const char *PORTAL_XML =
    "<node>"
    "  <interface name='org.freedesktop.impl.portal.Access'>"
    "    <method name='AccessDialog'>"
    "      <arg type='o' name='handle' direction='in'/>"
    "      <arg type='s' name='app_id' direction='in'/>"
    "      <arg type='s' name='parent_window' direction='in'/>"
    "      <arg type='s' name='title' direction='in'/>"
    "      <arg type='s' name='subtitle' direction='in'/>"
    "      <arg type='s' name='body' direction='in'/>"
    "      <arg type='a{sv}' name='options' direction='in'/>"
    "      <arg type='u' name='response' direction='out'/>"
    "      <arg type='a{sv}' name='results' direction='out'/>"
    "    </method>"
    "  </interface>"
    "  <interface name='org.freedesktop.impl.portal.WebAuthentication'>"
    "    <method name='CreateCredential'>"
    "      <arg type='s' name='parent_window' direction='in'/>"
    "      <arg type='a{sv}' name='options' direction='in'/>"
    "      <arg type='a{sv}' name='result' direction='out'/>"
    "    </method>"
    "    <method name='GetAssertion'>"
    "      <arg type='s' name='parent_window' direction='in'/>"
    "      <arg type='a{sv}' name='options' direction='in'/>"
    "      <arg type='a{sv}' name='result' direction='out'/>"
    "    </method>"
    "    <method name='Cancel'>"
    "      <arg type='s' name='token' direction='in'/>"
    "    </method>"
    "  </interface>"
    "</node>";

/* Portal responses */
#define PORTAL_RESPONSE_SUCCESS 0
#define PORTAL_RESPONSE_CANCELLED 1
#define PORTAL_RESPONSE_OTHER 2

#define BIO_CTAP2_SOCK_PATH "/run/bioauth/fido2.sock"
#define BIO_CTAP2_MAX_MSG 4096U

#define CTAP2_CMD_MAKE_CREDENTIAL 0x01
#define CTAP2_CMD_GET_ASSERTION 0x02

/* ── Portal state ────────────────────────────────────────────── */

typedef struct
{
    GDBusConnection *session_bus;
    GDBusConnection *system_bus; /* For talking to biometric-authd */
    GDBusNodeInfo *node_info;
    guint reg_id_access;
    guint reg_id_webauthn;
    guint name_id;
} bio_portal_ctx_t;

static bio_portal_ctx_t g_portal;

static bool io_read_exact_fd(int fd, uint8_t *buf, size_t len)
{
    size_t off = 0;
    while (off < len)
    {
        ssize_t n = read(fd, buf + off, len - off);
        if (n <= 0)
        {
            if (n < 0 && errno == EINTR)
                continue;
            return false;
        }
        off += (size_t)n;
    }
    return true;
}

static bool io_write_exact_fd(int fd, const uint8_t *buf, size_t len)
{
    size_t off = 0;
    while (off < len)
    {
        ssize_t n = write(fd, buf + off, len - off);
        if (n <= 0)
        {
            if (n < 0 && errno == EINTR)
                continue;
            return false;
        }
        off += (size_t)n;
    }
    return true;
}

static bool b64url_decode(const char *in, uint8_t **out, size_t *out_len)
{
    if (!in || !out || !out_len)
        return false;

    size_t in_len = strlen(in);
    size_t pad = (4 - (in_len % 4)) % 4;
    if (in_len > BIO_CTAP2_MAX_MSG * 4)
        return false;

    char *tmp = (char *)malloc(in_len + pad + 1);
    if (!tmp)
        return false;

    memcpy(tmp, in, in_len);
    for (size_t i = 0; i < in_len; i++)
    {
        if (tmp[i] == '-')
            tmp[i] = '+';
        else if (tmp[i] == '_')
            tmp[i] = '/';
    }
    for (size_t i = 0; i < pad; i++)
        tmp[in_len + i] = '=';
    tmp[in_len + pad] = '\0';

    gsize decoded_len = 0;
    guchar *decoded = g_base64_decode(tmp, &decoded_len);
    free(tmp);

    if (!decoded || decoded_len > BIO_CTAP2_MAX_MSG)
    {
        if (decoded)
            g_free(decoded);
        return false;
    }

    *out = (uint8_t *)decoded;
    *out_len = (size_t)decoded_len;
    return true;
}

static bool b64url_encode(const uint8_t *in, size_t in_len,
                          char *out, size_t out_sz)
{
    if (!in || !out || out_sz == 0)
        return false;

    gchar *tmp = g_base64_encode(in, in_len);
    if (!tmp)
        return false;

    size_t oi = 0;
    for (size_t i = 0; tmp[i] != '\0'; i++)
    {
        char c = tmp[i];
        if (c == '=')
            break;
        if (c == '+')
            c = '-';
        else if (c == '/')
            c = '_';

        if (oi + 1 >= out_sz)
        {
            g_free(tmp);
            return false;
        }
        out[oi++] = c;
    }
    out[oi] = '\0';
    g_free(tmp);
    return true;
}

static bool portal_ctap2_call(uint8_t cmd,
                              const uint8_t *req,
                              size_t req_len,
                              uint8_t *status_out,
                              uint8_t *rsp,
                              size_t *rsp_len)
{
    if (!status_out || !rsp || !rsp_len)
        return false;
    if (req_len > 0xFFFFu || req_len > BIO_CTAP2_MAX_MSG)
        return false;

    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return false;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, BIO_CTAP2_SOCK_PATH, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
    {
        close(fd);
        return false;
    }

    uint8_t hdr[3];
    hdr[0] = cmd;
    hdr[1] = (uint8_t)((req_len >> 8) & 0xFF);
    hdr[2] = (uint8_t)(req_len & 0xFF);

    if (!io_write_exact_fd(fd, hdr, sizeof(hdr)) ||
        (req_len > 0 && !io_write_exact_fd(fd, req, req_len)))
    {
        close(fd);
        return false;
    }

    uint8_t rhdr[3];
    if (!io_read_exact_fd(fd, rhdr, sizeof(rhdr)))
    {
        close(fd);
        return false;
    }

    *status_out = rhdr[0];
    uint16_t plen = (uint16_t)(((uint16_t)rhdr[1] << 8) | (uint16_t)rhdr[2]);
    if (plen > *rsp_len || plen > BIO_CTAP2_MAX_MSG)
    {
        close(fd);
        return false;
    }

    if (plen > 0 && !io_read_exact_fd(fd, rsp, plen))
    {
        close(fd);
        return false;
    }

    *rsp_len = plen;
    close(fd);
    return true;
}

/* Only the active desktop portal daemon may call AccessDialog. */
static bool sender_is_desktop_portal_owner(GDBusConnection *conn,
                                           const gchar *sender)
{
    if (!conn || !sender)
        return false;

    GError *err = NULL;
    GVariant *owner_result = g_dbus_connection_call_sync(
        conn,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
        "GetNameOwner",
        g_variant_new("(s)", "org.freedesktop.portal.Desktop"),
        G_VARIANT_TYPE("(s)"),
        G_DBUS_CALL_FLAGS_NONE,
        -1,
        NULL,
        &err);

    if (!owner_result)
    {
        BIO_WARN("portal: cannot resolve org.freedesktop.portal.Desktop owner: %s",
                 err ? err->message : "unknown");
        if (err)
            g_error_free(err);
        return false;
    }

    const gchar *owner = NULL;
    g_variant_get(owner_result, "(&s)", &owner);
    bool ok = (owner != NULL && g_strcmp0(owner, sender) == 0);
    g_variant_unref(owner_result);
    return ok;
}

/* ── Internal: call biometric-authd Verify ───────────────────── */

static bool portal_do_verify(bio_portal_ctx_t *ctx, const char *user)
{
    (void)user;
    if (!ctx->system_bus)
        return false;

    GError *err = NULL;

    GVariant *sess_result = g_dbus_connection_call_sync(
        ctx->system_bus,
        "org.bioauth.Manager",
        "/org/bioauth/Manager",
        "org.bioauth.Manager",
        "CreateSession",
        NULL,
        G_VARIANT_TYPE("(ay)"),
        G_DBUS_CALL_FLAGS_NONE,
        10000,
        NULL,
        &err);

    if (!sess_result)
    {
        BIO_WARN("portal: CreateSession failed: %s",
                 err ? err->message : "unknown");
        if (err)
            g_error_free(err);
        return false;
    }

    GVariant *token = NULL;
    g_variant_get(sess_result, "(@ay)", &token);
    g_variant_unref(sess_result);

    GVariant *result = g_dbus_connection_call_sync(
        ctx->system_bus,
        "org.bioauth.Manager",
        "/org/bioauth/Manager",
        "org.bioauth.Manager",
        "Verify",
        g_variant_new("(@ay)", token),
        G_VARIANT_TYPE("(b)"),
        G_DBUS_CALL_FLAGS_NONE,
        30000,
        NULL,
        &err);

    if (!result)
    {
        BIO_WARN("portal: Verify failed: %s",
                 err ? err->message : "unknown");
        if (err)
            g_error_free(err);
        return false;
    }

    gboolean authenticated = FALSE;
    g_variant_get(result, "(b)", &authenticated);
    g_variant_unref(result);

    return authenticated;
}

/* ── AccessDialog handler ────────────────────────────────────── */

static void portal_method_call(GDBusConnection *conn,
                               const gchar *sender,
                               const gchar *object_path,
                               const gchar *interface_name,
                               const gchar *method_name,
                               GVariant *parameters,
                               GDBusMethodInvocation *invocation,
                               gpointer user_data)
{
    bio_portal_ctx_t *ctx = (bio_portal_ctx_t *)user_data;
    (void)conn;
    (void)object_path;

    if (!sender_is_desktop_portal_owner(conn, sender))
    {
        BIO_WARN("portal: rejecting call from non-portal sender '%s'",
                 sender ? sender : "?");
        g_dbus_method_invocation_return_dbus_error(
            invocation,
            "org.freedesktop.DBus.Error.AccessDenied",
            "Only org.freedesktop.portal.Desktop may call BioAuth portal methods");
        return;
    }

    if (g_strcmp0(interface_name,
                  "org.freedesktop.impl.portal.WebAuthentication") == 0)
    {
        if (g_strcmp0(method_name, "Cancel") == 0)
        {
            const gchar *token = NULL;
            g_variant_get(parameters, "(&s)", &token);
            (void)token;
            g_dbus_method_invocation_return_value(invocation, NULL);
            return;
        }

        if (g_strcmp0(method_name, "CreateCredential") != 0 &&
            g_strcmp0(method_name, "GetAssertion") != 0)
        {
            g_dbus_method_invocation_return_dbus_error(
                invocation,
                "org.freedesktop.DBus.Error.UnknownMethod",
                "Unknown WebAuthentication method");
            return;
        }

        const gchar *parent_window = NULL;
        GVariant *options = NULL;
        g_variant_get(parameters, "(&s@a{sv})", &parent_window, &options);
        (void)parent_window;

        const gchar *ctap_req_b64u = NULL;
        if (!g_variant_lookup(options, "ctap2_request_b64u", "&s", &ctap_req_b64u) ||
            !ctap_req_b64u || ctap_req_b64u[0] == '\0')
        {
            g_variant_unref(options);
            g_dbus_method_invocation_return_dbus_error(
                invocation,
                "org.freedesktop.portal.Error.InvalidArgument",
                "Missing options['ctap2_request_b64u']");
            return;
        }

        uint8_t *ctap_req = NULL;
        size_t ctap_req_len = 0;
        if (!b64url_decode(ctap_req_b64u, &ctap_req, &ctap_req_len))
        {
            g_variant_unref(options);
            g_dbus_method_invocation_return_dbus_error(
                invocation,
                "org.freedesktop.portal.Error.InvalidArgument",
                "Invalid ctap2_request_b64u payload");
            return;
        }

        uint8_t cmd = (g_strcmp0(method_name, "CreateCredential") == 0)
                          ? CTAP2_CMD_MAKE_CREDENTIAL
                          : CTAP2_CMD_GET_ASSERTION;

        uint8_t rsp[BIO_CTAP2_MAX_MSG];
        size_t rsp_len = sizeof(rsp);
        uint8_t ctap_status = 0x7F;

        bool ok = portal_ctap2_call(cmd,
                                    ctap_req,
                                    ctap_req_len,
                                    &ctap_status,
                                    rsp,
                                    &rsp_len);
        g_free(ctap_req);
        g_variant_unref(options);

        if (!ok)
        {
            g_dbus_method_invocation_return_dbus_error(
                invocation,
                "org.freedesktop.portal.Error.Failed",
                "CTAP2 transport call failed");
            return;
        }

        char rsp_b64u[8192];
        if (!b64url_encode(rsp, rsp_len, rsp_b64u, sizeof(rsp_b64u)))
        {
            g_dbus_method_invocation_return_dbus_error(
                invocation,
                "org.freedesktop.portal.Error.Failed",
                "Failed to encode CTAP2 response");
            return;
        }

        GVariantBuilder result_builder;
        g_variant_builder_init(&result_builder, G_VARIANT_TYPE("a{sv}"));
        g_variant_builder_add(&result_builder, "{sv}",
                              "ctap_status",
                              g_variant_new_uint32((guint32)ctap_status));
        g_variant_builder_add(&result_builder, "{sv}",
                              "ctap2_response_b64u",
                              g_variant_new_string(rsp_b64u));

        g_dbus_method_invocation_return_value(
            invocation,
            g_variant_new("(a{sv})", &result_builder));
        return;
    }

    if (g_strcmp0(method_name, "AccessDialog") != 0)
    {
        g_dbus_method_invocation_return_dbus_error(
            invocation,
            "org.freedesktop.DBus.Error.UnknownMethod",
            "Unknown method");
        return;
    }

    const gchar *handle = NULL;
    const gchar *app_id = NULL;
    const gchar *parent_window = NULL;
    const gchar *title = NULL;
    const gchar *subtitle = NULL;
    const gchar *body = NULL;
    GVariant *options = NULL;

    g_variant_get(parameters, "(&o&s&s&s&s&s@a{sv})",
                  &handle, &app_id, &parent_window,
                  &title, &subtitle, &body, &options);

    BIO_INFO("portal: AccessDialog from sender='%s' app='%s' title='%s'",
             sender ? sender : "?", app_id, title);

    /* Defense in depth: caller UID must also match root or session user. */
    GError *err = NULL;
    GVariant *caller_uid_result = g_dbus_connection_call_sync(
        conn,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
        "GetConnectionUnixUser",
        g_variant_new("(s)", sender),
        G_VARIANT_TYPE("(u)"),
        G_DBUS_CALL_FLAGS_NONE,
        -1, NULL, &err);

    if (!caller_uid_result)
    {
        BIO_WARN("portal: Failed to get caller UID: %s",
                 err ? err->message : "unknown");
        if (err)
            g_error_free(err);
        g_dbus_method_invocation_return_dbus_error(
            invocation,
            "org.freedesktop.DBus.Error.AccessDenied",
            "Cannot verify caller identity");
        if (options)
            g_variant_unref(options);
        return;
    }

    guint32 caller_uid;
    g_variant_get(caller_uid_result, "(u)", &caller_uid);
    g_variant_unref(caller_uid_result);
    if (err)
        g_error_free(err);
    err = NULL;

    /* Only allow root (xdg-desktop-portal typically runs as user, but
     * verify caller matches session user) or the session user */
    uid_t session_uid = getuid();
    if (caller_uid != 0 && caller_uid != session_uid)
    {
        BIO_WARN("portal: AccessDialog rejected from UID %u "
                 "(session UID %u)",
                 caller_uid, (unsigned)session_uid);
        g_dbus_method_invocation_return_dbus_error(
            invocation,
            "org.freedesktop.DBus.Error.AccessDenied",
            "Only the session owner may trigger biometric authentication");
        if (options)
            g_variant_unref(options);
        return;
    }

    /* Resolve username from caller UID */
    char *username = NULL;
    {
        struct passwd pw_buf;
        char pw_strbuf[512];
        struct passwd *pw = NULL;
        int rc = getpwuid_r((uid_t)caller_uid, &pw_buf, pw_strbuf,
                            sizeof(pw_strbuf), &pw);
        if (rc == 0 && pw)
        {
            username = g_strdup(pw->pw_name);
        }
        else
        {
            BIO_WARN("portal: failed to resolve username for UID %u "
                     "(rc=%d)",
                     (unsigned)caller_uid, rc);
        }
    }

    /* Perform biometric verification */
    bool success = portal_do_verify(ctx, username);

    GVariantBuilder results_builder;
    g_variant_builder_init(&results_builder, G_VARIANT_TYPE("a{sv}"));
    g_variant_builder_add(&results_builder, "{sv}",
                          "bioauth-verified",
                          g_variant_new_boolean(success));
    if (app_id)
        g_variant_builder_add(&results_builder, "{sv}",
                              "app-id",
                              g_variant_new_string(app_id));

    guint32 response = success ? PORTAL_RESPONSE_SUCCESS
                               : PORTAL_RESPONSE_CANCELLED;

    g_dbus_method_invocation_return_value(
        invocation,
        g_variant_new("(ua{sv})", response, &results_builder));

    if (options)
        g_variant_unref(options);
    g_free(username);

    BIO_INFO("portal: AccessDialog result=%s for app='%s'",
             success ? "success" : "denied", app_id);
}

static const GDBusInterfaceVTable portal_vtable = {
    .method_call = portal_method_call,
    .get_property = NULL,
    .set_property = NULL,
};

/* ── Name callbacks ──────────────────────────────────────────── */

static void on_portal_name_acquired(GDBusConnection *conn,
                                    const gchar *name,
                                    gpointer user_data)
{
    (void)conn;
    (void)user_data;
    BIO_INFO("portal: acquired name '%s'", name);
}

static void on_portal_name_lost(GDBusConnection *conn,
                                const gchar *name,
                                gpointer user_data)
{
    (void)conn;
    (void)user_data;
    BIO_WARN("portal: lost name '%s'", name);
}

/* ── Public API ──────────────────────────────────────────────── */

int bio_portal_init(void)
{
    memset(&g_portal, 0, sizeof(g_portal));

    GError *err = NULL;

    /* Connect to session bus (portals run on session bus) */
    g_portal.session_bus = g_bus_get_sync(G_BUS_TYPE_SESSION, NULL, &err);
    if (!g_portal.session_bus)
    {
        BIO_WARN("portal: no session bus: %s",
                 err ? err->message : "unknown");
        if (err)
            g_error_free(err);
        return -1;
    }

    /* Connect to system bus (for talking to biometric-authd) */
    g_portal.system_bus = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &err);
    if (!g_portal.system_bus)
    {
        BIO_WARN("portal: no system bus: %s",
                 err ? err->message : "unknown");
        if (err)
            g_error_free(err);
        g_object_unref(g_portal.session_bus);
        g_portal.session_bus = NULL;
        return -1;
    }

    /* Parse introspection */
    g_portal.node_info = g_dbus_node_info_new_for_xml(PORTAL_XML, &err);
    if (!g_portal.node_info)
    {
        BIO_ERROR("portal: failed to parse XML: %s",
                  err ? err->message : "unknown");
        if (err)
            g_error_free(err);
        g_object_unref(g_portal.system_bus);
        g_portal.system_bus = NULL;
        g_object_unref(g_portal.session_bus);
        g_portal.session_bus = NULL;
        return -1;
    }

    GDBusInterfaceInfo *access_iface =
        g_dbus_node_info_lookup_interface(g_portal.node_info,
                                          "org.freedesktop.impl.portal.Access");
    if (!access_iface)
    {
        BIO_ERROR("portal: missing Access interface definition");
        g_object_unref(g_portal.system_bus);
        g_portal.system_bus = NULL;
        g_object_unref(g_portal.session_bus);
        g_portal.session_bus = NULL;
        g_dbus_node_info_unref(g_portal.node_info);
        g_portal.node_info = NULL;
        return -1;
    }

    /* Register object */
    g_portal.reg_id_access = g_dbus_connection_register_object(
        g_portal.session_bus,
        "/org/freedesktop/portal/desktop",
        access_iface,
        &portal_vtable,
        &g_portal,
        NULL,
        &err);
    if (g_portal.reg_id_access == 0)
    {
        BIO_ERROR("portal: failed to register: %s",
                  err ? err->message : "unknown");
        if (err)
            g_error_free(err);
        g_object_unref(g_portal.system_bus);
        g_portal.system_bus = NULL;
        g_object_unref(g_portal.session_bus);
        g_portal.session_bus = NULL;
        g_dbus_node_info_unref(g_portal.node_info);
        g_portal.node_info = NULL;
        return -1;
    }

    GDBusInterfaceInfo *webauthn_iface =
        g_dbus_node_info_lookup_interface(g_portal.node_info,
                                          "org.freedesktop.impl.portal.WebAuthentication");
    if (!webauthn_iface)
    {
        BIO_ERROR("portal: missing WebAuthentication interface definition");
        g_dbus_connection_unregister_object(g_portal.session_bus,
                                            g_portal.reg_id_access);
        g_portal.reg_id_access = 0;
        g_object_unref(g_portal.system_bus);
        g_portal.system_bus = NULL;
        g_object_unref(g_portal.session_bus);
        g_portal.session_bus = NULL;
        g_dbus_node_info_unref(g_portal.node_info);
        g_portal.node_info = NULL;
        return -1;
    }

    g_portal.reg_id_webauthn = g_dbus_connection_register_object(
        g_portal.session_bus,
        "/org/freedesktop/portal/desktop",
        webauthn_iface,
        &portal_vtable,
        &g_portal,
        NULL,
        &err);

    if (g_portal.reg_id_webauthn == 0)
    {
        BIO_ERROR("portal: failed to register WebAuthentication interface: %s",
                  err ? err->message : "unknown");
        if (err)
            g_error_free(err);
        g_dbus_connection_unregister_object(g_portal.session_bus,
                                            g_portal.reg_id_access);
        g_portal.reg_id_access = 0;
        g_object_unref(g_portal.system_bus);
        g_portal.system_bus = NULL;
        g_object_unref(g_portal.session_bus);
        g_portal.session_bus = NULL;
        g_dbus_node_info_unref(g_portal.node_info);
        g_portal.node_info = NULL;
        return -1;
    }

    /* Own the portal provider name */
    g_portal.name_id = g_bus_own_name_on_connection(
        g_portal.session_bus,
        "org.freedesktop.impl.portal.desktop.bioauth",
        G_BUS_NAME_OWNER_FLAGS_NONE,
        on_portal_name_acquired,
        on_portal_name_lost,
        &g_portal,
        NULL);

    BIO_INFO("portal: XDG Desktop Portal provider initialised");
    return 0;
}

void bio_portal_cleanup(void)
{
    if (g_portal.name_id > 0)
    {
        g_bus_unown_name(g_portal.name_id);
        g_portal.name_id = 0;
    }

    if (g_portal.reg_id_webauthn > 0 && g_portal.session_bus)
    {
        g_dbus_connection_unregister_object(
            g_portal.session_bus, g_portal.reg_id_webauthn);
        g_portal.reg_id_webauthn = 0;
    }

    if (g_portal.reg_id_access > 0 && g_portal.session_bus)
    {
        g_dbus_connection_unregister_object(
            g_portal.session_bus, g_portal.reg_id_access);
        g_portal.reg_id_access = 0;
    }

    if (g_portal.node_info)
    {
        g_dbus_node_info_unref(g_portal.node_info);
        g_portal.node_info = NULL;
    }

    if (g_portal.system_bus)
    {
        g_object_unref(g_portal.system_bus);
        g_portal.system_bus = NULL;
    }

    if (g_portal.session_bus)
    {
        g_object_unref(g_portal.session_bus);
        g_portal.session_bus = NULL;
    }

    BIO_INFO("portal: cleaned up");
}
