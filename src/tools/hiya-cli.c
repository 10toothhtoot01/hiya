#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gio/gio.h>

void show_status(GDBusConnection *conn) {
    printf("Hiya CLI Parity Interface\n");
    printf("Status: Connected to system D-Bus\n");
    
    // Ping daemon
    GError *err = NULL;
    GVariant *res = g_dbus_connection_call_sync(
        conn,
        "org.hiya.System",
        "/org/hiya/System",
        "org.freedesktop.DBus.Peer",
        "Ping",
        NULL,
        NULL,
        G_DBUS_CALL_FLAGS_NONE,
        -1,
        NULL,
        &err
    );
    if (!res) {
        printf("Daemon Status: OFFLINE (%s)\n", err->message);
        g_error_free(err);
    } else {
        printf("Daemon Status: ONLINE\n");
        g_variant_unref(res);
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: hiya-cli [status|search|show|save|lock|unlock]\n");
        return 1;
    }

    GError *err = NULL;
    GDBusConnection *conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &err);
    if (!conn) {
        fprintf(stderr, "Cannot connect to system D-Bus: %s\n", err->message);
        g_error_free(err);
        return 1;
    }

    const char *cmd = argv[1];
    if (strcmp(cmd, "status") == 0) {
        show_status(conn);
    } else {
        printf("Command '%s' started. (WIP Parity feature)\n", cmd);
    }

    g_object_unref(conn);
    return 0;
}
