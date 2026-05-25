# Config file installation

# D-Bus policy (allows clients to talk to the daemon)
install_data(
    'org.bioauth.Manager.conf',
    install_dir: join_paths(get_option('sysconfdir'), 'dbus-1', 'system.d'),
)

# D-Bus activation service (auto-start daemon on first D-Bus call)
install_data(
    'org.bioauth.Manager.service',
    install_dir: join_paths(get_option('datadir'), 'dbus-1', 'system-services'),
)

install_data(
    'org.bioauth.Daemon.service',
    install_dir: join_paths(get_option('datadir'), 'dbus-1', 'system-services'),
)

# Main daemon systemd service
install_data(
    'biometric-authd.service',
    install_dir: join_paths(get_option('prefix'), 'lib', 'systemd', 'system'),
)

# Systemd socket activation unit
install_data(
    'biometric-authd.socket',
    install_dir: join_paths(get_option('prefix'), 'lib', 'systemd', 'system'),
)

# FIDO2 transport systemd service
install_data(
    'bioauth-fido2.service',
    install_dir: join_paths(get_option('prefix'), 'lib', 'systemd', 'system'),
)

# Default configuration file
install_data(
    'bioauth.conf',
    install_dir: join_paths(get_option('sysconfdir'), 'bioauth'),
    install_mode: 'rw-r-----',
)

# PAM configuration snippet
install_data(
    'pam_bioauth',
    install_dir: join_paths(get_option('sysconfdir'), 'pam.d'),
)

# PolicyKit policy
install_data(
    'org.bioauth.policy',
    install_dir: join_paths(get_option('datadir'), 'polkit-1', 'actions'),
)

# udev rules
install_data(
    '70-bioauth-fingerprint.rules',
    install_dir: join_paths(get_option('prefix'), 'lib', 'udev', 'rules.d'),
)

# XDG Desktop Portal configuration
install_data(
    'bioauth.portal',
    install_dir: join_paths(get_option('datadir'), 'xdg-desktop-portal', 'portals'),
)

# Overlay/polkit desktop entry used for app-id metadata and autostart
install_data(
    'bioauth-polkit-agent.desktop',
    install_dir: join_paths(get_option('datadir'), 'applications'),
)

# Portal D-Bus activation service (session bus)
install_data(
    'org.freedesktop.impl.portal.desktop.bioauth.service',
    install_dir: join_paths(get_option('datadir'), 'dbus-1', 'services'),
)

# Man pages removed for daemon-only build.
