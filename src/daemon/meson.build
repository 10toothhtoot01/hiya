daemon_sources = files(
    'bio_daemon.c',
    'bio_fprintd_compat.c',
)

lib_bio_daemon = static_library(
    'bio_daemon',
    daemon_sources,
    include_directories: inc_root,
    dependencies: [dep_glib, dep_gio, dep_gio_unix, dep_dbus, dep_systemd],
    link_with: [lib_pm_foundation, lib_bio_crypto, lib_bio_tpm, lib_bio_fingerprint, lib_bio_common],
)

dep_bio_daemon = declare_dependency(
    link_with: lib_bio_daemon,
    include_directories: inc_root,
)

# The actual daemon executable
biometric_authd = executable(
    'biometric-authd',
    'main.c',
    include_directories: inc_root,
    dependencies: [dep_glib, dep_gio, dep_gio_unix, dep_dbus, dep_systemd],
    link_with: [lib_bio_daemon, lib_pm_foundation, lib_bio_crypto, lib_bio_tpm, lib_bio_fingerprint, lib_bio_cbor, lib_bio_common],
    install: true,
    install_dir: get_option('sbindir'),
)
