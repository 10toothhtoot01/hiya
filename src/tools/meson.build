# CLI tools
bioauth_enroll = executable(
    'bioauth-enroll',
    'bioauth_enroll.c',
    include_directories: inc_root,
    dependencies: [dep_glib, dep_gio],
    install: true,
    install_dir: get_option('bindir'),
)

bioauth_verify = executable(
    'bioauth-verify',
    'bioauth_verify.c',
    include_directories: inc_root,
    dependencies: [dep_glib, dep_gio],
    install: true,
    install_dir: get_option('bindir'),
)

bioauth_config = executable(
    'bioauth-config',
    'bioauth_config.c',
    include_directories: inc_root,
    dependencies: [dep_glib, dep_gio],
    install: true,
    install_dir: get_option('bindir'),
)

bioauth_cli = executable(
    'bioauth-cli',
    'bioauth-cli.c',
    include_directories: inc_root,
    dependencies: [dep_glib, dep_gio],
    install: true,
    install_dir: get_option('bindir'),
)
