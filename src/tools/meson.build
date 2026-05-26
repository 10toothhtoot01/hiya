# CLI tools
hiya_enroll = executable(
    'hiya-enroll',
    'hiya_enroll.c',
    include_directories: inc_root,
    dependencies: [dep_glib, dep_gio],
    install: true,
    install_dir: get_option('bindir'),
)

hiya_verify = executable(
    'hiya-verify',
    'hiya_verify.c',
    include_directories: inc_root,
    dependencies: [dep_glib, dep_gio],
    install: true,
    install_dir: get_option('bindir'),
)

hiya_config = executable(
    'hiya-config',
    'hiya_config.c',
    include_directories: inc_root,
    dependencies: [dep_glib, dep_gio],
    install: true,
    install_dir: get_option('bindir'),
)

hiya_cli = executable(
    'hiya-cli',
    'hiya-cli.c',
    include_directories: inc_root,
    dependencies: [dep_glib, dep_gio],
    install: true,
    install_dir: get_option('bindir'),
)
