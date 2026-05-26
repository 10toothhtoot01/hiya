# XDG Desktop Portal provider for biometric authentication

portal_sources = files(
    'bio_portal.c',
)

lib_bio_portal = static_library(
    'bio_portal',
    portal_sources,
    include_directories: inc_root,
    dependencies: [dep_glib, dep_gio],
    link_with: [lib_bio_common],
)

# Portal daemon executable
executable(
    'hiya-portal',
    'portal_main.c',
    include_directories: inc_root,
    dependencies: [dep_glib, dep_gio],
    link_with: [lib_bio_portal, lib_bio_common],
    install: true,
    install_dir: get_option('libexecdir'),
)
