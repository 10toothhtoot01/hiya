pam_sources = files(
    'pam_hiya.c',
)

pam_hiya = shared_library(
    'pam_hiya',
    pam_sources,
    include_directories: inc_root,
    dependencies: [dep_pam, dep_glib, dep_gio],
    name_prefix: '',  # Output: pam_hiya.so (no 'lib' prefix)
    install: true,
    install_dir: join_paths(get_option('libdir'), 'security'),
)
