pam_sources = files(
    'pam_bioauth.c',
)

pam_bioauth = shared_library(
    'pam_bioauth',
    pam_sources,
    include_directories: inc_root,
    dependencies: [dep_pam, dep_glib, dep_gio],
    name_prefix: '',  # Output: pam_bioauth.so (no 'lib' prefix)
    install: true,
    install_dir: join_paths(get_option('libdir'), 'security'),
)
