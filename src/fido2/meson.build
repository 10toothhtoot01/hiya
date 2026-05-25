fido2_sources = files(
    'bio_fido2.c',
    'bio_fido2_credential.c',
    'bio_fido2_pin.c',
    'bio_fido2_bio_cred.c',
    'bio_fido2_transport.c',
    'bio_fido2_uhid.c',
)

lib_bio_fido2 = static_library(
    'bio_fido2',
    fido2_sources,
    include_directories: inc_root,
    dependencies: [],
    link_with: [lib_bio_crypto, lib_bio_cbor],
)

dep_bio_fido2 = declare_dependency(
    link_with: lib_bio_fido2,
    include_directories: inc_root,
    dependencies: [dep_bio_crypto, dep_bio_cbor],
)

# ── FIDO2 daemon executable ──────────────────────────────────────
executable(
    'bioauth-fido2d',
    'fido2_main.c',
    include_directories: inc_root,
    dependencies: [dep_systemd, dep_threads, dep_gio, dep_glib],
    link_with: [lib_bio_fido2, lib_bio_crypto, lib_bio_cbor, lib_bio_tpm, lib_bio_common],
    install: true,
    install_dir: get_option('libexecdir'),
)
