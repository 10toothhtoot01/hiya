# SSH Security Key middleware (libsk-hiya.so)
# Implements OpenSSH's sk-api.h for FIDO2 SSH key operations.

shared_library(
    'sk-hiya',
    'bio_ssh_sk.c',
    include_directories: inc_root,
    dependencies: [dep_mbedcrypto, dep_mbedtls],
    link_with: [lib_bio_fido2, lib_bio_crypto, lib_bio_cbor, lib_bio_tpm, lib_bio_common],
    install: true,
    install_dir: get_option('libdir'),
    name_prefix: 'lib',  # Produces libsk-hiya.so
)
