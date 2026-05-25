# TPM 2.0 direct interface (hand-coded, raw /dev/tpmrm0)

bio_tpm_sources = files(
  'bio_tpm.c',
)

lib_bio_tpm = static_library('bio_tpm',
  bio_tpm_sources,
  include_directories : inc_root,
  dependencies : [dep_bio_crypto],
  install : false,
)

dep_bio_tpm = declare_dependency(
  link_with : lib_bio_tpm,
  include_directories : inc_root,
  dependencies : [dep_bio_crypto],
)
