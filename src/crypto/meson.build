# Crypto wrapper (thin layer over mbedtls)

bio_crypto_sources = files(
  'bio_crypto.c',
)

lib_bio_crypto = static_library('bio_crypto',
  bio_crypto_sources,
  include_directories : inc_root,
  dependencies : [dep_mbedcrypto, dep_mbedtls],
  install : false,
)

dep_bio_crypto = declare_dependency(
  link_with : lib_bio_crypto,
  include_directories : inc_root,
  dependencies : [dep_mbedcrypto, dep_mbedtls],
)
