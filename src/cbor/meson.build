# CBOR encoder/decoder (pure C, hand-coded RFC 8949)

bio_cbor_sources = files(
  'bio_cbor_encoder.c',
  'bio_cbor_decoder.c',
  'bio_cbor_ctap2.c',
)

lib_bio_cbor = static_library('bio_cbor',
  bio_cbor_sources,
  include_directories : inc_root,
  install : false,
)

dep_bio_cbor = declare_dependency(
  link_with : lib_bio_cbor,
  include_directories : inc_root,
)
