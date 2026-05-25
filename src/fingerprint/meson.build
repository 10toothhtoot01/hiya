# Fingerprint wrapper (wraps libfprint-2)

bio_fingerprint_sources = files(
  'bio_fingerprint.c',
)

lib_bio_fingerprint = static_library('bio_fingerprint',
  bio_fingerprint_sources,
  include_directories : inc_root,
  dependencies : [dep_fprint, dep_glib, dep_gio, dep_bio_crypto],
  install : false,
)

dep_bio_fingerprint = declare_dependency(
  link_with : lib_bio_fingerprint,
  include_directories : inc_root,
  dependencies : [dep_fprint, dep_glib],
)
