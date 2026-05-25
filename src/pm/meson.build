pm_foundation_sources = files(
  'pm_bio_wrap.c',
  'pm_errors.c',
  'pm_secure_mem.c',
  'pm_master_key.c',
  'pm_kdf.c',
  'pm_vault_format.c',
  'pm_vault_store.c',
  'pm_payload.c',
  'pm_history.c',
  'pm_entry_store.c',
  'pm_tpm_wrapping.c',
  'pm_otp.c',
  'pm_clipboard.c',
  'pm_hibp.c',
  'pm_ssh_keys.c',
  'pm_eff_wordlist.c',
  'pm_yubikey.c',
  'pm_password_gen.c',
  'pm_security_audit.c',
  '../../third_party/zxcvbn-c/zxcvbn.c',
)

inc_zxcvbn = include_directories('../../third_party/zxcvbn-c')

lib_pm_foundation = static_library('pm_foundation',
  pm_foundation_sources,
  include_directories : [inc_root, inc_zxcvbn],
  dependencies : [dep_threads, dep_curl],
  link_with : [lib_bio_crypto, lib_bio_cbor, lib_bio_tpm, lib_bio_common],
  install : false,
)

dep_pm_foundation = declare_dependency(
  link_with : lib_pm_foundation,
  include_directories : inc_root,
)
