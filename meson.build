project('hiya', ['c', 'cpp'],
  version : '0.2.0',
  default_options : [
    'c_std=gnu11',
    'cpp_std=gnu++17',
    'warning_level=2',
    'werror=false',
    'b_lto=true',
    'b_pie=true',
    'optimization=2',
  ],
  license : 'GPL-3.0-or-later',
  meson_version : '>=0.60.0',
)

# ── Compiler flags ─────────────────────────────────────────────────
cc = meson.get_compiler('c')

add_project_arguments(
  '-D_GNU_SOURCE',
  '-D_POSIX_C_SOURCE=200809L',
  '-fstack-protector-strong',
  '-fPIC',
  '-D_FORTIFY_SOURCE=2',
  '-Wformat-security',
  '-Wno-unused-parameter',       # PAM callbacks have unused params
  language : 'c',
)

# ── System dependencies ───────────────────────────────────────────
dep_mbedtls    = dependency('mbedtls',    required : true)
dep_mbedcrypto = dependency('mbedcrypto', required : true)
dep_fprint    = dependency('libfprint-2', required : true, version : '>=1.90')
dep_glib      = dependency('glib-2.0',    required : true, version : '>=2.56')
dep_gio       = dependency('gio-2.0',     required : true)
dep_gio_unix  = dependency('gio-unix-2.0', required : true)
dep_dbus      = dependency('dbus-1',      required : true)
dep_pam       = cc.find_library('pam',    required : true)
dep_systemd   = dependency('libsystemd',  required : true)
dep_threads   = dependency('threads',     required : true)
dep_curl      = dependency('libcurl',     required : false)
dep_x11       = dependency('x11',         required : false)
dep_xtst      = dependency('xtst',        required : false)
dep_wayland_client = dependency('wayland-client', required : false)

# ── Project-wide include path ─────────────────────────────────────
inc_root = include_directories('include', 'src')

# ── Common library (error strings, logging) ──────────────────────
lib_bio_common = static_library(
    'bio_common',
    'src/bio_common.c',
    include_directories: inc_root,
    dependencies: [dep_threads],
)
dep_bio_common = declare_dependency(
    link_with: lib_bio_common,
    include_directories: inc_root,
)

# ── Sub-components (order matters for dependencies) ───────────────

# 1. Crypto wrapper (thin layer over mbedtls)
subdir('src/crypto')

# 2. CBOR encoder/decoder (pure C, no deps)
subdir('src/cbor')

# 3. TPM 2.0 interface (talks to /dev/tpmrm0)
subdir('src/tpm')

# 4. Fingerprint wrapper (wraps libfprint-2)
subdir('src/fingerprint')

# 5. Password manager foundational modules
subdir('src/pm')


# 7. D-Bus system daemon
subdir('src/daemon')

# 8. PAM module
subdir('src/pam')

# 9. FIDO2/CTAP2 authenticator
subdir('src/fido2')

# 10. CLI tools
subdir('src/tools')

# 11. XDG Desktop Portal provider
subdir('src/portal')


# 13. SSH FIDO2 security key middleware
subdir('src/ssh')


# ── Configuration files ──────────────────────────────────────────
subdir('config')

# ── Public headers (for devel package) ───────────────────────────
install_headers('include/bio_common.h', subdir: 'hiya')
