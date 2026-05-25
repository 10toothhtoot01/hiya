%global selinux_policyver 3.14.3

Name:           bioauth
Version:        0.1.0
Release:        0.alpha1%{?dist}
Summary:        Local biometric authentication daemon for Linux

License:        GPL-3.0-or-later
URL:            https://github.com/bioauth/bioauth
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  meson >= 0.60.0
BuildRequires:  gcc
BuildRequires:  gcc-c++
BuildRequires:  ninja-build
BuildRequires:  pkgconfig(mbedtls) >= 3.0
BuildRequires:  pkgconfig(mbedcrypto)
BuildRequires:  pkgconfig(mbedx509)
BuildRequires:  pkgconfig(libfprint-2) >= 1.90
BuildRequires:  pkgconfig(glib-2.0) >= 2.56
BuildRequires:  pkgconfig(gio-2.0)
BuildRequires:  pkgconfig(gio-unix-2.0)
BuildRequires:  pkgconfig(dbus-1)
BuildRequires:  pkgconfig(libsystemd)
BuildRequires:  pam-devel
BuildRequires:  systemd-rpm-macros
# Qt6 / KF6 for UI components (auth overlay, KCM, plasmoid)
BuildRequires:  cmake(Qt6Core)
BuildRequires:  cmake(Qt6Gui)
BuildRequires:  cmake(Qt6Qml)
BuildRequires:  cmake(Qt6Quick)
BuildRequires:  cmake(Qt6DBus)
BuildRequires:  cmake(Qt6QuickControls2)
BuildRequires:  cmake(KF6I18n)
BuildRequires:  cmake(KF6CoreAddons)
BuildRequires:  cmake(KF6IconThemes)
BuildRequires:  cmake(KF6KCMUtils)
BuildRequires:  qt6-qtbase-private-devel
# SELinux policy build
BuildRequires:  selinux-policy-devel
BuildRequires:  checkpolicy

Requires:       libfprint%{?_isa}
Requires:       glib2%{?_isa}
Requires:       mbedtls%{?_isa}
Requires:       dbus
Requires:       systemd
Requires:       pam%{?_isa}
Requires:       polkit
Requires(post):    selinux-policy-base >= %{selinux_policyver}
Requires(post):    policycoreutils
Requires(postun):  policycoreutils

%description
BioAuth is a 100%% local, privacy-first biometric authentication system
for Linux, comparable to Windows Hello. It provides fingerprint-based
authentication integrated with PAM, D-Bus, systemd, PolicyKit, TPM 2.0,
and FIDO2/WebAuthn — entirely offline with zero cloud dependencies.

All biometric templates are stored locally, encrypted with AES-256-GCM,
and optionally sealed to the TPM 2.0 chip. The FIDO2 platform
authenticator enables passwordless WebAuthn with biometric user
verification.

Features:
- PAM module for login, sudo, screen lock, polkit
- D-Bus daemon with systemd socket activation
- TPM 2.0 key sealing with PCR binding
- FIDO2/CTAP2 platform authenticator
- Supports Goodix, Elan, Synaptics, Validity, AuthenTec, and more
- SELinux confined, systemd sandboxed
- fprintd-compatible D-Bus API for GDM/GNOME integration

%package        devel
Summary:        Development files for %{name}
Requires:       %{name}%{?_isa} = %{version}-%{release}

%description    devel
Header files and development documentation for BioAuth.

%package        selinux
Summary:        SELinux policy for %{name}
BuildArch:      noarch
Requires:       %{name} = %{version}-%{release}
Requires:       selinux-policy-base >= %{selinux_policyver}
Requires(post):    policycoreutils
Requires(postun):  policycoreutils

%description    selinux
SELinux policy module for the BioAuth biometric authentication daemon.
Confines the daemon, PAM module, and FIDO2 service to restricted
domains with minimal privileges.

%package        ui
Summary:        Qt/QML frontend for %{name}
Requires:       %{name}%{?_isa} = %{version}-%{release}
Requires:       qt6-qtbase%{?_isa}
Requires:       qt6-qtdeclarative%{?_isa}
Requires:       kf6-ki18n%{?_isa}
Requires:       kf6-kirigami%{?_isa}

%description    ui
Qt6/QML frontend components for BioAuth biometric authentication:
- Auth overlay: frosted glass modal for fingerprint verification
  (invoked by polkit agent, PAM, sudo)
- KDE System Settings module for fingerprint enrollment management
- Plasma system tray plasmoid for sensor status monitoring

# ── Build ────────────────────────────────────────────────────────

%prep
%autosetup -n %{name}-%{version}

%build
%meson
%meson_build

# Build SELinux policy module
cd selinux
make -f %{_datadir}/selinux/devel/Makefile bioauth.pp
bzip2 bioauth.pp
cd ..

%install
%meson_install

# SELinux policy module
install -D -m 0644 selinux/bioauth.pp.bz2 \
    %{buildroot}%{_datadir}/selinux/packages/%{name}/bioauth.pp.bz2

# Man pages
install -d %{buildroot}%{_mandir}/man1
install -d %{buildroot}%{_mandir}/man5
install -d %{buildroot}%{_mandir}/man8
install -m 0644 man/bioauth-enroll.1 %{buildroot}%{_mandir}/man1/
install -m 0644 man/bioauth-verify.1 %{buildroot}%{_mandir}/man1/
install -m 0644 man/bioauth-config.1 %{buildroot}%{_mandir}/man1/
install -m 0644 man/bioauth.conf.5 %{buildroot}%{_mandir}/man5/
install -m 0644 man/biometric-authd.8 %{buildroot}%{_mandir}/man8/
install -m 0644 man/pam_bioauth.8 %{buildroot}%{_mandir}/man8/

# PolicyKit policy
install -D -m 0644 config/org.bioauth.policy \
    %{buildroot}%{_datadir}/polkit-1/actions/org.bioauth.policy

# udev rules
install -D -m 0644 config/70-bioauth-fingerprint.rules \
    %{buildroot}%{_prefix}/lib/udev/rules.d/70-bioauth-fingerprint.rules

# Create state directories
install -d -m 0700 %{buildroot}%{_sharedstatedir}/bioauth
install -d -m 0750 %{buildroot}%{_rundir}/bioauth

# tmpfiles.d for /run/bioauth
install -d %{buildroot}%{_tmpfilesdir}
cat > %{buildroot}%{_tmpfilesdir}/%{name}.conf <<'EOF'
d /run/bioauth 0750 root root -
EOF

# sysusers.d (create bioauth group for udev/state access)
install -d %{buildroot}%{_sysusersdir}
cat > %{buildroot}%{_sysusersdir}/%{name}.conf <<'EOF'
g bioauth -
EOF

%check
%meson_test

# ── Scriptlets ───────────────────────────────────────────────────

%post
%systemd_post biometric-authd.service biometric-authd.socket bioauth-fido2.service
udevadm control --reload-rules 2>/dev/null || :
udevadm trigger --subsystem-match=usb --attr-match=bInterfaceClass=ff 2>/dev/null || :

%preun
%systemd_preun biometric-authd.service biometric-authd.socket bioauth-fido2.service

%postun
%systemd_postun_with_restart biometric-authd.service biometric-authd.socket bioauth-fido2.service
udevadm control --reload-rules 2>/dev/null || :

%post selinux
semodule -i %{_datadir}/selinux/packages/%{name}/bioauth.pp.bz2 2>/dev/null || :
fixfiles -R %{name} restore 2>/dev/null || :
restorecon -R %{_sbindir}/biometric-authd 2>/dev/null || :
restorecon -R %{_libexecdir}/bioauth-fido2d 2>/dev/null || :
restorecon -R %{_sharedstatedir}/bioauth 2>/dev/null || :
restorecon -R %{_sysconfdir}/bioauth 2>/dev/null || :

%postun selinux
if [ $1 -eq 0 ]; then
    semodule -r bioauth 2>/dev/null || :
    fixfiles -R %{name} restore 2>/dev/null || :
fi

# ── File lists ───────────────────────────────────────────────────

%files
# Daemon binary
%{_sbindir}/biometric-authd

# FIDO2 daemon
%{_libexecdir}/bioauth-fido2d

# CLI tools
%{_bindir}/bioauth-enroll
%{_bindir}/bioauth-verify
%{_bindir}/bioauth-config

# PAM module
%{_libdir}/security/pam_bioauth.so

# SSH middleware
%{_libdir}/libsk-bioauth.so

# XDG desktop portal backend
%{_libexecdir}/bioauth-portal
%{_datadir}/xdg-desktop-portal/portals/bioauth.portal
%{_datadir}/dbus-1/services/org.freedesktop.impl.portal.desktop.bioauth.service

# systemd units
%{_unitdir}/biometric-authd.service
%{_unitdir}/biometric-authd.socket
%{_unitdir}/bioauth-fido2.service

# D-Bus
%{_sysconfdir}/dbus-1/system.d/org.bioauth.Manager.conf
%{_datadir}/dbus-1/system-services/org.bioauth.Manager.service

# PolicyKit
%{_datadir}/polkit-1/actions/org.bioauth.policy

# udev
%{_sysusersdir}/%{name}.conf
%{_prefix}/lib/udev/rules.d/70-bioauth-fingerprint.rules

# Configuration
%dir %{_sysconfdir}/bioauth
%config(noreplace) %{_sysconfdir}/bioauth/bioauth.conf
%config(noreplace) %{_sysconfdir}/pam.d/pam_bioauth

# State and runtime
%dir %attr(0700,root,root) %{_sharedstatedir}/bioauth
%ghost %dir %attr(0750,root,root) %{_rundir}/bioauth
%{_tmpfilesdir}/%{name}.conf

# Man pages
%{_mandir}/man1/bioauth-enroll.1*
%{_mandir}/man1/bioauth-verify.1*
%{_mandir}/man1/bioauth-config.1*
%{_mandir}/man5/bioauth.conf.5*
%{_mandir}/man8/biometric-authd.8*
%{_mandir}/man8/pam_bioauth.8*

# License and docs
%license LICENSE
%doc README.md

%files selinux
%{_datadir}/selinux/packages/%{name}/bioauth.pp.bz2

%files devel
%{_includedir}/bioauth/

%files ui
# Auth overlay
%{_libexecdir}/bioauth-overlay

# KCM plugin
%{_libdir}/qt6/plugins/plasma/kcms/libkcm_bioauth_fingerprint.so
%{_libdir}/qt6/plugins/plasma/kcms/kcm_bioauth_fingerprint.json

# Plasmoid
%{_datadir}/plasma/plasmoids/org.bioauth.plasmoid/

%changelog
* Wed Jan 01 2025 BioAuth Project <bioauth@localhost> - 0.1.0-1
- Initial Fedora package
- PAM module with fingerprint authentication
- D-Bus daemon with systemd integration
- TPM 2.0 key sealing
- FIDO2/CTAP2 platform authenticator
- PolicyKit policy for privilege management
- SELinux policy module
- udev rules for fingerprint reader hotplug
- fprintd-compatible D-Bus API for GDM integration
- Socket activation support
- Man pages for all components
