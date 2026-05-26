# Hiya

Fingerprint authentication for Linux. Handles sudo, su, polkit, screen unlock, SSH keys, and browser passkeys from a single enrollment.

Replaces fprintd. Works with existing DEs without patching them.

## Requirements

- libfprint-supported fingerprint sensor
- Linux with PAM, systemd, D-Bus
- TPM 2.0 optional (used for sealing enrollment data)

## Install

```bash
sudo ./install.sh install
```

Installs build dependencies, compiles, wires PAM, starts the daemon.

Then enroll (as yourself, not root):

```bash
hiya-enroll --finger 2 --label "right index"
hiya-verify
sudo -k && sudo whoami
```

Finger numbers: 1–5 = left thumb to little, 6–10 = right thumb to little.

## Uninstall

```bash
sudo ./install.sh uninstall
```

Clears on-chip templates and removes enrollment data. FIDO2 credentials and SSH keys in `/var/lib/hiya/fido2/` are kept. To wipe those too:

```bash
sudo rm -rf /var/lib/hiya
```

## Commands


```
hiya-enroll --finger N --label "name"   enroll a finger
hiya-enroll --list                       list enrollments
hiya-enroll --delete --finger N          delete one finger
hiya-enroll --delete-all                 delete all
hiya-verify                              test verification
hiya-cli                                 interactive shell
sudo ./install.sh status                    daemon status
```

## What gets patched

Install wires `pam_hiya.so` into every PAM file on the system that has auth lines. Uninstall restores all backups. The PAM line uses `default=ignore` so a failed or timed-out fingerprint always falls through to password — it never blocks login.

## Supported distros

Fedora, RHEL, Ubuntu, Debian, Arch, openSUSE. Unknown distros: install deps manually, then run `sudo ./install.sh`.

## Build manually

```bash
meson setup build --prefix=/usr
ninja -C build
sudo ninja -C build install
```

Dependencies: `meson ninja gcc libfprint-2 glib2 dbus pam mbedtls libcurl systemd`

## Security

See [SECURITY.md](SECURITY.md).
