#!/usr/bin/env bash
# =============================================================================
# Hiya — Universal Installer (FIXED)
#
# Fixes applied vs original install.sh:
#   FIX-1: Service unit ExecStart path mismatch
#          Original: service file hardcodes /usr/sbin/hiya-authd but
#          meson's default prefix is /usr/local, so binary lands at
#          /usr/local/sbin/hiya-authd → status=203/EXEC at boot.
#          Fix: force --prefix=/usr in meson setup so binaries and service
#          unit agree on /usr/sbin. If prefix is overridden, patch the
#          installed service unit to match before daemon-reload.
#
#   FIX-2: install.sh run as root loses $XDG_CURRENT_DESKTOP → DE detection
#          fails → wrong PAM files targeted. Fix: read DE from the sudo
#          user's environment explicitly.
#
# Usage: sudo ./install_fixed.sh [install|uninstall|status|enroll]
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()   { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()     { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()   { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()  { echo -e "${RED}[ERROR]${NC} $*"; }
header() { echo; echo -e "${BOLD}${CYAN}── $* ${NC}"; echo; }
die()    { error "$*"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build"

# FIX-1: Always use /usr as prefix so service unit ExecStart paths match
# installed binary paths. The original code didn't set --prefix, so meson
# defaulted to /usr/local but the service file hardcodes /usr/sbin.
INSTALL_PREFIX="/usr"

PAM_DIR="/etc/pam.d"
BACKUP_SUFFIX=".hiya-backup"
STATE_DIR="/var/lib/hiya"
RUN_DIR="/run/hiya"

require_root() {
    [[ $EUID -eq 0 ]] || die "Run as root: sudo ./install_fixed.sh $*"
}

get_sudo_user() {
    echo "${SUDO_USER:-$(logname 2>/dev/null || echo "")}"
}

detect_distro() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        source /etc/os-release
        DISTRO_ID="${ID:-unknown}"
        DISTRO_LIKE="${ID_LIKE:-}"
    else
        DISTRO_ID="unknown"
        DISTRO_LIKE=""
    fi
    case "$DISTRO_ID" in
        fedora|rhel|centos|almalinux|rocky) DISTRO_FAMILY="fedora" ;;
        ubuntu|debian|linuxmint|pop)        DISTRO_FAMILY="debian" ;;
        arch|manjaro|endeavouros|garuda)    DISTRO_FAMILY="arch"   ;;
        opensuse*|sles*)                    DISTRO_FAMILY="suse"   ;;
        *)
            case "$DISTRO_LIKE" in
                *fedora*|*rhel*)   DISTRO_FAMILY="fedora" ;;
                *debian*|*ubuntu*) DISTRO_FAMILY="debian" ;;
                *arch*)            DISTRO_FAMILY="arch"   ;;
                *suse*)            DISTRO_FAMILY="suse"   ;;
                *)                 DISTRO_FAMILY="unknown" ;;
            esac
            ;;
    esac
    info "Detected: ${DISTRO_ID} (family: ${DISTRO_FAMILY})"
}

detect_de() {
    # FIX-2: When running as root via sudo, XDG_CURRENT_DESKTOP is often
    # unset. Read it from the invoking user's environment instead.
    local sudo_user
    sudo_user=$(get_sudo_user)
    local user_de=""
    if [[ -n "$sudo_user" ]]; then
        # Try to read from the user's systemd session environment
        user_de=$(sudo -u "$sudo_user" \
            systemctl --user show-environment 2>/dev/null \
            | grep "^XDG_CURRENT_DESKTOP=" \
            | cut -d= -f2- || true)
        # Fallback: check DBUS_SESSION_BUS_ADDRESS environment
        if [[ -z "$user_de" ]]; then
            user_de=$(sudo -u "$sudo_user" \
                sh -c 'echo "${XDG_CURRENT_DESKTOP:-}"' 2>/dev/null || true)
        fi
    fi
    DE="${user_de:-${XDG_CURRENT_DESKTOP:-${DESKTOP_SESSION:-}}}"
    DE="${DE,,}"

    if [[ "$DE" == *kde* || "$DE" == *plasma* ]]; then
        DE_FAMILY="kde"
    elif [[ "$DE" == *gnome* ]]; then
        DE_FAMILY="gnome"
    elif [[ "$DE" == *xfce* ]]; then
        DE_FAMILY="xfce"
    elif [[ "$DE" == *sway* || "$DE" == *hyprland* || "$DE" == *wlroots* ]]; then
        DE_FAMILY="wlroots"
    else
        DE_FAMILY="unknown"
    fi

    if systemctl is-active --quiet sddm 2>/dev/null; then DM="sddm"
    elif systemctl is-active --quiet gdm 2>/dev/null; then DM="gdm"
    elif systemctl is-active --quiet lightdm 2>/dev/null; then DM="lightdm"
    else DM="unknown"; fi

    info "Desktop: ${DE_FAMILY:-unknown}, Display manager: ${DM}"
}

install_build_deps() {
    header "Installing build dependencies"
    case "$DISTRO_FAMILY" in
        fedora)
            dnf install -y \
                meson ninja-build gcc gcc-c++ \
                mbedtls-devel libfprint-devel glib2-devel dbus-devel \
                systemd-devel libcurl-devel pam-devel \
                libX11-devel libXtst-devel wayland-devel
            ;;
        debian)
            apt-get update -qq
            apt-get install -y \
                meson ninja-build gcc g++ pkg-config \
                libmbedtls-dev libfprint-2-dev libglib2.0-dev libdbus-1-dev \
                libsystemd-dev libcurl4-openssl-dev libpam0g-dev \
                libx11-dev libxtst-dev libwayland-dev libpsl-dev
            apt-get install -y libfprint-2-tod1 2>/dev/null || true
            ;;
        arch)
            pacman -S --needed --noconfirm \
                meson ninja gcc mbedtls libfprint glib2 dbus \
                systemd-libs curl pam libx11 libxtst wayland libpsl
            ;;
        suse)
            zypper install -y \
                meson ninja gcc gcc-c++ mbedtls-devel libfprint-devel \
                glib2-devel dbus-1-devel systemd-devel libcurl-devel \
                pam-devel libX11-devel libXtst-devel wayland-devel
            ;;
        *)
            warn "Unknown distro — install deps manually."
            ;;
    esac
    ok "Dependencies installed"
}

ensure_hiya_group() {
    header "Ensuring hiya group"
    if ! getent group hiya &>/dev/null; then
        groupadd --system hiya
        ok "Group 'hiya' created"
    else
        ok "Group 'hiya' exists"
    fi
    local user
    user=$(get_sudo_user)
    if [[ -n "$user" ]]; then
        if ! id -nG "$user" | tr ' ' '\n' | grep -qx "hiya"; then
            usermod -aG hiya "$user"
            warn "Added '${user}' to hiya group (log out/in required)"
        else
            ok "User '${user}' already in hiya group"
        fi
    fi
}

ensure_uhid_module() {
    header "Ensuring UHID support"
    if [[ ! -c /dev/uhid ]]; then
        modprobe uhid 2>/dev/null || warn "Failed to load uhid"
    fi
    if [[ -c /dev/uhid ]]; then
        install -d -m 755 /etc/modules-load.d
        echo "uhid" > /etc/modules-load.d/hiya.conf
        ok "uhid: present and configured for boot"
    else
        warn "/dev/uhid missing — browser passkeys will not work"
    fi
}

detect_pam_libdir() {
    # Resolve the correct libdir (the parent of the 'security' folder)
    # by checking actual filesystem paths in priority order.
    #
    # Distro map:
    #   Fedora/RHEL/CentOS (x86_64) → /usr/lib64/security  → libdir=/usr/lib64
    #   Debian/Ubuntu (x86_64)      → /usr/lib/x86_64-linux-gnu/security → libdir=/usr/lib/x86_64-linux-gnu
    #   Arch Linux                  → /usr/lib/security     → libdir=/usr/lib
    #   openSUSE (x86_64)           → /usr/lib64/security   → libdir=/usr/lib64
    #   Generic fallback            → /usr/lib/security     → libdir=/usr/lib
    #
    # We prefer the path that already exists on disk. If none do, we fall
    # back to the multiarch path on Debian/Ubuntu (detected via dpkg), then
    # lib64 on rpm-based systems, then plain lib.

    local candidates=(
        "/usr/lib64/security"                          # Fedora, RHEL, openSUSE
        "/usr/lib/$(dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null)/security" # Debian/Ubuntu multiarch
        "/usr/lib/security"                            # Arch, generic
    )

    for dir in "${candidates[@]}"; do
        # Skip if the dpkg-architecture call produced a broken path (no multiarch)
        [[ "$dir" == */security ]] || continue
        if [[ -d "$dir" ]]; then
            PAM_LIBDIR="$dir"
            info "PAM security dir: ${PAM_LIBDIR}"
            return
        fi
    done

    # Hard fallback — should never reach here on a working PAM system
    PAM_LIBDIR="/usr/lib/security"
    warn "Could not detect PAM security dir — falling back to ${PAM_LIBDIR}"
}

build_hiya() {
    header "Building Hiya"

    detect_pam_libdir
    # libdir is the PARENT of the 'security' folder.
    # meson's pam/meson.build does: install_dir = join_paths(get_option('libdir'), 'security')
    # so we must pass the parent, not the full path.
    local MESON_LIBDIR="${PAM_LIBDIR%/security}"

    if [[ -f "${BUILD_DIR}/build.ninja" ]]; then
        info "Build dir exists — rebuilding"
        touch "${SCRIPT_DIR}/src/daemon/bio_daemon.c" "${SCRIPT_DIR}/src/pam/pam_hiya.c"
        ninja -C "${BUILD_DIR}"
    else
        # Use -Dlibdir only (not --libdir) — passing both causes:
        # "Got argument libdir as both -Dlibdir and --libdir. Pick one."
        meson setup "${BUILD_DIR}" "${SCRIPT_DIR}" \
            --prefix="${INSTALL_PREFIX}" \
            -Dlibdir="${MESON_LIBDIR}" \
            --buildtype=release \
            -Db_lto=true \
            -Db_pie=true
        ninja -C "${BUILD_DIR}"
    fi
    ok "Build complete"
}

remove_fprintd() {
    header "Removing fprintd"
    systemctl stop fprintd 2>/dev/null || true
    systemctl disable fprintd 2>/dev/null || true
    systemctl mask fprintd 2>/dev/null || true
    ok "fprintd stopped and masked"

    for pam_file in "${PAM_DIR}"/system-auth "${PAM_DIR}"/common-auth \
                    "${PAM_DIR}"/gdm-fingerprint "${PAM_DIR}"/kde-fingerprint \
                    "${PAM_DIR}"/sudo "${PAM_DIR}"/sddm; do
        if [[ -f "$pam_file" ]] && grep -q "pam_fprintd" "$pam_file" 2>/dev/null; then
            [[ ! -f "${pam_file}${BACKUP_SUFFIX}" ]] && cp -a "$pam_file" "${pam_file}${BACKUP_SUFFIX}"
            sed -i '/pam_fprintd/d' "$pam_file"
            ok "Removed pam_fprintd from $pam_file"
        fi
    done
}

install_binaries() {
    # Remove stale binary at /usr/bin if present
    rm -f /usr/bin/hiya-authd
    header "Installing Hiya"

    ninja -C "${BUILD_DIR}" install

    # FIX-1 safety net: even if someone calls with a different prefix at
    # meson-setup time, patch the installed service unit's ExecStart to
    # point at wherever the binary actually landed.
    local actual_bin
    actual_bin=$(find /usr/sbin /usr/local/sbin -name "hiya-authd" 2>/dev/null | head -1)
    local installed_svc=""
    for svc_path in /usr/lib/systemd/system /usr/local/lib/systemd/system \
                    /lib/systemd/system; do
        if [[ -f "${svc_path}/hiya-authd.service" ]]; then
            installed_svc="${svc_path}/hiya-authd.service"
            break
        fi
    done

    if [[ -n "$actual_bin" && -n "$installed_svc" ]]; then
        local svc_bin
        svc_bin=$(grep "^ExecStart=" "$installed_svc" | cut -d= -f2- | awk '{print $1}')
        if [[ "$svc_bin" != "$actual_bin" ]]; then
            warn "Service ExecStart mismatch: unit says '$svc_bin', binary is '$actual_bin'"
            sed -i "s|^ExecStart=.*|ExecStart=${actual_bin}|" "$installed_svc"
            ok "Patched ExecStart in ${installed_svc} → ${actual_bin}"
        fi
    fi

    install -d -m 750 -o root -g hiya "${STATE_DIR}"
    install -d -m 750 -o root -g hiya "${STATE_DIR}/fido2"
    install -d -m 755 -o root -g hiya "${RUN_DIR}"

    dbus-send --system --type=method_call --dest=org.freedesktop.DBus \
        / org.freedesktop.DBus.ReloadConfig 2>/dev/null || true
    udevadm control --reload-rules 2>/dev/null || true
    udevadm trigger 2>/dev/null || true

    ok "Installed to ${INSTALL_PREFIX}"
}

# PAM line: success=done means fingerprint matched → skip remaining auth modules
# (no password needed). default=ignore means any failure → fall through to
# next module (password prompt). No try_first — we never block on fingerprint.
PAM_HIYA_LINE='auth  [success=done new_authtok_reqd=done default=ignore]  pam_hiya.so timeout=15'

# Insert the hiya line into a PAM file correctly, handling every case:
#
#  Case A — file has a standalone auth line (not just includes):
#            Insert BEFORE the first auth line so fingerprint runs first.
#
#  Case B — file has ONLY include/substack lines (e.g. Fedora sudo):
#            Insert BEFORE the first auth include line. PAM processes the
#            file top-to-bottom, so our line runs before the include expands.
#
#  Case C — file has no auth lines at all:
#            Append at end (rare, but safe).
#
# In all cases, skip if already configured.
insert_pam_hiya() {
    local target="$1"
    [[ -f "$target" ]] || return 0
    if grep -q "pam_hiya" "$target" 2>/dev/null; then
        ok "  $(basename $target): already configured"
        return 0
    fi
    [[ ! -f "${target}${BACKUP_SUFFIX}" ]] && cp -a "$target" "${target}${BACKUP_SUFFIX}"
    # Insert before first auth line (real module or include)
    sed -i "0,/^auth/{/^auth/i ${PAM_HIYA_LINE}
}" "$target"
    chmod 644 "$target"
    ok "  $(basename $target): Hiya fingerprint auth added"
}

wire_pam() {
    header "Configuring PAM authentication"
    # Patch every PAM file that has auth lines — distro-agnostic
    for f in "${PAM_DIR}"/*; do
        [[ -f "$f" ]] || continue
        [[ "$f" == *.hiya-backup ]] && continue
        [[ "$(basename $f)" == "hiya" ]] && continue
        grep -q "^auth" "$f" 2>/dev/null || continue
        insert_pam_hiya "$f"
    done
    ok "PAM configuration complete"
}


start_services() {
    header "Starting Hiya services"
    systemctl daemon-reload
    systemctl enable --now hiya-authd.service
    ok "hiya-authd: started and enabled"
    systemctl enable --now hiya-fido2.service
    ok "hiya-fido2: started and enabled"

    local user
    user=$(get_sudo_user)
    if [[ -n "$user" ]]; then
        systemctl --user -M "${user}@" enable hiya-portal.service 2>/dev/null || \
        sudo -u "$user" systemctl --user enable hiya-portal.service 2>/dev/null || \
        warn "Could not enable hiya-portal for ${user} — run manually as ${user}"
    fi
}

verify_install() {
    header "Verifying installation"
    local all_ok=true

    if systemctl is-active --quiet hiya-authd.service; then
        ok "hiya-authd: running"
    else
        error "hiya-authd: NOT running"
        journalctl -u hiya-authd --no-pager -n 20
        all_ok=false
    fi

    if systemctl is-active --quiet hiya-fido2.service; then
        ok "hiya-fido2: running"
    else
        error "hiya-fido2: NOT running"
        all_ok=false
    fi

    [[ -c /dev/uhid ]] && ok "/dev/uhid: present" || { error "/dev/uhid: missing"; all_ok=false; }

    local user; user=$(get_sudo_user)
    if [[ -n "$user" ]]; then
        id -nG "$user" | tr ' ' '\n' | grep -qx "hiya" \
            && ok "User '${user}': in hiya group" \
            || warn "User '${user}' not in hiya group (log out/in)"
    fi

    if gdbus introspect --system \
        --dest net.reactivated.Fprint \
        --object-path /net/reactivated/Fprint/Manager \
        &>/dev/null; then
        ok "fprintd compat: responding on D-Bus"
    else
        warn "fprintd compat: D-Bus not responding yet (daemon may still be starting)"
    fi

    local pam_so
    pam_so=$(find /usr/lib /usr/lib64 /lib /lib64 -name "pam_hiya.so" 2>/dev/null | head -1)
    [[ -n "$pam_so" ]] && ok "PAM module: ${pam_so}" || { error "PAM module: not found"; all_ok=false; }

    echo
    $all_ok && ok "Installation complete and healthy" || error "Installation has issues — check above"
}

print_next_steps() {
    local user; user=$(get_sudo_user)
    echo
    echo -e "${BOLD}${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}  Hiya installed. Next: enroll your fingerprint.${NC}"
    echo -e "${BOLD}${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo
    echo -e "  ${BOLD}1. Enroll fingerprint (run as yourself, not root):${NC}"
    echo -e "     ${CYAN}hiya-enroll --finger 2 --label 'right index'${NC}"
    echo -e "     (1=left-thumb  2=left-index  3=left-middle ... 10=right-little)"
    echo
    echo -e "  ${BOLD}NOTE for Goodix MOC / any on-chip storage sensor:${NC}"
    echo -e "     If enrollment fails with 'already enrolled', clear the sensor first:"
    echo -e "     ${CYAN}sudo dbus-send --system --print-reply \\"
    echo -e "       --dest=org.hiya.Manager /org/hiya/Manager \\"
    echo -e "       org.hiya.Manager.ClearDevice${NC}"
    echo -e "     Then re-enroll. The daemon now does this automatically on retry."
    echo
    echo -e "  ${BOLD}2. Test:${NC}"
    echo -e "     ${CYAN}hiya-verify${NC}       ← raw verify"
    echo -e "     ${CYAN}sudo -k && sudo ls${NC}   ← test PAM sudo"
    echo
    echo -e "  ${BOLD}Logs:${NC}  journalctl -u hiya-authd -f"
    echo
}

do_enroll() {
    echo -e "${BOLD}Hiya Fingerprint Enrollment${NC}"
    echo
    echo "Finger map:  1=left-thumb  2=left-index  3=left-middle  4=left-ring  5=left-little"
    echo "             6=right-thumb 7=right-index 8=right-middle 9=right-ring 10=right-little"
    echo
    read -rp "Finger to enroll [2 = right index]: " finger
    finger="${finger:-2}"
    read -rp "Label [right index]: " label
    label="${label:-right index}"
    hiya-enroll --finger "$finger" --label "$label"
}

do_status() {
    header "Hiya Status"
    for svc in hiya-authd hiya-fido2; do
        local status
        status=$(systemctl is-active "$svc" 2>/dev/null || echo "inactive")
        [[ "$status" == "active" ]] && ok "${svc}: running" || warn "${svc}: ${status}"
    done
    echo
    echo "Enrolled fingers (current user):"
    hiya-enroll --list 2>/dev/null || echo "  (not enrolled or daemon not running)"
}

do_uninstall() {
    header "Uninstalling Hiya"
    require_root uninstall
    systemctl stop hiya-fido2.service 2>/dev/null || true

    # Clear on-chip templates BEFORE stopping daemon (MOC sensors like Goodix
    # store templates on-chip; leaving them causes "already enrolled" on reinstall)
    if systemctl is-active --quiet hiya-authd.service 2>/dev/null; then
        dbus-send --system --print-reply \
            --dest=org.hiya.Manager /org/hiya/Manager \
            org.hiya.Manager.ClearDevice 2>/dev/null && \
            ok "Cleared on-chip fingerprint templates" || \
            warn "Could not clear on-chip templates (non-storage device or unavailable)"
    fi

    systemctl stop hiya-authd.service 2>/dev/null || true
    systemctl disable hiya-fido2.service hiya-authd.service 2>/dev/null || true
    ok "Stopped and disabled services"

    # Delete fingerprint enrollment data but KEEP FIDO2/SSH credentials
    # (passkeys and SSH keys are tied to external services — deleting them
    # would invalidate GitHub passkeys, SSH keys, etc.)
    if [[ -d /var/lib/hiya ]]; then
        rm -rf /var/lib/hiya/users
        rm -f /var/lib/hiya/enrollment_hmac.key
        ok "Deleted fingerprint enrollment data"
        ok "Preserved FIDO2/SSH credentials (/var/lib/hiya/fido2)"
    fi

    # Restore PAM backups first
    for f in "${PAM_DIR}"/*"${BACKUP_SUFFIX}"; do
        [[ -f "$f" ]] || continue
        mv "$f" "${f%${BACKUP_SUFFIX}}"
        ok "Restored: ${f%${BACKUP_SUFFIX}}"
    done
    # Remove hiya lines from ALL pam files (catches files with no backup)
    for f in "${PAM_DIR}"/*; do
        [[ -f "$f" ]] || continue
        [[ "$f" == *.hiya-backup ]] && continue
        grep -q "pam_hiya" "$f" 2>/dev/null || continue
        sed -i '/pam_hiya/d;/Hiya fingerprint/d' "$f"
        ok "Cleaned: $(basename $f)"
    done
    # Delete leftover backups so next install starts clean
    rm -f "${PAM_DIR}"/*"${BACKUP_SUFFIX}"

    systemctl unmask fprintd 2>/dev/null || true
    systemctl enable --now fprintd 2>/dev/null || warn "Could not re-enable fprintd"
    ok "Re-enabled fprintd"

    [[ -f "${BUILD_DIR}/meson-info/intro-targets.json" ]] && \
        ninja -C "${BUILD_DIR}" uninstall 2>/dev/null || \
        warn "meson uninstall not available"
    ok "Hiya removed."
}


main() {
    local cmd="${1:-install}"
    case "$cmd" in
        install)
            require_root install
            echo
            echo -e "${BOLD}${CYAN}  Hiya — Fixed Installer${NC}"
            echo
            detect_distro
            detect_de
            install_build_deps
            build_hiya
            remove_fprintd
            ensure_hiya_group
            ensure_uhid_module
            install_binaries
            wire_pam
            start_services
            verify_install
            print_next_steps
            ;;
        uninstall|remove) detect_distro; do_uninstall ;;
        status|check)     do_status ;;
        enroll)           do_enroll ;;
        *)
            echo "Usage: sudo ./install_fixed.sh [install|uninstall|status|enroll]"
            exit 1
            ;;
    esac
}

main "$@"