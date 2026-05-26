#!/bin/bash
#
# hiya-kde-install.sh — KDE Plasma 6 integration installer
#
# Installs PAM configurations for seamless fingerprint authentication
# across all KDE Plasma 6 authentication points:
#
#   - SDDM login screen
#   - KScreenLocker (lock screen unlock)
#   - PolicyKit (privilege escalation dialogs)
#   - sudo/su (terminal)
#
# Usage: sudo ./hiya-kde-install.sh [install|uninstall|status]
#
# Copyright (C) 2025 Hiya Project
# SPDX-License-Identifier: GPL-3.0-or-later
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
PAM_DIR="/etc/pam.d"
HIYA_PAM="/usr/lib64/security/pam_hiya.so"
BACKUP_SUFFIX=".hiya-backup"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()  { echo -e "${BLUE}[INFO]${NC} $*"; }
log_ok()    { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

check_pam_module() {
    if [[ ! -f "$HIYA_PAM" ]]; then
        log_error "Hiya PAM module not found at $HIYA_PAM"
        log_error "Build and install Hiya first: meson install -C builddir"
        exit 1
    fi
    log_ok "PAM module found: $HIYA_PAM"
}

check_daemon() {
    if systemctl is-active --quiet hiya-authd.service 2>/dev/null; then
        log_ok "Hiya daemon is running"
    else
        log_warn "Hiya daemon is not running"
        log_warn "Start it: sudo systemctl enable --now hiya-authd.service"
    fi
}

check_enrollments() {
    if command -v hiya-enroll &>/dev/null; then
        local user
        user=$(logname 2>/dev/null || echo "$SUDO_USER")
        if hiya-enroll --list --user "$user" 2>/dev/null | grep -q "finger"; then
            log_ok "Fingerprint enrollments found for user $user"
        else
            log_warn "No fingerprint enrollments for user $user"
            log_warn "Enroll first: hiya-enroll --finger 2 --label 'right-index'"
        fi
    fi
}

backup_pam_file() {
    local pam_file="$1"
    if [[ -f "$pam_file" && ! -f "${pam_file}${BACKUP_SUFFIX}" ]]; then
        cp -a "$pam_file" "${pam_file}${BACKUP_SUFFIX}"
        log_info "Backed up: $pam_file → ${pam_file}${BACKUP_SUFFIX}"
    fi
}

install_pam_config() {
    local service="$1"
    local source="$2"
    local target="${PAM_DIR}/${service}"

    if [[ -f "$target" ]]; then
        # Check if Hiya is already integrated
        if grep -q "pam_hiya" "$target" 2>/dev/null; then
            log_ok "$service: Hiya already configured"
            return 0
        fi
        backup_pam_file "$target"
    fi

    cp "$source" "$target"
    chmod 644 "$target"
    log_ok "$service: Hiya PAM config installed"
}

do_install() {
    log_info "Installing Hiya KDE Plasma 6 integration..."
    echo

    check_pam_module
    check_daemon
    check_enrollments
    echo

    # Install PAM configs
    local kde_dir="${PROJECT_ROOT}/config/kde/pam.d"

    # SDDM login
    if [[ -f "${kde_dir}/sddm" ]]; then
        install_pam_config "sddm" "${kde_dir}/sddm"
    fi

    # KScreenLocker
    if [[ -f "${kde_dir}/kde" ]]; then
        install_pam_config "kde" "${kde_dir}/kde"
    fi

    # PolicyKit (only if not already customized)
    if [[ -f "${kde_dir}/polkit-1" ]]; then
        install_pam_config "polkit-1" "${kde_dir}/polkit-1"
    fi

    # Also configure sudo if not already done
    if ! grep -q "pam_hiya" "${PAM_DIR}/sudo" 2>/dev/null; then
        backup_pam_file "${PAM_DIR}/sudo"
        # Prepend hiya to sudo
        local tmp
        tmp=$(mktemp)
        {
            echo "# Hiya fingerprint auth for sudo"
            echo "auth      [success=2 default=ignore]  pam_hiya.so timeout=30"
            cat "${PAM_DIR}/sudo"
        } > "$tmp"
        mv "$tmp" "${PAM_DIR}/sudo"
        chmod 644 "${PAM_DIR}/sudo"
        log_ok "sudo: Hiya fingerprint auth prepended"
    else
        log_ok "sudo: Hiya already configured"
    fi

    echo
    log_ok "KDE Plasma 6 integration complete!"
    echo
    echo "  Integration points:"
    echo "    ✓ SDDM login screen       → fingerprint login"
    echo "    ✓ KScreenLocker            → fingerprint unlock"
    echo "    ✓ PolicyKit dialogs        → fingerprint for admin"
    echo "    ✓ sudo/su                  → fingerprint in terminal"
    echo
    echo "  fprintd compatibility (already active):"
    echo "    ✓ KDE System Settings      → recognizes enrolled fingers"
    echo "    ✓ GNOME Settings           → cross-DE enrollment sharing"
    echo
    echo "  To test: lock your screen (Super+L) and touch the sensor."
}

do_uninstall() {
    log_info "Removing Hiya KDE integration..."
    echo

    for service in sddm kde polkit-1 sudo; do
        local target="${PAM_DIR}/${service}"
        local backup="${target}${BACKUP_SUFFIX}"

        if [[ -f "$backup" ]]; then
            mv "$backup" "$target"
            log_ok "$service: restored original PAM config"
        elif grep -q "pam_hiya" "$target" 2>/dev/null; then
            # Remove hiya lines from the file
            sed -i '/pam_hiya/d' "$target"
            sed -i '/Hiya fingerprint/d' "$target"
            log_ok "$service: removed Hiya lines"
        else
            log_info "$service: no Hiya config found"
        fi
    done

    echo
    log_ok "Hiya KDE integration removed. Original PAM configs restored."
}

do_status() {
    echo "Hiya KDE Plasma 6 Integration Status"
    echo "========================================"
    echo

    # PAM module
    if [[ -f "$HIYA_PAM" ]]; then
        log_ok "PAM module: installed"
    else
        log_error "PAM module: not found"
    fi

    # Daemon
    if systemctl is-active --quiet hiya-authd.service 2>/dev/null; then
        log_ok "Daemon: running"
    else
        log_warn "Daemon: not running"
    fi

    # fprintd compat
    if systemctl is-active --quiet hiya-authd.service 2>/dev/null &&
       gdbus introspect -y -d net.reactivated.Fprint -o /net/reactivated/Fprint/Manager &>/dev/null; then
        log_ok "fprintd compatibility: active"
    else
        log_warn "fprintd compatibility: inactive"
    fi

    echo
    echo "PAM Service Configurations:"
    for service in sddm kde polkit-1 sudo; do
        local target="${PAM_DIR}/${service}"
        if [[ -f "$target" ]] && grep -q "pam_hiya" "$target" 2>/dev/null; then
            log_ok "  $service: Hiya enabled"
        elif [[ -f "$target" ]]; then
            log_warn "  $service: exists but no Hiya"
        else
            log_info "  $service: not present"
        fi
    done

    echo
    echo "Enrollment Status:"
    check_enrollments
}

# ── Main ──────────────────────────────────────────────────────

case "${1:-status}" in
    install)
        check_root
        do_install
        ;;
    uninstall|remove)
        check_root
        do_uninstall
        ;;
    status|check)
        do_status
        ;;
    *)
        echo "Usage: $0 {install|uninstall|status}"
        echo
        echo "Commands:"
        echo "  install     Install Hiya PAM configs for KDE Plasma 6"
        echo "  uninstall   Remove Hiya configs, restore originals"
        echo "  status      Show current integration status"
        exit 1
        ;;
esac
