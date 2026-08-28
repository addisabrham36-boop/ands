#!/usr/bin/env bash
# ==============================================================================
#  ANDS SENTINEL v2.0 - Uninstaller
# ==============================================================================

set -e

if [ "$EUID" -ne 0 ]; then
    echo "[-] Error: Please run the uninstaller with sudo."
    exit 1
fi

echo "[*] Removing ANDS binaries and desktop integration..."

rm -f /usr/local/bin/ANDS-shell
rm -f /usr/local/bin/ands
rm -f /usr/local/bin/ands-dashboard
rm -f /usr/share/applications/ands-sentinel.desktop
rm -f /usr/share/icons/hicolor/scalable/apps/ands-sentinel.png

echo "[+] ANDS Sentinel uninstalled successfully."
