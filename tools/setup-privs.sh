#!/usr/bin/env bash
#
# p0rtix privilege setup — run ONCE, with sudo. After this, p0rtix runs as your
# normal user with no sudo, ever:
#
#     sudo ./tools/setup-privs.sh
#     python3 p0rtix.py <ip> --name <name> --workspace <dir>
#
# What it changes (both reversible — see bottom of file):
#   1. Grants nmap the cap_net_raw capability so SYN/UDP scans work unprivileged.
#   2. Makes /etc/hosts group-writable so p0rtix can add vhost/domain entries.
#
# Note: an `apt upgrade` of nmap reinstalls the binary and drops the capability —
# re-run this script if SYN scans start failing after an update.
#
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "[!] Run with sudo:  sudo $0" >&2
    exit 1
fi

REAL_USER="${SUDO_USER:-$(logname 2>/dev/null || echo root)}"
REAL_GROUP="$(id -gn "$REAL_USER")"

NMAP="$(readlink -f "$(command -v nmap || true)" || true)"
if [[ -z "$NMAP" || ! -f "$NMAP" ]]; then
    echo "[!] nmap not found in PATH" >&2
    exit 1
fi

echo "[*] Granting nmap raw-socket capabilities: $NMAP"
setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$NMAP"
echo -n "    -> "; getcap "$NMAP"

echo "[*] Making /etc/hosts writable by group '$REAL_GROUP' (for vhost entries)"
chgrp "$REAL_GROUP" /etc/hosts
chmod g+w /etc/hosts
echo -n "    -> "; ls -l /etc/hosts

echo
echo "[+] Done — p0rtix now runs without sudo as $REAL_USER:"
echo "      python3 p0rtix.py <ip> --name <name> --workspace <dir>"
echo
echo "    To undo:"
echo "      sudo setcap -r '$NMAP'"
echo "      sudo chgrp root /etc/hosts && sudo chmod 644 /etc/hosts"
