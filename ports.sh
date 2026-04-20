#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${1:-}"
OUTPUT_BASE="${2:-}"
source "$SCRIPT_DIR/port_utils.sh"

usage() {
  cat <<USAGE
Usage: $0 <target-ip-or-hostname> <output-base-dir>

Example:
  $0 10.10.10.10 /home/user/Projects/p0rtix/output/10.10.10.10
USAGE
  exit 1
}

if [ -z "$TARGET" ] || [ -z "$OUTPUT_BASE" ]; then
  usage
fi

SCAN_DIR="$OUTPUT_BASE/scans"
mkdir -p "$SCAN_DIR"

FAST_TCP_BASE="$SCAN_DIR/fast_tcp"
FULL_TCP_BASE="$SCAN_DIR/full_tcp"
UDP_BASE="$SCAN_DIR/top_100_udp"
VERSION_BASE="$SCAN_DIR/service_version"

echo "Running discovery scans for $TARGET"

CMD_FAST="nmap -n --reason -sS -Pn --top-ports 1000 --open -oA \"$FAST_TCP_BASE\" \"$TARGET\""
echo "[*] $CMD_FAST"
nmap -n --reason -sS -Pn --top-ports 1000 --open \
  -oA "$FAST_TCP_BASE" "$TARGET"
printf "\n# Command: $CMD_FAST\n\n" | cat - "$FAST_TCP_BASE.nmap" > "$FAST_TCP_BASE.tmp" && mv "$FAST_TCP_BASE.tmp" "$FAST_TCP_BASE.nmap"

CMD_FULL="nmap -n --reason -sS -Pn -p- --open --min-rate 2000 --max-retries 2 --stats-every 60s -oA \"$FULL_TCP_BASE\" \"$TARGET\""
echo "[*] $CMD_FULL"
nmap -n --reason -sS -Pn -p- --open \
  --min-rate 2000 --max-retries 2 --stats-every 60s \
  -oA "$FULL_TCP_BASE" "$TARGET"
printf "\n# Command: $CMD_FULL\n\n" | cat - "$FULL_TCP_BASE.nmap" > "$FULL_TCP_BASE.tmp" && mv "$FULL_TCP_BASE.tmp" "$FULL_TCP_BASE.nmap"

CMD_UDP="nmap -n -sU -T4 -Pn --top-ports 100 --stats-every 60s -oA \"$UDP_BASE\" \"$TARGET\""
echo "[*] $CMD_UDP"
nmap -n -sU -T4 -Pn --top-ports 100 --stats-every 60s \
  -oA "$UDP_BASE" "$TARGET"
printf "\n# Command: $CMD_UDP\n\n" | cat - "$UDP_BASE.nmap" > "$UDP_BASE.tmp" && mv "$UDP_BASE.tmp" "$UDP_BASE.nmap"

OPEN_TCP_PORTS=$(awk -F'[:/, ]+' '/Ports:/{for(i=1;i<=NF;i++) if($(i+1)=="open") print $i}' "$FULL_TCP_BASE.gnmap" | sort -nu | paste -sd,)
OPEN_TCP_PORTS="$(normalize_port_list "$OPEN_TCP_PORTS")"

if [ -n "$OPEN_TCP_PORTS" ]; then
  printf '%s\n' "$OPEN_TCP_PORTS" | tr ',' '\n' > "$SCAN_DIR/open_tcp_ports.txt"
  echo "$OPEN_TCP_PORTS" > "$SCAN_DIR/open_tcp_ports.csv"
else
  : > "$SCAN_DIR/open_tcp_ports.txt"
  : > "$SCAN_DIR/open_tcp_ports.csv"
fi

if [ -n "$OPEN_TCP_PORTS" ]; then
  WEB_PORTS=$(printf '%s\n' "$OPEN_TCP_PORTS" | tr ',' '\n' | awk '/^(80|443)$/')
  NON_WEB_PORTS=$(printf '%s\n' "$OPEN_TCP_PORTS" | tr ',' '\n' | awk '!/^(80|443)$/')
  WEB_PORTS="$(printf '%s\n' "$WEB_PORTS" | paste -sd, -)"
  NON_WEB_PORTS="$(printf '%s\n' "$NON_WEB_PORTS" | paste -sd, -)"
else
  WEB_PORTS=""
  NON_WEB_PORTS=""
fi

echo "$WEB_PORTS" > "$SCAN_DIR/web_ports.txt"
echo "$NON_WEB_PORTS" > "$SCAN_DIR/non_web_ports.txt"

if [ -n "$OPEN_TCP_PORTS" ]; then
  echo "Running version scan against open TCP ports: $OPEN_TCP_PORTS"
  CMD_VERSION="nmap -n -sS -sV --version-light -sC -O -Pn -p \"$OPEN_TCP_PORTS\" -oA \"$VERSION_BASE\" \"$TARGET\""
  echo "[*] $CMD_VERSION"
  nmap -n -sS -sV --version-light -sC -O -Pn -p "$OPEN_TCP_PORTS" \
    -oA "$VERSION_BASE" "$TARGET"
  printf "\n# Command: $CMD_VERSION\n\n" | cat - "$VERSION_BASE.nmap" > "$VERSION_BASE.tmp" && mv "$VERSION_BASE.tmp" "$VERSION_BASE.nmap"
else
  echo "No open TCP ports found; skipping version scan."
fi

echo "Discovery complete. Scan results saved under $SCAN_DIR"
