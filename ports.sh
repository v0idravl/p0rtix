#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${1:-}"
OUTPUT_BASE="${2:-}"
source "$SCRIPT_DIR/log_utils.sh"
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
NMAP_STATS_EVERY="${NMAP_STATS_EVERY:-3m}"

log_info "Running discovery scans for $TARGET"

log_info "Running fast TCP discovery scan"
nmap -n --reason -sS -Pn --top-ports 1000 --open \
  --stats-every "$NMAP_STATS_EVERY" \
  -oA "$FAST_TCP_BASE" "$TARGET"

log_info "Running full TCP discovery scan"
nmap -n --reason -sS -Pn -p- --open \
  --min-rate 2000 --max-retries 2 --stats-every "$NMAP_STATS_EVERY" \
  -oA "$FULL_TCP_BASE" "$TARGET"

log_info "Running top 100 UDP scan"
nmap -n -sU -T4 -Pn --top-ports 100 --stats-every "$NMAP_STATS_EVERY" \
  -oA "$UDP_BASE" "$TARGET"

OPEN_TCP_PORTS=$(awk -F'[:/, ]+' '/Ports:/{for(i=1;i<=NF;i++) if($(i+1)=="open") print $i}' "$FULL_TCP_BASE.gnmap" | sort -nu | paste -sd,)
OPEN_TCP_PORTS="$(normalize_port_list "$OPEN_TCP_PORTS")"
OPEN_UDP_PORTS=$(awk -F'[:/, ]+' '/Ports:/{for(i=1;i<=NF;i++) if($(i+1)=="open" || $(i+1)=="open|filtered") print $i}' "$UDP_BASE.gnmap" | sort -nu | paste -sd,)
OPEN_UDP_PORTS="$(normalize_port_list "$OPEN_UDP_PORTS")"

if [ -n "$OPEN_TCP_PORTS" ]; then
  printf '%s\n' "$OPEN_TCP_PORTS" | tr ',' '\n' > "$SCAN_DIR/open_tcp_ports.txt"
  echo "$OPEN_TCP_PORTS" > "$SCAN_DIR/open_tcp_ports.csv"
else
  : > "$SCAN_DIR/open_tcp_ports.txt"
  : > "$SCAN_DIR/open_tcp_ports.csv"
fi

if [ -n "$OPEN_UDP_PORTS" ]; then
  printf '%s\n' "$OPEN_UDP_PORTS" | tr ',' '\n' > "$SCAN_DIR/open_udp_ports.txt"
  echo "$OPEN_UDP_PORTS" > "$SCAN_DIR/open_udp_ports.csv"
else
  : > "$SCAN_DIR/open_udp_ports.txt"
  : > "$SCAN_DIR/open_udp_ports.csv"
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
echo "$OPEN_UDP_PORTS" > "$SCAN_DIR/non_web_udp_ports.txt"

if [ -n "$OPEN_TCP_PORTS" ]; then
  log_info "Running version scan against open TCP ports: $OPEN_TCP_PORTS"
  log_info "Running TCP version detection"
  nmap -n -sS -sV --version-light -sC -O -Pn -p "$OPEN_TCP_PORTS" \
    --stats-every "$NMAP_STATS_EVERY" \
    -oA "$VERSION_BASE" "$TARGET"
else
  log_info "No open TCP ports found; skipping version scan."
fi

log_info "Discovery complete. Scan results saved under $SCAN_DIR"
