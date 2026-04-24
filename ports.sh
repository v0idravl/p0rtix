#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${1:-}"
OUTPUT_BASE="${2:-}"
source "$SCRIPT_DIR/log_utils.sh"

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

# Keep the raw nmap artifacts grouped by scan purpose for easier review later.
FULL_TCP_BASE="$SCAN_DIR/full_tcp"
UDP_BASE="$SCAN_DIR/top_100_udp"
NMAP_STATS_EVERY="${NMAP_STATS_EVERY:-3m}"

extract_ports_from_gnmap() {
  local gnmap_file="$1"
  local proto="$2"
  local include_open_filtered="${3:-0}"

  # Grepable output is easier to post-process than the human-readable .nmap files.
  awk -v proto="$proto" -v include_open_filtered="$include_open_filtered" '
    /Ports: / {
      sub(/^.*Ports: /, "")
      split($0, entries, /, /)
      for (i in entries) {
        split(entries[i], fields, "/")
        port = fields[1]
        state = fields[2]
        entry_proto = fields[3]

        if (entry_proto != proto) {
          continue
        }
        if (state == "open" || (include_open_filtered && state == "open|filtered")) {
          print port
        }
      }
    }
  ' "$gnmap_file" | sort -nu
}

write_port_files() {
  local ports_csv="$1"
  local txt_file="$2"
  local csv_file="${3:-}"

  # Write both one-port-per-line and CSV variants so later steps can use whichever
  # format is more convenient without reparsing the raw nmap output.
  if [ -n "$ports_csv" ]; then
    printf '%s\n' "$ports_csv" | tr ',' '\n' > "$txt_file"
  else
    : > "$txt_file"
  fi

  if [ -n "$csv_file" ]; then
    if [ -n "$ports_csv" ]; then
      printf '%s\n' "$ports_csv" > "$csv_file"
    else
      : > "$csv_file"
    fi
  fi
}

log_info "Running discovery scans for $TARGET"

log_info "Running full TCP discovery scan"
nmap -n --reason -sS -Pn -p- --open \
  --min-rate 2000 --max-retries 2 --stats-every "$NMAP_STATS_EVERY" \
  -oA "$FULL_TCP_BASE" "$TARGET"

log_info "Running top 100 UDP scan"
nmap -n -sU -T4 -Pn --top-ports 100 --stats-every "$NMAP_STATS_EVERY" \
  -oA "$UDP_BASE" "$TARGET"

# TCP requires strictly open ports; UDP often leaves us with open|filtered.
OPEN_TCP_PORTS="$(extract_ports_from_gnmap "$FULL_TCP_BASE.gnmap" tcp | paste -sd, -)"
OPEN_UDP_PORTS="$(extract_ports_from_gnmap "$UDP_BASE.gnmap" udp 1 | paste -sd, -)"

write_port_files "$OPEN_TCP_PORTS" "$SCAN_DIR/open_tcp_ports.txt" "$SCAN_DIR/open_tcp_ports.csv"
write_port_files "$OPEN_UDP_PORTS" "$SCAN_DIR/open_udp_ports.txt" "$SCAN_DIR/open_udp_ports.csv"

if [ -n "$OPEN_TCP_PORTS" ]; then
  # Web handling is intentionally separate so HTTP-specific tooling stays isolated.
  WEB_PORTS="$(printf '%s\n' "$OPEN_TCP_PORTS" | tr ',' '\n' | awk '/^(80|443)$/' | paste -sd, -)"
  NON_WEB_PORTS="$(printf '%s\n' "$OPEN_TCP_PORTS" | tr ',' '\n' | awk '!/^(80|443)$/' | paste -sd, -)"
else
  WEB_PORTS=""
  NON_WEB_PORTS=""
fi

write_port_files "$WEB_PORTS" "$SCAN_DIR/web_ports.txt"
write_port_files "$NON_WEB_PORTS" "$SCAN_DIR/non_web_ports.txt"
write_port_files "$OPEN_UDP_PORTS" "$SCAN_DIR/non_web_udp_ports.txt"

log_info "Discovery complete. Scan results saved under $SCAN_DIR"
