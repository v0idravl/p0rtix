#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-}"
PORTS="${2:-}"
OUTPUT_BASE="${3:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/log_utils.sh"
source "$SCRIPT_DIR/nse_utils.sh"

usage() {
  cat <<EOF
Usage: $0 <target-ip-or-hostname> <service-ports> <output-base-dir>

Example:
  $0 10.10.10.10 22,53,445 /home/user/Projects/p0rtix/output/10.10.10.10
EOF
  exit 1
}

if [ -z "$TARGET" ] || [ -z "$PORTS" ] || [ -z "$OUTPUT_BASE" ]; then
  usage
fi

SERVICE_DIR="$OUTPUT_BASE/services"
mkdir -p "$SERVICE_DIR"
OUTPUT_BASE_FILE="$SERVICE_DIR/${TARGET}_services"
NMAP_STATS_EVERY="${NMAP_STATS_EVERY:-3m}"
# Build the filtered NSE allowlist once so every port uses the same rules.
ALLOWED_NSE_SCRIPTS="$(load_allowed_nse_scripts)"

run_scan_file() {
  local output_file="$1"
  shift
  local status=0
  set +e
  # Keep nmap output visible on screen while also writing a plain-text artifact.
  "$@" --stats-every "$NMAP_STATS_EVERY" -oN - "$TARGET" 2>&1 | tee "$output_file"
  status=${PIPESTATUS[0]}
  set -e
  if [ "$status" -eq 139 ]; then
    log_warn "Scan crashed with a segmentation fault while writing $output_file"
  elif [ "$status" -ne 0 ]; then
    log_warn "Scan failed with exit code $status while writing $output_file"
  fi
  return 0
}

run_capture_file() {
  local output_file="$1"
  shift
  local status=0
  set +e
  # Some helpers are not nmap-based, but we still want identical tee-to-file behavior.
  "$@" 2>&1 | tee "$output_file"
  status=${PIPESTATUS[0]}
  set -e
  if [ "$status" -ne 0 ]; then
    log_warn "Command failed with exit code $status while writing $output_file"
  fi
  return 0
}

run_port_nse_scan() {
  local output_file="$1"
  if [ -z "$ALLOWED_NSE_SCRIPTS" ]; then
    log_info "No approved NSE scripts available locally for $(basename "$output_file")"
    return 0
  fi

  # We hand Nmap one large allowlist and let each script's portrule decide whether
  # it should actually run against the current service.
  run_scan_file "$output_file" nmap "$scan_flag" --script "$ALLOWED_NSE_SCRIPTS" -p "$port"
}

PORTS="$(printf '%s' "$PORTS" | tr -d ' \t\r\n')"
log_info "Running non-web service checks for $TARGET"
if [ -n "$ALLOWED_NSE_SCRIPTS" ]; then
  script_count=$(printf '%s\n' "$ALLOWED_NSE_SCRIPTS" | tr ',' '\n' | awk 'NF {count++} END {print count+0}')
  log_info "Approved NSE script count for per-port scans: $script_count"
fi

IFS=',' read -r -a ports <<< "$PORTS"
for target_port in "${ports[@]}"; do
  target_port="$(printf '%s' "$target_port" | tr -d '[:space:]')"
  if [ -z "$target_port" ]; then
    continue
  fi
  if [[ "$target_port" == */* ]]; then
    proto="${target_port%%/*}"
    port="${target_port##*/}"
  else
    proto="tcp"
    port="$target_port"
  fi
  scan_flag="-sS"
  if [ "$proto" = "udp" ]; then
    scan_flag="-sU"
  fi
  log_info "Running approved NSE set on $TARGET:$proto/$port"

  # SNMP gets one extra manual pass because a public community string is common
  # enough to be worth a quick check outside of NSE.
  if [ "$proto" = "udp" ] && [ "$port" = "161" ]; then
    log_info "SNMP public community walk"
    run_capture_file "${OUTPUT_BASE_FILE}_${proto}_${port}_snmp_public.txt" snmpwalk -v 2c -c public "$TARGET"
  fi

  run_port_nse_scan "${OUTPUT_BASE_FILE}_${proto}_${port}_nse.txt"
done

log_info "Non-web service outputs written to: $SERVICE_DIR"
