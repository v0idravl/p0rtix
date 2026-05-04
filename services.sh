#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-}"
PORTS="${2:-}"
OUTPUT_BASE="${3:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/log_utils.sh"

usage() {
  cat <<EOF
Usage: $0 <target-ip-or-hostname> <service-ports> <output-base-dir>

Example:
  $0 10.10.10.10 tcp/22,tcp/445,udp/161 /home/user/Projects/p0rtix/output/10.10.10.10
EOF
  exit 1
}

if [ -z "$TARGET" ] || [ -z "$PORTS" ] || [ -z "$OUTPUT_BASE" ]; then
  usage
fi

SERVICE_DIR="$OUTPUT_BASE/services"
mkdir -p "$SERVICE_DIR"
NMAP_STATS_EVERY="${NMAP_STATS_EVERY:-3m}"
TCP_PORTS=()
UDP_PORTS=()

run_scan_file() {
  local output_file="$1"
  shift
  local status=0

  set +e
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

append_port() {
  local -n target_array="$1"
  local port="$2"
  local existing

  for existing in "${target_array[@]}"; do
    if [ "$existing" = "$port" ]; then
      return 0
    fi
  done

  target_array+=("$port")
}

PORTS="$(printf '%s' "$PORTS" | tr -d ' \t\r\n')"

IFS=',' read -r -a raw_ports <<< "$PORTS"
for target_port in "${raw_ports[@]}"; do
  target_port="$(printf '%s' "$target_port" | tr -d '[:space:]')"
  [ -n "$target_port" ] || continue

  if [[ "$target_port" == */* ]]; then
    proto="${target_port%%/*}"
    port="${target_port##*/}"
  else
    proto="tcp"
    port="$target_port"
  fi

  case "$proto" in
    tcp)
      append_port TCP_PORTS "$port"
      ;;
    udp)
      append_port UDP_PORTS "$port"
      ;;
    *)
      log_warn "Skipping unsupported protocol prefix: $target_port"
      ;;
  esac
done

log_info "Running lightweight non-web follow-up for $TARGET"

if [ "${#TCP_PORTS[@]}" -gt 0 ]; then
  tcp_csv="$(printf '%s\n' "${TCP_PORTS[@]}" | sort -n | paste -sd, -)"
  log_info "Batch TCP baseline scan on ports: $tcp_csv"
  run_scan_file "$SERVICE_DIR/${TARGET}_services_tcp_baseline.txt" \
    nmap -n -sS -sV --version-light -sC -Pn -p "$tcp_csv"
else
  log_info "No non-web TCP ports detected."
fi

if [ "${#UDP_PORTS[@]}" -gt 0 ]; then
  udp_csv="$(printf '%s\n' "${UDP_PORTS[@]}" | sort -n | paste -sd, -)"
  log_info "Batch UDP version scan on ports: $udp_csv"
  run_scan_file "$SERVICE_DIR/${TARGET}_services_udp_baseline.txt" \
    nmap -n -sU -sV --version-light -Pn -p "$udp_csv"
else
  log_info "No non-web UDP ports detected."
fi

log_info "Non-web service outputs written to: $SERVICE_DIR"
