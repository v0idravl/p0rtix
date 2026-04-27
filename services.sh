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
# Temporary coarse filter: skip individual follow-up scans on high TCP ports that
# are often Windows dynamic RPC / ephemeral allocations. Discovery still records
# them, so revisit this threshold if it starts hiding something meaningful.
SKIP_INDIVIDUAL_TCP_PORTS_MIN=49152
# UDP follow-up is intentionally selective: discovery already records open UDP
# ports, and only a short list of higher-value ports gets individual baseline/NSE
# scans by default.
UDP_FOLLOW_UP_PORTS="${UDP_FOLLOW_UP_PORTS:-53,69,123,137,161,500,623}"
UDP_NOTES_FILE="$SERVICE_DIR/${TARGET}_udp_notes.txt"

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
  local scripts_csv="$2"

  if [ -z "$scripts_csv" ]; then
    log_info "No relevant NSE scripts selected for $(basename "$output_file")"
    return 0
  fi

  # Only hand Nmap the subset that matches the detected service family for this port.
  run_scan_file "$output_file" nmap "$scan_flag" -sV --version-light --script "$scripts_csv" -p "$port"
}

run_port_baseline_scan() {
  local output_file="$1"

  # Each service gets its own baseline -sV/-sC artifact so version data and
  # default-script output stay grouped with the port-specific follow-up NSE results.
  run_scan_file "$output_file" nmap "$scan_flag" -sV --version-light -sC -Pn -p "$port"
}

csv_contains_value() {
  local csv="$1"
  local value="$2"
  local item

  while IFS= read -r item; do
    item="$(printf '%s' "$item" | tr -d '[:space:]')"
    [ -n "$item" ] || continue
    if [ "$item" = "$value" ]; then
      return 0
    fi
  done < <(printf '%s\n' "$csv" | tr ',' '\n')

  return 1
}

should_skip_individual_scan() {
  local proto="$1"
  local port="$2"

  if [ "$proto" = "udp" ]; then
    if csv_contains_value "$UDP_FOLLOW_UP_PORTS" "$port"; then
      return 1
    fi
    return 0
  fi

  if [ "$proto" != "tcp" ]; then
    return 0
  fi

  if [ "$port" -ge "$SKIP_INDIVIDUAL_TCP_PORTS_MIN" ]; then
    return 0
  fi

  return 1
}

PORTS="$(printf '%s' "$PORTS" | tr -d ' \t\r\n')"
log_info "Running non-web service checks for $TARGET"
log_warn "Reminder: individual TCP follow-up scans are temporarily skipped for ports >= $SKIP_INDIVIDUAL_TCP_PORTS_MIN"
printf 'UDP ports discovered for %s\n' "$TARGET" > "$UDP_NOTES_FILE"
printf 'Selective UDP follow-up allowlist: %s\n\n' "$UDP_FOLLOW_UP_PORTS" >> "$UDP_NOTES_FILE"
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
    if csv_contains_value "$UDP_FOLLOW_UP_PORTS" "$port"; then
      printf 'udp/%s: targeted follow-up enabled\n' "$port" >> "$UDP_NOTES_FILE"
    else
      printf 'udp/%s: noted only, no individual follow-up scan\n' "$port" >> "$UDP_NOTES_FILE"
    fi
  fi
  if should_skip_individual_scan "$proto" "$port"; then
    if [ "$proto" = "udp" ]; then
      log_info "Noting $TARGET:$proto/$port without individual follow-up scan"
    else
      log_info "Skipping individual follow-up scans on $TARGET:$proto/$port due to temporary high-port filter"
    fi
    continue
  fi
  log_info "Running approved NSE set on $TARGET:$proto/$port"
  log_info "Running baseline service scan on $TARGET:$proto/$port"
  baseline_output="${OUTPUT_BASE_FILE}_${proto}_${port}_baseline.txt"
  run_port_baseline_scan "$baseline_output"

  detected_service="$(extract_detected_service "$baseline_output" "$port" "$proto")"
  relevant_nse_scripts="$(build_relevant_nse_scripts "$ALLOWED_NSE_SCRIPTS" "$detected_service" "$port" "$proto")"
  if [ -n "$detected_service" ]; then
    log_info "Detected service for $TARGET:$proto/$port: $detected_service"
  else
    log_info "No service name detected for $TARGET:$proto/$port; falling back to generic matching"
  fi

  # SNMP gets one extra manual pass because a public community string is common
  # enough to be worth a quick check outside of NSE.
  if [ "$proto" = "udp" ] && [ "$port" = "161" ]; then
    log_info "SNMP public community walk"
    run_capture_file "${OUTPUT_BASE_FILE}_${proto}_${port}_snmp_public.txt" snmpwalk -v 2c -c public "$TARGET"
  fi

  run_port_nse_scan "${OUTPUT_BASE_FILE}_${proto}_${port}_nse.txt" "$relevant_nse_scripts"
done

log_info "Non-web service outputs written to: $SERVICE_DIR"
