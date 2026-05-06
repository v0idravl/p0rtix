#!/usr/bin/env bash

# Keep log coloring optional so redirected output stays readable.
LOG_INFO_COLOR=""
LOG_WARN_COLOR=""
LOG_RESET_COLOR=""

if [ -t 1 ] && [ "${TERM:-}" != "dumb" ] && [ -z "${NO_COLOR:-}" ]; then
  LOG_INFO_COLOR="$(printf '\033[1;36m')"
  LOG_WARN_COLOR="$(printf '\033[1;33m')"
  LOG_RESET_COLOR="$(printf '\033[0m')"
fi

log_info() {
  printf '%s[*]%s %s\n' "$LOG_INFO_COLOR" "$LOG_RESET_COLOR" "$*"
}

log_warn() {
  printf '%s[!]%s %s\n' "$LOG_WARN_COLOR" "$LOG_RESET_COLOR" "$*" >&2
}

# Shared nmap wrapper: appends --stats-every and -oN - to the given nmap command,
# tees output to output_file, and tolerates non-zero exit codes (including segfaults).
# Callers must have NMAP_STATS_EVERY and TARGET set in their environment.
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

# Extract the service name for a given TCP port from an nmap -oN output file.
extract_detected_service() {
  local scan_file="$1"
  local port="$2"

  awk -v target="$port/tcp" '
    $1 == target {
      print $3
      exit
    }
  ' "$scan_file" 2>/dev/null
}
