#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-}"
PORTS="${2:-}"
OUTPUT_BASE="${3:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/log_utils.sh"

usage() {
  cat <<EOF
Usage: $0 <target-ip-or-hostname> <web-ports> <output-base-dir>

Example:
  $0 10.10.10.10 80,443 /home/user/Projects/p0rtix/output/10.10.10.10
EOF
  exit 1
}

if [ -z "$TARGET" ] || [ -z "$PORTS" ] || [ -z "$OUTPUT_BASE" ]; then
  usage
fi

WEB_DIR="$OUTPUT_BASE/web"
mkdir -p "$WEB_DIR"
NMAP_STATS_EVERY="${NMAP_STATS_EVERY:-3m}"
HAS_CURL=false

if command -v curl >/dev/null 2>&1; then
  HAS_CURL=true
else
  log_warn "curl not found; header and robots.txt checks will be skipped"
fi

run_capture() {
  local output_file="$1"
  shift
  local status=0

  set +e
  "$@" | tee "$output_file"
  status=${PIPESTATUS[0]}
  set -e

  if [ "$status" -ne 0 ]; then
    log_warn "Command failed with exit code $status while writing $output_file"
  fi

  return 0
}

fetch_if_present() {
  local output_file="$1"
  local url="$2"
  local label="$3"
  local temp_file
  local http_code
  local status=0

  temp_file="$(mktemp)"
  set +e
  http_code="$(curl -sS -L --max-time 15 -o "$temp_file" -w '%{http_code}' "$url")"
  status=$?
  set -e

  if [ "$status" -ne 0 ]; then
    rm -f "$temp_file"
    log_warn "Command failed with exit code $status while fetching $label"
    return 0
  fi

  if [ "${http_code:-000}" -ge 400 ]; then
    rm -f "$temp_file"
    log_info "$label returned HTTP $http_code; skipping saved output"
    return 0
  fi

  tee "$output_file" < "$temp_file"
  rm -f "$temp_file"
  return 0
}

web_scheme_for_port() {
  local service_name="$1"
  local port="$2"
  local normalized

  normalized="$(printf '%s' "$service_name" | tr '[:upper:]' '[:lower:]')"

  case "$normalized" in
    https|https-alt|ssl/http|ssl|ssl/*|tls|tls/*)
      printf '%s\n' "https"
      return 0
      ;;
    http|http-alt|http-proxy|sun-answerbook)
      printf '%s\n' "http"
      return 0
      ;;
  esac

  case "$port" in
    443|8443|9443)
      printf '%s\n' "https"
      ;;
    *)
      printf '%s\n' "http"
      ;;
  esac
}

run_http_checks() {
  local port="$1"
  local url
  local scheme
  local detected_service
  local output_base="$WEB_DIR/${TARGET}_${port}"

  log_info "Running web checks for $TARGET:$port"

  baseline_output="${output_base}_baseline.txt"
  run_scan_file "$baseline_output" nmap -n -sS -sV --version-light -sC -Pn -p "$port"

  detected_service="$(extract_detected_service "$baseline_output" "$port")"
  scheme="$(web_scheme_for_port "$detected_service" "$port")"

  if [ "$port" = "80" ] && [ "$scheme" = "http" ]; then
    url="$scheme://$TARGET"
  elif [ "$port" = "443" ] && [ "$scheme" = "https" ]; then
    url="$scheme://$TARGET"
  else
    url="$scheme://$TARGET:$port"
  fi

  log_info "Using $scheme for $TARGET:$port"

  if [ "$HAS_CURL" = true ]; then
    log_info "Headers"
    run_capture "${output_base}_headers.txt" curl -sS -I -L --max-time 15 "$url"

    log_info "robots.txt"
    fetch_if_present "${output_base}_robots.txt" "$url/robots.txt" "robots.txt"
  fi

  if command -v whatweb >/dev/null 2>&1; then
    log_info "WhatWeb"
    run_capture "${output_base}_whatweb.txt" whatweb --no-errors "$url"
  else
    log_warn "whatweb not found; skipping fingerprinting for $url"
  fi
}

for port in $(printf '%s\n' "$PORTS" | tr ',' ' '); do
  run_http_checks "$port"
done

log_info "Web enumeration complete for $TARGET"
log_info "Saved outputs under $WEB_DIR"
