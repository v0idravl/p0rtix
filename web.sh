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
# Web ports reuse the same approved NSE policy as non-web service ports.
ALLOWED_NSE_SCRIPTS="$(load_allowed_nse_scripts)"

WORDLIST=""
for candidate in \
  "/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt" \
  "/usr/share/seclists/Discovery/Web-Content/common.txt" \
  "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
do
  if [ -f "$candidate" ]; then
    WORDLIST="$candidate"
    break
  fi
done

AVAILABLE_WORDLIST=true
if [ -z "$WORDLIST" ]; then
  log_warn "No suitable web content wordlist found under /usr/share/seclists/Discovery/Web-Content/"
  AVAILABLE_WORDLIST=false
fi

run_capture() {
  local output_file="$1"
  shift
  local status=0
  set +e
  # Mirror command output to disk so quick web checks are easy to inspect later.
  "$@" 2>&1 | tee "$output_file"
  status=${PIPESTATUS[0]}
  set -e
  if [ "$status" -ne 0 ]; then
    log_warn "Command failed with exit code $status while writing $output_file"
  fi
  return 0
}

run_nmap_file() {
  local output_file="$1"
  shift
  local status=0
  set +e
  # Web NSE output gets the same tee-to-file treatment as the service scans.
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

run_port_nse_scan() {
  local output_file="$1"
  local scripts_csv="$2"

  if [ -z "$scripts_csv" ]; then
    log_info "No relevant NSE scripts selected for $(basename "$output_file")"
    return 0
  fi

  # Web ports still use the shared approved pool, but only after it has been narrowed
  # to scripts that actually fit the detected service family for this port.
  run_nmap_file "$output_file" nmap --script "$scripts_csv" -p "$port"
}

run_port_baseline_scan() {
  local output_file="$1"

  # Keep the standard Nmap service/version view beside the rest of the HTTP recon
  # so each web port has one cohesive folder of artifacts.
  run_nmap_file "$output_file" nmap -sS -sV --version-light -sC -Pn -p "$port"
}

run_http_checks() {
  local port="$1"
  local url
  local output_base="$WEB_DIR/${TARGET}_${port}"

  # Preserve friendly URLs for 80/443 and fall back to host:port for everything else.
  if [ "$port" = "80" ]; then
    url="http://$TARGET"
  elif [ "$port" = "443" ]; then
    url="https://$TARGET"
  else
    url="http://$TARGET:$port"
  fi

  log_info "Running web checks for $TARGET:$port"
  mkdir -p "$(dirname "$output_base")"

  log_info "Baseline service scan"
  baseline_output="${output_base}_baseline.txt"
  run_port_baseline_scan "$baseline_output"
  detected_service="$(extract_detected_service "$baseline_output" "$port" tcp)"
  relevant_nse_scripts="$(build_relevant_nse_scripts "$ALLOWED_NSE_SCRIPTS" "$detected_service" "$port" tcp)"
  if [ -n "$detected_service" ]; then
    log_info "Detected service for $TARGET:$port: $detected_service"
  else
    log_info "No service name detected for $TARGET:$port; falling back to generic matching"
  fi

  # These lightweight fetches give quick wins before any deeper directory or NSE work.
  log_info "Headers"
  run_capture "${output_base}_headers.txt" curl -IL --max-time 15 "$url"

  log_info "WhatWeb"
  run_capture "${output_base}_whatweb.txt" whatweb --no-errors "$url"
  
  log_info "robots.txt"
  run_capture "${output_base}_robots.txt" curl -s "$url/robots.txt"
  
  log_info "sitemap.xml"
  run_capture "${output_base}_sitemap.xml" curl -s "$url/sitemap.xml"
  
  log_info "crossdomain.xml"
  run_capture "${output_base}_crossdomain.xml" curl -s "$url/crossdomain.xml"
  
  log_info "clientaccesspolicy.xml"
  run_capture "${output_base}_clientaccesspolicy.xml" curl -s "$url/clientaccesspolicy.xml"
  
  log_info ".well-known"
  run_capture "${output_base}_well_known.txt" curl -s "$url/.well-known/"

  if [ "$AVAILABLE_WORDLIST" = true ]; then
    log_info "Gobuster dir"
    run_capture "${output_base}_gobuster_dir.txt" gobuster dir -u "$url" -w "$WORDLIST"
  fi

  log_info "Port-specific approved NSE scripts"
  run_port_nse_scan "${output_base}_nse.txt" "$relevant_nse_scripts"
}

for port in $(printf '%s\n' "$PORTS" | tr ',' ' '); do
  run_http_checks "$port"
done

log_info "Web enumeration complete for $TARGET"
log_info "Saved outputs under $WEB_DIR"
