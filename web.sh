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

WORDLIST="/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
AVAILABLE_WORDLIST=true
if [ ! -f "$WORDLIST" ]; then
  log_warn "Wordlist not found: $WORDLIST"
  AVAILABLE_WORDLIST=false
fi

run_capture() {
  local output_file="$1"
  shift
  local status=0
  set +e
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

run_http_checks() {
  local port="$1"
  local url
  local output_base="$WEB_DIR/${TARGET}_${port}"

  if [ "$port" = "80" ]; then
    url="http://$TARGET"
  elif [ "$port" = "443" ]; then
    url="https://$TARGET"
  else
    url="http://$TARGET:$port"
  fi

  log_info "Running web checks for $TARGET:$port"
  mkdir -p "$(dirname "$output_base")"

  log_info "HTTP enum"
  run_nmap_file "${output_base}_http_enum.txt" nmap --script=http-enum -p "$port"
  
  log_info "HTTP vuln scripts"
  run_nmap_file "${output_base}_http_vuln.txt" nmap --script="http-vuln* and not dos" -p "$port"
  
  log_info "Headers"
  run_capture "${output_base}_headers.txt" curl -IL --max-time 15 "$url"
  
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
  
  log_info "WhatWeb"
  run_capture "${output_base}_whatweb.txt" whatweb --no-errors "$url"

  if [ "$AVAILABLE_WORDLIST" = true ]; then
    log_info "Gobuster dir"
    run_capture "${output_base}_gobuster_dir.txt" gobuster dir -u "$url" -w "$WORDLIST"
    if [ "${GOBUSTER_VHOST:-0}" = "1" ]; then
      log_info "Gobuster vhost"
      run_capture "${output_base}_gobuster_vhost.txt" gobuster vhost -u "$url" -w "$WORDLIST"
    fi
  fi
}

for port in $(printf '%s\n' "$PORTS" | tr ',' ' '); do
  run_http_checks "$port"
done

log_info "Web enumeration complete for $TARGET"
log_info "Saved outputs under $WEB_DIR"
