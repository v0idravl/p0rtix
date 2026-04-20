#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/web"
WORDLIST="/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
IP="${1:-}"
PORT="${2:-}"

usage() {
  cat <<EOF
Usage: $0 <target-ip-or-hostname> <port>

Example:
  $0 10.10.10.10 80
EOF
  exit 1
}

if [ -z "$IP" ] || [ -z "$PORT" ]; then
  usage
fi

if [ ! -f "$WORDLIST" ]; then
  echo "Error: wordlist not found: $WORDLIST"
  exit 1
fi

mkdir -p "$OUTPUT_DIR"

if [ "$PORT" = "80" ]; then
  URL="http://$IP"
elif [ "$PORT" = "443" ]; then
  URL="https://$IP"
else
  URL="http://$IP:$PORT"
fi

OUTPUT_BASE="$OUTPUT_DIR/${IP}_${PORT}"

echo "Running web scan for $IP:$PORT"
echo "URL: $URL"
echo "Output directory: $OUTPUT_DIR"

run_cmd() {
  local desc="$1"
  shift
  echo "[*] $desc"
  "$@"
}

run_cmd "Nmap http-enum" nmap --script=http-enum -p "$PORT" -oN "${OUTPUT_BASE}_nmap_http_enum.txt" "$IP"
run_cmd "Curl header probe" curl -IL --max-time 15 "$URL" > "${OUTPUT_BASE}_curl_headers.txt" 2>&1 || true
run_cmd "Fetch robots.txt" curl -s "$URL/robots.txt" > "${OUTPUT_BASE}_robots.txt" || true
run_cmd "Fetch sitemap.xml" bash -lc "curl -s '$URL/sitemap.xml' | xmllint --format - 2>/dev/null" > "${OUTPUT_BASE}_sitemap.xml" || true
run_cmd "Fetch crossdomain.xml" bash -lc "curl -s '$URL/crossdomain.xml' | xmllint --format - 2>/dev/null" > "${OUTPUT_BASE}_crossdomain.xml" || true
run_cmd "Fetch clientaccesspolicy.xml" bash -lc "curl -s '$URL/clientaccesspolicy.xml' | xmllint --format - 2>/dev/null" > "${OUTPUT_BASE}_clientaccesspolicy.xml" || true
run_cmd "Fetch .well-known/" bash -lc "curl -s '$URL/.well-known/' | xmllint --format - 2>/dev/null" > "${OUTPUT_BASE}_well_known.xml" || true
run_cmd "Gobuster dir" gobuster dir -u "$URL" -w "$WORDLIST" -o "${OUTPUT_BASE}_gobuster_dir.txt" || true
run_cmd "Gobuster vhost" gobuster vhost -u "$URL" -w "$WORDLIST" -o "${OUTPUT_BASE}_gobuster_vhost.txt" || true
run_cmd "WhatWeb" whatweb --no-errors "$URL" > "${OUTPUT_BASE}_whatweb.txt" 2>&1 || true

echo "Web scan completed for $IP:$PORT"
echo "Saved outputs to: $OUTPUT_DIR"
