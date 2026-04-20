#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-}"
PORTS="${2:-}"
OUTPUT_BASE="${3:-}"

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

WORDLIST="/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
AVAILABLE_WORDLIST=true
if [ ! -f "$WORDLIST" ]; then
  echo "Warning: wordlist not found: $WORDLIST"
  AVAILABLE_WORDLIST=false
fi

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

  echo "[*] Running web checks for $TARGET:$port"
  mkdir -p "$(dirname "$output_base")"

  CMD_ENUM="nmap --script=http-enum -p \"$port\" -oN \"${output_base}_http_enum.txt\" \"$TARGET\""
  echo "[*] $CMD_ENUM"
  printf "\n# Command: $CMD_ENUM\n\n" > "${output_base}_http_enum.txt"
  nmap --script=http-enum -p "$port" -oN "${output_base}_http_enum.txt" "$TARGET" 2>/dev/null >> "${output_base}_http_enum.txt" || true
  
  CMD_VULN="nmap --script=\"http-vuln* and not dos\" -p \"$port\" -oN \"${output_base}_http_vuln.txt\" \"$TARGET\""
  echo "[*] $CMD_VULN"
  printf "\n# Command: $CMD_VULN\n\n" > "${output_base}_http_vuln.txt"
  nmap --script="http-vuln* and not dos" -p "$port" -oN "${output_base}_http_vuln.txt" "$TARGET" 2>/dev/null >> "${output_base}_http_vuln.txt" || true
  
  CMD_HEADERS="curl -IL --max-time 15 \"$url\""
  echo "[*] $CMD_HEADERS"
  printf "\n# Command: $CMD_HEADERS\n\n" > "${output_base}_headers.txt"
  curl -IL --max-time 15 "$url" >> "${output_base}_headers.txt" 2>&1 || true
  
  CMD_ROBOTS="curl -s \"$url/robots.txt\""
  echo "[*] $CMD_ROBOTS"
  printf "\n# Command: $CMD_ROBOTS\n\n" > "${output_base}_robots.txt"
  curl -s "$url/robots.txt" >> "${output_base}_robots.txt" || true
  
  CMD_SITEMAP="curl -s \"$url/sitemap.xml\""
  echo "[*] $CMD_SITEMAP"
  printf "\n# Command: $CMD_SITEMAP\n\n" > "${output_base}_sitemap.xml"
  curl -s "$url/sitemap.xml" >> "${output_base}_sitemap.xml" || true
  
  CMD_CROSSDOMAIN="curl -s \"$url/crossdomain.xml\""
  echo "[*] $CMD_CROSSDOMAIN"
  printf "\n# Command: $CMD_CROSSDOMAIN\n\n" > "${output_base}_crossdomain.xml"
  curl -s "$url/crossdomain.xml" >> "${output_base}_crossdomain.xml" || true
  
  CMD_CLIENTACCESS="curl -s \"$url/clientaccesspolicy.xml\""
  echo "[*] $CMD_CLIENTACCESS"
  printf "\n# Command: $CMD_CLIENTACCESS\n\n" > "${output_base}_clientaccesspolicy.xml"
  curl -s "$url/clientaccesspolicy.xml" >> "${output_base}_clientaccesspolicy.xml" || true
  
  CMD_WELLKNOWN="curl -s \"$url/.well-known/\""
  echo "[*] $CMD_WELLKNOWN"
  printf "\n# Command: $CMD_WELLKNOWN\n\n" > "${output_base}_well_known.txt"
  curl -s "$url/.well-known/" >> "${output_base}_well_known.txt" || true
  
  CMD_WHATWEB="whatweb --no-errors \"$url\""
  echo "[*] $CMD_WHATWEB"
  printf "\n# Command: $CMD_WHATWEB\n\n" > "${output_base}_whatweb.txt"
  whatweb --no-errors "$url" >> "${output_base}_whatweb.txt" 2>&1 || true

  if [ "$AVAILABLE_WORDLIST" = true ]; then
    CMD_GOBUSTER_DIR="gobuster dir -u \"$url\" -w \"$WORDLIST\" -o \"${output_base}_gobuster_dir.txt\""
    echo "[*] $CMD_GOBUSTER_DIR"
    printf "\n# Command: $CMD_GOBUSTER_DIR\n\n" > "${output_base}_gobuster_dir.txt"
    gobuster dir -u "$url" -w "$WORDLIST" -o "${output_base}_gobuster_dir.txt" 2>/dev/null >> "${output_base}_gobuster_dir.txt" || true
    if [ "${GOBUSTER_VHOST:-0}" = "1" ]; then
      CMD_GOBUSTER_VHOST="gobuster vhost -u \"$url\" -w \"$WORDLIST\" -o \"${output_base}_gobuster_vhost.txt\""
      echo "[*] $CMD_GOBUSTER_VHOST"
      printf "\n# Command: $CMD_GOBUSTER_VHOST\n\n" > "${output_base}_gobuster_vhost.txt"
      gobuster vhost -u "$url" -w "$WORDLIST" -o "${output_base}_gobuster_vhost.txt" 2>/dev/null >> "${output_base}_gobuster_vhost.txt" || true
    fi
  fi
}

for port in $(printf '%s\n' "$PORTS" | tr ',' ' '); do
  run_http_checks "$port"
done

echo "Web enumeration complete for $TARGET"
echo "Saved outputs under $WEB_DIR"
