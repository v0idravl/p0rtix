#!/usr/bin/env bash
set -euo pipefail

# Display banner
cat << 'EOF'
██▓███   ▒█████   ██▀███  ▄▄▄█████▓ ██▓▒███  ██▒
▓██░  ██▒▒██▒  ██▒▓██ ▒ ██▒▓  ██▒ ▓▒▓██▒▒▒ █ █ ▒░
▓██░ ██▓▒▒██░  ██▒▓██ ░▄█ ▒▒ ▓██░ ▒░▒██▒░░  █   ░
▒██▄█▓▒ ▒▒██   ██░▒██▀▀█▄  ░ ▓██▓ ░ ░██░ ░ █ █ ▒ 
▒██▒ ░  ░░ ████▓▒░░██▓ ▒██▒  ▒██▒ ░ ░██░▒██▒ ▒██▒
▒▓▒░ ░  ░░ ▒░▒░▒░ ░ ▒▓ ░▒▓░  ▒ ░░   ░▓  ▒▒ ░ ░▓ ░
░▒ ░       ░ ▒ ▒░   ░▒ ░ ▒░    ░     ▒ ░░░   ░▒ ░
░░       ░ ░ ░ ▒    ░░   ░   ░       ▒ ░ ░    ░  
             ░ ░     ░               ░   ░    ░  

by v0idravl

EOF

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${1:-}"

if [ -z "$TARGET" ]; then
  read -rp "Target IP/hostname: " TARGET
fi

if [ -z "$TARGET" ]; then
  echo "No target provided. Exiting."
  exit 1
fi

OUTPUT_BASE="$SCRIPT_DIR/output/$TARGET"
SCANS_DIR="$OUTPUT_BASE/scans"
WEB_DIR="$OUTPUT_BASE/web"
SERVICES_DIR="$OUTPUT_BASE/services"

mkdir -p "$SCANS_DIR" "$WEB_DIR" "$SERVICES_DIR"

echo "Starting orchestration for target: $TARGET"
echo "Output base: $OUTPUT_BASE"

"$SCRIPT_DIR/ports.sh" "$TARGET" "$OUTPUT_BASE"

OPEN_TCP_PORTS_FILE="$SCANS_DIR/open_tcp_ports.txt"
WEB_PORTS_FILE="$SCANS_DIR/web_ports.txt"
NON_WEB_PORTS_FILE="$SCANS_DIR/non_web_ports.txt"

WEB_PORTS=""
NON_WEB_PORTS=""

if [ -f "$WEB_PORTS_FILE" ]; then
  WEB_PORTS="$(tr -d ' \t\r\n' < "$WEB_PORTS_FILE" 2>/dev/null || true)"
  WEB_PORTS="${WEB_PORTS%,}"
fi
if [ -f "$NON_WEB_PORTS_FILE" ]; then
  NON_WEB_PORTS="$(tr -d ' \t\r\n' < "$NON_WEB_PORTS_FILE" 2>/dev/null || true)"
  NON_WEB_PORTS="${NON_WEB_PORTS%,}"
fi

echo "DEBUG: normalized web_ports='$WEB_PORTS' non_web_ports='$NON_WEB_PORTS'"

if [ -n "$WEB_PORTS" ]; then
  echo "Web ports detected: $WEB_PORTS"
  "$SCRIPT_DIR/web.sh" "$TARGET" "$WEB_PORTS" "$OUTPUT_BASE"
else
  echo "No web ports detected; skipping web enumeration."
fi

if [ -n "$NON_WEB_PORTS" ]; then
  echo "Non-web ports detected: $NON_WEB_PORTS"
  "$SCRIPT_DIR/services.sh" "$TARGET" "$NON_WEB_PORTS" "$OUTPUT_BASE"
else
  echo "No non-web service ports detected; skipping service checks."
fi

SUMMARY_FILE="$OUTPUT_BASE/summary.txt"
{
  echo "Target: $TARGET"
  echo "Output: $OUTPUT_BASE"
  echo ""
  echo "Open TCP ports: $(wc -l < "$OPEN_TCP_PORTS_FILE" 2>/dev/null || echo 0)"
  echo "Web ports: $WEB_PORTS"
  echo "Non-web ports: $NON_WEB_PORTS"
  echo ""
  echo "Scan folders:"
  echo "  Scans: $SCANS_DIR"
  echo "  Web: $WEB_DIR"
  echo "  Services: $SERVICES_DIR"
} > "$SUMMARY_FILE"

echo "Orchestration complete. Summary written to $SUMMARY_FILE"
