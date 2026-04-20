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
source "$SCRIPT_DIR/log_utils.sh"
source "$SCRIPT_DIR/port_utils.sh"

if [ -z "$TARGET" ]; then
  read -rp "Target IP/hostname: " TARGET
fi

if [ -z "$TARGET" ]; then
  log_warn "No target provided. Exiting."
  exit 1
fi

OUTPUT_BASE="$SCRIPT_DIR/output/$TARGET"
SCANS_DIR="$OUTPUT_BASE/scans"
WEB_DIR="$OUTPUT_BASE/web"
SERVICES_DIR="$OUTPUT_BASE/services"

mkdir -p "$SCANS_DIR" "$WEB_DIR" "$SERVICES_DIR"

log_info "Starting orchestration for target: $TARGET"
log_info "Output base: $OUTPUT_BASE"

"$SCRIPT_DIR/ports.sh" "$TARGET" "$OUTPUT_BASE"

OPEN_TCP_PORTS_FILE="$SCANS_DIR/open_tcp_ports.txt"
OPEN_UDP_PORTS_FILE="$SCANS_DIR/open_udp_ports.txt"
WEB_PORTS_FILE="$SCANS_DIR/web_ports.txt"
NON_WEB_PORTS_FILE="$SCANS_DIR/non_web_ports.txt"
NON_WEB_UDP_PORTS_FILE="$SCANS_DIR/non_web_udp_ports.txt"

WEB_PORTS=""
NON_WEB_PORTS=""
NON_WEB_UDP_PORTS=""
SERVICE_TARGETS=""

WEB_PORTS="$(sanitize_port_file "$WEB_PORTS_FILE" "web_ports.txt")"
NON_WEB_PORTS="$(sanitize_port_file "$NON_WEB_PORTS_FILE" "non_web_ports.txt")"
NON_WEB_UDP_PORTS="$(sanitize_port_file "$NON_WEB_UDP_PORTS_FILE" "non_web_udp_ports.txt")"

tcp_target_count=0
udp_target_count=0
if [ -n "$NON_WEB_PORTS" ]; then
  tcp_target_count=$(printf '%s\n' "$NON_WEB_PORTS" | tr ',' '\n' | awk 'NF {count++} END {print count+0}')
fi
if [ -n "$NON_WEB_UDP_PORTS" ]; then
  udp_target_count=$(printf '%s\n' "$NON_WEB_UDP_PORTS" | tr ',' '\n' | awk 'NF {count++} END {print count+0}')
fi

if [ -n "$NON_WEB_PORTS" ]; then
  SERVICE_TARGETS="$(printf '%s\n' "$NON_WEB_PORTS" | tr ',' '\n' | awk 'NF {print "tcp/" $0}' | paste -sd, -)"
fi
if [ -n "$NON_WEB_UDP_PORTS" ]; then
  if [ -n "$SERVICE_TARGETS" ]; then
    SERVICE_TARGETS="$SERVICE_TARGETS,"
  fi
  SERVICE_TARGETS="${SERVICE_TARGETS}$(printf '%s\n' "$NON_WEB_UDP_PORTS" | tr ',' '\n' | awk 'NF {print "udp/" $0}' | paste -sd, -)"
fi

log_info "DEBUG: normalized web_ports='$WEB_PORTS' non_web_tcp_ports='$NON_WEB_PORTS' non_web_udp_ports='$NON_WEB_UDP_PORTS'"

if [ -n "$WEB_PORTS" ]; then
  log_info "Web ports detected: $WEB_PORTS"
  "$SCRIPT_DIR/web.sh" "$TARGET" "$WEB_PORTS" "$OUTPUT_BASE"
else
  log_info "No web ports detected; skipping web enumeration."
fi

if [ -n "$SERVICE_TARGETS" ]; then
  "$SCRIPT_DIR/services.sh" "$TARGET" "$SERVICE_TARGETS" "$OUTPUT_BASE"
else
  log_info "No non-web service ports detected; skipping service checks."
fi

log_info "Orchestration complete. Outputs saved under $OUTPUT_BASE"
