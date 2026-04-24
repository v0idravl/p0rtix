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
PROJECT_ROOT="${2:-}"
MACHINE_NAME="${3:-}"
source "$SCRIPT_DIR/log_utils.sh"

usage() {
  cat <<EOF
Usage: $0 <target-ip-or-hostname> [project-root-dir] [machine-nickname]

Examples:
  $0 10.10.11.34
  $0 10.10.11.34 /home/user/Projects/htb lame
EOF
  exit 1
}

sanitize_machine_name() {
  local raw_name="$1"

  printf '%s\n' "$raw_name" \
    | tr '[:upper:]' '[:lower:]' \
    | sed 's/[^a-z0-9._-]/_/g'
}

if [ -z "$TARGET" ]; then
  read -rp "Target IP/hostname: " TARGET
fi

if [ -z "$TARGET" ]; then
  log_warn "No target provided. Exiting."
  exit 1
fi

if [ -z "$PROJECT_ROOT" ]; then
  read -rp "Project root directory [$SCRIPT_DIR]: " PROJECT_ROOT
fi
PROJECT_ROOT="${PROJECT_ROOT:-$SCRIPT_DIR}"

if [ -z "$MACHINE_NAME" ]; then
  read -rp "Machine nickname [$(sanitize_machine_name "$TARGET")]: " MACHINE_NAME
fi
MACHINE_NAME="${MACHINE_NAME:-$(sanitize_machine_name "$TARGET")}"
MACHINE_NAME="$(sanitize_machine_name "$MACHINE_NAME")"

if [ -z "$MACHINE_NAME" ]; then
  log_warn "Machine nickname resolved to an empty value. Exiting."
  usage
fi

MACHINE_ROOT="$PROJECT_ROOT/$MACHINE_NAME"
OUTPUT_BASE="$MACHINE_ROOT/output"
SCANS_DIR="$OUTPUT_BASE/scans"
WEB_DIR="$OUTPUT_BASE/web"
SERVICES_DIR="$OUTPUT_BASE/services"
LOOT_DIR="$MACHINE_ROOT/loot"
EXPLOIT_DIR="$MACHINE_ROOT/exploit"
REPORT_FILE="$MACHINE_ROOT/${MACHINE_NAME}_report.md"
REPORT_TEMPLATE_URL="https://raw.githubusercontent.com/v0idravl/lab-writeups/refs/heads/main/writeup-template.md"

# Create the full output tree up front so downstream scripts can assume it exists.
mkdir -p "$SCANS_DIR" "$WEB_DIR" "$SERVICES_DIR" "$LOOT_DIR" "$EXPLOIT_DIR"

if [ ! -f "$REPORT_FILE" ]; then
  if command -v wget >/dev/null 2>&1; then
    if wget -qO "$REPORT_FILE" "$REPORT_TEMPLATE_URL"; then
      log_info "Created report template at $REPORT_FILE"
    else
      rm -f "$REPORT_FILE"
      log_warn "Failed to download report template from $REPORT_TEMPLATE_URL"
    fi
  elif command -v curl >/dev/null 2>&1; then
    if curl -fsSL "$REPORT_TEMPLATE_URL" -o "$REPORT_FILE"; then
      log_info "Created report template at $REPORT_FILE"
    else
      rm -f "$REPORT_FILE"
      log_warn "Failed to download report template from $REPORT_TEMPLATE_URL"
    fi
  else
    log_warn "Neither wget nor curl is installed; skipping report template download."
  fi
else
  log_info "Report already exists at $REPORT_FILE; leaving it untouched."
fi

csv_from_port_file() {
  local file_path="$1"

  if [ ! -f "$file_path" ]; then
    printf '%s' ""
    return 0
  fi

  # Normalize plain-text port lists back into a clean CSV for the child scripts.
  awk '
    /^[[:space:]]*$/ {
      next
    }
    /^[[:space:]]*[0-9]+[[:space:]]*$/ {
      port = $1 + 0
      if (port >= 1 && port <= 65535) {
        print port
      }
    }
  ' "$file_path" | paste -sd, -
}

log_info "Starting orchestration for target: $TARGET"
log_info "Project root: $PROJECT_ROOT"
log_info "Machine workspace: $MACHINE_ROOT"
log_info "Output base: $OUTPUT_BASE"

# Discovery writes the canonical port lists used by the rest of the pipeline.
"$SCRIPT_DIR/ports.sh" "$TARGET" "$OUTPUT_BASE"

WEB_PORTS_FILE="$SCANS_DIR/web_ports.txt"
NON_WEB_PORTS_FILE="$SCANS_DIR/non_web_ports.txt"
NON_WEB_UDP_PORTS_FILE="$SCANS_DIR/non_web_udp_ports.txt"

WEB_PORTS=""
NON_WEB_PORTS=""
NON_WEB_UDP_PORTS=""
SERVICE_TARGETS=""

WEB_PORTS="$(csv_from_port_file "$WEB_PORTS_FILE")"
NON_WEB_PORTS="$(csv_from_port_file "$NON_WEB_PORTS_FILE")"
NON_WEB_UDP_PORTS="$(csv_from_port_file "$NON_WEB_UDP_PORTS_FILE")"

tcp_target_count=0
udp_target_count=0
if [ -n "$NON_WEB_PORTS" ]; then
  tcp_target_count=$(printf '%s\n' "$NON_WEB_PORTS" | tr ',' '\n' | awk 'NF {count++} END {print count+0}')
fi
if [ -n "$NON_WEB_UDP_PORTS" ]; then
  udp_target_count=$(printf '%s\n' "$NON_WEB_UDP_PORTS" | tr ',' '\n' | awk 'NF {count++} END {print count+0}')
fi

if [ -n "$NON_WEB_PORTS" ]; then
  # Service scans expect explicit protocol prefixes so TCP/UDP can be mixed.
  SERVICE_TARGETS="$(printf '%s\n' "$NON_WEB_PORTS" | tr ',' '\n' | awk 'NF {print "tcp/" $0}' | paste -sd, -)"
fi
if [ -n "$NON_WEB_UDP_PORTS" ]; then
  if [ -n "$SERVICE_TARGETS" ]; then
    SERVICE_TARGETS="$SERVICE_TARGETS,"
  fi
  SERVICE_TARGETS="${SERVICE_TARGETS}$(printf '%s\n' "$NON_WEB_UDP_PORTS" | tr ',' '\n' | awk 'NF {print "udp/" $0}' | paste -sd, -)"
fi

log_info "DEBUG: normalized web_ports='$WEB_PORTS' non_web_tcp_ports='$NON_WEB_PORTS' non_web_udp_ports='$NON_WEB_UDP_PORTS'"

if [ -n "$SERVICE_TARGETS" ]; then
  "$SCRIPT_DIR/services.sh" "$TARGET" "$SERVICE_TARGETS" "$OUTPUT_BASE"
else
  log_info "No non-web service ports detected; skipping service checks."
fi

if [ -n "$WEB_PORTS" ]; then
  log_info "Web ports detected: $WEB_PORTS"
  "$SCRIPT_DIR/web.sh" "$TARGET" "$WEB_PORTS" "$OUTPUT_BASE"
else
  log_info "No web ports detected; skipping web enumeration."
fi

# At this point the run is complete; everything else is already on disk.
log_info "Orchestration complete. Outputs saved under $OUTPUT_BASE"
