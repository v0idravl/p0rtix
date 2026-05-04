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

require_command() {
  local cmd="$1"

  if ! command -v "$cmd" >/dev/null 2>&1; then
    log_warn "Missing required dependency: $cmd"
    return 1
  fi

  return 0
}

optional_command() {
  local cmd="$1"
  local description="$2"

  if command -v "$cmd" >/dev/null 2>&1; then
    log_info "Optional dependency available: $cmd ($description)"
  else
    log_warn "Optional dependency missing: $cmd ($description will be skipped)"
  fi
}

preflight_dependencies() {
  local missing_required=0

  log_info "Running dependency preflight"

  require_command nmap || missing_required=1
  optional_command curl "HTTP header and robots.txt checks"
  optional_command whatweb "web fingerprinting"

  if [ "$missing_required" -ne 0 ]; then
    log_warn "Required dependencies are missing. Exiting."
    exit 1
  fi
}

sanitize_machine_name() {
  local raw_name="$1"

  printf '%s\n' "$raw_name" \
    | tr '[:upper:]' '[:lower:]' \
    | sed 's/[^a-z0-9._-]/_/g'
}

if [ -z "$TARGET" ]; then
  usage
fi
PROJECT_ROOT="${PROJECT_ROOT:-$SCRIPT_DIR}"

MACHINE_NAME="${MACHINE_NAME:-$(sanitize_machine_name "$TARGET")}"
MACHINE_NAME="$(sanitize_machine_name "$MACHINE_NAME")"

if [ -z "$MACHINE_NAME" ]; then
  log_warn "Machine nickname resolved to an empty value. Exiting."
  usage
fi

preflight_dependencies

MACHINE_ROOT="$PROJECT_ROOT/$MACHINE_NAME"
OUTPUT_BASE="$MACHINE_ROOT/output"
SCANS_DIR="$OUTPUT_BASE/scans"
WEB_DIR="$OUTPUT_BASE/web"
SERVICES_DIR="$OUTPUT_BASE/services"

mkdir -p "$SCANS_DIR" "$WEB_DIR" "$SERVICES_DIR"

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

log_info "Starting scan for $TARGET | Workspace: $MACHINE_ROOT | Output: $OUTPUT_BASE"

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
