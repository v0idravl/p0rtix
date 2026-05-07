#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/log_utils.sh"

# When run directly, parse arguments. When sourced by main.sh, TARGET and
# OUTPUT_BASE are already in scope.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  TARGET="${1:-}"
  OUTPUT_BASE="${2:-}"

  if [ -z "$TARGET" ] || [ -z "$OUTPUT_BASE" ]; then
    cat <<USAGE
Usage: $0 <target-ip-or-hostname> <output-base-dir>

Example:
  $0 10.10.10.10 /home/user/Projects/p0rtix/output/10.10.10.10
USAGE
    exit 1
  fi
fi

mkdir -p "$OUTPUT_BASE"

FULL_TCP_BASE="$OUTPUT_BASE/full_tcp"
UDP_BASE="$OUTPUT_BASE/top_100_udp"
UDP_CONFIRMED_BASE="$OUTPUT_BASE/udp_confirmed"
TCP_SERVICE_BASE="$OUTPUT_BASE/open_tcp_services"
NMAP_STATS_EVERY="${NMAP_STATS_EVERY:-3m}"
NMAP_MIN_RATE="${NMAP_MIN_RATE:-2000}"

extract_ports_from_gnmap() {
  local gnmap_file="$1"
  local proto="$2"
  local include_open_filtered="${3:-0}"

  # Grepable output is easier to post-process than the human-readable .nmap files.
  awk -v proto="$proto" -v include_open_filtered="$include_open_filtered" '
    /Ports: / {
      sub(/^.*Ports: /, "")
      split($0, entries, /, /)
      for (i in entries) {
        split(entries[i], fields, "/")
        port = fields[1]
        state = fields[2]
        entry_proto = fields[3]

        if (entry_proto != proto) {
          continue
        }
        if (state == "open" || (include_open_filtered && state == "open|filtered")) {
          print port
        }
      }
    }
  ' "$gnmap_file" | sort -nu
}

is_web_service() {
  local port="$1"
  local service_name="$2"
  local normalized

  normalized="$(printf '%s' "$service_name" | tr '[:upper:]' '[:lower:]')"

  case "$normalized" in
    http|http-alt|http-proxy|https|https-alt|ssl/http|sun-answerbook)
      return 0
      ;;
  esac

  case "$port" in
    80|81|280|443|591|593|3000|5000|8000|8008|8080|8081|8082|8088|8443|8888|9000|9090|9443)
      return 0
      ;;
  esac

  return 1
}

classify_tcp_ports() {
  local service_scan_file="$1"
  local open_tcp_ports_csv="$2"
  local port
  local detected_service
  local web_ports=()
  local non_web_ports=()

  for port in $(printf '%s\n' "$open_tcp_ports_csv" | tr ',' ' '); do
    detected_service="$(extract_detected_service "$service_scan_file" "$port")"
    if is_web_service "$port" "$detected_service"; then
      web_ports+=("$port")
    else
      non_web_ports+=("$port")
    fi
  done

  if [ "${#web_ports[@]}" -gt 0 ]; then
    local IFS=','
    WEB_PORTS="${web_ports[*]}"
  else
    WEB_PORTS=""
  fi

  if [ "${#non_web_ports[@]}" -gt 0 ]; then
    local IFS=','
    NON_WEB_PORTS="${non_web_ports[*]}"
  else
    NON_WEB_PORTS=""
  fi
}

log_info "Running discovery scans for $TARGET"

log_info "Running full TCP discovery scan"
nmap -n --reason -sS -Pn -p- --open \
  --min-rate "$NMAP_MIN_RATE" --max-retries 2 --stats-every "$NMAP_STATS_EVERY" \
  -oA "$FULL_TCP_BASE" "$TARGET"

log_info "Running top 100 UDP scan"
# T3 (not T4) gives nmap enough time to receive ICMP port-unreachable replies,
# so genuinely closed ports are marked closed rather than open|filtered.
nmap -n -sU -T3 -Pn --top-ports 100 --stats-every "$NMAP_STATS_EVERY" \
  -oA "$UDP_BASE" "$TARGET"

OPEN_TCP_PORTS="$(extract_ports_from_gnmap "$FULL_TCP_BASE.gnmap" tcp | paste -sd, -)"

# Collect open + open|filtered candidates from the discovery sweep, then run a
# lightweight version scan to confirm. Ports that respond to a service probe are
# promoted to strictly open; everything else is discarded as noise.
UDP_CANDIDATES="$(extract_ports_from_gnmap "$UDP_BASE.gnmap" udp 1 | paste -sd, -)"

if [ -n "$UDP_CANDIDATES" ]; then
  log_info "Confirming UDP candidates via version detection: $UDP_CANDIDATES"
  nmap -n -sU -sV --version-intensity 0 -Pn -p "$UDP_CANDIDATES" \
    --stats-every "$NMAP_STATS_EVERY" -oA "$UDP_CONFIRMED_BASE" "$TARGET"
  OPEN_UDP_PORTS="$(extract_ports_from_gnmap "$UDP_CONFIRMED_BASE.gnmap" udp 0 | paste -sd, -)"
else
  OPEN_UDP_PORTS=""
fi

if [ -n "$OPEN_TCP_PORTS" ]; then
  log_info "Running lightweight TCP service classification scan"
  nmap -n -sS -sV --version-light -Pn -p "$OPEN_TCP_PORTS" \
    --stats-every "$NMAP_STATS_EVERY" -oN "$TCP_SERVICE_BASE.nmap" "$TARGET"

  # Route anything identified as HTTP/HTTPS into the web workflow, even on
  # non-standard ports such as 8080/8082/8443.
  classify_tcp_ports "$TCP_SERVICE_BASE.nmap" "$OPEN_TCP_PORTS"
else
  WEB_PORTS=""
  NON_WEB_PORTS=""
fi

NON_WEB_UDP_PORTS="$OPEN_UDP_PORTS"

log_info "Discovery complete. Scan results saved under $OUTPUT_BASE"
