#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/nmap"
TARGET="${1:-}"

if [ -z "$TARGET" ]; then
  read -rp "Target IP/hostname: " TARGET
fi

if [ -z "$TARGET" ]; then
  echo "No target provided. Exiting."
  exit 1
fi

mkdir -p "$OUTPUT_DIR"

nmap -n --reason -sS -Pn --top-ports 1000 --open \
  -oA "$OUTPUT_DIR/fast_tcp_$TARGET" "$TARGET"

nmap -n --reason -sS -Pn -p- --open \
  --min-rate 2000 --max-retries 2 --stats-every 15s \
  -oA "$OUTPUT_DIR/full_tcp_$TARGET" "$TARGET"

nmap -n -sU -T4 -Pn --top-ports 100 --stats-every 15s \
  -oA "$OUTPUT_DIR/top_100_udp_$TARGET" "$TARGET"

PORTS=$(awk -F'[:/, ]+' '/Ports:/{for(i=1;i<=NF;i++) if($(i+1)=="open") print $i}' "$OUTPUT_DIR/full_tcp_$TARGET.gnmap" | sort -nu | paste -sd,)
WEBSCAN_SCRIPT="$SCRIPT_DIR/webscan.sh"
MISC_SCRIPT="$SCRIPT_DIR/misc_services.sh"

if [ -n "$PORTS" ]; then
  nmap -n -sS -sV --version-light -sC -O -Pn -p "$PORTS" \
    -oA "$OUTPUT_DIR/service_enum_$TARGET" "$TARGET"

  nmap -n -sS -sV -Pn -p "$PORTS" \
    --script "vuln and not dos" \
    -oA "$OUTPUT_DIR/service_vuln_$TARGET" "$TARGET"

  if [ -x "$WEBSCAN_SCRIPT" ] && printf '%s\n' "$PORTS" | grep -qE '(^|,)80(,|$)|(^|,)443(,|$)'; then
    for p in 80 443; do
      if printf '%s\n' "$PORTS" | grep -qE "(^|,)$p(,|$)"; then
        "$WEBSCAN_SCRIPT" "$TARGET" "$p"
      fi
    done
  fi

  if [ -x "$MISC_SCRIPT" ]; then
    "$MISC_SCRIPT" "$TARGET" "$PORTS"
  fi
else
  echo "No open TCP ports found in full scan; skipping service enumeration and vuln scans."
fi

# Fallback full TCP scan using TCP connect if SYN scan is too slow or blocked
 nmap -sT -p- --min-rate 5000 --max-retries 1 -oA "$OUTPUT_DIR/limited_tcp_$TARGET" "$TARGET"

COMBINED_FILE="$OUTPUT_DIR/combined_${TARGET}.nmap"
: > "$COMBINED_FILE"

for phase in fast_tcp full_tcp top_100_udp service_enum service_vuln limited_tcp; do
  phase_file="$OUTPUT_DIR/${phase}_$TARGET.nmap"
  if [ -f "$phase_file" ]; then
    printf "\n===== %s =====\n" "$phase" >> "$COMBINED_FILE"
    cat "$phase_file" >> "$COMBINED_FILE"
  fi
 done

echo "Combined human-readable output written to: $COMBINED_FILE"
