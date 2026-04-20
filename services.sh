#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-}"
PORTS="${2:-}"
OUTPUT_BASE="${3:-}"

usage() {
  cat <<EOF
Usage: $0 <target-ip-or-hostname> <service-ports> <output-base-dir>

Example:
  $0 10.10.10.10 22,53,445 /home/user/Projects/p0rtix/output/10.10.10.10
EOF
  exit 1
}

if [ -z "$TARGET" ] || [ -z "$PORTS" ] || [ -z "$OUTPUT_BASE" ]; then
  usage
fi

SERVICE_DIR="$OUTPUT_BASE/services"
mkdir -p "$SERVICE_DIR"
OUTPUT_BASE_FILE="$SERVICE_DIR/${TARGET}_services"

run_scan_file() {
  local output_file="$1"
  shift
  "$@" -oN "$output_file" "$TARGET" >/dev/null 2>&1 || true
}

run_capture_file() {
  local output_file="$1"
  shift
  "$@" > "$output_file" 2>&1 || true
}

PORTS="$(printf '%s' "$PORTS" | tr -d ' \t\r\n')"
printf "Running non-web service checks for %s on ports: %s\n" "$TARGET" "$PORTS"

IFS=',' read -r -a ports <<< "$PORTS"
for target_port in "${ports[@]}"; do
  target_port="$(printf '%s' "$target_port" | tr -d '[:space:]')"
  if [ -z "$target_port" ]; then
    continue
  fi
  if [[ "$target_port" == */* ]]; then
    proto="${target_port%%/*}"
    port="${target_port##*/}"
  else
    proto="tcp"
    port="$target_port"
  fi
  scan_flag="-sS"
  if [ "$proto" = "udp" ]; then
    scan_flag="-sU"
  fi
  case "$port" in
    21)
      if [ "$proto" != "tcp" ]; then
        echo "[*] No dedicated UDP service checks defined for $TARGET:$port"
        continue
      fi
      echo "[*] FTP service detected on $TARGET:$port"
      run_scan_file "${OUTPUT_BASE_FILE}_ftp.txt" nmap --script=ftp-* -p "$port"
      
      run_scan_file "${OUTPUT_BASE_FILE}_ftp_vuln.txt" nmap --script="ftp-vuln* and not dos" -p "$port"
      ;;
    22)
      if [ "$proto" != "tcp" ]; then
        echo "[*] No dedicated UDP service checks defined for $TARGET:$port"
        continue
      fi
      echo "[*] SSH service detected on $TARGET:$port"
      run_scan_file "${OUTPUT_BASE_FILE}_ssh_algos.txt" nmap -p "$port" --script ssh2-enum-algos
      
      run_scan_file "${OUTPUT_BASE_FILE}_ssh_hostkey.txt" nmap -p "$port" --script ssh-hostkey --script-args ssh_hostkey=full
      
      run_scan_file "${OUTPUT_BASE_FILE}_ssh_auth_methods.txt" nmap -p "$port" --script ssh-auth-methods
      
      run_scan_file "${OUTPUT_BASE_FILE}_ssh_vuln.txt" nmap --script="ssh-vuln* and not dos" -p "$port"
      ;;
    53)
      echo "[*] DNS service detected on $TARGET:$proto/$port"
      run_scan_file "${OUTPUT_BASE_FILE}_${proto}_dns.txt" nmap -n "$scan_flag" --script "(default and *dns*) or fcrdns or dns-srv-enum" -p "$port"
      
      run_scan_file "${OUTPUT_BASE_FILE}_${proto}_dns_vuln.txt" nmap "$scan_flag" --script="dns-vuln* and not dos" -p "$port"
      ;;
    111|2049)
      echo "[*] RPC/NFS service detected on $TARGET:$proto/$port"
      run_scan_file "${OUTPUT_BASE_FILE}_${proto}_rpcinfo_${port}.txt" nmap "$scan_flag" -p "$port" --script=rpcinfo
      ;;
    139|445)
      if [ "$proto" != "tcp" ]; then
        echo "[*] No dedicated UDP SMB checks defined for $TARGET:$port"
        continue
      fi
      echo "[*] SMB service detected on $TARGET:$port"
      run_scan_file "${OUTPUT_BASE_FILE}_smb_os_discovery.txt" nmap --script=smb-os-discovery.nse -p "$port"
      
      run_scan_file "${OUTPUT_BASE_FILE}_smb_enum.txt" nmap --script "safe or smb-enum-*" -p "$port"
      
      echo "[*] SMB vuln scripts"
      nmap -sS -p "$port" -Pn --script "smb-vuln* and not dos" --script-args=unsafe=1 -oA "${SERVICE_DIR}/smb_vuln_scan_${TARGET}" "$TARGET" >/dev/null 2>&1 || true
      ;;
    161)
      echo "[*] SNMP service detected on $TARGET:$proto/$port"
      if [ "$proto" = "udp" ]; then
        echo "[*] SNMP public community walk"
        run_capture_file "${OUTPUT_BASE_FILE}_${proto}_snmp_public.txt" snmpwalk -v 2c -c public "$TARGET"
      fi
      
      run_scan_file "${OUTPUT_BASE_FILE}_${proto}_snmp.txt" nmap "$scan_flag" --script "snmp* and not snmp-brute" -p "$port"
      
      run_scan_file "${OUTPUT_BASE_FILE}_${proto}_snmp_vuln.txt" nmap "$scan_flag" --script="snmp-vuln* and not dos" -p "$port"
      ;;
    5985|5986)
      if [ "$proto" != "tcp" ]; then
        echo "[*] No dedicated UDP WinRM checks defined for $TARGET:$port"
        continue
      fi
      echo "[*] WinRM service detected on $TARGET:$port"
      run_scan_file "${OUTPUT_BASE_FILE}_winrm.txt" nmap -p "$port" --script=http-windows*
      
      run_scan_file "${OUTPUT_BASE_FILE}_winrm_vuln.txt" nmap --script="http-vuln* and not dos" -p "$port"
      ;;
    80|443)
      if [ "$proto" = "tcp" ]; then
        echo "[*] Skipping web port $port in services checks"
      else
        echo "[*] No dedicated UDP web checks defined for $TARGET:$port"
      fi
      ;;
    *)
      echo "[*] No dedicated $proto service checks defined for $TARGET:$port"
      ;;
  esac
done

echo "Non-web service outputs written to: $SERVICE_DIR"
