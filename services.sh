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

printf "Running non-web service checks for %s on ports: %s\n" "$TARGET" "$PORTS"

IFS=',' read -r -a ports <<< "$PORTS"
for port in "${ports[@]}"; do
  case "$port" in
    21)
      echo "[*] FTP service detected on $TARGET:$port"
      echo "# Command: nmap --script=ftp-* -p \"$port\" -oN \"${OUTPUT_BASE_FILE}_ftp.txt\" \"$TARGET\"" > "${OUTPUT_BASE_FILE}_ftp.txt"
      nmap --script=ftp-* -p "$port" -oN "${OUTPUT_BASE_FILE}_ftp.txt" "$TARGET" 2>/dev/null >> "${OUTPUT_BASE_FILE}_ftp.txt" || true
      
      echo "# Command: nmap --script=\"ftp-vuln* and not dos\" -p \"$port\" -oN \"${OUTPUT_BASE_FILE}_ftp_vuln.txt\" \"$TARGET\"" > "${OUTPUT_BASE_FILE}_ftp_vuln.txt"
      nmap --script="ftp-vuln* and not dos" -p "$port" -oN "${OUTPUT_BASE_FILE}_ftp_vuln.txt" "$TARGET" 2>/dev/null >> "${OUTPUT_BASE_FILE}_ftp_vuln.txt" || true
      ;;
    22)
      echo "[*] SSH service detected on $TARGET:$port"
      echo "# Command: nmap -p \"$port\" --script ssh2-enum-algos -oN \"${OUTPUT_BASE_FILE}_ssh_algos.txt\" \"$TARGET\"" > "${OUTPUT_BASE_FILE}_ssh_algos.txt"
      nmap -p "$port" --script ssh2-enum-algos -oN "${OUTPUT_BASE_FILE}_ssh_algos.txt" "$TARGET" 2>/dev/null >> "${OUTPUT_BASE_FILE}_ssh_algos.txt" || true
      
      echo "# Command: nmap -p \"$port\" --script ssh-hostkey --script-args ssh_hostkey=full -oN \"${OUTPUT_BASE_FILE}_ssh_hostkey.txt\" \"$TARGET\"" > "${OUTPUT_BASE_FILE}_ssh_hostkey.txt"
      nmap -p "$port" --script ssh-hostkey --script-args ssh_hostkey=full -oN "${OUTPUT_BASE_FILE}_ssh_hostkey.txt" "$TARGET" 2>/dev/null >> "${OUTPUT_BASE_FILE}_ssh_hostkey.txt" || true
      
      echo "# Command: nmap -p \"$port\" --script ssh-auth-methods -oN \"${OUTPUT_BASE_FILE}_ssh_auth_methods.txt\" \"$TARGET\"" > "${OUTPUT_BASE_FILE}_ssh_auth_methods.txt"
      nmap -p "$port" --script ssh-auth-methods -oN "${OUTPUT_BASE_FILE}_ssh_auth_methods.txt" "$TARGET" 2>/dev/null >> "${OUTPUT_BASE_FILE}_ssh_auth_methods.txt" || true
      
      echo "# Command: nmap --script=\"ssh-vuln* and not dos\" -p \"$port\" -oN \"${OUTPUT_BASE_FILE}_ssh_vuln.txt\" \"$TARGET\"" > "${OUTPUT_BASE_FILE}_ssh_vuln.txt"
      nmap --script="ssh-vuln* and not dos" -p "$port" -oN "${OUTPUT_BASE_FILE}_ssh_vuln.txt" "$TARGET" 2>/dev/null >> "${OUTPUT_BASE_FILE}_ssh_vuln.txt" || true
      ;;
    53)
      echo "[*] DNS service detected on $TARGET:$port"
      echo "# Command: nmap -n --script \"(default and *dns*) or fcrdns or dns-srv-enum\" -p \"$port\" -oN \"${OUTPUT_BASE_FILE}_dns.txt\" \"$TARGET\"" > "${OUTPUT_BASE_FILE}_dns.txt"
      nmap -n --script "(default and *dns*) or fcrdns or dns-srv-enum" -p "$port" -oN "${OUTPUT_BASE_FILE}_dns.txt" "$TARGET" 2>/dev/null >> "${OUTPUT_BASE_FILE}_dns.txt" || true
      
      echo "# Command: nmap --script=\"dns-vuln* and not dos\" -p \"$port\" -oN \"${OUTPUT_BASE_FILE}_dns_vuln.txt\" \"$TARGET\"" > "${OUTPUT_BASE_FILE}_dns_vuln.txt"
      nmap --script="dns-vuln* and not dos" -p "$port" -oN "${OUTPUT_BASE_FILE}_dns_vuln.txt" "$TARGET" 2>/dev/null >> "${OUTPUT_BASE_FILE}_dns_vuln.txt" || true
      ;;
    111|2049)
      echo "[*] RPC/NFS service detected on $TARGET:$port"
      echo "# Command: nmap -p \"$port\" --script=rpcinfo -oN \"${OUTPUT_BASE_FILE}_rpcinfo_${port}.txt\" \"$TARGET\"" > "${OUTPUT_BASE_FILE}_rpcinfo_${port}.txt"
      nmap -p "$port" --script=rpcinfo -oN "${OUTPUT_BASE_FILE}_rpcinfo_${port}.txt" "$TARGET" 2>/dev/null >> "${OUTPUT_BASE_FILE}_rpcinfo_${port}.txt" || true
      ;;
    139|445)
      echo "[*] SMB service detected on $TARGET:$port"
      echo "# Command: nmap --script=smb-os-discovery.nse -p \"$port\" -oN \"${OUTPUT_BASE_FILE}_smb_os_discovery.txt\" \"$TARGET\"" > "${OUTPUT_BASE_FILE}_smb_os_discovery.txt"
      nmap --script=smb-os-discovery.nse -p "$port" -oN "${OUTPUT_BASE_FILE}_smb_os_discovery.txt" "$TARGET" 2>/dev/null >> "${OUTPUT_BASE_FILE}_smb_os_discovery.txt" || true
      
      echo "# Command: nmap --script \"safe or smb-enum-*\" -p \"$port\" -oN \"${OUTPUT_BASE_FILE}_smb_enum.txt\" \"$TARGET\"" > "${OUTPUT_BASE_FILE}_smb_enum.txt"
      nmap --script "safe or smb-enum-*" -p "$port" -oN "${OUTPUT_BASE_FILE}_smb_enum.txt" "$TARGET" 2>/dev/null >> "${OUTPUT_BASE_FILE}_smb_enum.txt" || true
      
      echo "# Command: nmap -sS -p \"$port\" -Pn --script \"smb-vuln* and not dos\" --script-args=unsafe=1 -oA \"${SERVICE_DIR}/smb_vuln_scan_${TARGET}\" \"$TARGET\"" > "${SERVICE_DIR}/smb_vuln_scan_${TARGET}.nmap"
      nmap -sS -p "$port" -Pn --script "smb-vuln* and not dos" --script-args=unsafe=1 -oA "${SERVICE_DIR}/smb_vuln_scan_${TARGET}" "$TARGET" 2>/dev/null >> "${SERVICE_DIR}/smb_vuln_scan_${TARGET}.nmap" || true
      ;;
    161)
      echo "[*] SNMP service detected on $TARGET:$port"
      echo "# Command: snmpwalk -v 2c -c public \"$TARGET\"" > "${OUTPUT_BASE_FILE}_snmp_public.txt"
      snmpwalk -v 2c -c public "$TARGET" >> "${OUTPUT_BASE_FILE}_snmp_public.txt" 2>/dev/null || true
      
      echo "# Command: nmap --script \"snmp* and not snmp-brute\" -p \"$port\" -oN \"${OUTPUT_BASE_FILE}_snmp.txt\" \"$TARGET\"" > "${OUTPUT_BASE_FILE}_snmp.txt"
      nmap --script "snmp* and not snmp-brute" -p "$port" -oN "${OUTPUT_BASE_FILE}_snmp.txt" "$TARGET" 2>/dev/null >> "${OUTPUT_BASE_FILE}_snmp.txt" || true
      
      echo "# Command: nmap --script=\"snmp-vuln* and not dos\" -p \"$port\" -oN \"${OUTPUT_BASE_FILE}_snmp_vuln.txt\" \"$TARGET\"" > "${OUTPUT_BASE_FILE}_snmp_vuln.txt"
      nmap --script="snmp-vuln* and not dos" -p "$port" -oN "${OUTPUT_BASE_FILE}_snmp_vuln.txt" "$TARGET" 2>/dev/null >> "${OUTPUT_BASE_FILE}_snmp_vuln.txt" || true
      ;;
    5985|5986)
      echo "[*] WinRM service detected on $TARGET:$port"
      echo "# Command: nmap -p \"$port\" --script=http-windows* -oN \"${OUTPUT_BASE_FILE}_winrm.txt\" \"$TARGET\"" > "${OUTPUT_BASE_FILE}_winrm.txt"
      nmap -p "$port" --script=http-windows* -oN "${OUTPUT_BASE_FILE}_winrm.txt" "$TARGET" 2>/dev/null >> "${OUTPUT_BASE_FILE}_winrm.txt" || true
      
      echo "# Command: nmap --script=\"http-vuln* and not dos\" -p \"$port\" -oN \"${OUTPUT_BASE_FILE}_winrm_vuln.txt\" \"$TARGET\"" > "${OUTPUT_BASE_FILE}_winrm_vuln.txt"
      nmap --script="http-vuln* and not dos" -p "$port" -oN "${OUTPUT_BASE_FILE}_winrm_vuln.txt" "$TARGET" 2>/dev/null >> "${OUTPUT_BASE_FILE}_winrm_vuln.txt" || true
      ;;
    80|443)
      echo "[*] Skipping web port $port in services checks"
      ;;
    *)
      echo "[*] No dedicated service checks defined for $TARGET:$port"
      ;;
  esac
done

echo "Non-web service outputs written to: $SERVICE_DIR"
