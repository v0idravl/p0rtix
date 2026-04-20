#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/misc"
IP="${1:-}"
PORTS="${2:-}"

usage() {
  cat <<EOF
Usage: $0 <target-ip-or-hostname> <port1,port2,...>

Example:
  $0 10.10.10.10 22,25,110
EOF
  exit 1
}

if [ -z "$IP" ] || [ -z "$PORTS" ]; then
  usage
fi

mkdir -p "$OUTPUT_DIR"
OUTPUT_BASE="$OUTPUT_DIR/${IP}_misc"

printf "Running misc service checks for %s on ports: %s\n" "$IP" "$PORTS"

SMB_PORTS=()
SNMP_TRIGGER=0
IFS=',' read -r -a ports <<< "$PORTS"
for port in "${ports[@]}"; do
  case "$port" in
    21)
      echo "[*] running FTP NSE scripts for $IP:$port"
      nmap --script=ftp-* -p "$port" -oN "${OUTPUT_BASE}_ftp_nmap.txt" "$IP" 2>&1 || true
      ;;
    161|162)
      if [ "$SNMP_TRIGGER" -eq 0 ]; then
        echo "[*] probing SNMP public"
        snmpwalk -v 2c -c public "$IP" > "${OUTPUT_BASE}_snmp_public.txt" 2>&1 || true
        echo "[*] probing SNMP private"
        snmpwalk -v 2c -c private "$IP" > "${OUTPUT_BASE}_snmp_private.txt" 2>&1 || true
        echo "[*] running SNMP NSE scripts"
        nmap --script "snmp* and not snmp-brute" -p 161,162 -oN "${OUTPUT_BASE}_snmp_nmap.txt" "$IP" 2>&1 || true
        SNMP_TRIGGER=1
      fi
      ;;
    445|139)
      SMB_PORTS+=("$port")
      ;;
    22)
      echo "[*] running SSH algorithm enumeration for $IP:$port"
      nmap -p22 --script ssh2-enum-algos -oN "${OUTPUT_BASE}_ssh_algos.txt" "$IP" 2>&1 || true
      echo "[*] retrieving SSH hostkey info for $IP:$port"
      nmap -p22 --script ssh-hostkey --script-args ssh_hostkey=full -oN "${OUTPUT_BASE}_ssh_hostkey.txt" "$IP" 2>&1 || true
      echo "[*] checking SSH auth methods for $IP:$port"
      nmap -p22 --script ssh-auth-methods --script-args="ssh.user=root" -oN "${OUTPUT_BASE}_ssh_auth_methods.txt" "$IP" 2>&1 || true
      ;;
    23)
      echo "[*] running Telnet NSE scripts for $IP:$port"
      nmap -n -sV -Pn --script "*telnet* and safe" -p 23 -oN "${OUTPUT_BASE}_telnet_nmap.txt" "$IP" 2>&1 || true
      ;;
    53)
      echo "[*] running DNS NSE scripts for $IP:$port"
      nmap -n --script "(default and *dns*) or fcrdns or dns-srv-enum or dns-random-txid or dns-random-srcport" -p 53 -oN "${OUTPUT_BASE}_dns_53.txt" "$IP" 2>&1 || true
      ;;
    123)
      echo "[*] running NTP NSE scripts for $IP:$port"
      nmap -sU -sV --script "ntp* and (discovery or vuln) and not (dos or brute)" -p 123 -oN "${OUTPUT_BASE}_ntp_discovery.txt" "$IP" 2>&1 || true
      nmap -sU -p123 --script ntp-monlist -oN "${OUTPUT_BASE}_ntp_monlist.txt" "$IP" 2>&1 || true
      ;;
    389|636|3268|3269)
      echo "[*] running LDAP NSE scripts for $IP:$port"
      nmap -n -sV --script "ldap* and not brute" -p "$port" -oN "${OUTPUT_BASE}_ldap_${port}.txt" "$IP" 2>&1 || true
      ;;
    554|8554)
      echo "[*] running RTSP NSE scripts for $IP:$port"
      nmap -sV --script "rtsp-*" -p "$port" -oN "${OUTPUT_BASE}_rtsp_${port}.txt" "$IP" 2>&1 || true
      ;;
    3306)
      echo "[*] running MySQL NSE scripts for $IP:$port"
      nmap -sV -p 3306 --script mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 -oN "${OUTPUT_BASE}_mysql_3306.txt" "$IP" 2>&1 || true
      ;;
    3389)
      echo "[*] running RDP NSE scripts for $IP:$port"
      nmap --script "rdp-enum-encryption or rdp-vuln-ms12-020 or rdp-ntlm-info" -p 3389 -T4 -oN "${OUTPUT_BASE}_rdp_3389.txt" "$IP" 2>&1 || true
      ;;
    3632)
      echo "[*] checking distcc CVE-2004-2687 for $IP:$port"
      nmap -p 3632 --script distcc-cve2004-2687 --script-args="distcc-exec.cmd='id'" -oN "${OUTPUT_BASE}_distcc_3632.txt" "$IP" 2>&1 || true
      ;;
    25)
      echo "[*] running SMTP NSE scripts for $IP:$port"
      nmap -p25 --script smtp-* -sV -oN "${OUTPUT_BASE}_smtp_25.txt" "$IP" 2>&1 || true
      ;;
    465)
      echo "[*] running SMTPS NSE scripts for $IP:$port"
      nmap -p465 --script smtp-* -sV --script-args smtp.ssl=true -oN "${OUTPUT_BASE}_smtp_465.txt" "$IP" 2>&1 || true
      ;;
    587)
      echo "[*] running SMTP submission NSE scripts for $IP:$port"
      nmap -p587 --script smtp-* -sV -oN "${OUTPUT_BASE}_smtp_587.txt" "$IP" 2>&1 || true
      ;;
    80|443)
      # skip web ports here; webscan handles these
      ;;
    *)
      echo "[*] no extra misc scripts defined for $IP:$port"
      ;;
  esac
 done

if [ "${#SMB_PORTS[@]}" -gt 0 ]; then
  SMB_PORT_CSV=$(IFS=,; echo "${SMB_PORTS[*]}")
  echo "[*] running SMB discovery and vuln scan for $IP on ports: $SMB_PORT_CSV"
  nmap --script=smb-os-discovery.nse -p "$SMB_PORT_CSV" -oN "${OUTPUT_BASE}_smb_os_discovery.txt" "$IP" 2>&1 || true
  nmap --script "safe or smb-enum-*" -p "$SMB_PORT_CSV" -oN "${OUTPUT_BASE}_smb_safe_enum.txt" "$IP" 2>&1 || true
  nmap -sS -p "$SMB_PORT_CSV" -Pn --script smb-vuln* --script-args=unsafe=1 -oA "$OUTPUT_DIR/smb_vuln_scan_${IP}" "$IP" 2>&1 || true
fi

echo "Misc service outputs written to: $OUTPUT_DIR"
