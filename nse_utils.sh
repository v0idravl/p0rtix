#!/usr/bin/env bash

# Shared NSE selection rules live here so web and service scans stay consistent.
NMAP_SCRIPT_DIR="${NMAP_SCRIPT_DIR:-/usr/share/nmap/scripts}"

nse_script_has_portrule() {
  local script="$1"
  # Ignore scripts that are meant for host, broadcast, or discovery-only runs.
  grep -Eq '^[[:space:]]*portrule[[:space:]]*=' "$NMAP_SCRIPT_DIR/$script"
}

nse_script_categories() {
  local script="$1"
  awk '
    /^[[:space:]]*categories[[:space:]]*=/ {
      capture = 1
    }
    capture {
      printf "%s", $0
      if ($0 ~ /}/) {
        exit
      }
    }
  ' "$NMAP_SCRIPT_DIR/$script" 2>/dev/null || true
}

nse_script_excluded() {
  local script="$1"
  local categories

  categories="$(nse_script_categories "$script")"

  # Drop NSE categories that overlap with -sC or exceed the intended safety level.
  case "$categories" in
    *default*|*brute*|*dos*|*exploit*|*fuzzer*)
      return 0
      ;;
  esac

  return 1
}

load_allowed_nse_scripts() {
  local script
  local allowed=()

  if [ ! -d "$NMAP_SCRIPT_DIR" ]; then
    log_warn "Nmap script directory not found: $NMAP_SCRIPT_DIR"
    printf '%s' ""
    return 0
  fi

  while IFS= read -r script; do
    script="$(basename "$script")"

    # Let Nmap decide if the script matches the current service, but only after
    # we have enforced our own category-based safety filters.
    if ! nse_script_has_portrule "$script"; then
      continue
    fi

    if nse_script_excluded "$script"; then
      continue
    fi

    allowed+=("$script")
  done < <(find "$NMAP_SCRIPT_DIR" -maxdepth 1 -type f -name '*.nse' | sort)

  if [ "${#allowed[@]}" -eq 0 ]; then
    printf '%s' ""
    return 0
  fi

  # Nmap accepts a comma-separated script list for a single --script argument.
  local IFS=','
  printf '%s' "${allowed[*]}"
}

extract_detected_service() {
  local baseline_file="$1"
  local port="$2"
  local proto="$3"

  awk -v target="$port/$proto" '
    $1 == target {
      print $3
      exit
    }
  ' "$baseline_file" 2>/dev/null
}

service_families_for_target() {
  local service_name="$1"
  local port="$2"
  local proto="$3"
  local normalized

  normalized="$(printf '%s' "$service_name" | tr '[:upper:]' '[:lower:]')"

  case "$normalized" in
    ssh|ssh?*)
      printf '%s\n' ssh
      ;;
    http|http-alt|http-proxy|sun-answerbook)
      printf '%s\n' http
      ;;
    https|https-alt|ssl/http|https?)
      printf '%s\n' http
      printf '%s\n' ssl
      ;;
    ssl|ssl/*|tls|tls/*)
      printf '%s\n' ssl
      ;;
    domain|dns)
      printf '%s\n' dns
      ;;
    microsoft-ds|netbios-ssn)
      printf '%s\n' smb
      ;;
    snmp)
      printf '%s\n' snmp
      ;;
    ldap|ldapssl|ssl/ldap)
      printf '%s\n' ldap
      ;;
    ftp)
      printf '%s\n' ftp
      ;;
    smtp)
      printf '%s\n' smtp
      ;;
    pop3)
      printf '%s\n' pop3
      ;;
    imap)
      printf '%s\n' imap
      ;;
    mysql)
      printf '%s\n' mysql
      ;;
    postgresql)
      printf '%s\n' pgsql
      ;;
    ms-sql-s|mssql)
      printf '%s\n' ms-sql
      ;;
    redis)
      printf '%s\n' redis
      ;;
    oracle|oracle-tns)
      printf '%s\n' oracle
      ;;
    nfs)
      printf '%s\n' nfs
      ;;
    rpcbind)
      printf '%s\n' rpc
      ;;
    ms-wbt-server|rdp)
      printf '%s\n' rdp
      ;;
    rsync)
      printf '%s\n' rsync
      ;;
    vnc|vnc-http)
      printf '%s\n' vnc
      ;;
    telnet)
      printf '%s\n' telnet
      ;;
    tftp)
      printf '%s\n' tftp
      ;;
    ntp)
      printf '%s\n' ntp
      ;;
  esac

  case "$proto/$port" in
    tcp/22)
      printf '%s\n' ssh
      ;;
    tcp/80)
      printf '%s\n' http
      ;;
    tcp/443)
      printf '%s\n' http
      printf '%s\n' ssl
      ;;
    tcp/25)
      printf '%s\n' smtp
      ;;
    tcp/110)
      printf '%s\n' pop3
      ;;
    tcp/143)
      printf '%s\n' imap
      ;;
    tcp/445|tcp/139)
      printf '%s\n' smb
      ;;
    tcp/53|udp/53)
      printf '%s\n' dns
      ;;
    udp/161)
      printf '%s\n' snmp
      ;;
    tcp/111|udp/111)
      printf '%s\n' rpc
      ;;
    tcp/2049)
      printf '%s\n' nfs
      ;;
    tcp/3306)
      printf '%s\n' mysql
      ;;
    tcp/5432)
      printf '%s\n' pgsql
      ;;
    tcp/3389)
      printf '%s\n' rdp
      ;;
    tcp/6379)
      printf '%s\n' redis
      ;;
  esac
}

script_matches_family() {
  local script="$1"
  local family="$2"

  case "$family" in
    ssh)
      [[ "$script" == ssh* ]]
      ;;
    http)
      [[ "$script" == http-* || "$script" == https-* || "$script" == xmlrpc-* ]]
      ;;
    ssl)
      [[ "$script" == ssl-* || "$script" == tls-* || "$script" == sslv2* ]]
      ;;
    dns)
      [[ "$script" == dns-* || "$script" == fcrdns.nse ]]
      ;;
    smb)
      [[ "$script" == smb-* || "$script" == smb2-* ]]
      ;;
    snmp)
      [[ "$script" == snmp-* ]]
      ;;
    ldap)
      [[ "$script" == ldap-* ]]
      ;;
    ftp)
      [[ "$script" == ftp-* ]]
      ;;
    smtp)
      [[ "$script" == smtp-* ]]
      ;;
    pop3)
      [[ "$script" == pop3-* ]]
      ;;
    imap)
      [[ "$script" == imap-* ]]
      ;;
    mysql)
      [[ "$script" == mysql-* ]]
      ;;
    pgsql)
      [[ "$script" == pgsql-* ]]
      ;;
    ms-sql)
      [[ "$script" == ms-sql-* ]]
      ;;
    redis)
      [[ "$script" == redis-* ]]
      ;;
    oracle)
      [[ "$script" == oracle-* ]]
      ;;
    nfs)
      [[ "$script" == nfs-* ]]
      ;;
    rpc)
      [[ "$script" == rpc* ]]
      ;;
    rdp)
      [[ "$script" == rdp-* ]]
      ;;
    rsync)
      [[ "$script" == rsync-* ]]
      ;;
    vnc)
      [[ "$script" == vnc-* ]]
      ;;
    telnet)
      [[ "$script" == telnet-* ]]
      ;;
    tftp)
      [[ "$script" == tftp-* ]]
      ;;
    ntp)
      [[ "$script" == ntp-* ]]
      ;;
  esac
}

build_relevant_nse_scripts() {
  local approved_csv="$1"
  local service_name="$2"
  local port="$3"
  local proto="$4"
  local script
  local family
  local scripts=()
  local families=()
  local generic_tcp_csv="banner.nse,fingerprint-strings.nse,vulners.nse"

  while IFS= read -r family; do
    [ -n "$family" ] || continue
    case " ${families[*]} " in
      *" $family "*) ;;
      *) families+=("$family") ;;
    esac
  done < <(service_families_for_target "$service_name" "$port" "$proto")

  if [ -n "$approved_csv" ]; then
    while IFS= read -r script; do
      [ -n "$script" ] || continue

      for family in "${families[@]}"; do
        if script_matches_family "$script" "$family"; then
          scripts+=("$script")
          break
        fi
      done
    done < <(printf '%s\n' "$approved_csv" | tr ',' '\n')
  fi

  if [ "${#scripts[@]}" -eq 0 ] && [ "$proto" = "tcp" ]; then
    while IFS= read -r script; do
      [ -n "$script" ] || continue
      if printf '%s\n' "$approved_csv" | tr ',' '\n' | grep -Fxq "$script"; then
        scripts+=("$script")
      fi
    done < <(printf '%s\n' "$generic_tcp_csv" | tr ',' '\n')
  fi

  if [ "${#scripts[@]}" -eq 0 ]; then
    printf '%s' ""
    return 0
  fi

  local IFS=','
  printf '%s' "${scripts[*]}"
}
