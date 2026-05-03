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

web_scheme_for_target() {
  local service_name="$1"
  local port="$2"
  local normalized

  normalized="$(printf '%s' "$service_name" | tr '[:upper:]' '[:lower:]')"

  case "$normalized" in
    https|https-alt|ssl/http|ssl|ssl/*|tls|tls/*)
      printf '%s\n' "https"
      return 0
      ;;
    http|http-alt|http-proxy|sun-answerbook)
      printf '%s\n' "http"
      return 0
      ;;
  esac

  case "$port" in
    443|8443|9443)
      printf '%s\n' "https"
      ;;
    *)
      printf '%s\n' "http"
      ;;
  esac
}

csv_contains_script() {
  local csv="$1"
  local script="$2"
  local item

  while IFS= read -r item; do
    [ -n "$item" ] || continue
    if [ "$item" = "$script" ]; then
      return 0
    fi
  done < <(printf '%s\n' "$csv" | tr ',' '\n')

  return 1
}

append_unique_script() {
  local -n target_array="$1"
  local script="$2"
  local existing

  [ -n "$script" ] || return 0
  for existing in "${target_array[@]}"; do
    if [ "$existing" = "$script" ]; then
      return 0
    fi
  done

  target_array+=("$script")
}

high_roi_scripts_for_family() {
  local family="$1"

  case "$family" in
    http)
      printf '%s\n' \
        http-methods.nse \
        http-put.nse \
        http-git.nse \
        http-config-backup.nse \
        http-backup-finder.nse \
        http-apache-server-status.nse \
        http-auth-finder.nse \
        http-security-headers.nse
      ;;
    ssl)
      printf '%s\n' \
        ssl-cert.nse \
        ssl-date.nse \
        ssl-enum-ciphers.nse \
        tls-alpn.nse
      ;;
    ssh)
      printf '%s\n' \
        ssh-hostkey.nse \
        ssh-auth-methods.nse \
        ssh2-enum-algos.nse \
        sshv1.nse
      ;;
    dns)
      printf '%s\n' \
        dns-nsid.nse \
        dns-recursion.nse \
        dns-zone-transfer.nse
      ;;
    smb)
      printf '%s\n' \
        smb-os-discovery.nse \
        smb-protocols.nse \
        smb-security-mode.nse \
        smb2-security-mode.nse \
        smb2-time.nse
      ;;
    snmp)
      printf '%s\n' snmp-info.nse
      ;;
    ldap)
      printf '%s\n' ldap-rootdse.nse
      ;;
    ftp)
      printf '%s\n' \
        ftp-anon.nse \
        ftp-syst.nse
      ;;
    smtp)
      printf '%s\n' \
        smtp-commands.nse \
        smtp-open-relay.nse
      ;;
    pop3)
      printf '%s\n' pop3-capabilities.nse
      ;;
    imap)
      printf '%s\n' imap-capabilities.nse
      ;;
    mysql)
      printf '%s\n' mysql-info.nse
      ;;
    ms-sql)
      printf '%s\n' ms-sql-info.nse
      ;;
    redis)
      printf '%s\n' redis-info.nse
      ;;
    oracle)
      printf '%s\n' oracle-tns-version.nse
      ;;
    nfs)
      printf '%s\n' \
        nfs-showmount.nse \
        nfs-ls.nse \
        nfs-statfs.nse
      ;;
    rpc)
      printf '%s\n' rpcinfo.nse
      ;;
    rdp)
      printf '%s\n' \
        rdp-enum-encryption.nse \
        rdp-ntlm-info.nse
      ;;
    rsync)
      printf '%s\n' rsync-list-modules.nse
      ;;
    vnc)
      printf '%s\n' vnc-info.nse
      ;;
    telnet)
      printf '%s\n' telnet-encryption.nse
      ;;
    ntp)
      printf '%s\n' ntp-info.nse
      ;;
  esac
}

generic_tcp_scripts() {
  printf '%s\n' \
    banner.nse \
    fingerprint-strings.nse
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

  while IFS= read -r family; do
    [ -n "$family" ] || continue
    case " ${families[*]} " in
      *" $family "*) ;;
      *) families+=("$family") ;;
    esac
  done < <(service_families_for_target "$service_name" "$port" "$proto")

  for family in "${families[@]}"; do
    while IFS= read -r script; do
      [ -n "$script" ] || continue
      if csv_contains_script "$approved_csv" "$script"; then
          append_unique_script scripts "$script"
      fi
    done < <(high_roi_scripts_for_family "$family")
  done

  if [ "${#scripts[@]}" -eq 0 ] && [ "$proto" = "tcp" ] && [ -n "$approved_csv" ]; then
    while IFS= read -r script; do
      [ -n "$script" ] || continue
      if csv_contains_script "$approved_csv" "$script"; then
        append_unique_script scripts "$script"
      fi
    done < <(generic_tcp_scripts)
  fi

  if [ "${#scripts[@]}" -eq 0 ]; then
    printf '%s' ""
    return 0
  fi

  local IFS=','
  printf '%s' "${scripts[*]}"
}
