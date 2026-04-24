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
