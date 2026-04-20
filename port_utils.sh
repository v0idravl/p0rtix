#!/usr/bin/env bash

normalize_port_list() {
  printf '%s' "${1:-}" \
    | tr 'N' 'n' \
    | sed -E 's/([0-9])n([0-9])/\1,\2/g; s/[[:space:]]+/,/g; s/,+/,/g; s/^,+//; s/,+$//'
}

sanitize_port_file() {
  local file_path="$1"
  local label="$2"
  local raw normalized validated invalid_entries

  if [ ! -f "$file_path" ]; then
    printf '%s' ""
    return 0
  fi

  raw="$(cat "$file_path" 2>/dev/null || true)"
  normalized="$(normalize_port_list "$raw")"

  if [ -n "$normalized" ]; then
    validated="$(printf '%s' "$normalized" | awk -F',' '
      {
        for (i = 1; i <= NF; i++) {
          port = $i
          if (port == "") {
            continue
          }
          if (port ~ /^[0-9]+$/ && port >= 1 && port <= 65535) {
            valid[port] = 1
          } else {
            invalid[++invalid_count] = port
          }
        }
      }
      END {
        for (port in valid) {
          print port
        }
        if (invalid_count > 0) {
          printf "__INVALID__:"
          for (i = 1; i <= invalid_count; i++) {
            printf "%s%s", (i > 1 ? "," : ""), invalid[i]
          }
          printf "\n"
        }
      }
    ' | sort -n | paste -sd, -)"
  else
    validated=""
  fi

  invalid_entries=""
  if printf '%s\n' "$validated" | grep -q '^__INVALID__:'; then
    invalid_entries="$(printf '%s\n' "$validated" | sed -n 's/^__INVALID__://p')"
    validated="$(printf '%s\n' "$validated" | grep -v '^__INVALID__:')"
  fi

  validated="${validated%,}"

  if [ "$normalized" != "$validated" ]; then
    echo "[!] Normalized $label from '$raw' to '$validated'" >&2
  fi
  if [ -n "$invalid_entries" ]; then
    echo "[!] Ignored invalid $label entries: $invalid_entries" >&2
  fi

  if [ -n "$validated" ]; then
    printf '%s\n' "$validated" | tr ',' '\n' > "$file_path"
  else
    : > "$file_path"
  fi

  printf '%s' "$validated"
}
