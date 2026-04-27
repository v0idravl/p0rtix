#!/usr/bin/env bash

# Keep log coloring optional so redirected output stays readable.
LOG_INFO_COLOR=""
LOG_WARN_COLOR=""
LOG_RESET_COLOR=""

if [ -t 1 ] && [ "${TERM:-}" != "dumb" ] && [ -z "${NO_COLOR:-}" ]; then
  LOG_INFO_COLOR="$(printf '\033[1;36m')"
  LOG_WARN_COLOR="$(printf '\033[1;33m')"
  LOG_RESET_COLOR="$(printf '\033[0m')"
fi

log_info() {
  # Standard user-facing status line for normal progress updates.
  printf '%s[*]%s %s\n' "$LOG_INFO_COLOR" "$LOG_RESET_COLOR" "$*"
}

log_warn() {
  # Warnings go to stderr so they still stand out in pipelines and tee output.
  printf '%s[*]%s %s\n' "$LOG_WARN_COLOR" "$LOG_RESET_COLOR" "$*" >&2
}
