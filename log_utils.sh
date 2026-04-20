#!/usr/bin/env bash

LOG_INFO_COLOR=""
LOG_WARN_COLOR=""
LOG_RESET_COLOR=""

if [ -t 1 ] && [ "${TERM:-}" != "dumb" ] && [ -z "${NO_COLOR:-}" ]; then
  LOG_INFO_COLOR="$(printf '\033[1;36m')"
  LOG_WARN_COLOR="$(printf '\033[1;33m')"
  LOG_RESET_COLOR="$(printf '\033[0m')"
fi

log_info() {
  printf '\n%s[*]%s %s\n\n' "$LOG_INFO_COLOR" "$LOG_RESET_COLOR" "$*"
}

log_warn() {
  printf '\n%s[*]%s %s\n\n' "$LOG_WARN_COLOR" "$LOG_RESET_COLOR" "$*" >&2
}
