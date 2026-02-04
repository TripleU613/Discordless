#!/usr/bin/env bash
set -euo pipefail

DISCOURSE_ROOT="${DISCOURSE_ROOT:-}"
LOG_DIR="${LOG_DIR:-}"
LOG_FILE="${REBUILD_LOG:-}"

if [[ -z "${DISCOURSE_ROOT}" ]]; then
  if [[ -x /var/discourse/launcher ]]; then
    DISCOURSE_ROOT="/var/discourse"
  elif command -v launcher >/dev/null 2>&1; then
    LAUNCHER_BIN="$(command -v launcher)"
    DISCOURSE_ROOT="$(cd "$(dirname "${LAUNCHER_BIN}")" && pwd)"
  else
    for base in /var /srv /opt; do
      if [[ -d "${base}" ]]; then
        candidate="$(find "${base}" -maxdepth 4 -name launcher -type f -perm -u+x 2>/dev/null | head -n 1)"
        if [[ -n "${candidate}" ]]; then
          DISCOURSE_ROOT="$(cd "$(dirname "${candidate}")" && pwd)"
          break
        fi
      fi
    done
  fi
fi

if [[ -z "${DISCOURSE_ROOT}" || ! -x "${DISCOURSE_ROOT}/launcher" ]]; then
  echo "Unable to locate Discourse launcher. Set DISCOURSE_ROOT=/path/to/discourse." >&2
  exit 1
fi

if [[ -z "${LOG_DIR}" ]]; then
  if [[ -d /var/www/errorpages ]]; then
    LOG_DIR="/var/www/errorpages/logs"
  else
    offline="$(find /var/www -maxdepth 5 -name discourse_offline.html -type f 2>/dev/null | head -n 1)"
    if [[ -n "${offline}" ]]; then
      LOG_DIR="$(dirname "${offline}")/logs"
    fi
  fi
fi

if [[ -z "${LOG_DIR}" ]]; then
  LOG_DIR="/var/www/errorpages/logs"
fi

if [[ -z "${LOG_FILE}" ]]; then
  LOG_FILE="${LOG_DIR}/rebuild.log"
fi

if ! mkdir -p "$(dirname "${LOG_FILE}")" 2>/dev/null; then
  LOG_FILE="/tmp/discourse-rebuild.log"
  mkdir -p "$(dirname "${LOG_FILE}")"
fi
: > "${LOG_FILE}"

timestamp() {
  TZ=UTC date +"%Y-%m-%dT%H:%M:%SZ"
}

echo "$(timestamp) [rebuild] starting rebuild" >> "${LOG_FILE}"

if command -v stdbuf >/dev/null 2>&1; then
  (
    cd "${DISCOURSE_ROOT}"
    TZ=UTC stdbuf -oL -eL ./launcher rebuild app 2>&1 \
      | awk '{ print strftime("%Y-%m-%dT%H:%M:%SZ"), $0; fflush(); }'
  ) | tee -a "${LOG_FILE}"
else
  (
    cd "${DISCOURSE_ROOT}"
    ./launcher rebuild app 2>&1 \
      | awk '{ print strftime("%Y-%m-%dT%H:%M:%SZ"), $0; fflush(); }'
  ) | tee -a "${LOG_FILE}"
fi

echo "$(timestamp) [rebuild] rebuild complete" >> "${LOG_FILE}"
