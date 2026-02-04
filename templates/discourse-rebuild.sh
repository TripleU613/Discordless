#!/usr/bin/env bash
set -euo pipefail

DISCOURSE_ROOT="${DISCOURSE_ROOT:-/var/discourse}"
LOG_DIR="/var/www/errorpages/logs"
LOG_FILE="${LOG_DIR}/rebuild.log"

if [[ ! -x "${DISCOURSE_ROOT}/launcher" ]]; then
  echo "Missing launcher at ${DISCOURSE_ROOT}/launcher" >&2
  exit 1
fi

mkdir -p "${LOG_DIR}"
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
