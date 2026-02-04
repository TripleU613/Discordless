#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  echo "Usage: sudo ./install.sh" >&2
  exit 0
fi

if [[ $EUID -ne 0 ]]; then
  if command -v sudo >/dev/null 2>&1; then
    exec sudo -E bash "$0" "$@"
  fi
  echo "This installer must run as root (sudo)." >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE_DIR="${SCRIPT_DIR}/templates"
WEB_DIR="${SCRIPT_DIR}/web"

if [[ ! -f "${TEMPLATE_DIR}/discourse_offline.html" ]]; then
  echo "Missing templates. Expected ${TEMPLATE_DIR}/discourse_offline.html" >&2
  exit 1
fi

DISCOURSE_ROOT="${DISCOURSE_ROOT:-}" 
if [[ -z "${DISCOURSE_ROOT}" ]]; then
  if [[ -d /var/discourse && -x /var/discourse/launcher ]]; then
    DISCOURSE_ROOT="/var/discourse"
  else
    LAUNCHER_BIN="$(command -v launcher || true)"
    if [[ -n "${LAUNCHER_BIN}" ]]; then
      DISCOURSE_ROOT="$(cd "$(dirname "${LAUNCHER_BIN}")" && pwd)"
    fi
  fi
fi

if [[ -z "${DISCOURSE_ROOT}" || ! -f "${DISCOURSE_ROOT}/containers/app.yml" ]]; then
  echo "Could not detect Discourse root. Set DISCOURSE_ROOT=/path/to/discourse and retry." >&2
  exit 1
fi

APP_YML="${DISCOURSE_ROOT}/containers/app.yml"

DOMAIN="${DISCOURSE_HOSTNAME:-}"
if [[ -z "${DOMAIN}" ]]; then
  DOMAIN="$(python3 - <<PY
import re
from pathlib import Path
text = Path("${APP_YML}").read_text(encoding="utf-8")
match = re.search(r"^\s*DISCOURSE_HOSTNAME:\s*['\"]?([^'\"\n]+)", text, re.M)
if match:
    print(match.group(1).strip())
PY
)"
fi

if [[ -z "${DOMAIN}" ]]; then
  echo "Could not detect DISCOURSE_HOSTNAME from ${APP_YML}. Set DISCOURSE_HOSTNAME and retry." >&2
  exit 1
fi

EMAIL="${EMAIL:-}"
if [[ -z "${EMAIL}" ]]; then
  EMAIL="$(python3 - <<PY
import re
from pathlib import Path
text = Path("${APP_YML}").read_text(encoding="utf-8")
email_re = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
keys = [
    "LETSENCRYPT_ACCOUNT_EMAIL",
    "LETSENCRYPT_EMAIL",
    "DISCOURSE_DEVELOPER_EMAILS",
    "DISCOURSE_SMTP_ADDRESS",
    "DISCOURSE_SMTP_USER",
]
for key in keys:
    m = re.search(r"^\s*%s:\s*['\"]?([^'\"\n]+)" % re.escape(key), text, re.M)
    if not m:
        continue
    val = m.group(1)
    em = email_re.search(val)
    if em:
        print(em.group(0))
        raise SystemExit
em = email_re.search(text)
if em:
    print(em.group(0))
PY
)"
fi

ALLOW_UNSAFE_EMAIL="${ALLOW_UNSAFE_EMAIL:-}"

if [[ -z "${EMAIL}" && "${ALLOW_UNSAFE_EMAIL}" != "1" ]]; then
  echo "Could not detect a certificate email. Set EMAIL=you@example.com or ALLOW_UNSAFE_EMAIL=1 and retry." >&2
  exit 1
fi

backup="${APP_YML}.bak.$(date +%Y%m%d%H%M%S)"
cp -a "${APP_YML}" "${backup}"

python3 - <<PY
import re
from pathlib import Path
path = Path("${APP_YML}")
lines = path.read_text(encoding="utf-8").splitlines()
out = []

in_templates = False
templates_indent = 0
socketed_found = False

in_expose = False
expose_indent = 0

def indent_len(line):
    return len(re.match(r"^(\s*)", line).group(1))

def comment(line):
    if line.lstrip().startswith("#"):
        return line
    return re.sub(r"^(\s*)", r"\1#", line, count=1)

for line in lines:
    m_templates = re.match(r"^(\s*)templates:\s*$", line)
    m_expose = re.match(r"^(\s*)expose:\s*$", line)

    if m_templates:
        in_templates = True
        templates_indent = len(m_templates.group(1))
        in_expose = False
        out.append(line)
        continue

    if m_expose:
        in_expose = True
        expose_indent = len(m_expose.group(1))
        in_templates = False
        out.append(line)
        continue

    if in_templates:
        if line.strip() and indent_len(line) <= templates_indent and not line.lstrip().startswith("-") and not line.lstrip().startswith("#-"):
            if not socketed_found:
                out.append(" " * (templates_indent + 2) + '- "templates/web.socketed.template.yml"')
                socketed_found = True
            in_templates = False
        else:
            if "templates/web.socketed.template.yml" in line:
                socketed_found = True
                if line.lstrip().startswith("#"):
                    line = re.sub(r"^(\s*)#\s*-\s*", r"\1- ", line)
            if re.search(r"templates/web\.ssl\.template\.yml|templates/web\.letsencrypt\.ssl\.template\.yml", line):
                line = comment(line)

    if in_expose:
        if line.strip() and indent_len(line) <= expose_indent and not line.lstrip().startswith("-") and not line.lstrip().startswith("#-"):
            in_expose = False
        else:
            if re.search(r"\b80:80\b|\b443:443\b", line):
                line = comment(line)

    out.append(line)

if in_templates and not socketed_found:
    out.append(" " * (templates_indent + 2) + '- "templates/web.socketed.template.yml"')

path.write_text("\n".join(out) + "\n", encoding="utf-8")
PY

if command -v apt-get >/dev/null 2>&1; then
  apt-get update
  apt-get install -y nginx python3 rsync
else
  echo "apt-get not found. Install nginx and python3 manually, then rerun." >&2
  exit 1
fi

systemctl enable --now nginx

mkdir -p /var/www /var/www/errorpages /var/www/errorpages/logs /var/www/errorpages/t-rex

rsync -a --delete "${WEB_DIR}/" /var/www/errorpages/t-rex/

install -m 0644 "${TEMPLATE_DIR}/discourse_offline.html" /var/www/errorpages/discourse_offline.html

install -m 0755 "${TEMPLATE_DIR}/discourse-log-stream.py" /usr/local/bin/discourse-log-stream
install -m 0755 "${TEMPLATE_DIR}/discourse-log-snapshot.py" /usr/local/bin/discourse-log-snapshot
install -m 0755 "${TEMPLATE_DIR}/discourse-rebuild.sh" /usr/local/bin/discourse-rebuild
install -m 0644 "${TEMPLATE_DIR}/discourse-log-stream.service" /etc/systemd/system/discourse-log-stream.service
install -m 0644 "${TEMPLATE_DIR}/discourse-log-snapshot.service" /etc/systemd/system/discourse-log-snapshot.service
install -m 0644 "${TEMPLATE_DIR}/discourse-log-snapshot.timer" /etc/systemd/system/discourse-log-snapshot.timer

systemctl daemon-reload
systemctl enable --now discourse-log-snapshot.timer
systemctl start discourse-log-snapshot.service
systemctl enable --now discourse-log-stream.service
systemctl restart discourse-log-stream.service

HTTP_CONF="/etc/nginx/sites-available/default"
HTTP_CONF_BAK="${HTTP_CONF}.bak.$(date +%Y%m%d%H%M%S)"
if [[ -f "${HTTP_CONF}" ]]; then
  cp -a "${HTTP_CONF}" "${HTTP_CONF_BAK}"
fi

mkdir -p /etc/nginx/sites-enabled
if [[ ! -L /etc/nginx/sites-enabled/default ]]; then
  ln -sf /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default
fi

cat > "${HTTP_CONF}" <<CONF
server {
  listen 80;
  listen [::]:80;
  server_name ${DOMAIN};

  location /.well-known/acme-challenge/ {
    root /var/www;
  }

  location / {
    return 301 https://\$host\$request_uri;
  }
}
CONF

systemctl reload nginx

if [[ ! -f "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" ]]; then
  if command -v certbot >/dev/null 2>&1; then
    if [[ -n "${EMAIL}" ]]; then
      certbot certonly --webroot -w /var/www -d "${DOMAIN}" --agree-tos --non-interactive --email "${EMAIL}"
    else
      certbot certonly --webroot -w /var/www -d "${DOMAIN}" --agree-tos --non-interactive --register-unsafely-without-email
    fi
  else
    if command -v apt-get >/dev/null 2>&1; then
      apt-get install -y certbot
      if [[ -n "${EMAIL}" ]]; then
        certbot certonly --webroot -w /var/www -d "${DOMAIN}" --agree-tos --non-interactive --email "${EMAIL}"
      else
        certbot certonly --webroot -w /var/www -d "${DOMAIN}" --agree-tos --non-interactive --register-unsafely-without-email
      fi
    else
      echo "certbot not found and apt-get unavailable. Install certbot and rerun." >&2
      exit 1
    fi
  fi
fi

SOCKET_PATH="${SOCKET_PATH:-}"
if [[ -z "${SOCKET_PATH}" ]]; then
  SOCKET_PATH="$(find "${DISCOURSE_ROOT}/shared" -name nginx.http.sock 2>/dev/null | head -n 1)"
fi
if [[ -z "${SOCKET_PATH}" ]]; then
  SOCKET_PATH="${DISCOURSE_ROOT}/shared/standalone/nginx.http.sock"
fi

cat > "${HTTP_CONF}" <<CONF
server {
  listen 80;
  listen [::]:80;
  server_name ${DOMAIN};

  location /.well-known/acme-challenge/ {
    root /var/www;
  }

  location / {
    return 301 https://\$host\$request_uri;
  }
}

server {
  listen 443 ssl http2;
  listen [::]:443 ssl http2;
  server_name ${DOMAIN};

  ssl_certificate      /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
  ssl_certificate_key  /etc/letsencrypt/live/${DOMAIN}/privkey.pem;

  ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256';
  ssl_protocols TLSv1.2 TLSv1.3;
  ssl_prefer_server_ciphers on;
  ssl_session_cache shared:SSL:10m;

  add_header Strict-Transport-Security "max-age=63072000;" always;
  ssl_stapling on;
  ssl_stapling_verify on;

  client_max_body_size 0;

  location /errorpages/ {
    alias /var/www/errorpages/;
  }

  location /errorpages/logs/stream {
    proxy_pass http://127.0.0.1:9123/stream;
    proxy_http_version 1.1;
    proxy_set_header Host \$host;
    proxy_set_header Connection "";
    proxy_buffering off;
    proxy_cache off;
    chunked_transfer_encoding off;
    proxy_read_timeout 3600;
    gzip off;
  }

  location / {
    proxy_pass http://unix:${SOCKET_PATH}:;
    proxy_set_header Host \$http_host;
    proxy_http_version 1.1;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Real-IP \$remote_addr;

    error_page 502 =502 /errorpages/discourse_offline.html;
    proxy_intercept_errors on;
  }
}
CONF

systemctl reload nginx

cd "${DISCOURSE_ROOT}"
./launcher rebuild app

echo "Install complete for ${DOMAIN}."
