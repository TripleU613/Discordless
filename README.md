# Discourse Offline Page + Live Logs + Dino Game Installer

This installer converts a standard Discourse Docker install into a host‑fronted nginx setup with:

- Custom offline page (auto refresh)
- Live, sanitized Discourse logs (SSE)
- Embedded Chrome Dino Runner game
- Automatic socketed Discourse + nginx reverse proxy

It follows the `meta.discourse.org` guide (Dec 25, 2025) and moves TLS termination to nginx on the host so the offline page works even while Discourse rebuilds.

## What It Changes

- Edits `containers/app.yml` to:
  - add `templates/web.socketed.template.yml`
  - comment out `web.ssl.template.yml` / `web.letsencrypt.ssl.template.yml`
  - comment out exposed `80:80` and `443:443`
- Rebuilds the Discourse container
- Installs nginx + certbot (apt)
- Requests a Let’s Encrypt cert for your Discourse domain
- Writes nginx config for HTTP->HTTPS + socket proxy + offline page
- Installs log sanitizer + streaming services (systemd)
- Deploys `/var/www/errorpages` assets

## Requirements

- Ubuntu/Debian host with `apt-get`
- Standard Discourse install at `/var/discourse`
- Domain in `DISCOURSE_HOSTNAME` inside `containers/app.yml`
- Root access (`sudo`)

## Install

Run on the Discourse host:

```bash
sudo ./install.sh
```

The installer auto-detects `DISCOURSE_HOSTNAME` from `containers/app.yml`.

## Install Options

- `NGINX_CONF=/etc/nginx/sites-available/discourse-offline.conf` to override the nginx config path (required if nginx does not include `sites-enabled` or `conf.d` in `nginx.conf`).
- `USE_TCP_PROXY=1` or `FORCE_TCP=1` to use a TCP upstream instead of the unix socket (auto-enabled when SELinux is Enforcing).
- `DISCOURSE_TCP_PORT=8008` to choose the local TCP port for the Discourse container.
- `OFFLINE_HTTP_STATUS=502` to change the status code served for the offline page (set to `200` if Cloudflare replaces 502 pages).

If it cannot detect a certificate email, provide one:

```bash
sudo EMAIL=you@example.com ./install.sh
```

If you accept the Let’s Encrypt “no email” option (not recommended):

```bash
sudo ALLOW_UNSAFE_EMAIL=1 ./install.sh
```

## Rebuild With Live Logs

Use the wrapper to stream rebuild output into the live log panel:

```bash
sudo discourse-rebuild
```

The wrapper auto-detects the Discourse root and the offline log directory. You can override:

```bash
sudo DISCOURSE_ROOT=/var/discourse LOG_DIR=/var/www/errorpages/logs discourse-rebuild
```

## Notes

- TLS is moved out of the Discourse container and into nginx on the host.
- Let’s Encrypt has rate limits (avoid repeated installs in a short window).
- If you previously used container-managed SSL, auto-renewal must be handled on the host.
- The installer writes a dedicated nginx config (no default vhost overwrite) and reloads nginx on cert renewals.
- If uploads fail or OAuth logins break after moving SSL, enable `force_https` in Discourse and update OAuth callback URLs to `https`.
- If you run Cloudflare in front, it may show its own 502 page. Use `OFFLINE_HTTP_STATUS=200` or pause Cloudflare to display the offline page.
- If SELinux is Enforcing, the installer switches to a TCP upstream and attempts to set required SELinux booleans/ports (ensure `setsebool` and `semanage` are available).
- To test the offline page:

```bash
cd /var/discourse
./launcher stop app
```

Then visit:

```
https://YOUR_DOMAIN/errorpages/discourse_offline.html
```

Restart Discourse afterward:

```bash
cd /var/discourse
./launcher start app
```

## Paths Used

- Offline assets: `/var/www/errorpages/`
- Game: `/var/www/errorpages/t-rex/`
- Log snapshot: `/var/www/errorpages/logs/discourse.log`
- Log stream: `http://127.0.0.1:9123/stream` (nginx proxy)
- Socket: `/var/discourse/shared/standalone/nginx.http.sock`
- TCP upstream (SELinux/TCP mode): `127.0.0.1:8008`
