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
