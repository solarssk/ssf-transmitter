# Synology Authentik Compose Integration

This service runs as a fourth container next to PostgreSQL, Authentik `server`, and `worker`.

Keep hostnames and secrets in `stack.env`. **Never commit** `stack.env` or paste secrets into compose YAML.

**Current release:** `ghcr.io/solarssk/ssf-transmitter:0.5.9`

See also: [Deployment.md](Deployment.md), [Upgrading.md](Upgrading.md), [Configuration.md](Configuration.md).

## Filesystem layout

```text
/volume2/docker/authentik/
├── compose.yml
├── stack.env
├── ssf-keys/          # RS256 signing key (persist)
├── ssf-data/          # SQLite (persist)
└── ssf-transmitter/   # optional: clone for local builds
```

Recommended: pull the prebuilt GHCR image — no local build required.

## Private GHCR access

```bash
docker login ghcr.io
# Username: GitHub username
# Password: PAT with read:packages
```

In Portainer: Registry → `ghcr.io` with the same credentials.

## `stack.env`

```env
# ── Required ──
SSF_ISSUER=https://idp.example.com/shared-signals
SSF_BASE_URL=https://idp.example.com/shared-signals
SSF_ROOT_PATH=/shared-signals
SSF_MANAGEMENT_TOKEN=<openssl rand -hex 32>
SSF_WEBHOOK_AUTH_MODE=bearer
SSF_WEBHOOK_TOKEN=<openssl rand -hex 32>

# ── Recommended ──
SSF_LOG_LEVEL=INFO
SSF_HOST_PORT=62107
SSF_CONTAINER_PORT=8000
SSF_FORWARDED_ALLOW_IPS=172.16.3.0/24

# ── Optional: Apple SCIM (see Apple-SCIM-Sync.md) ──
# APPLE_SCIM_CLIENT_ID=SCIM.xxx
# APPLE_SCIM_CLIENT_SECRET=
# AUTHENTIK_URL=https://idp.example.com
# AUTHENTIK_TOKEN=
# APPLE_SCIM_GROUP_ID=
# APPLE_SCIM_ALERT_WEBHOOK_URL=

# ── Optional: security hardening ──
# SSF_PII_PEPPER=
# SSF_ALLOWED_RECEIVER_HOSTS=receiver.example.com
# Do NOT set SSF_TOKEN_ENCRYPTION_KEY on existing installs with a working stream
```

Replace `idp.example.com` with your hostname.

### `SSF_FORWARDED_ALLOW_IPS`

Match your Docker bridge subnet. Example below uses `172.16.3.0/24`. If NPM uses a different network, adjust accordingly.

## Service block

```yaml
  ssf-transmitter:
    image: ghcr.io/solarssk/ssf-transmitter:0.5.9
    container_name: authentik-ssf
    restart: unless-stopped
    networks:
      - authentik_network
    env_file:
      - stack.env
    ports:
      - "127.0.0.1:${SSF_HOST_PORT:-62107}:${SSF_CONTAINER_PORT:-8000}"
    environment:
      SSF_ISSUER: "${SSF_ISSUER:?SSF issuer required}"
      SSF_BASE_URL: "${SSF_BASE_URL:?SSF base URL required}"
      SSF_ROOT_PATH: "${SSF_ROOT_PATH:-/shared-signals}"
      SSF_CONTAINER_PORT: "${SSF_CONTAINER_PORT:-8000}"
      SSF_LOG_LEVEL: "${SSF_LOG_LEVEL:-INFO}"
      SSF_WEBHOOK_AUTH_MODE: "${SSF_WEBHOOK_AUTH_MODE:-bearer}"
      SSF_WEBHOOK_TOKEN: "${SSF_WEBHOOK_TOKEN:?SSF webhook token required}"
      SSF_MANAGEMENT_TOKEN: "${SSF_MANAGEMENT_TOKEN:?SSF management token required}"
      SSF_FORWARDED_ALLOW_IPS: "${SSF_FORWARDED_ALLOW_IPS:-127.0.0.1}"
      TZ: Europe/Warsaw
    volumes:
      - /volume2/docker/authentik/ssf-keys:/app/keys
      - /volume2/docker/authentik/ssf-data:/app/data
```

Network (unchanged if already present):

```yaml
networks:
  authentik_network:
    name: authentik_network
    driver: bridge
    ipam:
      config:
        - subnet: 172.16.3.0/24
```

## Nginx Proxy Manager

```nginx
location ^~ /shared-signals/ {
    limit_req zone=ssf_api burst=10 nodelay;
    proxy_pass http://127.0.0.1:62107/;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

Add a rate-limit zone in the main `http` block (outside the server block):

```nginx
limit_req_zone $binary_remote_addr zone=ssf_api:10m rate=30r/m;
```

Set `SSF_FORWARDED_ALLOW_IPS` to your proxy subnet (e.g. `172.16.3.0/24` for the bridge above) so Uvicorn trusts `X-Forwarded-For` from NPM only.

If `SSF_HOST_PORT` changes, update the Nginx Proxy Manager port too.

## Authentik webhook

| Field | Value |
|---|---|
| URL | `http://authentik-ssf:8000/webhook/authentik` |
| Header Mapping | `Authorization` → `Bearer <SSF_WEBHOOK_TOKEN>` |
| Events | `logout`, `user.write` |

**Do not use HMAC** unless you set `SSF_WEBHOOK_AUTH_MODE=hmac` and `SSF_WEBHOOK_SECRET`.

## Public URLs for ABM

| Purpose | URL |
|---|---|
| SSF Config | `https://idp.example.com/shared-signals/.well-known/ssf-configuration` |
| OpenID Config | `https://idp.example.com/application/o/apple-id/.well-known/openid-configuration` |

## Upgrading from 0.5.8

If you already have ABM connected:

1. Backup `ssf-keys/` and `ssf-data/`.
2. Change image to `0.5.9`.
3. Add `SSF_FORWARDED_ALLOW_IPS` (proxy subnet).
4. **Do not** add `SSF_TOKEN_ENCRYPTION_KEY`.
5. Redeploy and check `/ssf/status` is `enabled`.

Full guide: [Upgrading.md](Upgrading.md).

## Image updates

Pin `0.5.9` in production. `:latest` updates on every `main` push when you pull and redeploy.

Stable release tags (`v0.5.9`) update the `latest` Docker tag; pre-release tags do not.

## Apple SCIM group filtering

See [Apple-SCIM-Sync.md](Apple-SCIM-Sync.md).
