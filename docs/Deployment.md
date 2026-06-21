# Deployment

SSF Transmitter runs as a single Docker container next to Authentik. TLS terminates at your reverse proxy; the container listens on port 8000 internally.

## Image

```text
ghcr.io/solarssk/ssf-transmitter:0.5.9   # pinned release
ghcr.io/solarssk/ssf-transmitter:latest    # tracks main
```

Private GHCR packages require `docker login ghcr.io` with a GitHub PAT (`read:packages`).

## Minimal compose service

See [docker-compose.snippet.yml](../docker-compose.snippet.yml) in the repository root.

```yaml
ssf-transmitter:
  image: ghcr.io/solarssk/ssf-transmitter:0.5.9
  container_name: authentik-ssf
  restart: unless-stopped
  env_file:
    - stack.env
  ports:
    - "127.0.0.1:${SSF_HOST_PORT:-62107}:${SSF_CONTAINER_PORT:-8000}"
  environment:
    SSF_ISSUER: "${SSF_ISSUER:?required}"
    SSF_BASE_URL: "${SSF_BASE_URL:?required}"
    SSF_ROOT_PATH: "${SSF_ROOT_PATH:-/shared-signals}"
    SSF_CONTAINER_PORT: "${SSF_CONTAINER_PORT:-8000}"
    SSF_LOG_LEVEL: "${SSF_LOG_LEVEL:-INFO}"
    SSF_WEBHOOK_AUTH_MODE: "${SSF_WEBHOOK_AUTH_MODE:-bearer}"
    SSF_WEBHOOK_TOKEN: "${SSF_WEBHOOK_TOKEN:?required}"
    SSF_MANAGEMENT_TOKEN: "${SSF_MANAGEMENT_TOKEN:?required}"
    SSF_FORWARDED_ALLOW_IPS: "${SSF_FORWARDED_ALLOW_IPS:-127.0.0.1}"
  volumes:
    - ./ssf-keys:/app/keys
    - ./ssf-data:/app/data
  networks:
    - authentik_network
```

Set `SSF_FORWARDED_ALLOW_IPS` to your **reverse proxy Docker subnet** when using Nginx Proxy Manager or similar. See [Configuration](Configuration.md).

## `stack.env` minimum

```env
SSF_ISSUER=https://idp.example.com/shared-signals
SSF_BASE_URL=https://idp.example.com/shared-signals
SSF_ROOT_PATH=/shared-signals
SSF_MANAGEMENT_TOKEN=<openssl rand -hex 32>
SSF_WEBHOOK_AUTH_MODE=bearer
SSF_WEBHOOK_TOKEN=<openssl rand -hex 32>
SSF_LOG_LEVEL=INFO
SSF_FORWARDED_ALLOW_IPS=172.16.3.0/24
```

## Reverse proxy (Nginx Proxy Manager)

Add a location block on your IdP hostname:

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

Rate-limit zone (in `http` block):

```nginx
limit_req_zone $binary_remote_addr zone=ssf_api:10m rate=30r/m;
```

Match `SSF_FORWARDED_ALLOW_IPS` to the Docker bridge subnet NPM uses.

## Authentik webhook

Create a **Generic Webhook** notification transport:

| Field | Value |
|---|---|
| URL | `http://authentik-ssf:8000/webhook/authentik` |
| Header | `Authorization: Bearer <SSF_WEBHOOK_TOKEN>` |
| Events | `authentik.core.auth.logout`, `authentik.core.user.write` |

Use the Docker service name (`authentik-ssf`) so traffic stays on the internal network.

## Register stream with receiver

After the container is healthy, register the SSF stream with your receiver (e.g. Apple Business Manager) using:

- **SSF Config URL:** `https://idp.example.com/shared-signals/.well-known/ssf-configuration`
- **Management API:** `POST /ssf/streams` with `Authorization: Bearer <SSF_MANAGEMENT_TOKEN>`

One active stream is supported; creating a new stream replaces the previous one.

## Synology step-by-step

See [synology-authentik-compose.md](synology-authentik-compose.md) for a full Authentik stack integration guide.

## Upgrading

See [Upgrading.md](Upgrading.md) — especially if you are moving from `0.5.8` to `0.5.9`.
