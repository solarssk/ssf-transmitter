# Synology Authentik Compose Integration

This service can be added to an existing Authentik stack as a fourth service next to PostgreSQL, `server`, and `worker`.

Keep deployment-specific hostnames and secrets in `stack.env`. Do not commit that file.

## Filesystem Layout

Recommended layout on Synology:

```text
/volume2/docker/authentik/
├── compose.yml
├── stack.env
├── ssf-transmitter/
├── ssf-data/
└── ssf-keys/
```

If you want Portainer/Synology to build locally, clone this repository into:

```text
/volume2/docker/authentik/ssf-transmitter
```

The recommended setup is to avoid local builds and pull the prebuilt GHCR image instead.

## Private GHCR Access

Because the repository is private, the container package is private too unless you explicitly change its visibility.
Configure Portainer with GitHub Container Registry credentials:

- Registry URL: `ghcr.io`
- Username: your GitHub username
- Password/token: a GitHub personal access token with `read:packages`

Alternatively, log in once on the Synology host:

```bash
docker login ghcr.io
```

Use your GitHub username and a personal access token with `read:packages`.

## `stack.env`

Add these variables to the same `stack.env` used by Authentik:

```env
SSF_ISSUER=https://idp.example.com/application/o/apple-id/
SSF_BASE_URL=https://idp.example.com/shared-signals
SSF_ROOT_PATH=/shared-signals
SSF_HOST_PORT=62107
SSF_CONTAINER_PORT=8000
SSF_LOG_LEVEL=INFO
SSF_WEBHOOK_SECRET=change_me_to_random_string_min_32_chars
```

Replace `idp.example.com` with your IdP hostname only in your private deployment environment.

## Service Block

Add this service under `services:` in your Authentik compose file:

```yaml
  ssf-transmitter:
    image: ghcr.io/solarssk/ssf-transmitter:latest
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
      LOG_LEVEL: "${SSF_LOG_LEVEL:-INFO}"
      AUTHENTIK_WEBHOOK_SECRET: "${SSF_WEBHOOK_SECRET:?SSF webhook secret required}"
      TZ: Europe/Warsaw
    volumes:
      - /volume2/docker/authentik/ssf-keys:/app/keys
      - /volume2/docker/authentik/ssf-data:/app/data
```

The existing network block can stay as-is:

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

In the existing proxy host for your IdP hostname, add:

```nginx
location ^~ /shared-signals/ {
    proxy_pass http://127.0.0.1:62107/;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

If `SSF_HOST_PORT` changes, update the Nginx Proxy Manager port too.

## Authentik Webhook

Create a Generic Webhook notification transport in Authentik:

- URL: `http://authentik-ssf:8000/webhook/authentik`
- HMAC secret: value of `SSF_WEBHOOK_SECRET`
- Events: `authentik.core.auth.logout`, `authentik.core.user.write`, `authentik.core.user.delete`

If `SSF_CONTAINER_PORT` changes, update the webhook URL port.

## Public Receiver Configuration

Use these URLs with the SSF receiver:

- SSF Config URL: `https://idp.example.com/shared-signals/.well-known/ssf-configuration`
- OpenID Config URL: `https://idp.example.com/application/o/apple-id/.well-known/openid-configuration`

Replace `idp.example.com` in the receiver UI with your real IdP hostname.

## Image Updates

Every push to `main` builds and publishes:

- `ghcr.io/solarssk/ssf-transmitter:latest`
- `ghcr.io/solarssk/ssf-transmitter:sha-<short_sha>`

In Portainer, redeploy the stack and enable image pulling when you want to update to the newest `latest` image.
