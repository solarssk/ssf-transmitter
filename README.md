# SSF Transmitter

[![CI](https://github.com/solarssk/ssf-transmitter/actions/workflows/ci.yml/badge.svg)](https://github.com/solarssk/ssf-transmitter/actions/workflows/ci.yml)

Standalone FastAPI service that provides OpenID Shared Signals Framework endpoints next to a free Authentik installation.
It is designed for deployments where Authentik handles OIDC and this service handles SSF/CAEP/RISC event delivery.

## Features

- SSF configuration metadata and JWKS endpoints.
- Stream create/read/update/delete endpoints for push delivery receivers.
- Authentik webhook receiver with HMAC-SHA256 signature verification.
- CAEP/RISC event mapping for logout, credential change, account disabled/enabled, and account purged events.
- RS256-signed Security Event Token push delivery.
- SQLite persistence for stream configuration.
- Docker-first deployment with configurable host and container ports.
- Stdout/stderr logging suitable for Portainer and `docker logs`.

## Project Status

MVP implementation for self-hosted Authentik deployments.
There is no admin panel; configuration is handled through environment variables, Docker Compose, reverse proxy rules, and receiver-managed stream setup.

## Public URLs

- SSF Config URL: `https://idp.example.com/shared-signals/.well-known/ssf-configuration`
- JWKS: `https://idp.example.com/shared-signals/jwks.json`
- Stream endpoint: `https://idp.example.com/shared-signals/ssf/streams`
- Status endpoint: `https://idp.example.com/shared-signals/ssf/status`

## Environment

```env
SSF_ISSUER=https://idp.example.com/application/o/apple-id/
SSF_BASE_URL=https://idp.example.com/shared-signals
SSF_ROOT_PATH=/shared-signals
SSF_CONTAINER_PORT=8000
AUTHENTIK_WEBHOOK_SECRET=change_me_to_random_string_min_32_chars
LOG_LEVEL=INFO
```

For Docker Compose on Synology, add the variables from `.env.example` next to your Authentik compose file.

## Nginx Proxy Manager

Add this custom location to your existing IdP proxy host:

```nginx
location ^~ /shared-signals/ {
    proxy_pass http://127.0.0.1:62107/;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

If `SSF_HOST_PORT` changes, update the port in Nginx Proxy Manager too.

## Authentik Webhook

Configure a Generic Webhook transport in Authentik:

- URL: `http://authentik-ssf:8000/webhook/authentik`
- HMAC secret: the value of `SSF_WEBHOOK_SECRET`
- Events: `authentik.core.auth.logout`, `authentik.core.user.write`, `authentik.core.user.delete`

If you change `SSF_CONTAINER_PORT`, update the internal webhook URL port.

## Logging

The service logs to stdout/stderr only, so logs are visible in Portainer and `docker logs`.
Secrets, bearer tokens, and full SET JWT payloads are not logged.

## Development

Install runtime and development dependencies:

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.txt
```

Run the local checks:

```bash
ruff check .
pytest
```

GitHub Actions runs linting, tests, and a Docker image build on pushes to `main` and pull requests.
