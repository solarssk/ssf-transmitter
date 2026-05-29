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
- Prebuilt multi-architecture container image published to GitHub Container Registry.
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
SSF_WEBHOOK_SECRET=change_me_to_random_string_min_32_chars
LOG_LEVEL=INFO
```

See `.env.example` for the full list of variables including optional ones.
For Docker Compose on Synology, see [Synology Authentik Compose Integration](docs/synology-authentik-compose.md).

## Container Image

The `main` branch publishes a multi-architecture image to GitHub Container Registry:

```text
ghcr.io/solarssk/ssf-transmitter:latest
```

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

### Recommended: Bearer token (Authentik Generic Webhook + Header Mapping)

Set in `stack.env`:

```env
SSF_WEBHOOK_AUTH_MODE=bearer
SSF_WEBHOOK_TOKEN=<random-token-min-32-chars>
```

In Authentik, create a **Webhook Header Mapping** (Directory → Property Mappings → Create → Webhook Mapping):

```python
return {
    "Authorization": "Bearer <SSF_WEBHOOK_TOKEN>"
}
```

Then create a **Generic Webhook** notification transport:

- URL: `http://authentik-ssf:8000/webhook/authentik`
- Attach the Header Mapping above

> **Important:** Use `SSF_WEBHOOK_TOKEN` here — **not** `SSF_MANAGEMENT_TOKEN`.
> `SSF_MANAGEMENT_TOKEN` protects the SSF management API (`/ssf/*`).
> `SSF_WEBHOOK_TOKEN` protects only `/webhook/authentik`.
> Keeping them separate limits blast radius if one is ever compromised.

Create a **Notification Rule** that sends to this transport for events:
`authentik.core.auth.logout`, `authentik.core.user.write`, `authentik.core.user.delete`

If you change `SSF_CONTAINER_PORT`, update the internal webhook URL port.

### Legacy: HMAC signature

```env
SSF_WEBHOOK_AUTH_MODE=hmac
SSF_WEBHOOK_SECRET=<random-secret-min-32-chars>
```

Configure the webhook transport with the HMAC secret — Authentik will send
`X-Authentik-Signature: sha256=<hmac>` on each request.

### Development only: unsigned

```env
SSF_WEBHOOK_AUTH_MODE=unsigned
```

No authentication. Logs a loud warning on every request.
**Do not use in production.**

## Event Mapping

| Authentik event | Condition | SSF/CAEP/RISC event |
|---|---|---|
| `authentik.core.auth.logout` | — | `caep/session-revoked` |
| `authentik.core.user.write` | `changed_fields` contains `password` | `caep/credential-change` |
| `authentik.core.user.write` | `is_active` set to `false` | `risc/account-disabled` |
| `authentik.core.user.write` | `is_active` set to `true` | `risc/account-enabled` |
| `authentik.core.user.delete` | — | `risc/account-purged` |
| `authentik.core.auth.login_failed` | — | *(ignored)* |

A single `user.write` event can emit multiple SSF events (e.g. password change + account disabled simultaneously).

## Key Management

On first startup the service generates an RS256 4096-bit private key and JWKS file in the `SSF_KEYS_DIR` directory (default: `/app/keys`).

- **Backup `/app/keys/private.pem`** — if lost, all previously issued SET JWTs become unverifiable by receivers.
- The key is never regenerated automatically as long as both `private.pem` and `jwks.json` exist.
- To rotate: stop the service, remove `/app/keys/`, restart. Receivers will need to re-fetch JWKS.

## Security

See [SECURITY.md](SECURITY.md) for the full threat model, trust boundaries, and vulnerability disclosure process.

### Production deployment requirements

| Requirement | Why |
|---|---|
| Run behind a TLS-terminating reverse proxy (nginx, Caddy) | All traffic must be HTTPS in production |
| `SSF_MANAGEMENT_TOKEN` ≥ 32 random characters | Guards stream create/update/delete |
| `SSF_WEBHOOK_SECRET` ≥ 32 random characters | Prevents spoofed Authentik events |
| `/ssf/streams` reachable only by authorised receivers | Management API is authenticated but defence-in-depth |
| `/webhook/authentik` reachable only from the Authentik container | Webhook is HMAC-protected but only Authentik should POST to it |
| Mount `/app/keys` and `/app/data` to root-owned host paths | Signing key and receiver tokens must not be readable by other containers |

### What this service does and does not do

**Does:**
- Sign and push Security Event Tokens (SETs) to registered receivers via HTTPS POST
- Verify Authentik webhook signatures with HMAC-SHA256
- Validate receiver endpoint URLs against SSRF (blocks RFC 1918, loopback, link-local, and unresolvable hostnames)
- Re-validate receiver endpoint DNS before every push (DNS rebinding protection)
- Mask email addresses in logs by default (`SSF_LOG_PII=false`)
- Enforce strict Pydantic validation on all management API inputs

**Does not:**
- Encrypt receiver tokens at rest (stored in plaintext SQLite — protect the data volume)
- Provide rate limiting (delegate to nginx/Caddy in front)
- Rotate signing keys automatically
- Support multiple simultaneous streams (single-stream design)

## API Reference

See [docs/API.md](docs/API.md) for full endpoint documentation with request and response examples.

## Logging

The service logs to stdout/stderr only, so logs are visible in Portainer and `docker logs`.
Secrets, bearer tokens, and full SET JWT payloads are not logged.
Email addresses are replaced by a pseudonymous hash by default (`SSF_LOG_PII=false`);
set `SSF_LOG_PII=true` only in controlled debug environments.

## Troubleshooting

**`unauthorized` when pulling the image**
The GHCR package visibility must be set to public separately from the repository.
Go to `https://github.com/users/<owner>/packages/container/ssf-transmitter/settings` and change visibility to Public,
or run `docker login ghcr.io` on the host before pulling.

**Portainer deploy fails with status 500**
Usually caused by a missing or misnamed environment variable. Check that all required variables (`SSF_ISSUER`, `SSF_BASE_URL`, `SSF_WEBHOOK_SECRET`) are present in `stack.env`. The `:?` syntax in the compose file causes a hard failure if a variable is unset.

**Container exits immediately on startup**
Run `docker logs authentik-ssf` to see the error. Missing required env vars are reported as:
`RuntimeError: Missing required environment variables: SSF_ISSUER, ...`

**Webhook returns 401**
The `X-Authentik-Signature` header does not match. Verify that `SSF_WEBHOOK_SECRET` in the service matches the HMAC secret configured in the Authentik webhook transport.

**Apple returns `invalid_request` / `Invalid security event token` for normal events, but verification SET was accepted (202)**

This means the verification SET passed (JWKS, stream registration, and endpoint delivery all work), but the event SET payload is malformed.
Inspect the event SET claims — the most common cause is a missing top-level `sub_id`:

```json
{
  "sub_id": { "format": "email", "email": "user@example.com" },
  "events": {
    "https://schemas.openid.net/secevent/caep/event-type/session-revoked": {
      "subject": { "format": "email", "email": "user@example.com" }
    }
  }
}
```

SSF 1.0 requires `sub_id` at the top level of the JWT payload (§5.1).
Also verify: `typ: secevent+jwt`, `kid` present, `aud` is a single-element array, `iss` matches your registered issuer, and `exp` is **absent**.

If you are running an older container image (before PR #11 / SSF 1.0 compliance), pull the latest image and restart:

```bash
docker compose pull && docker compose up -d
```

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
