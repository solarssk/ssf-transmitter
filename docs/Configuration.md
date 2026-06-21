# Configuration

All settings are environment variables. Copy [`.env.example`](../.env.example) to `stack.env` and fill in values. Never commit secrets.

## Required

| Variable | Description |
|---|---|
| `SSF_ISSUER` | Public issuer URL used in JWT `iss` (must be **HTTPS**). **Set to the same value as `SSF_BASE_URL`** (the transmitter public URL). Authentik OIDC application URLs (`/application/o/...`) trigger a startup warning. |
| `SSF_BASE_URL` | Public base URL where this service is reachable (must be **HTTPS**), e.g. `https://idp.example.com/shared-signals` |
| `SSF_MANAGEMENT_TOKEN` | Bearer token for all `/ssf/*` and protected Apple SCIM admin endpoints (min 32 chars). Generate: `openssl rand -hex 32` |
| `SSF_WEBHOOK_TOKEN` | Bearer token for Authentik webhook (`SSF_WEBHOOK_AUTH_MODE=bearer`, default). **Do not reuse** `SSF_MANAGEMENT_TOKEN`. |

## Webhook authentication

| Variable | Default | Description |
|---|---|---|
| `SSF_WEBHOOK_AUTH_MODE` | `bearer` | `bearer` (recommended), `hmac` (legacy), or `unsigned` (dev/lab only) |
| `SSF_WEBHOOK_SECRET` | — | Required only when `SSF_WEBHOOK_AUTH_MODE=hmac` |

Configure Authentik Generic Webhook with a Header Mapping:

- Name: `Authorization`
- Value: `Bearer <SSF_WEBHOOK_TOKEN>`

Older deployments that still use `X-Authentik-Signature` must keep `SSF_WEBHOOK_AUTH_MODE=hmac` and `SSF_WEBHOOK_SECRET` explicitly set during upgrades.

## Paths and ports

| Variable | Default | Description |
|---|---|---|
| `SSF_ROOT_PATH` | empty | URL prefix when served under a sub-path, e.g. `/shared-signals` |
| `SSF_HOST_PORT` | `62107` | Host port published by Docker (compose examples) |
| `SSF_CONTAINER_PORT` | `8000` | Port the app listens on inside the container |

## Logging

| Variable | Default | Description |
|---|---|---|
| `SSF_LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `LOG_LEVEL` | — | Legacy alias; `SSF_LOG_LEVEL` takes precedence when set |
| `SSF_LOG_COLOR` | `false` | ANSI colours in logs (useful in Portainer) |
| `SSF_LOG_PII` | `false` | When `false`, emails in logs are pseudonymised |

## Security (optional, v0.5.9+)

| Variable | Default | Description |
|---|---|---|
| `SSF_FORWARDED_ALLOW_IPS` | `127.0.0.1` | Trusted reverse-proxy IPs/CIDRs for `X-Forwarded-For` (Uvicorn). **Set to your proxy subnet** when behind NPM/Caddy/Traefik. |
| `SSF_ALLOWED_RECEIVER_HOSTS` | unset | Comma-separated allowlist of receiver hostnames for stream `endpoint_url`. Unset = any public host (private IPs always blocked). |
| `SSF_TOKEN_ENCRYPTION_KEY` | unset | Dedicated Fernet key for receiver tokens in SQLite. When unset, derived from `SSF_MANAGEMENT_TOKEN`. See [Key Management](Key-Management.md). |
| `SSF_PII_PEPPER` | unset | HMAC key for log pseudonymisation. Falls back to `SSF_MANAGEMENT_TOKEN` with a startup warning. |
| `SSF_ENABLE_OPENAPI` | `false` | Expose `/docs`, `/redoc`, `/openapi.json` (dev/trusted LAN only) |

### `SSF_FORWARDED_ALLOW_IPS` examples

```env
# Nginx Proxy Manager on Docker bridge 172.16.3.0/24
SSF_FORWARDED_ALLOW_IPS=172.16.3.0/24

# Single proxy container IP
SSF_FORWARDED_ALLOW_IPS=172.17.0.2
```

Default `127.0.0.1` is correct only when nothing forwards `X-Forwarded-For` from outside the container.

### `SSF_TOKEN_ENCRYPTION_KEY` — when to set

| Situation | Action |
|---|---|
| **New install**, before registering a stream | Optional but recommended — set once and keep |
| **Existing install** with ABM/stream already working | **Do not add** unless you plan to re-register the stream |
| Rotating `SSF_MANAGEMENT_TOKEN` | Expect paused streams; re-register with `delivery.endpoint_url_token` before setting `status: enabled` |

## Apple SCIM (optional)

| Variable | Description |
|---|---|
| `APPLE_SCIM_CLIENT_ID` | SCIM client ID from Apple Business Manager |
| `APPLE_SCIM_CLIENT_SECRET` | SCIM client secret (expires every 6/9/12 months) |
| `AUTHENTIK_URL` | Authentik base URL |
| `AUTHENTIK_TOKEN` | Authentik API token |
| `APPLE_SCIM_GROUP_ID` | Optional Authentik group UUID — sync only group members |
| `APPLE_SCIM_SYNC_INTERVAL` | Seconds between syncs (default `3600`) |
| `APPLE_SCIM_ALERT_WEBHOOK_URL` | Webhook for re-auth / secret-expiry alerts |

## Storage paths (inside container)

| Variable | Default | Description |
|---|---|---|
| `SSF_DATABASE_PATH` | `/app/data/ssf.db` | SQLite database (streams, SCIM tokens) |
| `SSF_KEYS_DIR` | `/app/keys` | RS256 private key + JWKS |

Mount both volumes persistently. See [Key Management](Key-Management.md).
