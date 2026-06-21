# SSF Transmitter

[![CI](https://github.com/solarssk/ssf-transmitter/actions/workflows/ci.yml/badge.svg)](https://github.com/solarssk/ssf-transmitter/actions/workflows/ci.yml)

Standalone service that sits next to Authentik and forwards user security events (logout, password change, account disable/delete) to receivers implementing the [OpenID Shared Signals Framework](https://openid.net/specs/openid-sharedsignals-framework-1_0.html). One container supports one active SSF stream — registering a new stream replaces the existing one. Multi-stream support (fan-out to multiple receivers) is planned for v1.1. Primary receiver: Apple Business Manager CAEP.

Events are signed as RS256 JWTs (Security Event Tokens) and pushed over HTTPS. No admin panel — all configuration is environment variables.

**Current release:** [v0.5.9 — Security hardening](https://github.com/solarssk/ssf-transmitter/releases/tag/v0.5.9)

## Features

- SSF discovery and JWKS endpoints
- Stream management API (create / read / update / delete)
- Authentik webhook receiver with Bearer or HMAC-SHA256 authentication
- CAEP/RISC event mapping for logout, password change, account disable/enable, account delete
- RS256-signed SET push delivery with SSRF and DNS rebinding protection
- Receiver hostname allowlist, in-app rate limiting, HTTP security headers (v0.5.9+)
- Fernet encryption for receiver tokens at rest (v0.5.9+)
- PII masking in logs by default
- Apple Business Manager SCIM user sync (optional)
- Startup preflight checks with ✅/⚠️/❌ output per item
- Multi-architecture Docker image (`linux/amd64`, `linux/arm64`)

## Quick start

1. Copy [`.env.example`](.env.example) to `stack.env` and set:
   - `SSF_ISSUER`, `SSF_BASE_URL`
   - `SSF_MANAGEMENT_TOKEN`, `SSF_WEBHOOK_TOKEN`
   - `SSF_FORWARDED_ALLOW_IPS` (your reverse proxy subnet if behind NPM/Caddy)
2. Add the service to Docker Compose — see [docs/Deployment.md](docs/Deployment.md) or [Synology guide](docs/synology-authentik-compose.md)
3. Register the stream with your receiver using the SSF Config URL below

## Upgrading

**Already running with Apple Business Manager?** See [docs/Upgrading.md](docs/Upgrading.md#v059--security-hardening-from-058-or-earlier):

- Bump image to `0.5.9`
- Set `SSF_FORWARDED_ALLOW_IPS` behind reverse proxy
- Do **not** add `SSF_TOKEN_ENCRYPTION_KEY` unless re-registering the stream

## Public endpoints

| Endpoint | URL |
|---|---|
| Service root | `https://idp.example.com/shared-signals/` |
| SSF Config | `https://idp.example.com/shared-signals/.well-known/ssf-configuration` |
| JWKS | `https://idp.example.com/shared-signals/jwks.json` |
| Stream management | `https://idp.example.com/shared-signals/ssf/streams` |
| Status | `https://idp.example.com/shared-signals/ssf/status` |

`/docs` and `/openapi.json` are off by default — set `SSF_ENABLE_OPENAPI=true` only in dev or a trusted LAN.

Replace `idp.example.com` with your IdP hostname and `/shared-signals` with your `SSF_ROOT_PATH`.

## Documentation

| Topic | Location |
|---|---|
| **Documentation index** | [docs/README.md](docs/README.md) |
| Deployment | [docs/Deployment.md](docs/Deployment.md) |
| Synology + Authentik | [docs/synology-authentik-compose.md](docs/synology-authentik-compose.md) |
| Environment variables | [docs/Configuration.md](docs/Configuration.md) |
| Upgrading (v0.5.9) | [docs/Upgrading.md](docs/Upgrading.md) |
| Event mapping | [docs/Event-Mapping.md](docs/Event-Mapping.md) |
| Keys and rotation | [docs/Key-Management.md](docs/Key-Management.md) |
| Apple SCIM sync | [docs/Apple-SCIM-Sync.md](docs/Apple-SCIM-Sync.md) |
| Security checklist | [docs/Security-Notes.md](docs/Security-Notes.md) |
| Troubleshooting | [docs/Troubleshooting.md](docs/Troubleshooting.md) |
| API reference | [docs/API.md](docs/API.md) |
| Threat model | [SECURITY.md](SECURITY.md) |
| Changelog | [CHANGELOG.md](CHANGELOG.md) |

Wiki pages mirror `docs/` — sync from the repo when updating [GitHub Wiki](https://github.com/solarssk/ssf-transmitter/wiki).

## Apple SCIM group filtering

Set `APPLE_SCIM_GROUP_ID` to an Authentik group UUID to sync only members of a dedicated Apple group. See [docs/Apple-SCIM-Sync.md](docs/Apple-SCIM-Sync.md).

## Development

Requires **Python 3.14** (see `.python-version`; matches CI and the Docker image).

```bash
python3.14 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
ruff check .
pytest
```

GitHub Actions runs linting, tests, dependency checks, and a Docker image build on every push and pull request.
