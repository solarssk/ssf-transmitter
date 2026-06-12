# SSF Transmitter

[![CI](https://github.com/solarssk/ssf-transmitter/actions/workflows/ci.yml/badge.svg)](https://github.com/solarssk/ssf-transmitter/actions/workflows/ci.yml)

Standalone service that sits next to Authentik and forwards user security events (logout, password change, account disable/delete) to receivers implementing the [OpenID Shared Signals Framework](https://openid.net/specs/openid-sharedsignals-framework-1_0.html). One container supports one active SSF stream — registering a new stream replaces the existing one. Multi-stream support (fan-out to multiple receivers) is planned for v1.1. Primary receiver: Apple Business Manager CAEP.

Events are signed as RS256 JWTs (Security Event Tokens) and pushed over HTTPS. No admin panel — all configuration is environment variables.

## Features

- SSF discovery and JWKS endpoints
- Stream management API (create / read / update / delete)
- Authentik webhook receiver with Bearer or HMAC-SHA256 authentication
- CAEP/RISC event mapping for logout, password change, account disable/enable, account delete
- RS256-signed SET push delivery with SSRF and DNS rebinding protection
- PII masking in logs by default
- Apple Business Manager SCIM user sync (optional)
- Startup preflight checks with ✅/⚠️/❌ output per item
- Multi-architecture Docker image (`linux/amd64`, `linux/arm64`)

## Quick start

1. Copy `.env.example` to `stack.env` and fill in the four required variables:
   `SSF_ISSUER`, `SSF_BASE_URL`, `SSF_MANAGEMENT_TOKEN`, `SSF_WEBHOOK_TOKEN`
2. Add the service to your Docker Compose file — see [Deployment](../../wiki/Deployment) for the full block including Nginx Proxy Manager and Authentik webhook setup
3. Register the stream with your receiver using the SSF Config URL below

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
| Deployment (Synology, Nginx, Authentik) | [Wiki: Deployment](../../wiki/Deployment) |
| All environment variables | [Wiki: Configuration](../../wiki/Configuration) |
| Authentik → SSF event mapping | [Wiki: Event Mapping](../../wiki/Event-Mapping) |
| Key generation, backup, rotation | [Wiki: Key Management](../../wiki/Key-Management) |
| Apple SCIM directory sync | [Wiki: Apple SCIM Sync](../../wiki/Apple-SCIM-Sync) |
| Production security checklist | [Wiki: Security Notes](../../wiki/Security-Notes) |
| Common errors and fixes | [Wiki: Troubleshooting](../../wiki/Troubleshooting) |
| Full API reference | [docs/API.md](docs/API.md) |
| Threat model | [SECURITY.md](SECURITY.md) |
| Changelog | [CHANGELOG.md](CHANGELOG.md) |


## Apple SCIM group filtering

Set `APPLE_SCIM_GROUP_ID` to an Authentik group UUID to sync only members of a dedicated Apple group, for example **Apple Accounts**:

```env
APPLE_SCIM_GROUP_ID=978bff1a-5f55-4068-808c-45e09bb196d4
```

Leaving `APPLE_SCIM_GROUP_ID` empty preserves the legacy behavior: all active internal Authentik users are considered for Apple SCIM sync. In production, use a dedicated group and exclude local backup, break-glass/admin, technical/service, and Authentik-only accounts.

## Development

Requires **Python 3.12** (see `.python-version`; matches CI and the Docker image).

```bash
python3.12 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
ruff check .
pytest
```

GitHub Actions runs linting, tests, dependency checks, and a Docker image build on **every push and pull request** — no manual test run is required before merge; forked copies get the same workflow when Actions are enabled.
