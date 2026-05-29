# Changelog

All notable changes to this project are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)
Versioning: [Semantic Versioning](https://semver.org/)

---

## [Unreleased]

---

## [0.3.0] — 2026-05-29

### Added
- **Structured CAEP event payloads** — `session-revoked` now carries `event_timestamp`, `initiating_entity`, and `reason_admin`; `credential-change` carries `credential_type`, `change_type`, and `event_timestamp` per CAEP Interoperability Profile
- **`txn` claim in every SET** — derived from Authentik event `pk` when available so multiple SETs from one webhook share the same transaction ID; falls back to a fresh UUID
- **`events_requested` filtering** — `push_set` skips events not listed in the stream's `events_requested`; empty list means no filter (backward compatible)
- **`POST /ssf/verification`** — receiver-initiated verification endpoint (management auth required); accepts optional `{"state": "..."}` body; returns 202/404/502
- **`verification_endpoint`** in `.well-known/ssf-configuration` discovery response
- **`SSF_ISSUER` startup warnings** — preflight warns (⚠️, no exit) when `SSF_ISSUER` differs from `SSF_BASE_URL` or looks like an Authentik OIDC application URL; suppressed with `SSF_ALLOW_CUSTOM_ISSUER=true`
- **`SSF_ALLOW_CUSTOM_ISSUER`** env var (bool, default false)
- **`SSF_LOG_COLOR`** env var — enables ANSI-coloured log output; Portainer renders ANSI codes; requires optional `colorlog` package (falls back to plain text)
- **Log rotation** in `docker-compose.snippet.yml` — `json-file` driver with `max-size: 10m` / `max-file: 5`
- **Trivy image scan** in CI — scans locally built image for HIGH/CRITICAL CVEs; results uploaded to GitHub Security tab (SARIF)
- **SBOM (CycloneDX)** generated on every CI build and uploaded as a 90-day artifact
- **`SSF_PII_PEPPER`** documented in `.env.example`

### Changed
- **`push_set` return type** is now `bool | None` — `None` means intentionally skipped (disabled stream or event not in `events_requested`); callers must not count `None` as a delivery failure
- **Canonical RISC URIs** for account-state events — `account-disabled/enabled/purged` moved from `caep/event-type/` to `risc/event-type/` namespace; legacy `caep/` URIs accepted on input and canonicalized transparently
- **`push_verification_set`** accepts optional `state` parameter forwarded to the verification SET
- **`supported_scopes`** removed from `.well-known/ssf-configuration` — was incorrectly claiming `["openid"]` (OAuth2 not implemented)
- **`SSF_WEBHOOK_AUTH_MODE=unsigned`** startup message strengthened: "never use in production"
- **`SSF_ALLOW_UNSIGNED_WEBHOOK=true`** logs a DEPRECATED warning at startup; alias still works but will be removed in a future release
- **`account-enabled/disabled`** events are only emitted when `is_active` is listed in `changed_fields` — prevents false events when `is_active` is present in context but unchanged
- **Healthcheck log** reduced from `INFO` to `DEBUG` — no longer floods Portainer at default `LOG_LEVEL=INFO`
- **GitHub Actions SHA-pinned** — all `uses:` in `ci.yml` and `docker-publish.yml` reference immutable commit SHAs
- **Docker base image** switched from `python:3.12-slim` (Debian 13 Trixie/testing) to `python:3.12-slim-bookworm@sha256:…` (Debian 12 LTS, pinned digest) for reproducible builds and stable CVE support
- **Dependabot** extended to track Docker base image digest updates weekly

### Fixed
- `push_verification_set` now validates the endpoint before signing the JWT (consistent with `push_set` order)
- Redundant `enabled_streams` filter removed from webhook handler — `push_set` already handles disabled streams
- `sign_set` uses `event_payload: dict | None = None` default instead of mutable `{}` (Python mutable-default bug)

### Security
- **`Accept: application/json`** header added to all SET push requests per RFC 8935 §4
- Receiver error bodies no longer logged at WARNING — WARNING now logs a SHA-256 body hash (`body_hash=`) for correlation; raw body available at DEBUG only
- `SECURITY.md` updated: bearer = default/recommended, hmac = legacy, all three webhook auth modes documented; `SSF_WEBHOOK_TOKEN` added to "Data processed" table

### Added
- Version number printed in preflight log header: `── SSF Transmitter preflight  v0.2.4 ──`
- Apple SCIM preflight diagnostics: when SCIM is disabled, the log now shows exactly which env vars are missing instead of listing all four every time
- Authentik connectivity check in preflight when Apple SCIM is enabled — probes `GET /api/v3/core/users/` and reports connected user count, auth error, or network failure
- Beta Docker image published automatically on every push to the `beta` branch (`ghcr.io/solarssk/ssf-transmitter:beta`)
- SET JWT claims logged at `DEBUG` level before each push (PII fields `sub_id`/`sub` redacted)

### Fixed
- `latest` Docker tag is now only applied on stable semver release tags (`vX.Y.Z`), not on every push to `main` or on pre-release tags (`v1.0.0-rc.1`)

---

## [0.2.3] — 2026-05-29

### Fixed
- Docker healthcheck access log (`GET /jwks.json` from `127.0.0.1`) replaced with a single readable `INFO [app.health] Docker healthcheck OK` line instead of the raw uvicorn access entry
- Duplicate "Apple SCIM disabled" log line removed — preflight already reports it; the lifespan startup no longer logs it a second time
- CAEP event body no longer includes a `subject` field inside the `events` object — the subject belongs only at the top-level `sub_id` JWT claim per SSF 1.0 §5.1

---

## [0.2.2] — 2026-05-29

### Added
- Startup preflight checks: on every container start the service runs a BIOS-style POST sequence and logs ✅/⚠️/❌ for `SSF_ISSUER`, `SSF_BASE_URL`, `SSF_MANAGEMENT_TOKEN`, webhook auth config, signing key, JWKS, and database writability
- Container exits with code **0** on any critical preflight failure so Docker `restart: unless-stopped` does **not** loop — fix the config and restart manually
- Built-in Docker `HEALTHCHECK` polling `GET /jwks.json` every 30 seconds using Python stdlib (no `curl`/`wget` required); Portainer shows **(healthy)**/**(unhealthy)**

### Fixed
- Startup configuration errors now print a single readable `❌ Configuration error: …` line instead of a 30-line Python traceback

---

## [0.2.1] — 2026-05-29

### Added
- `SSF_WEBHOOK_AUTH_MODE` environment variable with three modes:
  - `bearer` (default/recommended) — Authentik sends `Authorization: Bearer <SSF_WEBHOOK_TOKEN>` via a Webhook Header Mapping
  - `hmac` (legacy) — Authentik sends `X-Authentik-Signature: sha256=<hmac>` using `SSF_WEBHOOK_SECRET`
  - `unsigned` (development only) — no authentication; logs a loud warning on every request
- `SSF_WEBHOOK_TOKEN` environment variable for bearer mode (minimum 32 characters, validated at startup)
- `SSF_ALLOW_UNSIGNED_WEBHOOK=true` retained as a backward-compatible alias for `SSF_WEBHOOK_AUTH_MODE=unsigned`

---

## [0.2.0] — 2026-05-29

### Added
- SSF Framework 1.0 conformance: `sub_id` at top level of SET JWT payload (§5.1), `typ: secevent+jwt` header (RFC 8417 §2.3), verification SET uses correct `ssf/event-type/verification` URI (SSF §6.2), `aud` encoded as single-element array (RFC 7519 §4.1.3)
- PII masking: email addresses replaced by `[pii:<sha256[:8]>]` in all log output by default (`SSF_LOG_PII=false`); keyed with `SSF_PII_PEPPER`
- SSRF protection for `delivery.endpoint_url`: blocks RFC 1918, loopback, link-local, multicast, and reserved ranges; hostname blocklist (`localhost`, `169.254.169.254`, `metadata.google.internal`)
- DNS rebinding protection: receiver endpoint hostname is re-resolved before every outbound SET push
- Webhook body size limit: 64 KiB maximum before HMAC check
- `SSF_MANAGEMENT_TOKEN` bearer token protecting all `/ssf/*` management endpoints (minimum 32 characters)
- Strict Pydantic validation on all management API inputs: extra fields rejected, event URIs validated against an allowlist, delivery method validated against an allowlist
- SQLite database file created with `chmod 0600`; atomic creation using `O_EXCL`
- Container runs as non-root user `appuser` (UID 10001)
- RSA key size upgraded from 2048 to 4096 bits
- Apple Business Manager SCIM directory sync (optional; requires `APPLE_SCIM_CLIENT_ID`, `APPLE_SCIM_CLIENT_SECRET`, `AUTHENTIK_URL`, `AUTHENTIK_TOKEN`)
- `SECURITY.md` with threat model, trust boundaries, data processed, mitigations, deployment requirements, and vulnerability disclosure process

### Security
- Webhook authentication is now fail-closed: requests without a valid signature/token are rejected with 401 by default

---

## [0.1.0]

### Added
- FastAPI service implementing SSF transmitter push delivery endpoints:
  - `GET /.well-known/ssf-configuration` — discovery metadata
  - `GET /jwks.json` — public JWKS for RS256 SET verification
  - `POST/GET/PATCH/DELETE /ssf/streams` — stream management
  - `POST /ssf/streams/subjects:add` and `subjects:remove`
  - `GET /ssf/status`
  - `POST /webhook/authentik` — Authentik event receiver
- Authentik → SSF/CAEP/RISC event mapping:
  - `auth.logout` → `caep/session-revoked`
  - `user.write` (password change) → `caep/credential-change`
  - `user.write` (`is_active` false/true) → `risc/account-disabled` / `risc/account-enabled`
  - `user.delete` → `risc/account-purged`
- RS256-signed Security Event Token (SET) push delivery to registered receiver
- SQLite persistence for stream configuration
- Docker-first deployment with multi-architecture GHCR image (`linux/amd64`, `linux/arm64`)
- CI pipeline: linting (ruff), tests (pytest), Docker image build on push to `main`
- `docs/API.md` — API reference with request/response examples
- `docs/synology-authentik-compose.md` — Synology NAS deployment guide
