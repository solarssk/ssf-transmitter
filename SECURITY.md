# Security Policy

## Scope

This document covers the threat model, trust boundaries, and security properties of **SSF Transmitter** — a self-hosted FastAPI service that bridges Authentik webhooks to OpenID Shared Signals Framework (SSF) push receivers.

---

## Trust boundaries

```text
[Internet / Receiver]
        │ HTTPS only, RS256-signed JWT
        ▼
[Reverse proxy — TLS termination, rate limiting, IP filtering]
        │
        ▼
[SSF Transmitter container]
        ▲                    ▲
        │ Bearer token        │ Bearer token (SSF_MANAGEMENT_TOKEN)
        │ (SSF_WEBHOOK_TOKEN) │
[Authentik container]   [Management client (local / Portainer)]
```

### Protected endpoints (require `Authorization: Bearer <SSF_MANAGEMENT_TOKEN>`)

- `POST/GET/PATCH/DELETE /ssf/streams`
- `POST /ssf/streams/subjects:add`
- `POST /ssf/streams/subjects:remove`
- `GET /ssf/status`
- `POST /ssf/verification`
- `GET /apple-scim/status` (if Apple SCIM is enabled)
- `POST /apple-scim/sync` (if Apple SCIM is enabled)

### Public endpoints (no authentication required)

- `GET /` — minimal service discovery (service name, version, link to SSF well-known)
- `GET /.well-known/ssf-configuration`
- `GET /jwks.json`
- `GET /apple-scim/authorize` (initiates OAuth flow — admin browser)
- `GET /apple-scim/callback` (OAuth redirect from Apple; CSRF-protected via `state` parameter)

### OpenAPI / Swagger (disabled by default)

- `GET /docs`, `GET /redoc`, and `GET /openapi.json` are **not** exposed unless `SSF_ENABLE_OPENAPI=true`.
- Keep the flag `false` on production deployments reachable from untrusted networks. Enable only in dev or a trusted LAN when you need interactive API exploration.

### Webhook endpoint

- `POST /webhook/authentik` — authentication mode controlled by `SSF_WEBHOOK_AUTH_MODE`:
  - **`bearer` (default/recommended):** Authentik sends `Authorization: Bearer <SSF_WEBHOOK_TOKEN>` via a Generic Webhook Header Mapping. Simplest to configure and rotate.
  - **`hmac` (legacy):** Authentik sends `X-Authentik-Signature: sha256=<hmac>`. Still supported but new deployments should use `bearer`.
  - **`unsigned` (dev/lab only):** No authentication. Only use if the webhook endpoint is reachable exclusively from the Authentik container on an isolated internal Docker network.
  - `SSF_ALLOW_UNSIGNED_WEBHOOK=true` is a deprecated alias for `unsigned` — it logs a startup warning and will be removed in a future release.

---

## Data processed

| Data | Where stored | Protection |
|---|---|---|
| RSA 4096-bit private key | `/app/keys/private.pem` | File permissions 0600; volume must be root-owned |
| Receiver endpoint URL | SQLite (`/app/data/ssf.db`) | Not secret; validated against SSRF blocklist |
| Receiver bearer token | SQLite (`/app/data/ssf.db`) | Encrypted at rest (Fernet); key from `SSF_TOKEN_ENCRYPTION_KEY` or derived from `SSF_MANAGEMENT_TOKEN` |
| Management token | Environment variable only | Never written to disk or logged |
| Webhook bearer token (`SSF_WEBHOOK_TOKEN`) | Environment variable only | Never written to disk or logged |
| Webhook HMAC secret (`SSF_WEBHOOK_SECRET`) | Environment variable only | Never written to disk or logged (legacy mode only) |
| User email addresses | Logs (pseudonymous by default) | Replaced by `[pii:<sha256[:8]>]` when `SSF_LOG_PII=false` |
| PII pseudonymisation key (`SSF_PII_PEPPER`) | Environment variable only | Never written to disk or logged; falls back to `SSF_MANAGEMENT_TOKEN` if unset (startup warning issued) |

---

## Main risks and mitigations

### SSRF via receiver `endpoint_url`

**Risk:** An attacker with access to the management API could register a stream pointing to an internal service (cloud metadata endpoint, internal database).

**Mitigation:**
- `validate_receiver_endpoint_url()` at stream creation and update: HTTPS only, no credentials in URL, no fragment, resolves to a non-private IP.
- `_revalidate_endpoint()` called before every outbound push: re-resolves hostname to detect DNS rebinding.
- Blocked ranges: RFC 1918, loopback (`127.0.0.0/8`, `::1`), link-local (`169.254.0.0/16`), multicast, reserved.
- Blocked hostnames: `localhost`, `169.254.169.254`, `metadata.google.internal`.
- `follow_redirects=False` in all outbound HTTP clients.

### Spoofed Authentik webhooks

**Risk:** An attacker who can POST to `/webhook/authentik` could trigger arbitrary session-revocation events for any user.

**Mitigation:**
- In `bearer` mode (default): missing or invalid `Authorization: Bearer <SSF_WEBHOOK_TOKEN>` returns 401. Token comparison uses `hmac.compare_digest` (constant-time).
- In `hmac` mode (legacy): missing or invalid `X-Authentik-Signature` returns 401. Signature verification uses `hmac.compare_digest` (constant-time).
- `unsigned` mode disables authentication entirely — only for isolated dev/lab environments.
- Body size limited to 64 KiB before authentication is checked.

### Management API abuse

**Risk:** An unauthenticated attacker could register a malicious stream, delete the legitimate stream, or enumerate stream configuration.

**Mitigation:**
- All management endpoints require `Authorization: Bearer <SSF_MANAGEMENT_TOKEN>`.
- Token comparison is constant-time (`hmac.compare_digest`).
- Token minimum length is 32 characters, enforced at startup.
- Strict Pydantic models on all management inputs: extra fields rejected, event URIs validated against an allowlist, delivery method validated against an allowlist.

### Receiver token exposure

**Risk:** Receiver bearer tokens (used to authenticate push delivery to SSF receivers) are stored in SQLite.

**Mitigation:**
- Tokens are never returned in any API response.
- Tokens are never logged.
- SQLite file is created with `chmod 0600`.
- The container runs as a non-root user (`appuser`, UID 10001).
- Streams with undecryptable stored receiver tokens are quarantined to `paused` at startup and cannot be re-enabled without a replacement `delivery.endpoint_url_token`.
- **Operator responsibility:** mount `/app/data` to a root-owned host path; use encrypted storage if your threat model requires it.

### JWT signing key compromise

**Risk:** If `/app/keys/private.pem` is stolen, an attacker can sign arbitrary SETs appearing to come from this transmitter.

**Mitigation:**
- Key file is created with `chmod 0600`.
- The container runs as non-root.
- **Operator responsibility:** back up the key securely; protect the `/app/keys` volume.
- To rotate: stop the service, remove `/app/keys/`, restart. Receivers will re-fetch JWKS.

### DNS rebinding

**Risk:** A receiver hostname might resolve to a public IP at stream registration time but later rebind to a private IP.

**Mitigation:**
- `_revalidate_endpoint()` re-resolves the hostname before every outbound push.
- A hostname that resolves to an empty list (NXDOMAIN, timeout) causes the push to be silently dropped (fail-closed).

---

## Deployment requirements

To run this service securely in production:

1. **TLS:** Place behind nginx or Caddy with a valid certificate. Never expose the service directly on port 8000.
2. **Network isolation:** The webhook endpoint (`/webhook/authentik`) should be reachable only from the Authentik container. Use Docker networks or nginx `allow`/`deny` rules.
3. **Strong secrets:** Generate `SSF_MANAGEMENT_TOKEN` and `SSF_WEBHOOK_TOKEN` (bearer mode) or `SSF_WEBHOOK_SECRET` (hmac mode) with at least 32 random characters (`openssl rand -hex 24`). Do not reuse the same value for both tokens — they protect different trust boundaries.
   Existing HMAC deployments must keep `SSF_WEBHOOK_AUTH_MODE=hmac` explicitly set during upgrades until the Authentik transport is migrated to bearer auth.
4. **Volume permissions:** Mount `/app/keys` and `/app/data` to host paths owned by root (mode 700). Do not share these volumes with other containers.
5. **Log pipeline:** Logs go to stdout/stderr only. Route them to a private log aggregator; do not ship logs to untrusted third parties (they may contain pseudonymous user identifiers).
6. **Rate limiting:** The application enforces in-app limits via slowapi (default 200/min per IP; webhook 60/min; stream create 10/min). Also configure nginx `limit_req` or Caddy `rate_limit` in front of the service as a second line of defence.
7. **Reverse proxy trust:** `SSF_FORWARDED_ALLOW_IPS` defaults to `127.0.0.1` in the container image. Set it to your reverse proxy's Docker network subnet (e.g. `172.18.0.0/16` for a typical Nginx Proxy Manager bridge network) so client IP logging and rate limits are accurate.
8. **Signing key at rest:** The RS256 private key is stored unencrypted PEM with `0600` permissions on a dedicated volume. Protect `/app/keys` the same way as `/app/data`; optional passphrase encryption is not used because the passphrase would live in the same environment as the key material.

---

## Vulnerability disclosure

This is a personal home-lab project.

If you find a security issue, please open a **private security advisory** via:
`https://github.com/solarssk/ssf-transmitter/security/advisories/new`

Please include:
- A clear description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (optional but appreciated)

There is no formal SLA, but I aim to respond within a week and ship a fix within 30 days for critical issues.
