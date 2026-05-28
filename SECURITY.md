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
        │ HMAC-SHA256         │ Bearer token (SSF_MANAGEMENT_TOKEN)
[Authentik container]   [Management client (local / Portainer)]
```

### Protected endpoints (require `Authorization: Bearer <SSF_MANAGEMENT_TOKEN>`)

- `POST/GET/PATCH/DELETE /ssf/streams`
- `POST /ssf/streams/subjects:add`
- `POST /ssf/streams/subjects:remove`
- `GET /ssf/status`
- `POST /apple-scim/sync` (if Apple SCIM is enabled)

### Public endpoints (no authentication required)

- `GET /.well-known/ssf-configuration`
- `GET /jwks.json`
- `GET /apple-scim/status` (Apple SCIM OAuth status, no sensitive data)
- `GET /apple-scim/authorize` (initiates OAuth flow)
- `GET /apple-scim/callback` (OAuth callback)

### Webhook endpoint

- `POST /webhook/authentik` — requires `X-Authentik-Signature: sha256=<hmac>` by default.
  Set `SSF_ALLOW_UNSIGNED_WEBHOOK=true` only if the endpoint is reachable exclusively from the Authentik container on an internal Docker network.

---

## Data processed

| Data | Where stored | Protection |
|---|---|---|
| RSA 4096-bit private key | `/app/keys/private.pem` | File permissions 0600; volume must be root-owned |
| Receiver endpoint URL | SQLite (`/app/data/ssf.db`) | Not secret; validated against SSRF blocklist |
| Receiver bearer token | SQLite (`/app/data/ssf.db`) | **Stored in plaintext** — protect the data volume |
| Management token | Environment variable only | Never written to disk or logged |
| Webhook HMAC secret | Environment variable only | Never written to disk or logged |
| User email addresses | Logs (pseudonymous by default) | Replaced by `[pii:<sha256[:8]>]` when `SSF_LOG_PII=false` |

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
- Webhook is fail-closed by default: missing `X-Authentik-Signature` returns 401.
- Signature verification uses `hmac.compare_digest` (constant-time).
- Body size limited to 64 KiB before HMAC is checked.

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
3. **Strong secrets:** Generate `SSF_MANAGEMENT_TOKEN` and `SSF_WEBHOOK_SECRET` with at least 32 random characters (`openssl rand -hex 24`).
4. **Volume permissions:** Mount `/app/keys` and `/app/data` to host paths owned by root (mode 700). Do not share these volumes with other containers.
5. **Log pipeline:** Logs go to stdout/stderr only. Route them to a private log aggregator; do not ship logs to untrusted third parties (they may contain pseudonymous user identifiers).
6. **Rate limiting:** Use nginx `limit_req` or Caddy `rate_limit` in front of the service. SSF Transmitter does not implement rate limiting internally.

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
