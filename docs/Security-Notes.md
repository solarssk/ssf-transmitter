# Security Notes

Operator checklist for production. Full threat model: [SECURITY.md](../SECURITY.md).

## Before go-live

- [ ] TLS at reverse proxy; container not exposed on `0.0.0.0:8000` publicly
- [ ] `SSF_MANAGEMENT_TOKEN` and `SSF_WEBHOOK_TOKEN` ≥ 32 chars, **different values**
- [ ] `SSF_WEBHOOK_AUTH_MODE=bearer` (not `unsigned`)
- [ ] `SSF_FORWARDED_ALLOW_IPS` set to proxy subnet (not `*` in production)
- [ ] `SSF_ISSUER` and `SSF_BASE_URL` are HTTPS
- [ ] `/app/keys` and `/app/data` on root-owned volumes, backed up
- [ ] `SSF_ENABLE_OPENAPI=false` on internet-facing deployments
- [ ] Webhook URL uses internal Docker DNS (`authentik-ssf:8000`), not public URL
- [ ] Secrets in `stack.env` only — never in compose YAML or git

## v0.5.9 hardening

| Feature | Operator action |
|---|---|
| Receiver token encryption | Automatic; protect `/app/data` volume |
| `SSF_ALLOWED_RECEIVER_HOSTS` | Optional allowlist for receiver hostnames |
| Rate limiting | In-app limits on webhook and management API; add nginx `limit_req` too |
| Security headers | Automatic on all responses |
| Undecryptable tokens | Startup pauses stream; re-register with new token |

## Token rotation rules

| Rotate | Consequence |
|---|---|
| `SSF_MANAGEMENT_TOKEN` | May pause stream; re-register receiver token |
| `SSF_TOKEN_ENCRYPTION_KEY` | Pauses streams encrypted with old key |
| `SSF_WEBHOOK_TOKEN` | Update Authentik Header Mapping only |
| RSA key in `/app/keys` | Receivers refresh JWKS; no stream re-register |

See [Key-Management.md](Key-Management.md).

## Reporting vulnerabilities

Private advisory: https://github.com/solarssk/ssf-transmitter/security/advisories/new
