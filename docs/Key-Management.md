# Key Management

## Secrets overview

| Secret | Purpose | Stored |
|---|---|---|
| `SSF_MANAGEMENT_TOKEN` | Protects `/ssf/*`, `/apple-scim/status`, `/apple-scim/sync` | Env only |
| `SSF_WEBHOOK_TOKEN` | Authentik webhook auth (bearer mode) | Env only |
| `SSF_WEBHOOK_SECRET` | Authentik webhook auth (HMAC legacy) | Env only |
| `SSF_PII_PEPPER` | Log email pseudonymisation | Env only |
| `SSF_TOKEN_ENCRYPTION_KEY` | Encrypt receiver tokens in SQLite | Env only |
| RSA private key | Sign SET JWTs | `/app/keys/private.pem` |
| Receiver bearer token | Authenticate push to ABM/receiver | SQLite (encrypted at rest since v0.5.9) |

Generate random secrets:

```bash
openssl rand -hex 32
```

**Never reuse** `SSF_MANAGEMENT_TOKEN` as `SSF_WEBHOOK_TOKEN` — they protect different boundaries.

## RS256 signing key (`/app/keys`)

- Created automatically on first start (`chmod 0600`).
- **Backup** before upgrades or host migration.
- **Rotation:** stop container → remove `private.pem` and `jwks.json` → start (new key pair). Receivers re-fetch JWKS.
- Compromise: rotate immediately; receivers may need to refresh trusted keys.

## Receiver token encryption (v0.5.9+)

Receiver endpoint tokens in SQLite are Fernet-encrypted with prefix `fernet1:`.

| Key source | When |
|---|---|
| `SSF_TOKEN_ENCRYPTION_KEY` | Set explicitly (recommended for **new** installs) |
| Derived from `SSF_MANAGEMENT_TOKEN` | Default when encryption key unset |

### Existing deployment (stream already registered)

- **Leave `SSF_TOKEN_ENCRYPTION_KEY` unset** unless you will re-register the stream.
- **Do not rotate** `SSF_MANAGEMENT_TOKEN` without re-registering the stream with a new `delivery.endpoint_url_token`.

### New deployment

1. Generate `SSF_TOKEN_ENCRYPTION_KEY` and add to `stack.env`.
2. Start container.
3. Register stream (`POST /ssf/streams`).

### After rotation

If startup logs show paused streams due to undecryptable tokens:

1. Obtain new receiver token from ABM/receiver.
2. `PATCH /ssf/streams` with the current `delivery.endpoint_url`, the new `delivery.endpoint_url_token`, and `status: enabled`.

## `SSF_PII_PEPPER`

Optional. When unset, logs use a key derived from `SSF_MANAGEMENT_TOKEN` (startup warning). Set a dedicated pepper in production.

## Backup checklist

```text
/volume/.../ssf-keys/     → private.pem, jwks.json
/volume/.../ssf-data/     → ssf.db
stack.env                 → all tokens (secure store, not in git)
```

Restore both volumes together when migrating hosts.
