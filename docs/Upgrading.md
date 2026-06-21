# Upgrading

## v0.5.9 — Security hardening (from 0.5.8 or earlier)

Release notes: [v0.5.9](https://github.com/solarssk/ssf-transmitter/releases/tag/v0.5.9)

### What changed for operators

| Area | Change |
|---|---|
| Receiver tokens | Encrypted at rest in SQLite (Fernet) |
| Reverse proxy | `SSF_FORWARDED_ALLOW_IPS` default is now `127.0.0.1` (was `*`) |
| Management API | In-app rate limits; failed auth attempts rate-limited per IP |
| Apple SCIM | `GET /apple-scim/status` requires management Bearer token |
| Startup | HTTPS required for `SSF_ISSUER` / `SSF_BASE_URL`; undecryptable receiver tokens pause streams |
| Logging | Prefer `SSF_LOG_LEVEL` over `LOG_LEVEL` |

### Upgrade checklist (existing ABM / stream)

Use this when you **already have a working stream** and Apple Business Manager is connected.

1. **Backup** volumes:
   - `/app/keys` (signing key)
   - `/app/data` (SQLite — stream + SCIM tokens)
2. **Update image tag:**
   ```yaml
   image: ghcr.io/solarssk/ssf-transmitter:0.5.9
   ```
3. **Set proxy trust** (if behind NPM/Caddy/Traefik):
   ```env
   SSF_FORWARDED_ALLOW_IPS=172.16.3.0/24   # your proxy subnet
   ```
4. **Do not add** `SSF_TOKEN_ENCRYPTION_KEY` on an existing install unless you will re-register the stream.
5. **Do not rotate** `SSF_MANAGEMENT_TOKEN` without a plan to re-register the stream.
6. Pull and redeploy:
   ```bash
   docker compose pull ssf-transmitter
   docker compose up -d ssf-transmitter
   ```
7. **Verify** startup logs show `preflight OK`.
8. **Check stream status:**
   ```bash
   curl -s -H "Authorization: Bearer $SSF_MANAGEMENT_TOKEN" \
     https://idp.example.com/shared-signals/ssf/status
   ```
   Expect `"status": "enabled"`.

### What is a “stream”?

A **stream** is the SSF receiver configuration stored in SQLite (`/app/data/ssf.db`): receiver URL, bearer token, events, and status. “Already connected to ABM” means you already have a stream — not a fresh install.

### If stream is `paused` after upgrade

Startup pauses streams when the stored receiver token cannot be decrypted (e.g. after key rotation). Logs contain:

```text
undecryptable endpoint tokens and were paused
```

**Fix:** Re-register the stream via management API with a new `delivery.endpoint_url_token` from your receiver, then set `status: enabled`.

You cannot re-enable a paused stream with an undecryptable token without supplying a replacement token (by design since v0.5.9).

### Optional hardening after upgrade

| Variable | When |
|---|---|
| `SSF_ALLOWED_RECEIVER_HOSTS` | Restrict stream registration to known receiver hostnames |
| `SSF_PII_PEPPER` | Dedicated secret for log pseudonymisation |
| `SSF_TOKEN_ENCRYPTION_KEY` | **New installs only**, or planned migration with stream re-registration |

### Fresh install (no existing stream)

1. Set all required variables per [Configuration.md](Configuration.md).
2. Optionally set `SSF_TOKEN_ENCRYPTION_KEY` **before** first `POST /ssf/streams`.
3. Set `SSF_FORWARDED_ALLOW_IPS` if behind a reverse proxy.
4. Register stream with ABM.

## General upgrade procedure

```bash
docker compose pull ssf-transmitter
docker compose up -d ssf-transmitter
docker logs authentik-ssf --tail 50
```

Pin to a version tag (`0.5.9`) in production; use `:latest` only if you accept automatic updates on redeploy.

## Rolling back

1. Stop container.
2. Restore `/app/keys` and `/app/data` from backup if needed.
3. Deploy previous image tag (e.g. `0.5.8`).
4. If you upgraded DB format or encryption on 0.5.9, test rollback in a lab first.
