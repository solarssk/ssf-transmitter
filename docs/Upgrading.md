# Upgrading

## v0.5.18 — Apple SCIM pagination compatibility (from 0.5.17)

Release notes: [v0.5.18](https://github.com/solarssk/ssf-transmitter/releases/tag/v0.5.18)

This release has no configuration or database migration. It handles the
nonstandard Apple SCIM listing metadata observed in one directory by
preflighting individual identity lookups rather than assuming the initial
listing is complete. The fallback can make two filtered requests per
Authentik user plus reads for matched Apple IDs, so syncs can take longer.
Exact-filter completeness remains dependent on Apple's API.

1. Back up `/app/data` (SQLite) and `/app/keys` (signing key), and retain the existing environment secrets and encryption-key configuration. **Do not add or rotate `SSF_TOKEN_ENCRYPTION_KEY` on a working installation as part of this upgrade.** If it is unset, keep the same `SSF_MANAGEMENT_TOKEN`: it is the encryption-key source. If upgrading from a version before v0.5.17, also follow the v0.5.17 outbox and stream-upgrade cautions in [CHANGELOG.md](../CHANGELOG.md#0517--apple-scim-safety-and-reliable-set-delivery).
2. Update the image tag to `0.5.18`, pull and restart the service:

```bash
docker compose pull ssf-transmitter
docker compose up -d ssf-transmitter
docker compose logs ssf-transmitter --tail 50
```

3. Check startup logs and `GET /ssf/status` using the management token. The new outbox table is created automatically in the existing SQLite database.
4. Check `GET /ssf/delivery/status` for pending or blocked SETs. An accepted webhook response reports the number of SETs stored (for example, `{"status":"accepted","queued":1}`), not whether the receiver accepted them. The count can be zero when all events are filtered; ignored events also return HTTP 200 without queueing. Delivery is at-least-once; an ambiguous failure may produce a duplicate.
5. Monitor webhook failures and ensure the sender retries `500`/`503` responses. The queue holds at most 10,000 pending or blocked items; a full queue returns `503` without accepting a new event. Failed accepted deliveries retry with backoff; inspect queue age and blocked counts.

Queued SETs contain subject email addresses and are encrypted at rest with the receiver-token key. Pausing a stream holds pending deliveries; replacing or deleting it, or changing its audience, endpoint, token, or event filter, cancels pending deliveries for the old configuration. These operations wait for any in-flight delivery to finish. During graceful shutdown the worker finishes an in-flight push or its 30-second delivery deadline; if the container runtime stops it sooner, queued work is retried on restart and may be delivered more than once. See [API.md](API.md) for status and explicit retry/discard controls.

Apple SCIM username-only recovery remains disabled by default. Existing
`externalId`-linked accounts are unaffected. Set
`APPLE_SCIM_ALLOW_USERNAME_RECOVERY=true` only after verifying ownership of
**all** matching unlinked Apple accounts in the configured sync scope. Failed,
ambiguous, or inconsistent individual identity lookups stop the sync before
user writes; exact filters can still miss results if Apple omits them. A
concurrent manual sync or OAuth callback returns `409`. Run only one container
for the same Apple integration: coordination is process-local.

## v0.5.15 — Dependency security refresh (from 0.5.14)

Release notes: [v0.5.15](https://github.com/solarssk/ssf-transmitter/releases/tag/v0.5.15)

Dependency-only — patches PyJWT (CVE-2026-101918, not reachable here) and certifi (PYSEC-2026-4320) and bumps FastAPI, Uvicorn and cryptography; no `app/` changes. Nothing to configure, no migration, no new env vars — bump the tag whenever convenient:

```bash
docker compose pull ssf-transmitter
docker compose up -d ssf-transmitter
docker compose logs ssf-transmitter --tail 50
```

## v0.5.14 — OpenSSF Scorecard hardening (from 0.5.13)

Release notes: [v0.5.14](https://github.com/solarssk/ssf-transmitter/releases/tag/v0.5.14)

Mostly CI/security-tooling — least-privilege `GITHUB_TOKEN` grants, real fuzz testing, hash-pinned dev/CI tooling, Sigstore-signed SBOMs. One real app-level fix: a malformed stored `endpoint_url` (found by the new fuzzer, not seen in production) is now blocked instead of crashing outbound push or startup preflight. Nothing to configure, no migration, no new env vars — bump the tag whenever convenient:

```bash
docker compose pull ssf-transmitter
docker compose up -d ssf-transmitter
docker compose logs ssf-transmitter --tail 50
```

## v0.5.13 — Apple SCIM sync error handling (from 0.5.12)

Release notes: [v0.5.13](https://github.com/solarssk/ssf-transmitter/releases/tag/v0.5.13)

One bug fix: `POST /apple-scim/sync` no longer 500s on a transient Apple API error while listing existing users — it now returns the same `502 Could not reach Apple Business Manager` that an unreachable Authentik already produced. Nothing to configure, no migration. Bump the tag whenever convenient:

```bash
docker compose pull ssf-transmitter
docker compose up -d ssf-transmitter
docker compose logs ssf-transmitter --tail 50
```

## v0.5.12 — Release pipeline hardening (from 0.5.11)

Release notes: [v0.5.12](https://github.com/solarssk/ssf-transmitter/releases/tag/v0.5.12)

No `app/` changes at all — this release only touches CI/release tooling (fixes to `release.yml` and `docker-publish.yml` found while cutting v0.5.11, the first release actually run through the new automation). Nothing to act on; the image content is identical to v0.5.11's except for a corrected SBOM (now covers both `linux/amd64` and `linux/arm64` instead of amd64 only). Upgrading is optional — bump the tag whenever convenient:

```bash
docker compose pull ssf-transmitter
docker compose up -d ssf-transmitter
docker compose logs ssf-transmitter --tail 50
```

## v0.5.11 — Security audit fixes & release automation (from 0.5.10)

Release notes: [v0.5.11](https://github.com/solarssk/ssf-transmitter/releases/tag/v0.5.11)

No config changes, no required env vars, no migration. This release is a set of internal bug fixes (an SSRF blocklist gap, a stream-write race condition, several Apple SCIM sync correctness fixes, a rate-limit sharing fix) plus new release-automation tooling that doesn't touch the running app. Bump the image tag and redeploy:

```bash
docker compose pull ssf-transmitter
docker compose up -d ssf-transmitter
docker compose logs ssf-transmitter --tail 50
```

Two things worth knowing, neither requiring action unless they apply to you:

- **If you've set `APPLE_SCIM_UPDATE_MODE`** to anything other than the default `patch_all`: the sync loop that could previously retry the same no-op update forever under a narrow mode is fixed, and a new `out_of_scope_diffs` counter (plus a one-time `WARNING` log) now tells you when a field difference is permanently outside what that mode will write. See [docs/Apple-SCIM-Sync.md](Apple-SCIM-Sync.md#apple_scim_update_mode).
- **If you script against the management API**: `PATCH /ssf/streams` and `PATCH /ssf/streams/{stream_id}` now share one rate-limit counter instead of each getting its own — a script alternating between the two routes will hit `429` sooner than before (20/minute total, not 40).

## v0.5.10 — Stream recovery hardening (from 0.5.8 or earlier)

Release notes: [v0.5.10](https://github.com/solarssk/ssf-transmitter/releases/tag/v0.5.10)

### What changed for operators

| Area | Change |
|---|---|
| Receiver tokens | Encrypted at rest in SQLite (Fernet) |
| Reverse proxy | `SSF_FORWARDED_ALLOW_IPS` default is now `127.0.0.1` (was `*`) |
| Management API | In-app rate limits; failed auth attempts rate-limited per IP |
| Apple SCIM | `GET /apple-scim/status` requires management Bearer token |
| Startup | HTTPS required for `SSF_ISSUER` / `SSF_BASE_URL`; undecryptable receiver tokens pause streams |
| Logging | Prefer `SSF_LOG_LEVEL` over `LOG_LEVEL` |
| Webhook auth | Default is `bearer`; legacy HMAC installs must keep `SSF_WEBHOOK_AUTH_MODE=hmac` (see below) |

### Webhook auth: bearer vs HMAC

`SSF_WEBHOOK_AUTH_MODE` defaults to **`bearer`** in application code. New installs should use bearer with Authentik Header Mapping (`Authorization: Bearer <SSF_WEBHOOK_TOKEN>`).

If your deployment still uses **HMAC** (`X-Authentik-Signature` + `SSF_WEBHOOK_SECRET`), you must **explicitly** set in `stack.env`:

```env
SSF_WEBHOOK_AUTH_MODE=hmac
SSF_WEBHOOK_SECRET=<your existing secret>
```

Without this, an upgrade can silently switch to bearer mode and Authentik webhooks will return **401** until you migrate the transport to bearer or restore `hmac` in env.

To migrate to bearer: set `SSF_WEBHOOK_AUTH_MODE=bearer`, add `SSF_WEBHOOK_TOKEN`, and update the Authentik Generic Webhook Header Mapping. See [Deployment.md](Deployment.md#authentik-webhook).


Use this when you **already have a working stream** and Apple Business Manager is connected.

1. **Backup** volumes:
   - `/app/keys` (signing key)
   - `/app/data` (SQLite — stream + SCIM tokens)
2. **Update image tag:**
   ```yaml
   image: ghcr.io/solarssk/ssf-transmitter:0.5.10
   ```
   (or `docker.io/solarssk/ssf-transmitter:0.5.10` — same image, public, no login; see [Deployment.md#image](Deployment.md#image))
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
   docker compose logs ssf-transmitter --tail 50
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

You cannot re-enable a paused stream with an undecryptable token without supplying a replacement token (by design since v0.5.9, still enforced in v0.5.10).

Minimal recovery PATCH (include the current `delivery.endpoint_url`; the PATCH schema still requires it):

```json
{
  "status": "enabled",
  "delivery": {
    "endpoint_url": "https://receiver.example.com/sets",
    "endpoint_url_token": "<new receiver token>"
  }
}
```

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
docker compose logs ssf-transmitter --tail 50
```

Pin to a version tag (`0.5.18`) in production; use `:latest` only if you accept automatic updates on redeploy.

## Rolling back

1. Before rolling back from `0.5.18` to a version older than `0.5.17`, drain the outbox if possible and verify `/ssf/delivery/status`: those versions do not deliver queued SETs.
2. Stop the container and back up the current `/app/keys`, `/app/data`, and encryption-key configuration. Restoring an older database backup discards any queued events created after that backup.
3. Deploy the previous image tag (e.g. `0.5.17`). Preserve the newer database and original key if blocked or pending SETs need to be recovered by returning to `0.5.18`.
4. Test rollback in a lab first when changing DB format or encryption settings.
