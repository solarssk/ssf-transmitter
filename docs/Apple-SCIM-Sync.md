# Apple SCIM Sync

Optional directory sync from Authentik to Apple Business Manager (ABM). SSF/CAEP event forwarding works without SCIM.

## Required variables

```env
APPLE_SCIM_CLIENT_ID=SCIM.xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
APPLE_SCIM_CLIENT_SECRET=<from ABM>
AUTHENTIK_URL=https://idp.example.com
AUTHENTIK_TOKEN=<Authentik API token>
```

Generate the client secret in ABM under **Settings → Directory Sync**. It expires every 6, 9, or 12 months — update `stack.env` and redeploy.

## Optional

| Variable | Description |
|---|---|
| `APPLE_SCIM_GROUP_ID` | Authentik group UUID — sync only members (recommended in production) |
| `APPLE_SCIM_SYNC_INTERVAL` | Seconds between automatic syncs (default `3600`) |
| `APPLE_SCIM_ALERT_WEBHOOK_URL` | Alerts for re-authorization or expired client secret |
| `APPLE_SCIM_UPDATE_MODE` | Which fields a sync writes back to Apple (default `patch_all`) — see below |

### `APPLE_SCIM_UPDATE_MODE`

Controls which user fields a sync is allowed to write to Apple. Leave this at
the default unless you have a specific reason to narrow it (e.g. isolating
which field an Apple `400` response is coming from).

| Value | Writes |
|---|---|
| `patch_all` (default) | Every syncable field (`externalId`, `userName`, name, emails, `active`) |
| `replace_all` | Same fields as `patch_all`, via a full `PUT` instead of a `PATCH` |
| `external_id_only` | Only `externalId` (identity linkage) |
| `emails_only` | Only the email address |
| `username_only` | Only `userName` |

**A narrow mode (anything but `patch_all`/`replace_all`) can permanently
undersync a user.** If a user's email (say) differs from Apple's record but
`APPLE_SCIM_UPDATE_MODE=external_id_only`, that email difference is outside
what the configured mode will ever write — it does not get retried forever,
but it also never gets fixed automatically. `POST /apple-scim/sync`'s
response and the sync-done log line report this as `out_of_scope_diffs`; a
non-zero count also triggers a one-time `WARNING` log after the sync:

```
Apple SCIM: ⚠️  N user(s) have a field diff outside update_mode=... scope and will stay stale — widen APPLE_SCIM_UPDATE_MODE or fix manually in Apple Business Manager
```

To resolve it: either widen `APPLE_SCIM_UPDATE_MODE` back to `patch_all` (or
`replace_all`) so the next sync writes the missing field, or edit the
user's record directly in Apple Business Manager.

## OAuth authorization

1. Open `GET /apple-scim/authorize` in a browser (public — no management token).
2. Complete Apple OAuth; callback is `GET /apple-scim/callback` (CSRF-protected via state TTL since v0.5.9).

## Admin endpoints (v0.5.9+)

Require `Authorization: Bearer <SSF_MANAGEMENT_TOKEN>`:

| Endpoint | Purpose |
|---|---|
| `GET /apple-scim/status` | SCIM connection status |
| `POST /apple-scim/sync` | Trigger manual sync |

## Group filtering (recommended)

```env
APPLE_SCIM_GROUP_ID=978bff1a-5f55-4068-808c-45e09bb196d4
```

1. Create an Authentik group (e.g. **Apple Accounts**).
2. Add only users who should receive Apple Managed Accounts.
3. Exclude break-glass, service, and local-only accounts.

If `APPLE_SCIM_GROUP_ID` is empty, all active internal users are considered (legacy behaviour).

## Alerts

Set `APPLE_SCIM_ALERT_WEBHOOK_URL` to Ntfy, Slack, Discord, n8n, etc. The service POSTs JSON at most once per hour per alert type when re-authorization or secret expiry is needed.

**Do not commit webhook URLs** — keep them in `stack.env` only.
