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
