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
| `APPLE_SCIM_ALLOW_USERNAME_RECOVERY` | Allow username-only linking of existing Apple accounts without `externalId` (default `false`) — see below |

### Existing Apple accounts

The sync matches existing accounts by Authentik `externalId`. A matching Apple
username alone does not establish ownership: by default, an account without
`externalId` is reported as a conflict and is not created or updated. A
matching username with a different `externalId` is always a conflict, even
when username recovery is enabled. Already linked accounts are unaffected.

To recover unlinked accounts, first verify that **every** matching Apple
account in the configured sync scope belongs to the corresponding Authentik
user. If necessary, restrict the scope with `APPLE_SCIM_GROUP_ID`. Then set
`APPLE_SCIM_ALLOW_USERNAME_RECOVERY=true` and redeploy. This opts in all
matching unlinked accounts in that scope, not one selected account; a
username match alone is not proof of ownership. After the intended links
have been established, set the option back to `false` and redeploy.

The transmitter attempts to write the missing `externalId`, reads the Apple
account back to confirm its identity and linkage, and stops further updates
for that account during the run if either step fails. This recovery flow has
not been verified on a live unlinked Apple account. A failed or ambiguous
lookup is reported rather than used to select the first result.

### `APPLE_SCIM_UPDATE_MODE`

Controls which user fields a sync is allowed to write to Apple. Leave this at
the default unless you have a specific reason to narrow it (e.g. isolating
which field an Apple `400` response is coming from).

| Value | Writes |
|---|---|
| `patch_all` (default) | Only changed syncable fields (`externalId`, `userName`, name, emails, `active`) via `PATCH` |
| `replace_all` | A full `PUT` with `userName`, name, emails and `active`, excluding `externalId` |
| `external_id_only` | Only `externalId` (identity linkage) |
| `emails_only` | Only the email address |
| `username_only` | Only `userName` |

When username-only recovery is explicitly enabled, the sync attempts a
separate `externalId` repair in **every** mode, including the narrow modes.

These modes describe the requests the transmitter attempts, not a fully
verified Apple contract. Apple has rejected a `PATCH` to the whole `name`
attribute, so the default mode sends only changed `name.givenName` and
`name.familyName` subattributes. In a limited live test on one account,
Apple accepted no-op updates to both paths and stored and restored a changed
`givenName`. It also stored and restored a changed `familyName` in a
two-operation request that resent the unchanged `givenName`. Empty values,
multiple changed values in one request, and combinations with other fields
have not yet been verified. The tested Apple tenant did not advertise ETag
support, so a concurrent change to the same field can be overwritten between
the sync's read and write. A `PATCH` to `emails` replaces the whole email
array and may remove additional addresses; `replace_all` can also overwrite
other attributes. Do not probe alternative updates against production
accounts; use an approved, isolated test account and verify the resulting
record.

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

## Concurrent syncs and authorization

Only one full Apple SCIM sync or authorization-code exchange runs at a time.
A scheduled sync waits for an ongoing operation to finish and then fetches
fresh data. A manual sync instead returns HTTP `409` without starting another
run; retry after the current operation finishes. The OAuth callback also returns
`409` if the connection is busy, without exchanging the code. Retry the
callback after the current operation, or start authorization again if Apple's
code or the ten-minute state has expired.

After a successful authorization, the initial sync waits for any operation
already in progress and reads the latest stored token before starting. Token
refresh and authorization-code exchange are also serialized so concurrent
requests do not reuse a rotating refresh token or overwrite newer credentials.
An interrupted token exchange may still require reauthorization if Apple
rotated a token before the replacement was saved.

This coordination is **in-process**, not a distributed lock. The supplied
image explicitly starts one Uvicorn worker, even if `WEB_CONCURRENCY` is set.
Run only one container for this Apple connection; overriding the command to
use multiple workers or running overlapping containers can still cause races.
The lock does not prevent changes by other SCIM clients or administrators.

## Admin endpoints (v0.5.9+)

Require `Authorization: Bearer <SSF_MANAGEMENT_TOKEN>`:

| Endpoint | Purpose |
|---|---|
| `GET /apple-scim/status` | SCIM connection status |
| `POST /apple-scim/sync` | Trigger manual sync |

The sync first reads the Apple user listing. If a page fails, has malformed
pagination or identity metadata, or cannot be reconciled with the other
pages, the sync stops without creating or updating Apple users. Manual sync
returns `502`; automatic sync logs the failure and tries again on the next
scheduled cycle.

In one Apple directory, `startIndex` was one more than the number of returned
users, `itemsPerPage` echoed the requested `count`, and `totalResults` was the
returned count. Changing the requested `startIndex` did not advance the
tested results. For that observed response format, the client does not assume
the initial listing is complete. Before writing any user, it queries Apple
separately for every Authentik `externalId` and `userName`, checks the results
against the initial sample, and reads each matched Apple user by ID. Duplicate
source identities, inconsistent lookup responses, failed preflight requests,
or multiple returned matches stop the sync before user writes. An ownership
conflict is reported and skipped for that account; other accounts may still
sync. The normal SCIM multi-page path is unchanged.

This fallback makes two filtered requests per Authentik user and one request
per distinct matched Apple ID, so larger syncs can take longer. A successful
create also needs follow-up lookups.

The Apple `externalId` retains the Authentik identifier between syncs; the
service does not store a separate local user-to-user mapping. Newly created
users are read back and checked against both filters and the ID returned by
Apple. If this verification fails, the sync reports an error even though Apple
may already have created the account.

**Limitation:** individual lookups rely on Apple returning all matches to each
exact filter. If Apple silently hides a duplicate or an existing match, the
client cannot detect that from the observed metadata alone. The behavior was
checked in a seven-user directory, not a larger one; queries combining multiple
values were rejected, so duplicate-filter behavior has not been verified.
Review the Apple directory for duplicate `externalId` values before enabling
sync. Another actor can also change the directory between reads and writes.

When Apple returns a zero-based username-filter response after a create
conflict, the client checks the candidate against a fresh verified lookup
before considering any account update. Existing `externalId` ownership and
username-recovery rules still apply. Accounts present only in Apple remain
untouched.

An HTTP `200` sync response can still report nonzero `conflicts` or `errors`:
identity mismatches and unlinked accounts requiring review count as conflicts;
failed lookups or unverified links count as errors. Account names are omitted
from the response and masked in logs unless PII logging is explicitly enabled.

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
