# Data Protection Notes (GDPR)

> **Legal basis:** to be confirmed by your organisation's privacy officer or legal team. This
> document captures **design intent**: what the software actually does with personal data, not
> legal advice. The operator (whoever deploys and configures this service) is the data controller
> or processor of record; this document exists to make that determination easier, not to make it.

## What this service does

SSF Transmitter is a stateless bridge: it receives an Authentik webhook, maps it to an SSF
Security Event Token (SET), and pushes the signed SET to one configured receiver (typically Apple
Business Manager). Optionally, it also syncs a user directory from Authentik to Apple via SCIM.
It has no admin UI and no end-user-facing surface. The only "users" of the personal data it
handles are the identity provider (Authentik) on one side and the receiver on the other, both
chosen and operated by whoever deploys this service.

## Data processed

| Field | Purpose | Where it goes | Sensitivity |
|---|---|---|---|
| Email address (webhook path) | Subject identifier (`sub_id.format: email`) in the signed SET pushed for a logout / password-change event | Read from the Authentik webhook body, embedded in the outbound SET, sent to the configured receiver over HTTPS | Personal data |
| Email, name, username (Apple SCIM sync path, optional) | User directory sync: creates/updates the matching SCIM User resource at the receiver | Read from Authentik's user API, sent to Apple's SCIM API over HTTPS | Personal data |
| Pseudonymised email token (`[pii:<sha256[:8]>]`) | Log correlation without exposing the real address | Application logs only (stdout/stderr) | Pseudonymised (see [Logs](#logs)) |

No special-category data (health, biometric, etc.) is processed. No name, address, phone number,
or payment data passes through the webhook/SET path; the optional SCIM sync path may additionally
carry a name and username, whichever fields the receiver's SCIM schema requires.

## Data minimisation

Only the fields required to identify the subject of a security event (webhook path) or to keep a
directory in sync (SCIM path) are read and forwarded. Set `APPLE_SCIM_GROUP_ID` to scope SCIM sync
to a single Authentik group instead of the whole user directory. See
[Apple-SCIM-Sync.md](../Apple-SCIM-Sync.md).

## Legal basis

**Pending confirmation by the deploying organisation.** This service is typically run as internal
identity-provider infrastructure (bridging an organisation's own Authentik instance to its own
chosen receiver), where the applicable legal basis is usually legitimate interest (security event
propagation) or the same basis already covering the underlying Authentik deployment; that
determination belongs to the operator, not this document.

## Logs

- Email addresses are pseudonymised by default (`SSF_LOG_PII=false`): HMAC-SHA256 keyed by
  `SSF_PII_PEPPER` (or, if unset, `SSF_MANAGEMENT_TOKEN`), truncated to 8 hex characters
  (`app/security/pii.py`). The token is consistent per address across log lines but is not
  reversible without the key.
- No receiver tokens, management tokens, or webhook secrets are ever logged, pseudonymised or
  otherwise.
- Set `SSF_LOG_PII=true` only in controlled dev/debug environments, never in production.
- Logs go to stdout/stderr only; this service does not ship logs anywhere itself. Retention of the
  pseudonymised tokens is entirely a function of the operator's own log pipeline (see
  [SECURITY.md](../../SECURITY.md)'s "Deployment requirements").

## Retention

**No personal data is persisted at rest by this service.** The SQLite database
(`app/database.py`) stores only stream/receiver configuration (endpoint URL, encrypted receiver
token, requested event types, status) and Apple SCIM OAuth tokens, never an email address, name,
or other per-user record. A webhook's email address exists in memory only for the duration of
mapping and pushing that one event; the only thing that outlives the request is the pseudonymised
log token described above, whose retention the operator controls.

## Data subject rights

This service holds no queryable store of personal data to run an access or erasure request
against: there is nothing here to export or delete beyond log retention (see
[Logs](#logs)/[Retention](#retention)), since it doesn't persist subject records. A subject access,
correction, or erasure request should be directed to the actual data controller (the organisation
operating Authentik) and, for data already forwarded, to the receiver's own subprocessor
agreement.

## Subprocessors

The only "subprocessor" in this data flow is the SSF receiver or Apple Business Manager the
operator has configured, chosen by the operator, not by this project. This service itself
processes data only in transit and does not introduce any additional third party (no analytics,
no external logging service, no telemetry).

## Hosting

Self-hosted by the operator; no vendor-hosted deployment of this service exists. See
[Deployment.md](../Deployment.md) and [SECURITY.md](../../SECURITY.md) for infrastructure and
trust-boundary detail.
