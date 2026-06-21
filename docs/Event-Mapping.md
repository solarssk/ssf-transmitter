# Event Mapping

Authentik sends webhook notifications to `POST /webhook/authentik`. The transmitter maps supported actions to SSF Security Event Tokens (SETs) and pushes them to the active stream receiver.

## Supported mappings

| Authentik event | SSF event URI |
|---|---|
| `authentik.core.auth.logout` | `https://schemas.openid.net/secevent/caep/event-type/session-revoked` |
| Password change (via `authentik.core.user.write`) | `https://schemas.openid.net/secevent/caep/event-type/credential-change` |
| User deactivated | `https://schemas.openid.net/secevent/risc/event-type/account-disabled` |
| User reactivated | `https://schemas.openid.net/secevent/risc/event-type/account-enabled` |
| User deleted | `https://schemas.openid.net/secevent/risc/event-type/account-purged` |

Legacy `caep/event-type/account-*` URIs in `events_requested` are canonicalized to `risc/event-type/*`.

## Ignored events

| Response | Reason |
|---|---|
| `{"status":"ignored","reason":"unmapped_event"}` | Action not mapped (e.g. `login_failed`) |
| `{"status":"ignored","reason":"missing_email"}` | User has no email |
| `{"status":"ignored","reason":"no_enabled_stream"}` | No active stream |

## Authentik configuration

**Notification transport:** Generic Webhook

- URL: `http://authentik-ssf:8000/webhook/authentik` (internal Docker DNS)
- Header Mapping: `Authorization: Bearer <SSF_WEBHOOK_TOKEN>`

**Subscribe to:**

- `authentik.core.auth.logout`
- `authentik.core.user.write`
- `authentik.core.user.delete`

## SET structure

- Signed RS256 JWT (`typ: secevent+jwt`)
- `iss` = `SSF_ISSUER`
- `sub_id` = `{"format":"email","email":"<user>"}` for Authentik events
- RISC lifecycle events use empty `{}` in `events` body; identity is in `sub_id` only

Full API details: [API.md](API.md)
