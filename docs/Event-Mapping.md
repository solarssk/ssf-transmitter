# Event Mapping

Authentik sends webhook notifications to `POST /webhook/authentik`. The transmitter maps supported actions to SSF Security Event Tokens (SETs) and pushes them to the active stream receiver.

## Currently emitted (v0.5.9)

| Authentik event | SSF event URI |
|---|---|
| `authentik.core.auth.logout` | `https://schemas.openid.net/secevent/caep/event-type/session-revoked` |
| Password change (`authentik.core.user.write` with `password` in `changed_fields`) | `https://schemas.openid.net/secevent/caep/event-type/credential-change` |

These match `app/models.py::SUPPORTED_EVENT_URIS` (excluding verification, which is sent only during stream registration).

## Received but not emitted

The webhook may receive these Authentik actions, but **no SET is produced** (`app/events/mapper.py` logs and returns an empty list):

| Authentik event | Behaviour |
|---|---|
| `authentik.core.user.delete` | Skipped (`event_not_supported`) |
| `authentik.core.user.write` with `is_active` in `changed_fields` | Skipped (`event_not_supported`) |
| `authentik.core.auth.login_failed` | Skipped |
| Other unmapped actions | Logged as unmapped; no SET |

Do **not** subscribe to `authentik.core.user.delete` expecting account-purged delivery. RISC lifecycle URIs (`account-disabled`, `account-enabled`, `account-purged`) are **not** in `SUPPORTED_EVENT_URIS` and cannot be requested in `events_requested`.

## Webhook responses

| Response | Reason |
|---|---|
| `{"status":"ignored","reason":"unmapped_event"}` | Action not mapped (e.g. `user.delete`, `is_active` change) |
| `{"status":"ignored","reason":"missing_email"}` | User has no email |
| `{"status":"ignored","reason":"no_enabled_stream"}` | No active stream configured |

## Authentik configuration

**Notification transport:** Generic Webhook

- URL: `http://authentik-ssf:8000/webhook/authentik` (internal Docker DNS)
- Header Mapping: `Authorization: Bearer <SSF_WEBHOOK_TOKEN>`

**Subscribe to:**

- `authentik.core.auth.logout`
- `authentik.core.user.write` (password changes only; `is_active` changes are ignored)

## SET structure

- Signed RS256 JWT (`typ: secevent+jwt`)
- `iss` = `SSF_ISSUER` (should match `SSF_BASE_URL`)
- `sub_id` = `{"format":"email","email":"<user>"}` for Authentik events
- CAEP events (`session-revoked`, `credential-change`) use an empty `{}` in the `events` body

Full API details: [API.md](API.md)
