# API Reference

All endpoints are served under `SSF_BASE_URL` (e.g. `https://idp.example.com/shared-signals`).
The service is typically deployed behind a reverse proxy that handles TLS.

All management endpoints require `Authorization: Bearer <SSF_MANAGEMENT_TOKEN>`.

Unknown paths return `404` with a JSON or HTML body that points to `/.well-known/ssf-configuration` (content negotiation via `Accept`).

---

## Discovery

### `GET /`

Minimal public service discovery. No authentication required.

Returns HTML when `Accept` includes `text/html` (and not JSON-only); otherwise JSON:

```json
{
  "service": "SSF Transmitter",
  "version": "0.5.10",
  "discovery": "/.well-known/ssf-configuration"
}
```

`version` comes from the `APP_VERSION` environment variable (`dev` when unset; set at Docker image build time).

---

### `GET /.well-known/ssf-configuration`

Returns the SSF transmitter metadata document. Public — no authentication required.

**Response**
```json
{
  "issuer": "https://idp.example.com/shared-signals",
  "jwks_uri": "https://idp.example.com/shared-signals/jwks.json",
  "delivery_methods_supported": [
    "urn:ietf:rfc:8935"
  ],
  "configuration_endpoint": "https://idp.example.com/shared-signals/ssf/streams",
  "add_subject_endpoint": "https://idp.example.com/shared-signals/ssf/streams/subjects:add",
  "remove_subject_endpoint": "https://idp.example.com/shared-signals/ssf/streams/subjects:remove",
  "status_endpoint": "https://idp.example.com/shared-signals/ssf/status",
  "verification_endpoint": "https://idp.example.com/shared-signals/ssf/verification",
  "authorization_schemes": [{"spec_urn": "urn:ietf:rfc:6750"}],
  "critical_subject_members": [],
  "spec_version": "1_0"
}
```

---

### `GET /jwks.json`

Returns the public JWKS used to verify RS256-signed SET JWTs. Public — no authentication required.

**Response**
```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "a1b2c3d4",
      "alg": "RS256",
      "n": "...",
      "e": "AQAB"
    }
  ]
}
```

---

## Stream Management

SSF Transmitter 1.0 supports **one active stream per container**. Registering a new stream replaces the existing stream. Multi-stream support is planned for v1.1.

All stream management endpoints require `Authorization: Bearer <SSF_MANAGEMENT_TOKEN>`.

### `POST /ssf/streams`

Registers an SSF push stream. The receiver calls this to configure where SETs are delivered.

**Request body**

| Field | Required | Notes |
|---|---|---|
| `delivery.endpoint_url` | Yes | HTTPS URL where SETs will be pushed |
| `delivery.endpoint_url_token` | Yes | Bearer token sent in `Authorization` header of each SET push |
| `aud` | Yes | Audience claim in SET JWTs |
| `events_requested` | No | List of event URIs the receiver wants. Empty means all supported events |
| `stream_id` | No | Custom UUID; auto-generated if omitted |

```json
{
  "delivery": {
    "endpoint_url": "https://receiver.example.com/sets",
    "endpoint_url_token": "receiver-bearer-token"
  },
  "aud": "https://receiver.example.com",
  "events_requested": [
    "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
  ]
}
```

**Response** `201 Created`
```json
{
  "iss": "https://idp.example.com/shared-signals",
  "stream_id": "550e8400-e29b-41d4-a716-446655440000",
  "aud": "https://receiver.example.com",
  "delivery": {
    "method": "urn:ietf:rfc:8935",
    "endpoint_url": "https://receiver.example.com/sets"
  },
  "events_supported": [
    "https://schemas.openid.net/secevent/caep/event-type/credential-change",
    "https://schemas.openid.net/secevent/caep/event-type/session-revoked",
    "https://schemas.openid.net/secevent/ssf/event-type/verification"
  ],
  "events_requested": [
    "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
  ],
  "events_delivered": [
    "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
  ],
  "stream_model": "single-stream",
  "status": "enabled",
  "created_at": 1716800000
}
```

> `endpoint_url_token` is never returned in any response.
>
> `events_delivered` reflects what the transmitter will actually push: the intersection of `events_requested` and `events_supported`. If `events_requested` is empty, all supported events are delivered.

---

### `GET /ssf/streams`

Returns the current stream configuration.

**Response** `200 OK` — same shape as POST response.
**Response** `404 Not Found` — no stream configured.

---

### `PATCH /ssf/streams`

Updates the current stream. Accepts the same fields as POST; omitted fields retain their values.

**Response** `200 OK` — updated stream.
**Response** `404 Not Found` — no stream configured.

If the current stream is `paused` because its stored receiver token is undecryptable, setting `status: "enabled"` requires a replacement `delivery.endpoint_url_token` in the same PATCH. When you send a `delivery` block, include `delivery.endpoint_url` as well — the nested PATCH schema still requires it.

---

### `DELETE /ssf/streams`

Deletes the current stream. No body.

**Response** `204 No Content`

---

### `POST /ssf/streams/subjects:add`

Acknowledges subject registration. Returns `{"status": "ok"}` and logs the request.

> Subject filtering is not implemented — all Authentik events are forwarded to the active stream regardless of registered subjects. Subject management is planned for a future release.

---

### `POST /ssf/streams/subjects:remove`

Acknowledges subject removal. Same behaviour as `subjects:add`.

---

### `GET /ssf/status`

Returns the current stream status.

**Response** `200 OK` (stream exists)
```json
{
  "status": "enabled",
  "stream_id": "550e8400-e29b-41d4-a716-446655440000",
  "aud": "https://receiver.example.com",
  "events_requested": []
}
```

**Response** `200 OK` (no stream configured)
```json
{
  "status": "disabled",
  "reason": "no_stream"
}
```

---

## Verification

### `POST /ssf/verification`

Triggers a receiver-initiated verification SET for the current stream.

**Request body** (optional)
```json
{ "state": "optional-opaque-string" }
```

**Response** `202 Accepted` — verification SET delivered.
**Response** `404 Not Found` — no stream configured.
**Response** `502 Bad Gateway` — delivery to receiver failed.

---

## Webhook Receiver

### `POST /webhook/authentik`

Receives event notifications from Authentik. Called by Authentik, not by SSF receivers.

**Authentication** — controlled by `SSF_WEBHOOK_AUTH_MODE`:

| Mode | Header required | Notes |
|---|---|---|
| `bearer` (default) | `Authorization: Bearer <SSF_WEBHOOK_TOKEN>` | Recommended |
| `hmac` (legacy) | `X-Authentik-Signature: sha256=<hex>` | Verified against `SSF_WEBHOOK_SECRET` |
| `unsigned` | None | Dev/lab only — never use in production |

**Response** `200 OK`
```json
{ "status": "ok", "delivered": 1, "failed": 0 }
```

Possible `status` values when no SET is delivered:

| status | reason | Meaning |
|---|---|---|
| `"ignored"` | `"unmapped_event"` | Authentik event has no SSF mapping |
| `"ignored"` | `"missing_email"` | Event has no user email |
| `"ignored"` | `"no_enabled_stream"` | No active stream configured |

---

## Supported event types

| Event URI | Triggered by |
|---|---|
| `https://schemas.openid.net/secevent/ssf/event-type/verification` | Stream registration (`POST /ssf/streams`) |
| `https://schemas.openid.net/secevent/caep/event-type/session-revoked` | Authentik logout |
| `https://schemas.openid.net/secevent/caep/event-type/credential-change` | Password change (`user.write` with `password` in `changed_fields`) |

RISC lifecycle events (`account-disabled`, `account-enabled`, `account-purged`) are **not** supported in v0.5.10 — see [Event-Mapping.md](Event-Mapping.md).

---

## SET JWT structure

Each pushed SET is an RS256 JWT with `typ: secevent+jwt`. Relevant claims:

| Claim | Notes |
|---|---|
| `iss` | `SSF_ISSUER` |
| `aud` | Single-element array with the stream audience |
| `sub_id` | `{"format": "email", "email": "<user>"}` for Authentik-derived events |
| `events` | Map of event URI → event-specific body |

**CAEP** events (`session-revoked`, `credential-change`) use an empty `{}` event body.

Verification SETs use `sub_id` with `format: opaque` (stream UUID) instead.

---

## OpenAPI / Swagger

`GET /docs`, `GET /redoc`, and `GET /openapi.json` are disabled unless `SSF_ENABLE_OPENAPI=true`. Keep the flag `false` on production deployments reachable from untrusted networks.
