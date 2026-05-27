# API Reference

All endpoints are served under `SSF_BASE_URL` (e.g. `https://idp.example.com/shared-signals`).
The service is typically deployed behind a reverse proxy that handles TLS.

---

## Discovery

### `GET /.well-known/ssf-configuration`

Returns the SSF transmitter metadata document. Used by receivers to auto-configure the stream endpoint and JWKS URI.

**Response**
```json
{
  "issuer": "https://idp.example.com/application/o/apple-id/",
  "jwks_uri": "https://idp.example.com/shared-signals/jwks.json",
  "delivery_methods_supported": [
    "https://schemas.openid.net/secevent/risc/delivery-method/push"
  ],
  "configuration_endpoint": "https://idp.example.com/shared-signals/ssf/streams",
  "add_subject_endpoint": "https://idp.example.com/shared-signals/ssf/streams/subjects:add",
  "remove_subject_endpoint": "https://idp.example.com/shared-signals/ssf/streams/subjects:remove",
  "status_endpoint": "https://idp.example.com/shared-signals/ssf/status",
  "supported_scopes": ["openid"],
  "critical_subject_members": [],
  "spec_version": "1_0-ID2"
}
```

---

### `GET /jwks.json`

Returns the public JWKS used to verify RS256-signed SET JWTs issued by this service.

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

The service supports one active stream at a time. Creating a new stream replaces any existing one.

### `POST /ssf/streams`

Creates a stream. The receiver calls this endpoint to register its push delivery URL and token.

**Request body** (fields accepted by this implementation):

| Field | Required | Notes |
|---|---|---|
| `delivery.endpoint_url` | Yes | URL where SETs will be pushed |
| `delivery.endpoint_url_token` | Yes | Bearer token included in SET push requests |
| `aud` | Yes | Audience value used in JWT claims. Also accepted as `audience`, `receiver`, or `iss` |
| `events_requested` | No | List of event URIs the receiver wants. Stored but not filtered on |
| `stream_id` | No | Custom ID; auto-generated UUID if omitted |

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
  "stream_id": "550e8400-e29b-41d4-a716-446655440000",
  "aud": "https://receiver.example.com",
  "delivery": {
    "method": "https://schemas.openid.net/secevent/risc/delivery-method/push",
    "endpoint_url": "https://receiver.example.com/sets"
  },
  "events_requested": ["https://schemas.openid.net/secevent/caep/event-type/session-revoked"],
  "status": "enabled",
  "created_at": 1716800000
}
```

> The `endpoint_url_token` is never returned in responses.

---

### `GET /ssf/streams`

Returns the current stream configuration.

**Response** `200 OK` — same shape as POST response.
**Response** `404 Not Found` — if no stream is configured.

---

### `PATCH /ssf/streams`

Updates fields on the existing stream. Accepts the same fields as POST; omitted fields retain their current values.

**Response** `200 OK` — updated stream.
**Response** `404 Not Found` — if no stream is configured.

---

### `DELETE /ssf/streams`

Removes the current stream. No body.

**Response** `204 No Content`

---

### `POST /ssf/streams/subjects:add`

Acknowledges subject registration. Logs the request and returns `{"status": "ok"}`.
The service does not filter events by subject — all Authentik events are forwarded to the active stream.

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

## Webhook Receiver

### `POST /webhook/authentik`

Receives event notifications from Authentik. This endpoint is called by Authentik, not by SSF receivers.

**Headers**

| Header | Required | Value |
|---|---|---|
| `X-Authentik-Signature` | Yes | `sha256=<HMAC-SHA256 hex of raw body>` |
| `Content-Type` | Yes | `application/json` |

**Authentication**: HMAC-SHA256 signature verified against `SSF_WEBHOOK_SECRET`. Requests with missing or invalid signatures are rejected with `401 Unauthorized`.

**Response** `200 OK`
```json
{ "status": "ok", "delivered": 1, "failed": 0 }
```

Possible `status` values when no SET is delivered:
- `"ignored"` with `"reason": "unmapped_event"` — event has no SSF mapping
- `"ignored"` with `"reason": "missing_email"` — event has no user email
- `"ignored"` with `"reason": "no_enabled_stream"` — no active stream to deliver to
