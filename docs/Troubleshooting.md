# Troubleshooting

## Startup / preflight

### Container exits immediately / restarts loop

Preflight failed on a **critical** check (`❌`). Read logs:

```bash
docker compose logs ssf-transmitter --tail 100
```

(Compose service name is `ssf-transmitter`; container name is `authentik-ssf` — either works with `docker logs authentik-ssf`.)

Common causes:

| Log message | Fix |
|---|---|
| `SSF_ISSUER` / `SSF_BASE_URL` not HTTPS | Use `https://` URLs |
| `SSF_MANAGEMENT_TOKEN too short` | Min 32 characters |
| `SSF_WEBHOOK_TOKEN` missing in bearer mode | Set token or switch mode |
| Database not writable | Fix volume permissions on `/app/data` |

Undecryptable receiver tokens produce `⚠️` and **pause** streams — startup continues.

### `undecryptable endpoint tokens and were paused`

You rotated `SSF_MANAGEMENT_TOKEN` or added `SSF_TOKEN_ENCRYPTION_KEY` after the stream was created.

1. Get a new receiver token from your SSF receiver (ABM).
2. `PATCH /ssf/streams` with `delivery.endpoint_url_token` and `status: enabled`.
3. Example body:

```json
{
  "status": "enabled",
  "delivery": {
    "endpoint_url": "https://receiver.example.com/sets",
    "endpoint_url_token": "<new receiver token>"
  }
}
```
4. Or delete and re-create the stream.

## Stream / delivery

### `GET /ssf/status` returns `"disabled"`

No stream configured. Register via `POST /ssf/streams` or ABM onboarding.

### Stream `paused` after PATCH

Since v0.5.9 you cannot set `status: enabled` without a valid receiver token. Supply `delivery.endpoint_url_token` in the same PATCH.

### Events not reaching Apple / receiver

1. Check stream status is `enabled`.
2. Check Authentik webhook fires (test notification).
3. Check webhook auth: `SSF_WEBHOOK_AUTH_MODE=bearer` and Header Mapping in Authentik.
4. Check logs for `delivered` / `failed` on `POST /webhook/authentik`.
5. Verify receiver URL still passes SSRF validation and allowlist (`SSF_ALLOWED_RECEIVER_HOSTS`).

### `502` on stream create

Verification SET delivery to receiver failed. Stream is rolled back. Check receiver URL, token, and network egress.

## Authentication

### `401` on `/ssf/*`

Missing or malformed `Authorization: Bearer` header.

### `403` on `/ssf/*`

Wrong `SSF_MANAGEMENT_TOKEN`.

### `429` on management API

Rate limit exceeded (failed auth or stream PATCH/create limits). Wait one minute or check if a scanner is hitting the API.

### `401` on `/apple-scim/status` (v0.5.9+)

This endpoint now requires management Bearer token:

```bash
curl -H "Authorization: Bearer $SSF_MANAGEMENT_TOKEN" \
  https://idp.example.com/shared-signals/apple-scim/status
```

OAuth `/apple-scim/authorize` and `/callback` remain public.

## Webhook

### Authentik webhook returns 401

- **Bearer mode:** Header Mapping must send `Authorization: Bearer <SSF_WEBHOOK_TOKEN>`.
- **HMAC mode:** `SSF_WEBHOOK_AUTH_MODE=hmac` and matching `SSF_WEBHOOK_SECRET`.

### Events ignored (`unmapped_event`)

Authentik action has no SSF mapping. See [Event-Mapping.md](Event-Mapping.md).

## Proxy / networking

### Wrong client IP in logs / rate limits affect all users

Set `SSF_FORWARDED_ALLOW_IPS` to your reverse proxy subnet. Default `127.0.0.1` ignores `X-Forwarded-For` from NPM.

### 404 on public URLs

Check `SSF_ROOT_PATH` matches nginx location (`/shared-signals`) and `SSF_BASE_URL` includes the same path.

## Apple SCIM

### SCIM sync not running

All of `APPLE_SCIM_CLIENT_ID`, `APPLE_SCIM_CLIENT_SECRET`, `AUTHENTIK_URL`, `AUTHENTIK_TOKEN` must be set.

### 409 / duplicate users

See changelog for 409 recovery rules. Use `APPLE_SCIM_GROUP_ID` to limit scope.

## Health checks

```bash
curl -s https://idp.example.com/shared-signals/.well-known/ssf-configuration | jq .
curl -s -H "Authorization: Bearer $SSF_MANAGEMENT_TOKEN" \
  https://idp.example.com/shared-signals/ssf/status | jq .
```
