# Upgrading

## v0.6.0 — Validated Apple SCIM and SSF integration (from 0.5.19)

[Release notes for v0.6.0](https://github.com/solarssk/ssf-transmitter/releases/tag/v0.6.0)

### Preserve your data

Back up `/app/data` and `/app/keys`. Preserve the signing key, secrets, and encryption settings.

- Do not add or rotate `SSF_TOKEN_ENCRYPTION_KEY` during this upgrade.
- If that key is unset, preserve `SSF_MANAGEMENT_TOKEN`: it supplies the encryption-key source.

### Deploy 0.6.0

Pin the image to `0.6.0`, then pull and restart the service:

```bash
docker compose pull ssf-transmitter
docker compose up -d ssf-transmitter
docker compose logs ssf-transmitter --tail 50
```

### Verify the service

1. Check startup and authenticated `GET /ssf/status`.
2. Check `GET /ssf/delivery/status` for pending or blocked deliveries.
3. Confirm a normal scheduled SCIM cycle.
4. Test a fresh event with a dedicated account; check receiver acceptance separately from device behavior.

Keep one container/worker for the integration. This upgrade from 0.5.19 needs no database migration or new required variables. A live test prompted reauthentication on an iPhone; iCloud.com retained its browser session.

### Review changes that need operator attention

| Area | What to check |
|---|---|
| SCIM outcomes | HTTP 401/403/429 stops a cycle. Inspect partial/failed status, skipped accounts, and stop reasons. Honor the `Retry-After` cooldown. |
| Source identities | Duplicate source identities stop writes. Correct the source instead of bypassing validation. |
| Apple email updates | When Apple omits `emails`, the sync manages the mapped address through `userName`. |
| Issuer | Verify [Apple's expected issuer](Apple-SSF-Validation.md). Only if needed, set the exact `SSF_ISSUER` (including its trailing slash) and `SSF_ALLOW_CUSTOM_ISSUER=true`. Keep `SSF_BASE_URL` and public routes unchanged. |
| Blocked SETs | Issuer corrections affect newly signed tokens. Retries retain old claims; review blocked events before retrying, discarding, or regenerating them. |

For versions before 0.5.19, review the historical changes in [CHANGELOG.md](../CHANGELOG.md), especially the encrypted outbox and webhook response changes introduced in 0.5.17.

## Rollback

Stop the service, retain a backup of the current SQLite data, keys, and configuration, then restore the previous image tag (`0.5.19`). Keep the same data and encryption-key source. Restoring an older database backup loses events accepted after that backup. A rollback restores the previous SCIM behavior, including its known email-update and error-reporting limitations. Do not downgrade below 0.5.17 with queued deliveries: those versions do not deliver the outbox.
