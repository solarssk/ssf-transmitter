# Upgrading

## v0.6.0 — Validated Apple SCIM and SSF integration (from 0.5.19)

[Release notes for v0.6.0](https://github.com/solarssk/ssf-transmitter/releases/tag/v0.6.0)

1. Back up `/app/data` and `/app/keys`. Preserve existing secrets, the signing key, and encryption settings. Do not add or rotate `SSF_TOKEN_ENCRYPTION_KEY` during this upgrade; if unset, preserve `SSF_MANAGEMENT_TOKEN` as the encryption-key source.
2. Pin the image to `0.6.0`, pull, and restart the service:

   ```bash
   docker compose pull ssf-transmitter
   docker compose up -d ssf-transmitter
   docker compose logs ssf-transmitter --tail 50
   ```

3. Check startup, authenticated `GET /ssf/status`, and `GET /ssf/delivery/status`. Keep one container/worker for the integration. No database migration or new required environment variables are needed from 0.5.19.
4. Inspect Apple SCIM sync results: upstream 401/403/429 now stop the cycle; partial/failed status, skipped counts, and stop reasons must not be treated as success. Honor the shared `Retry-After` cooldown. Duplicate source identities stop writes; correct the source instead of bypassing validation. Apple-managed email changes use `userName` when Apple omits `emails`.
5. Verify the issuer expected by your Apple connection using [Apple SSF validation](Apple-SSF-Validation.md). Only if required, configure `SSF_ISSUER` to that exact issuer (including its trailing slash) and `SSF_ALLOW_CUSTOM_ISSUER=true`. Keep `SSF_BASE_URL` and public SSF routes unchanged. An issuer correction affects newly signed SETs; retries retain old claims. Review blocked events individually before retrying, discarding, or regenerating them.
6. Confirm a normal scheduled SCIM cycle and delivery of a fresh event for a dedicated test account. A live test prompted reauthentication on an iPhone; iCloud.com retained its browser session. Do not promise immediate logout of all Apple sessions.

For versions before 0.5.19, review the historical changes in [CHANGELOG.md](../CHANGELOG.md), especially the encrypted outbox and webhook response changes introduced in 0.5.17.

## Rollback

Stop the service, retain a backup of the current SQLite data, keys, and configuration, then restore the previous image tag (`0.5.19`). Keep the same data and encryption-key source. Restoring an older database backup loses events accepted after that backup. A rollback restores the previous SCIM behavior, including its known email-update and error-reporting limitations. Do not downgrade below 0.5.17 with queued deliveries: those versions do not deliver the outbox.
