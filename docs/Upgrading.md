# Upgrading

## v0.6.1 — Account-disablement policy (from 0.6.0)

[Release notes for v0.6.1](https://github.com/solarssk/ssf-transmitter/releases/tag/v0.6.1)

This release stops ordinary Authentik logout from requesting Apple-wide session revocation. To deliver account-disablement and password-change events from native Authentik notifications, update both the service and its external webhook mapping.

### Preserve data and review queued events

Back up `/app/data`, `/app/keys`, and your environment configuration. Preserve the issuer, public base URL, signing keys, receiver token, and encryption settings.

- Do not add or rotate `SSF_TOKEN_ENCRYPTION_KEY` during this upgrade.
- If that key is unset, preserve `SSF_MANAGEMENT_TOKEN`: it supplies the encryption-key source.
- Check authenticated `GET /ssf/delivery/status` before redeploying. Existing queued JWTs retain their original event and claims; the new mapping does not rewrite them. Review any old logout events before allowing them to deliver. Use [queue controls](API.md#get-ssfdeliverystatus) only after deciding which stored events should be retained or discarded.

### Deploy 0.6.1

Pin your image to `0.6.1`, then pull and restart only the SSF service:

```bash
docker compose pull ssf-transmitter
docker compose up -d ssf-transmitter
docker compose logs ssf-transmitter --tail 50
```

Keep one container/worker for the integration. Upgrading from 0.6.0 needs no database migration or new required runtime environment variables.

### Update Authentik event delivery

1. Keep the Generic Webhook transport URL and Authorization header mapping unchanged.
2. Replace the body mapping with [webhook-body.py.txt](../integrations/authentik/webhook-body.py.txt).
3. Subscribe to native `model_updated` events for `authentik_core.user`, plus `user_write` for self-service password changes. Match the notification policies with **any/OR**.
4. Remove the ordinary `logout` subscription. Existing 0.6.0 deployments can do this before the image update to stop global logout requests immediately.
5. Read [Event Mapping](Event-Mapping.md) for target identity, delayed-event behavior, and administrative password-reset limitations. The new image alone does not configure Authentik.

The body mapping looks up the edited account by model ID; the administrator who performed the edit is not the subject. It checks current inactive state rather than reconstructing a historical state transition. Further edits to an inactive account may repeat revocation; a target already re-enabled before processing produces no disablement event.

### Verify after deployment

| Check | Expected result |
|---|---|
| Startup and `GET /ssf/status` | Healthy service and enabled stream |
| Ordinary logout on a dedicated account | No new SSF delivery |
| Disable that account in Authentik | `session-revoked` queued for the disabled user, then accepted by Apple |
| Re-enable the account | No session-revocation SET |
| Self-service password change | `credential-change` for that account |
| Scheduled SCIM sync | Inspect status, errors, conflicts, skipped counts, and delivery queue health |

Check device behavior separately from HTTP 202 acceptance. Earlier tests confirmed an iPhone reauthentication prompt; immediate iCloud.com browser logout is not established. The new native disablement-to-device path requires a dedicated-account live check after wiring the notification rules.

For SCIM deactivation, disable the account while it remains in the sync scope with its email intact. Confirm Apple's state before removing group membership or deleting the source account. See [SCIM operations](Apple-SCIM-Sync.md).

### Repository automation

The AI reviewer and required approvals affect repository maintenance only. They do not change your container configuration or perform a deployment. See [Automated PR review](AI-Review.md).

## Rollback

Stop the service, retain a backup of current data and keys, then restore the previous image tag (`0.6.0`). Preserve the same encryption-key source and SQLite volume. Restoring an older database backup loses events accepted after that backup.

The old image ignores normalized disablement events. Keep ordinary logout unsubscribed during rollback; restoring the old logout mapping restores account-wide revocation on local logout. Do not downgrade below 0.5.17 with queued deliveries: those versions do not deliver the outbox.

For a starting version before 0.6.0, also review [historical changes](../CHANGELOG.md) and [Apple issuer validation](Apple-SSF-Validation.md).
