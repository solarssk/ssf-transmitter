# Event Mapping

Authentik notifications reach `POST /webhook/authentik`. Supported security events are signed, encrypted in the durable outbox, and delivered asynchronously to the active receiver.

## Account policy

| Normalized webhook | Result |
|---|---|
| `authentik.core.auth.logout` | Ignored: ending a local session must not revoke every Apple device session |
| `authentik.core.user.write`, `is_active` in `context.changed_fields`, `context.is_active` exactly boolean `false` | CAEP `session-revoked` for the affected account |
| `authentik.core.user.write`, `password` in `context.changed_fields` | CAEP `credential-change` |
| Account enabled, missing/ambiguous state, deletion, failed login, unsupported action | No event |

Account disablement revokes sessions; this is not an account-deletion or access-denial protocol. Optional SCIM independently propagates account state. Re-enabling an account does not emit a session-revocation signal. No explicit "revoke all sessions" action is inferred from logout. Password and disablement in one normalized event produce both supported event types.

The subject is the affected user's email. `event.user` can be the administrator who edited another account: never use that administrator as the subject of a target-user disablement.

## Configure Authentik

This policy applies from 0.6.1. The 0.6.0 image maps ordinary logout to session revocation. Remove the logout subscription to stop that behavior before upgrading, then follow [the upgrade procedure](Upgrading.md).

### Install the mapping

1. Keep the Generic Webhook transport URL and its existing Authorization header mapping unchanged.
2. Copy [webhook-body.py.txt](../integrations/authentik/webhook-body.py.txt) into the transport's **body mapping expression**. This is an Authentik expression, not a standalone Python program.
3. Subscribe to native `model_updated` events for `authentik_core.user`, plus native `user_write` for password changes. Remove the ordinary `logout` subscription. A notification rule with multiple event matchers must use **any/OR**, not all/AND.
4. Test the mapping before enabling the rule, using the checks under [Verification](#verification).

### Understand native-event limits

| Native event | What the mapping does | Limit |
|---|---|---|
| `model_updated` for an Authentik user | Resolve `context.model.pk` and emit disablement only if the target is currently inactive | Later edits to an inactive account can repeat revocation. If the target is missing or already re-enabled, no disablement is emitted. |
| `user_write` with `created=false` and a password field | Normalize a password change without forwarding its value | Covers the observed self-service flow. Administrative reset paths may emit different events. |

The mapping observes current state when processed; it does not reconstruct a historical state transition.

### Upgrade an existing mapping

The existing deployment body mapping forwards raw context without `changed_fields`; it must be updated for these native events. Updating only the service image cannot establish the native-event wiring. Older images ignore normalized account disablement, so deploy the updated service before relying on this behavior. Removing logout subscription immediately prevents the old account-wide logout behavior.

### Inspect the normalized webhook

The email below belongs to the disabled target, not the administrator:

```json
{
  "body": {
    "action": "authentik.core.user.write",
    "pk": "source-event-id",
    "user": {"email": "target@example.com"},
    "context": {
      "changed_fields": ["is_active"],
      "is_active": false
    }
  }
}
```

## Verification

Use a dedicated account and verify each operation:

| Operation | Expected result |
|---|---|
| Ordinary logout | `ignored/unmapped_event`; no outbox item, even with an enabled stream |
| Disable account | Queue `session-revoked` for that account |
| Enable account | No session-revocation event |

Check receiver acceptance and the device prompt separately. A live Apple test confirmed device reauthentication; it did not establish iCloud.com browser logout.

## Responses and SETs

- `ignored/unmapped_event`: unsupported or deliberately ignored action.
- `ignored/missing_email`: a mapped event has no usable subject email.
- `ignored/no_enabled_stream`: a mapped event has no active receiver.
- `accepted/queued`: matching events committed to the outbox, not receiver acceptance; zero is possible when filtered.

SETs use RS256, `typ: secevent+jwt`, the configured receiver-expected `iss`, and email `sub_id`. Event bodies include event time, initiating entity and an administrative reason. RISC account lifecycle URIs remain unsupported. See [API.md](API.md) and [Apple issuer validation](Apple-SSF-Validation.md).
