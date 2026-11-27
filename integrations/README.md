# Integration templates

These templates run in external systems, not inside the transmitter container.

- [Authentik webhook body mapping](authentik/README.md): normalize security events and identify the affected account.
- [Event mapping guide](../docs/Event-Mapping.md): configure the transport, subscriptions, and expected outcomes.

Keep secrets in the external system's configuration. The templates contain no production credentials.
