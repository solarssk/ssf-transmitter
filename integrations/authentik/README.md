# Authentik webhook mapping

Use [webhook-body.py.txt](webhook-body.py.txt) as the Generic Webhook transport's body mapping expression. It is not a standalone Python script: Authentik supplies `notification` and its model API.

1. Follow [Event Mapping](../../docs/Event-Mapping.md) for the supported service version and event subscriptions.
2. Paste the expression into the body mapping. Keep your existing Authorization header mapping separate.
3. Test with a dedicated account. Confirm the disabled target is selected instead of the administrator who edited it.

Ordinary logout is ignored. Native `model_updated` events resolve an inactive target; observed self-service `user_write` password events become credential changes. See the guide for delayed-event limitations and deployment order.

[Mapping regression tests](../../tests/test_authentik_body_mapping.py) check the template with an ORM stand-in. They do not establish native Authentik execution or Apple device behavior.
