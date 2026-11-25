# Apple SSF issuer validation

Apple SCIM directory synchronization and SSF event delivery are separate
integrations. A successful SCIM sync, healthy container, or HTTP 200 from JWKS
does not establish that Apple accepts a signed Security Event Token (SET).

## Match the receiver's expected issuer

`SSF_ISSUER` supplies the exact `iss` claim and the issuer advertised by SSF
discovery. `SSF_BASE_URL` supplies this service's public endpoint URLs. They
usually match, but the receiver's registered expectation takes precedence.

In a live test on 2026-11-25, one Apple custom IdP connection rejected a SET
whose issuer was the transmitter base URL with HTTP 400:

```json
{"err":"invalid_issuer","description":"Issuer mismatch"}
```

The same transmitter code and signing key received HTTP 202 after using the
issuer from that connection's Authentik OpenID configuration. Signature
verification against the publicly served transmitter JWKS passed in both
cases. This is a verified result for that connection, not a requirement to
change every deployment to an OIDC issuer.

Read the exact `issuer` from the OpenID configuration document for the
application registered with Apple. Preserve its trailing slash. For example,
if that document publishes `https://idp.example.com/application/o/apple-id/`
and the connection requires that issuer:

```dotenv
SSF_ISSUER=https://idp.example.com/application/o/apple-id/
SSF_ALLOW_CUSTOM_ISSUER=true
SSF_BASE_URL=https://idp.example.com/shared-signals
SSF_ROOT_PATH=/shared-signals
```

`SSF_ALLOW_CUSTOM_ISSUER` suppresses the generic mismatch/OIDC-path startup
warnings. It does not change the token or make an issuer acceptable to Apple.
Keep the service base URL, proxy routing, signing key, and receiver token in
place when correcting only the issuer. After restarting, read public SSF
discovery and verify the advertised issuer and JWKS before testing delivery.

## Verify delivery, not just discovery

On an approved dedicated test account, verify all of the following:

1. Public transmitter JWKS matches the signing key.
2. Apple accepts a verification SET.
3. An authenticated test webhook is queued and its signed SET reaches Apple.
4. Apple returns HTTP 202 and the test queue has no pending or blocked item.

Live validation of main commit `5d17adf` exercised this path with the corrected
issuer in an isolated application and temporary SQLite database. Apple
returned 202 for both verification and `session-revoked`; the queue drained,
and the persisted files contained neither a plaintext subject email nor the
receiver bearer token. The production stream and settings were unchanged by
that isolated test.

A subsequent dedicated-account test on 2026-11-25 confirmed that an iPhone
requested reauthentication after Apple accepted a `session-revoked` SET.
The operator reported that iCloud.com retained its browser session. This
evidence covers device reauthentication, not immediate revocation of every
Apple session. HTTP 202 alone still proves only protocol acceptance.
Do not send logout tests for ordinary production users.

## Existing blocked SETs retain their original issuer

An issuer correction affects newly signed tokens. The queue retries the
original signed JWT, so `POST /ssf/delivery/retry-blocked` cannot repair a
token's `iss` claim. Inspect the rejection and the event's relevance before
deciding whether to discard or regenerate it. Do not clear all blocked items
just because the issuer changed; unrelated failures may also be present.

See [delivery queue operations](API.md#get-ssfdeliverystatus) for inspection,
retry, and discard endpoints. Existing events should be regenerated only
from an authoritative source or an explicitly reviewed operator action.
