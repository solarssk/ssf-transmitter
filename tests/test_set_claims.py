"""SSF 1.0 SET claims conformance tests.

Decodes generated JWTs without verifying the signature and asserts that
all required claims match the final SSF Framework 1.0 specification.
"""

from __future__ import annotations

import base64
import json

from fastapi.testclient import TestClient

from app.crypto import sign_set, sign_verification_set


def _decode_payload(token: str) -> dict:
    """Base64url-decode the JWT payload without signature verification."""
    parts = token.split(".")
    assert len(parts) == 3, "Expected a 3-part JWT"
    padded = parts[1] + "=" * (-len(parts[1]) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


def _decode_header(token: str) -> dict:
    parts = token.split(".")
    padded = parts[0] + "=" * (-len(parts[0]) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


EVENT_URI = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
AUDIENCE = "apple-business-manager"
EMAIL = "user@example.com"
STREAM_ID = "stream-abc-123"


# ---------------------------------------------------------------------------
# sign_set — regular event SET
# ---------------------------------------------------------------------------


def test_set_header_typ_is_secevent_jwt():
    token = sign_set(event_uri=EVENT_URI, audience=AUDIENCE, email=EMAIL)
    assert _decode_header(token)["typ"] == "secevent+jwt"


def test_set_header_alg_is_rs256():
    token = sign_set(event_uri=EVENT_URI, audience=AUDIENCE, email=EMAIL)
    assert _decode_header(token)["alg"] == "RS256"


def test_set_header_kid_present():
    token = sign_set(event_uri=EVENT_URI, audience=AUDIENCE, email=EMAIL)
    assert _decode_header(token).get("kid")


def test_set_payload_iss_matches_config():
    from app.config import settings
    token = sign_set(event_uri=EVENT_URI, audience=AUDIENCE, email=EMAIL)
    assert _decode_payload(token)["iss"] == settings.ssf_issuer


def test_set_payload_iat_present():
    token = sign_set(event_uri=EVENT_URI, audience=AUDIENCE, email=EMAIL)
    assert isinstance(_decode_payload(token).get("iat"), int)


def test_set_payload_jti_present_and_unique():
    t1 = sign_set(event_uri=EVENT_URI, audience=AUDIENCE, email=EMAIL)
    t2 = sign_set(event_uri=EVENT_URI, audience=AUDIENCE, email=EMAIL)
    assert _decode_payload(t1)["jti"]
    assert _decode_payload(t1)["jti"] != _decode_payload(t2)["jti"]


def test_set_payload_aud_is_list_with_correct_value():
    token = sign_set(event_uri=EVENT_URI, audience=AUDIENCE, email=EMAIL)
    aud = _decode_payload(token)["aud"]
    assert isinstance(aud, list)
    assert aud == [AUDIENCE]


def test_set_payload_top_level_sub_id_present():
    """SSF 1.0 requires sub_id at the top level of the payload."""
    token = sign_set(event_uri=EVENT_URI, audience=AUDIENCE, email=EMAIL)
    sub_id = _decode_payload(token).get("sub_id")
    assert sub_id is not None, "sub_id missing from SET payload"


def test_set_payload_sub_id_format_is_email():
    token = sign_set(event_uri=EVENT_URI, audience=AUDIENCE, email=EMAIL)
    sub_id = _decode_payload(token)["sub_id"]
    assert sub_id["format"] == "email"


def test_set_payload_sub_id_email_matches_input():
    token = sign_set(event_uri=EVENT_URI, audience=AUDIENCE, email=EMAIL)
    assert _decode_payload(token)["sub_id"]["email"] == EMAIL


def test_set_payload_events_contains_event_uri():
    token = sign_set(event_uri=EVENT_URI, audience=AUDIENCE, email=EMAIL)
    assert EVENT_URI in _decode_payload(token)["events"]


def test_set_payload_no_exp_claim():
    """SETs must not carry an exp claim per SSF 1.0."""
    token = sign_set(event_uri=EVENT_URI, audience=AUDIENCE, email=EMAIL)
    assert "exp" not in _decode_payload(token)


def test_set_payload_no_sub_claim():
    """The sub claim is not used; sub_id is the correct field."""
    token = sign_set(event_uri=EVENT_URI, audience=AUDIENCE, email=EMAIL)
    assert "sub" not in _decode_payload(token)


# ---------------------------------------------------------------------------
# sign_verification_set
# ---------------------------------------------------------------------------


def test_verification_set_header_typ():
    token = sign_verification_set(audience=AUDIENCE, stream_id=STREAM_ID)
    assert _decode_header(token)["typ"] == "secevent+jwt"


def test_verification_set_sub_id_format_opaque():
    token = sign_verification_set(audience=AUDIENCE, stream_id=STREAM_ID)
    sub_id = _decode_payload(token)["sub_id"]
    assert sub_id["format"] == "opaque"
    assert sub_id["id"] == STREAM_ID


def test_verification_set_no_exp():
    token = sign_verification_set(audience=AUDIENCE, stream_id=STREAM_ID)
    assert "exp" not in _decode_payload(token)


def test_verification_set_no_sub():
    token = sign_verification_set(audience=AUDIENCE, stream_id=STREAM_ID)
    assert "sub" not in _decode_payload(token)


# ---------------------------------------------------------------------------
# Well-known metadata
# ---------------------------------------------------------------------------


def test_wellknown_spec_version_is_final():
    from app.main import app
    with TestClient(app) as client:
        resp = client.get("/.well-known/ssf-configuration")
    assert resp.status_code == 200
    assert resp.json()["spec_version"] == "1_0"


def test_wellknown_delivery_method_is_rfc8935():
    from app.main import app
    with TestClient(app) as client:
        resp = client.get("/.well-known/ssf-configuration")
    assert "urn:ietf:rfc:8935" in resp.json()["delivery_methods_supported"]


# ---------------------------------------------------------------------------
# txn claim
# ---------------------------------------------------------------------------


def test_set_payload_txn_present():
    token = sign_set(event_uri=EVENT_URI, audience=AUDIENCE, email=EMAIL)
    assert "txn" in _decode_payload(token)


def test_set_payload_txn_uses_provided_value():
    token = sign_set(event_uri=EVENT_URI, audience=AUDIENCE, email=EMAIL, txn="my-txn-value")
    assert _decode_payload(token)["txn"] == "my-txn-value"


def test_set_payload_txn_defaults_to_uuid_when_not_provided():
    import uuid
    token = sign_set(event_uri=EVENT_URI, audience=AUDIENCE, email=EMAIL)
    txn = _decode_payload(token)["txn"]
    uuid.UUID(txn)  # raises ValueError if not a valid UUID


# ---------------------------------------------------------------------------
# event_payload claim
# ---------------------------------------------------------------------------


def test_set_payload_event_body_is_empty_dict_by_default():
    token = sign_set(event_uri=EVENT_URI, audience=AUDIENCE, email=EMAIL)
    events = _decode_payload(token)["events"]
    assert events[EVENT_URI] == {}


def test_risc_account_purged_has_empty_event_body_and_top_level_sub_id():
    uri = "https://schemas.openid.net/secevent/risc/event-type/account-purged"
    token = sign_set(event_uri=uri, audience=AUDIENCE, email=EMAIL, event_payload={})
    payload = _decode_payload(token)
    assert payload["events"][uri] == {}
    assert payload["sub_id"] == {"format": "email", "email": EMAIL}


def test_set_payload_event_body_contains_provided_payload():
    ep = {"event_timestamp": 1234567890, "initiating_entity": "policy",
          "reason_admin": {"en": "Test"}}
    token = sign_set(event_uri=EVENT_URI, audience=AUDIENCE, email=EMAIL, event_payload=ep)
    assert _decode_payload(token)["events"][EVENT_URI] == ep


def test_sign_set_mutable_default_not_shared_between_calls():
    """sign_set must not mutate a caller-supplied mutable payload dict."""
    original = {"event_timestamp": 12345}
    snapshot = dict(original)
    sign_set(event_uri=EVENT_URI, audience=AUDIENCE, email=EMAIL, event_payload=original)
    assert original == snapshot, "sign_set must not modify the caller's event_payload dict"

    # Calling twice with the same dict must not cause cross-call contamination
    t2 = sign_set(event_uri=EVENT_URI, audience=AUDIENCE, email=EMAIL, event_payload=original)
    assert _decode_payload(t2)["events"][EVENT_URI] == snapshot


# ---------------------------------------------------------------------------
# Log redaction — no JWT in logs
# ---------------------------------------------------------------------------


def test_verification_jwt_not_logged(caplog):
    """The full verification SET JWT must never appear in logs (debug log removed).

    Exercises the real push_verification_set code path with a mocked HTTP
    client so that any accidental re-introduction of ``logger.debug(token)``
    would be caught inside the capture scope.
    """
    import asyncio
    import logging
    from unittest.mock import AsyncMock, MagicMock, patch

    from app.database import Stream
    from app.events.pusher import push_verification_set

    async def run_test():
        stream = Stream(
            stream_id=STREAM_ID,
            aud=AUDIENCE,
            endpoint_url="https://receiver.example.test/events",
            endpoint_token="tok",
            events_requested=[],
            status="enabled",
            created_at=0,
        )

        mock_response = MagicMock()
        mock_response.status_code = 200

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        mock_client.post = AsyncMock(return_value=mock_response)

        with caplog.at_level(logging.DEBUG), patch(
            "app.events.pusher.httpx.AsyncClient", return_value=mock_client
        ), patch("app.events.pusher._revalidate_endpoint", return_value=True):
            result = await push_verification_set(stream)

        assert result is True

    asyncio.run(run_test())

    # JWT header is a stable base64 fingerprint — must not appear anywhere in logs
    token = sign_verification_set(audience=AUDIENCE, stream_id=STREAM_ID)
    assert token.split(".")[0] not in caplog.text
