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

    with caplog.at_level(logging.DEBUG):
        with patch("app.events.pusher.httpx.AsyncClient", return_value=mock_client):
            result = asyncio.get_event_loop().run_until_complete(push_verification_set(stream))

    assert result is True
    # JWT header is a stable base64 fingerprint — must not appear anywhere in logs
    token = sign_verification_set(audience=AUDIENCE, stream_id=STREAM_ID)
    assert token.split(".")[0] not in caplog.text
