"""Property-based tests for SET claims building (app.crypto.sign_set /
sign_verification_set).

test_set_claims.py checks the SSF 1.0 conformance contract against one fixed
set of inputs. These tests instead assert that contract holds for the full
space of inputs the functions accept — arbitrary event URIs, audiences,
subject emails, event payload shapes and txn values — since the SET is
built directly from webhook-derived and stream-configuration data (see
app/events/mapper.py and app/routes/streams.py) rather than from a fixed,
trusted template.

Uses the same key material as test_set_claims.py (generated on first app
startup within the test session); no separate key fixture needed.
"""

from __future__ import annotations

import base64
import json

from hypothesis import given, settings
from hypothesis import strategies as st

from app.crypto import sign_set, sign_verification_set

# Each example here signs at least one real RS256/RSA-4096 token (~0.3s in
# this environment — no hardware acceleration). Hypothesis' default 100
# examples would make this file alone take minutes; 15 is still enough to
# exercise the input space (unicode, empty-ish strings, deeply nested event
# payloads, ...) without making every CI run pay for it.
_signing_settings = settings(deadline=None, max_examples=15)


def _decode_payload(token: str) -> dict:
    parts = token.split(".")
    assert len(parts) == 3, "Expected a 3-part JWT"
    padded = parts[1] + "=" * (-len(parts[1]) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


def _decode_header(token: str) -> dict:
    parts = token.split(".")
    padded = parts[0] + "=" * (-len(parts[0]) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


# JSON-safe event payload: arbitrary nesting of what a CAEP/RISC event body
# can actually contain, matching the values app/events/mapper.py produces
# (str/int/float/bool/None, nested dicts and lists).
_json_value = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats(allow_nan=False, allow_infinity=False) | st.text(),
    lambda children: st.lists(children, max_size=3) | st.dictionaries(st.text(), children, max_size=3),
    max_leaves=10,
)
event_payload_strategy = st.dictionaries(st.text(min_size=1, max_size=20), _json_value, max_size=5)

# Realistic-ish string fields: non-empty, no null bytes (JWT claims are text).
_claim_text = st.text(min_size=1, max_size=100).filter(lambda s: "\x00" not in s)


@given(
    event_uri=_claim_text,
    audience=_claim_text,
    email=_claim_text,
    event_payload=event_payload_strategy,
    txn=st.one_of(st.none(), _claim_text),
)
@_signing_settings
def test_sign_set_conforms_to_ssf_contract_for_any_input(event_uri, audience, email, event_payload, txn):
    token = sign_set(event_uri=event_uri, audience=audience, email=email, event_payload=event_payload, txn=txn)

    header = _decode_header(token)
    payload = _decode_payload(token)

    # RFC 8417 §2.3
    assert header["typ"] == "secevent+jwt"
    # RFC 7519 §4.1.3 — aud is always a single-element array, never a bare string
    assert payload["aud"] == [audience]
    # SSF §5.1 — sub_id at top level, format: email
    assert payload["sub_id"] == {"format": "email", "email": email}
    # The event body is keyed by exactly the given event_uri
    assert payload["events"] == {event_uri: event_payload}
    # SSF 1.0 explicitly omits exp and sub
    assert "exp" not in payload
    assert "sub" not in payload
    # txn always present — either the caller's value, or a generated fallback
    assert "txn" in payload
    if txn is not None:
        assert payload["txn"] == txn
    else:
        assert payload["txn"]  # non-empty fallback (a UUID)
    # iss/iat/jti are always populated regardless of input
    assert payload["iss"]
    assert isinstance(payload["iat"], int)
    assert payload["jti"]


@given(event_uri=_claim_text, audience=_claim_text, email=_claim_text)
@_signing_settings
def test_sign_set_with_no_event_payload_defaults_to_empty_object(event_uri, audience, email):
    token = sign_set(event_uri=event_uri, audience=audience, email=email)
    payload = _decode_payload(token)
    assert payload["events"] == {event_uri: {}}


@given(audience=_claim_text, stream_id=_claim_text, state=st.one_of(st.none(), _claim_text))
@_signing_settings
def test_sign_verification_set_conforms_to_ssf_contract_for_any_input(audience, stream_id, state):
    token = sign_verification_set(audience=audience, stream_id=stream_id, state=state)

    header = _decode_header(token)
    payload = _decode_payload(token)

    assert header["typ"] == "secevent+jwt"
    assert payload["aud"] == [audience]
    # SSF §5.1 — verification events use format: opaque with the stream id
    assert payload["sub_id"] == {"format": "opaque", "id": stream_id}
    assert "exp" not in payload
    assert "sub" not in payload

    event_body = payload["events"]["https://schemas.openid.net/secevent/ssf/event-type/verification"]
    if state is not None:
        assert event_body == {"state": state}
    else:
        # RFC 8417: transmitter-initiated verification SHOULD omit state.
        assert "state" not in event_body


@given(event_uri=_claim_text, audience=_claim_text, email=_claim_text)
@settings(deadline=None, max_examples=10)  # 2 signs/example; this only needs a handful of samples
def test_sign_set_jti_is_unique_per_call(event_uri, audience, email):
    """Same inputs, called twice, must never produce the same jti (replay/dedup safety)."""
    token1 = sign_set(event_uri=event_uri, audience=audience, email=email)
    token2 = sign_set(event_uri=event_uri, audience=audience, email=email)
    assert _decode_payload(token1)["jti"] != _decode_payload(token2)["jti"]
