"""Property-based tests for app.events.mapper.

Authentik webhook payloads are attacker-influenceable in shape (a compromised
or misbehaving Authentik instance, a proxy that mangles the body, ...) even
though the transport is authenticated. The one invariant that actually
matters here — more than any specific mapping — is that malformed input
never crashes the webhook handler: every extractor function must handle
arbitrary JSON-shaped input and either return a sensible value or an empty
result, never raise.
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from app.events.mapper import (
    CREDENTIAL_CHANGE,
    SESSION_REVOKED,
    extract_action,
    extract_email,
    extract_source_txn,
    map_authentik_event,
)

# A recursive JSON-like value strategy: arbitrary nesting of the shapes a
# webhook body could plausibly contain, including the "wrong type entirely"
# cases (a list where a dict is expected, a number where a string is
# expected, ...) that are exactly what a fuzzer/property test is for.
_json_value = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats(allow_nan=False) | st.text() | st.binary(),
    lambda children: st.lists(children, max_size=5) | st.dictionaries(st.text(), children, max_size=5),
    max_leaves=20,
)

arbitrary_payload = st.dictionaries(st.text(min_size=1, max_size=20), _json_value, max_size=10)


@given(payload=arbitrary_payload)
@settings(deadline=None)
def test_map_authentik_event_never_raises(payload: dict):
    result = map_authentik_event(payload)
    assert isinstance(result, list)


@given(payload=arbitrary_payload)
@settings(deadline=None)
def test_extract_email_never_raises(payload: dict):
    result = extract_email(payload)
    assert result is None or isinstance(result, str)


@given(payload=arbitrary_payload)
@settings(deadline=None)
def test_extract_action_never_raises(payload: dict):
    extract_action(payload)  # no return-type contract beyond "doesn't raise"


@given(payload=arbitrary_payload)
@settings(deadline=None)
def test_extract_source_txn_never_raises(payload: dict):
    result = extract_source_txn(payload)
    assert result is None or isinstance(result, (str, int, float))


# ---------------------------------------------------------------------------
# Targeted structural fuzzing: right shape, wrong value types
# ---------------------------------------------------------------------------


@given(
    action=st.one_of(st.text(), st.none(), st.integers(), st.lists(st.text())),
    changed_fields=st.one_of(st.lists(st.text()), st.none(), st.text(), st.dictionaries(st.text(), st.text())),
)
@settings(deadline=None)
def test_user_write_with_arbitrary_changed_fields_never_raises(action, changed_fields):
    payload = {
        "body": {
            "action": action,
            "context": {"changed_fields": changed_fields},
        }
    }
    result = map_authentik_event(payload)
    assert isinstance(result, list)


@given(email=st.one_of(st.text(), st.none(), st.integers(), st.binary(), st.lists(st.text())))
@settings(deadline=None)
def test_extract_email_with_arbitrary_value_type_never_raises(email):
    result = extract_email({"body": {"user": {"email": email}}})
    assert result is None or isinstance(result, str)


# ---------------------------------------------------------------------------
# Reserved keys holding the wrong JSON type entirely
#
# arbitrary_payload's dict-of-arbitrary-keys strategy essentially never
# generates the *literal* key "body" (or "context", "user") by chance —
# across the whole random text space, hitting one exact 4-character string is
# vanishingly unlikely. So the "never raises" tests above never actually
# exercise {"body": <not-a-dict>}, even though that's exactly the shape a
# misbehaving Authentik instance or a mangling proxy could send, and it's
# what map_authentik_event/extract_* call .get() on directly. Target these
# reserved keys explicitly instead of hoping the fuzzer stumbles onto them.
# ---------------------------------------------------------------------------

_wrong_type_leaf = st.one_of(
    st.integers(),
    st.floats(allow_nan=False, allow_infinity=False),
    st.text(min_size=1),
    st.booleans(),
    st.lists(st.text(), min_size=1, max_size=3),
)


@given(body=_wrong_type_leaf)
@settings(deadline=None)
def test_body_key_with_wrong_type_never_raises(body):
    payload = {"body": body}
    assert isinstance(map_authentik_event(payload), list)
    email = extract_email(payload)
    assert email is None or isinstance(email, str)
    extract_action(payload)
    txn = extract_source_txn(payload)
    assert txn is None or isinstance(txn, (str, int, float))


@given(context=_wrong_type_leaf)
@settings(deadline=None)
def test_context_key_with_wrong_type_never_raises(context):
    payload = {"body": {"action": "authentik.core.user.write", "context": context}}
    assert isinstance(map_authentik_event(payload), list)


@given(user=_wrong_type_leaf)
@settings(deadline=None)
def test_user_key_with_wrong_type_never_raises(user):
    result = extract_email({"body": {"user": user}})
    assert result is None or isinstance(result, str)


@given(changed_fields=_wrong_type_leaf)
@settings(deadline=None)
def test_changed_fields_key_with_wrong_type_never_raises(changed_fields):
    payload = {"body": {"action": "authentik.core.user.write", "context": {"changed_fields": changed_fields}}}
    assert isinstance(map_authentik_event(payload), list)


# ---------------------------------------------------------------------------
# Well-formed inputs: the actual mapping contract
# ---------------------------------------------------------------------------


@given(txn=st.text(min_size=1, max_size=64))
def test_logout_always_maps_to_exactly_one_session_revoked_event(txn: str):
    payload = {"body": {"action": "authentik.core.auth.logout", "pk": txn}}
    events = map_authentik_event(payload)
    assert len(events) == 1
    assert events[0].uri == SESSION_REVOKED
    assert events[0].txn == txn


@given(other_fields=st.lists(st.text(min_size=1, max_size=20), max_size=5))
def test_password_change_always_maps_to_credential_change_event(other_fields: list[str]):
    changed_fields = ["password", *other_fields]
    payload = {"body": {"action": "authentik.core.user.write", "context": {"changed_fields": changed_fields}}}
    events = map_authentik_event(payload)
    assert any(e.uri == CREDENTIAL_CHANGE for e in events)


@given(email=st.emails())
def test_valid_email_is_extracted_and_normalized(email: str):
    padded = f"  {email}  "
    assert extract_email({"body": {"user": {"email": padded}}}) == email
