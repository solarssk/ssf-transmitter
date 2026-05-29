"""Backward compatibility: legacy caep/ account-* URIs must be canonicalized to risc/."""

from app.models import SUPPORTED_EVENT_URIS, canonicalize_event_uri

LEGACY = {
    "disabled": "https://schemas.openid.net/secevent/caep/event-type/account-disabled",
    "enabled": "https://schemas.openid.net/secevent/caep/event-type/account-enabled",
    "purged": "https://schemas.openid.net/secevent/caep/event-type/account-purged",
}
CANONICAL = {
    "disabled": "https://schemas.openid.net/secevent/risc/event-type/account-disabled",
    "enabled": "https://schemas.openid.net/secevent/risc/event-type/account-enabled",
    "purged": "https://schemas.openid.net/secevent/risc/event-type/account-purged",
}


def test_canonical_risc_uris_are_in_supported_set():
    for uri in CANONICAL.values():
        assert uri in SUPPORTED_EVENT_URIS


def test_legacy_caep_uris_not_in_supported_set():
    for uri in LEGACY.values():
        assert uri not in SUPPORTED_EVENT_URIS


def test_canonicalize_account_disabled():
    assert canonicalize_event_uri(LEGACY["disabled"]) == CANONICAL["disabled"]


def test_canonicalize_account_enabled():
    assert canonicalize_event_uri(LEGACY["enabled"]) == CANONICAL["enabled"]


def test_canonicalize_account_purged():
    assert canonicalize_event_uri(LEGACY["purged"]) == CANONICAL["purged"]


def test_canonicalize_non_legacy_uri_unchanged():
    uri = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
    assert canonicalize_event_uri(uri) == uri


def test_stream_create_accepts_legacy_uri_and_persists_canonical():
    """StreamCreateRequest validator must accept legacy URIs and return canonical ones."""

    from app.models import StreamCreateRequest

    body = {
        "aud": "https://receiver.example.com",
        "delivery": {"endpoint_url": "https://receiver.example.com/events"},
        "events_requested": [LEGACY["disabled"], LEGACY["purged"]],
    }
    req = StreamCreateRequest.model_validate(body)
    assert CANONICAL["disabled"] in req.events_requested
    assert CANONICAL["purged"] in req.events_requested
    assert LEGACY["disabled"] not in req.events_requested
    assert LEGACY["purged"] not in req.events_requested


def test_stream_create_rejects_unknown_uri():
    import pytest
    from pydantic import ValidationError

    from app.models import StreamCreateRequest

    body = {
        "aud": "https://receiver.example.com",
        "delivery": {"endpoint_url": "https://receiver.example.com/events"},
        "events_requested": ["https://example.com/unknown-event"],
    }
    with pytest.raises(ValidationError):
        StreamCreateRequest.model_validate(body)
