"""Backward compatibility: legacy caep/ account-* URIs must be canonicalized to risc/."""

from app.models import SUPPORTED_EVENT_URIS, canonicalize_event_uri

SUPPORTED = {
    "verification": "https://schemas.openid.net/secevent/ssf/event-type/verification",
    "session_revoked": "https://schemas.openid.net/secevent/caep/event-type/session-revoked",
    "credential_change": "https://schemas.openid.net/secevent/caep/event-type/credential-change",
}
UNSUPPORTED = {
    "disabled": "https://schemas.openid.net/secevent/risc/event-type/account-disabled",
    "enabled": "https://schemas.openid.net/secevent/risc/event-type/account-enabled",
    "purged": "https://schemas.openid.net/secevent/risc/event-type/account-purged",
}


def test_supported_event_uris_are_in_supported_set():
    for uri in SUPPORTED.values():
        assert uri in SUPPORTED_EVENT_URIS


def test_account_lifecycle_uris_not_in_supported_set():
    for uri in UNSUPPORTED.values():
        assert uri not in SUPPORTED_EVENT_URIS


def test_canonicalize_non_legacy_uri_unchanged():
    uri = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"
    assert canonicalize_event_uri(uri) == uri


def test_stream_create_accepts_supported_subset():
    """StreamCreateRequest validator must accept only the SSF/CAEP subset."""

    from app.models import StreamCreateRequest

    body = {
        "aud": "https://receiver.example.com",
        "delivery": {"endpoint_url": "https://receiver.example.com/events"},
        "events_requested": [SUPPORTED["verification"], SUPPORTED["credential_change"]],
    }
    req = StreamCreateRequest.model_validate(body)
    assert req.events_requested == [SUPPORTED["verification"], SUPPORTED["credential_change"]]


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
