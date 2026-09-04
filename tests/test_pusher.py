import hashlib
from dataclasses import replace
from typing import ClassVar

import pytest

from app.database import Stream
from app.events import pusher
from app.events.mapper import MappedEvent

SESSION_REVOKED = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"


class FakeResponse:
    def __init__(self, status_code: int, text: str = ""):
        self.status_code = status_code
        self.text = text
        self.content = text.encode()


class FakeAsyncClient:
    # Deliberately class-level, not per-instance: tests monkeypatch these
    # attributes directly on the class (see monkeypatch.setattr(FakeAsyncClient, ...)
    # throughout this file), so pytest can restore the originals after each test.
    requests: ClassVar[list[tuple]] = []
    status_code = 202
    response_text = ""

    def __init__(self, timeout: float, follow_redirects: bool = True):
        self.timeout = timeout
        self.follow_redirects = follow_redirects

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def post(self, url, content, headers):
        self.requests.append((url, content, headers))
        return FakeResponse(self.status_code, self.response_text)


@pytest.fixture()
def stream():
    return Stream(
        stream_id="stream-1",
        aud="receiver-audience",
        endpoint_url="https://receiver.example.test/events",
        endpoint_token="receiver-secret-token",
        events_requested=[],
        status="enabled",
        created_at=123,
    )


@pytest.fixture()
def event():
    return MappedEvent(uri=SESSION_REVOKED, payload={}, txn=None)


@pytest.mark.anyio
async def test_push_set_posts_signed_set_as_plain_secevent_jwt(monkeypatch, stream, event):
    monkeypatch.setattr(FakeAsyncClient, "requests", [])
    monkeypatch.setattr(FakeAsyncClient, "status_code", 202)
    monkeypatch.setattr(pusher, "sign_set", lambda *a, **kw: "signed.jwt")
    monkeypatch.setattr(pusher.httpx, "AsyncClient", FakeAsyncClient)

    delivered = await pusher.push_set(stream, event, "user@example.com")

    assert delivered is True
    assert FakeAsyncClient.requests == [
        (
            "https://receiver.example.test/events",
            "signed.jwt",
            {
                "Authorization": "Bearer receiver-secret-token",
                "Content-Type": "application/secevent+jwt",
                "Accept": "application/json",
            },
        )
    ]


@pytest.mark.anyio
async def test_push_set_sends_accept_application_json(monkeypatch, stream, event):
    monkeypatch.setattr(FakeAsyncClient, "requests", [])
    monkeypatch.setattr(FakeAsyncClient, "status_code", 202)
    monkeypatch.setattr(pusher, "sign_set", lambda *a, **kw: "signed.jwt")
    monkeypatch.setattr(pusher.httpx, "AsyncClient", FakeAsyncClient)

    await pusher.push_set(stream, event, "user@example.com")

    _, _, sent_headers = FakeAsyncClient.requests[0]
    assert sent_headers["Accept"] == "application/json"


@pytest.mark.anyio
async def test_push_verification_set_sends_accept_application_json(monkeypatch, stream):
    monkeypatch.setattr(FakeAsyncClient, "requests", [])
    monkeypatch.setattr(FakeAsyncClient, "status_code", 202)
    monkeypatch.setattr(pusher, "sign_verification_set", lambda audience, stream_id, **kw: "signed.jwt")
    monkeypatch.setattr(pusher.httpx, "AsyncClient", FakeAsyncClient)

    await pusher.push_verification_set(stream)

    _, _, sent_headers = FakeAsyncClient.requests[0]
    assert sent_headers["Accept"] == "application/json"


@pytest.mark.anyio
async def test_receiver_error_body_not_logged_at_warn(monkeypatch, stream, event, caplog):
    """Raw receiver error body must not appear in WARNING logs."""
    monkeypatch.setattr(FakeAsyncClient, "requests", [])
    monkeypatch.setattr(FakeAsyncClient, "status_code", 400)
    monkeypatch.setattr(FakeAsyncClient, "response_text", "Invalid security event token — secret diagnostic info")
    monkeypatch.setattr(pusher, "sign_set", lambda *a, **kw: "signed.jwt")
    monkeypatch.setattr(pusher.httpx, "AsyncClient", FakeAsyncClient)

    import logging

    with caplog.at_level(logging.WARNING, logger="app.events.pusher"):
        delivered = await pusher.push_set(stream, event, "user@example.com")

    assert delivered is False
    warn_records = [r for r in caplog.records if r.levelno == logging.WARNING]
    warn_text = " ".join(r.getMessage() for r in warn_records)
    assert "Invalid security event token" not in warn_text
    assert "secret diagnostic info" not in warn_text


@pytest.mark.anyio
async def test_receiver_error_body_hash_logged_at_warn(monkeypatch, stream, event, caplog):
    """WARNING log must include a body hash for correlation."""
    monkeypatch.setattr(FakeAsyncClient, "requests", [])
    monkeypatch.setattr(FakeAsyncClient, "status_code", 400)
    monkeypatch.setattr(FakeAsyncClient, "response_text", "error body")
    monkeypatch.setattr(pusher, "sign_set", lambda *a, **kw: "signed.jwt")
    monkeypatch.setattr(pusher.httpx, "AsyncClient", FakeAsyncClient)

    import logging

    with caplog.at_level(logging.WARNING, logger="app.events.pusher"):
        await pusher.push_set(stream, event, "user@example.com")

    expected_hash = hashlib.sha256(b"error body").hexdigest()[:8]
    assert expected_hash in caplog.text


@pytest.mark.anyio
async def test_push_set_reports_receiver_error(monkeypatch, stream, event, caplog):
    """Failed push returns False and logs status code."""
    monkeypatch.setattr(FakeAsyncClient, "requests", [])
    monkeypatch.setattr(FakeAsyncClient, "status_code", 500)
    monkeypatch.setattr(FakeAsyncClient, "response_text", "Internal Server Error")
    monkeypatch.setattr(pusher, "sign_set", lambda *a, **kw: "signed.jwt")
    monkeypatch.setattr(pusher.httpx, "AsyncClient", FakeAsyncClient)

    delivered = await pusher.push_set(stream, event, "user@example.com")

    assert delivered is False
    assert "500" in caplog.text


@pytest.mark.anyio
async def test_push_set_skips_disabled_stream(monkeypatch, stream, event):
    monkeypatch.setattr(FakeAsyncClient, "requests", [])
    monkeypatch.setattr(pusher.httpx, "AsyncClient", FakeAsyncClient)
    disabled_stream = Stream(
        stream_id=stream.stream_id,
        aud=stream.aud,
        endpoint_url=stream.endpoint_url,
        endpoint_token=stream.endpoint_token,
        events_requested=stream.events_requested,
        status="paused",
        created_at=stream.created_at,
    )

    result = await pusher.push_set(disabled_stream, event, "user@example.com")

    assert result is None
    assert FakeAsyncClient.requests == []


@pytest.mark.anyio
async def test_push_set_skips_event_not_in_events_requested(monkeypatch, stream):
    """Events not listed in stream.events_requested return None (skipped), not False (failure)."""
    monkeypatch.setattr(FakeAsyncClient, "requests", [])
    monkeypatch.setattr(pusher.httpx, "AsyncClient", FakeAsyncClient)
    stream_with_filter = Stream(
        stream_id=stream.stream_id,
        aud=stream.aud,
        endpoint_url=stream.endpoint_url,
        endpoint_token=stream.endpoint_token,
        events_requested=["https://schemas.openid.net/secevent/caep/event-type/credential-change"],
        status="enabled",
        created_at=stream.created_at,
    )
    other_event = MappedEvent(uri=SESSION_REVOKED, payload={})

    result = await pusher.push_set(stream_with_filter, other_event, "user@example.com")

    assert result is None
    assert FakeAsyncClient.requests == []


@pytest.mark.anyio
async def test_push_set_delivers_event_in_events_requested(monkeypatch, stream):
    """Events present in stream.events_requested are pushed."""
    stream_with_filter = Stream(
        stream_id=stream.stream_id,
        aud=stream.aud,
        endpoint_url=stream.endpoint_url,
        endpoint_token=stream.endpoint_token,
        events_requested=[SESSION_REVOKED],
        status="enabled",
        created_at=stream.created_at,
    )
    monkeypatch.setattr(FakeAsyncClient, "requests", [])
    monkeypatch.setattr(FakeAsyncClient, "status_code", 202)
    monkeypatch.setattr(pusher, "sign_set", lambda *a, **kw: "signed.jwt")
    monkeypatch.setattr(pusher.httpx, "AsyncClient", FakeAsyncClient)
    allowed_event = MappedEvent(uri=SESSION_REVOKED, payload={})

    delivered = await pusher.push_set(stream_with_filter, allowed_event, "user@example.com")

    assert delivered is True


@pytest.mark.anyio
async def test_push_set_allows_all_when_events_requested_empty(monkeypatch, stream, event):
    """Empty events_requested means no filter — all events are pushed."""
    monkeypatch.setattr(FakeAsyncClient, "requests", [])
    monkeypatch.setattr(FakeAsyncClient, "status_code", 202)
    monkeypatch.setattr(pusher, "sign_set", lambda *a, **kw: "signed.jwt")
    monkeypatch.setattr(pusher.httpx, "AsyncClient", FakeAsyncClient)

    delivered = await pusher.push_set(stream, event, "user@example.com")

    assert delivered is True


@pytest.mark.anyio
async def test_push_set_passes_empty_risc_event_payload_to_signer(monkeypatch, stream):
    captured = {}

    def _capture_sign_set(*args, **kwargs):
        captured.update(kwargs)
        return "signed.jwt"

    event = MappedEvent(
        uri="https://schemas.openid.net/secevent/ssf/event-type/verification",
        payload={},
    )
    monkeypatch.setattr(FakeAsyncClient, "requests", [])
    monkeypatch.setattr(FakeAsyncClient, "status_code", 202)
    monkeypatch.setattr(pusher, "sign_set", _capture_sign_set)
    monkeypatch.setattr(pusher.httpx, "AsyncClient", FakeAsyncClient)

    delivered = await pusher.push_set(stream, event, "deleted@example.com")

    assert delivered is True
    assert captured["event_payload"] == {}
    assert captured["email"] == "deleted@example.com"


@pytest.mark.anyio
async def test_receiver_error_body_logged_only_when_enabled(monkeypatch, stream, event, caplog):
    monkeypatch.setattr(FakeAsyncClient, "requests", [])
    monkeypatch.setattr(FakeAsyncClient, "status_code", 400)
    monkeypatch.setattr(FakeAsyncClient, "response_text", "receiver detail")
    monkeypatch.setattr(pusher, "sign_set", lambda *a, **kw: "signed.jwt")
    monkeypatch.setattr(pusher.httpx, "AsyncClient", FakeAsyncClient)
    monkeypatch.setattr(pusher, "settings", replace(pusher.settings, ssf_log_receiver_error_body=True))

    import logging

    with caplog.at_level(logging.DEBUG, logger="app.events.pusher"):
        delivered = await pusher.push_set(stream, event, "user@example.com")

    assert delivered is False
    assert "receiver detail" in caplog.text


@pytest.mark.anyio
async def test_verification_receiver_error_body_logged_only_when_enabled(monkeypatch, stream, caplog):
    monkeypatch.setattr(FakeAsyncClient, "requests", [])
    monkeypatch.setattr(FakeAsyncClient, "status_code", 400)
    monkeypatch.setattr(FakeAsyncClient, "response_text", "receiver detail")
    monkeypatch.setattr(pusher, "sign_verification_set", lambda *a, **kw: "signed.jwt")
    monkeypatch.setattr(pusher.httpx, "AsyncClient", FakeAsyncClient)
    monkeypatch.setattr(pusher, "settings", replace(pusher.settings, ssf_log_receiver_error_body=True))

    import logging

    with caplog.at_level(logging.DEBUG, logger="app.events.pusher"):
        delivered = await pusher.push_verification_set(stream)

    assert delivered is False
    assert "receiver detail" in caplog.text


@pytest.mark.anyio
async def test_push_set_blocked_when_host_not_in_allowlist(monkeypatch, stream, event, caplog):
    monkeypatch.setattr(FakeAsyncClient, "requests", [])
    monkeypatch.setattr(pusher, "sign_set", lambda *a, **kw: "signed.jwt")
    monkeypatch.setattr(pusher.httpx, "AsyncClient", FakeAsyncClient)
    monkeypatch.setattr(
        pusher,
        "settings",
        replace(pusher.settings, ssf_allowed_receiver_hosts=["allowed.example.com"]),
    )

    import logging

    with caplog.at_level(logging.WARNING, logger="app.events.pusher"):
        delivered = await pusher.push_set(stream, event, "user@example.com")

    assert delivered is False
    assert FakeAsyncClient.requests == []
    assert "SSF_ALLOWED_RECEIVER_HOSTS allowlist" in caplog.text


@pytest.mark.anyio
async def test_push_verification_set_blocked_when_host_not_in_allowlist(monkeypatch, stream, caplog):
    monkeypatch.setattr(FakeAsyncClient, "requests", [])
    monkeypatch.setattr(pusher, "sign_verification_set", lambda *a, **kw: "signed.jwt")
    monkeypatch.setattr(pusher.httpx, "AsyncClient", FakeAsyncClient)
    monkeypatch.setattr(
        pusher,
        "settings",
        replace(pusher.settings, ssf_allowed_receiver_hosts=["allowed.example.com"]),
    )

    import logging

    with caplog.at_level(logging.WARNING, logger="app.events.pusher"):
        delivered = await pusher.push_verification_set(stream)

    assert delivered is False
    assert FakeAsyncClient.requests == []
    assert "SSF_ALLOWED_RECEIVER_HOSTS allowlist" in caplog.text


@pytest.mark.anyio
async def test_push_set_logs_claims_from_inputs_without_decoding_token(monkeypatch, stream, event, caplog):
    """DEBUG-level claims logging reads the pre-signing inputs, not the signed token.

    Regression test: this used to jwt.decode() the token we had just signed
    ourselves (verify_signature=False) purely to log it back — logging the
    inputs directly means there's nothing to decode, and nothing to silently
    fail decoding either.
    """
    monkeypatch.setattr(FakeAsyncClient, "requests", [])
    monkeypatch.setattr(FakeAsyncClient, "status_code", 202)
    monkeypatch.setattr(pusher, "sign_set", lambda *a, **kw: "not a real jwt at all")
    monkeypatch.setattr(pusher.httpx, "AsyncClient", FakeAsyncClient)

    import logging

    with caplog.at_level(logging.DEBUG, logger="app.events.pusher"):
        delivered = await pusher.push_set(stream, event, "user@example.com")

    assert delivered is True
    assert f"event_uri={event.uri}" in caplog.text
    assert f"aud={stream.aud}" in caplog.text
    assert "could not be decoded" not in caplog.text


@pytest.mark.anyio
async def test_push_set_sanitizes_control_characters_in_logged_claims(monkeypatch, stream, caplog):
    """aud and txn can carry attacker-controlled CR/LF; the claims log must not forge lines.

    aud is client-supplied when a stream is created (no format validation);
    txn can come straight from an Authentik webhook body (see
    app.events.mapper.extract_source_txn). Regression for a CWE-117 log
    injection gap introduced when the claims log stopped reading the signed
    token's dict repr (which happened to escape control characters) and
    started reading these values directly.
    """
    malicious_stream = replace(stream, aud="receiver\r\nFAKE LOG LINE aud")
    malicious_event = MappedEvent(uri=SESSION_REVOKED, payload={}, txn="txn-1\r\nFAKE LOG LINE txn")

    monkeypatch.setattr(FakeAsyncClient, "requests", [])
    monkeypatch.setattr(FakeAsyncClient, "status_code", 202)
    monkeypatch.setattr(pusher, "sign_set", lambda *a, **kw: "signed.jwt")
    monkeypatch.setattr(pusher.httpx, "AsyncClient", FakeAsyncClient)

    import logging

    with caplog.at_level(logging.DEBUG, logger="app.events.pusher"):
        delivered = await pusher.push_set(malicious_stream, malicious_event, "user@example.com")

    assert delivered is True
    # The raw CR/LF must be gone (no forged line break)...
    assert "\r\nFAKE" not in caplog.text
    assert "\n\r\nFAKE" not in caplog.text
    # ...but the rest of the value still shows up, de-fanged, on the same line.
    assert "aud=receiverFAKE LOG LINE aud" in caplog.text
    assert "txn=txn-1FAKE LOG LINE txn" in caplog.text
