import hashlib
from dataclasses import replace

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
    requests = []
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
    FakeAsyncClient.requests = []
    FakeAsyncClient.status_code = 202
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
    FakeAsyncClient.requests = []
    FakeAsyncClient.status_code = 202
    monkeypatch.setattr(pusher, "sign_set", lambda *a, **kw: "signed.jwt")
    monkeypatch.setattr(pusher.httpx, "AsyncClient", FakeAsyncClient)

    await pusher.push_set(stream, event, "user@example.com")

    _, _, sent_headers = FakeAsyncClient.requests[0]
    assert sent_headers["Accept"] == "application/json"


@pytest.mark.anyio
async def test_push_verification_set_sends_accept_application_json(monkeypatch, stream):
    FakeAsyncClient.requests = []
    FakeAsyncClient.status_code = 202
    monkeypatch.setattr(pusher, "sign_verification_set", lambda audience, stream_id, **kw: "signed.jwt")
    monkeypatch.setattr(pusher.httpx, "AsyncClient", FakeAsyncClient)

    await pusher.push_verification_set(stream)

    _, _, sent_headers = FakeAsyncClient.requests[0]
    assert sent_headers["Accept"] == "application/json"


@pytest.mark.anyio
async def test_receiver_error_body_not_logged_at_warn(monkeypatch, stream, event, caplog):
    """Raw receiver error body must not appear in WARNING logs."""
    FakeAsyncClient.requests = []
    FakeAsyncClient.status_code = 400
    FakeAsyncClient.response_text = "Invalid security event token — secret diagnostic info"
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
    FakeAsyncClient.requests = []
    FakeAsyncClient.status_code = 400
    FakeAsyncClient.response_text = "error body"
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
    FakeAsyncClient.requests = []
    FakeAsyncClient.status_code = 500
    FakeAsyncClient.response_text = "Internal Server Error"
    monkeypatch.setattr(pusher, "sign_set", lambda *a, **kw: "signed.jwt")
    monkeypatch.setattr(pusher.httpx, "AsyncClient", FakeAsyncClient)

    delivered = await pusher.push_set(stream, event, "user@example.com")

    assert delivered is False
    assert "500" in caplog.text


@pytest.mark.anyio
async def test_push_set_skips_disabled_stream(monkeypatch, stream, event):
    FakeAsyncClient.requests = []
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
    FakeAsyncClient.requests = []
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
    FakeAsyncClient.requests = []
    FakeAsyncClient.status_code = 202
    monkeypatch.setattr(pusher, "sign_set", lambda *a, **kw: "signed.jwt")
    monkeypatch.setattr(pusher.httpx, "AsyncClient", FakeAsyncClient)
    allowed_event = MappedEvent(uri=SESSION_REVOKED, payload={})

    delivered = await pusher.push_set(stream_with_filter, allowed_event, "user@example.com")

    assert delivered is True


@pytest.mark.anyio
async def test_push_set_allows_all_when_events_requested_empty(monkeypatch, stream, event):
    """Empty events_requested means no filter — all events are pushed."""
    FakeAsyncClient.requests = []
    FakeAsyncClient.status_code = 202
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
        uri="https://schemas.openid.net/secevent/risc/event-type/account-purged",
        payload={},
    )
    FakeAsyncClient.requests = []
    FakeAsyncClient.status_code = 202
    monkeypatch.setattr(pusher, "sign_set", _capture_sign_set)
    monkeypatch.setattr(pusher.httpx, "AsyncClient", FakeAsyncClient)

    delivered = await pusher.push_set(stream, event, "deleted@example.com")

    assert delivered is True
    assert captured["event_payload"] == {}
    assert captured["email"] == "deleted@example.com"


@pytest.mark.anyio
async def test_receiver_error_body_logged_only_when_enabled(monkeypatch, stream, event, caplog):
    FakeAsyncClient.requests = []
    FakeAsyncClient.status_code = 400
    FakeAsyncClient.response_text = "receiver detail"
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
    FakeAsyncClient.requests = []
    FakeAsyncClient.status_code = 400
    FakeAsyncClient.response_text = "receiver detail"
    monkeypatch.setattr(pusher, "sign_verification_set", lambda *a, **kw: "signed.jwt")
    monkeypatch.setattr(pusher.httpx, "AsyncClient", FakeAsyncClient)
    monkeypatch.setattr(pusher, "settings", replace(pusher.settings, ssf_log_receiver_error_body=True))

    import logging
    with caplog.at_level(logging.DEBUG, logger="app.events.pusher"):
        delivered = await pusher.push_verification_set(stream)

    assert delivered is False
    assert "receiver detail" in caplog.text
