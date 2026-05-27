import pytest

from app.database import Stream
from app.events import pusher


class FakeResponse:
    def __init__(self, status_code: int):
        self.status_code = status_code


class FakeAsyncClient:
    requests = []
    status_code = 202

    def __init__(self, timeout: float):
        self.timeout = timeout

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def post(self, url, content, headers):
        self.requests.append((url, content, headers))
        return FakeResponse(self.status_code)


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


@pytest.mark.anyio
async def test_push_set_posts_signed_set_as_plain_secevent_jwt(monkeypatch, stream):
    FakeAsyncClient.requests = []
    FakeAsyncClient.status_code = 202
    monkeypatch.setattr(pusher, "sign_set", lambda event_uri, audience, email: "signed.jwt")
    monkeypatch.setattr(pusher.httpx, "AsyncClient", FakeAsyncClient)

    delivered = await pusher.push_set(
        stream,
        "https://schemas.openid.net/secevent/caep/event-type/session-revoked",
        "user@example.com",
    )

    assert delivered is True
    assert FakeAsyncClient.requests == [
        (
            "https://receiver.example.test/events",
            "signed.jwt",
            {
                "Authorization": "Bearer receiver-secret-token",
                "Content-Type": "application/secevent+jwt",
            },
        )
    ]


@pytest.mark.anyio
async def test_push_set_reports_receiver_error(monkeypatch, stream):
    FakeAsyncClient.requests = []
    FakeAsyncClient.status_code = 500
    monkeypatch.setattr(pusher, "sign_set", lambda event_uri, audience, email: "signed.jwt")
    monkeypatch.setattr(pusher.httpx, "AsyncClient", FakeAsyncClient)

    delivered = await pusher.push_set(
        stream,
        "https://schemas.openid.net/secevent/caep/event-type/session-revoked",
        "user@example.com",
    )

    assert delivered is False


@pytest.mark.anyio
async def test_push_set_skips_disabled_stream(stream):
    disabled_stream = Stream(
        stream_id=stream.stream_id,
        aud=stream.aud,
        endpoint_url=stream.endpoint_url,
        endpoint_token=stream.endpoint_token,
        events_requested=stream.events_requested,
        status="paused",
        created_at=stream.created_at,
    )

    delivered = await pusher.push_set(
        disabled_stream,
        "https://schemas.openid.net/secevent/caep/event-type/session-revoked",
        "user@example.com",
    )

    assert delivered is False
