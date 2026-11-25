"""Sync-wide identity validation, upstream failures, and rate-limit backoff."""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime
from email.utils import format_datetime

import httpx
import pytest

from app.config import settings
from app.scim import apple, coordination


def _user(number: int) -> dict:
    return {
        "externalId": str(number),
        "userName": f"user{number}@example.test",
        "name": {"givenName": "New", "familyName": "Name"},
        "emails": [{"value": f"user{number}@example.test", "primary": True}],
        "active": True,
    }


def _client(monkeypatch, handler):
    client_type = httpx.AsyncClient
    monkeypatch.setattr(
        apple.httpx, "AsyncClient", lambda timeout: client_type(transport=httpx.MockTransport(handler), timeout=timeout)
    )


@pytest.mark.anyio
@pytest.mark.parametrize("key", ["externalId", "userName"])
async def test_duplicate_source_rejected_before_any_apple_request(monkeypatch, key):
    """Standard listings must not bypass the source preflight."""
    requests = []
    _client(monkeypatch, lambda request: requests.append(request))
    first, second = _user(1), _user(2)
    second[key] = " 1 " if key == "externalId" else first[key].upper()

    with pytest.raises(apple.AppleUserListError, match="duplicate identities"):
        await apple.sync_users("token", [first, second])

    assert requests == []


@pytest.mark.anyio
@pytest.mark.parametrize("status", [401, 403, 429])
@pytest.mark.parametrize("operation", ["list", "POST", "PATCH", "PUT", "repair", "repair_read"])
async def test_connection_failure_stops_before_next_account(monkeypatch, status, operation):
    requests = []
    users = [_user(1), _user(2)]
    existing = (
        []
        if operation == "POST"
        else [
            {**u, "id": f"apple-{i}", "name": {"givenName": "Old", "familyName": "Name"}} for i, u in enumerate(users)
        ]
    )
    if operation.startswith("repair"):
        del existing[0]["externalId"]
    monkeypatch.setattr(
        apple,
        "settings",
        dataclasses.replace(
            settings,
            apple_scim_update_mode="replace_all" if operation == "PUT" else "patch_all",
            apple_scim_allow_username_recovery=True,
        ),
    )

    def handler(request):
        requests.append(request)
        if request.method == "GET" and request.url.path.endswith("/Users") and operation != "list":
            return httpx.Response(200, json={"Resources": existing, "totalResults": len(existing)})
        if operation == "repair_read" and request.method == "PATCH":
            return httpx.Response(200, json={})
        return httpx.Response(status, headers={"Retry-After": "120"}, json={})

    _client(monkeypatch, handler)
    result = await apple.sync_users("token", users)

    assert len(requests) == (1 if operation == "list" else 3 if operation == "repair_read" else 2)
    assert result.status == "failed"
    assert result.errors == 1
    assert result.created == result.updated == 0
    assert result.skipped == (2 if operation == "list" else 1)
    assert result.stopped_reason == ("rate_limited" if status == 429 else "authorization_failed")
    assert result.retry_after_seconds == (120 if status == 429 else None)


@pytest.mark.anyio
async def test_cooldown_shared_between_sync_calls_and_expires(monkeypatch):
    requests = []
    now = [1000.0]
    monkeypatch.setattr(coordination.time, "monotonic", lambda: now[0])

    def handler(request):
        requests.append(request)
        if len(requests) == 1:
            return httpx.Response(429, headers={"Retry-After": "7200"})
        return httpx.Response(200, json={"Resources": [], "totalResults": 0})

    _client(monkeypatch, handler)
    first = await apple.sync_users("token", [_user(1)])
    now[0] += 3600
    second = await apple.sync_users("token", [_user(1)])
    assert first.retry_after_seconds == 7200
    assert second.retry_after_seconds == 3600
    assert second.status == "failed"
    assert second.skipped == 1
    assert len(requests) == 1
    now[0] += 3600
    third = await apple.sync_users("token", [])
    assert third.status == "ok"
    assert len(requests) == 2


@pytest.mark.anyio
@pytest.mark.parametrize("status", [401, 403, 429])
async def test_connection_failure_during_conflict_recovery_stops_sync(monkeypatch, status):
    requests = []

    def handler(request):
        requests.append(request)
        if request.method == "POST":
            return httpx.Response(409, json={})
        if "filter" in request.url.params:
            return httpx.Response(status, json={})
        return httpx.Response(200, json={"Resources": [], "totalResults": 0})

    _client(monkeypatch, handler)
    result = await apple.sync_users("token", [_user(1), _user(2)])

    assert [r.method for r in requests] == ["GET", "POST", "GET"]
    assert result.errors == 1
    assert result.conflicts == 0
    assert result.skipped == 1
    assert result.stopped_reason == ("rate_limited" if status == 429 else "authorization_failed")


@pytest.mark.anyio
@pytest.mark.parametrize("failure", [401, 403, 429, 500, "timeout"])
async def test_partial_success_is_retained_without_retrying_writes(monkeypatch, failure):
    source = [_user(1), _user(2)]
    existing = [{**source[0], "id": "apple-1"}]
    writes = []

    def handler(request):
        if request.method == "GET":
            return httpx.Response(200, json={"Resources": existing, "totalResults": 1})
        writes.append(request)
        if failure == "timeout":
            raise httpx.ReadTimeout("ambiguous write outcome")
        return httpx.Response(failure, json={})

    _client(monkeypatch, handler)
    result = await apple.sync_users("token", source)
    assert result.status == "partial"
    assert result.unchanged == 1
    assert result.errors == 1
    assert result.created == 0
    assert len(writes) == 1


@pytest.mark.parametrize(
    "header, expected", [(None, 60), ("bad", 60), ("-1", 60), ("120", 120), ("0", 0), ("9" * 400, 60)]
)
def test_retry_after_seconds(header, expected):
    assert apple._retry_after_seconds(header) == expected


def test_retry_after_http_date(monkeypatch):
    monkeypatch.setattr(apple.time, "time", lambda: 1000.5)
    future = format_datetime(datetime.fromtimestamp(1061, UTC), usegmt=True)
    past = format_datetime(datetime.fromtimestamp(900, UTC), usegmt=True)
    assert apple._retry_after_seconds(future) == 61
    assert apple._retry_after_seconds(past) == 0
