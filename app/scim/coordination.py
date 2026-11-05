"""Coordinate Apple SCIM operations within the single Uvicorn worker."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import AbstractAsyncContextManager, asynccontextmanager


class AppleScimBusy(RuntimeError):
    """Another sync or authorization is already using the Apple connection."""


class _Coordinator:
    def __init__(self) -> None:
        self._busy = False
        self._idle = asyncio.Event()
        self._idle.set()
        self.token_lock = asyncio.Lock()

    @asynccontextmanager
    async def operation(self, *, wait: bool = False) -> AsyncIterator[None]:
        """Claim the connection, optionally waiting for an existing operation."""
        while self._busy:
            if not wait:
                raise AppleScimBusy("Another Apple SCIM operation is in progress")
            await self._idle.wait()
        self._busy = True
        self._idle.clear()
        try:
            yield
        finally:
            self._busy = False
            self._idle.set()


_coordinator: _Coordinator | None = None
_coordinator_loop: asyncio.AbstractEventLoop | None = None


def _get_coordinator() -> _Coordinator:
    """Reuse the coordinator for the current loop, including across requests."""
    global _coordinator, _coordinator_loop
    loop = asyncio.get_running_loop()
    if _coordinator is None or _coordinator_loop is not loop:
        _coordinator = _Coordinator()
        _coordinator_loop = loop
    return _coordinator


def scim_operation(*, wait: bool = False) -> AbstractAsyncContextManager[None]:
    """Return a context manager for a full sync or an OAuth code exchange."""
    return _get_coordinator().operation(wait=wait)


def token_lock() -> asyncio.Lock:
    """Serialize token refresh and authorization-code exchange/save."""
    return _get_coordinator().token_lock
