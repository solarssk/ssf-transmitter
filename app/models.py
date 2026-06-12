"""Pydantic request/response models for SSF stream management endpoints.

Extra fields are forbidden on all models to prevent parameter smuggling.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, field_validator

# ---------------------------------------------------------------------------
# Supported values
# ---------------------------------------------------------------------------

SUPPORTED_EVENT_URIS: frozenset[str] = frozenset(
    {
        "https://schemas.openid.net/secevent/caep/event-type/session-revoked",
        "https://schemas.openid.net/secevent/caep/event-type/credential-change",
        # Final RISC URIs for account-state events (moved from caep/ namespace in the final spec)
        "https://schemas.openid.net/secevent/risc/event-type/account-disabled",
        "https://schemas.openid.net/secevent/risc/event-type/account-enabled",
        "https://schemas.openid.net/secevent/risc/event-type/account-purged",
    }
)

# Legacy caep/ URIs for account events that pre-1.0 receivers may send in events_requested.
# Accepted on input; canonicalized to risc/ before storage and emission.
_LEGACY_CAEP_ACCOUNT_URIS: dict[str, str] = {
    "https://schemas.openid.net/secevent/caep/event-type/account-disabled": "https://schemas.openid.net/secevent/risc/event-type/account-disabled",
    "https://schemas.openid.net/secevent/caep/event-type/account-enabled": "https://schemas.openid.net/secevent/risc/event-type/account-enabled",
    "https://schemas.openid.net/secevent/caep/event-type/account-purged": "https://schemas.openid.net/secevent/risc/event-type/account-purged",
}


def canonicalize_event_uri(uri: str) -> str:
    """Return the canonical URI for an event, mapping legacy caep/ account URIs to risc/."""
    return _LEGACY_CAEP_ACCOUNT_URIS.get(uri, uri)

SUPPORTED_DELIVERY_METHODS: frozenset[str] = frozenset(
    {
        # SSF 1.0 final (RFC 8935)
        "urn:ietf:rfc:8935",
        # Legacy / pre-1.0 clients still using the OpenID URI form
        "https://schemas.openid.net/secevent/risc/delivery-method/push",
    }
)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class StreamStatus(StrEnum):
    """Lifecycle state of an SSF push stream."""

    enabled = "enabled"
    paused = "paused"
    disabled = "disabled"


# ---------------------------------------------------------------------------
# Helpers (shared by both request models to avoid duplication)
# ---------------------------------------------------------------------------


def _coerce_aud(v: object) -> str:
    """Normalise an *aud* value from a request body to a plain string.

    Accepts a single string or a one-element list containing a string.
    Raises ``ValueError`` for multi-element lists, non-string types, or
    empty/whitespace-only strings.
    """
    if isinstance(v, list):
        if len(v) != 1:
            raise ValueError(f"aud must be a single string value, got list of {len(v)}")
        v = v[0]
    if not isinstance(v, str):
        raise ValueError(f"aud must be a string, got {type(v).__name__}")
    if not v.strip():
        raise ValueError("aud must not be empty")
    return v


def _validate_event_uris(uris: list[str]) -> list[str]:
    """Canonicalize and validate event URIs; raises ValueError for unsupported URIs."""
    canonical = [canonicalize_event_uri(u) for u in uris]
    unsupported = [u for u in canonical if u not in SUPPORTED_EVENT_URIS]
    if unsupported:
        raise ValueError(
            f"Unsupported event URI(s): {unsupported}. "
            f"Supported: {sorted(SUPPORTED_EVENT_URIS)}"
        )
    return canonical


# ---------------------------------------------------------------------------
# Nested models
# ---------------------------------------------------------------------------


class DeliveryConfig(BaseModel):
    """Delivery block sent inside a stream create or update request."""

    model_config = ConfigDict(extra="forbid")

    endpoint_url: str
    method: str | None = None
    endpoint_url_token: str | None = None
    authorization_header: str | None = None

    @field_validator("method")
    @classmethod
    def _validate_method(cls, v: str | None) -> str | None:
        """Reject delivery methods outside the supported SSF push set."""
        if v is not None and v not in SUPPORTED_DELIVERY_METHODS:
            raise ValueError(
                f"Unsupported delivery method: {v!r}. "
                f"Supported: {sorted(SUPPORTED_DELIVERY_METHODS)}"
            )
        return v


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class StreamCreateRequest(BaseModel):
    """Body for POST /ssf/streams."""

    model_config = ConfigDict(extra="forbid")

    aud: str | list[str]
    delivery: DeliveryConfig
    events_requested: list[str] = []
    status: StreamStatus = StreamStatus.enabled

    @field_validator("aud", mode="before")
    @classmethod
    def _normalize_aud(cls, v: object) -> str:
        """Coerce aud from a string or single-element list."""
        return _coerce_aud(v)

    @field_validator("events_requested")
    @classmethod
    def _validate_events(cls, v: list[str]) -> list[str]:
        """Canonicalize and validate requested event URIs."""
        return _validate_event_uris(v)


class StreamPatchRequest(BaseModel):
    """Body for PATCH /ssf/streams — all fields optional, no extra fields allowed."""

    model_config = ConfigDict(extra="forbid")

    status: StreamStatus | None = None
    events_requested: list[str] | None = None
    delivery: DeliveryConfig | None = None
    aud: str | list[str] | None = None

    @field_validator("aud", mode="before")
    @classmethod
    def _normalize_aud(cls, v: object) -> str | None:
        """Coerce aud from a string or single-element list when provided."""
        return None if v is None else _coerce_aud(v)

    @field_validator("events_requested")
    @classmethod
    def _validate_events(cls, v: list[str] | None) -> list[str] | None:
        """Canonicalize and validate requested event URIs when provided."""
        return None if v is None else _validate_event_uris(v)
