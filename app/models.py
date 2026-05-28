"""Pydantic request/response models for SSF stream management endpoints.

Extra fields are forbidden on all models to prevent parameter smuggling.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, field_validator

# ---------------------------------------------------------------------------
# Supported values
# ---------------------------------------------------------------------------

SUPPORTED_EVENT_URIS: frozenset[str] = frozenset(
    {
        "https://schemas.openid.net/secevent/caep/event-type/session-revoked",
        "https://schemas.openid.net/secevent/caep/event-type/credential-change",
        "https://schemas.openid.net/secevent/caep/event-type/account-disabled",
        "https://schemas.openid.net/secevent/caep/event-type/account-enabled",
        "https://schemas.openid.net/secevent/caep/event-type/account-purged",
    }
)

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


class StreamStatus(str, Enum):
    enabled = "enabled"
    paused = "paused"
    disabled = "disabled"


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
        if isinstance(v, list):
            if len(v) != 1:
                raise ValueError(f"aud must be a single string value, got list of {len(v)}")
            v = v[0]
        if not v or not str(v).strip():
            raise ValueError("aud must not be empty")
        return str(v)

    @field_validator("events_requested")
    @classmethod
    def _validate_events(cls, v: list[str]) -> list[str]:
        unsupported = [e for e in v if e not in SUPPORTED_EVENT_URIS]
        if unsupported:
            raise ValueError(
                f"Unsupported event URI(s): {unsupported}. "
                f"Supported: {sorted(SUPPORTED_EVENT_URIS)}"
            )
        return v


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
        if v is None:
            return None
        if isinstance(v, list):
            if len(v) != 1:
                raise ValueError(f"aud must be a single string value, got list of {len(v)}")
            v = v[0]
        if not v or not str(v).strip():
            raise ValueError("aud must not be empty")
        return str(v)

    @field_validator("events_requested")
    @classmethod
    def _validate_events(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return None
        unsupported = [e for e in v if e not in SUPPORTED_EVENT_URIS]
        if unsupported:
            raise ValueError(
                f"Unsupported event URI(s): {unsupported}. "
                f"Supported: {sorted(SUPPORTED_EVENT_URIS)}"
            )
        return v
