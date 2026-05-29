from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Optional, Union

_WEBHOOK_AUTH_MODES = {"bearer", "hmac", "unsigned"}


def _strip_trailing_slash(value: str) -> str:
    """Remove any trailing slashes from *value*."""
    return value.rstrip("/")


def _parse_sync_interval(value: str) -> int:
    """Parse APPLE_SCIM_SYNC_INTERVAL and raise if the result is less than 1."""
    interval = int(value)
    if interval < 1:
        raise ValueError(f"APPLE_SCIM_SYNC_INTERVAL must be >= 1 second, got {interval}")
    return interval


def _parse_management_token(value: Optional[str]) -> str:
    """Validate SSF_MANAGEMENT_TOKEN — required, minimum 32 characters."""
    if not value:
        raise RuntimeError("Missing required environment variable: SSF_MANAGEMENT_TOKEN")
    if len(value) < 32:
        raise RuntimeError(
            f"SSF_MANAGEMENT_TOKEN is too short ({len(value)} chars); minimum is 32 characters"
        )
    return value


def _parse_webhook_auth_mode(value: Optional[str], allow_unsigned_legacy: bool) -> str:
    """Return the resolved webhook auth mode.

    ``SSF_ALLOW_UNSIGNED_WEBHOOK=true`` is accepted as a backward-compatible
    alias for ``SSF_WEBHOOK_AUTH_MODE=unsigned``.
    """
    if allow_unsigned_legacy:
        return "unsigned"
    mode = (value or "bearer").lower().strip()
    if mode not in _WEBHOOK_AUTH_MODES:
        raise RuntimeError(
            f"SSF_WEBHOOK_AUTH_MODE must be one of: {', '.join(sorted(_WEBHOOK_AUTH_MODES))}"
        )
    return mode


def _parse_webhook_token(value: Optional[str], mode: str) -> Optional[str]:
    """Validate SSF_WEBHOOK_TOKEN — required and ≥ 32 chars when mode is 'bearer'."""
    if mode != "bearer":
        return value or None
    if not value:
        raise RuntimeError(
            "Missing required environment variable: SSF_WEBHOOK_TOKEN "
            "(required when SSF_WEBHOOK_AUTH_MODE=bearer)"
        )
    if len(value) < 32:
        raise RuntimeError(
            f"SSF_WEBHOOK_TOKEN is too short ({len(value)} chars); minimum is 32 characters"
        )
    return value


def _parse_webhook_secret(value: Optional[str], mode: str) -> str:
    """Validate SSF_WEBHOOK_SECRET — required when mode is 'hmac'."""
    if mode == "hmac" and not value:
        raise RuntimeError(
            "Missing required environment variable: SSF_WEBHOOK_SECRET "
            "(required when SSF_WEBHOOK_AUTH_MODE=hmac)"
        )
    return value or ""


@dataclass(frozen=True)
class Settings:
    ssf_issuer: str
    ssf_base_url: str
    ssf_root_path: str
    ssf_container_port: int
    ssf_management_token: str
    log_level: str
    # Webhook authentication
    ssf_webhook_auth_mode: str = "bearer"   # bearer | hmac | unsigned
    ssf_webhook_token: Optional[str] = None    # required in bearer mode
    ssf_webhook_secret: str = ""           # required in hmac mode
    database_path: str = "/app/data/ssf.db"
    keys_dir: str = "/app/keys"
    # Privacy — when False (default), emails are replaced by a keyed HMAC token in logs.
    # Set SSF_LOG_PII=true only in controlled dev/debug environments.
    log_pii: bool = False
    # HMAC key used for email pseudonymisation (SSF_PII_PEPPER).
    # Falls back to ssf_management_token if unset; override with a dedicated secret
    # when you want log-correlation tokens that are independent of the management credential.
    pii_pepper: str = ""
    # Apple SCIM sync — all optional; sync is disabled when any required field is unset.
    # Set these to enable automatic user provisioning from Authentik to Apple Business Manager.
    apple_scim_client_id: Optional[str] = None
    apple_scim_client_secret: Optional[str] = None
    authentik_url: Optional[str] = None
    authentik_token: Optional[str] = None
    apple_scim_group_id: Optional[str] = None  # sync only members of this Authentik group UUID
    apple_scim_sync_interval: int = 3600    # seconds between automatic syncs (default: 1 hour)

    @property
    def allow_unsigned_webhook(self) -> bool:
        """Backward-compatible alias — True when ssf_webhook_auth_mode == 'unsigned'."""
        return self.ssf_webhook_auth_mode == "unsigned"

    @property
    def apple_scim_enabled(self) -> bool:
        """True when all required Apple SCIM variables are configured."""
        return bool(
            self.apple_scim_client_id
            and self.apple_scim_client_secret
            and self.authentik_url
            and self.authentik_token
        )

    @classmethod
    def from_env(cls) -> Settings:
        """Build a :class:`Settings` instance from environment variables.

        Raises :class:`RuntimeError` if any required variable is missing or invalid.
        """
        required = {
            "SSF_ISSUER": os.getenv("SSF_ISSUER"),
            "SSF_BASE_URL": os.getenv("SSF_BASE_URL"),
        }
        missing = [name for name, value in required.items() if not value]
        if missing:
            raise RuntimeError(f"Missing required environment variables: {', '.join(missing)}")

        allow_unsigned = os.getenv("SSF_ALLOW_UNSIGNED_WEBHOOK", "false").lower() == "true"
        auth_mode = _parse_webhook_auth_mode(os.getenv("SSF_WEBHOOK_AUTH_MODE"), allow_unsigned)
        webhook_token = _parse_webhook_token(os.getenv("SSF_WEBHOOK_TOKEN"), auth_mode)
        webhook_secret = _parse_webhook_secret(os.getenv("SSF_WEBHOOK_SECRET"), auth_mode)

        return cls(
            ssf_issuer=required["SSF_ISSUER"],
            ssf_base_url=_strip_trailing_slash(required["SSF_BASE_URL"]),
            ssf_root_path=os.getenv("SSF_ROOT_PATH", ""),
            ssf_container_port=int(os.getenv("SSF_CONTAINER_PORT", "8000")),
            ssf_management_token=_parse_management_token(os.getenv("SSF_MANAGEMENT_TOKEN")),
            ssf_webhook_auth_mode=auth_mode,
            ssf_webhook_token=webhook_token,
            ssf_webhook_secret=webhook_secret,
            log_pii=os.getenv("SSF_LOG_PII", "false").lower() == "true",
            pii_pepper=os.getenv("SSF_PII_PEPPER", ""),
            log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
            database_path=os.getenv("SSF_DATABASE_PATH", "/app/data/ssf.db"),
            keys_dir=os.getenv("SSF_KEYS_DIR", "/app/keys"),
            apple_scim_client_id=os.getenv("APPLE_SCIM_CLIENT_ID") or None,
            apple_scim_client_secret=os.getenv("APPLE_SCIM_CLIENT_SECRET") or None,
            authentik_url=_strip_trailing_slash(os.getenv("AUTHENTIK_URL", "")),
            authentik_token=os.getenv("AUTHENTIK_TOKEN") or None,
            apple_scim_group_id=os.getenv("APPLE_SCIM_GROUP_ID") or None,
            apple_scim_sync_interval=_parse_sync_interval(os.getenv("APPLE_SCIM_SYNC_INTERVAL", "3600")),
        )

    def public_url(self, path: str) -> str:
        """Return the fully-qualified public URL for *path* (e.g. ``/jwks.json``)."""
        normalized_path = path if path.startswith("/") else f"/{path}"
        return f"{self.ssf_base_url}{normalized_path}"

    def safe_log_dict(self) -> dict[str, Union[str, int, bool]]:
        """Return a dict of non-sensitive settings suitable for startup logging."""
        return {
            "ssf_issuer": self.ssf_issuer,
            "ssf_base_url": self.ssf_base_url,
            "ssf_root_path": self.ssf_root_path,
            "ssf_container_port": self.ssf_container_port,
            "database_path": self.database_path,
            "keys_dir": self.keys_dir,
            "log_level": self.log_level,
            "ssf_webhook_auth_mode": self.ssf_webhook_auth_mode,
            "apple_scim_enabled": self.apple_scim_enabled,
        }


try:
    settings = Settings.from_env()
except (RuntimeError, ValueError) as _cfg_exc:
    import sys as _sys
    print(f"\n❌  Configuration error: {_cfg_exc}\n", file=_sys.stderr)
    _sys.exit(0)  # exit 0 → Docker restart: unless-stopped does NOT restart


def configure_logging() -> None:
    """Configure the root logger using the level from :data:`settings`.

    - Unifies log format across uvicorn and application loggers so all lines
      have the same timestamp format in Portainer.
    - Caps noisy third-party loggers at WARNING (aiosqlite, httpx, httpcore).
    """
    fmt = "%(asctime)s %(levelname)s [%(name)s] %(message)s"
    logging.basicConfig(
        level=getattr(logging, settings.log_level, logging.INFO),
        format=fmt,
    )
    # Align uvicorn's own loggers to the same format so all lines look the same
    # in Portainer (uvicorn defaults to a different format without timestamps).
    for uvicorn_logger_name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        uvicorn_log = logging.getLogger(uvicorn_logger_name)
        uvicorn_log.handlers.clear()
        uvicorn_log.propagate = True

    # Suppress noisy third-party loggers even when DEBUG is enabled globally.
    for noisy in ("aiosqlite", "httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
