"""Environment-based application settings and logging configuration."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from urllib.parse import urlparse


class _HealthcheckFilter(logging.Filter):
    """Suppress uvicorn access log entries for Docker healthcheck requests.

    The healthcheck hits /jwks.json from 127.0.0.1 every 30 s — logging it
    at any level (even DEBUG) floods Portainer. Drop it completely.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        """Return False for Docker healthcheck access log lines."""
        msg = record.getMessage()
        return not ("127.0.0.1" in msg and "/jwks.json" in msg)

_WEBHOOK_AUTH_MODES = {"bearer", "hmac", "unsigned"}
_APPLE_SCIM_UPDATE_MODES = {
    "patch_all",
    "external_id_only",
    "emails_only",
    "username_only",
    "replace_all",
}


def _strip_trailing_slash(value: str) -> str:
    """Remove any trailing slashes from *value*."""
    return value.rstrip("/")


def _parse_https_url(value: str, env_name: str) -> str:
    """Validate that value is a well-formed HTTPS URL; raise ValueError otherwise."""
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError(
            f"{env_name} must be a valid HTTPS URL, got {value!r}"
        )
    return value


def _parse_sync_interval(value: str) -> int:
    """Parse APPLE_SCIM_SYNC_INTERVAL and raise if the result is less than 1."""
    interval = int(value)
    if interval < 1:
        raise ValueError(f"APPLE_SCIM_SYNC_INTERVAL must be >= 1 second, got {interval}")
    return interval


def _parse_apple_scim_update_mode(value: str | None) -> str:
    """Validate APPLE_SCIM_UPDATE_MODE against the supported experiment set."""
    mode = (value or "patch_all").strip().lower()
    if mode not in _APPLE_SCIM_UPDATE_MODES:
        raise ValueError(
            "APPLE_SCIM_UPDATE_MODE must be one of: "
            f"{', '.join(sorted(_APPLE_SCIM_UPDATE_MODES))}"
        )
    return mode


def _parse_management_token(value: str | None) -> str:
    """Validate SSF_MANAGEMENT_TOKEN — required, minimum 32 characters."""
    if not value:
        raise RuntimeError("Missing required environment variable: SSF_MANAGEMENT_TOKEN")
    if len(value) < 32:
        raise RuntimeError(
            f"SSF_MANAGEMENT_TOKEN is too short ({len(value)} chars); minimum is 32 characters"
        )
    return value


def _parse_webhook_auth_mode(value: str | None, allow_unsigned_legacy: bool) -> str:
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


def _parse_webhook_token(value: str | None, mode: str) -> str | None:
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


def _parse_allowed_receiver_hosts(value: str | None) -> list[str]:
    """Parse SSF_ALLOWED_RECEIVER_HOSTS — comma-separated hostname allowlist."""
    if not value:
        return []
    return [h.strip().lower() for h in value.split(",") if h.strip()]


def _parse_log_level(value: str | None) -> str:
    """Validate log level value."""
    level = (value or "INFO").upper()
    valid = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
    if level not in valid:
        raise ValueError(
            f"SSF_LOG_LEVEL must be one of {', '.join(sorted(valid))}, got {level!r}"
        )
    return level


def _parse_webhook_secret(value: str | None, mode: str) -> str:
    """Validate SSF_WEBHOOK_SECRET — required when mode is 'hmac'."""
    if mode == "hmac" and not value:
        raise RuntimeError(
            "Missing required environment variable: SSF_WEBHOOK_SECRET "
            "(required when SSF_WEBHOOK_AUTH_MODE=hmac)"
        )
    return value or ""


@dataclass(frozen=True)
class Settings:
    """Application configuration loaded from environment variables."""

    ssf_issuer: str
    ssf_base_url: str
    ssf_root_path: str
    ssf_container_port: int
    ssf_management_token: str
    log_level: str
    # Webhook authentication
    ssf_webhook_auth_mode: str = "bearer"   # bearer | hmac | unsigned
    ssf_webhook_token: str | None = None    # required in bearer mode
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
    apple_scim_client_id: str | None = None
    apple_scim_client_secret: str | None = None
    authentik_url: str | None = None
    authentik_token: str | None = None
    apple_scim_group_id: str | None = None  # sync only members of this Authentik group UUID
    apple_scim_sync_interval: int = 3600    # seconds between automatic syncs (default: 1 hour)
    apple_scim_alert_webhook_url: str | None = None  # POST alerts here when re-auth is needed
    apple_scim_authorize_url: str = "https://appleid.apple.com/auth/oauth2/v2/authorize"
    apple_scim_token_url: str = "https://appleid.apple.com/auth/oauth2/v2/token"
    apple_scim_log_error_body: bool = False
    apple_scim_update_mode: str = "patch_all"
    # Set true to suppress the startup warning when SSF_ISSUER differs from SSF_BASE_URL.
    # Only needed during migration from older deployments where these values diverge.
    ssf_allow_custom_issuer: bool = False
    # Set SSF_LOG_COLOR=true to enable ANSI color output — Portainer renders ANSI codes.
    # Requires the optional `colorlog` package; falls back to plain text if not installed.
    ssf_log_color: bool = False
    # Set SSF_LOG_RECEIVER_ERROR_BODY=true only during controlled troubleshooting.
    # When false, receiver error bodies are never logged; only a body hash is logged.
    ssf_log_receiver_error_body: bool = False
    # Expose Swagger UI (/docs), ReDoc (/redoc), and /openapi.json. Default false.
    ssf_enable_openapi: bool = False
    # Optional receiver hostname allowlist for SSRF defence-in-depth.
    ssf_allowed_receiver_hosts: list[str] = field(default_factory=list)
    # Optional dedicated key for encrypting receiver tokens at rest; None = derive from management token.
    ssf_token_encryption_key: str | None = None

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

        for var_name, var_value in required.items():
            try:
                _parse_https_url(var_value, var_name)
            except ValueError as exc:
                raise RuntimeError(str(exc)) from exc

        allow_unsigned = os.getenv("SSF_ALLOW_UNSIGNED_WEBHOOK", "false").lower() == "true"
        auth_mode = _parse_webhook_auth_mode(os.getenv("SSF_WEBHOOK_AUTH_MODE"), allow_unsigned)
        webhook_token = _parse_webhook_token(os.getenv("SSF_WEBHOOK_TOKEN"), auth_mode)
        webhook_secret = _parse_webhook_secret(os.getenv("SSF_WEBHOOK_SECRET"), auth_mode)

        return cls(
            ssf_issuer=_parse_https_url(required["SSF_ISSUER"], "SSF_ISSUER"),
            ssf_base_url=_strip_trailing_slash(
                _parse_https_url(required["SSF_BASE_URL"], "SSF_BASE_URL")
            ),
            ssf_root_path=os.getenv("SSF_ROOT_PATH", ""),
            ssf_container_port=int(os.getenv("SSF_CONTAINER_PORT", "8000")),
            ssf_management_token=_parse_management_token(os.getenv("SSF_MANAGEMENT_TOKEN")),
            ssf_webhook_auth_mode=auth_mode,
            ssf_webhook_token=webhook_token,
            ssf_webhook_secret=webhook_secret,
            log_pii=os.getenv("SSF_LOG_PII", "false").lower() == "true",
            pii_pepper=os.getenv("SSF_PII_PEPPER", ""),
            log_level=_parse_log_level(
                os.getenv("SSF_LOG_LEVEL", os.getenv("LOG_LEVEL", "INFO"))
            ),
            database_path=os.getenv("SSF_DATABASE_PATH", "/app/data/ssf.db"),
            keys_dir=os.getenv("SSF_KEYS_DIR", "/app/keys"),
            apple_scim_client_id=os.getenv("APPLE_SCIM_CLIENT_ID") or None,
            apple_scim_client_secret=os.getenv("APPLE_SCIM_CLIENT_SECRET") or None,
            authentik_url=(
                _strip_trailing_slash(os.getenv("AUTHENTIK_URL"))
                if os.getenv("AUTHENTIK_URL")
                else None
            ),
            authentik_token=os.getenv("AUTHENTIK_TOKEN") or None,
            apple_scim_group_id=os.getenv("APPLE_SCIM_GROUP_ID") or None,
            apple_scim_sync_interval=_parse_sync_interval(os.getenv("APPLE_SCIM_SYNC_INTERVAL", "3600")),
            apple_scim_alert_webhook_url=_parse_https_url(
                os.getenv("APPLE_SCIM_ALERT_WEBHOOK_URL", ""),
                "APPLE_SCIM_ALERT_WEBHOOK_URL",
            ) if os.getenv("APPLE_SCIM_ALERT_WEBHOOK_URL") else None,
            apple_scim_authorize_url=_parse_https_url(
                os.getenv("APPLE_SCIM_AUTHORIZE_URL", "https://appleid.apple.com/auth/oauth2/v2/authorize"),
                "APPLE_SCIM_AUTHORIZE_URL",
            ),
            apple_scim_token_url=_parse_https_url(
                os.getenv("APPLE_SCIM_TOKEN_URL", "https://appleid.apple.com/auth/oauth2/v2/token"),
                "APPLE_SCIM_TOKEN_URL",
            ),
            apple_scim_log_error_body=os.getenv("APPLE_SCIM_LOG_ERROR_BODY", "false").lower() == "true",
            apple_scim_update_mode=_parse_apple_scim_update_mode(os.getenv("APPLE_SCIM_UPDATE_MODE")),
            ssf_allow_custom_issuer=os.getenv("SSF_ALLOW_CUSTOM_ISSUER", "false").lower() == "true",
            ssf_log_color=os.getenv("SSF_LOG_COLOR", "false").lower() == "true",
            ssf_log_receiver_error_body=os.getenv("SSF_LOG_RECEIVER_ERROR_BODY", "false").lower() == "true",
            ssf_enable_openapi=os.getenv("SSF_ENABLE_OPENAPI", "false").lower() == "true",
            ssf_allowed_receiver_hosts=_parse_allowed_receiver_hosts(
                os.getenv("SSF_ALLOWED_RECEIVER_HOSTS")
            ),
            ssf_token_encryption_key=os.getenv("SSF_TOKEN_ENCRYPTION_KEY") or None,
        )

    def public_url(self, path: str) -> str:
        """Return the fully-qualified public URL for *path* (e.g. ``/jwks.json``)."""
        normalized_path = path if path.startswith("/") else f"/{path}"
        return f"{self.ssf_base_url}{normalized_path}"

    def safe_log_dict(self) -> dict[str, str | int | bool]:
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
            "apple_scim_group_filter_enabled": bool(self.apple_scim_group_id),
            "apple_scim_group_id": self.apple_scim_group_id or "",
            "apple_scim_update_mode": self.apple_scim_update_mode,
            "apple_scim_log_error_body": self.apple_scim_log_error_body,
            "ssf_enable_openapi": self.ssf_enable_openapi,
            "ssf_allowed_receiver_hosts_count": len(self.ssf_allowed_receiver_hosts),
            "token_encryption_key_dedicated": bool(self.ssf_token_encryption_key),
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
    - When SSF_LOG_COLOR=true, uses colorlog for ANSI-coloured output (Portainer
      renders ANSI codes). Falls back to plain text if colorlog is not installed.
    """
    level = getattr(logging, settings.log_level, logging.INFO)
    plain_fmt = "%(asctime)s %(levelname)s [%(name)s] %(message)s"

    formatter: logging.Formatter = logging.Formatter(plain_fmt)
    if settings.ssf_log_color:
        try:
            import colorlog  # optional dependency
            formatter = colorlog.ColoredFormatter(
                "%(log_color)s%(asctime)s %(levelname)s%(reset)s [%(name)s] %(message)s",
                log_colors={
                    "DEBUG": "cyan",
                    "INFO": "green",
                    "WARNING": "yellow",
                    "ERROR": "red",
                    "CRITICAL": "bold_red",
                },
            )
        except ImportError:
            pass  # colorlog not installed — plain text fallback already set

    logging.basicConfig(level=level, format=plain_fmt)
    for handler in logging.root.handlers:
        handler.setFormatter(formatter)
    # Align uvicorn's own loggers to the same format so all lines look the same
    # in Portainer (uvicorn defaults to a different format without timestamps).
    for uvicorn_logger_name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        uvicorn_log = logging.getLogger(uvicorn_logger_name)
        uvicorn_log.handlers.clear()
        uvicorn_log.propagate = True
    logging.getLogger("uvicorn.access").addFilter(_HealthcheckFilter())

    # Suppress noisy third-party loggers even when DEBUG is enabled globally.
    for noisy in ("aiosqlite", "httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
