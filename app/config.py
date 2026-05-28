from __future__ import annotations

import logging
import os
from dataclasses import dataclass


def _strip_trailing_slash(value: str) -> str:
    return value.rstrip("/")


def _parse_sync_interval(value: str) -> int:
    """Parse APPLE_SCIM_SYNC_INTERVAL and raise if the result is less than 1."""
    interval = int(value)
    if interval < 1:
        raise ValueError(f"APPLE_SCIM_SYNC_INTERVAL must be >= 1 second, got {interval}")
    return interval


def _parse_management_token(value: str | None) -> str:
    """Validate SSF_MANAGEMENT_TOKEN — required, minimum 32 characters."""
    if not value:
        raise RuntimeError("Missing required environment variable: SSF_MANAGEMENT_TOKEN")
    if len(value) < 32:
        raise RuntimeError(
            f"SSF_MANAGEMENT_TOKEN is too short ({len(value)} chars); minimum is 32 characters"
        )
    return value


@dataclass(frozen=True)
class Settings:
    ssf_issuer: str
    ssf_base_url: str
    ssf_root_path: str
    ssf_container_port: int
    ssf_webhook_secret: str
    ssf_management_token: str
    log_level: str
    database_path: str = "/app/data/ssf.db"
    keys_dir: str = "/app/keys"
    # Webhook — opt-out of mandatory HMAC (unsafe, document clearly)
    allow_unsigned_webhook: bool = False
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
        required = {
            "SSF_ISSUER": os.getenv("SSF_ISSUER"),
            "SSF_BASE_URL": os.getenv("SSF_BASE_URL"),
            "SSF_WEBHOOK_SECRET": os.getenv("SSF_WEBHOOK_SECRET"),
        }
        missing = [name for name, value in required.items() if not value]
        if missing:
            raise RuntimeError(f"Missing required environment variables: {', '.join(missing)}")

        return cls(
            ssf_issuer=required["SSF_ISSUER"],
            ssf_base_url=_strip_trailing_slash(required["SSF_BASE_URL"]),
            ssf_root_path=os.getenv("SSF_ROOT_PATH", ""),
            ssf_container_port=int(os.getenv("SSF_CONTAINER_PORT", "8000")),
            ssf_webhook_secret=required["SSF_WEBHOOK_SECRET"],
            ssf_management_token=_parse_management_token(os.getenv("SSF_MANAGEMENT_TOKEN")),
            allow_unsigned_webhook=os.getenv("SSF_ALLOW_UNSIGNED_WEBHOOK", "false").lower() == "true",
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
        normalized_path = path if path.startswith("/") else f"/{path}"
        return f"{self.ssf_base_url}{normalized_path}"

    def safe_log_dict(self) -> dict[str, str | int | bool]:
        return {
            "ssf_issuer": self.ssf_issuer,
            "ssf_base_url": self.ssf_base_url,
            "ssf_root_path": self.ssf_root_path,
            "ssf_container_port": self.ssf_container_port,
            "database_path": self.database_path,
            "keys_dir": self.keys_dir,
            "log_level": self.log_level,
            "apple_scim_enabled": self.apple_scim_enabled,
        }


settings = Settings.from_env()


def configure_logging() -> None:
    logging.basicConfig(
        level=getattr(logging, settings.log_level, logging.INFO),
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )
