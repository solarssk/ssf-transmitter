from __future__ import annotations

import logging
import os
from dataclasses import dataclass


def _strip_trailing_slash(value: str) -> str:
    return value.rstrip("/")


@dataclass(frozen=True)
class Settings:
    ssf_issuer: str
    ssf_base_url: str
    ssf_root_path: str
    ssf_container_port: int
    authentik_webhook_secret: str
    log_level: str
    database_path: str = "/app/data/ssf.db"
    keys_dir: str = "/app/keys"

    @classmethod
    def from_env(cls) -> "Settings":
        required = {
            "SSF_ISSUER": os.getenv("SSF_ISSUER"),
            "SSF_BASE_URL": os.getenv("SSF_BASE_URL"),
            "AUTHENTIK_WEBHOOK_SECRET": os.getenv("AUTHENTIK_WEBHOOK_SECRET"),
        }
        missing = [name for name, value in required.items() if not value]
        if missing:
            raise RuntimeError(f"Missing required environment variables: {', '.join(missing)}")

        return cls(
            ssf_issuer=required["SSF_ISSUER"],
            ssf_base_url=_strip_trailing_slash(required["SSF_BASE_URL"]),
            ssf_root_path=os.getenv("SSF_ROOT_PATH", ""),
            ssf_container_port=int(os.getenv("SSF_CONTAINER_PORT", "8000")),
            authentik_webhook_secret=required["AUTHENTIK_WEBHOOK_SECRET"],
            log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
            database_path=os.getenv("SSF_DATABASE_PATH", "/app/data/ssf.db"),
            keys_dir=os.getenv("SSF_KEYS_DIR", "/app/keys"),
        )

    def public_url(self, path: str) -> str:
        normalized_path = path if path.startswith("/") else f"/{path}"
        return f"{self.ssf_base_url}{normalized_path}"

    def safe_log_dict(self) -> dict[str, str | int]:
        return {
            "ssf_issuer": self.ssf_issuer,
            "ssf_base_url": self.ssf_base_url,
            "ssf_root_path": self.ssf_root_path,
            "ssf_container_port": self.ssf_container_port,
            "database_path": self.database_path,
            "keys_dir": self.keys_dir,
            "log_level": self.log_level,
        }


settings = Settings.from_env()


def configure_logging() -> None:
    logging.basicConfig(
        level=getattr(logging, settings.log_level, logging.INFO),
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )
