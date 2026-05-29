import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TESTDATA = ROOT / ".testdata"

os.environ.setdefault("SSF_ISSUER", "https://idp.example.com/application/o/apple-id/")
os.environ.setdefault("SSF_BASE_URL", "https://idp.example.com/shared-signals")
os.environ.setdefault("SSF_ROOT_PATH", "/shared-signals")
os.environ.setdefault("SSF_CONTAINER_PORT", "8000")
os.environ.setdefault("SSF_WEBHOOK_SECRET", "test_secret_min_32_chars_1234567890")
os.environ.setdefault("SSF_MANAGEMENT_TOKEN", "test_management_token_min_32_chars_1234")
os.environ.setdefault("SSF_WEBHOOK_TOKEN", "test_webhook_token_min_32_chars_1234567")
# Default test mode is hmac so existing HMAC-based tests keep working unchanged.
# Bearer/unsigned tests override settings via dataclasses.replace() + monkeypatch.
os.environ.setdefault("SSF_WEBHOOK_AUTH_MODE", "hmac")
os.environ.setdefault("LOG_LEVEL", "INFO")
os.environ.setdefault("SSF_DATABASE_PATH", str(TESTDATA / "ssf.db"))
os.environ.setdefault("SSF_KEYS_DIR", str(TESTDATA / "keys"))


@pytest.fixture(autouse=True)
def mock_push_verification_set(monkeypatch):
    """Prevent real outbound HTTP calls during stream creation tests."""

    async def _always_ok(stream) -> bool:
        return True

    monkeypatch.setattr("app.routes.streams.push_verification_set", _always_ok)


@pytest.fixture(autouse=True)
def mock_dns_resolve(monkeypatch):
    """Return a public IP for all DNS lookups so SSRF validation passes in tests.

    Tests in test_url_validation.py override this with their own mocks to
    exercise specific rejection paths (private IPs, unresolvable hosts, etc.).

    Patches both the url_validation module (used at stream create/patch time)
    and the pusher module (used at delivery time for DNS rebinding protection).
    """
    _public_ip = lambda host: ["93.184.216.34"]  # noqa: E731  # example.com
    monkeypatch.setattr("app.security.url_validation._resolve_host", _public_ip)
    monkeypatch.setattr("app.events.pusher._resolve_host", _public_ip)
