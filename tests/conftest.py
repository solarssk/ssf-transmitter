import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TESTDATA = ROOT / ".testdata"

os.environ.setdefault("SSF_ISSUER", "https://idp.example.com/application/o/apple-id/")
os.environ.setdefault("SSF_BASE_URL", "https://idp.example.com/shared-signals")
os.environ.setdefault("SSF_ROOT_PATH", "/shared-signals")
os.environ.setdefault("SSF_CONTAINER_PORT", "8000")
os.environ.setdefault("SSF_WEBHOOK_SECRET", "test_secret_min_32_chars_1234567890")
os.environ.setdefault("LOG_LEVEL", "INFO")
os.environ.setdefault("SSF_DATABASE_PATH", str(TESTDATA / "ssf.db"))
os.environ.setdefault("SSF_KEYS_DIR", str(TESTDATA / "keys"))
