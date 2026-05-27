import base64
import hashlib
import json
import logging
import time
import uuid
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import jwt

from app.config import settings

logger = logging.getLogger(__name__)

PRIVATE_KEY_PATH = "private.pem"
JWKS_PATH = "jwks.json"


def _b64url_uint(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _public_jwk(private_key: rsa.RSAPrivateKey) -> dict[str, str]:
    public_key = private_key.public_key()
    numbers = public_key.public_numbers()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    kid = hashlib.sha256(public_pem).hexdigest()[:8]
    return {
        "kty": "RSA",
        "use": "sig",
        "kid": kid,
        "alg": "RS256",
        "n": _b64url_uint(numbers.n),
        "e": _b64url_uint(numbers.e),
    }


def ensure_keys() -> None:
    keys_dir = Path(settings.keys_dir)
    keys_dir.mkdir(parents=True, exist_ok=True)
    private_path = keys_dir / PRIVATE_KEY_PATH
    jwks_path = keys_dir / JWKS_PATH

    if private_path.exists() and jwks_path.exists():
        logger.info("Loaded existing SSF signing key and JWKS from %s", keys_dir)
        return

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    private_path.write_bytes(private_pem)
    private_path.chmod(0o600)
    jwks_path.write_text(json.dumps({"keys": [_public_jwk(private_key)]}, indent=2), encoding="utf-8")
    logger.info("Generated new RSA signing key and JWKS in %s", keys_dir)


def load_jwks() -> dict[str, Any]:
    with open(Path(settings.keys_dir) / JWKS_PATH, encoding="utf-8") as jwks_file:
        return json.load(jwks_file)


def sign_set(event_uri: str, audience: str, email: str) -> str:
    private_path = Path(settings.keys_dir) / PRIVATE_KEY_PATH
    private_pem = private_path.read_text(encoding="utf-8")
    kid = load_jwks()["keys"][0]["kid"]
    payload = {
        "iss": settings.ssf_issuer,
        "iat": int(time.time()),
        "jti": str(uuid.uuid4()),
        "aud": audience,
        "events": {
            event_uri: {
                "subject": {
                    "format": "email",
                    "email": email,
                }
            }
        },
    }
    return jwt.encode(payload, private_pem, algorithm="RS256", headers={"kid": kid})
