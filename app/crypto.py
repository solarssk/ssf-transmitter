"""RSA key management and Security Event Token (SET) JWT signing."""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import time
import uuid
from pathlib import Path
from typing import Any

import jwt
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.config import settings

logger = logging.getLogger(__name__)

_FERNET_PREFIX = "fernet1:"
_FERNET_BLOB_PREFIX = "gAAAA"


class TokenDecryptionError(Exception):
    """Raised when a versioned at-rest token cannot be decrypted."""


def _looks_like_fernet_ciphertext(value: str) -> bool:
    """Heuristic for Fernet tokens stored before the ``fernet1:`` version prefix."""
    return value.startswith(_FERNET_BLOB_PREFIX) and len(value) > 100


PRIVATE_KEY_PATH = "private.pem"
JWKS_PATH = "jwks.json"


def _b64url_uint(value: int) -> str:
    """Encode an unsigned integer as a base64url string without padding."""
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _public_jwk(private_key: rsa.RSAPrivateKey) -> dict[str, str]:
    """Build a JWK dict for the public half of an RSA signing key."""
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
    """Generate RSA signing key and JWKS if they do not already exist."""
    keys_dir = Path(settings.keys_dir)
    keys_dir.mkdir(parents=True, exist_ok=True)
    private_path = keys_dir / PRIVATE_KEY_PATH
    jwks_path = keys_dir / JWKS_PATH

    if private_path.exists() and jwks_path.exists():
        logger.info("Loaded existing SSF signing key and JWKS from %s", keys_dir)
        return

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
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
    """Load and return the JWKS from disk."""
    with open(Path(settings.keys_dir) / JWKS_PATH, encoding="utf-8") as jwks_file:
        return json.load(jwks_file)


def _load_signing_material() -> tuple[str, str]:
    """Return (private_pem, kid) for JWT signing."""
    private_pem = (Path(settings.keys_dir) / PRIVATE_KEY_PATH).read_text(encoding="utf-8")
    jwks = load_jwks()
    if not jwks.get("keys"):
        raise RuntimeError(
            f"JWKS at {settings.keys_dir}/{JWKS_PATH} contains no keys — "
            "delete the keys directory and restart to regenerate"
        )
    kid = jwks["keys"][0].get("kid")
    if not kid:
        raise RuntimeError(
            f"First key in JWKS at {settings.keys_dir}/{JWKS_PATH} is missing 'kid' — "
            "delete the keys directory and restart to regenerate"
        )
    return private_pem, kid


def sign_set(
    event_uri: str,
    audience: str,
    email: str,
    *,
    event_payload: dict[str, Any] | None = None,
    txn: str | None = None,
) -> str:
    """Sign a Security Event Token (SET) JWT for the given event and subject email.

    Conforms to SSF Framework 1.0 (final):
    - ``sub_id`` at top level with ``format: email`` (SSF §5.1)
    - ``aud`` as single-element array (RFC 7519 §4.1.3)
    - ``typ: secevent+jwt`` header (RFC 8417 §2.3)
    - ``txn`` included per SSF SHOULD requirement; falls back to a fresh UUID
    - No ``exp`` or ``sub`` claims
    """
    private_pem, kid = _load_signing_material()
    payload = {
        "iss": settings.ssf_issuer,
        "iat": int(time.time()),
        "jti": str(uuid.uuid4()),
        "aud": [audience],
        "txn": txn or str(uuid.uuid4()),
        "sub_id": {
            "format": "email",
            "email": email,
        },
        "events": {
            event_uri: event_payload if event_payload is not None else {},
        },
    }
    return jwt.encode(payload, private_pem, algorithm="RS256", headers={"kid": kid, "typ": "secevent+jwt"})


def sign_verification_set(audience: str, stream_id: str, state: str | None = None) -> str:
    """Sign a verification SET JWT as defined in the SSF specification.

    Event type URI follows SSF Framework §6.2:
    ``https://schemas.openid.net/secevent/ssf/event-type/verification``

    Other conformance notes:
    - ``aud`` encoded as single-element array (RFC 7519 §4.1.3)
    - ``sub_id`` with ``format: opaque`` and the stream UUID as identifier
    - ``typ: secevent+jwt`` header (RFC 8417 §2.3)
    - ``state`` is omitted when the transmitter initiates verification (RFC 8417:
      "If the Transmitter is initiating the verification, SHOULD omit state")
    """
    private_pem, kid = _load_signing_material()
    event_payload: dict = {}
    if state is not None:
        event_payload["state"] = state
    payload = {
        "iss": settings.ssf_issuer,
        "iat": int(time.time()),
        "jti": str(uuid.uuid4()),
        "aud": [audience],
        "sub_id": {"format": "opaque", "id": stream_id},
        "events": {
            "https://schemas.openid.net/secevent/ssf/event-type/verification": event_payload,
        },
    }
    return jwt.encode(payload, private_pem, algorithm="RS256", headers={"kid": kid, "typ": "secevent+jwt"})


def _get_token_encryption_key() -> bytes:
    """Derive a Fernet key from SSF_TOKEN_ENCRYPTION_KEY or SSF_MANAGEMENT_TOKEN."""
    raw = settings.ssf_token_encryption_key or settings.ssf_management_token
    key_bytes = hashlib.sha256(raw.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(key_bytes)


def encrypt_token(plaintext: str) -> str:
    """Encrypt a receiver endpoint token for storage in SQLite."""
    if not plaintext:
        return ""
    fernet = Fernet(_get_token_encryption_key())
    encrypted = fernet.encrypt(plaintext.encode("utf-8")).decode("utf-8")
    return f"{_FERNET_PREFIX}{encrypted}"


def _decrypt_fernet_blob(blob: str) -> str:
    """Decrypt a Fernet ciphertext blob; never fall back to returning the blob."""
    fernet = Fernet(_get_token_encryption_key())
    try:
        return fernet.decrypt(blob.encode("utf-8")).decode("utf-8")
    except InvalidToken as exc:
        logger.warning(
            "decrypt_token: InvalidToken on encrypted receiver token — "
            "SSF_TOKEN_ENCRYPTION_KEY or SSF_MANAGEMENT_TOKEN may have changed; "
            "re-register the stream with delivery.endpoint_url_token"
        )
        raise TokenDecryptionError(
            "Receiver endpoint token cannot be decrypted — re-register the stream"
        ) from exc


def decrypt_token(ciphertext: str) -> str:
    """Decrypt a receiver endpoint token retrieved from SQLite."""
    if not ciphertext:
        return ""
    if ciphertext.startswith(_FERNET_PREFIX):
        return _decrypt_fernet_blob(ciphertext[len(_FERNET_PREFIX):])
    if _looks_like_fernet_ciphertext(ciphertext):
        return _decrypt_fernet_blob(ciphertext)
    # Legacy plaintext token from deployments before at-rest encryption.
    return ciphertext
