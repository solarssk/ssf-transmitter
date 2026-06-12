"""Public JWKS endpoint for SET signature verification."""

from fastapi import APIRouter

from app.crypto import load_jwks

router = APIRouter()


@router.get("/jwks.json")
async def jwks() -> dict:
    """Return the public JWKS used to verify RS256-signed SETs."""
    return load_jwks()
