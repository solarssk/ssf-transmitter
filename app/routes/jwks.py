from fastapi import APIRouter

from app.crypto import load_jwks

router = APIRouter()


@router.get("/jwks.json")
async def jwks() -> dict:
    return load_jwks()
