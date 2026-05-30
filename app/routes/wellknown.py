from fastapi import APIRouter

from app.config import settings

router = APIRouter()


@router.get("/.well-known/ssf-configuration")
async def ssf_configuration() -> dict:
    return {
        "issuer": settings.ssf_issuer,
        "jwks_uri": settings.public_url("/jwks.json"),
        "delivery_methods_supported": [
            "urn:ietf:rfc:8935",
        ],
        "configuration_endpoint": settings.public_url("/ssf/streams"),
        "add_subject_endpoint": settings.public_url("/ssf/streams/subjects:add"),
        "remove_subject_endpoint": settings.public_url("/ssf/streams/subjects:remove"),
        "status_endpoint": settings.public_url("/ssf/status"),
        "verification_endpoint": settings.public_url("/ssf/verification"),
        "authorization_schemes": [{"spec_urn": "urn:ietf:rfc:6750"}],
        "critical_subject_members": [],
        "spec_version": "1_0",
    }
