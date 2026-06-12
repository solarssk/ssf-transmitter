"""Root discovery page and human-friendly 404 responses."""

from __future__ import annotations

import html
import os

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

SERVICE_NAME = "SSF Transmitter"
DISCOVERY_PATH = "/.well-known/ssf-configuration"

router = APIRouter()


def app_version() -> str:
    """Return the application version from APP_VERSION (``dev`` when unset)."""
    return os.getenv("APP_VERSION", "dev")


def wants_html(request: Request) -> bool:
    """Return True when the client prefers an HTML response over JSON."""
    accept = request.headers.get("accept", "")
    if "application/json" in accept and "text/html" not in accept:
        return False
    return "text/html" in accept


def discovery_payload() -> dict[str, str]:
    """Build the JSON body for GET /."""
    return {
        "service": SERVICE_NAME,
        "version": app_version(),
        "discovery": DISCOVERY_PATH,
    }


def not_found_payload(path: str) -> dict[str, str]:
    """Build the JSON body for unmatched-route 404 responses."""
    return {
        "error": "not_found",
        "path": path,
        "hint": DISCOVERY_PATH,
    }


def is_unmatched_route(exc: StarletteHTTPException) -> bool:
    """True for router misses; False when a matched route raised HTTP 404."""
    return exc.status_code == 404 and exc.detail == "Not Found"


def exception_headers(exc: StarletteHTTPException) -> dict[str, str] | None:
    """Return response headers from the raised HTTPException, if any."""
    return exc.headers


def _discovery_html() -> str:
    """Render the HTML discovery page for GET /."""
    version = html.escape(app_version())
    discovery = html.escape(DISCOVERY_PATH)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{SERVICE_NAME}</title>
</head>
<body>
  <h1>{SERVICE_NAME}</h1>
  <p>Version {version}</p>
  <p>SSF discovery: <a href="{discovery}">{discovery}</a></p>
</body>
</html>
"""


def _not_found_html(path: str) -> str:
    """Render the HTML page for unmatched-route 404 responses."""
    safe_path = html.escape(path)
    discovery = html.escape(DISCOVERY_PATH)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Not Found — {SERVICE_NAME}</title>
</head>
<body>
  <h1>Not Found</h1>
  <p>No route for <code>{safe_path}</code>.</p>
  <p>SSF discovery: <a href="{discovery}">{discovery}</a></p>
</body>
</html>
"""


@router.get("/")
async def service_root(request: Request):
    """Minimal service discovery — public SSF metadata only, no management paths."""
    if wants_html(request):
        return HTMLResponse(_discovery_html())
    return discovery_payload()


def register_exception_handlers(app) -> None:
    """Register a 404 handler with HTML/JSON content negotiation."""

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException):
        """Map HTTP exceptions to JSON or HTML, preserving route-level details."""
        headers = exception_headers(exc)
        if is_unmatched_route(exc):
            path = request.url.path
            if wants_html(request):
                return HTMLResponse(_not_found_html(path), status_code=404, headers=headers)
            return JSONResponse(not_found_payload(path), status_code=404, headers=headers)
        return JSONResponse(
            {"detail": exc.detail},
            status_code=exc.status_code,
            headers=headers,
        )
