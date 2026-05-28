"""Tests for SSRF protection in validate_receiver_endpoint_url.

DNS resolution is mocked so tests are hermetic and fast.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from app.security.url_validation import validate_receiver_endpoint_url

# Public IP to return for safe hosts in mock
_PUBLIC_IP = "93.184.216.34"  # example.com


def _mock_resolve(public_ips: list[str] = None):
    """Return a patch for _resolve_host that returns the given IPs."""
    ips = public_ips if public_ips is not None else [_PUBLIC_IP]
    return patch("app.security.url_validation._resolve_host", return_value=ips)


# ---------------------------------------------------------------------------
# Scheme validation
# ---------------------------------------------------------------------------


def test_http_scheme_rejected():
    with _mock_resolve(), pytest.raises(ValueError, match="scheme must be 'https'"):
        validate_receiver_endpoint_url("http://receiver.example.com/events")


def test_file_scheme_rejected():
    with pytest.raises(ValueError):
        validate_receiver_endpoint_url("file:///etc/passwd")


def test_gopher_scheme_rejected():
    with pytest.raises(ValueError):
        validate_receiver_endpoint_url("gopher://example.com/")


# ---------------------------------------------------------------------------
# Credential / fragment / malformed
# ---------------------------------------------------------------------------


def test_credentials_in_url_rejected():
    with _mock_resolve(), pytest.raises(ValueError, match="credentials"):
        validate_receiver_endpoint_url("https://user:pass@example.com/events")


def test_fragment_rejected():
    with _mock_resolve(), pytest.raises(ValueError, match="fragment"):
        validate_receiver_endpoint_url("https://receiver.example.com/events#section")


def test_userinfo_host_confusion_rejected():
    """https://example.com@127.0.0.1/ must be rejected as credentials."""
    with pytest.raises(ValueError):
        validate_receiver_endpoint_url("https://example.com@127.0.0.1/")


# ---------------------------------------------------------------------------
# Blocked IP literals
# ---------------------------------------------------------------------------


def test_localhost_literal_rejected():
    with pytest.raises(ValueError):
        validate_receiver_endpoint_url("https://localhost/events")


def test_127_0_0_1_rejected():
    with pytest.raises(ValueError):
        validate_receiver_endpoint_url("https://127.0.0.1/events")


def test_ipv6_loopback_rejected():
    with pytest.raises(ValueError):
        validate_receiver_endpoint_url("https://[::1]/events")


def test_rfc1918_10_rejected():
    with pytest.raises(ValueError):
        validate_receiver_endpoint_url("https://10.0.0.10/events")


def test_rfc1918_172_rejected():
    with pytest.raises(ValueError):
        validate_receiver_endpoint_url("https://172.16.0.1/events")


def test_rfc1918_192_168_rejected():
    with pytest.raises(ValueError):
        validate_receiver_endpoint_url("https://192.168.1.10/events")


def test_link_local_metadata_ip_rejected():
    with pytest.raises(ValueError):
        validate_receiver_endpoint_url("https://169.254.169.254/latest/meta-data")


# ---------------------------------------------------------------------------
# Blocked via DNS resolution
# ---------------------------------------------------------------------------


def test_hostname_resolving_to_private_ip_rejected():
    """A hostname that resolves to a private IP must be rejected."""
    mock = patch("app.security.url_validation._resolve_host", return_value=["192.168.0.1"])
    with mock, pytest.raises(ValueError, match="blocked IP"):
        validate_receiver_endpoint_url("https://internal.example.com/events")


def test_hostname_resolving_to_loopback_rejected():
    mock = patch("app.security.url_validation._resolve_host", return_value=["127.0.0.1"])
    with mock, pytest.raises(ValueError, match="blocked IP"):
        validate_receiver_endpoint_url("https://local.example.com/events")


def test_unresolvable_host_rejected():
    """A host that cannot be resolved must be rejected."""
    mock = patch("app.security.url_validation._resolve_host", return_value=[])
    with mock, pytest.raises(ValueError, match="did not resolve"):
        validate_receiver_endpoint_url("https://nxdomain.example.invalid/events")


# ---------------------------------------------------------------------------
# Allowlist
# ---------------------------------------------------------------------------


def test_host_not_in_allowlist_rejected():
    with _mock_resolve(), pytest.raises(ValueError, match="allowlist"):
        validate_receiver_endpoint_url(
            "https://other.example.com/events",
            allowed_hosts=["approved.example.com"],
        )


def test_host_in_allowlist_accepted():
    with _mock_resolve():
        result = validate_receiver_endpoint_url(
            "https://approved.example.com/events",
            allowed_hosts=["approved.example.com"],
        )
    assert result == "https://approved.example.com/events"


# ---------------------------------------------------------------------------
# Valid URL
# ---------------------------------------------------------------------------


def test_valid_https_url_accepted():
    """A well-formed HTTPS URL resolving to a public IP is accepted."""
    with _mock_resolve([_PUBLIC_IP]):
        result = validate_receiver_endpoint_url("https://receiver.example.test/events")
    assert result == "https://receiver.example.test/events"


def test_valid_url_with_port_accepted():
    """HTTPS URL with non-standard port is accepted (port filtering is optional)."""
    with _mock_resolve([_PUBLIC_IP]):
        result = validate_receiver_endpoint_url("https://receiver.example.test:8443/events")
    assert result == "https://receiver.example.test:8443/events"


# ---------------------------------------------------------------------------
# Stream creation rejects SSRF payloads (integration)
# ---------------------------------------------------------------------------


def test_post_stream_rejects_ssrf_endpoint_url():
    """POST /ssf/streams with a private endpoint_url returns 400."""
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as client:
        resp = client.post(
            "/ssf/streams",
            json={
                "aud": "test",
                "delivery": {
                    "endpoint_url": "https://169.254.169.254/latest/meta-data",
                },
            },
            headers={"Authorization": "Bearer test_management_token_min_32_chars_1234"},
        )
    assert resp.status_code == 400
    assert "endpoint_url" in resp.json()["detail"].lower()
