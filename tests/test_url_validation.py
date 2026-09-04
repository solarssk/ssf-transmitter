"""Tests for SSRF protection in validate_receiver_endpoint_url.

DNS resolution is mocked so tests are hermetic and fast.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from app.security.url_validation import _is_blocked_ip, receiver_host_allowed, validate_receiver_endpoint_url

# Public IP to return for safe hosts in mock
_PUBLIC_IP = "93.184.216.34"  # example.com


def _mock_resolve(public_ips: list[str] | None = None):
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
# IPv4-mapped / embedded-IPv4 IPv6 literals — a blocked IPv4 address wrapped
# in one of these forms is a distinct IPv6Address that `addr in ipv4_network`
# silently (no exception) never matches, unless unwrapped first.
# ---------------------------------------------------------------------------


def test_ipv4_mapped_metadata_ip_rejected():
    with pytest.raises(ValueError):
        validate_receiver_endpoint_url("https://[::ffff:169.254.169.254]/latest/meta-data")


def test_ipv4_mapped_rfc1918_rejected():
    with pytest.raises(ValueError):
        validate_receiver_endpoint_url("https://[::ffff:10.0.0.1]/events")


def test_ipv4_mapped_public_ip_accepted():
    with _mock_resolve():
        validate_receiver_endpoint_url("https://[::ffff:8.8.8.8]/events")


def test_is_blocked_ip_unwraps_ipv4_mapped():
    assert _is_blocked_ip("::ffff:169.254.169.254") is True
    assert _is_blocked_ip("::ffff:10.0.0.1") is True
    assert _is_blocked_ip("::ffff:8.8.8.8") is False


def test_is_blocked_ip_unwraps_6to4_embedded_metadata_ip():
    # 2002:a9fe:a9fe:: encodes 169.254.169.254 in 6to4 (2002::/16) form.
    assert _is_blocked_ip("2002:a9fe:a9fe::") is True


def test_ipv4_via_nat64_metadata_ip_rejected():
    """Regression test: NAT64's well-known prefix (64:ff9b::/96, RFC 6052)
    embeds an IPv4 address the same way ipv4_mapped/sixtofour/teredo do,
    but Python's ipaddress module has no dedicated property for it — the
    original fix's unwrap logic missed this form entirely.
    """
    with pytest.raises(ValueError):
        validate_receiver_endpoint_url("https://[64:ff9b::a9fe:a9fe]/latest/meta-data")


def test_ipv4_via_nat64_rfc1918_rejected():
    with pytest.raises(ValueError):
        validate_receiver_endpoint_url("https://[64:ff9b::a00:1]/events")


def test_ipv4_via_ipv4_compatible_metadata_ip_rejected():
    """::169.254.169.254 (IPv4-compatible, RFC4291 §2.5.5.1, deprecated but
    still parseable) — same missing-unwrap gap as NAT64 above."""
    with pytest.raises(ValueError):
        validate_receiver_endpoint_url("https://[::169.254.169.254]/latest/meta-data")


def test_is_blocked_ip_unwraps_nat64():
    assert _is_blocked_ip("64:ff9b::a9fe:a9fe") is True
    assert _is_blocked_ip("64:ff9b::a00:1") is True
    assert _is_blocked_ip("64:ff9b::808:808") is False


def test_is_blocked_ip_unwraps_ipv4_compatible():
    assert _is_blocked_ip("::169.254.169.254") is True
    assert _is_blocked_ip("::") is True  # 0.0.0.0, blocked via 0.0.0.0/8
    assert _is_blocked_ip("::8.8.8.8") is False


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


def test_receiver_host_allowed_empty_allowlist_permits_any_host():
    assert receiver_host_allowed("https://anything.example.com/events", []) is True


def test_receiver_host_allowed_enforces_exact_host_match():
    allowed = ["approved.example.com"]
    assert receiver_host_allowed("https://approved.example.com/events", allowed) is True
    assert receiver_host_allowed("https://other.example.com/events", allowed) is False


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
