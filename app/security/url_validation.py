"""SSRF protection for receiver endpoint URLs.

Called when creating or updating an SSF stream to validate that the
endpoint_url points to a safe public host.

Rejects:
- Non-HTTPS schemes
- URLs with credentials (user:pass)
- Fragment (#anchor)
- Private/reserved IP ranges (RFC1918, loopback, link-local, cloud metadata)
- Hosts that resolve to any private IP
- HTTP redirects (follow_redirects=False enforced in pusher)

Optional allowlist:
  SSF_ALLOWED_RECEIVER_HOSTS=host1.example.com,host2.example.com
  If set, endpoint host must match one of these exactly.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# IP networks that are never acceptable as receiver targets
# Hostnames that are always blocked regardless of DNS resolution
_BLOCKED_HOSTNAMES = {
    "localhost",
    "metadata.google.internal",  # GCE metadata
    "169.254.169.254",            # also caught as bare IP, belt-and-suspenders
}

_BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),          # "This" network
    ipaddress.ip_network("10.0.0.0/8"),          # RFC1918 private
    ipaddress.ip_network("100.64.0.0/10"),       # Shared address space
    ipaddress.ip_network("127.0.0.0/8"),         # Loopback
    ipaddress.ip_network("169.254.0.0/16"),      # Link-local / cloud metadata
    ipaddress.ip_network("172.16.0.0/12"),       # RFC1918 private
    ipaddress.ip_network("192.0.0.0/24"),        # IETF protocol assignments
    ipaddress.ip_network("192.0.2.0/24"),        # TEST-NET-1 (documentation)
    ipaddress.ip_network("192.168.0.0/16"),      # RFC1918 private
    ipaddress.ip_network("198.18.0.0/15"),       # Benchmarking
    ipaddress.ip_network("198.51.100.0/24"),     # TEST-NET-2 (documentation)
    ipaddress.ip_network("203.0.113.0/24"),      # TEST-NET-3 (documentation)
    ipaddress.ip_network("224.0.0.0/4"),         # Multicast
    ipaddress.ip_network("240.0.0.0/4"),         # Reserved
    ipaddress.ip_network("255.255.255.255/32"),  # Broadcast
    # IPv6
    ipaddress.ip_network("::1/128"),             # Loopback
    ipaddress.ip_network("fc00::/7"),            # Unique local
    ipaddress.ip_network("fe80::/10"),           # Link-local
    ipaddress.ip_network("ff00::/8"),            # Multicast
]


def _is_blocked_ip(ip_str: str) -> bool:
    """Return True if the IP address falls into a blocked network range."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # unparseable → treat as blocked
    return any(addr in net for net in _BLOCKED_NETWORKS)


def _resolve_host(host: str) -> list[str]:
    """Resolve hostname to a list of IP address strings.

    Returns an empty list on resolution failure (NXDOMAIN, timeout, etc.).
    """
    try:
        results = socket.getaddrinfo(host, None)
        return [r[4][0] for r in results]
    except OSError:
        return []


def validate_receiver_endpoint_url(url: str, allowed_hosts: list[str] | None = None) -> str:
    """Validate that *url* is a safe public HTTPS endpoint.

    Args:
        url: The endpoint URL to validate.
        allowed_hosts: Optional explicit allowlist. If provided, the URL's
            host must be in this list (exact match). Pass
            ``settings.ssf_allowed_receiver_hosts`` here.

    Returns:
        The original url string (unchanged) if valid.

    Raises:
        ValueError: With a descriptive message when the URL is rejected.
    """
    if not url:
        raise ValueError("endpoint_url must not be empty")

    try:
        parsed = urlparse(url)
    except Exception as exc:
        raise ValueError(f"endpoint_url is not a valid URL: {exc}") from exc

    # --- scheme ---
    if parsed.scheme != "https":
        raise ValueError(
            f"endpoint_url scheme must be 'https', got '{parsed.scheme}'"
        )

    # --- credentials in URL ---
    if parsed.username or parsed.password:
        raise ValueError("endpoint_url must not contain credentials (user:pass@host)")

    # --- fragment ---
    if parsed.fragment:
        raise ValueError("endpoint_url must not contain a fragment (#)")

    # --- host ---
    host = parsed.hostname
    if not host:
        raise ValueError("endpoint_url has no host")

    if host.lower() in _BLOCKED_HOSTNAMES:
        raise ValueError(f"endpoint_url host {host!r} is not allowed")

    # Reject bare IP literals that are in blocked ranges
    try:
        ip_literal = ipaddress.ip_address(host)
        if _is_blocked_ip(str(ip_literal)):
            raise ValueError(f"endpoint_url host {host!r} resolves to a blocked IP address")
    except ValueError as exc:
        # Not a bare IP literal — that's fine, fall through to DNS check
        if "blocked" in str(exc):
            raise

    # --- allowlist check (if configured) ---
    host_lower = host.lower()
    if allowed_hosts and host_lower not in allowed_hosts:
        raise ValueError(
            f"endpoint_url host {host!r} is not in SSF_ALLOWED_RECEIVER_HOSTS allowlist"
        )

    # --- DNS resolution + IP block check ---
    resolved_ips = _resolve_host(host)
    if not resolved_ips:
        raise ValueError(f"endpoint_url host {host!r} did not resolve to any IP address")

    for ip in resolved_ips:
        if _is_blocked_ip(ip):
            raise ValueError(
                f"endpoint_url host {host!r} resolves to blocked IP {ip!r}"
            )

    logger.debug("endpoint_url validated host=%s resolved_ips=%s", host, resolved_ips)
    return url
