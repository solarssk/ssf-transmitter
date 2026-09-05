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
from urllib.parse import ParseResult, urlparse

logger = logging.getLogger(__name__)

# IP networks that are never acceptable as receiver targets
# Hostnames that are always blocked regardless of DNS resolution
_BLOCKED_HOSTNAMES = {
    "localhost",
    "metadata.google.internal",  # GCE metadata
    "169.254.169.254",  # also caught as bare IP, belt-and-suspenders
}

_BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),  # "This" network
    ipaddress.ip_network("10.0.0.0/8"),  # RFC1918 private
    ipaddress.ip_network("100.64.0.0/10"),  # Shared address space
    ipaddress.ip_network("127.0.0.0/8"),  # Loopback
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local / cloud metadata
    ipaddress.ip_network("172.16.0.0/12"),  # RFC1918 private
    ipaddress.ip_network("192.0.0.0/24"),  # IETF protocol assignments
    ipaddress.ip_network("192.0.2.0/24"),  # TEST-NET-1 (documentation)
    ipaddress.ip_network("192.168.0.0/16"),  # RFC1918 private
    ipaddress.ip_network("198.18.0.0/15"),  # Benchmarking
    ipaddress.ip_network("198.51.100.0/24"),  # TEST-NET-2 (documentation)
    ipaddress.ip_network("203.0.113.0/24"),  # TEST-NET-3 (documentation)
    ipaddress.ip_network("224.0.0.0/4"),  # Multicast
    ipaddress.ip_network("240.0.0.0/4"),  # Reserved
    ipaddress.ip_network("255.255.255.255/32"),  # Broadcast
    # IPv6
    ipaddress.ip_network("::1/128"),  # Loopback
    ipaddress.ip_network("fc00::/7"),  # Unique local
    ipaddress.ip_network("fe80::/10"),  # Link-local
    ipaddress.ip_network("ff00::/8"),  # Multicast
]

# IPv6 forms that embed an IPv4 address directly in their low 32 bits, but
# that Python's ipaddress module has no dedicated unwrap property for
# (unlike ipv4_mapped/sixtofour/teredo, used in _is_blocked_ip below).
_IPV4_EMBEDDING_NETWORKS = [
    ipaddress.ip_network("::/96"),  # IPv4-compatible (deprecated, RFC4291 §2.5.5.1)
    ipaddress.ip_network("64:ff9b::/96"),  # NAT64 well-known prefix (RFC 6052)
]


def _is_blocked_ip(ip_str: str) -> bool:
    """Return True if the IP address falls into a blocked network range."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # unparseable → treat as blocked
    # An IPv4-mapped IPv6 literal (e.g. ::ffff:169.254.169.254) is a distinct
    # IPv6Address object — `addr in net` against an IPv4Network silently
    # returns False (no version mismatch exception), so a blocked address
    # sails straight through unless unwrapped to its embedded IPv4 form
    # first. 6to4 (2002::/16) and Teredo (2001::/32) embed an IPv4 address
    # the same way; unwrap those too. IPv4-compatible and NAT64 addresses
    # embed it in their low 32 bits directly with no dedicated ipaddress
    # property, so extract it from the packed bytes instead.
    if isinstance(addr, ipaddress.IPv6Address):
        embedded = addr.ipv4_mapped or addr.sixtofour or (addr.teredo[1] if addr.teredo else None)
        if embedded is None and any(addr in net for net in _IPV4_EMBEDDING_NETWORKS):
            embedded = ipaddress.IPv4Address(addr.packed[-4:])
        if embedded is not None:
            addr = embedded
    return any(addr in net for net in _BLOCKED_NETWORKS)


def _resolve_host(host: str) -> list[str]:
    """Resolve hostname to a list of IP address strings.

    Returns an empty list on resolution failure (NXDOMAIN, timeout, etc.).
    """
    try:
        results = socket.getaddrinfo(host, None)
        # sockaddr is (address, port) for IPv4 or (address, port, flowinfo,
        # scope_id) for IPv6 — typeshed types it loosely across both shapes,
        # so make the "it's always an address string" contract explicit.
        return [str(r[4][0]) for r in results]
    except OSError:
        return []


def receiver_host_allowed(url: str, allowed_hosts: list[str]) -> bool:
    """Return True when *url*'s host is permitted by the configured allowlist.

    An empty *allowed_hosts* list means all hosts are permitted (no allowlist).
    """
    if not allowed_hosts:
        return True
    host = (urlparse(url).hostname or "").lower()
    return host in allowed_hosts


def _reject_unsafe_scheme_or_parts(parsed: ParseResult) -> None:
    """Raise if *parsed* uses a non-HTTPS scheme, carries credentials, or has a fragment."""
    if parsed.scheme != "https":
        raise ValueError(f"endpoint_url scheme must be 'https', got '{parsed.scheme}'")
    if parsed.username or parsed.password:
        raise ValueError("endpoint_url must not contain credentials (user:pass@host)")
    if parsed.fragment:
        raise ValueError("endpoint_url must not contain a fragment (#)")


def _reject_blocked_host_literal(host: str) -> None:
    """Raise if *host* is a blocked hostname or a bare IP literal in a blocked range."""
    if host.lower() in _BLOCKED_HOSTNAMES:
        raise ValueError(f"endpoint_url host {host!r} is not allowed")

    try:
        ip_literal = ipaddress.ip_address(host)
    except ValueError:
        return  # Not a bare IP literal — fine, fall through to the DNS check

    if _is_blocked_ip(str(ip_literal)):
        raise ValueError(f"endpoint_url host {host!r} resolves to a blocked IP address")


def _reject_blocked_resolved_ips(host: str) -> list[str]:
    """Resolve *host* and raise if it has no A/AAAA records or any resolve to a blocked IP."""
    resolved_ips = _resolve_host(host)
    if not resolved_ips:
        raise ValueError(f"endpoint_url host {host!r} did not resolve to any IP address")

    for ip in resolved_ips:
        if _is_blocked_ip(ip):
            raise ValueError(f"endpoint_url host {host!r} resolves to blocked IP {ip!r}")

    return resolved_ips


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

    _reject_unsafe_scheme_or_parts(parsed)

    host = parsed.hostname
    if not host:
        raise ValueError("endpoint_url has no host")

    _reject_blocked_host_literal(host)

    if allowed_hosts and not receiver_host_allowed(url, allowed_hosts):
        raise ValueError(f"endpoint_url host {host!r} is not in SSF_ALLOWED_RECEIVER_HOSTS allowlist")

    resolved_ips = _reject_blocked_resolved_ips(host)

    logger.debug("endpoint_url validated host=%s resolved_ips=%s", host, resolved_ips)
    return url
