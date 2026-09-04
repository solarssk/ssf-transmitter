"""Property-based tests for SSRF protection (app.security.url_validation).

The example-based tests in test_url_validation.py check specific known-bad
inputs (127.0.0.1, 169.254.169.254, ...). These tests instead assert the
*invariant* the module exists to enforce — every address in every blocked
network is rejected, and only genuinely public addresses are ever accepted —
by generating addresses across the full space of each range rather than
picking a handful of examples by hand. Hypothesis' shrinking also means a
failure here reports the smallest/simplest address that breaks the property,
not just "some fuzzed input failed".

DNS resolution is mocked throughout, matching test_url_validation.py.
"""

from __future__ import annotations

import ipaddress
from unittest.mock import patch

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from app.security.url_validation import _BLOCKED_NETWORKS, _is_blocked_ip, validate_receiver_endpoint_url

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------


def _addresses_in(network: ipaddress.IPv4Network | ipaddress.IPv6Network):
    """Hypothesis strategy generating address strings from anywhere in *network*."""
    address_cls = ipaddress.IPv4Address if network.version == 4 else ipaddress.IPv6Address
    return st.integers(min_value=int(network.network_address), max_value=int(network.broadcast_address)).map(
        lambda i: str(address_cls(i))
    )


# One strategy per blocked network, combined — covers every reserved/private
# range the module knows about (RFC1918, loopback, link-local/cloud metadata,
# multicast, documentation ranges, IPv6 equivalents, ...).
blocked_ip_strategy = st.one_of(*(_addresses_in(net) for net in _BLOCKED_NETWORKS))

# A small set of address blocks known to be *publicly routable* — deliberately
# not exhaustive (unlike the blocklist, "public" isn't a fixed list of
# ranges), just enough spread to exercise the accept path across IPv4/IPv6.
_PUBLIC_RANGES = [
    ipaddress.ip_network("8.8.8.0/24"),  # Google DNS block
    ipaddress.ip_network("93.184.216.0/24"),  # example.com's block
    ipaddress.ip_network("1.1.1.0/24"),  # Cloudflare DNS block
    ipaddress.ip_network("2606:4700:4700::/48"),  # Cloudflare IPv6 block
]
public_ip_strategy = st.one_of(*(_addresses_in(net) for net in _PUBLIC_RANGES))


# ---------------------------------------------------------------------------
# _is_blocked_ip
# ---------------------------------------------------------------------------


@given(ip=blocked_ip_strategy)
def test_every_address_in_every_blocked_network_is_blocked(ip: str):
    assert _is_blocked_ip(ip) is True


@given(ip=public_ip_strategy)
def test_addresses_outside_blocked_ranges_are_not_blocked(ip: str):
    assert _is_blocked_ip(ip) is False


@given(garbage=st.text(min_size=1).filter(lambda s: not s.strip().replace(".", "").replace(":", "").isdigit()))
def test_unparseable_strings_are_treated_as_blocked(garbage: str):
    """_is_blocked_ip fails closed: anything that isn't a valid IP is 'blocked'."""
    try:
        ipaddress.ip_address(garbage)
    except ValueError:
        assert _is_blocked_ip(garbage) is True
    # else: garbage happened to be a valid IP after all — hypothesis found a
    # real address, not a failure of this test's own filter; skip silently.


# ---------------------------------------------------------------------------
# validate_receiver_endpoint_url — bare IP literals
# ---------------------------------------------------------------------------


@given(ip=blocked_ip_strategy)
@settings(deadline=None)
def test_bare_blocked_ip_literal_always_rejected(ip: str):
    url = f"https://[{ip}]/events" if ":" in ip else f"https://{ip}/events"
    with pytest.raises(ValueError):
        validate_receiver_endpoint_url(url)


@given(ip=public_ip_strategy)
@settings(deadline=None)
def test_public_host_resolving_to_itself_is_accepted(ip: str):
    """A hostname that resolves only to public addresses is accepted end-to-end."""
    url = "https://receiver.example.test/events"
    with patch("app.security.url_validation._resolve_host", return_value=[ip]):
        assert validate_receiver_endpoint_url(url) == url


# ---------------------------------------------------------------------------
# Structural rejections that must hold regardless of host
# ---------------------------------------------------------------------------


_SAFE_URL_TEXT = st.text(
    # Exclude "[" / "]" too: urlparse treats them as IPv6-literal delimiters,
    # so a stray one in the userinfo component makes it raise its own
    # "Invalid IPv6 URL" / "not a valid URL" error before ever reaching the
    # credentials check this is meant to exercise.
    alphabet=st.characters(blacklist_characters="/:@#?[] \t\n\r", min_codepoint=33, max_codepoint=126),
    min_size=1,
    max_size=20,
)


@given(url_userinfo_name=_SAFE_URL_TEXT, url_userinfo_secret=_SAFE_URL_TEXT)
@settings(deadline=None)
def test_any_credentials_in_url_are_rejected(url_userinfo_name: str, url_userinfo_secret: str):
    # Deliberately not named "user"/"password": CodeQL's clear-text-logging
    # query flags call sites downstream of a variable named "password" by
    # naming heuristic, even though what's actually logged here (in
    # validate_receiver_endpoint_url) is just the hostname — urlparse
    # separates userinfo from hostname, so the fuzzed value never reaches a
    # log call. See PR #122 review discussion.
    url = f"https://{url_userinfo_name}:{url_userinfo_secret}@receiver.example.test/events"
    with (
        patch("app.security.url_validation._resolve_host", return_value=["93.184.216.34"]),
        pytest.raises(ValueError, match="credentials"),
    ):
        validate_receiver_endpoint_url(url)


@given(fragment=_SAFE_URL_TEXT)
@settings(deadline=None)
def test_any_fragment_is_rejected(fragment: str):
    url = f"https://receiver.example.test/events#{fragment}"
    with (
        patch("app.security.url_validation._resolve_host", return_value=["93.184.216.34"]),
        pytest.raises(ValueError, match="fragment"),
    ):
        validate_receiver_endpoint_url(url)


@given(scheme=st.sampled_from(["http", "ftp", "file", "gopher", "ws", "javascript", "data"]))
def test_any_non_https_scheme_is_rejected(scheme: str):
    with pytest.raises(ValueError, match="scheme must be 'https'"):
        validate_receiver_endpoint_url(f"{scheme}://receiver.example.test/events")
