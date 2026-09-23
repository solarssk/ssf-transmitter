#!/usr/bin/python3
"""Fuzzing harness for app.security.url_validation's SSRF-blocking logic.

Exercises the deterministic, in-process pieces of validate_receiver_endpoint_url():
scheme/credential/fragment rejection, blocked-hostname/IP-literal checks (including
the IPv4-in-IPv6 unwrapping _is_blocked_ip does for mapped/6to4/Teredo/NAT64
addresses), and allowlist matching. Deliberately does NOT call
validate_receiver_endpoint_url() itself or _reject_blocked_resolved_ips(): those
do real DNS resolution via socket.getaddrinfo(), and a fuzz target has to stay
fast and hermetic — real network calls would make this one slow, flaky, and
dependent on external state instead of testing the library's own logic.
"""

import sys
from contextlib import suppress
from urllib.parse import urlparse

import atheris

with atheris.instrument_imports():
    from app.security import url_validation


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    text = fdp.ConsumeUnicodeNoSurrogates(fdp.remaining_bytes())

    # _is_blocked_ip: the only exception ipaddress.ip_address ever raises is
    # ValueError, already caught internally — this must never raise for any
    # string input.
    url_validation._is_blocked_ip(text)

    # receiver_host_allowed: pure urlparse + membership check, no DNS.
    url_validation.receiver_host_allowed(text, ["example.com"])
    url_validation.receiver_host_allowed(text, [])

    # The rest of validate_receiver_endpoint_url()'s checks, up to (not
    # including) the DNS resolution step.
    try:
        parsed = urlparse(text)
    except ValueError:
        return
    with suppress(ValueError):
        url_validation._reject_unsafe_scheme_or_parts(parsed)
    host = parsed.hostname
    if host:
        with suppress(ValueError):
            url_validation._reject_blocked_host_literal(host)


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
