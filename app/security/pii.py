"""PII (Personally Identifiable Information) utilities for safe logging.

When SSF_LOG_PII=false (the default), email addresses are replaced by a
short, consistent pseudonymous hash that can be used to correlate log lines
for the same user without revealing the actual address.

The hash is NOT a secret — it is just a privacy-preserving representation.
Use SSF_LOG_PII=true only in controlled dev/debug environments.
"""

from __future__ import annotations

import hashlib


def mask_email(email: str | None, *, log_pii: bool) -> str:
    """Return a safe representation of an email address for use in log messages.

    When *log_pii* is True the address is returned unchanged.
    When *log_pii* is False the address is replaced by ``[pii:<hex8>]`` where
    ``<hex8>`` is the first 8 hex characters of the SHA-256 of the address.
    This is consistent (same email → same token across log lines) and
    does not expose the actual address or its domain.

    >>> mask_email("alice@example.com", log_pii=True)
    'alice@example.com'
    >>> mask_email("alice@example.com", log_pii=False)  # doctest: +ELLIPSIS
    '[pii:...]'
    >>> mask_email(None, log_pii=False)
    '[pii:none]'
    """
    if email is None:
        return "[pii:none]"
    if log_pii:
        return email
    digest = hashlib.sha256(email.encode("utf-8")).hexdigest()[:8]
    return f"[pii:{digest}]"
