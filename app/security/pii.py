"""PII (Personally Identifiable Information) utilities for safe logging.

When SSF_LOG_PII=false (the default), email addresses are replaced by a
short, consistent pseudonymous token in log messages.  The token uses
HMAC-SHA256 keyed by a secret pepper so it cannot be reversed by an
attacker who has only the log file.

Use SSF_LOG_PII=true only in controlled dev/debug environments.
"""

from __future__ import annotations

import hashlib
import hmac


def mask_email(email: str | None, *, log_pii: bool, pii_key: str = "") -> str:
    """Return a safe representation of an email address for log messages.

    When *log_pii* is True the address is returned unchanged.

    When *log_pii* is False the address is replaced by ``[pii:<hex8>]``
    where ``<hex8>`` is the first 8 hex characters of HMAC-SHA256(key, email).
    The HMAC key is *pii_key* (pass ``settings.ssf_management_token`` or a
    dedicated ``SSF_PII_PEPPER`` secret).  The token is consistent across log
    lines for the same email but is not recoverable without the key.

    >>> mask_email("alice@example.com", log_pii=True)
    'alice@example.com'
    >>> mask_email("alice@example.com", log_pii=False, pii_key="secret")  # doctest: +ELLIPSIS
    '[pii:...]'
    >>> mask_email(None, log_pii=False)
    '[pii:none]'
    """
    if email is None:
        return "[pii:none]"
    if log_pii:
        return email
    key = pii_key.encode("utf-8") if pii_key else b""
    digest = hmac.new(key, email.encode("utf-8"), hashlib.sha256).hexdigest()[:8]
    return f"[pii:{digest}]"
