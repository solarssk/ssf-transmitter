"""Sanitize untrusted values before interpolating them into log messages.

Free-form input that reaches a log line unescaped — a query parameter, a
client-supplied identifier — can carry control characters (CR, LF, ...) that
forge fake log lines or otherwise corrupt log parsing (CWE-117). This is
about the log stream's own structural integrity; it is orthogonal to PII
masking (see ``app.security.pii``) and upstream response-body redaction (see
``app.security.http_logging``), both of which assume well-formed text.
"""

from __future__ import annotations

import re

_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")


def sanitize_for_log(value: str | None, *, max_len: int = 200) -> str:
    """Strip control characters and cap length for safe interpolation into logs.

    >>> sanitize_for_log("bad\\r\\nFAKE LOG LINE")
    'badFAKE LOG LINE'
    >>> sanitize_for_log(None)
    'None'
    """
    if value is None:
        return "None"
    stripped = _CONTROL_CHARS_RE.sub("", value)
    if len(stripped) > max_len:
        return stripped[:max_len] + "...[truncated]"
    return stripped
