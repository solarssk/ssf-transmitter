"""Tests for app.security.log_sanitize — CRLF/control-char log injection guard."""

from __future__ import annotations

from app.security.log_sanitize import sanitize_for_log


def test_strips_crlf():
    assert sanitize_for_log("bad\r\nFAKE LOG LINE") == "badFAKE LOG LINE"


def test_strips_other_control_characters():
    # \x00 (NUL), \x1b (ESC, terminal control sequences), \x7f (DEL)
    assert sanitize_for_log("a\x00b\x1bc\x7fd") == "abcd"


def test_passes_through_ordinary_text_unchanged():
    assert sanitize_for_log("perfectly normal aud value") == "perfectly normal aud value"


def test_none_becomes_literal_string():
    assert sanitize_for_log(None) == "None"


def test_truncates_long_values():
    result = sanitize_for_log("x" * 500, max_len=200)
    assert result == "x" * 200 + "...[truncated]"


def test_does_not_truncate_at_exact_limit():
    result = sanitize_for_log("x" * 200, max_len=200)
    assert result == "x" * 200


def test_non_string_value_is_coerced_not_raised():
    """Regression test: app/events/mapper.py's extract_source_txn() returns
    body.get("pk") etc. with no type coercion — a webhook with an int `pk`
    produces a non-string event.txn, and this is called on it at DEBUG log
    level in app/events/pusher.py. Previously raised TypeError (re.sub on
    an int), which surfaced as an unhandled 500 aborting webhook delivery.
    """
    assert sanitize_for_log(12345) == "12345"


def test_non_string_value_still_strips_control_chars_after_str_coercion():
    class _Weird:
        def __str__(self) -> str:
            return "bad\r\nFAKE LOG LINE"

    assert sanitize_for_log(_Weird()) == "badFAKE LOG LINE"
