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
