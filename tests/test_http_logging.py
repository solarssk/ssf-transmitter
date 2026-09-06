"""Tests for app/security/http_logging — safe HTTP diagnostics."""

from __future__ import annotations

import time

import httpx

from app.security.http_logging import json_key_summary, redact_text, response_metadata, safe_response_body_text


class TestResponseMetadata:
    def test_shape(self):
        resp = httpx.Response(401, json={"error": "invalid_token", "access_token": "SECRET"})
        meta = response_metadata(resp)
        assert meta["status_code"] == 401
        assert meta["body_len"] == len(resp.content)
        assert len(meta["body_sha256_8"]) == 8

    def test_never_exposes_body_values(self):
        secret = "super-secret-refresh-token"
        resp = httpx.Response(400, json={"refresh_token": secret})
        meta = response_metadata(resp)
        assert secret not in str(meta)

    def test_content_type_included(self):
        resp = httpx.Response(200, json={}, headers={"content-type": "application/scim+json"})
        assert response_metadata(resp)["content_type"] == "application/scim+json"

    def test_hash_is_deterministic(self):
        r1 = httpx.Response(200, content=b"same body")
        r2 = httpx.Response(200, content=b"same body")
        assert response_metadata(r1)["body_sha256_8"] == response_metadata(r2)["body_sha256_8"]

    def test_different_bodies_different_hash(self):
        r1 = httpx.Response(200, content=b"body one")
        r2 = httpx.Response(200, content=b"body two")
        assert response_metadata(r1)["body_sha256_8"] != response_metadata(r2)["body_sha256_8"]


class TestJsonKeySummary:
    def test_never_exposes_values(self):
        data = {"access_token": "SECRET", "refresh_token": "ALSO_SECRET"}
        summary = json_key_summary(data)
        assert "SECRET" not in summary
        assert "ALSO_SECRET" not in summary

    def test_keys_present(self):
        data = {"access_token": "x", "expires_in": 3600}
        summary = json_key_summary(data)
        assert "access_token" in summary
        assert "expires_in" in summary

    def test_keys_sorted(self):
        data = {"z_key": 1, "a_key": 2, "m_key": 3}
        summary = json_key_summary(data)
        assert summary == "object_keys=['a_key', 'm_key', 'z_key']"

    def test_list_input(self):
        summary = json_key_summary([1, 2, 3])
        assert summary == "list_len=3"

    def test_other_type(self):
        assert json_key_summary("plain string") == "type=str"
        assert json_key_summary(42) == "type=int"

    def test_empty_dict(self):
        assert json_key_summary({}) == "object_keys=[]"


class TestSafeResponseBodyText:
    def test_redacts_sensitive_keys_and_emails_from_json(self):
        resp = httpx.Response(
            400,
            json={
                "detail": "invalid user alice@example.com",
                "access_token": "SECRET",
                "nested": {"refresh_token": "ALSO_SECRET"},
            },
        )
        safe = safe_response_body_text(resp, log_pii=False, pii_key="pepper")
        assert "SECRET" not in safe
        assert "ALSO_SECRET" not in safe
        assert "alice@example.com" not in safe
        assert "[redacted]" in safe
        assert "[pii:" in safe

    def test_redacts_email_from_plain_text(self):
        resp = httpx.Response(400, text="invalid request for bob@example.com")
        safe = safe_response_body_text(resp, log_pii=False, pii_key="pepper")
        assert "bob@example.com" not in safe
        assert "[pii:" in safe


class TestRedactText:
    """_EMAIL_RE's quantifiers are all bounded rather than open-ended, to
    avoid the super-linear-runtime hazard flagged by SonarCloud
    (python:S5852) — an unbounded repeated group lets each of the O(n)
    positions re.search() tries on non-matching text still greedily consume
    an O(n) suffix before failing, which is O(n^2) overall and is NOT fixed
    by possessive quantifiers alone (they only remove backtracking *within*
    one attempt, not the cost repeated *across* attempts). The bounds
    themselves are sized to safe_response_body_text()'s 512-byte
    truncation, not RFC limits — a component can never legitimately need
    more than that within its only caller, and RFC limits are the wrong
    boundary for redacting *malformed* input from upstream error
    responses (see test_redacts_over_rfc_limit_* below)."""

    def test_redacts_multi_label_domain(self):
        text = "contact alice.bob+tag@sub.example.co.uk please"
        result = redact_text(text, log_pii=False, pii_key="pepper")
        assert "alice.bob+tag@sub.example.co.uk" not in result
        assert "[pii:" in result

    def test_redacts_multiple_emails(self):
        text = "a@b.com and c@d.org"
        result = redact_text(text, log_pii=False, pii_key="pepper")
        assert "a@b.com" not in result
        assert "c@d.org" not in result

    def test_non_email_text_is_unaffected(self):
        text = "no email content here, just plain diagnostics"
        assert redact_text(text, log_pii=False, pii_key="pepper") == text

    def test_redacts_domain_with_more_than_ten_labels(self):
        """Regression test: an earlier version capped the domain at 10
        labels ("generous for any real domain"), which was wrong — a
        domain with 11+ labels (e.g. deeply-nested internal subdomains)
        made the *entire* address fail to match and pass through
        completely unredacted, silently leaking PII even with
        SSF_LOG_PII=false. RFC 1035 doesn't cap the label count, only
        per-label (63) and total (253 octet) length."""
        text = "contact alice@a.b.c.d.e.f.g.h.i.j.k.example.com please"
        result = redact_text(text, log_pii=False, pii_key="pepper")
        assert "alice@a.b.c.d.e.f.g.h.i.j.k.example.com" not in result
        assert "[pii:" in result

    def test_redacts_over_rfc_limit_domain_label_completely(self):
        """Regression test: a subsequent version bounded each domain label
        at RFC 1035's 63-octet limit — also wrong, for a different reason
        than the label-count cap above. This regex redacts PII from
        *upstream error responses*, exactly where a malformed, over-limit
        value is likely to appear (e.g. an upstream echoing back invalid
        input it's rejecting). A 64+ char label made the whole address
        fail to match anywhere, passing through completely unredacted."""
        text = "contact alice@" + ("b" * 64) + ".com please"
        result = redact_text(text, log_pii=False, pii_key="pepper")
        assert "alice@" + ("b" * 64) + ".com" not in result
        assert "b" * 64 not in result  # not even a partial, unredacted fragment
        assert "[pii:" in result

    def test_redacts_over_rfc_limit_local_part_completely(self):
        """Regression test for the other half of the same bug: a local
        part over RFC 5321's 64-octet limit used to still produce a
        match (the bound just slides the window), but only over the
        *last* N characters — leaving the leading, over-limit characters
        of the local part visible, unredacted, right before the masked
        suffix. The full local part must be captured, not a suffix of it."""
        text = "contact " + ("a" * 65) + "@example.com please"
        result = redact_text(text, log_pii=False, pii_key="pepper")
        assert ("a" * 65) + "@example.com" not in result
        assert "a" * 65 not in result  # not even a partial, unredacted prefix
        assert "[pii:" in result

    def test_adversarial_dotted_text_completes_quickly(self):
        """Regression test: this exact shape (many dots, no valid TLD) took
        several seconds with the unbounded regex once input reached ~16k
        repetitions; bounded quantifiers keep it linear. Budget is 5s, not
        a tighter bound: these quantifiers are sized to a real 512-byte
        production ceiling (see the comment on _EMAIL_RE), so this 200k-hostile
        input is already ~400x beyond anything the function is ever actually
        called with — a few seconds here is a generous constant, not a sign
        of quadratic blowup (compare the *scaling* across input sizes, not
        the absolute number, if this ever needs re-checking)."""
        adversarial = "a." * 200_000 + "!"
        start = time.monotonic()
        result = redact_text(adversarial, log_pii=False, pii_key="pepper")
        elapsed = time.monotonic() - start
        assert result == adversarial  # no email-shaped match in this input
        assert elapsed < 5.0, f"redact_text took {elapsed:.2f}s on adversarial input — possible ReDoS regression"

    def test_adversarial_long_local_part_completes_quickly(self):
        """Regression test for the other adversarial shape: a long run of
        local-part-compatible characters (letters) with no '@' anywhere
        nearby, repeated across many candidate '@' positions. See the note
        on the 5s budget above — same reasoning."""
        adversarial = ("a" * 5000 + "@") * 200
        start = time.monotonic()
        redact_text(adversarial, log_pii=False, pii_key="pepper")
        elapsed = time.monotonic() - start
        assert elapsed < 5.0, f"redact_text took {elapsed:.2f}s on adversarial input — possible ReDoS regression"
