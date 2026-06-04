"""Tests for apple.py SCIM comparison logic (_users_differ, _primary_email)."""

from __future__ import annotations

from app.scim.apple import _primary_email, _users_differ

# ---------------------------------------------------------------------------
# _primary_email
# ---------------------------------------------------------------------------

class TestPrimaryEmail:
    def test_explicit_primary_true(self):
        user = {"emails": [{"value": "a@example.com", "primary": True}]}
        assert _primary_email(user) == "a@example.com"

    def test_no_primary_flag_falls_back_to_first(self):
        """Apple may omit primary flag — first email is the fallback."""
        user = {"emails": [{"value": "a@example.com"}, {"value": "b@example.com"}]}
        assert _primary_email(user) == "a@example.com"

    def test_primary_false_skipped_falls_back_to_first(self):
        user = {"emails": [{"value": "a@example.com", "primary": False}]}
        assert _primary_email(user) == "a@example.com"

    def test_no_emails_returns_none(self):
        assert _primary_email({}) is None
        assert _primary_email({"emails": []}) is None

    def test_mixed_primary_picks_true(self):
        user = {"emails": [
            {"value": "first@example.com", "primary": False},
            {"value": "primary@example.com", "primary": True},
        ]}
        assert _primary_email(user) == "primary@example.com"


# ---------------------------------------------------------------------------
# _users_differ
# ---------------------------------------------------------------------------

def _apple_user(
    username="user@example.com",
    given="John",
    family="Doe",
    active=True,
    email="user@example.com",
    email_primary=None,  # None = omit flag (simulates Apple response)
) -> dict:
    """Build a fake Apple SCIM GET response user.

    Set ``email_primary=None`` to simulate Apple omitting the ``primary`` flag
    (the common case that triggered the false-positive bug).
    """
    email_entry: dict = {"value": email}
    if email_primary is not None:
        email_entry["primary"] = email_primary
    return {
        "userName": username,
        "name": {"givenName": given, "familyName": family},
        "active": active,
        "emails": [email_entry],
    }


def _authentik_user(
    username="user@example.com",
    given="John",
    family="Doe",
    active=True,
    email="user@example.com",
) -> dict:
    """Build a fake Authentik → SCIM mapped user (always includes ``primary: true``)."""
    return {
        "userName": username,
        "name": {"givenName": given, "familyName": family},
        "active": active,
        "emails": [{"value": email, "primary": True, "type": "work"}],
    }


class TestUsersDiffer:
    def test_identical_no_diff(self):
        existing = _apple_user()
        new = _authentik_user()
        assert _users_differ(existing, new) is False

    def test_apple_omits_primary_flag_no_false_diff(self):
        """Core bug fix: Apple returns email without primary flag → must not diff."""
        existing = _apple_user(email_primary=None)  # Apple omits primary
        new = _authentik_user()                      # We always send primary=True
        assert _users_differ(existing, new) is False

    def test_apple_omits_active_no_false_diff(self):
        """Apple may omit active when True — should not be treated as changed."""
        existing = _apple_user()
        existing.pop("active")  # Apple omits the field
        new = _authentik_user(active=True)
        assert _users_differ(existing, new) is False

    def test_username_case_insensitive(self):
        """Apple may normalise userName to lowercase."""
        existing = _apple_user(username="user@example.com")
        new = _authentik_user(username="USER@example.com")
        assert _users_differ(existing, new) is False

    def test_given_name_changed(self):
        existing = _apple_user(given="John")
        new = _authentik_user(given="Jonathan")
        assert _users_differ(existing, new) is True

    def test_family_name_changed(self):
        existing = _apple_user(family="Doe")
        new = _authentik_user(family="Smith")
        assert _users_differ(existing, new) is True

    def test_email_changed(self):
        existing = _apple_user(email="old@example.com", email_primary=None)
        new = _authentik_user(email="new@example.com")
        assert _users_differ(existing, new) is True

    def test_active_changed_to_false(self):
        existing = _apple_user(active=True)
        new = _authentik_user(active=False)
        assert _users_differ(existing, new) is True

    def test_no_emails_in_apple_vs_email_in_new(self):
        """If Apple returns no emails at all, any email in new is a change."""
        existing = _apple_user()
        existing["emails"] = []
        new = _authentik_user(email="user@example.com")
        assert _users_differ(existing, new) is True
