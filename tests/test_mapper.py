from app.events.mapper import map_authentik_event


def test_maps_logout_to_session_revoked():
    events = map_authentik_event({"body": {"action": "authentik.core.auth.logout"}})

    assert events == ["https://schemas.openid.net/secevent/caep/event-type/session-revoked"]


def test_maps_user_write_password_and_disabled_to_multiple_events():
    events = map_authentik_event(
        {
            "body": {
                "action": "authentik.core.user.write",
                "context": {
                    "changed_fields": ["password", "is_active"],
                    "is_active": False,
                },
            }
        }
    )

    assert events == [
        "https://schemas.openid.net/secevent/caep/event-type/credential-change",
        "https://schemas.openid.net/secevent/risc/event-type/account-disabled",
    ]


def test_maps_user_delete_to_account_purged():
    events = map_authentik_event({"body": {"action": "authentik.core.user.delete"}})

    assert events == ["https://schemas.openid.net/secevent/risc/event-type/account-purged"]


def test_ignores_unmapped_event():
    assert map_authentik_event({"body": {"action": "authentik.core.auth.login_failed"}}) == []
