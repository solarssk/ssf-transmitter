# Application tests

Run the hermetic suite from the repository root with Python 3.14 and the locked development environment:

```bash
uv sync --locked --all-extras
uv run --no-sync pytest
```

The suite uses an in-process FastAPI client and reports branch coverage. It writes temporary keys and SQLite state under `.testdata/`. Read [conftest.py](conftest.py) before changing fixtures or adding tests.

| Need | Where to start |
|---|---|
| Webhook authentication and queueing | `test_webhook_security.py`, `test_app.py` |
| Event policy and external mapping template | `test_mapper.py`, `test_authentik_body_mapping.py` |
| Receiver SSRF and token handling | `test_url_validation.py`, `test_pusher.py`, `test_database_security.py` |
| SCIM identity and update behavior | `test_scim_users_differ.py`, `test_scim_authentik.py` |

Default fixtures skip preflight and verification pushes, mock DNS, and disable rate limits. Explicit markers opt into DNS/rate-limit behavior; follow [testing conventions](../AGENTS.md#testing-conventions).

Plain `pytest` does not run [container HTTP tests](../tests_e2e/README.md). Unit mocks and green CI do not prove a real Apple account or device changed state.
