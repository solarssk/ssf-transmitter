# AGENTS.md — guide for AI coding assistants

This file helps Cursor, Codex, Claude Code, and similar tools work effectively in **ssf-transmitter**.

**Operator docs**: [`README.md`](README.md), [`docs/API.md`](docs/API.md), [`docs/synology-authentik-compose.md`](docs/synology-authentik-compose.md)  
**Threat model**: [`SECURITY.md`](SECURITY.md)

---

## What this project is

A **single-container FastAPI service** that:

1. Receives Authentik webhooks (`POST /webhook/authentik`)
2. Maps events to SSF Security Event Tokens (SETs)
3. Signs SETs with RS256 and pushes them to one active SSF receiver (e.g. Apple Business Manager)

Optional: Apple SCIM directory sync (Authentik → ABM).

There is **no admin UI**. Configuration is environment variables only. One active stream at a time (stored in SQLite).

---

## Tech stack

| Layer | Choice |
|---|---|
| Language | Python **3.14** (see `.python-version`) |
| Framework | FastAPI + Uvicorn |
| DB | SQLite via `aiosqlite` |
| Crypto | `cryptography` (RS256 JWT, Fernet token encryption) |
| Auth | Bearer tokens (`SSF_MANAGEMENT_TOKEN`, `SSF_WEBHOOK_TOKEN`) |
| Rate limits | `slowapi` |
| Lint / test | `ruff`, `pytest` |
| CI | GitHub Actions — lint, test, deptry, pip-audit, Docker build, Trivy |

---

## Repository layout

```text
app/
  main.py              # FastAPI app, middleware, Apple SCIM background loop
  config.py            # Settings from env; startup validation
  auth.py              # Management Bearer auth + failed-auth rate limit
  crypto.py            # RS256 keys, Fernet encrypt/decrypt receiver tokens
  database.py          # SQLite streams + SCIM tokens
  models.py            # Pydantic request/response models
  startup.py           # Preflight checks (✅/⚠️/❌)
  rate_limit.py        # slowapi limiter instance
  routes/              # HTTP routers (streams, webhook, wellknown, apple_scim, …)
  events/              # mapper.py (Authentik→SET), pusher.py (outbound HTTPS)
  security/            # url_validation (SSRF), pii, http_logging
  scim/                # Apple + Authentik SCIM clients
tests/                 # pytest; mirrors app modules
docs/                  # Operator documentation (API, Synology guide; more in docs PR)
```

---

## Request flow (mental model)

```text
Authentik webhook → app/routes/webhook.py → app/events/mapper.py
  → app/events/pusher.py → receiver HTTPS endpoint

Management API → app/routes/streams.py → app/database.py
  → encrypt receiver token → SQLite

Discovery: /.well-known/ssf-configuration, /jwks.json (public)
```

---

## Security invariants — do not break

These are product/security requirements, not style preferences.

1. **Receiver tokens** are Fernet-encrypted in SQLite (`app/crypto.py`). Never log them or return them in API responses.
2. **Sparse PATCH** on streams must preserve `endpoint_token` when `delivery.endpoint_url_token` is omitted (`app/database.py::_replacement_endpoint_token`).
3. **Cannot enable** a stream (`status: enabled`) when the stored receiver token is undecryptable without supplying a replacement token.
4. **SSRF protection**: `app/security/url_validation.py` validates receiver URLs at create/patch; `app/events/pusher.py` re-validates DNS before every push.
5. **Constant-time** secret comparison (`hmac.compare_digest`) for management and webhook tokens.
6. **Rate limits** are per-route decorators on `app/rate_limit.limiter`. Do not call one decorated route handler from another — each endpoint needs its own decorator (see `app/routes/streams.py`).
7. **`SSF_MANAGEMENT_TOKEN` ≠ `SSF_WEBHOOK_TOKEN`** — different trust boundaries.
8. **Middleware order** in `app/main.py` is LIFO; `RequestIDMiddleware` must wrap `SlowAPIMiddleware` so 429 responses get `X-Request-ID`.
9. **OpenAPI** (`/docs`) is off unless `SSF_ENABLE_OPENAPI=true`.

When changing auth, tokens, streams, or outbound HTTP, add or extend tests in `tests/test_*_security.py` or adjacent modules.

---

## Development commands

```bash
python3.14 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
ruff check .
pytest
deptry .
```

Copy [`.env.example`](.env.example) for local env vars. Tests use defaults from `tests/conftest.py` (`.testdata/` for keys + DB).

---

## Testing conventions

Read `tests/conftest.py` before writing tests.

| Fixture / marker | Purpose |
|---|---|
| `mock_preflight` (autouse) | Skips `run_preflight_checks()` — avoids `sys.exit` in lifespan |
| `mock_push_verification_set` (autouse) | Blocks real outbound HTTP on stream create |
| `mock_dns_resolve` (autouse) | Returns public IP for SSRF checks; opt out with `@pytest.mark.no_dns_mock` |
| `disable_rate_limits` (autouse) | Disables slowapi; opt in with `@pytest.mark.enable_rate_limit` |

Default test webhook mode is **hmac** (legacy tests). Bearer/unsigned tests patch settings via `dataclasses.replace()` + `monkeypatch`.

Prefer **focused regression tests** over broad mocks. Security fixes should include a test that fails without the fix.

---

## Coding style

- Match existing module style: `from __future__ import annotations`, type hints, module docstrings.
- Use `logging.getLogger(__name__)` — never `print`.
- Pydantic models in `app/models.py` for API inputs; reject extra fields.
- Keep diffs minimal; do not refactor unrelated code in the same change.
- Comments only for non-obvious security or protocol behaviour.
- No new dependencies without CI justification (`deptry` will flag unused imports).

---

## Common pitfalls for agents

| Mistake | Why it matters |
|---|---|
| Adding `SSF_TOKEN_ENCRYPTION_KEY` in upgrade docs for existing installs | Pauses streams; operators must re-register receiver token |
| Defaulting `SSF_FORWARDED_ALLOW_IPS` to `*` | Image default is `127.0.0.1` since v0.5.9; proxy subnet must be set explicitly |
| Sharing rate-limit decorators across routes | PATCH and POST can share a counter incorrectly |
| Calling `push_verification_set` without mocking in tests | Flaky CI / real network calls |
| Returning `endpoint_url_token` in stream GET responses | Token leak |
| Using `logger.error` for quarantine/warning paths | Startup uses ✅/⚠️/❌ semantics; warnings should be `logger.warning` |

---

## Versioning and releases

- Semver tags: `v0.5.x`
- Changelog: [`CHANGELOG.md`](CHANGELOG.md) (Keep a Changelog format)
- Docker image: `ghcr.io/solarssk/ssf-transmitter:<version>`
- `APP_VERSION` is set at image build time; local dev shows `dev`

---

## Pull requests

- Run `ruff check .` and `pytest` before pushing.
- Security changes: mention operator impact in PR body (env vars, upgrade steps).
- Operator-facing changes: update `docs/` (not only README).
- Do not commit secrets, `.env`, or `stack.env`.
- Pin GitHub Actions by commit SHA (repo convention).

---

## Where to look for specific tasks

| Task | Start here |
|---|---|
| New Authentik event mapping | `app/events/mapper.py`, `app/models.py`, `tests/test_mapper.py` |
| Stream CRUD / PATCH semantics | `app/routes/streams.py`, `app/database.py` |
| Webhook auth modes | `app/routes/webhook.py`, `app/config.py`, `tests/test_webhook_auth_modes.py` |
| Outbound push / DNS rebinding | `app/events/pusher.py`, `tests/test_pusher.py` |
| Env var / startup validation | `app/config.py`, `app/startup.py`, `tests/test_config_security.py` |
| Apple SCIM | `app/scim/`, `app/routes/apple_scim.py` |
| Rate limits | `app/rate_limit.py`, route decorators, `tests/test_security_headers.py` |
