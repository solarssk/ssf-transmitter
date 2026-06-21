# CLAUDE.md — Claude Code project instructions

Read **[`AGENTS.md`](AGENTS.md)** first — it is the canonical guide for all AI assistants in this repository.

This file adds Claude Code–specific notes only.

---

## Quick context

**ssf-transmitter** is a security-sensitive FastAPI bridge: Authentik webhooks → SSF SET push to Apple Business Manager (or other SSF receivers). Single stream, SQLite persistence, RS256 signing, Fernet-encrypted receiver tokens (v0.5.9+).

---

## Before making changes

1. Skim `AGENTS.md` → **Security invariants** and **Common pitfalls**.
2. For deployment/operator questions, use `README.md`, `docs/`, and `CHANGELOG.md`.
3. For threat model details, read `SECURITY.md`.

---

## Claude Code workflow

```bash
# Setup (Python 3.14)
python3.14 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt

# Verify before commit
ruff check .
pytest
```

- Prefer editing the smallest surface that fixes the issue.
- After security-related edits, check whether `tests/conftest.py` fixtures still apply and add a regression test.
- Do not create commits or PRs unless the user asks.

---

## High-risk areas (extra care)

| Area | Files |
|---|---|
| Receiver token encrypt/decrypt | `app/crypto.py`, `app/database.py` |
| Stream PATCH preserve semantics | `app/database.py`, `app/routes/streams.py` |
| SSRF / outbound push | `app/security/url_validation.py`, `app/events/pusher.py` |
| Auth boundaries | `app/auth.py`, `app/routes/webhook.py` |
| Rate limit decorator sharing | `app/routes/streams.py`, `app/rate_limit.py` |

When unsure, read existing tests in the matching `tests/test_*.py` file before implementing.

---

## Documentation split

| Audience | Location |
|---|---|
| Operators (Synology, NPM, env vars) | `README.md`, `docs/` |
| Security reviewers | `SECURITY.md` |
| AI assistants | `AGENTS.md` (this file is a supplement) |
| API consumers | `docs/API.md` |

Do not duplicate operator docs in `AGENTS.md` — link to `docs/` instead.
