<!--
Required PR format for this repository.
All human- and AI-authored PRs should follow this structure.
If a checklist item does not apply, keep it and add a brief note instead of deleting it.
-->

## Summary

<!--
What changed and why, in plain language. For a security fix or hardening
change, say what the operator-facing impact is (new/changed env vars,
upgrade steps, behavior change) — see AGENTS.md's Pull requests section.
For CI/docs/dependency-only changes, say so explicitly; the rest of this
template can stay short.
-->

## Test plan

<!--
Concrete verification: which commands you ran (ruff/mypy/pytest at minimum),
and how you exercised the change beyond the test suite if relevant (manual
API calls, a running container, etc). If tests weren't run, say so and why.
-->

---

## Checklist

- [ ] `ruff check .`, `ruff format --check .`, `mypy`, and `pytest` all pass locally
- [ ] No secrets, tokens, or `.env`/`stack.env` content in the diff
- [ ] GitHub Actions pinned by commit SHA (repo convention — see AGENTS.md)
- [ ] `CHANGELOG.md`'s `## [Unreleased]` section updated, if this is a user-visible change
- [ ] `docs/` updated, if this changes operator-facing behavior (not just README)
- [ ] New/changed security-sensitive code has a regression test (see CLAUDE.md's High-risk areas table)
