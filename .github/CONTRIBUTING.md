# Contributing to ssf-transmitter

Thanks for your interest in ssf-transmitter. This document covers the practical
steps for proposing a change. Project conventions that matter for correctness
(security invariants, coding style, high-risk areas) live in
[AGENTS.md](../AGENTS.md) and [SECURITY.md](../SECURITY.md); this file is a
quick-start on top of them, not a replacement.

## Before you start

- For anything beyond a small fix, open an issue first to discuss the approach.
- Search existing issues before opening a new one.
- Found a security vulnerability? Do **not** open a public issue — see
  [SECURITY.md](../SECURITY.md) for the reporting process.

## Ways to contribute

| Type | Where to start |
|---|---|
| Bug report | Open a [Bug report](https://github.com/solarssk/ssf-transmitter/issues/new?template=bug_report.yml) issue. Include the version/tag, reproduction steps, and expected vs. actual behaviour. Strip tokens, webhook payloads, and any real user data from logs first. |
| Feature request | Open a [Feature request](https://github.com/solarssk/ssf-transmitter/issues/new?template=feature_request.yml) issue. |
| Code change | Branch and open a pull request (see below). |
| Documentation | Operator docs live in [`README.md`](../README.md) and [`docs/`](../docs/); the threat model is [`SECURITY.md`](../SECURITY.md). See [Documentation split](../CLAUDE.md#documentation-split) in CLAUDE.md for which doc covers what. |

## Development setup

Setup, environment variables, and local run instructions are documented once,
in the README's [Quick start](../README.md). AI coding assistants working in
this repo should read [AGENTS.md](../AGENTS.md) first — it's the canonical
guide and this file assumes it.

## Making a change

1. Branch from `main` using this repo's existing prefix convention:

   | Prefix | Use for |
   |---|---|
   | `fix/<slug>` | Bug fixes |
   | `security/<slug>` | Security fixes or hardening |
   | `ci/<slug>` | CI/workflow changes |
   | `test/<slug>` | Test-only changes |
   | `docs/<slug>` | Documentation only |
   | `chore/<slug>` | Maintenance, dependency bumps, tooling |
   | `release/<version>` | Release PRs (see [Cutting a release](../AGENTS.md#cutting-a-release) in AGENTS.md) |

2. Before pushing, run:
   ```bash
   ruff check . && ruff format --check . && mypy && pytest
   ```
   CI runs the same checks (plus `deptry`, `pip-audit`, a Docker build+boot
   smoke test on both published architectures, and a Trivy scan) — a locally
   green suite isn't a guarantee, but a locally red one will fail CI for sure.

3. After a security-related change, check whether `tests/conftest.py`'s
   fixtures still apply and add a regression test — see
   [CLAUDE.md](../CLAUDE.md#before-making-changes).

## Using AI coding tools

AI-assisted contributions are welcome — this project is itself built with heavy
AI-agent involvement (see [AGENTS.md](../AGENTS.md) and
[CLAUDE.md](../CLAUDE.md), the instructions this repo already ships for coding
agents). If you use one to help write a PR, the same bar applies as to any
other contribution: you're responsible for what you submit, not the tool.

- **Read and understand every line before submitting.** Don't paste agent
  output you haven't verified against the actual codebase.
- **Run it, don't guess.** `ruff`, `mypy`, and the real `pytest` suite — see
  [Making a change](#making-a-change) above.
- **Keep the diff scoped to the issue.** Agents tend to "improve" adjacent
  code or add speculative abstractions. Resist that.
- **Don't invent.** No fabricated APIs, made-up test coverage, or confident
  claims about behaviour you haven't actually checked.
- **Write commits and PR text like a human would** — describe what changed and
  why, not tool-generated boilerplate.

## Opening a pull request

Use the repository's [PR template](pull_request_template.md). Fill in the
checklist honestly rather than deleting items that don't apply.

ssf-transmitter is currently a single-maintainer project: @solarssk reviews
and merges every PR, including their own, once CI is green — there's no one
else to hand it to yet. Branches are deleted automatically on merge.

## Merge protection and the engineering standard

This repository follows [playbook v0.3.0](https://github.com/solarssk/playbook/tree/v0.3.0)
at Tier 2. The reusable verifier is pinned to that release's full commit SHA.
A green verifier result covers automated checks only; its assessment remains
partial, and repository settings are not checked on the PR path. Do not pass
an administrative token to a pull-request workflow.

The active [SSF main protection ruleset](https://github.com/solarssk/ssf-transmitter/rules/26756303)
has no bypass actors, including administrators. It requires a pull request,
resolved review conversations and an up-to-date branch; force pushes and branch
deletion are blocked. The existing classic protection remains enabled alongside
it. Required approvals stay at **0** for the solo maintainer; revisit this choice
when a second maintainer gets write access.

These exact check contexts are required, all bound to the GitHub Actions app
(integration ID `15368`):

| Required check | Purpose |
|---|---|
| `Test and lint` | Tests, lint, types, workflow audits, dependency audit and image checks |
| `Analyze (python)` | Python CodeQL analysis |
| `Analyze (actions)` | GitHub Actions CodeQL analysis |
| `Dependency review` | Newly introduced dependency vulnerabilities |
| `Verify uv.lock matches pyproject.toml` | Shared lock consistency |
| `verify / verify` | Playbook automated tier checks |

Keep GitHub's required-check settings in sync with workflow job names. Confirm
the exact contexts and source app on a real PR before changing the settings;
adding or renaming workflow files alone does not update merge enforcement.
These contexts were verified on [PR #210](https://github.com/solarssk/ssf-transmitter/pull/210).
After the ruleset rollout, use the next real PR to confirm successful merging
and rejection of a failing required check; an API settings inspection alone
does not test that behaviour.

Scorecard remains a report, not a PR gate. The separate `CodeQL` report and
CodeRabbit, Codecov and SonarCloud checks are not required merge contexts.
Codecov coverage upload errors still fail CI when its token is available;
JUnit Test Analytics uses `codecov/codecov-action` with `report_type: test_results`,
retains uploads after failed tests and does not fail CI on upload errors.
Fork and Dependabot runs without the token still skip these uploads.

These changes affect repository maintenance only: deployed containers need no
new environment variables, tokens or database migrations.

## Questions

Open a GitHub issue, or reach **@solarssk**.
