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
| Documentation | Operator docs live in [`README.md`](../README.md) and [`docs/`](../docs/); the threat model is [`SECURITY.md`](../SECURITY.md). See [Documentation split](../AGENTS.md#documentation-split) in AGENTS.md for which doc covers what. |

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
   [AGENTS.md](../AGENTS.md#before-making-changes).

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

## Questions

Open a GitHub issue, or reach **@solarssk**.
