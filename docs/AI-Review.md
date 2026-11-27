# Automated pull-request review

The SSF reviewer reads changes and submits a commit-specific review as `github-actions[bot]`. It does not merge, push, or change labels. CI and the maintainer's final merge decision remain separate.

## Configure the repository

1. Generate a Claude subscription token on your workstation with `claude setup-token`. Store it as the repository Actions secret `CLAUDE_CODE_OAUTH_TOKEN`. Do not put it in chat, source files, or workflow logs. This uses the subscription and its shared usage limits, not an Anthropic API key. Keep the SSF secret separate from other repositories.
2. Under **Settings → Actions → General → Workflow permissions**, enable **Allow GitHub Actions to create and approve pull requests**. Keep the default token permissions read-only; this workflow grants only `contents: read` and `pull-requests: write` to its review job.
3. Merge the reviewer workflow through the existing PR process. It cannot validate itself before reaching the default branch: `pull_request_target` deliberately uses the trusted base definition.
4. Open a same-repository test PR owned by the maintainer. Check that Claude completed the review and the resulting approval names the exact current head commit. Check a new push dismisses the approval and triggers another review. Provider failure must not issue approval.
5. Only after that validation, set required approvals to **1** and enable approval of the most recent push in both the classic branch protection and the active main ruleset. Retain all CI gates, administrator enforcement, strict up-to-date checks, and conversation resolution. No bypass is needed. Keep Code Owner review off while the sole CODEOWNER is also the PR author.

Do not turn on mandatory review before the first successful real review. Missing subscription access would otherwise block owner-authored PRs.

## Read the review result

Check both the **AI review** workflow run and the review attached to the current commit. A successful CI check alone does not establish that the bot approved the latest changes.

## Run or retry a review

Owner and Dependabot PRs from this repository targeting the default branch trigger review automatically after a 30-second debounce. Forks, drafts, other authors, and other base branches are excluded from this automation; they need manual review.

To rerun, use the **AI review** workflow in Actions, select the default branch, and enter the PR number. Only the repository owner may manually dispatch or rerun a review via that route. For a provider error, inspect the Actions failure, correct subscription access or wait for its usage limit to reset, then rerun.

An automated review can take up to 15 minutes; the full job has a 25-minute limit. There is no paid API fallback or policy-only approval. Each run consumes the configured Claude subscription allowance.

## Approval rules

Approval requires all of the following:

- The model action completed successfully and returned valid structured output.
- The reviewer declared the review complete and listed every changed file.
- The verdict is approve with no blocking findings.
- The full file list and patches are readable, match GitHub's change counts, and fit the 100-file / 250,000-byte review limit.
- The head commit, base commit, and complete diff are unchanged before publication. A post-publication check confirms the head and base again; if the target changed or cannot be checked, the publisher withdraws the exact approval it created.

All changed patches, including lockfiles and tests, are included. Missing patches (including binary or empty-only changes), large changes, incomplete coverage, findings, malformed results, or provider failures produce no approval. The model's coverage declaration is not proof of perfect analysis; this remains an automated review with limited context, not an independent human audit.

Once preparation reads the current head, it invalidates this reviewer's previous approval before checking eligibility and the base checkout. A new push also dismisses approvals under branch protection. Reviews include the marker `[ssf-ai-review]` so other bots' reviews are not dismissed by this workflow.

## Trust boundary

The workflow checks out only the base commit and fetches the PR patch as text. It executes no PR scripts, installs no PR dependencies, and does not check out the PR head. The model is restricted to read tools in that checkout, with shell, write, network/MCP tools unavailable. The prompt and output schema also come from the base commit.

PR content is untrusted input. Publication uses a separate deterministic script, validates the result, checks for credential-shaped text, and binds the review to the reviewed commit. Keep changes to this workflow, its prompt, schema, and publisher under close maintainer review.

Implementation: [workflow](../.github/workflows/ai-review.yml), [publisher](../scripts/ai-review.py), and [regression tests](../tests/test_ai_review.py).

GitHub review creation has no atomic base-commit condition. The post-publication check narrows the race window but cannot eliminate it, or prevent a brief approval before withdrawal. If withdrawal itself fails because GitHub is unavailable, inspect and dismiss the marked review before merging; the run fails and reports the need for inspection.
