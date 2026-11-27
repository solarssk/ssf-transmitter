"""Fail-closed review publication and immutable target regression tests."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location("review", Path(__file__).resolve().parents[1] / "scripts/ai-review.py")
assert SPEC is not None
assert SPEC.loader is not None
review = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(review)


def result(**changes):
    return json.dumps(
        {
            "verdict": "approve",
            "complete": True,
            "reviewed_files": ["app/main.py"],
            "summary": "Checked the complete patch and its base context.",
            "blocking_findings": [],
            **changes,
        }
    )


def pr(**changes):
    return {
        "state": "open",
        "draft": False,
        "user": {"login": "solarssk"},
        "head": {"sha": "a" * 40, "repo": {"full_name": "solarssk/ssf-transmitter"}},
        "base": {"sha": "b" * 40, "ref": "main", "repo": {"full_name": "solarssk/ssf-transmitter"}},
        "changed_files": 1,
        **changes,
    }


@pytest.fixture(autouse=True)
def environment(monkeypatch):
    monkeypatch.setenv("GITHUB_REPOSITORY", "solarssk/ssf-transmitter")
    monkeypatch.setenv("PR_NUMBER", "12")
    monkeypatch.setenv("DEFAULT_BRANCH", "main")
    monkeypatch.setenv("CHECKOUT_SHA", "b" * 40)


def test_complete_clean_review_can_approve():
    assert review.verdict(result(), ["app/main.py"], "success")[0]


@pytest.mark.parametrize("outcome", ["", "failure", "cancelled", "skipped"])
def test_provider_failure_is_never_an_approval(outcome):
    raw = result()
    with pytest.raises(ValueError):
        review.verdict(raw, ["app/main.py"], outcome)


@pytest.mark.parametrize("raw", ["", "{}", "[]", "null", "not json"])
def test_invalid_provider_result_is_rejected(raw):
    with pytest.raises(ValueError):
        review.verdict(raw, ["app/main.py"], "success")


@pytest.mark.parametrize(
    "changes",
    [
        {"complete": False},
        {"reviewed_files": []},
        {"reviewed_files": ["other.py"]},
        {"reviewed_files": ["app/main.py", "app/main.py"]},
        {"summary": ""},
        {"complete": "true"},
        {"summary": "sk-ant-fake-token"},
    ],
)
def test_incomplete_or_unsafe_review_is_rejected(changes):
    raw = result(**changes)
    with pytest.raises(ValueError):
        review.verdict(raw, ["app/main.py"], "success")


def test_findings_override_approve_verdict():
    assert not review.verdict(
        result(blocking_findings=[{"file": "app/main.py", "issue": "Concrete broken path"}]), ["app/main.py"], "success"
    )[0]


def test_fork_draft_and_untrusted_author_are_ineligible():
    assert review.eligible(pr())
    assert not review.eligible(pr(draft=True))
    assert not review.eligible(pr(user={"login": "unknown"}))
    assert not review.eligible(pr(head={"sha": "a" * 40, "repo": {"full_name": "other/fork"}}))
    assert review.eligible(pr(user={"login": "dependabot[bot]"}))


def file_patch(**changes):
    return {
        "filename": "app/main.py",
        "status": "modified",
        "patch": "@@ -1 +1 @@\n-old\n+new",
        "additions": 1,
        "deletions": 1,
        **changes,
    }


@pytest.mark.parametrize(
    "files,count",
    [
        ([], 1),
        ([file_patch()], 2),
        ([file_patch(patch=None)], 1),
        ([file_patch(additions=2)], 1),
        ([file_patch(deletions=0)], 1),
    ],
)
def test_unreadable_or_incomplete_diff_is_rejected(files, count):
    with pytest.raises(ValueError):
        review.build_diff(files, count)


def test_diff_limit_is_enforced(monkeypatch):
    monkeypatch.setattr(review, "MAX_DIFF_BYTES", 1)
    files = [file_patch()]
    with pytest.raises(ValueError):
        review.build_diff(files, 1)


def test_prepare_dismisses_old_approval_before_unreadable_diff(monkeypatch):
    calls = []
    monkeypatch.setattr(review, "api", lambda path: pr())
    monkeypatch.setattr(review, "dismiss", lambda head: calls.append(head))
    monkeypatch.setattr(review, "pages", lambda path: [file_patch(patch=None)])
    with pytest.raises(ValueError):
        review.prepare()
    assert calls == ["a" * 40]


@pytest.mark.parametrize("change", ["head", "base"])
def test_changed_target_never_posts_review(monkeypatch, tmp_path, change):
    monkeypatch.setattr(review, "STATE", tmp_path)
    target = {**review.snapshot(pr()), "files": ["app/main.py"], "digest": "unused"}
    (tmp_path / "target.json").write_text(json.dumps(target))
    changed = pr()
    changed[change]["sha"] = "c" * 40
    calls = []

    def fake_api(path, method="GET", body=None):
        calls.append(method)
        return changed

    monkeypatch.setattr(review, "api", fake_api)
    with pytest.raises(ValueError):
        review.submit()
    assert calls == ["GET"]


def test_submit_binds_approval_to_exact_head(monkeypatch, tmp_path):
    monkeypatch.setattr(review, "STATE", tmp_path)
    files = [file_patch()]
    import hashlib

    digest = hashlib.sha256(review.build_diff(files, 1).encode()).hexdigest()
    (tmp_path / "target.json").write_text(
        json.dumps({**review.snapshot(pr()), "files": ["app/main.py"], "digest": digest})
    )
    monkeypatch.setenv("STRUCTURED", result())
    monkeypatch.setenv("MODEL_OUTCOME", "success")
    monkeypatch.setattr(review, "pages", lambda path: files)
    posts = []

    def fake_api(path, method="GET", body=None):
        if method == "POST":
            posts.append(body)
            return {"id": 123}
        return pr()

    monkeypatch.setattr(review, "api", fake_api)
    assert review.submit()
    assert posts[0]["commit_id"] == "a" * 40
    assert posts[0]["event"] == "APPROVE"


def test_only_this_reviewers_approvals_are_dismissed(monkeypatch):
    records = [
        {
            "id": 1,
            "user": {"login": review.BOT},
            "state": "APPROVED",
            "commit_id": "a" * 40,
            "body": "[ssf-ai-review] old review",
        },
        {
            "id": 2,
            "user": {"login": review.BOT},
            "state": "APPROVED",
            "commit_id": "a" * 40,
            "body": "Other automation",
        },
        {
            "id": 3,
            "user": {"login": "human"},
            "state": "APPROVED",
            "commit_id": "a" * 40,
            "body": "[ssf-ai-review] quoted",
        },
    ]
    monkeypatch.setattr(review, "pages", lambda path: records)
    calls = []
    monkeypatch.setattr(review, "api", lambda path, method, body: calls.append(path))
    review.dismiss("a" * 40)
    assert calls == ["repos/solarssk/ssf-transmitter/pulls/12/reviews/1/dismissals"]


def test_workflow_never_checks_out_pr_code():
    workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/ai-review.yml").read_text()
    assert "ref: ${{ steps.target.outputs.base_sha }}" in workflow
    assert "pull_request.head.sha" not in workflow
    assert "persist-credentials: false" in workflow
    assert '--tools "Read,Grep,Glob"' in workflow
    assert "--permission-mode dontAsk" in workflow
    assert "--strict-mcp-config" in workflow
    assert "MODEL_OUTCOME: ${{ steps.model.outcome }}" in workflow


def test_closed_pr_between_validation_and_post_is_not_approved(monkeypatch, tmp_path):
    monkeypatch.setattr(review, "STATE", tmp_path)
    files = [file_patch()]
    import hashlib

    digest = hashlib.sha256(review.build_diff(files, 1).encode()).hexdigest()
    (tmp_path / "target.json").write_text(
        json.dumps({**review.snapshot(pr()), "files": ["app/main.py"], "digest": digest})
    )
    monkeypatch.setenv("STRUCTURED", result())
    monkeypatch.setenv("MODEL_OUTCOME", "success")
    monkeypatch.setattr(review, "pages", lambda path: files)
    reads = iter([pr(), pr(state="closed")])

    def fake_api(path, method="GET", body=None):
        assert method == "GET", "Closed PR must never receive an approval"
        return next(reads)

    monkeypatch.setattr(review, "api", fake_api)
    with pytest.raises(ValueError, match="changed before publication"):
        review.submit()


@pytest.mark.parametrize("failure", ["base", "ineligible"])
def test_prepare_dismisses_previous_approval_before_guard_failure(monkeypatch, failure):
    calls = []
    current = pr(draft=True) if failure == "ineligible" else pr()
    monkeypatch.setenv("CHECKOUT_SHA", "c" * 40)
    monkeypatch.setattr(review, "api", lambda path: current)
    monkeypatch.setattr(review, "dismiss", lambda head: calls.append(head))
    with pytest.raises(ValueError, match="ineligible or base checkout changed"):
        review.prepare()
    assert calls == ["a" * 40]


@pytest.mark.parametrize("failure", ["head", "base", "closed", "read"])
def test_post_publication_target_failure_withdraws_exact_new_approval(monkeypatch, tmp_path, failure):
    monkeypatch.setattr(review, "STATE", tmp_path)
    files = [file_patch()]
    import hashlib

    digest = hashlib.sha256(review.build_diff(files, 1).encode()).hexdigest()
    (tmp_path / "target.json").write_text(
        json.dumps({**review.snapshot(pr()), "files": ["app/main.py"], "digest": digest})
    )
    monkeypatch.setenv("STRUCTURED", result())
    monkeypatch.setenv("MODEL_OUTCOME", "success")
    monkeypatch.setattr(review, "pages", lambda path: files)
    changed = pr()
    if failure in {"head", "base"}:
        changed[failure]["sha"] = "c" * 40
    elif failure == "closed":
        changed["state"] = "closed"
    reads = iter([pr(), pr(), changed])
    calls = []

    def fake_api(path, method="GET", body=None):
        calls.append((method, path))
        if method == "POST":
            return {"id": 987}
        if method == "PUT":
            return {}
        value = next(reads)
        if failure == "read" and len(calls) == 4:
            raise OSError("API read failed")
        return value

    monkeypatch.setattr(review, "api", fake_api)
    with pytest.raises((ValueError, OSError)):
        review.submit()
    assert calls[-1] == ("PUT", "repos/solarssk/ssf-transmitter/pulls/12/reviews/987/dismissals")
    assert sum(method == "POST" for method, _ in calls) == 1
