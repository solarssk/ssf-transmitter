"""Prepare an immutable PR diff and publish only completed, current AI reviews."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from pathlib import Path
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / ".ai-review"
MAX_DIFF_BYTES = 250_000
BOT = "github-actions[bot]"
SECRET_PATTERN = re.compile(r"sk-ant-|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_|-----BEGIN")


def api(path: str, method: str = "GET", body: dict | None = None):
    """Use the job token only for GitHub's fixed API origin."""
    if not path.startswith("repos/"):
        raise ValueError("Unexpected GitHub API path")
    req = Request(
        "https://api.github.com/" + path,
        data=None if body is None else json.dumps(body).encode(),
        method=method,
        headers={
            "Authorization": "Bearer " + os.environ["GH_TOKEN"],
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urlopen(req, timeout=30) as response:  # noqa: S310 -- fixed GitHub API origin
        data = response.read()
    return json.loads(data) if data else None


def prefix() -> str:
    repo = os.environ["GITHUB_REPOSITORY"]
    number = os.environ["PR_NUMBER"]
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo) or not re.fullmatch(r"[1-9][0-9]*", number):
        raise ValueError("Invalid repository or PR number")
    return f"repos/{repo}/pulls/{number}"


def eligible(pr: dict) -> bool:
    repo = os.environ["GITHUB_REPOSITORY"]
    owner = repo.split("/")[0]
    return (
        pr["state"] == "open"
        and not pr["draft"]
        and pr["head"]["repo"]["full_name"] == repo
        and pr["base"]["repo"]["full_name"] == repo
        and pr["base"]["ref"] == os.environ["DEFAULT_BRANCH"]
        and pr["user"]["login"] in {owner, "dependabot[bot]"}
        and bool(re.fullmatch(r"[a-f0-9]{40}", pr["head"]["sha"]))
        and bool(re.fullmatch(r"[a-f0-9]{40}", pr["base"]["sha"]))
    )


def snapshot(pr: dict) -> dict:
    return {"head": pr["head"]["sha"], "base": pr["base"]["sha"], "base_ref": pr["base"]["ref"]}


def pages(path: str) -> list:
    result = []
    for page in range(1, 32):
        batch = api(f"{path}?per_page=100&page={page}")
        result.extend(batch)
        if len(batch) < 100:
            return result
    raise ValueError("GitHub pagination limit reached")


def dismiss(head: str) -> None:
    for review in pages(prefix() + "/reviews"):
        if (
            review["user"]["login"] == BOT
            and review["state"] == "APPROVED"
            and review["commit_id"] == head
            and review.get("body", "").startswith("[ssf-ai-review]")
        ):
            api(
                prefix() + f"/reviews/{review['id']}/dismissals",
                "PUT",
                {"message": "A new review attempt invalidates this bot's previous approval."},
            )


def build_diff(files: list[dict], expected_count: int) -> str:
    if not files or len(files) != expected_count or len(files) > 100:
        raise ValueError("Incomplete or oversized changed-file list")
    parts = []
    for file in files:
        patch = file.get("patch")
        if not isinstance(patch, str) or not patch:
            raise ValueError("A changed file has no readable patch")
        # The API can omit or truncate large/binary patches; never approve unseen changes.
        if (
            sum(line.startswith("+") for line in patch.splitlines()) != file["additions"]
            or sum(line.startswith("-") for line in patch.splitlines()) != file["deletions"]
        ):
            raise ValueError("Patch does not cover all reported changes")
        parts.append(json.dumps({k: file[k] for k in ("filename", "status", "previous_filename") if k in file}))
        parts.append(patch)
    diff = "\n".join(parts)
    if len(diff.encode()) > MAX_DIFF_BYTES:
        raise ValueError("Diff exceeds the automated review limit")
    return diff


def prepare() -> None:
    pr = api(prefix())
    if not eligible(pr) or snapshot(pr)["base"] != os.environ["CHECKOUT_SHA"]:
        raise ValueError("PR is ineligible or base checkout changed")
    # Re-review failure must not leave an older approval of the same head alive.
    dismiss(pr["head"]["sha"])
    files = pages(prefix() + "/files")
    diff = build_diff(files, pr["changed_files"])
    if snapshot(api(prefix())) != snapshot(pr):
        raise ValueError("PR changed while collecting the diff")
    STATE.mkdir(exist_ok=True)
    (STATE / "pr.diff").write_text(diff)
    (STATE / "target.json").write_text(
        json.dumps(
            {
                **snapshot(pr),
                "files": [f["filename"] for f in files],
                "digest": hashlib.sha256(diff.encode()).hexdigest(),
            }
        )
    )


def verdict(raw: str, files: list[str], outcome: str) -> tuple[bool, str]:
    if outcome != "success":
        raise ValueError("Model did not complete successfully")
    value = json.loads(raw)
    if not isinstance(value, dict) or set(value) != {
        "verdict",
        "complete",
        "reviewed_files",
        "summary",
        "blocking_findings",
    }:
        raise ValueError("Invalid model result")
    if value["verdict"] not in {"approve", "comment"} or type(value["complete"]) is not bool:
        raise ValueError("Invalid verdict")
    reviewed = value["reviewed_files"]
    if not isinstance(reviewed, list) or any(not isinstance(item, str) for item in reviewed):
        raise ValueError("Invalid reviewed-file list")
    if not value["complete"] or sorted(reviewed) != sorted(files):
        raise ValueError("Review did not cover every changed file")
    summary = value["summary"]
    findings = value["blocking_findings"]
    if not isinstance(summary, str) or not summary.strip() or not isinstance(findings, list):
        raise ValueError("Missing review summary or findings")
    lines = [summary]
    for finding in findings:
        if not isinstance(finding, dict) or set(finding) != {"file", "issue"}:
            raise ValueError("Invalid finding")
        if finding["file"] not in files or not isinstance(finding["issue"], str) or not finding["issue"].strip():
            raise ValueError("Invalid finding target")
        lines.append(f"- {finding['file']}: {finding['issue']}")
    body = "\n\n".join(lines)
    if len(body) > 12_000 or SECRET_PATTERN.search(body):
        raise ValueError("Review text is unsafe or oversized")
    return value["verdict"] == "approve" and not findings, body


def submit() -> bool:
    target = json.loads((STATE / "target.json").read_text())
    current = api(prefix())
    if not eligible(current) or snapshot(current) != {k: target[k] for k in ("head", "base", "base_ref")}:
        raise ValueError("PR target changed; no review published")
    files = pages(prefix() + "/files")
    diff = build_diff(files, current["changed_files"])
    if hashlib.sha256(diff.encode()).hexdigest() != target["digest"]:
        raise ValueError("Diff changed; no review published")
    approve, text = verdict(os.environ.get("STRUCTURED", ""), target["files"], os.environ.get("MODEL_OUTCOME", ""))
    body = (
        f"[ssf-ai-review] Automated Claude review of `{target['head']}`. "
        f"The maintainer merges; CI still applies.\n\n{text}"
    )
    # Full comparison immediately before posting, including the base commit.
    final = api(prefix())
    if not eligible(final) or snapshot(final) != snapshot(current):
        raise ValueError("PR changed before publication")
    api(
        prefix() + "/reviews",
        "POST",
        {"commit_id": target["head"], "event": "APPROVE" if approve else "COMMENT", "body": body},
    )
    return approve


def main() -> int:
    try:
        if sys.argv[1:] == ["prepare"]:
            prepare()
            return 0
        if sys.argv[1:] == ["submit"]:
            return 0 if submit() else 1
        raise ValueError("Expected prepare or submit")
    except ValueError, KeyError, OSError, TypeError:
        # Never echo raw provider/API errors or untrusted model output into public logs.
        print("AI review incomplete, unsafe, stale, or failed; no approval was issued.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
