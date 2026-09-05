"""Regression tests for scripts/generate-release-notes.py.

Companion to test_sync_release_docs.py: guards that this script's own
CHANGELOG.md parsing (HEADER_RE / SECTION_RE) keeps handling a release
title containing "]" correctly (e.g. quoting a CVE ID or a code
identifier) — see AGENTS.md's "Cutting a release" checklist. Unlike
sync-release-docs.py's now-fixed `patterns_for()` regexes, this script's
title capture (`(.+?)\\s*$`, anchored on end-of-line) was already correct;
these tests pin that down so it can't regress silently.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "generate-release-notes.py"

BRACKET_TITLE = "Fix [CVE-2026-1234] token disclosure"


def _load_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("generate_release_notes", SCRIPT_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def generate_release_notes() -> ModuleType:
    return _load_module()


def test_parse_sections_preserves_bracket_title_and_body(generate_release_notes):
    changelog = (
        "## [Unreleased]\n\n"
        f"## [0.5.12] — 2026-10-01 — {BRACKET_TITLE}\n\n"
        "### Security\n\n"
        "- did stuff\n\n"
        "## [0.5.11] — 2026-09-01 — Earlier release\n\n"
        "- earlier stuff\n"
    )

    sections = generate_release_notes.parse_sections(changelog)

    assert "0.5.12" in sections
    date, title, body = sections["0.5.12"]
    assert date == "2026-10-01"
    assert title == BRACKET_TITLE
    assert body == "### Security\n\n- did stuff"
    # The next release's own heading must correctly bound this section's
    # body — a bracket in the title must not confuse SECTION_RE's boundary
    # detection and swallow the following entry.
    assert "earlier stuff" not in body


def test_main_writes_notes_file_for_bracket_title(tmp_path, generate_release_notes, monkeypatch):
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(
        f"## [Unreleased]\n\n## [0.5.12] — 2026-10-01 — {BRACKET_TITLE}\n\n- did stuff\n",
        encoding="utf-8",
    )
    out_dir = tmp_path / ".github" / "release-notes"

    monkeypatch.setattr(generate_release_notes, "CHANGELOG", changelog)
    monkeypatch.setattr(generate_release_notes, "OUT_DIR", out_dir)
    monkeypatch.setattr("sys.argv", ["generate-release-notes.py", "0.5.12"])

    assert generate_release_notes.main() == 0

    out_path = out_dir / "v0.5.12.md"
    assert out_path.exists()
    assert "did stuff" in out_path.read_text(encoding="utf-8")
