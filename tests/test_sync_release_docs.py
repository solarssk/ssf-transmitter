"""Regression tests for scripts/sync-release-docs.py.

Covers a CHANGELOG.md release title containing "]" (e.g. quoting a CVE ID
or a code identifier) — see AGENTS.md's "Cutting a release" checklist.
Before the fix, `patterns_for()`'s README.md/docs/README.md "Current
release" regexes used `[^\\]]+` for the embedded title, which stopped at
the title's own first "]" and could never match the line again once such a
title was written — so `sync-release-docs.py` then `--check` would fail
with "pattern not found" on the very release that introduced it.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path
from types import ModuleType

import pytest

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "sync-release-docs.py"

BRACKET_TITLE = "Fix [CVE-2026-1234] token disclosure"


def _load_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("sync_release_docs", SCRIPT_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def sync_release_docs() -> ModuleType:
    return _load_module()


def test_read_title_for_preserves_brackets_in_title(tmp_path, sync_release_docs, monkeypatch):
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(
        f"## [Unreleased]\n\n## [0.5.12] — 2026-10-01 — {BRACKET_TITLE}\n\n- did stuff\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(sync_release_docs, "CHANGELOG", changelog)

    assert sync_release_docs.read_title_for("0.5.12") == BRACKET_TITLE


@pytest.mark.parametrize(
    ("rel", "old_line"),
    [
        (
            "README.md",
            "**Current release:** [v0.5.11 — Old title]"
            "(https://github.com/solarssk/ssf-transmitter/releases/tag/v0.5.11)",
        ),
        (
            "docs/README.md",
            "**Current stable release:** `v0.5.11` — [Old title]"
            "(https://github.com/solarssk/ssf-transmitter/releases/tag/v0.5.11)",
        ),
    ],
)
def test_current_release_pattern_matches_and_replaces_bracket_title(sync_release_docs, rel, old_line):
    version = "0.5.12"
    patterns = {
        r: (pattern, replacement) for r, pattern, replacement in sync_release_docs.patterns_for(version, BRACKET_TITLE)
    }
    pattern, replacement = patterns[rel]

    assert re.search(pattern, old_line), f"pattern for {rel} should match the pre-existing line"
    updated = re.sub(pattern, lambda _m, r=replacement: r, old_line, count=1)
    assert updated == replacement

    # The critical regression: re-running the *same* pattern against the
    # freshly-written line (now itself containing a title with "]") must
    # still match, exactly as `--check` does on a subsequent run.
    assert re.search(pattern, updated), f"pattern for {rel} must still match its own bracket-title output"


def test_main_end_to_end_survives_bracket_title(tmp_path, sync_release_docs, monkeypatch):
    """Full main() round-trip: sync then --check must both succeed once a
    CHANGELOG title containing "]" has actually been written into the docs.
    """
    version = "0.5.12"
    (tmp_path / "pyproject.toml").write_text(f'[project]\nversion = "{version}"\n', encoding="utf-8")
    (tmp_path / "CHANGELOG.md").write_text(
        f"## [Unreleased]\n\n## [{version}] — 2026-10-01 — {BRACKET_TITLE}\n\n- did stuff\n",
        encoding="utf-8",
    )
    (tmp_path / "README.md").write_text(
        "Intro.\n\n"
        "**Current release:** [v0.5.11 — Old title]"
        "(https://github.com/solarssk/ssf-transmitter/releases/tag/v0.5.11)\n\n"
        "More.\n",
        encoding="utf-8",
    )
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "README.md").write_text(
        "**Current stable release:** `v0.5.11` — [Old title]"
        "(https://github.com/solarssk/ssf-transmitter/releases/tag/v0.5.11)\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(sync_release_docs, "ROOT", tmp_path)
    monkeypatch.setattr(sync_release_docs, "PYPROJECT", tmp_path / "pyproject.toml")
    monkeypatch.setattr(sync_release_docs, "CHANGELOG", tmp_path / "CHANGELOG.md")

    original_patterns_for = sync_release_docs.patterns_for
    only_readmes = {"README.md", "docs/README.md"}
    monkeypatch.setattr(
        sync_release_docs,
        "patterns_for",
        lambda v, t: tuple(p for p in original_patterns_for(v, t) if p[0] in only_readmes),
    )

    monkeypatch.setattr(sys, "argv", ["sync-release-docs.py"])
    assert sync_release_docs.main() == 0

    readme_text = (tmp_path / "README.md").read_text(encoding="utf-8")
    assert f"[v{version} — {BRACKET_TITLE}]" in readme_text

    monkeypatch.setattr(sys, "argv", ["sync-release-docs.py", "--check"])
    assert sync_release_docs.main() == 0
