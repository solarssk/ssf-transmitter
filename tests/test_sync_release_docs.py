"""Regression tests for scripts/sync-release-docs.py.

Covers CHANGELOG.md release titles containing punctuation that used to
confuse `patterns_for()`'s docs/README.md "Current stable release" regex —
see AGENTS.md's "Cutting a release" checklist:

- A title containing "]" (e.g. quoting a CVE ID). The original `[^\\]]+`
  stopped at the title's own first "]" and could never match the line
  again once such a title was written — so `sync-release-docs.py` then
  `--check` would fail with "pattern not found" on the very release that
  introduced it.
- A title containing its own `[x](y)` markdown link. A generic
  `.+?\\]\\([^)]+\\)` closer (the first fix's approach) is non-greedy and
  stops at the title's own inner `](...)`, not the line's real closing
  link — so the first sync leaves the real `](url)` dangling unreplaced,
  and a later run's `--check` matches only the truncated prefix, missing
  the leftover fragment entirely. Fixed by anchoring the closer to this
  repo's specific github.com release URL shape instead of "any non-)".
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
MARKDOWN_LINK_TITLE = "Fix [CVE-2026-1234](https://example.com/advisory) token disclosure"


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


@pytest.mark.parametrize("title", [BRACKET_TITLE, MARKDOWN_LINK_TITLE])
@pytest.mark.parametrize(
    ("rel", "old_line"),
    [
        (
            "docs/README.md",
            "**Current stable release:** `v0.5.11` — [Old title]"
            "(https://github.com/solarssk/ssf-transmitter/releases/tag/v0.5.11)",
        ),
    ],
)
def test_current_release_pattern_matches_and_replaces_punctuated_title(sync_release_docs, rel, old_line, title):
    version = "0.5.12"
    patterns = {r: (pattern, replacement) for r, pattern, replacement in sync_release_docs.patterns_for(version, title)}
    pattern, replacement = patterns[rel]

    assert re.search(pattern, old_line), f"pattern for {rel} should match the pre-existing line"
    updated = re.sub(pattern, lambda _m, r=replacement: r, old_line, count=1)
    assert updated == replacement, "sync must replace the *whole* old line, leaving no leftover fragment"

    # The critical regression: re-running the *same* pattern against the
    # freshly-written line (now itself containing a punctuated title) must
    # still match the *entire* line, exactly as `--check` does on a
    # subsequent run — a partial match here means a corrupted doc.
    rerun = re.search(pattern, updated)
    assert rerun, f"pattern for {rel} must still match its own {title!r} output"
    assert rerun.group(0) == updated, f"pattern for {rel} must match the full line, not a truncated prefix"


@pytest.mark.parametrize("title", [BRACKET_TITLE, MARKDOWN_LINK_TITLE])
def test_main_end_to_end_survives_punctuated_title(tmp_path, sync_release_docs, monkeypatch, title):
    """Full main() round-trip: sync then --check must both succeed once a
    CHANGELOG title containing "]" or its own markdown link has actually
    been written into the docs.
    """
    version = "0.5.12"
    (tmp_path / "pyproject.toml").write_text(f'[project]\nversion = "{version}"\n', encoding="utf-8")
    (tmp_path / "CHANGELOG.md").write_text(
        f"## [Unreleased]\n\n## [{version}] — 2026-10-01 — {title}\n\n- did stuff\n",
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
    only_docs_readme = {"docs/README.md"}
    monkeypatch.setattr(
        sync_release_docs,
        "patterns_for",
        lambda v, t: tuple(p for p in original_patterns_for(v, t) if p[0] in only_docs_readme),
    )

    monkeypatch.setattr(sys, "argv", ["sync-release-docs.py"])
    assert sync_release_docs.main() == 0

    docs_readme_text = (tmp_path / "docs" / "README.md").read_text(encoding="utf-8")
    assert f"`v{version}` — [{title}]" in docs_readme_text

    monkeypatch.setattr(sys, "argv", ["sync-release-docs.py", "--check"])
    assert sync_release_docs.main() == 0
