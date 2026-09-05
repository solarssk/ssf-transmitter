"""Regression tests for scripts/sync-wiki.py.

Covers the link-rewriting logic that lets a docs/*.md page keep its normal
relative markdown links while still rendering correctly once copied into
the wiki's flat, extension-less page namespace: a link to another synced
page becomes a bare page name, a link to a real repo file that isn't
synced (SECURITY.md, CHANGELOG.md, a non-markdown file) becomes a GitHub
blob URL, and an external link is left untouched. Also pins down that
docs/README.md is deliberately excluded from MAPPING (it would clobber
Home.md's hand-curated content on the wiki) so that exclusion can't
silently regress.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "sync-wiki.py"
ROOT = SCRIPT_PATH.parents[1]


def _load_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("sync_wiki", SCRIPT_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def sync_wiki() -> ModuleType:
    return _load_module()


def test_every_mapped_source_file_exists(sync_wiki):
    for repo_relative in sync_wiki.MAPPING:
        assert (ROOT / repo_relative).is_file(), f"{repo_relative} in MAPPING but missing on disk"


def test_docs_readme_not_mapped(sync_wiki):
    assert "docs/README.md" not in sync_wiki.MAPPING


def test_rewrites_link_to_mapped_page(sync_wiki):
    source = Path("docs/Deployment.md")
    assert sync_wiki._rewrite_link("Configuration.md", source) == "Configuration"


def test_preserves_anchor_on_mapped_page(sync_wiki):
    source = Path("docs/Upgrading.md")
    assert sync_wiki._rewrite_link("Deployment.md#authentik-webhook", source) == "Deployment#authentik-webhook"


def test_rewrites_unsynced_repo_file_to_github_blob_url(sync_wiki):
    source = Path("docs/security/Security-Notes.md")
    assert sync_wiki._rewrite_link("../../SECURITY.md", source) == (
        "https://github.com/solarssk/ssf-transmitter/blob/main/SECURITY.md"
    )


def test_rewrites_non_markdown_repo_file_to_github_blob_url(sync_wiki):
    source = Path("docs/Deployment.md")
    assert sync_wiki._rewrite_link("../docker-compose.snippet.yml", source) == (
        "https://github.com/solarssk/ssf-transmitter/blob/main/docker-compose.snippet.yml"
    )


def test_leaves_external_link_untouched(sync_wiki):
    source = Path("docs/Deployment.md")
    url = "https://openid.net/specs/openid-sharedsignals-framework-1_0.html"
    assert sync_wiki._rewrite_link(url, source) == url


def test_leaves_unresolvable_link_untouched(sync_wiki):
    source = Path("docs/Deployment.md")
    assert sync_wiki._rewrite_link("Nonexistent-File.md", source) == "Nonexistent-File.md"


def test_convert_rewrites_security_notes_own_link(sync_wiki):
    text = "See [SECURITY.md](../../SECURITY.md) for the full model."
    converted = sync_wiki.convert(text, Path("docs/security/Security-Notes.md"))
    assert "https://github.com/solarssk/ssf-transmitter/blob/main/SECURITY.md" in converted


def test_main_writes_every_mapped_page(tmp_path, sync_wiki, monkeypatch):
    monkeypatch.setattr("sys.argv", ["sync-wiki.py", str(tmp_path)])
    assert sync_wiki.main() == 0

    for page_name in sync_wiki.MAPPING.values():
        assert (tmp_path / f"{page_name}.md").is_file()
