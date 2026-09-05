#!/usr/bin/env python3
"""Sync docs/*.md into a checked-out GitHub Wiki repo.

The wiki is a separate git repo (`<repo>.wiki.git`) with a flat page
namespace (no subfolders) and its own naming convention (Title-Case,
hyphenated, no `.md` in cross-page links) that predates this script and
was set by hand — see the existing pages for the exact style this
mirrors. MAPPING below is deliberately explicit, not a blind 1:1 copy of
docs/, because the two namespaces don't match: some files rename
(`API.md` -> `API-Reference`), some move out of `docs/security/` into the
wiki's flat layout, and `docs/README.md` is NOT synced to the wiki's
`Home` page on purpose. `Home.md` carries hand-curated introductory
content (an architecture diagram, an SSF/CAEP/RISC primer) that doesn't
exist in docs/README.md's plain index table; overwriting it here would
silently delete that content on the next sync. Update `Home.md` by hand
in the wiki when the page list changes.

`SECURITY.md` and `CHANGELOG.md` (both repo-root, not under docs/) are
not synced either, matching the wiki's existing convention: neither has
ever had a wiki page. Any link to a real repo file that isn't in
MAPPING (those two, `docker-compose.snippet.yml`, etc.) gets rewritten
to the real GitHub blob URL instead of a wiki-relative path that would
be broken there.

Run with the wiki checkout's path as the only argument:
    python3 scripts/sync-wiki.py /path/to/wiki/checkout
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPO_BLOB_BASE = "https://github.com/solarssk/ssf-transmitter/blob/main"

# repo-relative source path -> wiki page name (no .md)
MAPPING = {
    "docs/API.md": "API-Reference",
    "docs/Apple-SCIM-Sync.md": "Apple-SCIM-Sync",
    "docs/Configuration.md": "Configuration",
    "docs/Deployment.md": "Deployment",
    "docs/Event-Mapping.md": "Event-Mapping",
    "docs/Key-Management.md": "Key-Management",
    "docs/Troubleshooting.md": "Troubleshooting",
    "docs/Upgrading.md": "Upgrading",
    "docs/synology-authentik-compose.md": "Synology-Authentik-Compose",
    "docs/security/DATA-PROTECTION.md": "Data-Protection",
    "docs/security/Security-Notes.md": "Security-Notes",
}

LINK_RE = re.compile(r"(\]\()([^)]+)(\))")


def _rewrite_link(target: str, source_repo_path: Path) -> str:
    if target.startswith(("http://", "https://", "mailto:")):
        return target
    path_part, _, fragment = target.partition("#")
    if not path_part:
        return target
    resolved = (ROOT / source_repo_path.parent / path_part).resolve()
    try:
        repo_relative = resolved.relative_to(ROOT).as_posix()
    except ValueError:
        return target
    if repo_relative in MAPPING:
        new_target = MAPPING[repo_relative]
    elif resolved.is_file():
        # Any other real repo file (SECURITY.md, CHANGELOG.md,
        # docker-compose.snippet.yml, ...) isn't on the wiki, so a
        # wiki-relative path to it would be broken there: point at the
        # real file on GitHub instead.
        new_target = f"{REPO_BLOB_BASE}/{repo_relative}"
    else:
        return target
    return f"{new_target}#{fragment}" if fragment else new_target


def convert(text: str, source_repo_path: Path) -> str:
    def replace(match: re.Match[str]) -> str:
        prefix, target, suffix = match.groups()
        return f"{prefix}{_rewrite_link(target, source_repo_path)}{suffix}"

    return LINK_RE.sub(replace, text)


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: sync-wiki.py <path to wiki checkout>", file=sys.stderr)
        return 1
    wiki_dir = Path(sys.argv[1]).resolve()
    if not wiki_dir.is_dir():
        print(f"Not a directory: {wiki_dir}", file=sys.stderr)
        return 1

    for repo_relative, page_name in MAPPING.items():
        source = ROOT / repo_relative
        if not source.is_file():
            print(f"Missing source file: {repo_relative}", file=sys.stderr)
            return 1
        converted = convert(source.read_text(encoding="utf-8"), Path(repo_relative))
        (wiki_dir / f"{page_name}.md").write_text(converted, encoding="utf-8")
        print(f"Synced {repo_relative} -> {page_name}.md")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
