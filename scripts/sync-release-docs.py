#!/usr/bin/env python3
"""Sync "current release" pointers in docs from pyproject.toml + CHANGELOG.md.

Several docs quote the current stable version as a live pointer — "current
release" (version, title, and release URL), the image tag in a
copy-pasteable example, a sample API response — and go stale the moment a
new version ships if nobody remembers to touch them by hand. This does NOT
touch every place a version number appears: docs/Upgrading.md's upgrade
walkthrough, README.md's "## Upgrading" summary, and
docs/synology-authentik-compose.md's "## Upgrading from X.Y.Z" section (plus
the historical "since vX.Y" notes elsewhere) all describe a *specific past
version's* upgrade steps, not just a version number — rewriting those
mechanically would leave stale prose under a fresh-looking version, which is
worse than leaving it visibly stale. They're a required manual step in the
release checklist (see AGENTS.md) instead. Only add a pattern below for a
genuine "this is the current version" spot, where swapping the number is the
whole story.

README.md deliberately has no such pattern: its "Latest release" badge
already shows the current version and links to it, so a separate
"**Current release:** vX.Y.Z" line would just be the same fact restated in
prose, one more thing to keep in sync for no reader benefit. docs/README.md
is a plain documentation index with no badge row, so its own "Current stable
release" line still earns its place.

Run after bumping pyproject.toml's version and adding the new CHANGELOG.md
entry during a release cut (before generate-release-notes.py, which needs
the same CHANGELOG.md entry to already exist). Use --check in CI/release.yml.
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"
CHANGELOG = ROOT / "CHANGELOG.md"

# ## [X.Y.Z] — YYYY-MM-DD — Title  (mirrors generate-release-notes.py's HEADER_RE)
HEADER_RE = re.compile(r"^## \[([^\]]+)\] — \d{4}-\d{2}-\d{2} — (.+?)\s*$", re.M)


def read_current_version() -> str:
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    version = data.get("project", {}).get("version", "")
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise SystemExit(f"Invalid or missing [project].version in {PYPROJECT}: {version!r}")
    return version


def read_title_for(version: str) -> str:
    text = CHANGELOG.read_text(encoding="utf-8")
    for match in HEADER_RE.finditer(text):
        if match.group(1) == version:
            return match.group(2)
    raise SystemExit(
        f"No CHANGELOG.md entry for [{version}] — add '## [{version}] — YYYY-MM-DD — Title' before running this script."
    )


# Each entry: (path relative to repo root, regex, replacement).
# The regex must match the *entire* span to replace; `replacement` is a
# plain string (already filled in with the current version/title/URL) —
# not a re.sub template, so any literal backslashes in it are safe.
def patterns_for(version: str, title: str) -> tuple[tuple[str, str, str], ...]:
    release_url = f"https://github.com/solarssk/ssf-transmitter/releases/tag/v{version}"
    return (
        (
            "docs/README.md",
            # The embedded title can itself contain "]" — or even a full
            # `[x](y)` markdown link, e.g. a title quoting a CVE ID or a code
            # identifier — so `[^\]]+` would stop at the title's own first
            # "]", and a generic `.+?\]\([^)]+\)` would stop at the title's
            # own inner `](...)` instead of the line's real closing link.
            # Anchor the closing `](...)` to the release URL's known,
            # specific shape instead of a generic "any non-)" match, so only
            # this repo's actual github.com release link can end the match —
            # a title would have to literally contain that exact URL to
            # collide, which isn't a realistic release title.
            r"\*\*Current stable release:\*\* `v[\d.]+` — \[.+?\]"
            r"\(https://github\.com/solarssk/ssf-transmitter/releases/tag/v[\d.]+\)",
            f"**Current stable release:** `v{version}` — [{title}]({release_url})",
        ),
        (
            "docs/synology-authentik-compose.md",
            r"\*\*Current release:\*\* `ghcr\.io/solarssk/ssf-transmitter:[\d.]+`",
            f"**Current release:** `ghcr.io/solarssk/ssf-transmitter:{version}`",
        ),
        (
            "docs/synology-authentik-compose.md",
            r"`docker\.io/solarssk/ssf-transmitter:[\d.]+` — same image, public",
            f"`docker.io/solarssk/ssf-transmitter:{version}` — same image, public",
        ),
        (
            "docs/synology-authentik-compose.md",
            r"Swap `image:` to `docker\.io/solarssk/ssf-transmitter:[\d.]+` for the public",
            f"Swap `image:` to `docker.io/solarssk/ssf-transmitter:{version}` for the public",
        ),
        (
            "docs/synology-authentik-compose.md",
            r"image: ghcr\.io/solarssk/ssf-transmitter:[\d.]+",
            f"image: ghcr.io/solarssk/ssf-transmitter:{version}",
        ),
        (
            "docs/synology-authentik-compose.md",
            r"Pin `[\d.]+` in production\.",
            f"Pin `{version}` in production.",
        ),
        (
            "docs/synology-authentik-compose.md",
            r"Stable release tags \(`v[\d.]+`\) update the `latest` Docker tag",
            f"Stable release tags (`v{version}`) update the `latest` Docker tag",
        ),
        (
            "docs/Deployment.md",
            r"ghcr\.io/solarssk/ssf-transmitter:[\d.]+ +# pinned release",
            f"ghcr.io/solarssk/ssf-transmitter:{version}     # pinned release",
        ),
        (
            "docs/Deployment.md",
            r"docker\.io/solarssk/ssf-transmitter:[\d.]+ +# same image, Docker Hub",
            f"docker.io/solarssk/ssf-transmitter:{version}   # same image, Docker Hub",
        ),
        (
            "docs/Deployment.md",
            r"image: ghcr\.io/solarssk/ssf-transmitter:[\d.]+",
            f"image: ghcr.io/solarssk/ssf-transmitter:{version}",
        ),
        (
            "docs/Deployment.md",
            r"docker\.io/solarssk/ssf-transmitter:[\d.]+` to pull from Docker Hub",
            f"docker.io/solarssk/ssf-transmitter:{version}` to pull from Docker Hub",
        ),
        (
            "docs/API.md",
            r'"version": "[\d.]+"',
            f'"version": "{version}"',
        ),
    )


def main() -> int:
    check = "--check" in sys.argv
    version = read_current_version()
    title = read_title_for(version)

    by_path: dict[str, str] = {}
    stale: list[str] = []
    for rel, pattern, replacement in patterns_for(version, title):
        path = ROOT / rel
        text = by_path.get(rel) or path.read_text(encoding="utf-8")
        if not re.search(pattern, text):
            raise SystemExit(f"{path}: pattern not found: {pattern!r}")
        by_path[rel] = re.sub(pattern, lambda _m, r=replacement: r, text, count=1)

    for rel, updated in by_path.items():
        path = ROOT / rel
        original = path.read_text(encoding="utf-8")
        if updated != original:
            stale.append(rel)
            if not check:
                path.write_text(updated, encoding="utf-8")

    if check:
        if stale:
            print(f"Docs out of sync with v{version} ({title!r}): {', '.join(stale)}", file=sys.stderr)
            print("Run: python3 scripts/sync-release-docs.py", file=sys.stderr)
            return 1
        print(f"All docs already in sync (v{version} — {title}).")
        return 0

    if stale:
        print(f"Updated: {', '.join(stale)} (v{version} — {title})")
    else:
        print(f"Already in sync (v{version} — {title}).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
