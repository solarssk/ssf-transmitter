#!/usr/bin/env python3
"""Generate .github/release-notes/vX.Y.Z.md from a CHANGELOG.md entry.

Run this as part of preparing a release PR, after adding the version's
CHANGELOG.md entry (`## [X.Y.Z] — YYYY-MM-DD — Title`) and bumping
pyproject.toml's [project].version. release.yml's "release: vX.Y.Z"
detection requires the generated file to exist before it will cut the
release, so this is a required step, not an optional nicety.

Usage:
    python3 scripts/generate-release-notes.py 0.5.11
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CHANGELOG = ROOT / "CHANGELOG.md"
OUT_DIR = ROOT / ".github" / "release-notes"

# ## [X.Y.Z] — YYYY-MM-DD — Title
HEADER_RE = re.compile(r"^## \[([^\]]+)\] — (\d{4}-\d{2}-\d{2}) — (.+?)\s*$", re.M)


def parse_sections(text: str) -> dict[str, tuple[str, str, str]]:
    """Return {version: (date, title, body)} for every dated CHANGELOG.md entry.

    ``## [Unreleased]`` has no date and no title, so HEADER_RE's required
    date/title groups naturally exclude it — nothing else needed to skip it.
    """
    matches = list(HEADER_RE.finditer(text))
    sections: dict[str, tuple[str, str, str]] = {}
    for i, match in enumerate(matches):
        version, date, title = match.group(1), match.group(2), match.group(3)
        start = match.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        body = text[start:end].strip()
        # Strip this repo's own "---" section divider (see CHANGELOG.md) so it
        # doesn't collide with deploy_footer()'s own "---" below it.
        body = re.sub(r"\n*-{3,}\s*$", "", body).rstrip()
        sections[version] = (date, title, body)
    return sections


def deploy_footer(version: str) -> str:
    return (
        "---\n\n"
        "### Deploy\n\n"
        f"- `ghcr.io/solarssk/ssf-transmitter:{version}` / "
        f"`docker.io/solarssk/ssf-transmitter:{version}` — same image, both registries, "
        "`linux/amd64` and `linux/arm64`\n"
        "- Upgrade notes: "
        "[docs/Upgrading.md](https://github.com/solarssk/ssf-transmitter/blob/main/docs/Upgrading.md)\n"
    )


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: generate-release-notes.py <version>  (e.g. 0.5.11)", file=sys.stderr)
        return 1
    version = sys.argv[1].removeprefix("v")
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        print(f"Invalid version: {version!r} (expected X.Y.Z)", file=sys.stderr)
        return 1

    sections = parse_sections(CHANGELOG.read_text(encoding="utf-8"))
    if version not in sections:
        print(
            f"No CHANGELOG.md entry for [{version}] — add '## [{version}] — YYYY-MM-DD — Title' first.",
            file=sys.stderr,
        )
        return 1

    date, title, body = sections[version]
    if not body:
        print(f"CHANGELOG.md entry for [{version}] has no content under its heading.", file=sys.stderr)
        return 1

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUT_DIR / f"v{version}.md"
    out_path.write_text(f"{body}\n\n{deploy_footer(version)}", encoding="utf-8")
    print(f"Wrote {out_path} (title: {title!r}, date: {date})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
