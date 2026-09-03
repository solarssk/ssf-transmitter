#!/usr/bin/env python3
"""Regenerate requirements.lock.txt from requirements.txt.

The Dockerfile installs the runtime image's dependencies from
requirements.lock.txt with `pip install --require-hashes`, so that install
is verified against exact, pinned artifact hashes instead of the loose
version ranges in requirements.txt. This script is the single source of
truth for producing that lock file — resolves requirements.txt with
`uv pip compile --generate-hashes` for both linux/amd64 and linux/arm64
(the platforms the image is published for, see
.github/workflows/docker-publish.yml) and merges the hashes into one
pip-compatible lock file. Requires the `uv` binary (https://docs.astral.sh/uv/).

Usage:
    python scripts/lock_requirements.py            # regenerate requirements.lock.txt in place
    python scripts/lock_requirements.py --check     # exit 1 if requirements.lock.txt is stale (used in CI)
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REQUIREMENTS = ROOT / "requirements.txt"
LOCK_FILE = ROOT / "requirements.lock.txt"

PYTHON_VERSION = "3.14"
PLATFORMS = ["x86_64-manylinux2014", "aarch64-manylinux2014"]

HEADER = f"""\
# Hash-locked requirements for the runtime container image, consumed via
# `pip install --require-hashes -r requirements.lock.txt` in the Dockerfile.
#
# Generated from requirements.txt with `uv pip compile --generate-hashes`,
# merged across linux/amd64 ({PLATFORMS[0]}) and linux/arm64
# ({PLATFORMS[1]}) targets for Python {PYTHON_VERSION}, to match the
# multi-arch image built in .github/workflows/docker-publish.yml.
#
# DO NOT EDIT BY HAND — regenerate with:
#   python scripts/lock_requirements.py
"""

HASH_RE = re.compile(r"--hash=(sha256:[0-9a-f]+)")


def compile_for_platform(platform: str, out_path: Path) -> None:
    result = subprocess.run(
        [
            "uv",
            "pip",
            "compile",
            str(REQUIREMENTS),
            "--generate-hashes",
            "--python-platform",
            platform,
            "--python-version",
            PYTHON_VERSION,
            "-o",
            str(out_path),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        sys.stderr.write(result.stdout)
        sys.stderr.write(result.stderr)
        raise subprocess.CalledProcessError(result.returncode, result.args)


def parse_hashes_by_package(path: Path) -> dict[str, set[str]]:
    blocks: dict[str, set[str]] = {}
    current_pkg: str | None = None
    for line in path.read_text().splitlines():
        if line.startswith("#"):
            continue
        if line and not line[0].isspace():
            current_pkg = line.split()[0]
            blocks.setdefault(current_pkg, set())
        elif current_pkg is not None:
            blocks[current_pkg].update(HASH_RE.findall(line))
    return blocks


def build_lock_text() -> str:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        per_platform: dict[str, dict[str, set[str]]] = {}
        for platform in PLATFORMS:
            out = tmp_path / f"{platform}.txt"
            compile_for_platform(platform, out)
            per_platform[platform] = parse_hashes_by_package(out)

        all_pkgs: set[str] = set()
        for hashes_by_pkg in per_platform.values():
            all_pkgs.update(hashes_by_pkg)

        lines = [HEADER.rstrip("\n"), ""]
        for pkg in sorted(all_pkgs):
            merged_hashes: set[str] = set()
            for hashes_by_pkg in per_platform.values():
                merged_hashes.update(hashes_by_pkg.get(pkg, set()))
            hashes = sorted(merged_hashes)
            lines.append(f"{pkg} \\")
            for i, h in enumerate(hashes):
                suffix = " \\" if i < len(hashes) - 1 else ""
                lines.append(f"    --hash={h}{suffix}")
        return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit non-zero if requirements.lock.txt is out of date, without writing anything.",
    )
    args = parser.parse_args()

    new_content = build_lock_text()

    if args.check:
        current = LOCK_FILE.read_text() if LOCK_FILE.exists() else ""
        if current != new_content:
            print("requirements.lock.txt is out of date with requirements.txt.", file=sys.stderr)
            print("Run: python scripts/lock_requirements.py", file=sys.stderr)
            return 1
        print("requirements.lock.txt is up to date.")
        return 0

    LOCK_FILE.write_text(new_content)
    print(f"Wrote {LOCK_FILE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
