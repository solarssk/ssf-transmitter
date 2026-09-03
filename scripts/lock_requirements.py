#!/usr/bin/env python3
"""Regenerate the hash-locked requirements files consumed with `--require-hashes`.

Two locks, for two different fixed-platform environments — the loose
version ranges in requirements.txt / requirements-dev.txt are what
Dependabot bumps and what local dev installs from (any developer
platform), but wherever we know the exact target platform(s) in
advance, install from a locked, hash-verified file instead:

  requirements.lock.txt      <- requirements.txt
    Runtime container image, both published platforms (see
    .github/workflows/docker-publish.yml): linux/amd64 and linux/arm64.

  requirements-dev.lock.txt  <- requirements-dev.txt
    CI's "Test and lint" job, which only ever runs on ubuntu-latest
    (linux/amd64) — see .github/workflows/ci.yml.

Each lock is requirements(-dev).txt resolved with
`uv pip compile --generate-hashes`, one compile per target platform,
hashes merged into a single pip-compatible file. Requires the `uv`
binary (https://docs.astral.sh/uv/).

Usage:
    python scripts/lock_requirements.py            # regenerate both lock files in place
    python scripts/lock_requirements.py --check     # exit 1 if either lock is stale (used in CI)

Plain regeneration always resolves to the newest version each package's
constraints allow — run it any time you actually want to refresh pins (a
dependency bump, or picking up a fix for something pip-audit flagged in a
transitive dependency). `--check` instead preserves existing pins that still
satisfy their constraints, so it flags real drift (a requirements(-dev).txt
change not yet reflected in the lock) without also flagging every unrelated
release published upstream since the lock was last regenerated.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
import textwrap
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PYTHON_VERSION = "3.14"

HASH_RE = re.compile(r"--hash=(sha256:[0-9a-f]+)")


@dataclass(frozen=True)
class LockTarget:
    source: str
    lock: str
    platforms: tuple[str, ...]
    consumer: str


TARGETS = [
    LockTarget(
        source="requirements.txt",
        lock="requirements.lock.txt",
        platforms=("x86_64-manylinux2014", "aarch64-manylinux2014"),
        consumer="the Dockerfile (`pip install --require-hashes -r requirements.lock.txt`), "
        "matching the linux/amd64 + linux/arm64 image built in .github/workflows/docker-publish.yml",
    ),
    LockTarget(
        source="requirements-dev.txt",
        lock="requirements-dev.lock.txt",
        platforms=("x86_64-manylinux2014",),
        consumer="CI's Test and lint job (`pip install --require-hashes -r requirements-dev.lock.txt`), "
        "which only ever runs on ubuntu-latest (linux/amd64) — see .github/workflows/ci.yml",
    ),
]


def header_for(target: LockTarget) -> str:
    platform_list = " and ".join(target.platforms)
    merge_note = " Hashes are merged across both platforms." if len(target.platforms) > 1 else ""
    body = (
        f"Hash-locked requirements, consumed by {target.consumer}. "
        f"Generated from {target.source} with `uv pip compile --generate-hashes` "
        f"for {platform_list} (Python {PYTHON_VERSION}).{merge_note}"
    )
    wrapped = textwrap.fill(body, width=76)
    commented = "\n".join(f"# {line}" for line in wrapped.splitlines())
    return f"""\
{commented}
#
# DO NOT EDIT BY HAND — regenerate with:
#   python scripts/lock_requirements.py
"""


def compile_for_platform(source: Path, platform: str, out_path: Path) -> None:
    # --only-binary :all: here too, not just in the resulting `pip install`:
    # without it, resolving a dependency with no matching wheel would make
    # uv build its sdist (running the package's own build-backend code) just
    # to compile the lock — on every CI run, via the freshness check, before
    # the hardened install step ever gets a chance to reject it.
    result = subprocess.run(
        [
            "uv",
            "pip",
            "compile",
            str(source),
            "--generate-hashes",
            "--only-binary",
            ":all:",
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


def build_lock_text(target: LockTarget, *, seed_from_existing: bool) -> str:
    source = ROOT / target.source
    existing_lock = ROOT / target.lock
    # Seeding makes `uv pip compile` treat the existing lock as prior state
    # and keep its pins as long as they still satisfy source's constraints,
    # only re-resolving what actually needs to change (confirmed: forcing a
    # constraint that excludes the pinned version does still update it).
    #
    # --check wants that: without a seed, every run re-resolves everything to
    # whatever is newest on the index *right now*, so a completely unrelated
    # upstream release (a transitive dependency's patch version, say) would
    # flip `--check` from "did requirements(-dev).txt change" to "did
    # anything anywhere in the tree publish since the lock was last
    # regenerated" and fail on essentially every subsequent CI run.
    #
    # Plain regeneration wants the opposite: an already-vulnerable pin that
    # still satisfies its range (e.g. flagged by the "Audit locked
    # dependencies" CI step) would never move to the fixed version if this
    # command kept preserving it — there'd be no supported way to refresh a
    # pin short of deleting the lock file first. So only --check seeds.
    seed = existing_lock.read_text() if seed_from_existing and existing_lock.exists() else None
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        per_platform: dict[str, dict[str, set[str]]] = {}
        for platform in target.platforms:
            out = tmp_path / f"{platform}.txt"
            if seed is not None:
                out.write_text(seed)
            compile_for_platform(source, platform, out)
            per_platform[platform] = parse_hashes_by_package(out)

        all_pkgs: set[str] = set()
        for hashes_by_pkg in per_platform.values():
            all_pkgs.update(hashes_by_pkg)

        lines = [header_for(target).rstrip("\n"), ""]
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
        help="Exit non-zero if any lock file is out of date, without writing anything.",
    )
    args = parser.parse_args()

    stale: list[str] = []
    for target in TARGETS:
        lock_path = ROOT / target.lock
        new_content = build_lock_text(target, seed_from_existing=args.check)

        if args.check:
            current = lock_path.read_text() if lock_path.exists() else ""
            if current != new_content:
                stale.append(target.lock)
            continue

        lock_path.write_text(new_content)
        print(f"Wrote {lock_path}")

    if args.check:
        if stale:
            for name in stale:
                print(f"{name} is out of date.", file=sys.stderr)
            print("Run: python scripts/lock_requirements.py", file=sys.stderr)
            return 1
        print("All lock files are up to date.")
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
