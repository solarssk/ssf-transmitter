#!/usr/bin/env bash
# Emergency manual release path: cut a signed git tag directly.
#
# The normal path is a "release PR" — bump pyproject.toml's version, add a
# CHANGELOG.md entry, run generate-release-notes.py and sync-release-docs.py,
# commit as "release: vX.Y.Z", merge to main. release.yml detects that commit
# and does everything else (GitHub Release, tag, dispatching docker-publish.yml
# and release-smoke.yml) using the repo's own GITHUB_TOKEN.
#
# Use this script instead only if release.yml itself is broken, or you need a
# release cut with your own signed tag rather than release.yml's GITHUB_TOKEN-
# authored one. Pushing a signed tag with real user credentials (not
# GITHUB_TOKEN) DOES trigger docker-publish.yml's own `push: tags:` fallback
# trigger directly, which then dispatches release-smoke.yml itself once the
# image is actually published — same as the normal release.yml path.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

usage() {
  cat <<'EOF'
Usage: scripts/release-tag.sh <version> [options]

  <version>   Release version: 0.5.11 or v0.5.11

Options:
  -m, --message <text>   Annotated tag message (default: "vX.Y.Z")
  --push                 Push tag to origin after creating it
  --no-sign-check        Skip local signing-key check

Examples:
  scripts/release-tag.sh 0.5.11 -m "v0.5.11 — short summary" --push
EOF
}

VERSION_RAW="${1:-}"
shift || true

MESSAGE=""
PUSH=false
SIGN_CHECK=true

while [[ $# -gt 0 ]]; do
  case "$1" in
    -m|--message)
      MESSAGE="${2:?missing message}"
      shift 2
      ;;
    --push)
      PUSH=true
      shift
      ;;
    --no-sign-check)
      SIGN_CHECK=false
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z "$VERSION_RAW" ]]; then
  usage >&2
  exit 1
fi

TAG="${VERSION_RAW#v}"
TAG="v${TAG}"
VERSION="${TAG#v}"

if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Invalid version: $VERSION_RAW (expected semver like 0.5.11)" >&2
  exit 1
fi

if [[ -z "$MESSAGE" ]]; then
  MESSAGE="$TAG"
fi

if [[ "$SIGN_CHECK" == true ]] && ! git config --get user.signingkey >/dev/null; then
  echo "user.signingkey is not set — configure SSH or GPG signing first, or pass --no-sign-check." >&2
  exit 1
fi

if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
  echo "Tag $TAG already exists locally. Delete it first if you intend to re-sign." >&2
  exit 1
fi

BRANCH="$(git branch --show-current)"
if [[ "$BRANCH" != "main" ]]; then
  echo "Refusing to tag from branch '$BRANCH' (expected main)." >&2
  exit 1
fi

if [[ -n "$(git status --porcelain)" ]]; then
  echo "Working tree is not clean — commit or stash before tagging." >&2
  exit 1
fi

git pull --ff-only origin main

# Cross-check against the checked-out release metadata rather than trusting
# the typed-in version — a mistyped argument, or running this before the
# intended release commit has actually landed on main, would otherwise sign
# and can push a permanent tag for the wrong commit.
PYPROJECT_VERSION="$(python3 -c 'import tomllib; print(tomllib.load(open("pyproject.toml", "rb"))["project"]["version"])')"
if [[ "$PYPROJECT_VERSION" != "$VERSION" ]]; then
  echo "pyproject.toml's [project].version is '$PYPROJECT_VERSION', not '$VERSION' — refusing to tag." >&2
  echo "Make sure the release commit bumping to $VERSION is on main before running this." >&2
  exit 1
fi
if ! grep -q "^## \[${VERSION}\] — [0-9-]* — .*\$" CHANGELOG.md; then
  echo "No CHANGELOG.md entry for [$VERSION] — refusing to tag." >&2
  exit 1
fi

echo "Creating signed tag $TAG at $(git rev-parse --short HEAD)"
git tag -s "$TAG" -m "$MESSAGE"

if [[ "$PUSH" == true ]]; then
  echo "Pushing $TAG to origin"
  git push origin "$TAG"
  echo "Done. docker-publish.yml should start automatically (push: tags: trigger)."
  echo "It creates the GitHub Release itself if one doesn't already exist, then attaches the SBOM and dispatches release-smoke.yml once the image is published."
else
  echo "Created locally. Push with: git push origin $TAG"
fi
