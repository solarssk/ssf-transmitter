# Maintenance scripts

Run these from the repository root. Release preparation changes files; inspect the diff before committing.

| Script | Purpose |
|---|---|
| `generate-release-notes.py X.Y.Z` | Generate `.github/release-notes/vX.Y.Z.md` from the changelog |
| `sync-release-docs.py` | Update current-release pointers; `--check` verifies them without writing |
| `sync-wiki.py /path/to/wiki` | Copy the explicitly mapped guides into an existing wiki checkout |
| `ai-review.py prepare` / `submit` | Validate review input and publish an immutable commit-specific verdict in Actions; see [review setup](../docs/AI-Review.md) |
| `release-tag.sh` | Emergency signed-tag fallback; read its header before use |

Follow the [release checklist](../AGENTS.md#cutting-a-release) for version, changelog, narrative upgrade instructions, and release PR requirements. The generators do not rewrite version-specific upgrade advice.

The wiki has flat page names. Its Home page is maintained separately; [the sync mapping](sync-wiki.py) defines which repository pages are mirrored. A new guide needs a mapping entry if it should appear as a wiki page.
