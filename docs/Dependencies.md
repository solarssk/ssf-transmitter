# Maintaining Python dependencies

Install uv 0.13.7 and Python 3.14, then run:

```bash
uv sync --locked --all-extras
uv run --no-sync ruff check .
uv run --no-sync pytest
uv run --no-sync deptry .
```

`pyproject.toml` declares acceptable versions; `uv.lock` records one compatible resolution for the application and every tooling extra. Dependabot uses its native `uv` integration to update this pair. GitHub Actions, Docker base images, and the separate ClusterFuzzLite environment retain their existing Dependabot entries.

For a targeted update:

```bash
uv lock --upgrade-package fastapi
uv lock --check
```

After changing a dependency range in `pyproject.toml`, run `uv lock` and commit both files. Use `uv lock --upgrade` only when intentionally refreshing the entire dependency set. Review all resolved version changes before merging. Docker's export stage uses uv 0.13.7; CI currently checks and exports the lock with uv 0.11.26. Use the newer version when writing the lock to avoid an unintended lock-format rewrite or dependency refresh.

The old `requirements*.txt` files and pip-tools bootstrap have been removed. Requirements files are now temporary exports, generated with `uv export --locked --no-dev --no-emit-project`. CI adds `--all-extras`; release smoke tests add `--extra test`. Every automated install retains `--only-binary :all:` and `--require-hashes`, and the runtime image includes neither uv nor pip. A missing or stale lock fails the build rather than silently resolving newer packages. Runtime vulnerability audits and submitted dependency snapshots use the same runtime export.

This changes repository maintenance only. Existing deployments need no new environment variables, token registration, or database migration. Continue upgrading through the published container images as described in [Upgrading](Upgrading.md).
