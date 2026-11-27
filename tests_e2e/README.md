# Container HTTP tests

These tests call a real running transmitter over HTTP. They create and delete streams, so use a disposable local container, never production.

Install Python 3.14 and uv. From the repository root, prepare the host test environment, then build and start the test image:

```bash
uv sync --locked --all-extras
docker build -t ssf-transmitter:e2e .
docker run -d --rm --name ssf-e2e -p 127.0.0.1:18000:8000 \
  -e SSF_CONTAINER_PORT=8000 \
  -e SSF_ISSUER=https://ssf.ci.invalid \
  -e SSF_BASE_URL=https://ssf.ci.invalid \
  -e SSF_WEBHOOK_AUTH_MODE=bearer \
  -e SSF_WEBHOOK_TOKEN=ci-smoke-test-webhook-token-000000 \
  -e SSF_MANAGEMENT_TOKEN=ci-smoke-test-mgmt-token-0000000 \
  ssf-transmitter:e2e
```

Wait for the container to become healthy, then run the suite and remove it:

```bash
E2E_BASE_URL=http://localhost:18000 uv run --no-sync pytest tests_e2e/ --no-cov
# Remove the container even if tests fail.
docker stop ssf-e2e
```

Use `--no-cov` because the application runs in the container, outside host pytest coverage. [conftest.py](conftest.py) defines the test-only tokens and optional `E2E_MANAGEMENT_TOKEN` / `E2E_WEBHOOK_TOKEN` overrides. No live Apple credentials are needed. Plain `pytest` runs only [the application suite](../tests/README.md).
