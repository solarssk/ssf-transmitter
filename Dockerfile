# Pin to an immutable digest for reproducible builds and predictable CVE surface.
# To update: docker pull python:3.14-slim-bookworm && docker inspect --format='{{index .RepoDigests 0}}'
# Dependabot will propose digest bumps automatically when a new image is published.
FROM python:3.14-slim-bookworm@sha256:82bc3c539b8813ada9d68c63b40158fa002f7f33de9bf3312a3dfdc0620dff56

ARG APP_VERSION=dev
ENV APP_VERSION=${APP_VERSION}

WORKDIR /app

# Apply Debian's own security-repo updates on top of the pinned base image.
# The upstream python:3.14-slim-bookworm digest above is rebuilt on its own
# cadence, so a Debian security fix (e.g. a libpcre2-8-0 patch) can land in
# the bookworm-security repo days before the next upstream image rebuild
# picks it up — this closes that gap without waiting on Dependabot's next
# digest bump.
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user before installing deps
RUN groupadd --system --gid 10001 appuser && \
    useradd --system --uid 10001 --gid 10001 --no-create-home appuser

COPY requirements.txt .
# Install only pre-built wheels (--only-binary :all:, no setup.py execution)
# whose hash matches requirements.txt (--require-hashes, tamper-evident
# supply chain — it's pip-compile output from requirements.in, see its
# header for how to regenerate). Then strip pip/setuptools/wheel and
# ensurepip's bundled pip wheel — none are needed at runtime (the app
# never imports or shells out to pip), and removing them drops pip's
# internally vendored copies of msgpack/setuptools (which even the latest
# pip release ships at versions with known CVEs) from the image entirely,
# instead of just suppressing the scanner finding.
RUN pip install --no-cache-dir --only-binary :all: --require-hashes -r requirements.txt && \
    pip uninstall --yes --no-input pip setuptools wheel && \
    rm -rf /usr/local/lib/python3.14/ensurepip

COPY app/ ./app/

# Create data directories and set ownership
RUN mkdir -p /app/keys /app/data && \
    chown -R appuser:appuser /app && \
    chmod 700 /app/keys /app/data

USER appuser

# Health check — poll /jwks.json (public, no auth, confirms crypto layer is up).
# Uses Python stdlib so no curl/wget dependency is needed in the image.
# start-period covers key generation on first start (~2s) plus DB init.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python3 -c \
    "import urllib.request, os; \
     port = os.getenv('SSF_CONTAINER_PORT', '8000'); \
     urllib.request.urlopen(f'http://localhost:{port}/jwks.json', timeout=4)" \
  || exit 1

CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port \"${SSF_CONTAINER_PORT:-8000}\" --proxy-headers --forwarded-allow-ips=\"${SSF_FORWARDED_ALLOW_IPS:-127.0.0.1}\""]
