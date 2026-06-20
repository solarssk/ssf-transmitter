# Pin to an immutable digest for reproducible builds and predictable CVE surface.
# To update: docker pull python:3.14-slim-bookworm && docker inspect --format='{{index .RepoDigests 0}}'
# Dependabot will propose digest bumps automatically when a new image is published.
FROM python:3.14-slim-bookworm@sha256:a70519002c49552ea0a853de47599cf40479b001bd7a624f1112eaf44dcaccc7

ARG APP_VERSION=dev
ENV APP_VERSION=${APP_VERSION}

WORKDIR /app

# Create non-root user before installing deps
RUN groupadd --system --gid 10001 appuser && \
    useradd --system --uid 10001 --gid 10001 --no-create-home appuser

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

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
