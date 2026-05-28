FROM python:3.12-slim

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

CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${SSF_CONTAINER_PORT:-8000}"]
