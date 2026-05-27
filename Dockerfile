FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/
RUN mkdir -p /app/keys /app/data

CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${SSF_CONTAINER_PORT:-8000}"]
