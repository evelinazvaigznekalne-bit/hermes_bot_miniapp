FROM python:3.11-slim

# gcc is insurance: every dependency below ships a manylinux wheel for cp311,
# but if one ever has to build from source, the slim image has no compiler.
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/
COPY scripts/ ./scripts/

# Render injects PORT (default 10000). Bind to 0.0.0.0 or Render cannot reach us.
ENV HOST=0.0.0.0 \
    PYTHONUNBUFFERED=1

EXPOSE 10000

# Never COPY .env — secrets come from Render's environment variables.
CMD ["sh", "-c", "python3 -m app.main --host 0.0.0.0 --port ${PORT:-10000}"]
