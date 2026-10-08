#!/usr/bin/env bash
# Universal start script for any Linux server (Render, Railway, Fly.io, VPS)
# Usage: bash start.sh [--port 8080]
set -euo pipefail

cd "$(dirname "$0")"

PORT="${PORT:-8080}"
PY="${PYTHON:-python3}"

echo "Installing dependencies..."
"$PY" -m pip install -r requirements.txt --quiet

echo "Starting server on 0.0.0.0:$PORT..."
exec "$PY" -m app.main --host 0.0.0.0 --port "$PORT"
