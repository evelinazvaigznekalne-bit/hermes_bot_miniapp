#!/data/data/com.termux/files/usr/bin/bash
# Start the Mini App server + a public HTTPS tunnel, then record the URL.
#
# Usage:  bash scripts/start.sh [--port 8080] [--no-tunnel]
#
# Writes runtime state to .run/ (pids + tunnel URL). Safe to re-run: it stops
# any previous instance first.

set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_DIR"

PY="${PYTHON:-/data/data/com.termux/files/usr/bin/python3}"
RUN_DIR="$PROJECT_DIR/.run"
LOG_DIR="$PROJECT_DIR/logs"
PORT="${PORT:-8080}"
USE_TUNNEL=1
ENV_FILE="$PROJECT_DIR/.env"

while [ $# -gt 0 ]; do
  case "$1" in
    --port) PORT="$2"; shift 2 ;;
    --no-tunnel) USE_TUNNEL=0; shift ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

# --- tunnel mode: named (stable URL) or quick (random URL) -----------------
# Read from .env, never sourced, so no secret is ever exported into the shell.
env_get() {
  [ -f "$ENV_FILE" ] || return 0
  sed -n "s/^$1=//p" "$ENV_FILE" | tail -1
}
TUNNEL_MODE="${TUNNEL_MODE:-$(env_get TUNNEL_MODE)}"
TUNNEL_MODE="${TUNNEL_MODE:-quick}"
TUNNEL_HOSTNAME="${TUNNEL_HOSTNAME:-$(env_get TUNNEL_HOSTNAME)}"
CF_CONFIG="${CLOUDFLARED_CONFIG:-$HOME/.cloudflared/config.yml}"

if [ "$TUNNEL_MODE" = "named" ] && [ ! -f "$CF_CONFIG" ]; then
  echo "✗ TUNNEL_MODE=named but $CF_CONFIG is missing." >&2
  echo "  Run: bash scripts/tunnel_setup.sh <hostname>" >&2
  exit 1
fi

mkdir -p "$RUN_DIR" "$LOG_DIR"
chmod 700 "$RUN_DIR" 2>/dev/null || true

# --- stop anything already running -----------------------------------------
if [ -f "$RUN_DIR/server.pid" ] && kill -0 "$(cat "$RUN_DIR/server.pid")" 2>/dev/null; then
  echo "stopping previous server (pid $(cat "$RUN_DIR/server.pid"))"
  kill "$(cat "$RUN_DIR/server.pid")" 2>/dev/null || true
  sleep 1
fi
if [ -f "$RUN_DIR/tunnel.pid" ] && kill -0 "$(cat "$RUN_DIR/tunnel.pid")" 2>/dev/null; then
  echo "stopping previous tunnel (pid $(cat "$RUN_DIR/tunnel.pid"))"
  kill "$(cat "$RUN_DIR/tunnel.pid")" 2>/dev/null || true
  sleep 1
fi

# --- keep the device awake while serving -----------------------------------
command -v termux-wake-lock >/dev/null 2>&1 && termux-wake-lock || true

# --- start the server -------------------------------------------------------
echo "starting server on 127.0.0.1:$PORT"
nohup "$PY" -m app.main --host 127.0.0.1 --port "$PORT" \
  >> "$LOG_DIR/server.out" 2>&1 &
echo $! > "$RUN_DIR/server.pid"
sleep 2

if ! kill -0 "$(cat "$RUN_DIR/server.pid")" 2>/dev/null; then
  echo "✗ server failed to start; last log lines:" >&2
  tail -20 "$LOG_DIR/server.out" >&2
  exit 1
fi

# --- health check -----------------------------------------------------------
if curl -fsS --max-time 10 "http://127.0.0.1:$PORT/health" >/dev/null 2>&1; then
  echo "✓ server healthy on http://127.0.0.1:$PORT"
else
  echo "✗ server did not answer /health" >&2
  exit 1
fi

# --- start the tunnel -------------------------------------------------------
if [ "$USE_TUNNEL" -eq 1 ]; then
  if ! command -v cloudflared >/dev/null 2>&1; then
    echo "✗ cloudflared not installed. Install with: pkg install cloudflared" >&2
    exit 1
  fi
  if [ "$TUNNEL_MODE" = "named" ]; then
    # A named tunnel keeps a fixed hostname on your own domain. cloudflared
    # reads credentials + ingress from config.yml; nothing random is emitted.
    echo "starting cloudflared named tunnel ($TUNNEL_HOSTNAME)…"
    nohup cloudflared tunnel --no-autoupdate \
      --config "$CF_CONFIG" run \
      > "$LOG_DIR/tunnel.out" 2>&1 &
    echo $! > "$RUN_DIR/tunnel.pid"

    URL="https://$TUNNEL_HOSTNAME"
  else
    echo "starting cloudflared quick tunnel…"
    nohup cloudflared tunnel --no-autoupdate \
      --url "http://127.0.0.1:$PORT" \
      > "$LOG_DIR/tunnel.out" 2>&1 &
    echo $! > "$RUN_DIR/tunnel.pid"

    # cloudflared prints the URL within ~10s
    URL=""
    for _ in $(seq 1 30); do
      URL="$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' "$LOG_DIR/tunnel.out" 2>/dev/null | head -1 || true)"
      [ -n "$URL" ] && break
      sleep 1
    done
  fi

  if [ -z "$URL" ]; then
    echo "✗ could not obtain tunnel URL; last log lines:" >&2
    tail -20 "$LOG_DIR/tunnel.out" >&2
    exit 1
  fi

  echo "$URL" > "$RUN_DIR/tunnel.url"
  echo "✓ tunnel: $URL"

  # --- persist the URL into .env IMMEDIATELY --------------------------------
  # Do this before the readiness poll: the poll can fail for reasons that have
  # nothing to do with the tunnel (local DNS negative-caching of a brand-new
  # trycloudflare hostname lasts the 300s TTL), and a stale URL in .env is
  # worse than a failed poll.
  if [ -f "$PROJECT_DIR/.env" ]; then
    if grep -q '^TELEGRAM_WEBAPP_URL=' "$PROJECT_DIR/.env"; then
      "$PY" - "$PROJECT_DIR/.env" "$URL" <<'PYEOF'
import sys, pathlib
path, url = pathlib.Path(sys.argv[1]), sys.argv[2]
lines = path.read_text().splitlines()
out = [f"TELEGRAM_WEBAPP_URL={url}" if l.startswith("TELEGRAM_WEBAPP_URL=") else l
       for l in lines]
path.write_text("\n".join(out) + "\n")
PYEOF
      echo "✓ TELEGRAM_WEBAPP_URL updated in .env"
    else
      echo "TELEGRAM_WEBAPP_URL=$URL" >> "$PROJECT_DIR/.env"
      echo "✓ TELEGRAM_WEBAPP_URL appended to .env"
    fi
  else
    echo "⚠ no .env found; create it from .env.example"
  fi

  # --- readiness poll ------------------------------------------------------
  # The URL appears in the log before the tunnel finishes registering with the
  # edge; hitting it too early returns HTTP 530 (Argo Tunnel error). Poll until
  # the public endpoint actually serves 200.
  #
  # A local NXDOMAIN is NOT a tunnel failure - it is DNS negative caching
  # (trycloudflare.com records carry a 300s TTL). Resolve the real edge IP over
  # DoH and pin it with --resolve so the probe tests the tunnel, not the phone's
  # resolver. Falls back to a plain request when DoH is unavailable.
  HOST="${URL#https://}"
  EDGE_IP="$(curl -s --max-time 10 -H 'accept: application/dns-json' \
    "https://cloudflare-dns.com/dns-query?name=$HOST&type=A" 2>/dev/null \
    | tr ',' '\n' | grep -oE '"data":"[0-9.]+"' | head -1 \
    | sed 's/.*:"//; s/"//' || true)"

  ready=0
  for i in $(seq 1 40); do
    if [ -n "$EDGE_IP" ]; then
      code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
        --resolve "$HOST:443:$EDGE_IP" "$URL/health" 2>/dev/null)"
    else
      code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
        "$URL/health" 2>/dev/null)"
    fi
    [ -z "$code" ] && code=000
    if [ "$code" = "200" ]; then
      ready=1
      echo "✓ public endpoint live after ${i} attempt(s): $URL/health"
      [ -n "$EDGE_IP" ] && echo "  (probed via edge IP $EDGE_IP; local DNS may lag ~300s)"
      break
    fi
    [ "$i" -eq 1 ] && echo "  waiting for tunnel registration (got HTTP $code)…"
    sleep 3
  done

  if [ "$ready" -ne 1 ]; then
    echo "⚠ public endpoint did not return 200 within the poll window" >&2
    echo "  last status: HTTP ${code:-000}; recent log:" >&2
    tail -10 "$LOG_DIR/tunnel.out" >&2
    echo "  .env already holds $URL - the tunnel may still be registering." >&2
    exit 1
  fi
fi

echo
echo "server pid : $(cat "$RUN_DIR/server.pid")"
[ -f "$RUN_DIR/tunnel.pid" ] && echo "tunnel pid : $(cat "$RUN_DIR/tunnel.pid")"
echo "logs       : $LOG_DIR/"
