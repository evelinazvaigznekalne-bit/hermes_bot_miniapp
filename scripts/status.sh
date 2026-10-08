#!/data/data/com.termux/files/usr/bin/bash
# Report deployment state: processes, endpoints, credentials, tunnel URL.
# Never prints secret values.

set -uo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_DIR"
RUN_DIR="$PROJECT_DIR/.run"
PY="${PYTHON:-/data/data/com.termux/files/usr/bin/python3}"
PORT="${PORT:-8080}"

echo "── processes ────────────────────────────────────────────"
for name in server tunnel; do
  pidfile="$RUN_DIR/$name.pid"
  if [ -f "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
    echo "✓ $name running (pid $(cat "$pidfile"))"
  else
    echo "✗ $name not running"
  fi
done

echo
echo "── local endpoint ───────────────────────────────────────"
if curl -fsS --max-time 5 "http://127.0.0.1:$PORT/health" >/dev/null 2>&1; then
  echo "✓ http://127.0.0.1:$PORT/health"
else
  echo "✗ http://127.0.0.1:$PORT/health unreachable"
fi

echo
echo "── public endpoint ──────────────────────────────────────"
if [ -f "$RUN_DIR/tunnel.url" ]; then
  URL="$(cat "$RUN_DIR/tunnel.url")"
  MODE="$(sed -n 's/^TUNNEL_MODE=//p' "$PROJECT_DIR/.env" 2>/dev/null | tail -1)"
  MODE="${MODE:-quick}"
  echo "url : $URL"
  echo "mode: $MODE$([ "$MODE" = "named" ] && echo "  (permanent — survives restarts)" || echo "  (random — changes every restart)")"
  if curl -fsS --max-time 15 "$URL/health" >/dev/null 2>&1; then
    echo "✓ public /health reachable"
  else
    echo "✗ public /health unreachable (tunnel may have expired)"
    [ "$MODE" = "quick" ] && echo "  · quick-tunnel hostnames are revoked when cloudflared stops"
    [ "$MODE" = "named" ] && echo "  · check: cloudflared tunnel --config ~/.cloudflared/config.yml ingress validate"
  fi
else
  echo "· no tunnel URL recorded"
fi

echo
echo "── credentials (presence only) ──────────────────────────"
"$PY" - <<'PYEOF'
import sys, os
sys.path.insert(0, os.getcwd())
from app.config import get_settings, is_placeholder
try:
    from app.config import load_dotenv
    load_dotenv()
except Exception:
    pass
s = get_settings()
def mark(ok): return "✓" if ok else "✗"
print(f"{mark(s.telegram_configured)} TELEGRAM_BOT_TOKEN")
print(f"{mark(bool(s.telegram_webapp_url))} TELEGRAM_WEBAPP_URL  {s.telegram_webapp_url or ''}")
print(f"{mark(s.memepol_configured)} MEMEPOL_API_KEY")
print(f"{mark(s.eth_rpc_configured)} ETH_RPC_URL")
PYEOF

echo
echo "── subsystem status ─────────────────────────────────────"
"$PY" -m app.cli status 2>/dev/null | "$PY" -c "import json,sys; print(json.load(sys.stdin)['statuses'])" 2>/dev/null || echo "· unavailable"
