#!/data/data/com.termux/files/usr/bin/bash
# Stop the server and tunnel started by scripts/start.sh.

set -uo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_DIR="$PROJECT_DIR/.run"

stopped=0
for name in tunnel server; do
  pidfile="$RUN_DIR/$name.pid"
  if [ -f "$pidfile" ]; then
    pid="$(cat "$pidfile")"
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null && echo "✓ stopped $name (pid $pid)"
      stopped=1
    else
      echo "· $name not running (stale pid $pid)"
    fi
    rm -f "$pidfile"
  fi
done

# belt and braces: kill any stray cloudflared quick tunnels for this port
pkill -f "cloudflared tunnel --no-autoupdate" 2>/dev/null && echo "✓ cleared stray cloudflared" || true

command -v termux-wake-unlock >/dev/null 2>&1 && termux-wake-unlock || true

[ "$stopped" -eq 0 ] && echo "nothing was running"
rm -f "$RUN_DIR/tunnel.url"
exit 0
