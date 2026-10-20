#!/data/data/com.termux/files/usr/bin/bash
# Start the Telegram bot with auto-restart supervision.
#
# Usage:  bash scripts/run_bot.sh            # supervise, restart on crash
#         bash scripts/run_bot.sh --once     # single batch, then exit
#
# Requires TELEGRAM_BOT_TOKEN in .env. The bot never asks for seeds or keys.

set -uo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_DIR"

PY="${PYTHON:-/data/data/com.termux/files/usr/bin/python3}"
# BOT_RUN_DIR lets a caller (a test, a second instance) use its own state directory so
# the duplicate-supervisor check cannot short-circuit against a supervisor that is
# legitimately running elsewhere.  Defaults to the project's own .run, so normal use and
# the watchdog are unchanged.
RUN_DIR="${BOT_RUN_DIR:-$PROJECT_DIR/.run}"
LOG_DIR="$PROJECT_DIR/logs"
mkdir -p "$RUN_DIR" "$LOG_DIR"

# Prevent duplicate supervisor instances
if [ -f "$RUN_DIR/bot_supervisor.pid" ]; then
    OLD_PID=$(cat "$RUN_DIR/bot_supervisor.pid" 2>/dev/null)
    if [ -n "$OLD_PID" ] && kill -0 "$OLD_PID" 2>/dev/null; then
        echo "bot supervisor already running (pid $OLD_PID)"
        exit 0
    fi
fi
echo $$ > "$RUN_DIR/bot_supervisor.pid"

if [ "${1:-}" = "--once" ]; then
  exec "$PY" -m app.bot_main --once
fi

# Refuse to start without a usable token (fail closed, don't loop on 401).
if ! "$PY" - <<'PYEOF'
import sys, os
sys.path.insert(0, os.getcwd())
from app.config import get_settings, load_dotenv
load_dotenv()
sys.exit(0 if get_settings().telegram_configured else 1)
PYEOF
then
  echo "✗ TELEGRAM_BOT_TOKEN is not configured (or still a placeholder)." >&2
  echo "  Run:  bash scripts/setup_credentials.sh" >&2
  exit 2
fi

# Refuse to poll a bot that something else is already polling.
#
# Two getUpdates consumers on one token steal each other's updates. If the token
# here is the Hermes gateway's own bot, starting this would silently break the
# user's existing Hermes Telegram. scripts/check_bot_token.py compares tokens by
# SHA-256 digest, so no secret is ever printed.
"$PY" scripts/check_bot_token.py
case $? in
  0) ;;
  2) echo "  Run:  bash scripts/setup_credentials.sh" >&2; exit 2 ;;
  3) echo >&2
     echo "  Fix:  create a NEW bot with @BotFather and put its token in .env." >&2
     echo "        Do not reuse the Hermes gateway's bot." >&2
     exit 3 ;;
  4) echo >&2
     echo "  Fix:  the token is invalid or revoked. Get a fresh one from @BotFather," >&2
     echo "        or rotate it if it was ever pasted into a chat or log." >&2
     exit 4 ;;
  *) echo "⚠ could not verify the token; proceeding is unsafe." >&2
     echo "  Set SKIP_TOKEN_CHECK=1 to override (only if you know it is a new bot)." >&2
     [ "${SKIP_TOKEN_CHECK:-0}" = "1" ] || exit 5 ;;
esac

if [ -f "$RUN_DIR/bot.pid" ] && kill -0 "$(cat "$RUN_DIR/bot.pid")" 2>/dev/null; then
  echo "stopping previous bot (pid $(cat "$RUN_DIR/bot.pid"))"
  kill "$(cat "$RUN_DIR/bot.pid")" 2>/dev/null || true
  sleep 1
fi

command -v termux-wake-lock >/dev/null 2>&1 && termux-wake-lock || true

# Supervisor loop: back off 5s -> 60s on repeated crashes.
backoff=5
while true; do
  echo "$(date -u +%FT%TZ) starting bot" >> "$LOG_DIR/bot.out"
  # Launch bot in its OWN session so it survives Android killing the supervisor.
  setsid "$PY" -m app.bot_main >> "$LOG_DIR/bot.out" 2>&1 < /dev/null &
  bot_pid=$!
  echo "$bot_pid" > "$RUN_DIR/bot.pid"
  wait "$bot_pid"
  code=$?
  echo "$(date -u +%FT%TZ) bot exited code=$code" >> "$LOG_DIR/bot.out"

  # exit code 2 = config error; do not spin on it
  if [ "$code" -eq 2 ]; then
    echo "✗ bot stopped on a configuration error; not restarting." >&2
    exit 2
  fi
  if [ "$code" -eq 0 ]; then
    echo "· bot exited cleanly; not restarting."
    exit 0
  fi

  echo "· bot crashed (code $code); restarting in ${backoff}s" >&2
  sleep "$backoff"
  backoff=$(( backoff * 2 ))
  [ "$backoff" -gt 60 ] && backoff=60
done
