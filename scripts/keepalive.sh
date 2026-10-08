#!/data/data/com.termux/files/usr/bin/bash
# Keepalive: runs supervisor.sh in a loop, acquiring termux-wake-lock.
# Designed to be launched with terminal(background=true) or nohup.

set -uo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_DIR"

RUN_DIR="$PROJECT_DIR/.run"
LOG_DIR="$PROJECT_DIR/logs"
KEEPALIVE_LOG="$LOG_DIR/keepalive.log"

mkdir -p "$RUN_DIR" "$LOG_DIR"

# Check if another keepalive is already running
if [ -f "$RUN_DIR/keepalive.pid" ]; then
    KEEPALIVE_PID=$(cat "$RUN_DIR/keepalive.pid" 2>/dev/null)
    if [ -n "$KEEPALIVE_PID" ] && kill -0 "$KEEPALIVE_PID" 2>/dev/null; then
        echo "keepalive already running (pid $KEEPALIVE_PID)"
        exit 0
    fi
fi

echo $$ > "$RUN_DIR/keepalive.pid"

log() {
    echo "$(date -u +%FT%TZ) $*" >> "$KEEPALIVE_LOG"
}

# Acquire wake lock
command -v termux-wake-lock >/dev/null 2>&1 && termux-wake-lock || true

log "keepalive started (pid $$)"

# Run supervisor in a loop
while true; do
    if [ -f "$RUN_DIR/supervisor.pid" ]; then
        SUPERVISOR_PID=$(cat "$RUN_DIR/supervisor.pid" 2>/dev/null)
        if [ -n "$SUPERVISOR_PID" ] && kill -0 "$SUPERVISOR_PID" 2>/dev/null; then
            log "supervisor already running (pid $SUPERVISOR_PID)"
            sleep 60
            continue
        fi
    fi

    log "starting supervisor"
    bash "$PROJECT_DIR/scripts/supervisor.sh" &
    SUPERVISOR_PID=$!
    echo "$SUPERVISOR_PID" > "$RUN_DIR/supervisor.pid"

    # Wait for supervisor to exit
    wait "$SUPERVISOR_PID" 2>/dev/null
    EXIT_CODE=$?
    log "supervisor exited (code $EXIT_CODE)"

    # Don't spin too fast on repeated crashes
    sleep 10
done
