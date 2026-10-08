#!/data/data/com.termux/files/usr/bin/bash
# Supervisor: monitors cloudflared, app.main, app.bot_main and restarts them if they die.
# Checks every 30 seconds. Logs to logs/supervisor.log.

set -uo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_DIR"

PY="/data/data/com.termux/files/usr/bin/python3"
RUN_DIR="$PROJECT_DIR/.run"
LOG_DIR="$PROJECT_DIR/logs"
SUPERVISOR_LOG="$LOG_DIR/supervisor.log"
PORT="${PORT:-8080}"

mkdir -p "$RUN_DIR" "$LOG_DIR"

# Check if another supervisor is already running
if [ -f "$RUN_DIR/supervisor.pid" ]; then
    SUPERVISOR_PID=$(cat "$RUN_DIR/supervisor.pid" 2>/dev/null)
    if [ -n "$SUPERVISOR_PID" ] && kill -0 "$SUPERVISOR_PID" 2>/dev/null; then
        echo "supervisor already running (pid $SUPERVISOR_PID)"
        exit 0
    fi
fi

echo $$ > "$RUN_DIR/supervisor.pid"

log() {
    echo "$(date -u +%FT%TZ) $*" >> "$SUPERVISOR_LOG"
}

# Helper: find PIDs matching a pattern (excluding self, shells and wrappers).
#
# The `bash -lic ...` wrapper that launches each service has the full command
# line as its argument, so a naive `ps aux | grep` returns BOTH the wrapper and
# the real process. ensure_single would then treat them as duplicates and kill
# one of them — sometimes the real service — producing an endless
# restart/rotate loop. Match the process name (comm) against the binary instead
# and skip anything whose command line starts with a shell.
find_pids() {
    local pattern="$1"
    ps -eo pid,comm,args 2>/dev/null \
        | grep -E "$pattern" \
        | grep -v grep \
        | grep -v 'supervisor\.sh' \
        | grep -v 'keepalive\.sh' \
        | awk '{
            comm=$2
            # Skip shell wrappers: their argv[0] is a shell binary.
            if (comm ~ /(^|\/)(bash|sh|dash|zsh)$/) next
            print $1
        }'
}

# Helper: ensure only one process matching a pattern is running
# Returns 0 if running (or duplicates killed), 1 if not running
ensure_single() {
    local pattern="$1"
    local pidfile="$2"

    local pids
    pids=$(find_pids "$pattern")

    if [ -z "$pids" ]; then
        return 1  # Not running
    fi

    local count
    count=$(echo "$pids" | wc -l)

    if [ "$count" -eq 1 ]; then
        echo "$pids" > "$pidfile"
        return 0  # Running
    else
        # Multiple processes - kill all but the first
        local first=1
        for pid in $pids; do
            if [ "$first" -eq 1 ]; then
                first=0
                echo "$pid" > "$pidfile"
            else
                log "killing duplicate $pattern (pid $pid)"
                kill "$pid" 2>/dev/null || true
            fi
        done
        return 0
    fi
}

# Start the server
start_server() {
    log "starting server"
    nohup "$PY" -m app.main --host 127.0.0.1 --port "$PORT" \
        >> "$LOG_DIR/server.out" 2>&1 &
    echo $! > "$RUN_DIR/server.pid"
    sleep 2
    if ! kill -0 "$(cat "$RUN_DIR/server.pid")" 2>/dev/null; then
        log "server failed to start"
        return 1
    fi
    log "server started (pid $(cat "$RUN_DIR/server.pid"))"
}

# Start the tunnel
start_tunnel() {
    log "starting tunnel"

    # Read tunnel mode from .env
    local tunnel_mode
    tunnel_mode=$(sed -n 's/^TUNNEL_MODE=//p' "$PROJECT_DIR/.env" 2>/dev/null | tail -1)
    tunnel_mode="${tunnel_mode:-quick}"

    if [ "$tunnel_mode" = "named" ]; then
        local cf_config="${CLOUDFLARED_CONFIG:-$HOME/.cloudflared/config.yml}"
        nohup cloudflared tunnel --no-autoupdate \
            --config "$cf_config" run \
            > "$LOG_DIR/tunnel.out" 2>&1 &
        echo $! > "$RUN_DIR/tunnel.pid"
    else
        nohup cloudflared tunnel --no-autoupdate \
            --url "http://127.0.0.1:$PORT" \
            > "$LOG_DIR/tunnel.out" 2>&1 &
        echo $! > "$RUN_DIR/tunnel.pid"
    fi

    sleep 2
    if ! kill -0 "$(cat "$RUN_DIR/tunnel.pid")" 2>/dev/null; then
        log "tunnel failed to start"
        return 1
    fi
    log "tunnel started (pid $(cat "$RUN_DIR/tunnel.pid"))"

    # For quick tunnels, wait for the URL and update .run/tunnel.url
    if [ "$tunnel_mode" != "named" ]; then
        local url
        for _ in $(seq 1 30); do
            url=$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' "$LOG_DIR/tunnel.out" 2>/dev/null | head -1 || true)
            [ -n "$url" ] && break
            sleep 1
        done
        if [ -n "$url" ]; then
            echo "$url" > "$RUN_DIR/tunnel.url"
            log "tunnel URL: $url"
        fi
    fi
}

# Start the bot
start_bot() {
    log "starting bot"
    nohup "$PY" -m app.bot_main \
        >> "$LOG_DIR/bot.out" 2>&1 &
    echo $! > "$RUN_DIR/bot.pid"
    sleep 2
    if ! kill -0 "$(cat "$RUN_DIR/bot.pid")" 2>/dev/null; then
        log "bot failed to start"
        return 1
    fi
    log "bot started (pid $(cat "$RUN_DIR/bot.pid"))"
}

# Sync the current quick-tunnel URL into .env so the bot's Mini App link and
# menu button never point at a dead hostname. Quick tunnels rotate their
# hostname on every restart, so this must run each loop.
sync_tunnel_url() {
    local mode url env_url
    mode=$(sed -n 's/^TUNNEL_MODE=//p' "$PROJECT_DIR/.env" 2>/dev/null | tail -1)
    mode="${mode:-quick}"
    [ "$mode" = "named" ] && return 0

    url=$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' "$LOG_DIR/tunnel.out" 2>/dev/null | tail -1 || true)
    [ -z "$url" ] && return 0
    echo "$url" > "$RUN_DIR/tunnel.url"

    env_url=$(sed -n 's/^TELEGRAM_WEBAPP_URL=//p' "$PROJECT_DIR/.env" 2>/dev/null | tail -1)
    if [ "$url" != "$env_url" ]; then
        sed -i.bak "s|^TELEGRAM_WEBAPP_URL=.*|TELEGRAM_WEBAPP_URL=$url|" "$PROJECT_DIR/.env" \
            && rm -f "$PROJECT_DIR/.env.bak"
        log "tunnel URL changed -> $url (restarting bot)"
        if [ -f "$RUN_DIR/bot.pid" ]; then
            kill "$(cat "$RUN_DIR/bot.pid")" 2>/dev/null || true
            rm -f "$RUN_DIR/bot.pid"
        fi
    fi
}

# Main loop
log "supervisor started (pid $$)"

while true; do
    # Check server
    if ! ensure_single "python3.*-m app\.main" "$RUN_DIR/server.pid"; then
        log "server not running"
        start_server
    fi

    # Check tunnel
    if ! ensure_single "cloudflared.*tunnel" "$RUN_DIR/tunnel.pid"; then
        log "tunnel not running"
        start_tunnel
    fi

    # Keep .env pointed at the live tunnel hostname
    sync_tunnel_url

    # Check bot
    if ! ensure_single "python3.*-m app\.bot_main" "$RUN_DIR/bot.pid"; then
        log "bot not running"
        start_bot
    fi

    sleep 30
done
