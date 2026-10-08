#!/data/data/com.termux/files/usr/bin/bash
# Interactively write .env with real credentials.
#
# Values are read with `read -s` (no echo) and never printed back.
# The resulting .env is chmod 600.

set -uo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_DIR"
ENV_FILE="$PROJECT_DIR/.env"

if [ ! -f "$PROJECT_DIR/.env.example" ]; then
  echo "✗ .env.example missing" >&2; exit 1
fi

[ -f "$ENV_FILE" ] || cp "$PROJECT_DIR/.env.example" "$ENV_FILE"

echo "Configure credentials. Press Enter to keep the current value."
echo "Input is hidden. Nothing is echoed or logged."
echo

set_env() {
  local key="$1" prompt="$2" value
  printf '%s: ' "$prompt"
  read -rs value
  echo
  [ -z "$value" ] && { echo "  · unchanged"; return 0; }
  if grep -q "^${key}=" "$ENV_FILE"; then
    /data/data/com.termux/files/usr/bin/python3 - "$ENV_FILE" "$key" "$value" <<'PYEOF'
import sys, pathlib
path, key, value = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]
lines = path.read_text().splitlines()
out = [f"{key}={value}" if l.startswith(f"{key}=") else l for l in lines]
path.write_text("\n".join(out) + "\n")
PYEOF
  else
    echo "${key}=${value}" >> "$ENV_FILE"
  fi
  echo "  ✓ set"
}

set_env TELEGRAM_BOT_TOKEN  "Telegram bot token (from @BotFather)"
set_env MEMEPOL_API_KEY     "MemePol API key (optional, Enter to skip)"
set_env MEMEPOL_BASE_URL    "MemePol base URL (optional)"
set_env ETH_RPC_URL         "Custom ETH RPC URL (optional)"

chmod 600 "$ENV_FILE"
echo
echo "✓ wrote $ENV_FILE (chmod 600)"
echo
echo "Current status:"
bash "$PROJECT_DIR/scripts/status.sh" 2>/dev/null | sed -n '/credentials/,/subsystem/p'
