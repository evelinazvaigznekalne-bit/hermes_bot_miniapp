#!/data/data/com.termux/files/usr/bin/bash
# Register the Mini App with @BotFather's API.
#
# Uses the Bot API `setChatMenuButton` (works with any token) and prints the
# manual @BotFather /newapp steps, since app *registration* has no public API.
#
# Requires TELEGRAM_BOT_TOKEN and TELEGRAM_WEBAPP_URL in .env.

set -uo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_DIR"
PY="${PYTHON:-/data/data/com.termux/files/usr/bin/python3}"

"$PY" - <<'PYEOF'
import sys, os, json, urllib.request, urllib.error
sys.path.insert(0, os.getcwd())
from app.config import get_settings, load_dotenv, redact
load_dotenv()
s = get_settings()

if not s.telegram_configured:
    print("✗ TELEGRAM_BOT_TOKEN not configured. Run scripts/setup_credentials.sh")
    sys.exit(2)
if not s.telegram_webapp_url:
    print("✗ TELEGRAM_WEBAPP_URL not configured. Run scripts/start.sh first.")
    sys.exit(2)

url = s.telegram_webapp_url.rstrip("/")
token = s.telegram_bot_token
print(f"token : {redact(token)}")
print(f"webapp: {url}")
print()

def call(method, payload):
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{token}/{method}",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return json.loads(e.read())

# 1. identity check - never prints the token
me = call("getMe", {})
if me.get("ok"):
    b = me["result"]
    print(f"✓ bot identity: @{b.get('username')} ({b.get('first_name')})")
else:
    print(f"✗ getMe failed: {me.get('description')}")
    sys.exit(1)

# 1b. display name (the @username itself is fixed at creation by @BotFather)
name = s.bot_display_name
nm = call("setMyName", {"name": name})
print(f"✓ display name set to {name!r}" if nm.get("ok")
      else f"✗ setMyName: {nm.get('description')}")

desc = (f"{name} - read-only public wallet inspection. "
        "Never asks for a seed phrase or private key.")
de = call("setMyDescription", {"description": desc})
print("✓ description set" if de.get("ok") else f"✗ setMyDescription: {de.get('description')}")

sd = call("setMyShortDescription", {"short_description": "Read-only wallet inspector"})
print("✓ short description set" if sd.get("ok")
      else f"✗ setMyShortDescription: {sd.get('description')}")

# 2. menu button pointing at the Mini App
mb = call("setChatMenuButton", {
    "menu_button": {"type": "web_app", "text": "Open App",
                    "web_app": {"url": url}}})
print("✓ menu button set" if mb.get("ok") else f"✗ menu button: {mb.get('description')}")

# 3. command list
cmds = {"commands": [
    {"command": "start",   "description": "Open the Mini App"},
    {"command": "status",  "description": "🔹 Subsystem status"},
    {"command": "inspect", "description": "Public assets for an address"},
    {"command": "puzzles", "description": "Compare with MemePol data"},
    {"command": "chains",  "description": "Supported chains"},
    {"command": "setname", "description": "Set the bot display name"},
    {"command": "help",    "description": "Help"},
]}
cs = call("setMyCommands", cmds)
print("✓ commands registered" if cs.get("ok") else f"✗ setMyCommands: {cs.get('description')}")

print()
print("── remaining manual step (no public API) ──────────────")
print("The @username is fixed at creation. To change it, or to create the")
print("Mini App entry, open @BotFather and send:")
print("    /newapp")
print(f"    → select your bot → title → description → icon")
print(f"    → Web App URL: {url}")
print("Use /setname in @BotFather to change the @username.")
PYEOF
