#!/usr/bin/env bash
# One-time setup for a Cloudflare NAMED tunnel -> permanent, stable URL.
#
# A quick tunnel (scripts/start.sh default) gets a random hostname that changes
# on every restart, so the Mini App URL must be re-registered with @BotFather
# each time. A named tunnel is bound to a hostname on a domain you own and keeps
# the same URL forever.
#
# Requirements (one-time, done by you in a browser):
#   - a Cloudflare account
#   - a domain added to that account, with its nameservers pointed at Cloudflare
#
# Usage:
#   bash scripts/tunnel_setup.sh                 # reads TUNNEL_HOSTNAME from .env
#   bash scripts/tunnel_setup.sh bot.example.com # or pass it explicitly
#
# This script never prints tunnel credentials.
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CF_DIR="${CLOUDFLARED_HOME:-$HOME/.cloudflared}"
ENV_FILE="$PROJECT_DIR/.env"

# --- helpers ---------------------------------------------------------------
# Read a key from .env without echoing anything else in the file.
env_get() {
  [ -f "$ENV_FILE" ] || return 0
  sed -n "s/^$1=//p" "$ENV_FILE" | tail -1
}

env_set() {
  local key="$1" value="$2"
  [ -f "$ENV_FILE" ] || return 0
  if grep -q "^$key=" "$ENV_FILE"; then
    KEY="$key" VALUE="$value" /data/data/com.termux/files/usr/bin/python3 - "$ENV_FILE" <<'PYEOF'
import os, pathlib
p = pathlib.Path(os.sys.argv[1])
k, v = os.environ["KEY"], os.environ["VALUE"]
lines = p.read_text().splitlines()
p.write_text("\n".join(f"{k}={v}" if l.startswith(f"{k}=") else l for l in lines) + "\n")
PYEOF
  else
    printf '%s=%s\n' "$key" "$value" >> "$ENV_FILE"
  fi
}

die() { echo "✗ $*" >&2; exit 1; }

# --- resolve inputs --------------------------------------------------------
command -v cloudflared >/dev/null 2>&1 || die "cloudflared not installed (pkg install cloudflared)"

HOSTNAME_ARG="${1:-}"
TUNNEL_HOSTNAME="${HOSTNAME_ARG:-$(env_get TUNNEL_HOSTNAME)}"
TUNNEL_NAME="$(env_get TUNNEL_NAME)"; TUNNEL_NAME="${TUNNEL_NAME:-hermesgotdat}"

if [ -z "$TUNNEL_HOSTNAME" ] || [ "$TUNNEL_HOSTNAME" = "your-subdomain.your-domain.com" ]; then
  cat >&2 <<'EOF'
✗ No tunnel hostname given.

Pass your subdomain as an ARGUMENT to this script — do not run it on its own:

    bash scripts/tunnel_setup.sh bot.yourdomain.com
                                 ^^^^^^^^^^^^^^^^^^ this part is the argument

Prerequisites, both required BEFORE this will work:

  1. You own the domain (e.g. yourdomain.com is registered).
  2. The domain is added to your Cloudflare account and shows as "Active":
       dash.cloudflare.com -> Add a site -> Free plan
       then set the two nameservers Cloudflare shows you at your registrar,
       then wait for Cloudflare to report the zone as Active.

Verify your domain is live on Cloudflare before running this:

    curl -s -H 'accept: application/dns-json' \
      "https://cloudflare-dns.com/dns-query?name=yourdomain.com&type=NS"

If that returns Status 3, the domain is not registered at all.
EOF
  exit 1
fi

PORT="$(env_get PORT)"; PORT="${PORT:-8080}"
echo "project    : $PROJECT_DIR"
echo "tunnel name: $TUNNEL_NAME"
echo "hostname   : $TUNNEL_HOSTNAME"
echo "origin     : http://127.0.0.1:$PORT"
echo

mkdir -p "$CF_DIR"
chmod 700 "$CF_DIR"

# --- 1. login --------------------------------------------------------------
if [ -f "$CF_DIR/cert.pem" ]; then
  echo "✓ already logged in ($CF_DIR/cert.pem)"
else
  cat <<EOF
── step 1/4: authorize cloudflared ──────────────────────────────
cloudflared will print a URL. Open it in a browser (the phone's
browser works, since the callback targets 127.0.0.1), pick the
domain, and click Authorize. Then come back here.
EOF
  echo
  cloudflared tunnel login || die "login failed or was cancelled"
  [ -f "$CF_DIR/cert.pem" ] || die "login did not produce cert.pem"
  echo "✓ authorized"
fi

# --- 2. create (or reuse) the tunnel ---------------------------------------
EXISTING_ID="$(cloudflared tunnel list --output json 2>/dev/null \
  | tr '}' '\n' | grep -F "\"name\":\"$TUNNEL_NAME\"" \
  | grep -oE '"id":"[a-f0-9-]{36}"' | head -1 | sed 's/.*:"//; s/"//' || true)"

if [ -n "$EXISTING_ID" ]; then
  TUNNEL_ID="$EXISTING_ID"
  echo "✓ tunnel '$TUNNEL_NAME' already exists (id $TUNNEL_ID)"
else
  echo "── step 2/4: creating tunnel '$TUNNEL_NAME' ──"
  cloudflared tunnel create "$TUNNEL_NAME" >/dev/null || die "tunnel create failed"
  TUNNEL_ID="$(cloudflared tunnel list --output json 2>/dev/null \
    | tr '}' '\n' | grep -F "\"name\":\"$TUNNEL_NAME\"" \
    | grep -oE '"id":"[a-f0-9-]{36}"' | head -1 | sed 's/.*:"//; s/"//' || true)"
  [ -n "$TUNNEL_ID" ] || die "created the tunnel but could not read its id"
  echo "✓ created tunnel id $TUNNEL_ID"
fi

CRED_FILE="$CF_DIR/$TUNNEL_ID.json"
[ -f "$CRED_FILE" ] || die "credentials file missing: $CRED_FILE (run: cloudflared tunnel token $TUNNEL_NAME)"
chmod 600 "$CRED_FILE" 2>/dev/null || true

# --- 3. point DNS at the tunnel --------------------------------------------
echo "── step 3/4: routing $TUNNEL_HOSTNAME -> tunnel ──"
if cloudflared tunnel route dns "$TUNNEL_NAME" "$TUNNEL_HOSTNAME" 2>&1 | tee /tmp/.cf_route.$$ | grep -qiE 'already|exists'; then
  echo "✓ DNS route already present"
else
  grep -qiE 'Added CNAME|Creating|updated' /tmp/.cf_route.$$ \
    && echo "✓ DNS route created" \
    || { cat /tmp/.cf_route.$$ >&2; rm -f /tmp/.cf_route.$$; die "DNS routing failed"; }
fi
rm -f /tmp/.cf_route.$$

# --- 4. write config.yml ---------------------------------------------------
CONFIG="$CF_DIR/config.yml"
cat > "$CONFIG" <<EOF
# Generated by hermes_bot_miniapp/scripts/tunnel_setup.sh - safe to commit? No.
# Contains no secrets itself, but references the credentials file.
tunnel: $TUNNEL_ID
credentials-file: $CRED_FILE

ingress:
  - hostname: $TUNNEL_HOSTNAME
    service: http://127.0.0.1:$PORT
  - service: http_status:404
EOF
chmod 600 "$CONFIG"

echo "── step 4/4: validating ingress ──"
cloudflared tunnel --config "$CONFIG" ingress validate \
  && echo "✓ ingress config valid" \
  || die "ingress config failed validation"

# --- persist into .env -----------------------------------------------------
env_set TUNNEL_MODE named
env_set TUNNEL_NAME "$TUNNEL_NAME"
env_set TUNNEL_HOSTNAME "$TUNNEL_HOSTNAME"
env_set TUNNEL_ID "$TUNNEL_ID"
env_set TELEGRAM_WEBAPP_URL "https://$TUNNEL_HOSTNAME"
[ -f "$ENV_FILE" ] && chmod 600 "$ENV_FILE"

cat <<EOF

✓ Named tunnel ready — this URL is permanent:
    https://$TUNNEL_HOSTNAME

Next:
    bash scripts/start.sh              # runs the named tunnel
    bash scripts/register_miniapp.sh   # register the URL with Telegram (once)

The URL never changes, so @BotFather registration is one-time only.
EOF
