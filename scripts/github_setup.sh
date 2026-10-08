#!/usr/bin/env bash
# One-time GitHub repo setup for Hermes Wallet Inspector
# Usage: bash scripts/github_setup.sh <github-username> <repo-name>
set -euo pipefail

USERNAME="${1:-}"
REPO="${2:-hermes_bot_miniapp}"

if [ -z "$USERNAME" ]; then
    echo "Usage: bash scripts/github_setup.sh <github-username> [repo-name]"
    exit 1
fi

echo "=== GitHub Repo Setup ==="
echo "Username: $USERNAME"
echo "Repo: $REPO"
echo

# Check if git is initialized
if [ ! -d .git ]; then
    echo "Initializing git repo..."
    git init
    git add .
    git commit -m "Initial commit: Hermes Wallet Inspector"
fi

# Check if remote exists
if git remote get-url origin &>/dev/null; then
    echo "Remote 'origin' already exists: $(git remote get-url origin)"
else
    echo "Creating GitHub repo and adding remote..."
    gh repo create "$USERNAME/$REPO" --public --source=. --remote=origin --push
fi

echo
echo "=== Next Steps ==="
echo "1. Go to https://github.com/$USERNAME/$REPO"
echo "2. Deploy to Render: https://render.com/deploy?repo=https://github.com/$USERNAME/$REPO"
echo "3. Or deploy to Railway: https://railway.app/new/template?template=https://github.com/$USERNAME/$REPO"
echo "4. Set environment variables in your deploy platform:"
echo "   - TELEGRAM_BOT_TOKEN=your_bot_token"
echo "   - SESSION_SECRET=$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
echo "   - TELEGRAM_WEBAPP_URL=https://your-app.onrender.com"
echo "5. Update your Telegram bot's WebApp URL via @BotFather"
echo
echo "=== Deploy Buttons ==="
echo "Render: [![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/$USERNAME/$REPO)"
echo "Railway: [![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/new/template?template=https://github.com/$USERNAME/$REPO)"
