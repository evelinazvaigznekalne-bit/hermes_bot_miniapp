# Deployment Guide

Make the Hermes Wallet Inspector available to other users on free cloud platforms.

## Prerequisites

- A Telegram bot token from @BotFather
- A GitHub account
- That's it — no credit card, no domain required

## Option 1: Render (Recommended — Easiest)

1. **Fork this repo** on GitHub
2. **Create Render account** at [render.com](https://render.com) (free)
3. **New Web Service** → Connect your forked repo
4. **Configure:**
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `python3 -m app.main --host 0.0.0.0 --port $PORT`
   - Plan: Free
5. **Set environment variables** in Render dashboard:
   - `TELEGRAM_BOT_TOKEN` — your bot token
   - `SESSION_SECRET` — random 32+ char string
   - `TELEGRAM_WEBAPP_URL` — `https://your-app-name.onrender.com`
6. **Deploy** — Render gives you a public URL in ~2 minutes
7. **Update Telegram bot** with the new URL via @BotFather

## Option 2: Railway

1. **Fork this repo**
2. **Create Railway account** at [railway.app](https://railway.app) (free)
3. **New Project** → Deploy from GitHub repo
4. **Set environment variables:**
   - `TELEGRAM_BOT_TOKEN`
   - `SESSION_SECRET`
   - `TELEGRAM_WEBAPP_URL` — `https://your-app.up.railway.app`
5. **Deploy** — Railway auto-detects Python and deploys

## Option 3: Fly.io

1. **Fork this repo**
2. **Install Fly CLI:** `curl -L https://fly.io/install.sh | sh`
3. **Login:** `fly auth signup` (free tier, no credit card)
4. **Launch:**
   ```bash
   cd ~/hermes_bot_miniapp
   fly launch --name hermes-wallet-inspector --no-deploy
   fly secrets set TELEGRAM_BOT_TOKEN=your_token SESSION_SECRET=your_secret
   fly deploy
   ```
5. **Set URL:**
   ```bash
   fly secrets set TELEGRAM_WEBAPP_URL=https://hermes-wallet-inspector.fly.dev
   ```

## Option 4: Oracle Cloud Always Free (Advanced)

1. **Create Oracle Cloud account** (requires credit card for verification, but free tier is free)
2. **Create Always Free ARM instance** (4 cores, 24GB RAM)
3. **SSH into instance:**
   ```bash
   sudo apt update && sudo apt install python3-pip -y
   git clone https://github.com/YOUR_USERNAME/hermes_bot_miniapp.git
   cd hermes_bot_miniapp
   pip3 install -r requirements.txt
   cp .env.example .env
   nano .env  # set TELEGRAM_BOT_TOKEN, SESSION_SECRET
   python3 -m app.main --host 0.0.0.0 --port 8080 &
   ```
4. **Configure security list** to allow inbound traffic on port 8080
5. **Use the public IP** as `TELEGRAM_WEBAPP_URL`

## Option 5: Docker (Any Platform)

```bash
docker build -t hermes-wallet-inspector .
docker run -p 8080:8080 \
  -e TELEGRAM_BOT_TOKEN=your_token \
  -e SESSION_SECRET=your_secret \
  -e TELEGRAM_WEBAPP_URL=https://your-domain.com \
  hermes-wallet-inspector
```

## Post-Deployment

1. **Verify health:** `curl https://your-url/health`
2. **Register Mini App:** `bash scripts/register_miniapp.sh`
3. **Set menu button** in @BotFather → Bot Settings → Menu Button
4. **Share the URL** with users

## Environment Variables Reference

| Variable | Required | Description |
|----------|----------|-------------|
| `TELEGRAM_BOT_TOKEN` | Yes | From @BotFather |
| `SESSION_SECRET` | Yes | Random 32+ char string |
| `TELEGRAM_WEBAPP_URL` | Yes | Your public HTTPS URL |
| `PAYPAL_CLIENT_ID` | No | For paid tier checkout |
| `PAYPAL_CLIENT_SECRET` | No | For paid tier checkout |
| `PORT` | No | Default: 8080 |
| `NONCE_TTL_SECONDS` | No | Default: 300 |
| `RATE_LIMIT_PER_MINUTE` | No | Default: 60 |

## Free Tier Limits

| Platform | Free Tier | Notes |
|----------|-----------|-------|
| Render | 750 hrs/month | Spins down after 15min inactivity |
| Railway | $5 credit/month | Enough for 1-2 apps |
| Fly.io | 3 shared VMs | Always free |
| Oracle Cloud | 4 ARM cores, 24GB RAM | Always free, needs credit card |

## Troubleshooting

**App not loading:**
- Check `TELEGRAM_WEBAPP_URL` matches your actual URL
- Verify `TELEGRAM_BOT_TOKEN` is correct
- Check logs: `fly logs` or Render/Railway dashboard

**Auth not working:**
- Ensure `SESSION_SECRET` is set and consistent
- Check that `TELEGRAM_WEBAPP_URL` is HTTPS (not HTTP)

**Bot not responding:**
- Make sure `python3 -m app.bot_main` is running
- Verify the bot token belongs to YOUR bot, not the Hermes gateway
