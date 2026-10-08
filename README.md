# Telegram Hermes Bot Mini App

Read-only wallet inspection with signature-based ownership verification.

A Telegram bot backend + Telegram Mini App frontend that lets a user prove they
control a wallet by signing a one-time challenge, then inspects that wallet's
**public** assets and chain data.

---

## Hard security boundaries

| Rule | Enforcement |
|------|-------------|
| Never asks for a seed phrase | No code path accepts one; `/start` states it explicitly |
| Never asks for a private key | Only `personal_sign` output (a signature) is accepted |
| Never stores secrets server-side | Keys are ephemeral client-side; server holds public addresses only |
| Read-only | No transaction is ever built, signed, or broadcast |
| Never moves funds | There is no send/broadcast/sweep endpoint (returns 404) |
| Secrets never logged | `RedactingFilter` + `register_secret` scrub every log record |
| Credentials never hard-coded | All secrets come from the environment / `.env` |

Ownership is proven with a **nonce/challenge + EIP-191 `personal_sign`**
signature. The server recovers the signer's public address from the signature
and compares it to the claimed address — so verification happens without the
private key ever leaving the user's device.

---

## Architecture

```
app/
  config.py            env-only settings, .env parser, secret redaction helpers
  errors.py            typed error hierarchy
  logging_setup.py     JSON logging + mandatory secret redaction
  status.py            ✓ / ✗ / ⏳ status tracker (persists to logs/status.log)
  addresses.py         EVM (EIP-55) + Bitcoin (base58check/bech32/bech32m) validation
  http.py              retrying HTTP client (backoff, rate-limit aware)
  auth.py              nonce store, EIP-191 recovery, HMAC session tokens
  service.py           orchestration; the only place status is mutated
  cli.py               dry-run CLI
  main.py              Mini App backend entrypoint
  bot_main.py          Telegram bot entrypoint
  chains/
    base.py            ChainProvider ABC + ChainRegistry (add chains here)
    evm.py             Ethereum + EVM chains (Blockscout + JSON-RPC fallback)
    bitcoin.py         Bitcoin (mempool.space) — fully separate from EVM
    registry.py        default wiring
  puzzles/
    memepol.py         MemePol API client (key from env, sent in a header)
    analysis.py        four-valued verdict engine
  telegram/
    bot.py             Bot API client + long-polling command handlers
    webapp_auth.py     Mini App initData HMAC-SHA256 validation
  webapp/
    server.py          stdlib HTTP server + JSON API
    static/            Mini App frontend (index.html / app.js / styles.css)
tests/                 146 tests
logs/                  created automatically (git-ignored)
tools/wallet_tools.py  superseded legacy stub, kept for reference only
```

### Adding a chain

```python
from app.chains.base import ChainProvider, AssetReport

class DogecoinProvider(ChainProvider):
    chain, family, label, native_symbol = "dogecoin", "dogecoin", "Dogecoin", "DOGE"
    def validate(self, address): ...
    def fetch_assets(self, address, *, limit=50) -> AssetReport: ...

registry.register(DogecoinProvider())
```

No call site changes — `registry.resolve(address)` dispatches by address format.

---

## Ownership verification flow

1. Client `POST /api/auth/challenge {address}` → server issues a single-use
   nonce and the exact message to sign (TTL 300 s).
2. Client wallet signs it **locally** via `personal_sign`.
3. Client `POST /api/auth/verify {address, signature, nonce}` → server recovers
   the signer address and compares it. On success it returns an HMAC session
   token bound to that address.
4. `POST /api/wallet/assets` then returns public asset data; the response is
   marked `verified: true` when the session token matches the queried address.

Nonces are single-use (replay is rejected) and the message is domain-bound, so
a signature harvested for another app cannot be reused here.

---

## Puzzle analysis verdicts

Having an address or a non-zero balance is **never** enough for a match.

| Verdict | Meaning |
|---------|---------|
| `exact_match` (✓) | Address confirmed **and** all value criteria satisfied |
| `possible_match` (⏳) | Address confirmed but value criteria unmet, or a value threshold met without address confirmation |
| `no_match` (✗) | Evaluated; nothing matched |
| `error` (✗) | Dataset unconfigured/unreachable — **never** reported as a match |

**Chain is a filter, not evidence.** If a puzzle record names a chain that
differs from the wallet's, that record is excluded outright. Sharing a chain
with 31 bitcoin puzzles is not a signal, and treating it as one produced false
`possible_match` results until this was fixed.

### Dataset sources

The analyzer takes any source implementing `list_puzzles() -> list[PuzzleEntry]`.

**Local corpus (preferred, no key):** `app/puzzles/ocp.py` reads the
`open-crypto-puzzles` index — 49 puzzles with escrow addresses, ranked leads
(hints) and artifact references (images). Auto-detected at
`~/ocp/puzzles.json` or `~/open-crypto-puzzles/puzzles.json`; override with
`OCP_DATASET_PATH`.

```bash
python3 -m app.cli inspect 14zMkTgaVXJcxdh4JdWi29MLRR44iUSG9W --puzzles
# -> verdict: exact_match, source=ocp, evaluated=49
```

**HTTP API (fallback):** `app/puzzles/memepol.py`, used only when no local
corpus is found or when `PUZZLE_SOURCE=memepol` forces it. Auth header and
prefix are configurable because providers differ:

```
PUZZLE_SOURCE=memepol               # auto | ocp | memepol
MEMEPOL_BASE_URL=https://host/v1
MEMEPOL_API_KEY=...
MEMEPOL_AUTH_HEADER=Authorization   # or X-API-Key
MEMEPOL_AUTH_PREFIX=Bearer          # empty for a bare key
```

`MemePolClient.ping()` verifies the endpoint and key without printing the key.
**Full contract, auth variants, record schema and a local reference server:
[`docs/puzzle-endpoint.md`](docs/puzzle-endpoint.md).**

### Verified verdict behaviour

| Address | Result |
|---|---|
| `14zMkTgaVXJcxdh4JdWi29MLRR44iUSG9W` (OCP escrow, 0.777 BTC) | `exact_match` ✓ |
| `1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa` (unrelated BTC) | `no_match` ✗ |
| `0xDe0DAFC80d487b8aE652bBF906ac6c6007aE3A5e` (ETH) | `no_match` ✗ |
| no dataset configured | `error` ✗ |

---

## Status vocabulary

| Symbol | Meaning |
|--------|---------|
| ✓ | successfully loaded |
| ✗ | failed / not found (error detail recorded in `logs/status.log`) |
| ⏳ | currently loading / awaiting user action |

Tracked subsystems: `wallet_data`, `assets_chains`, `memepol_comparison`,
`puzzle_hints`, `puzzle_images`.

---

## Termux setup

```bash
# 1. System python3 is required (it carries the crypto modules).
which python3                 # /data/data/com.termux/files/usr/bin/python3
python3 --version             # 3.11+

# 2. Dependencies
cd ~/hermes_bot_miniapp
python3 -m pip install -r requirements.txt

# 3. Configuration (never commit .env)
cp .env.example .env
nano .env                     # fill in TELEGRAM_BOT_TOKEN / MEMEPOL_API_KEY
chmod 600 .env

# 4. Run the tests
python3 -m pytest -q

# 5. Dry-run against a public address (no credentials needed)
python3 -m app.cli inspect 0xDe0DAFC80d487b8aE652bBF906ac6c6007aE3A5e

# 6. Offline signature-flow self-test (ephemeral in-process key)
python3 -m app.cli demo

# 7. Mini App backend
python3 -m app.main --host 127.0.0.1 --port 8080

# 8. Telegram bot (requires TELEGRAM_BOT_TOKEN)
python3 -m app.bot_main                 # poll forever
python3 -m app.bot_main --once          # one batch, then exit
python3 -m app.bot_main --selftest      # render replies locally, no network
```

> **Note:** Termux's `$PREFIX` python is used deliberately. If you use a venv
> that lacks `eth-keys` / `pycryptodome`, signature recovery will fail.

### If `pip install` fails on `coincurve`

`coincurve` is only a fallback; the core path needs `eth-keys` +
`pycryptodome`. Install those alone:

```bash
python3 -m pip install requests eth-keys pycryptodome base58 pytest
```

---

## HTTP API

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/health` | liveness + capability flags |
| GET | `/api/status` | subsystem ✓/✗/⏳ status |
| GET | `/api/chains` | registered chains |
| POST | `/api/auth/challenge` | issue signing challenge |
| POST | `/api/auth/verify` | verify signature → session token |
| POST | `/api/wallet/assets` | read-only public asset lookup |
| POST | `/api/telegram/validate` | validate Mini App `initData` |

There is intentionally **no** transaction, signing, or broadcast endpoint.

### Telegram Mini App setup

1. Talk to @BotFather → `/newapp`, point it at your public HTTPS URL.
2. Set `TELEGRAM_WEBAPP_URL` in `.env` to that URL.
3. Expose the local server (e.g. `cloudflared tunnel --url http://127.0.0.1:8080`).
4. Optionally set the menu button:

```python
import os
from app.telegram.bot import TelegramClient
TelegramClient(os.environ["TELEGRAM_BOT_TOKEN"]).set_webapp_menu(
    os.environ["TELEGRAM_WEBAPP_URL"])
```

---

## Environment variables

| Variable | Required | Purpose |
|----------|----------|---------|
| `TELEGRAM_BOT_TOKEN` | for bot | Bot API auth + Mini App `initData` validation |
| `TELEGRAM_WEBAPP_URL` | for Mini App | Public HTTPS URL Telegram opens |
| `MEMEPOL_API_KEY` | for HTTP puzzles | Authorized puzzle dataset (only used when no local corpus) |
| `MEMEPOL_BASE_URL` | no | Puzzle API base URL |
| `MEMEPOL_AUTH_HEADER` | no | Auth header name (default `Authorization`) |
| `MEMEPOL_AUTH_PREFIX` | no | Auth value prefix (default `Bearer`; empty for `X-API-Key`) |
| `OCP_DATASET_PATH` | no | Path to a local `puzzles.json` (auto-detected if absent) |
| `PUZZLE_SOURCE` | no | `auto` (default) \| `ocp` \| `memepol` — which source wins |
| `ETH_RPC_URL` | no | Private RPC; public fallbacks are built in |
| `BTC_API_BASE` | no | Defaults to `https://mempool.space/api` |
| `HOST` / `PORT` | no | Server bind (default `127.0.0.1:8080`) |
| `NONCE_TTL_SECONDS` | no | Challenge validity (default 300) |
| `RATE_LIMIT_PER_MINUTE` | no | Per-IP request budget (default 60) |
| `RATE_LIMIT_EXPENSIVE_PER_MINUTE` | no | Budget for chain/puzzle endpoints (default 20) |
| `LOG_DIR` | no | Defaults to `./logs` |

Placeholder values (e.g. `YOUR_TELEGRAM_BOT_TOKEN`) are detected and treated as
**unconfigured**, so a forgotten edit fails closed rather than silently.

---

## Testing

```bash
python3 -m pytest -q              # 146 tests
python3 -m pytest tests/test_addresses.py -v
python3 -m pytest -k signature    # signature verification only
```

Coverage: address validation (EVM + Bitcoin, incl. checksum/bech32 failures),
family separation, signature recovery/rejection, nonce single-use + expiry,
status transitions and persistence, log redaction, upstream API failure paths,
MemePol verdicts, Telegram `initData` HMAC, and the HTTP API end-to-end.

Tests never touch the network — upstream APIs are stubbed.

The bot deploy path (getMe → menu button → getUpdates → dispatch → sendMessage)
is verified against a mock Bot API:

```bash
python3 tests/deploy_check.py
```

### Frontend integration (Node, no browser)

`tests/frontend_harness.mjs` loads the **real** `static/app.js` into a minimal
fake DOM, points its `fetch()` at a **real** server, and stands in for a wallet
by signing via `tools/sign_message.py`. It proves the frontend actually runs and
that every endpoint it calls exists and returns the fields it reads:

```bash
node tests/frontend_harness.mjs http://127.0.0.1:8080
node tests/frontend_harness.mjs https://<tunnel>.trycloudflare.com
```

21 checks: app.js executes, the status table and capability line render, the
connect → challenge → sign → verify flow completes, asset rows are written, the
session token is carried into the asset request, and no secret reaches the DOM.
Negative controls confirm it has teeth (dead server → 16 failures; a broken
endpoint → 8 failures naming the missing call).

### Security surface (verified against the public tunnel)

| Probe | Result |
|---|---|
| `GET /../config.py`, `..%2f`, `--path-as-is` | `400` — traversal blocked |
| `GET /.env`, `/logs/app.log` | `404` — not served |
| 200 KB request body | `400` — capped at 64 KB |
| 28 rapid POSTs to an expensive endpoint | 20× `200` then `429` |
| `/health` during an expensive-endpoint block | `200` — separate budget |

---

## Deployment

### Stable URL (named tunnel) — recommended

A quick tunnel gets a **random hostname that changes on every restart**, so the
Mini App URL has to be re-registered with @BotFather each time. A *named* tunnel
is bound to a hostname on a domain you own and keeps the same URL forever.

**One-time prerequisites** (browser work only you can do):

1. A Cloudflare account.
2. A domain added to that account, with its nameservers pointed at Cloudflare
   (Cloudflare's dashboard shows the two nameservers to set at your registrar).
   The domain does not need to be registered *with* Cloudflare — it only needs to
   be *managed* by it. A cheap domain is fine; Cloudflare's tunnel + DNS are free.

**Then:**

```bash
cd ~/hermes_bot_miniapp
bash scripts/tunnel_setup.sh bot.your-domain.com
```

It logs in, creates the tunnel, routes DNS, writes `~/.cloudflared/config.yml`
(mode 600), validates the ingress rules, and records everything in `.env`:

```
TUNNEL_MODE=named
TUNNEL_NAME=hermesgotdat
TUNNEL_HOSTNAME=bot.your-domain.com
TUNNEL_ID=<uuid>
TELEGRAM_WEBAPP_URL=https://bot.your-domain.com
```

From then on `bash scripts/start.sh` runs the named tunnel automatically:

```
bash scripts/start.sh              # uses TUNNEL_MODE from .env
bash scripts/register_miniapp.sh   # register with Telegram — ONCE, not every restart
```

Switch back to a quick tunnel any time with `TUNNEL_MODE=quick` in `.env`.

**Notes**
- `scripts/tunnel_setup.sh` is idempotent — re-running reuses the existing tunnel.
- It never prints tunnel credentials; `~/.cloudflared/*.json` and `config.yml` are
  chmod 600. `.env` is chmod 600 too.
- No inbound ports are opened. The tunnel is an outbound connection only, which
  matters on a phone behind CGNAT.

### Quick tunnel (default)

```bash
bash scripts/start.sh --port 8080
```

Random `*.trycloudflare.com` hostname, changes every restart, and the hostname is
revoked the moment cloudflared stops.

### Termux notes

`cloudflared` is in the Termux repo: `pkg install cloudflared`. A freshly created
`trycloudflare.com` hostname is often **NXDOMAIN locally for ~300s** (negative
caching) even though it resolves globally — `start.sh` works around this by
resolving the edge IP over DoH and pinning it with `--resolve`, so the readiness
probe tests the tunnel rather than the phone's resolver. A named tunnel on your
own domain does not have this problem, since the hostname is stable.

The callback for `cloudflared tunnel login` targets `127.0.0.1`, so opening the
printed URL in the phone's own browser works.

All deployment logic lives in `scripts/` and is idempotent.

| Script | Purpose |
|--------|---------|
| `scripts/setup_credentials.sh` | Interactively write `.env` (hidden input, `chmod 600`) |
| `scripts/check_bot_token.py` | Refuse to poll a bot the Hermes gateway already polls (digest compare, exit 3) |
| `scripts/tunnel_setup.sh` | One-time: create a named Cloudflare tunnel + DNS route for a permanent URL |
| `scripts/start.sh` | Start server + tunnel (`TUNNEL_MODE=named`\|`quick`), wait for a real `200`, record the URL in `.env` |
| `scripts/stop.sh` | Stop server + tunnel |
| `scripts/run_bot.sh` | Run the bot with crash-restart supervision |
| `scripts/register_miniapp.sh` | `getMe`, menu button, command list; prints the manual @BotFather step |
| `scripts/status.sh` | Full deploy report (processes, endpoints, credential presence) |
| `scripts/install_boot.sh` | Install a Termux:Boot hook for auto-start after reboot |

### Access tiers (free / paid / owner)

Four tiers, resolved from the **verified session**. The caller's tier applies only
to their **own** address — signing with your wallet does not let you read another
address's entitlements.

| Tier | Puzzles | Hints/puzzle | Images | Private corpus |
|---|---|---|---|---|
| `anonymous` | 0 | 0 | ✗ | ✗ |
| `verified` (free) | 3 | 1 | ✗ | ✗ |
| `paid` | all | all | ✓ | ✗ |
| `owner` | all | all | ✓ | **✓** |

**Your private puzzle list is a separate file.** It is never merged into the
public corpus, so it cannot leak through a bug in the public filtering path.
Non-owner responses contain no trace of it — not titles, not counts, not its
existence. Path is `PRIVATE_DATASET_PATH` (keep it outside the repo).

**Grant access** (operator-only, local JSON store — no payment processor needed):

```bash
python3 -m app.cli grant tiers                       # show the tier matrix
python3 -m app.cli grant grant 0xABC… --tier paid --days 30 --note "paypal"
python3 -m app.cli grant grant 0xDEF… --tier owner --note "me"
python3 -m app.cli grant list
python3 -m app.cli grant revoke 0xABC…
```

Sell however you like (PayPal, card, crypto), then grant. `OWNER_ADDRESSES` in
`.env` (comma-separated) grants owner permanently without needing the store.

Verified live:

```
anonymous  on an escrow address : matches=0  hints=0  evaluated=49
                                   locked={"hidden_matches":1,"full_corpus":"…"}
free       on own wallet        : matches=0 (genuinely matches nothing)
owner      on own wallet        : private_count=12
owner      querying someone else: verified=False  tier=anonymous  private=no
```

The last line is the important one: an owner signature queried against a
**different** address is downgraded to anonymous and receives nothing.

`app/access.py` + `tests/test_access.py` (41 tests, incl. non-disclosure
assertions that check for the *absence* of private titles).

### Secret-shape detection (warn, never store)

`POST /api/security/scan` or `python3 -m app.cli scan` detects private keys, seed
phrases, API tokens and card numbers — and **stores nothing**. The raw value is
never returned, logged, or written to disk; only a masked preview and advice.
Tests assert the secret is absent from the response *and* from every log file.

```bash
python3 -m app.cli scan "some text"
python3 -m app.cli scan --file ~/notes.txt --json   # exit 1 if secrets found
```

### Never reuse the Hermes gateway's bot

`TELEGRAM_BOT_TOKEN` in `.env` must belong to a **new** bot from @BotFather. If it
is the Hermes gateway's own bot, a second `getUpdates` poller would steal the
gateway's updates and break your existing Hermes Telegram.

`scripts/check_bot_token.py` makes that impossible to trip. It compares tokens by
SHA-256 digest against `~/.hermes/.env` and `~/.hermes/secrets.env`, so no secret
is ever read out or printed:

| Exit | Meaning |
|---|---|
| `0` | safe to poll |
| `2` | no token configured |
| `3` | token belongs to the running Hermes gateway — **refused** |
| `4` | token rejected by Telegram (invalid/revoked) |
| `5` | could not verify (network) |

```bash
python3 scripts/check_bot_token.py          # human output
python3 scripts/check_bot_token.py --json   # machine output
```

Both entry points into polling enforce it — `scripts/run_bot.sh` **and** a direct
`python3 -m app.bot_main` — so there is no bypass. Override only for a
deliberately-shared token with `SKIP_TOKEN_CHECK=1`.

### Full sequence

```bash
cd ~/hermes_bot_miniapp

# 1. credentials (hidden input)
bash scripts/setup_credentials.sh

# 2. server + public HTTPS tunnel  (prints the trycloudflare URL)
bash scripts/start.sh

# 3. verify everything
bash scripts/status.sh

# 4. register the Mini App + menu button
bash scripts/register_miniapp.sh

# 5. run the bot (supervised, auto-restart)
bash scripts/run_bot.sh
```

### Notes and gotchas

- **Quick-tunnel URLs are ephemeral.** Every `start.sh` produces a new
  `*.trycloudflare.com` hostname and rewrites `TELEGRAM_WEBAPP_URL` in `.env`.
  Re-run `register_miniapp.sh` after a restart, or set up a *named* tunnel with
  a stable hostname for anything long-lived.
- **The tunnel needs ~30–90 s to register.** Hitting the URL too early returns
  **HTTP 530 (Argo Tunnel error)**. `start.sh` polls until `/health` returns
  `200` before reporting success — don't shortcut this.
- **`http://127.0.0.1` is not reachable by Telegram.** The Mini App must be
  served over public HTTPS; that is what the tunnel provides.
- **DNS negative caching.** A freshly created `trycloudflare.com` name can
  return NXDOMAIN locally for up to the 300 s TTL while it already resolves
  globally. Verify with `--resolve <host>:443:<ip>` if a local lookup fails.
- **Termux:Boot** is a separate F-Droid app; `install_boot.sh` writes the hook
  but you must open that app once to grant the boot permission.
- `termux-wake-lock` is held while serving so Android does not suspend the
  processes; `stop.sh` releases it.

### Verified deployment state

```
✓ server running          127.0.0.1:8080
✓ tunnel running          https://<name>.trycloudflare.com
✓ public /health          200
✓ public /  (Mini App)    200
✓ public /app.js          200
✓ live chain lookup       ✓ ['ETH', 'USDT', 'HEX', 'MCAT']
✓ auth challenge          ⏳ nonce issued, ttl 300
```

Public routes are read-only. There is still no send/sign/broadcast endpoint
(404), so a publicly reachable URL exposes no ability to move funds.

