# Hermes Mini App Tool Audit Summary

## Primary Objective
Bring `~/hermes_bot_miniapp` to a production-quality state with verified tool implementations and deploy through Render.

## Audit Result (2026-10-21)

| Metric | Value |
|--------|-------|
| Total tools audited | 23 |
| Verified (live HTTP or local handler, real input) | 17 |
| Defective in the deployed build | 6 |
| Unverified | 0 |
| Test suite (after repairs) | 783 passed, 0 failed, 0 skipped |

**The earlier baseline of "all tools verified" was wrong.** Nine tools were marked
`verified` in `audit_inventory.json` without a live request ever being made. A live
probe of the deployed build shows six of the 23 fail on a valid input.

## Tool Inventory Status

| # | Tool Name | Endpoint | Frontend | Status |
|---|-----------|----------|----------|--------|
| 1 | analyze_file | POST /api/tools/file | app.js: loadFile() | verified |
| 2 | decode_data | POST /api/tools/decode | app.js: decodeHex() | verified |
| 3 | analyze_data | POST /api/tools/analyze | app.js: analyzeHex() | verified |
| 4 | simulate_sweep | POST /api/tools/sweep | app.js: simulateSweep() | verified |
| 5 | crack_puzzle | POST /api/tools/crack | app.js: crackPuzzle() | verified |
| 6 | analyze_image | POST /api/tools/image | app.js: analyzeImage() | **defective** — `PIL` missing, LSB branch dead |
| 7 | validate_seed_phrase | POST /api/tools/seed-validate | app.js: validateSeed() | **defective** — HTTP 500 |
| 8 | derive_addresses | POST /api/tools/derive-addresses | app.js: deriveAddresses() | **defective** — HTTP 500 |
| 9 | tools_decode_transaction | POST /api/tools/decode-transaction | backend only | **defective** — ETH 500, BTC 200 |
| 10 | tools_convert_mnemonic | POST /api/tools/mnemonic | backend only | **defective** — HTTP 500 |
| 11 | tools_crypto_calculator | POST /api/tools/calculator | backend only | **defective** — hex 500, WIF 400 |
| 12 | tools_parse_wallet_dat | POST /api/tools/wallet-dat | backend only | verified |
| 13 | puzzles_classify | POST /api/puzzles/classify | backend only | verified |
| 14 | crack_list | GET /api/crack/list | app.js: catalog page | verified |
| 15 | puzzles_plan | POST /api/puzzles/plan | backend only | verified |
| 16 | puzzles_attack | POST /api/puzzles/attack | backend only | verified |
| 17 | puzzles_bitcoin_puzzle | POST /api/puzzles/bitcoin-puzzle | app.js: checkBtcPuzzle() | verified |
| 18 | web_sources | POST /api/web-sources | app.js: searchWebSources() | verified |
| 19 | auth_challenge | POST /api/auth/challenge | app.js: wallet gate | verified |
| 20 | auth_verify | POST /api/auth/verify | app.js: wallet verify | verified |
| 21 | wallet_assets | POST /api/wallet/assets | app.js: loadAssets() | verified |
| 22 | telegram_validate | POST /api/telegram/validate | app.js: telegram login | verified |
| 23 | scan_secrets | POST /api/security/scan | app.js: checkSecrets() | verified |

## Defects

### D1 — `mnemonic` missing from `requirements.txt` (blocks tools 7, 8, 10)
**Evidence:** live `POST /api/tools/seed-validate`, `/api/tools/derive-addresses` and
`/api/tools/mnemonic` each return `500 {"error":"internal_error"}` for a valid BIP39
vector, while the same inputs succeed locally. `app/tools.py:672` and
`app/crypto_tools.py:653` do `from mnemonic import Mnemonic` at call time; the package
is installed in the Termux dev environment but is **not listed in `requirements.txt`**,
so the Render virtualenv does not contain it.
**Reproduced:** blocking `mnemonic` on `sys.meta_path` makes all three functions raise
`ImportError`, and the server's catch-all turns that into a 500.
**Repair applied:** added `mnemonic>=0.20` to `requirements.txt`.
**Not live** — requires a Render redeploy.

### D2 — `bech32` missing from `requirements.txt` (blocks tool 8)
**Evidence:** `derive_addresses` returns SegWit addresses via `bech32.encode`. Blocking
`bech32` makes the function raise `ImportError` even when `mnemonic` is present.
**Repair applied:** added `bech32>=1.2.0` to `requirements.txt`.

### D3 — `pillow` missing from `requirements.txt` (degrades tool 6)
**Evidence:** live `POST /api/tools/image` returns 200, but the steganography block
reports `could not decode image for pixel analysis: ModuleNotFoundError: No module named
'PIL'`, and `lsb_analysis` comes back empty. The endpoint answers, so the tool is not
"verified" — its core LSB feature is dead.
**Repair applied:** added `pillow>=10.0` to `requirements.txt`.

### D4 — `v`/`r`/`s` bytes crash JSON encoding (blocks tool 9)
**Evidence:** live `POST /api/tools/decode-transaction` with a real 110-byte legacy ETH
transaction returns `500 internal_error` for `chain` = `auto`, `ethereum`, `eth` and
`evm`, while the Bitcoin branch returns 200 and a truncated payload correctly returns
400 — so the decode path runs and the failure is downstream.
**Root cause:** `decode_transaction` returns `v`/`r`/`s` as `bytes`. The working tree
contains a hex conversion at `app/webapp/server.py:472-475`; **git HEAD does not**. The
deployed build therefore passes raw bytes to `json.dumps`, which raises
`TypeError: Object of type bytes is not JSON serializable`, caught by the router's
`except Exception` and reported as 500.
**Reproduced:** monkeypatching the handler to omit the hex conversion returns exactly
`HTTP 500 {'error': 'internal_error'}` from the local server.
**Repair status:** the fix exists in the working tree but is **uncommitted and not
deployed**. Regression tests added (`test_eth_result_is_json_serializable`,
`test_eth_sender_is_recovered`, `test_eth_route_is_wired`).

### D5 — `crypto_calculator` WIF parsing is wrong (blocks tool 11)
**Evidence:** live `POST /api/tools/calculator` with `5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ`
returns `400 unrecognised WIF payload length 33`, and with
`KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn` returns
`400 unrecognised WIF payload length 34`.
**Root cause:** `app/crypto_tools.py` dispatched on the *raw* payload length instead of
the version-prefixed structure. `b58decode_check` yields `0x80 || key` (33 bytes,
uncompressed) or `0x80 || key || 0x01` (34 bytes, compressed). The old code read a
33-byte payload as "compressed" and kept the `0x80` version byte in the key — deriving a
*wrong* address from a valid key — and rejected a genuine 34-byte compressed key outright.
**Reproduced:** with the old code the uncompressed WIF raises `DecodeError`; the
corrected parse derives `p2pkh_compressed=1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH` and
`eth=0x7e5f4552091a69125d5dfcb7b8c2659029395bdf`, matching the scalar-1 hex key.
**Repair applied:** rewritten WIF dispatch strips `0x80` in both cases and distinguishes
compressed/uncompressed by the trailing `0x01`. Regression tests added.
**Not live** — requires a Render redeploy.

### D6 — calculator hex-key path returns 500
**Evidence:** live `POST /api/tools/calculator` with
`0000000000000000000000000000000000000000000000000000000000000001` returns
`500 internal_error`, although that same input succeeds locally.
**Status:** root cause not yet isolated — the local path works, so this is
environment-specific on Render. **Unrepaired.** Needs the Render server log for the
`POST failed` line (the router logs the exception detail at `app/webapp/server.py:1116`).

## Not defects (verified, with evidence)

- `analyze_file` — live 200 for `/etc/hostname`.
- `decode_data` — live 200, hex → UTF-8.
- `analyze_data` — live 200, pure-hex pattern.
- `simulate_sweep` — live 200, read-only step list, no broadcast.
- `crack_puzzle` — live 200, correct `match:false` for missing `puzzle_id`.
- `tools_parse_wallet_dat` — live 400 `file not found` for a bad path (validation works).
- `puzzles_classify`, `puzzles_plan`, `puzzles_attack` — live 400 `unknown slug` for a slug
  absent from the deployed corpus; all three succeed locally against the 49-entry corpus.
  The 400 is correct behaviour, not a defect — the deployed corpus is simply empty (D7).
- `crack_list` — live 200, well-formed empty listing.
- `web_sources` — live 200, well-formed empty result set.
- `auth_challenge` — live 200 with nonce + message.
- `auth_verify` — live 400 `'nonce' is required`; a full challenge→verify round trip
  needs a real signature and was not exercised.
- `wallet_assets` — live 200, real ETH balance and USD value. **Slow: 38–39 s.**
- `telegram_validate` — live 200 with the correct fail-closed
  `TELEGRAM_BOT_TOKEN not configured` response.
- `scan_secrets` — live 200, `clean:true`, with the no-storage notice.

## Related non-tool observations

- **D7 — deployed catalog is empty.** `/health` reports `catalog_items: 0`;
  `/api/catalog/items` and `/api/crack/list` return zero items; `/api/puzzles/classify`
  rejects every slug. Local `WalletService` loads 49 public entries from
  `~/ocp/puzzles.json`, which is not in the repository and is not present on Render.
  This is a data/config gap, not a code defect.
- **`app.js` localStorage keys are inconsistent.** The onboarding path reads
  `hermes_token` / `hermes_wallet_addr` / `hermes_main_wallet_session_token`, while the
  main-app path uses `hermes_session_token` / `hermes_wallet_address`. A session
  established by one path is not restored by the other. Not repaired (needs a product
  decision on the canonical key set).
- **`/api/wallet/assets` latency** of 38–39 s on Render is worth a follow-up but is a
  performance issue, not a correctness defect.

## Test Suite

Command: `python3 -m pytest tests/ -q -p no:cacheprovider`

| Stage | Result |
|-------|--------|
| Baseline (start of audit) | 775 passed, 0 failed, 0 skipped |
| After repairs | **783 passed, 0 failed, 0 skipped** |

The 8 new tests cover D4 and D5. The suite passes both before and after the repairs,
which is itself the finding: **the existing suite could not have caught these defects.**
It runs against the local Termux environment, where `mnemonic`, `bech32` and `pillow`
are installed, and its HTTP tests spin up a local server that shares that environment.

## Render Deployment Status

- **URL:** `https://hermes-bot-miniapp.onrender.com`
- **Main page:** HTTP 200, 33,316 bytes, `HermesMiniApp/1.0 Python/3.11.17`
- **`/health`:** HTTP 200, `ok:true`, `telegram_configured:false`,
  `memepol_configured:false`, `catalog_items:0`, `eth_rpc_configured:true`,
  `paypal_configured:false`
- **`/api/status`:** HTTP 200, all five subsystems `⏳` (expected — see the skill note:
  `app.cli status` is not a health check, and a fresh process seeds everything `PENDING`)
- **Reachability vs function:** the service is reachable and serving. Functionally,
  6 of 23 tools fail on a valid input.
- **Local fixes are NOT live.** `diff` of the deployed `/app.js` against the local file
  shows the local `walletSessionToken` changes are absent from the deployment, and the
  `v`/`r`/`s` hex fix is uncommitted, so the deployed Python is older than the working tree.

## Environment Variables (names only — no values)

Required by the app and listed in `DEPLOYMENT.md`: `TELEGRAM_BOT_TOKEN`,
`SESSION_SECRET`, `TELEGRAM_WEBAPP_URL`. Optional: `PAYPAL_CLIENT_ID`,
`PAYPAL_CLIENT_SECRET`, `PORT`, `NONCE_TTL_SECONDS`, `RATE_LIMIT_PER_MINUTE`.

Additional variables the code reads but `DEPLOYMENT.md` does not document:
`ETH_RPC_URL`, `BTC_API_BASE`, `HTTP_TIMEOUT`, `RATE_LIMIT_EXPENSIVE_PER_MINUTE`,
`LOG_DIR`, `OCP_DATASET_PATH`, `PRIVATE_DATASET_PATH`, `ENTITLEMENTS_PATH`,
`OWNER_ADDRESSES`, `MEMEPOL_API_KEY`, `MEMEPOL_AUTH_HEADER`, `MEMEPOL_AUTH_PREFIX`,
`MEMEPOL_BASE_URL`, `PUZZLE_SOURCE`, `BOT_DISPLAY_NAME`, `TUNNEL_MODE`, `TUNNEL_NAME`.

**Render env vars were inspected by name only. No secret value was printed, and no
credential or production setting was changed.**

## Next Actions

1. **Commit and redeploy.** The working tree holds the D4 hex fix, the D5 WIF fix and the
   three new `requirements.txt` entries; none of it is live. Commit, push, and trigger a
   Render redeploy.
2. **Verify D1–D6 after redeploy** by re-running the live probe with the same inputs.
3. **Diagnose D6** from the Render log: find the `POST failed` line for
   `/api/tools/calculator`, which carries the exception detail.
4. **Decide on D7** — whether the 49-entry puzzle corpus should ship to Render (add it to
   the repo and `OCP_DATASET_PATH`) or stay local.
5. **Add a dependency test to the suite** that parses `requirements.txt` and asserts
   every third-party import in `app/` resolves to a declared distribution. This is the
   regression that would have caught D1–D3.
6. **Make the HTTP tests deploy-aware**, or add a CI step that probes the live URL with
   real inputs, so "verified" stops meaning "passes locally".
