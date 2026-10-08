# Puzzle endpoint contract

How to point the app at a real remote puzzle service instead of the local
`open-crypto-puzzles` corpus.

---

## 1. Switch the source

`PUZZLE_SOURCE` decides where puzzle data comes from:

| Value | Behaviour |
|-------|-----------|
| `auto` (default) | local `~/ocp/puzzles.json` if present, else the HTTP endpoint |
| `ocp` | local corpus only; `error` verdict if absent |
| `memepol` | HTTP endpoint only — use this for a real remote service |

Set these in `~/hermes_bot_miniapp/.env`:

```bash
MEMEPOL_BASE_URL=https://your-host.example/v1
MEMEPOL_API_KEY=your-real-key
MEMEPOL_AUTH_HEADER=Authorization
MEMEPOL_AUTH_PREFIX=Bearer
PUZZLE_SOURCE=memepol
```

Then verify — the key is never printed:

```bash
cd ~/hermes_bot_miniapp
python3 -c "
from app.config import load_dotenv, get_settings
from app.puzzles.memepol import MemePolClient
import json; load_dotenv()
print(json.dumps(MemePolClient(get_settings()).ping(), indent=2))
"
```

`ping()` returns `{"ok": true, ...}` when the endpoint is reachable and the key
is accepted, or `{"ok": false, "detail": "..."}` otherwise. It never raises.

---

## 2. Auth header variants

Providers disagree on how a key travels, so both parts are configurable:

| Provider style | Header | Prefix | Resulting header |
|---|---|---|---|
| Generic REST | `Authorization` | `Bearer` | `Authorization: Bearer <key>` |
| Bare API key | `X-API-Key` | *(empty)* | `X-API-Key: <key>` |
| Custom scheme | `Authorization` | `Token` | `Authorization: Token <key>` |

The key is **always** sent in a header, never a query string, so it cannot leak
through proxy logs or error messages.

---

## 3. Required endpoints

### `GET {base_url}/puzzles`

Returns the dataset. Either shape is accepted:

```json
{ "puzzles": [ { ... }, { ... } ] }
```

```json
[ { ... }, { ... } ]
```

A `?limit=` parameter is sent; ignore it if you do not paginate.

### `GET {base_url}/puzzles/{id}` *(optional)*

Returns a single puzzle object. Only used by `MemePolClient.get_puzzle()`.

---

## 4. Record schema

```json
{
  "id": "unique-puzzle-id",
  "title": "Human readable title",
  "chain": "ethereum",
  "criteria": {
    "address": "0x...",
    "chain": "ethereum",
    "min_balance": 0.5,
    "symbol": "ETH"
  },
  "hints": ["first hint", "second hint"],
  "images": ["https://.../clue.png"],
  "note": "status=open"
}
```

Every field except `id` is optional. A **flat** shape also works — these are
equivalent:

```json
{ "id": "p1", "address": "0x...", "min_balance": 0.5, "symbol": "ETH" }
```

Recognised `criteria` keys:

| Key | Meaning | Weight |
|---|---|---|
| `address` | The escrow address | **Required** for any match |
| `chain` | Chain id (`ethereum`, `bitcoin`, …) | Filter only — a mismatch excludes the record |
| `min_balance` | Escrow expected balance, lower bound | Refines a match once the address is confirmed |
| `balance` | Escrow expected balance, exact | Same |
| `symbol` / `asset` | Asset symbol | Weak signal, refines only |

### Semantics you must understand

`min_balance` and `balance` describe **the escrow's** expected balance — not a
filter on the visiting wallet. The analyzer therefore requires
`criteria.address` to be confirmed before it will report any match. A record
with only a balance threshold can never match anything.

---

## 5. Response codes

| Code | Client behaviour |
|---|---|
| `200` | Parsed |
| `401` / `403` | `HttpError` → `error` verdict (auth problem) |
| `404` | `HttpError` → `error` verdict (wrong path) |
| `429` | Retried with `Retry-After` honoured, then `error` |
| `5xx` | Retried with exponential backoff, then `error` |

All failures surface as the `error` verdict with a reason string. The analyzer
never reports a match when the dataset could not be read.

---

## 6. Test locally before pointing at anything real

A reference implementation ships with the repo:

```bash
cd ~/hermes_bot_miniapp
python3 tools/mock_puzzle_server.py --port 9099 --token demo-secret-123
```

In another shell:

```bash
MEMEPOL_BASE_URL=http://127.0.0.1:9099 \
MEMEPOL_API_KEY=demo-secret-123 \
MEMEPOL_AUTH_HEADER=Authorization \
MEMEPOL_AUTH_PREFIX=Bearer \
PUZZLE_SOURCE=memepol \
python3 -m app.cli inspect 0xDe0DAFC80d487b8aE652bBF906ac6c6007aE3A5e --puzzles
```

Expected: `exact_match`, `source=memepol`, with the demo hints and image.

Run the integration suite (real sockets, no HTTP mocking):

```bash
python3 -m pytest tests/test_http_source.py -v
```
