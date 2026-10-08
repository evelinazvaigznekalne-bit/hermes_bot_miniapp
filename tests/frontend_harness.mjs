/**
 * Frontend integration harness (Node, no browser required).
 *
 * Loads the REAL app/webapp/static/app.js into a minimal fake DOM, points its
 * fetch() at a REAL running backend, and stands in for a user's wallet by
 * shelling out to tools/sign_message.py for personal_sign.
 *
 * This verifies what a syntax check cannot:
 *   - app.js runs top to bottom without throwing
 *   - every endpoint it calls exists and returns the fields it reads
 *   - the connect -> challenge -> sign -> verify flow completes
 *   - the render paths actually write to the DOM
 *
 * Usage:  node tests/frontend_harness.mjs http://127.0.0.1:PORT
 * Exit 0 = pass, 1 = fail. Prints a JSON summary.
 */

import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const BASE = process.argv[2] || "http://127.0.0.1:8080";
const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const APP_JS = join(ROOT, "app/webapp/static/app.js");

const failures = [];
const notes = [];
const calls = [];

function check(name, cond, detail = "") {
  if (cond) {
    notes.push(`ok   ${name}`);
  } else {
    failures.push(`${name}${detail ? " :: " + detail : ""}`);
    notes.push(`FAIL ${name}${detail ? " :: " + detail : ""}`);
  }
}

// ---------------------------------------------------------------- fake DOM
function makeEl(id) {
  const el = {
    id,
    innerHTML: "",
    textContent: "",
    value: "",
    disabled: false,
    _listeners: {},
    _children: {},
    classList: {
      _s: new Set(),
      add(...c) { c.forEach((x) => this._s.add(x)); },
      remove(...c) { c.forEach((x) => this._s.delete(x)); },
      contains(c) { return this._s.has(c); },
    },
    addEventListener(type, fn) { (this._listeners[type] ||= []).push(fn); },
    appendChild(child) { this._children[`_appended${Object.keys(this._children).length}`] = child; return child; },
    removeChild(child) { return child; },
    remove() {},
    querySelector(sel) { return (this._children[sel] ||= makeEl(`${id}>${sel}`)); },
    click() {
      const fns = this._listeners.click || [];
      return Promise.all(fns.map((fn) => fn()));
    },
  };
  return el;
}

const els = {};
const document = {
  getElementById(id) { return (els[id] ||= makeEl(id)); },
  // app.js's clipboard fallback and toast() build elements dynamically.
  createElement(tag) {
    const node = makeEl(`created:${tag}`);
    node.tagName = String(tag).toUpperCase();
    node.style = {};
    node.remove = () => {};
    node.appendChild = () => {};
    return node;
  },
  body: makeEl("body"),
  head: makeEl("head"),
  querySelector(sel) {
    // Simple fake: return first element whose innerHTML contains the selector text
    const text = sel.replace(/[.#]/g, "");
    for (const el of Object.values(els)) {
      if (el.innerHTML && el.innerHTML.includes(text)) return el;
    }
    return null;
  },
  querySelectorAll(sel) {
    // Return elements matching a class selector like ".profile-nav-btn"
    const text = sel.replace(/^\./, "");
    return Object.values(els).filter((el) => {
      const m = el.innerHTML && el.innerHTML.match(new RegExp(`class="[^"]*${text}[^"]*"`));
      return !!m;
    });
  },
};
// Always go through the accessor so lazily-created elements exist.
const el = (id) => document.getElementById(id);
const window = { location: { search: "" }, Telegram: undefined };

// ------------------------------------------------------- signing via python
// Use the interpreter that actually has the project's dependencies. On Termux
// the bundled Hermes python3 shadows the system one and lacks eth_keys, so
// honour PYTHON if the caller set it (scripts/start.sh does the same).
const PYTHON = process.env.PYTHON || "/data/data/com.termux/files/usr/bin/python3";
function signWithTestKey(message) {
  const out = execFileSync(
    PYTHON,
    [join(ROOT, "tools/sign_message.py")],
    { input: message, encoding: "utf8" },
  );
  return JSON.parse(out);
}

const TEST = signWithTestKey("probe");
notes.push(`test wallet address: ${TEST.address}`);

window.ethereum = {
  async request({ method, params }) {
    if (method === "eth_requestAccounts") return [TEST.address];
    if (method === "personal_sign") {
      const [message] = params;
      calls.push({ kind: "personal_sign" });
      return signWithTestKey(message).signature;
    }
    throw new Error(`unexpected wallet method ${method}`);
  },
};

// ------------------------------------------------------------ fetch → real
const realFetch = globalThis.fetch;
async function fetchShim(path, opts) {
  const url = path.startsWith("http") ? path : BASE + path;
  const res = await realFetch(url, opts);
  let body = null;
  try { body = await res.clone().json(); } catch { /* non-JSON */ }
  calls.push({
    kind: "http",
    method: opts?.method || "GET",
    path,
    status: res.status,
    body: opts?.body ? JSON.parse(opts.body) : undefined,
  });
  return res;
}

// ------------------------------------------------------------- load app.js
const source = readFileSync(APP_JS, "utf8");
const runApp = new Function(
  "document", "window", "fetch", "setInterval", "URLSearchParams", "console",
  source,
);
// setInterval is stubbed: the 20s status poll would keep node alive.
runApp(document, window, fetchShim, () => 0, URLSearchParams, console);

// let the initial refreshStatus() settle
await new Promise((r) => setTimeout(r, 1200));

// ------------------------------------------------------------- assertions
check("app.js executed without throwing", true);

const statusTbody = el("status-table").querySelector("tbody").innerHTML || "";
check("initial refreshStatus rendered status table",
  statusTbody.includes("wallet_data"), statusTbody.slice(0, 80));
check("initial refreshStatus rendered capabilities",
  (el("capabilities").textContent || "").includes("read-only"),
  el("capabilities").textContent);
check("status table renders the ✓/✗/⏳ vocabulary",
  /✓|✗|⏳/.test(statusTbody), statusTbody.slice(0, 60));

// ---- connect + sign flow
el("address-input").value = TEST.address;
try {
  await el("connect-btn")._listeners.click[0]();
} catch (err) {
  failures.push(`connectAndSign threw: ${err.message}`);
}

const authStatus = el("auth-status").innerHTML || "";
check("auth status shows verified ✓", authStatus.includes("✓"),
  authStatus.replace(/<[^>]+>/g, ""));
check("challenge message was displayed",
  (el("challenge-box").textContent || "").includes("authentication"),
  (el("challenge-box").textContent || "").slice(0, 60));
check("assets card revealed", !el("assets-card").classList.contains("hidden"));

// ---- asset render
const assetsTbody = el("assets-table").querySelector("tbody").innerHTML || "";
const assetsStatus = el("assets-status").innerHTML || "";
check("assets status rendered", /✓|✗|⏳/.test(assetsStatus),
  assetsStatus.replace(/<[^>]+>/g, ""));
check("asset rows written to the table",
  assetsTbody.includes("<tr>"), assetsTbody.slice(0, 80));

// ---- endpoint contract
const httpCalls = calls.filter((c) => c.kind === "http");
const paths = httpCalls.map((c) => `${c.method} ${c.path}`);
const expected = [
  "GET /health",
  "GET /api/status",
  "POST /api/auth/challenge",
  "POST /api/auth/verify",
  "POST /api/wallet/assets",
];
for (const want of expected) {
  check(`frontend called ${want}`, paths.includes(want), paths.join(", "));
}
check("every frontend request returned 2xx",
  httpCalls.every((c) => c.status >= 200 && c.status < 300),
  httpCalls.map((c) => `${c.path}=${c.status}`).join(" "));
check("personal_sign was invoked", calls.some((c) => c.kind === "personal_sign"));

// challenge payload carries the address the user typed
const chal = httpCalls.find((c) => c.path === "/api/auth/challenge");
check("challenge payload contains the address",
  chal?.body?.address === TEST.address, JSON.stringify(chal?.body));

// verify payload carries address + signature + nonce
const ver = httpCalls.find((c) => c.path === "/api/auth/verify");
check("verify payload has address/signature/nonce",
  !!(ver?.body?.address && ver?.body?.signature && ver?.body?.nonce),
  JSON.stringify(Object.keys(ver?.body || {})));

// assets payload carries the session token (proving verification chained)
const ast = httpCalls.find((c) => c.path === "/api/wallet/assets");
check("assets request sent the session token",
  typeof ast?.body?.session_token === "string" && ast.body.session_token.length > 10,
  JSON.stringify(Object.keys(ast?.body || {})));

// ---- no secrets in what the frontend received
check("no token/private key in DOM",
  !/AAH|apisio_live|private_key/i.test(
    statusTbody + assetsTbody + authStatus + assetsStatus),
  "secret-looking string found in DOM");

// ---- PayPal purchase flow
// After connect, the paypal card should be visible
check("paypal card visible after connect",
  !el("paypal-card").classList.contains("hidden"));

// loadPaypalConfig() is async and not awaited in connectAndSign(),
// so poll until the plans render (or the not-configured message appears).
async function waitForPlans(timeoutMs = 5000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const html = el("paypal-plans").innerHTML || "";
    if (html.includes("plan-card") || html.includes("not configured")) return html;
    await new Promise((r) => setTimeout(r, 100));
  }
  return el("paypal-plans").innerHTML || "";
}

const plansHtml = await waitForPlans();
const paypalConfigured = plansHtml.includes("plan-card");
const paypalNotConfigured = plansHtml.includes("not configured");
check("paypal plans rendered or not-configured message shown",
  paypalConfigured || paypalNotConfigured,
  plansHtml.slice(0, 120));
if (paypalConfigured) {
  check("paypal plans show prices", /\d+\.\d{2}/.test(plansHtml),
    plansHtml.slice(0, 80));
  // Buttons may be Smart Button wrappers or fallback buy-btns
  const buttonsHtml = el("paypal-buttons").innerHTML || "";
  const hasSmartButtons = buttonsHtml.includes("paypal-btn-wrapper");
  const hasFallbackButtons = buttonsHtml.includes("buy-btn");
  check("paypal buttons rendered (smart or fallback)",
    hasSmartButtons || hasFallbackButtons,
    buttonsHtml.slice(0, 120));
  check("sku present in HTML",
    buttonsHtml.includes("data-sku=") || plansHtml.includes("data-sku="),
    buttonsHtml.slice(0, 80));
}
check("paypal status element exists",
  el("paypal-status").innerHTML !== undefined);

console.log(JSON.stringify({
  pass: failures.length === 0,
  base: BASE,
  checks: notes.length,
  failures,
  requests: paths,
}, null, 2));

process.exit(failures.length === 0 ? 0 : 1);
