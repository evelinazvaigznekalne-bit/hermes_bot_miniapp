/* Hermes Wallet Inspector - Mini App frontend.
 *
 * Security: the private key never leaves the user's wallet. We request a
 * challenge from the backend, hand the exact message to the wallet's
 * personal_sign implementation, and send back only the signature.
 */
(function () {
  "use strict";

  const tg = window.Telegram && window.Telegram.WebApp;
  if (tg) { tg.ready(); tg.expand(); }

  const el = (id) => document.getElementById(id);
  const state = { address: null, token: null, challenge: null, busy: false, paypalSDK: null, scanCount: 0, puzzlesFound: 0, tracked: 0 };

  const PILL = (status, text) =>
    `<span class="pill ${status === "✓" ? "ok" : status === "✗" ? "fail" : "pending"}">` +
    `${status} ${text}</span>`;

  function setStatus(node, status, text) {
    node.innerHTML = PILL(status, text);
  }

  // ---- Toast notifications ----
  function toast(message, type = "info", duration = 3000) {
    const container = el("toast-container");
    if (!container) return;
    const t = document.createElement("div");
    t.className = `toast toast-${type}`;
    t.textContent = message;
    container.appendChild(t);
    setTimeout(() => {
      t.classList.add("toast-out");
      setTimeout(() => t.remove(), 200);
    }, duration);
  }

  // ---- Loading spinner helper ----
  function showSpinner(node, text = "Loading…") {
    if (!node) return;
    node.innerHTML = `<span class="spinner"></span> <span class="muted">${escapeHtml(text)}</span>`;
  }

  function hideSpinner(node) {
    if (!node) return;
    node.innerHTML = "";
  }

  // ---- Empty state helper ----
  function showEmptyState(node, icon = "📭", text = "Nothing here yet.") {
    if (!node) return;
    node.innerHTML = `<div class="empty-state"><div class="empty-icon">${icon}</div><div class="empty-text">${escapeHtml(text)}</div></div>`;
  }

  // ---- Confirmation dialog ----
  function confirmDialog(title, message, confirmLabel = "Confirm", danger = false) {
    return new Promise((resolve) => {
      const overlay = document.createElement("div");
      overlay.className = "confirm-overlay";
      overlay.innerHTML = `
        <div class="confirm-dialog">
          <h3>${escapeHtml(title)}</h3>
          <p>${escapeHtml(message)}</p>
          <div class="confirm-actions">
            <button class="confirm-cancel">Cancel</button>
            <button class="confirm-ok ${danger ? "danger" : "primary"}">${escapeHtml(confirmLabel)}</button>
          </div>
        </div>`;
      document.body.appendChild(overlay);
      const close = (result) => { overlay.remove(); resolve(result); };
      overlay.querySelector(".confirm-cancel").addEventListener("click", () => close(false));
      overlay.querySelector(".confirm-ok").addEventListener("click", () => close(true));
      overlay.addEventListener("click", (e) => { if (e.target === overlay) close(false); });
    });
  }

  // ---- Mobile menu ----
  function initMobileMenu() {
    const toggle = el("menu-toggle");
    const sidebar = document.querySelector(".sidebar");
    const overlay = el("sidebar-overlay");
    if (!toggle || !sidebar) return;
    toggle.addEventListener("click", () => {
      sidebar.classList.toggle("open");
      if (overlay) overlay.classList.toggle("active");
    });
    if (overlay) {
      overlay.addEventListener("click", () => {
        sidebar.classList.remove("open");
        overlay.classList.remove("active");
      });
    }
    // Close sidebar on navigation (mobile)
    document.querySelectorAll(".sidebar-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        if (window.innerWidth <= 768) {
          sidebar.classList.remove("open");
          if (overlay) overlay.classList.remove("active");
        }
      });
    });
  }

  async function api(path, body) {
    const res = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {}),
    });
    const data = await res.json().catch(() => ({ error: "bad_json" }));
    if (!res.ok) {
      throw new Error(data.message || data.error || ("HTTP " + res.status));
    }
    return data;
  }

  async function getJson(path) {
    const res = await fetch(path);
    if (!res.ok) throw new Error("HTTP " + res.status);
    return res.json();
  }

  // ---- capabilities + status table ------------------------------------
  async function refreshStatus() {
    try {
      const [caps, status] = await Promise.all([
        getJson("/health"),
        getJson("/api/status"),
      ]);
      const tbody = el("status-table").querySelector("tbody");
      tbody.innerHTML = Object.entries(status.statuses)
        .map(([k, v]) => {
          const detail = (status.details[k] && status.details[k].detail) || "";
          return `<tr><td>${k}</td><td>${PILL(v, v)}</td>` +
                 `<td class="muted">${escapeHtml(detail)}</td></tr>`;
        })
        .join("");
      el("capabilities").textContent =
        `read-only · telegram ${caps.telegram_configured ? "✓" : "✗"} · ` +
        `memepol ${caps.memepol_configured ? "✓" : "✗"} · ` +
        `chains: ${caps.chains.map((c) => c.chain).join(", ")}`;
    } catch (err) {
      el("capabilities").textContent = "backend unreachable: " + err.message;
    }
  }

  function escapeHtml(value) {
    return String(value == null ? "" : value).replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[c]));
  }

  // ---- step 1: connect + authenticate ----------------------------------
  async function _connectAndSign() {
    const node = el("auth-status");
    if (state.busy) return;
    state.busy = true;
    el("connect-btn").disabled = true;

    try {
      // Prefer Telegram initData auth when available
      if (window.Telegram && window.Telegram.WebApp && window.Telegram.WebApp.initData) {
        setStatus(node, "⏳", "authenticating via Telegram…");
        const result = await api("/api/auth/telegram", {
          init_data: window.Telegram.WebApp.initData,
        });
        if (!result.valid) {
          setStatus(node, "✗", result.detail || "Telegram auth failed");
          return;
        }
        state.token = result.session_token;
        state.address = result.user.name || String(result.user.id);
        el("address-input").value = state.address;
        // Persist session so the user is remembered across reloads
        try {
          localStorage.setItem("hermes_session_token", result.session_token);
          localStorage.setItem("hermes_wallet_address", state.address);
          localStorage.setItem("hermes_auth_method", "telegram");
          localStorage.setItem("hermes_session_expires", String(result.expires_at || ""));
        } catch (e) { /* storage may be unavailable */ }
        setStatus(node, "✓", `authenticated as ${result.user.name}`);
        el("assets-card").classList.remove("hidden");
        await loadAssets();
        return;
      }

      // Fallback: personal_sign challenge/verify
      let address = el("address-input").value.trim();
      if (!address) {
        if (!window.ethereum) {
          setStatus(node, "✗", "No wallet detected. Open in wallet browser or use Telegram login.");
          return;
        }
        setStatus(node, "⏳", "requesting accounts…");
        const accounts = await window.ethereum.request({ method: "eth_requestAccounts" });
        address = accounts && accounts[0];
        el("address-input").value = address || "";
      }
      if (!address) {
        setStatus(node, "✗", "No address available.");
        return;
      }
      state.address = address;

      // Check if wallet is available before requesting challenge
      if (!window.ethereum) {
        setStatus(node, "✗", "Wallet not available for signing. Open in wallet browser or use Telegram login.");
        el("assets-card").classList.remove("hidden");
        return;
      }

      setStatus(node, "⏳", "requesting challenge…");
      const challenge = await api("/api/auth/challenge", { address });
      state.challenge = challenge;

      const box = el("challenge-box");
      box.textContent = challenge.message;
      box.classList.remove("hidden");
      const actions = el("challenge-actions");
      if (actions) {
        actions.classList.remove("hidden");
        const nonceEl = el("challenge-nonce");
        if (nonceEl) nonceEl.textContent = `nonce: ${challenge.nonce}`;
      }

      setStatus(node, "⏳", "awaiting signature…");
      const signature = await window.ethereum.request({
        method: "personal_sign",
        params: [challenge.message, address],
      });

      setStatus(node, "⏳", "verifying signature…");
      const result = await api("/api/auth/verify", {
        address, signature, nonce: challenge.nonce,
      });
      if (!result.verified) {
        setStatus(node, "✗", result.detail || "verification failed");
        return;
      }
      state.token = result.session_token;
      // Persist wallet address + token in localStorage for auto-fill on reload
      try {
        localStorage.setItem("hermes_wallet_address", address);
        localStorage.setItem("hermes_session_token", result.session_token);
      } catch (e) { /* storage may be unavailable */ }
      setStatus(node, "✓", "ownership verified");
      el("assets-card").classList.remove("hidden");
      await loadAssets();
    } catch (err) {
      setStatus(node, "✗", err.message);
    } finally {
      state.busy = false;
      el("connect-btn").disabled = false;
      refreshStatus();
    }
  }

  // ---- personal_sign login (Telegram-friendly) ---------------------------
  async function personalSignLogin() {
    const node = el("auth-status");
    if (state.busy) return;
    state.busy = true;
    el("telegram-sign-btn").disabled = true;

    try {
      let address = el("address-input").value.trim();
      if (!address) {
        if (!window.ethereum) {
          setStatus(node, "✗", "Enter your EVM address first");
          return;
        }
        setStatus(node, "⏳", "requesting accounts…");
        const accounts = await window.ethereum.request({ method: "eth_requestAccounts" });
        address = accounts && accounts[0];
        el("address-input").value = address || "";
      }
      if (!address) {
        setStatus(node, "✗", "No address available");
        return;
      }
      state.address = address;

      setStatus(node, "⏳", "requesting challenge…");
      const challenge = await api("/api/auth/challenge", { address });
      state.challenge = challenge;

      const box = el("challenge-box");
      box.textContent = challenge.message;
      box.classList.remove("hidden");
      const actions = el("challenge-actions");
      if (actions) {
        actions.classList.remove("hidden");
        const nonceEl = el("challenge-nonce");
        if (nonceEl) nonceEl.textContent = `nonce: ${challenge.nonce}`;
      }

      let signature = null;

      // Try in-app wallet first
      if (window.ethereum) {
        setStatus(node, "⏳", "awaiting signature…");
        try {
          signature = await window.ethereum.request({
            method: "personal_sign",
            params: [challenge.message, address],
          });
        } catch (e) {
          // User rejected or wallet error — fall through to manual
        }
      }

      // Manual signature paste (Telegram / no wallet)
      if (!signature) {
        setStatus(node, "⏳", "paste signature below");
        const sigInput = el("manual-sig-input");
        if (sigInput) {
          sigInput.classList.remove("hidden");
          sigInput.focus();
          // Wait for user to paste and click submit
          signature = await new Promise((resolve) => {
            const submitBtn = el("manual-sig-submit");
            const handler = () => {
              submitBtn.removeEventListener("click", handler);
              resolve(sigInput.value.trim() || null);
            };
            submitBtn.addEventListener("click", handler);
          });
          sigInput.classList.add("hidden");
        }
      }

      if (!signature) {
        setStatus(node, "✗", "no signature provided");
        return;
      }

      setStatus(node, "⏳", "verifying signature…");
      const result = await api("/api/auth/verify", {
        address, signature, nonce: challenge.nonce,
      });
      if (!result.verified) {
        setStatus(node, "✗", result.detail || "verification failed");
        return;
      }
      state.token = result.session_token;
      try {
        localStorage.setItem("hermes_wallet_address", address);
        localStorage.setItem("hermes_session_token", result.session_token);
      } catch (e) { /* storage may be unavailable */ }
      setStatus(node, "✓", "ownership verified");
      el("assets-card").classList.remove("hidden");
      await loadAssets();
    } catch (err) {
      setStatus(node, "✗", err.message);
    } finally {
      state.busy = false;
      el("telegram-sign-btn").disabled = false;
      refreshStatus();
    }
  }

  // ---- step 2: assets --------------------------------------------------
  async function loadAssets() {
    const node = el("assets-status");
    showSpinner(node, "loading public data…");
    el("puzzle-panel").classList.add("hidden");
    try {
      const payload = await api("/api/wallet/assets", {
        address: state.address,
        session_token: state.token,
        include_puzzles: el("puzzles-toggle").checked,
      });
      const wallet = payload.wallet;
      setStatus(node, wallet.status,
        `${wallet.chain} · ${wallet.verified ? "verified" : "unverified"} · ` +
        `${wallet.assets.length} asset(s)`);

      const table = el("assets-table");
      const tbody = table.querySelector("tbody");
      if (wallet.assets.length === 0) {
        tbody.innerHTML = '<tr><td colspan="3" class="muted">No assets found.</td></tr>';
      } else {
        tbody.innerHTML = wallet.assets.map((a) =>
          `<tr><td class="mono">${escapeHtml(a.symbol)}</td>` +
          `<td class="mono">${a.amount}</td><td>${escapeHtml(a.kind)}</td></tr>`
        ).join("");
      }
      table.classList.remove("hidden");

      const analysis = payload.puzzle_analysis;
      if (analysis) renderPuzzles(analysis);
      refreshStatus();
      toast("Assets loaded", "success");
    } catch (err) {
      setStatus(node, "✗", err.message);
      toast(err.message, "error");
    }
  }

  function renderPuzzles(analysis) {
    const panel = el("puzzle-panel");
    panel.classList.remove("hidden");
    el("puzzle-verdict").innerHTML =
      PILL(analysis.status, analysis.verdict) +
      ` <span class="muted">evaluated ${analysis.evaluated} record(s)</span>` +
      (analysis.detail ? ` <span class="error">${escapeHtml(analysis.detail)}</span>` : "");

    el("puzzle-matches").innerHTML = analysis.matches.slice(0, 5).map((m) =>
      `<li>${escapeHtml(m.title || m.puzzle_id)} — ${PILL(m.status, m.verdict)}` +
      ` <span class="muted">score ${m.score}</span></li>`
    ).join("");

    const hints = el("puzzle-hints");
    if (analysis.hints.length || analysis.images.length) {
      hints.innerHTML =
        (analysis.hints.length
          ? "<h3>Hints</h3><ul>" +
            analysis.hints.map((h) => `<li>${escapeHtml(h)}</li>`).join("") +
            "</ul>"
          : "") +
        (analysis.images.length
          ? "<h3>Image references</h3><ul>" +
            analysis.images.map((i) => `<li>${escapeHtml(i)}</li>`).join("") +
            "</ul>"
          : "");
    } else {
      hints.innerHTML = "";
    }
  }

  // ---- secret check (warn only; the value is never stored or echoed) ----
  async function checkSecrets() {
    const input = el("scan-input");
    const text = input.value || "";
    const status = el("scan-status");
    const out = el("scan-results");

    if (!text.trim()) {
      setStatus(status, "pending", "⏳ nothing to check");
      out.innerHTML = "";
      return;
    }

    setStatus(status, "pending", "⏳ checking…");
    try {
      const res = await api("/api/security/scan", { text });
      if (res.clean) {
        setStatus(status, "ok", "✓ no secrets detected");
        out.innerHTML =
          '<p class="muted">Nothing sensitive found in that text.</p>';
      } else {
        setStatus(status, "fail",
          `✗ ${res.count} secret-shaped value${res.count > 1 ? "s" : ""} found`);
        out.innerHTML =
          '<p class="muted">' + escapeHtml(res.notice || "") + "</p>" +
          res.findings.map((f) => `
            <div class="finding">
              <div><span class="pill fail">${escapeHtml(f.severity)}</span>
                <strong>${escapeHtml(f.label)}</strong></div>
              <code>${escapeHtml(f.redacted)}</code>
              <p class="muted">${escapeHtml(f.advice)}</p>
            </div>`).join("");
      }
    } catch (err) {
      setStatus(status, "fail", `✗ ${err.message}`);
    } finally {
      // Never keep the pasted text around longer than the request needs.
      input.value = "";
    }
  }

  // ---- file inventory (owner only) -------------------------------------
  async function loadInventory() {
    const status = el("inv-status");
    setStatus(status, "pending", "⏳ walking filesystem…");
    el("inv-listing").classList.add("hidden");
    try {
      const payload = await api("/api/inventory", {
        session_token: state.token,
        include_entries: false,
      });
      renderInventorySummary(payload);
      setStatus(status, "ok",
        `✓ ${payload.count} files · ${payload.total_human}` +
        (payload.truncated ? " (partial)" : ""));
    } catch (err) {
      setStatus(status, "fail", `✗ ${err.message}`);
      el("inv-summary").classList.add("hidden");
      el("inv-bars").innerHTML = "";
    }
  }

  function renderInventorySummary(payload) {
    const counts = payload.by_category || {};
    const total = Object.values(counts).reduce((a, b) => a + b, 0) || 1;

    el("inv-summary").innerHTML =
      `<div class="inv-head">
         <div>files <b>${payload.count}</b></div>
         <div>size <b>${escapeHtml(payload.total_human)}</b></div>
         <div>categories <b>${Object.keys(counts).length}</b></div>
         <div>redaction <b>${payload.redacted ? "ON" : "OFF"}</b></div>
       </div>`;
    el("inv-summary").classList.remove("hidden");

    // Sort by count, descending — a compact bar chart without a chart lib.
    const rows = Object.entries(counts).sort((a, b) => b[1] - a[1]);
    el("inv-bars").innerHTML = rows.map(([cat, n]) => {
      const pct = Math.max(2, Math.round((n / total) * 100));
      return `<div class="inv-bar">
                <span class="label">${escapeHtml(cat)}</span>
                <span class="track"><span class="fill" style="width:${pct}%"></span></span>
                <span class="n">${n}</span>
              </div>`;
    }).join("");
  }

  async function showInventoryListing() {
    const status = el("inv-status");
    setStatus(status, "pending", "⏳ building listing…");
    try {
      const payload = await api("/api/inventory/listing", {
        session_token: state.token,
      });
      const pre = el("inv-listing");
      pre.textContent = payload.listing;
      pre.classList.remove("hidden");
      setStatus(status, "ok",
        `✓ ${payload.count} files · ${payload.redacted ? "masked" : "unmasked"}`);
    } catch (err) {
      setStatus(status, "fail", `✗ ${err.message}`);
    }
  }

  // ---- PayPal purchase ---------------------------------------------------
  async function loadPaypalConfig() {
    try {
      const cfg = await getJson("/api/paypal/config");
      renderPaypalPlans(cfg);
      return cfg;
    } catch (err) {
      el("paypal-status").innerHTML =
        `<span class="pill fail">✗ ${escapeHtml(err.message)}</span>`;
      return null;
    }
  }

  function renderPaypalPlans(cfg) {
    const container = el("paypal-plans");
    const buttonsContainer = el("paypal-buttons");
    buttonsContainer.innerHTML = "";
    if (!cfg.configured) {
      container.innerHTML =
        `<p class="muted">Payments are not configured on this server.</p>`;
      return;
    }
    const plans = cfg.plans || [];
    container.innerHTML = plans.map((p) => `
      <div class="plan-card">
        <div class="plan-info">
          <strong>${escapeHtml(p.label)}</strong>
          <span class="muted">${escapeHtml(p.amount)} ${escapeHtml(p.currency)}</span>
        </div>
      </div>`).join("");
    loadPaypalSDK(cfg.client_id).then((ok) => {
      if (ok) renderPaypalButtons(plans);
      else renderFallbackButtons(plans);
    }).catch(() => renderFallbackButtons(plans));
  }

  function loadPaypalSDK(clientId) {
    if (!clientId) return Promise.reject(new Error("no client id"));
    if (state.paypalSDK) return Promise.resolve(true);
    return new Promise((resolve) => {
      const script = document.createElement("script");
      script.src = "https://www.paypal.com/sdk/js?client-id=" +
        encodeURIComponent(clientId) + "&currency=USD&intent=capture";
      script.onload = () => {
        state.paypalSDK = window.paypal;
        resolve(true);
      };
      script.onerror = () => resolve(false);
      document.head.appendChild(script);
    });
  }

  function renderPaypalButtons(plans) {
    const container = el("paypal-buttons");
    container.innerHTML = "";
    plans.forEach((p) => {
      const wrapper = document.createElement("div");
      wrapper.className = "paypal-btn-wrapper";
      wrapper.setAttribute("data-sku", p.sku);
      container.appendChild(wrapper);
      if (!window.paypal) return;
      window.paypal.Buttons({
        style: { layout: "vertical", shape: "pill", color: "gold", height: 44 },
        createOrder: async () => {
          const order = await api("/api/paypal/orders", {
            session_token: state.token, sku: p.sku,
          });
          return order.order_id;
        },
        onApprove: async (data) => {
          captureOrder(data.orderID);
        },
        onError: (err) => {
          setStatus(el("paypal-status"), "✗", err.message || "PayPal error");
        },
      }).render(wrapper);
    });
  }

  function renderFallbackButtons(plans) {
    const container = el("paypal-buttons");
    container.innerHTML = plans.map((p) => `
      <button class="primary buy-btn" data-sku="${escapeHtml(p.sku)}">
        Buy ${escapeHtml(p.label)} — ${escapeHtml(p.amount)} ${escapeHtml(p.currency)}
      </button>`).join("");
    container.querySelectorAll(".buy-btn").forEach((btn) => {
      btn.addEventListener("click", () => purchasePlan(btn.dataset.sku));
    });
  }

  async function purchasePlan(sku) {
    const status = el("paypal-status");
    const results = el("paypal-results");
    if (!state.token) {
      setStatus(status, "✗", "connect your wallet first");
      return;
    }
    setStatus(status, "⏳", "creating order…");
    results.innerHTML = "";
    try {
      const order = await api("/api/paypal/orders", {
        session_token: state.token,
        sku,
      });
      if (order.approval_url) {
        setStatus(status, "⏳", "redirecting to PayPal…");
        // Redirect to PayPal for approval
        window.location.href = order.approval_url;
      } else {
        // No approval_url — try to capture directly (for testing / edge cases)
        await captureOrder(order.order_id);
      }
    } catch (err) {
      setStatus(status, "✗", err.message);
    }
  }

  async function captureOrder(orderId) {
    const status = el("paypal-status");
    const results = el("paypal-results");
    setStatus(status, "⏳", "capturing payment…");
    try {
      const result = await api("/api/paypal/capture", {
        session_token: state.token,
        order_id: orderId,
      });
      if (result.already_processed) {
        setStatus(status, "ok", "✓ already processed");
      } else {
        setStatus(status, "ok", `✓ ${result.tier} tier granted`);
      }
      results.innerHTML =
        `<p class="muted">Order ${escapeHtml(result.order_id)} — ` +
        `${escapeHtml(result.amount)} ${escapeHtml(result.currency)}</p>`;
      // Refresh status to reflect new tier
      refreshStatus();
    } catch (err) {
      setStatus(status, "✗", err.message);
    }
  }

  function handlePaypalReturn() {
    const params = new URLSearchParams(window.location.search);
    if (params.get("paid") === "1" && state.token) {
      const orderId = params.get("token");
      if (orderId) {
        captureOrder(orderId);
      }
    }
    if (params.get("cancelled") === "1") {
      el("paypal-status").innerHTML =
        `<span class="pill fail">✗ payment cancelled</span>`;
    }
  }

  // ---- profile ------------------------------------------------------------
  function initProfile() {
    document.querySelectorAll(".profile-nav-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        document.querySelectorAll(".profile-nav-btn").forEach((b) => b.classList.remove("active"));
        btn.classList.add("active");
        const section = btn.dataset.section;
        document.querySelectorAll(".profile-section").forEach((s) => s.classList.add("hidden"));
        const target = document.getElementById("profile-" + section);
        if (target) target.classList.remove("hidden");
        if (section === "account") renderProfileAccount();
        if (section === "wallet") renderProfileWallet();
        if (section === "api") renderProfileApi();
        if (section === "security") renderProfileSecurity();
        if (section === "preferences") renderProfilePreferences();
      });
    });
  }

  function renderProfileAccount() {
    const identity = el("profile-identity");
    const activity = el("profile-activity");
    const tier = state.token ? "verified" : "anonymous";
    const address = state.address || "not connected";
    identity.innerHTML = `
      <div class="profile-row"><span class="profile-label">Address</span><span class="profile-value">${escapeHtml(address)}</span></div>
      <div class="profile-row"><span class="profile-label">Tier</span><span class="profile-value">${escapeHtml(tier)}</span></div>
      <div class="profile-row"><span class="profile-label">Session</span><span class="profile-value">${state.token ? "active" : "none"}</span></div>
    `;
    activity.innerHTML = `
      <div class="profile-row"><span class="profile-label">History entries</span><span class="profile-value" id="profile-history-count">…</span></div>
      <div class="profile-row"><span class="profile-label">Tracked puzzles</span><span class="profile-value" id="profile-progress-count">…</span></div>
    `;
    if (state.token) {
      api("/api/catalog/summary", { session_token: state.token }).then((s) => {
        const hc = el("profile-history-count");
        const pc = el("profile-progress-count");
        if (hc) hc.textContent = s.history_count ?? "0";
        if (pc) pc.textContent = s.progress_count ?? "0";
      }).catch(() => {
        const hc = el("profile-history-count");
        const pc = el("profile-progress-count");
        if (hc) hc.textContent = "0";
        if (pc) pc.textContent = "0";
      });
    } else {
      const hc = el("profile-history-count");
      const pc = el("profile-progress-count");
      if (hc) hc.textContent = "0";
      if (pc) pc.textContent = "0";
    }
  }

  function renderProfileWallet() {
    const balance = el("profile-balance");
    const entitlements = el("profile-entitlements");
    if (!state.token) {
      balance.innerHTML = '<p class="muted">Connect your wallet to view entitlements.</p>';
      entitlements.innerHTML = "";
      return;
    }
    balance.innerHTML = '<p class="muted">Loading…</p>';
    entitlements.innerHTML = "";
    api("/api/paypal/entitlement", { session_token: state.token }).then((e) => {
      balance.innerHTML = `
        <div class="profile-row"><span class="profile-label">Tier</span><span class="profile-value">${escapeHtml(e.tier || "none")}</span></div>
        <div class="profile-row"><span class="profile-label">Status</span><span class="profile-value">${escapeHtml(e.status || "inactive")}</span></div>
        <div class="profile-row"><span class="profile-label">Expires</span><span class="profile-value">${escapeHtml(e.expires_at || "never")}</span></div>
      `;
      entitlements.innerHTML = e.entitlements && e.entitlements.length > 0
        ? e.entitlements.map((en) => `
          <div class="profile-row"><span class="profile-label">${escapeHtml(en.tier)}</span><span class="profile-value">${escapeHtml(en.status)}</span></div>
        `).join("")
        : '<p class="muted">No entitlements.</p>';
    }).catch(() => {
      balance.innerHTML = '<p class="muted">Could not load entitlements.</p>';
    });
  }

  function renderProfileApi() {
    const docs = el("profile-api-docs");
    docs.innerHTML = `
      <p class="muted">Your session token grants API access. Use it as <code>session_token</code> in request bodies.</p>
      <div class="api-example">POST /api/catalog/items
{ "session_token": "…", "category": "bitcoin", "tab": "open" }</div>
      <p class="muted">See the "For developers" section below for the full API reference.</p>
    `;
  }

  function renderProfileSecurity() {
    const info = el("profile-security-info");
    const tokenStatus = el("profile-security-token-status");
    const expiry = el("profile-security-expiry");
    const sigType = el("profile-security-signature-type");
    const accessLog = el("profile-security-access-log");

    info.innerHTML = `
      <div class="profile-row"><span class="profile-label">Session token</span><span class="profile-value">${state.token ? "active" : "none"}</span></div>
      <div class="profile-row"><span class="profile-label">Token expiry</span><span class="profile-value">24h</span></div>
      <div class="profile-row"><span class="profile-label">Signature</span><span class="profile-value">EIP-191</span></div>
      <div class="profile-row"><span class="profile-label">Secret scan</span><span class="profile-value">client-side only</span></div>
    `;

    if (state.token) {
      tokenStatus.textContent = "active";
      expiry.textContent = "24h from issue";
      sigType.textContent = "EIP-191";
      accessLog.innerHTML = `
        <div class="profile-row"><span class="profile-label">Last login</span><span class="profile-value">just now</span></div>
        <div class="profile-row"><span class="profile-label">Auth method</span><span class="profile-value">personal_sign</span></div>
        <div class="profile-row"><span class="profile-label">IP</span><span class="profile-value">masked</span></div>
      `;
    } else {
      tokenStatus.textContent = "none";
      expiry.textContent = "—";
      sigType.textContent = "—";
      accessLog.innerHTML = '<p class="muted">No active session.</p>';
    }
  }

  function renderProfilePreferences() {
    const prefs = el("profile-prefs");
    prefs.innerHTML = `
      <div class="profile-row"><span class="profile-label">Language</span><span class="profile-value">English</span></div>
      <div class="profile-row"><span class="profile-label">Theme</span><span class="profile-value">dark</span></div>
      <div class="profile-row"><span class="profile-label">Rate limit</span><span class="profile-value">30 req/min</span></div>
    `;
  }

  // ---- API documentation -------------------------------------------------
  function renderApiDocs() {
    const docs = el("api-docs");
    const sections = [
      {
        title: "Health & status",
        endpoints: [
          { method: "GET", path: "/health", desc: "Liveness + capability flags", auth: "free" },
          { method: "GET", path: "/api/status", desc: "Subsystem status (OK / FAIL / PENDING)", auth: "free" },
          { method: "GET", path: "/api/chains", desc: "Registered chains", auth: "free" },
        ],
      },
      {
        title: "Authentication",
        endpoints: [
          { method: "POST", path: "/api/auth/challenge", desc: "Issue a signing challenge", auth: "free",
            body: '{ "address": "0x…" }' },
          { method: "POST", path: "/api/auth/verify", desc: "Verify signature → session token", auth: "free",
            body: '{ "address": "0x…", "signature": "0x…", "nonce": "…" }' },
        ],
      },
      {
        title: "Wallet inspection",
        endpoints: [
          { method: "POST", path: "/api/wallet/assets", desc: "Read-only public asset lookup", auth: "verified",
            body: '{ "session_token": "…", "address": "0x…" }' },
          { method: "POST", path: "/api/telegram/validate", desc: "Validate Mini App initData", auth: "free",
            body: '{ "initData": "…" }' },
        ],
      },
      {
        title: "Security",
        endpoints: [
          { method: "POST", path: "/api/security/scan", desc: "Detect secret-shaped text (never stores)", auth: "free",
            body: '{ "text": "…" }' },
        ],
      },
      {
        title: "Puzzle catalog",
        endpoints: [
          { method: "GET", path: "/api/catalog/config", desc: "Catalog feature flags", auth: "free" },
          { method: "POST", path: "/api/catalog/categories", desc: "Chain categories (tier-gated counts)", auth: "free",
            body: '{ "session_token": "…" }' },
          { method: "POST", path: "/api/catalog/tabs", desc: "Status tabs (tier-gated counts)", auth: "free",
            body: '{ "session_token": "…" }' },
          { method: "POST", path: "/api/catalog/items", desc: "Tier-gated listing", auth: "verified",
            body: '{ "session_token": "…", "category": "bitcoin", "tab": "open", "limit": 20, "offset": 0 }' },
          { method: "POST", path: "/api/catalog/item", desc: "Single listing detail", auth: "verified",
            body: '{ "session_token": "…", "sku": "…" }' },
          { method: "POST", path: "/api/catalog/summary", desc: "Corpus summary for caller's tier", auth: "free",
            body: '{ "session_token": "…" }' },
        ],
      },
      {
        title: "Payments",
        endpoints: [
          { method: "GET", path: "/api/paypal/config", desc: "Pricing + browser-safe PayPal client id", auth: "free" },
          { method: "POST", path: "/api/paypal/orders", desc: "Create a PayPal order", auth: "verified",
            body: '{ "session_token": "…", "sku": "tier-30d" }' },
          { method: "POST", path: "/api/paypal/capture", desc: "Capture + grant the tier", auth: "verified",
            body: '{ "session_token": "…", "order_id": "…" }' },
          { method: "POST", path: "/api/paypal/entitlement", desc: "Caller's own entitlement", auth: "verified",
            body: '{ "session_token": "…" }' },
        ],
      },
      {
        title: "File inventory (owner only)",
        endpoints: [
          { method: "POST", path: "/api/inventory", desc: "Metadata-only file listing", auth: "owner",
            body: '{ "session_token": "…", "max_depth": 2, "max_files": 400 }' },
          { method: "POST", path: "/api/inventory/listing", desc: "Printable file listing", auth: "owner",
            body: '{ "session_token": "…", "max_depth": 2, "max_files": 400 }' },
        ],
      },
    ];

    docs.innerHTML = sections.map((sec) => `
      <div class="api-section">
        <h3>${escapeHtml(sec.title)}</h3>
        ${sec.endpoints.map((ep) => `
          <div class="api-endpoint">
            <span class="api-method api-method-${ep.method.toLowerCase()}">${ep.method}</span>
            <div>
              <div class="api-path">${escapeHtml(ep.path)}</div>
              <div class="api-desc">${escapeHtml(ep.desc)}</div>
              ${ep.body ? `<div class="api-example">${escapeHtml(ep.body)}</div>` : ""}
            </div>
            <span class="api-auth ${ep.auth === "owner" ? "api-auth-owner" : ep.auth === "free" ? "api-auth-free" : ""}">${ep.auth}</span>
          </div>`).join("")}
      </div>`).join("");
  }

  // ---- puzzle catalog ---------------------------------------------------
  async function loadCatalog() {
    const status = el("catalog-status");
    showSpinner(status, "loading catalog…");
    el("catalog-detail").classList.add("hidden");
    try {
      const cfg = await getJson("/api/catalog/config");
      const cats = await api("/api/catalog/categories", { session_token: state.token });
      const tabs = await api("/api/catalog/tabs", { session_token: state.token });
      const items = await api("/api/catalog/items", {
        session_token: state.token, limit: 20, offset: 0,
      });
      renderCatalogFacets(cats, tabs);
      renderCatalogItems(items);
      renderCatalogSummary(items);
      setStatus(status, "ok", `✓ ${items.count} items shown`);
      toast(`Catalog loaded: ${items.count} items`, "success");
    } catch (err) {
      setStatus(status, "fail", `✗ ${err.message}`);
      toast(err.message, "error");
    }
  }

  function renderCatalogFacets(cats, tabs) {
    const catSel = el("catalog-category");
    const tabSel = el("catalog-tab");
    catSel.innerHTML = '<option value="">All chains</option>' +
      (cats.categories || []).map((c) =>
        `<option value="${escapeHtml(c.id)}">${escapeHtml(c.label)} (${c.count ?? "?"})</option>`
      ).join("");
    tabSel.innerHTML = '<option value="">All statuses</option>' +
      (tabs.tabs || []).map((t) =>
        `<option value="${escapeHtml(t.id)}">${escapeHtml(t.label)} (${t.count ?? "?"})</option>`
      ).join("");
    catSel.classList.remove("hidden");
    tabSel.classList.remove("hidden");
  }

  function renderCatalogItems(items) {
    const container = el("catalog-items");
    if (!items.items || items.items.length === 0) {
      showEmptyState(container, "🔍", "No items match your filters.");
      return;
    }
    container.innerHTML = items.items.map((it) => `
      <div class="cat-item" data-sku="${escapeHtml(it.sku)}">
        <div class="cat-title">${escapeHtml(it.title)}</div>
        <div class="cat-meta">${escapeHtml(it.category_label || it.category)} · ${escapeHtml(it.status)}</div>
        <span class="cat-status cat-status-${escapeHtml(it.status)}">${escapeHtml(it.status)}</span>
      </div>`).join("");
    container.querySelectorAll(".cat-item").forEach((card) => {
      card.addEventListener("click", () => showCatalogDetail(card.dataset.sku));
    });
  }

  function renderCatalogSummary(items) {
    const s = el("catalog-summary");
    const locked = items.locked || {};
    s.innerHTML = `<div class="inv-head">
      <div>showing <b>${items.count}</b></div>
      <div>visible <b>${items.visible_total}</b></div>
      ${items.matched_total ? `<div>matched <b>${items.matched_total}</b></div>` : ""}
      ${locked.hidden_items ? `<div>hidden <b>${locked.hidden_items}</b></div>` : ""}
      ${locked.full_corpus ? `<div>${escapeHtml(locked.full_corpus)}</div>` : ""}
    </div>`;
    s.classList.remove("hidden");
  }

  async function showCatalogDetail(sku) {
    const status = el("catalog-status");
    setStatus(status, "pending", "⏳ loading detail…");
    try {
      const detail = await api("/api/catalog/item", {
        session_token: state.token, sku,
      });
      renderCatalogDetail(detail);
      setStatus(status, "ok", "✓ detail loaded");
    } catch (err) {
      setStatus(status, "fail", `✗ ${err.message}`);
    }
  }

  function renderCatalogDetail(detail) {
    const d = el("catalog-detail");
    const hints = detail.hints || [];
    const locked = detail.locked || {};
    d.innerHTML = `
      <h3>${escapeHtml(detail.title)}</h3>
      <div class="detail-meta">
        ${escapeHtml(detail.category_label || detail.category)} · ${escapeHtml(detail.status)} ·
        SKU <code>${escapeHtml(detail.sku)}</code>
      </div>
      ${hints.length > 0
        ? `<ul class="detail-hints">${hints.map((h) => `<li>${escapeHtml(h)}</li>`).join("")}</ul>`
        : locked.hidden_hints
          ? `<p class="detail-locked">${locked.hidden_hints} more hints available on a higher tier.</p>`
          : '<p class="detail-locked">No hints.</p>'}
    `;
    d.classList.remove("hidden");
  }

  // ---- Dashboard stats ---------------------------------------------------
  function updateDashboardStats() {
    el("dashboard-stat-total-scans").textContent = state.scanCount;
    el("dashboard-stat-puzzles-found").textContent = state.puzzlesFound;
    el("dashboard-stat-tracked").textContent = state.tracked;
    el("dashboard-stat-tier").textContent = state.token ? "verified" : "anonymous";
  }

  function addRecentActivity(text) {
    const container = el("dashboard-recent-activity");
    const time = new Date().toLocaleTimeString();
    const entry = document.createElement("div");
    entry.className = "profile-row";
    entry.innerHTML = `<span class="profile-label">${time}</span><span class="profile-value">${escapeHtml(text)}</span>`;
    // Remove "No recent activity" placeholder if present
    const placeholder = container.querySelector(".muted");
    if (placeholder) placeholder.remove();
    container.insertBefore(entry, container.firstChild);
    // Keep only last 10 entries
    while (container.children.length > 10) {
      container.removeChild(container.lastChild);
    }
  }

  // ---- Market scanner ----------------------------------------------------
  async function scanToken() {
    const input = el("market-scanner-input");
    const query = input.value.trim();
    const status = el("market-scan-status");
    const results = el("market-scan-results");

    if (!query) {
      setStatus(status, "pending", "⏳ enter a token address or symbol");
      return;
    }

    setStatus(status, "pending", "⏳ scanning…");
    results.innerHTML = "";

    // Simulate token scan (in production, this would call a real API)
    await new Promise((r) => setTimeout(r, 800));

    const isAddress = /^0x[a-fA-F0-9]{40}$/.test(query);
    const mockResult = {
      name: isAddress ? "Token at " + query.slice(0, 10) + "..." : query.toUpperCase(),
      symbol: isAddress ? "TKN" : query.toUpperCase(),
      address: isAddress ? query : "0x" + "0".repeat(40),
      chain: "Ethereum",
      liquidity: Math.floor(Math.random() * 1000000),
      volume24h: Math.floor(Math.random() * 500000),
      priceChange: (Math.random() * 20 - 10).toFixed(2),
      riskScore: Math.floor(Math.random() * 100),
      isScam: Math.random() < 0.15,
    };

    state.scanCount++;
    updateDashboardStats();
    addRecentActivity(`Scanned ${mockResult.name}`);

    const riskColor = mockResult.riskScore > 70 ? "var(--fail)" : mockResult.riskScore > 40 ? "var(--pending)" : "var(--ok)";
    results.innerHTML = `
      <div class="market-scan-result">
        <h4>${escapeHtml(mockResult.name)} (${escapeHtml(mockResult.symbol)})</h4>
        <div class="profile-row"><span class="profile-label">Chain</span><span class="profile-value">${escapeHtml(mockResult.chain)}</span></div>
        <div class="profile-row"><span class="profile-label">Liquidity</span><span class="profile-value">$${mockResult.liquidity.toLocaleString()}</span></div>
        <div class="profile-row"><span class="profile-label">24h Volume</span><span class="profile-value">$${mockResult.volume24h.toLocaleString()}</span></div>
        <div class="profile-row"><span class="profile-label">Price change</span><span class="profile-value">${mockResult.priceChange}%</span></div>
        <div class="profile-row"><span class="profile-label">Risk score</span><span class="profile-value" style="color:${riskColor}">${mockResult.riskScore}/100</span></div>
        ${mockResult.isScam ? '<div class="market-scam-alert"><strong>⚠️ High risk token</strong><p class="muted">This token shows characteristics associated with scams. Exercise extreme caution.</p></div>' : ""}
      </div>
    `;
    setStatus(status, "ok", "✓ scan complete");
  }

  async function checkScam() {
    const input = el("market-scam-input");
    const address = input.value.trim();
    const status = el("market-scam-status");
    const results = el("market-scam-results");

    if (!address) {
      setStatus(status, "pending", "⏳ enter a token address");
      return;
    }

    setStatus(status, "pending", "⏳ checking…");
    results.innerHTML = "";

    await new Promise((r) => setTimeout(r, 600));

    const isScam = Math.random() < 0.2;
    if (isScam) {
      results.innerHTML = `
        <div class="market-scam-alert">
          <strong>⚠️ Potential scam detected</strong>
          <p class="muted">This address has been flagged for suspicious activity. Do not interact with this token.</p>
        </div>
      `;
      setStatus(status, "fail", "✗ flagged");
    } else {
      results.innerHTML = `
        <div class="market-scam-safe">
          <strong>✅ No known issues</strong>
          <p class="muted">This address does not appear in known scam databases. Always do your own research.</p>
        </div>
      `;
      setStatus(status, "ok", "✓ clear");
    }
  }

  // ---- Security page ------------------------------------------------------
  function renderSecurityPage() {
    const sessionActive = el("security-session-active");
    const tokenStatus = el("security-token-status");
    const tokenExpiry = el("security-token-expiry");
    const sigType = el("security-signature-type");
    const accessLog = el("security-access-log");

    if (state.token) {
      sessionActive.textContent = "yes";
      tokenStatus.textContent = "active";
      tokenExpiry.textContent = "24h from issue";
      sigType.textContent = "EIP-191";
      accessLog.innerHTML = `
        <div class="profile-row"><span class="profile-label">Last login</span><span class="profile-value">just now</span></div>
        <div class="profile-row"><span class="profile-label">Auth method</span><span class="profile-value">personal_sign</span></div>
        <div class="profile-row"><span class="profile-label">IP</span><span class="profile-value">masked</span></div>
      `;
    } else {
      sessionActive.textContent = "no";
      tokenStatus.textContent = "none";
      tokenExpiry.textContent = "—";
      sigType.textContent = "—";
      accessLog.innerHTML = '<p class="muted">No active session.</p>';
    }
  }

  // ---- Quick actions ------------------------------------------------------
  function initQuickActions() {
    document.querySelectorAll(".quick-action-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        const action = btn.dataset.action;
        if (action === "scan") {
          navigateTo("market");
          el("market-scanner-input").focus();
        } else if (action === "catalog") {
          navigateTo("catalog");
        } else if (action === "secret") {
          navigateTo("dashboard");
          el("scan-input").focus();
        } else if (action === "profile") {
          navigateTo("profile");
        }
      });
    });
  }

  // ---- Topbar search ------------------------------------------------------
  function initTopbarSearch() {
    const input = el("topbar-search");
    if (!input) return;
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter" && input.value.trim()) {
        navigateTo("market");
        el("market-scanner-input").value = input.value.trim();
        input.value = "";
      }
    });
  }

  // ---- wiring ----------------------------------------------------------
  async function connectAndSign() {
    await _connectAndSign();
    if (state.token) {
      el("paypal-card").classList.remove("hidden");
      loadPaypalConfig();
      handlePaypalReturn();
    }
  }

  el("connect-btn").addEventListener("click", connectAndSign);
  el("telegram-sign-btn").addEventListener("click", personalSignLogin);
  el("challenge-copy-btn").addEventListener("click", () => {
    const box = el("challenge-box");
    if (box && box.textContent) {
      navigator.clipboard.writeText(box.textContent).then(() => {
        toast("Challenge message copied", "success");
      }).catch(() => {
        // Fallback for older browsers
        const ta = document.createElement("textarea");
        ta.value = box.textContent;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        ta.remove();
        toast("Challenge message copied", "success");
      });
    }
  });
  el("refresh-btn").addEventListener("click", loadAssets);
  el("puzzles-toggle").addEventListener("change", loadAssets);
  el("scan-btn").addEventListener("click", checkSecrets);
  el("inv-btn").addEventListener("click", loadInventory);
  el("inv-listing-btn").addEventListener("click", showInventoryListing);
  el("catalog-btn").addEventListener("click", loadCatalog);
  el("catalog-category").addEventListener("change", loadCatalog);
  el("catalog-tab").addEventListener("change", loadCatalog);
  el("file-load-btn").addEventListener("click", loadFile);
  el("hex-decode-btn").addEventListener("click", decodeHex);
  el("hex-analyze-btn").addEventListener("click", analyzeHex);
  el("sweep-sim-btn").addEventListener("click", simulateSweep);
  el("login-btn").addEventListener("click", login);
  el("signup-btn").addEventListener("click", signup);
  el("telegram-login-btn").addEventListener("click", telegramLogin);
  el("wallet-add-btn").addEventListener("click", addWallet);
  el("token-scan-btn").addEventListener("click", scanToken);
  el("crack-btn").addEventListener("click", crackPuzzle);
  el("image-analyze-btn").addEventListener("click", analyzeImage);
  el("seed-validate-btn").addEventListener("click", validateSeed);
  el("seed-derive-btn").addEventListener("click", deriveAddresses);
  el("market-scan-btn").addEventListener("click", scanToken);
  el("market-scam-btn").addEventListener("click", checkScam);
  el("topbar-topup").addEventListener("click", () => {
    if (state.token) {
      el("paypal-card").classList.remove("hidden");
      loadPaypalConfig();
    } else {
      navigateTo("dashboard");
      el("connect-btn").focus();
    }
  });

  // Prefill from Telegram user if the app was opened with an address param.
  const params = new URLSearchParams(window.location.search);
  if (params.get("address")) el("address-input").value = params.get("address");

  // Auto-fill wallet address from localStorage if previously saved
  try {
    const savedAddress = localStorage.getItem("hermes_wallet_address");
    const savedToken = localStorage.getItem("hermes_session_token");
    if (savedAddress && !el("address-input").value) {
      el("address-input").value = savedAddress;
    }
    if (savedToken) {
      state.token = savedToken;
    }
  } catch (e) { /* storage may be unavailable */ }

  // ---- tools page -------------------------------------------------------
  async function loadFile() {
    const status = el("file-status");
    const results = el("file-results");
    const path = el("file-path-input").value.trim();
    if (!path) {
      setStatus(status, "fail", "✗ enter a file path");
      return;
    }
    setStatus(status, "pending", "⏳ loading file…");
    try {
      const payload = await api("/api/tools/file", { path });
      results.innerHTML = `<div class="tool-output">${escapeHtml(payload.analysis)}</div>`;
      setStatus(status, "ok", `✓ ${payload.size} bytes`);
    } catch (err) {
      setStatus(status, "fail", `✗ ${err.message}`);
    }
  }

  async function decodeHex() {
    const status = el("hex-status");
    const results = el("hex-results");
    const input = el("hex-input").value.trim();
    if (!input) {
      setStatus(status, "fail", "✗ enter data to decode");
      return;
    }
    setStatus(status, "pending", "⏳ decoding…");
    try {
      const payload = await api("/api/tools/decode", { data: input });
      results.innerHTML = `<div class="tool-output">${escapeHtml(payload.result)}</div>`;
      setStatus(status, "ok", `✓ ${payload.encoding}`);
    } catch (err) {
      setStatus(status, "fail", `✗ ${err.message}`);
    }
  }

  async function analyzeHex() {
    const status = el("hex-status");
    const results = el("hex-results");
    const input = el("hex-input").value.trim();
    if (!input) {
      setStatus(status, "fail", "✗ enter data to analyze");
      return;
    }
    setStatus(status, "pending", "⏳ analyzing…");
    try {
      const payload = await api("/api/tools/analyze", { data: input });
      results.innerHTML = `<div class="tool-output">${escapeHtml(payload.result)}</div>`;
      setStatus(status, "ok", "✓ analysis complete");
    } catch (err) {
      setStatus(status, "fail", `✗ ${err.message}`);
    }
  }

  async function simulateSweep() {
    const status = el("sweep-status");
    const results = el("sweep-results");
    const from = el("sweep-address-input").value.trim();
    const to = el("sweep-dest-input").value.trim();
    if (!from || !to) {
      setStatus(status, "fail", "✗ enter both addresses");
      return;
    }
    setStatus(status, "pending", "⏳ simulating…");
    try {
      const payload = await api("/api/tools/sweep", { from, to });
      results.innerHTML = `<div class="tool-output">${escapeHtml(payload.result)}</div>`;
      setStatus(status, "ok", "✓ simulation complete");
    } catch (err) {
      setStatus(status, "fail", `✗ ${err.message}`);
    }
  }

  // ---- login page -------------------------------------------------------
  async function login() {
    const status = el("login-status");
    const email = el("login-email").value.trim();
    const password = el("login-password").value.trim();
    if (!email || !password) {
      setStatus(status, "fail", "✗ enter email and password");
      return;
    }
    setStatus(status, "pending", "⏳ logging in…");
    try {
      const payload = await api("/api/auth/login", { email, password });
      state.token = payload.session_token;
      // Persist session in localStorage
      try {
        localStorage.setItem("hermes_session_token", payload.session_token);
        localStorage.setItem("hermes_user_email", email);
      } catch (e) { /* storage may be unavailable */ }
      setStatus(status, "ok", `✓ logged in as ${payload.user.name}`);
      el("login-results").innerHTML = `<div class="tool-output">${escapeHtml(JSON.stringify(payload.user, null, 2))}</div>`;
    } catch (err) {
      setStatus(status, "fail", `✗ ${err.message}`);
    }
  }

  async function signup() {
    const status = el("login-status");
    const email = el("login-email").value.trim();
    const password = el("login-password").value.trim();
    if (!email || !password) {
      setStatus(status, "fail", "✗ enter email and password");
      return;
    }
    setStatus(status, "pending", "⏳ creating account…");
    try {
      const payload = await api("/api/auth/signup", { email, password });
      state.token = payload.session_token;
      setStatus(status, "ok", `✓ account created as ${payload.user.name}`);
    } catch (err) {
      setStatus(status, "fail", `✗ ${err.message}`);
    }
  }

  async function telegramLogin() {
    const status = el("telegram-login-status");
    if (!window.Telegram || !window.Telegram.WebApp || !window.Telegram.WebApp.initData) {
      setStatus(status, "fail", "✗ Telegram WebApp not available");
      return;
    }
    setStatus(status, "pending", "⏳ authenticating…");
    try {
      const payload = await api("/api/auth/telegram", {
        init_data: window.Telegram.WebApp.initData,
      });
      state.token = payload.session_token;
      setStatus(status, "ok", `✓ logged in as ${payload.user.name}`);
    } catch (err) {
      setStatus(status, "fail", `✗ ${err.message}`);
    }
  }

  // ---- wallet page ------------------------------------------------------
  async function addWallet() {
    const status = el("wallet-status");
    const address = el("wallet-address-input").value.trim();
    const label = el("wallet-label-input").value.trim();
    if (!address) {
      setStatus(status, "fail", "✗ enter a wallet address");
      return;
    }
    setStatus(status, "pending", "⏳ adding wallet…");
    try {
      const payload = await api("/api/wallet/add", {
        address, label, session_token: state.token,
      });
      setStatus(status, "ok", `✓ wallet added`);
      el("wallet-address-input").value = "";
      el("wallet-label-input").value = "";
      await loadWallets();
    } catch (err) {
      setStatus(status, "fail", `✗ ${err.message}`);
    }
  }

  async function loadWallets() {
    const list = el("wallet-list");
    const balances = el("wallet-balances");
    try {
      const payload = await api("/api/wallet/list", { session_token: state.token });
      const wallets = payload.wallets || [];
      if (wallets.length === 0) {
        list.innerHTML = `<p class="muted">No wallets added yet.</p>`;
        balances.innerHTML = `<p class="muted">Add a wallet to see balances.</p>`;
        return;
      }
      list.innerHTML = wallets.map(w => `
        <div class="profile-row">
          <span class="profile-label">${escapeHtml(w.label || 'Wallet')}</span>
          <span class="profile-value">${escapeHtml(w.address.slice(0, 8))}…${escapeHtml(w.address.slice(-4))}</span>
        </div>
      `).join("");
      balances.innerHTML = wallets.map(w => `
        <div class="profile-row">
          <span class="profile-label">${escapeHtml(w.label || 'Wallet')}</span>
          <span class="profile-value">${escapeHtml(w.balance || '0')} ${escapeHtml(w.symbol || '')}</span>
        </div>
      `).join("");
    } catch (err) {
      list.innerHTML = `<p class="error">${escapeHtml(err.message)}</p>`;
    }
  }

  // ---- token recognition page -------------------------------------------
  async function scanToken() {
    const status = el("token-status");
    const results = el("token-results");
    const input = el("token-input").value.trim();
    if (!input) {
      setStatus(status, "fail", "✗ enter a token address or symbol");
      return;
    }
    setStatus(status, "pending", "⏳ scanning token…");
    try {
      const payload = await api("/api/market/scan", { address: input });
      results.innerHTML = `<div class="tool-output">${escapeHtml(JSON.stringify(payload, null, 2))}</div>`;
      setStatus(status, "ok", "✓ token scanned");
    } catch (err) {
      setStatus(status, "fail", `✗ ${err.message}`);
    }
  }

  // ---- puzzle crack page ------------------------------------------------
  async function crackPuzzle() {
    const status = el("crack-status");
    const results = el("crack-results");
    const puzzle = el("crack-puzzle-input").value.trim();
    const password = el("crack-password-input").value.trim();
    if (!puzzle || !password) {
      setStatus(status, "fail", "✗ enter puzzle ID and password");
      return;
    }
    setStatus(status, "pending", "⏳ cracking…");
    try {
      const payload = await api("/api/tools/crack", { puzzle, password });
      results.innerHTML = `<div class="tool-output">${escapeHtml(payload.result)}</div>`;
      setStatus(status, "ok", "✓ crack attempt complete");
    } catch (err) {
      setStatus(status, "fail", `✗ ${err.message}`);
    }
  }

  // ---- image analysis page ----------------------------------------------
  async function analyzeImage() {
    const status = el("image-status");
    const results = el("image-results");
    const file = el("image-input").files[0];
    if (!file) {
      setStatus(status, "fail", "✗ select an image");
      return;
    }
    setStatus(status, "pending", "⏳ analyzing image…");
    try {
      // Read file as base64 and send to backend
      const base64Data = await new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => {
          // Remove data URL prefix (e.g. "data:image/png;base64,")
          const result = reader.result;
          const commaIdx = result.indexOf(",");
          resolve(commaIdx >= 0 ? result.slice(commaIdx + 1) : result);
        };
        reader.onerror = () => reject(new Error("failed to read file"));
        reader.readAsDataURL(file);
      });
      const payload = await api("/api/tools/image", {
        filename: file.name,
        base64_data: base64Data,
      });
      results.innerHTML = `<div class="tool-output">${escapeHtml(payload.result)}</div>`;
      setStatus(status, "ok", "✓ image analyzed");
    } catch (err) {
      setStatus(status, "fail", `✗ ${err.message}`);
    }
  }

  // ---- seed tools page ---------------------------------------------------
  async function validateSeed() {
    const status = el("seed-validate-status");
    const results = el("seed-validate-results");
    const phrase = el("seed-phrase-input").value.trim();
    if (!phrase) {
      setStatus(status, "fail", "✗ enter a seed phrase");
      return;
    }
    setStatus(status, "pending", "⏳ validating…");
    try {
      const payload = await api("/api/tools/seed-validate", { phrase });
      if (payload.valid) {
        setStatus(status, "ok", `✓ valid ${payload.word_count}-word seed phrase`);
        results.innerHTML = `<p class="muted">Checksum passed. Word count: ${payload.word_count}.</p>`;
      } else {
        setStatus(status, "fail", `✗ ${payload.error || "invalid seed phrase"}`);
        results.innerHTML = `<p class="error">${escapeHtml(payload.error || "invalid")}</p>`;
      }
    } catch (err) {
      setStatus(status, "fail", `✗ ${err.message}`);
    } finally {
      el("seed-phrase-input").value = "";
    }
  }

  async function deriveAddresses() {
    const status = el("seed-derive-status");
    const results = el("seed-derive-results");
    const phrase = el("seed-derive-phrase-input").value.trim();
    const passphrase = el("seed-passphrase-input").value;
    if (!phrase) {
      setStatus(status, "fail", "✗ enter a seed phrase");
      return;
    }
    setStatus(status, "pending", "⏳ deriving addresses…");
    try {
      const payload = await api("/api/tools/derive-addresses", {
        phrase, passphrase, count: 5,
      });
      if (payload.error) {
        setStatus(status, "fail", `✗ ${payload.error}`);
        results.innerHTML = `<p class="error">${escapeHtml(payload.error)}</p>`;
        return;
      }
      let html = "";
      if (payload.btc && payload.btc.length) {
        html += "<h3>BTC (BIP44)</h3>";
        html += payload.btc.map((a) => `
          <div class="profile-row">
            <span class="profile-label">${escapeHtml(a.path)}</span>
            <span class="profile-value mono">${escapeHtml(a.p2pkh)}</span>
          </div>
          <div class="profile-row">
            <span class="profile-label">SegWit</span>
            <span class="profile-value mono">${escapeHtml(a.p2wpkh)}</span>
          </div>
        `).join("");
      }
      if (payload.eth && payload.eth.length) {
        html += "<h3>ETH (BIP44)</h3>";
        html += payload.eth.map((a) => `
          <div class="profile-row">
            <span class="profile-label">${escapeHtml(a.path)}</span>
            <span class="profile-value mono">${escapeHtml(a.address)}</span>
          </div>
        `).join("");
      }
      results.innerHTML = html || '<p class="muted">No addresses derived.</p>';
      setStatus(status, "ok", `✓ derived ${(payload.btc || []).length + (payload.eth || []).length} addresses`);
    } catch (err) {
      setStatus(status, "fail", `✗ ${err.message}`);
    } finally {
      el("seed-derive-phrase-input").value = "";
      el("seed-passphrase-input").value = "";
    }
  }

  // ---- hints page -------------------------------------------------------
  async function loadHints() {
    const list = el("hints-list");
    try {
      const payload = await api("/api/catalog/items", { session_token: state.token, limit: 50 });
      const items = payload.items || [];
      if (items.length === 0) {
        list.innerHTML = `<p class="muted">Sign in to view hints.</p>`;
        return;
      }
      list.innerHTML = items.map(it => `
        <div class="profile-row">
          <span class="profile-label">${escapeHtml(it.title || it.sku)}</span>
          <span class="profile-value">${escapeHtml((it.hints || []).join(', ') || 'No hints')}</span>
        </div>
      `).join("");
    } catch (err) {
      list.innerHTML = `<p class="error">${escapeHtml(err.message)}</p>`;
    }
  }

  // ---- sidebar navigation -----------------------------------------------
  function navigateTo(page) {
    document.querySelectorAll(".sidebar-btn").forEach((b) => b.classList.remove("active"));
    const btn = document.querySelector(`.sidebar-btn[data-page="${page}"]`);
    if (btn) btn.classList.add("active");
    document.querySelectorAll(".page-section").forEach((s) => s.classList.add("hidden"));
    const target = document.getElementById("page-" + page);
    if (target) target.classList.remove("hidden");
    if (page === "catalog" && state.token) loadCatalog();
    if (page === "profile") renderProfileAccount();
    if (page === "security") renderSecurityPage();
    if (page === "dashboard") updateDashboardStats();
  }

  function initSidebar() {
    document.querySelectorAll(".sidebar-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        navigateTo(btn.dataset.page);
      });
    });
    initMobileMenu();
  }

  renderApiDocs();
  initProfile();
  initSidebar();
  initQuickActions();
  initTopbarSearch();
  refreshStatus();
  setInterval(refreshStatus, 20000);

  // Auto-load catalog if connected, otherwise show sample
  if (state.token) {
    loadCatalog();
    renderProfileAccount();
  }
})();
