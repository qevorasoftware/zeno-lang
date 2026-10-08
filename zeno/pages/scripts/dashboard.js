"use strict";

const SNAPSHOT_URL = "dashboard-data.json";
const state = {
  base: "",
  live: false,
  snapshot: null,
  provider: null,
  token: localStorage.getItem("zeno.token") || "",
  watchtower: null,
  history: [],
  cursor: 0,
};

const consoleEl = document.getElementById("console");
const commandInput = document.getElementById("command");
const backendInput = document.getElementById("backend");
const modePill = document.getElementById("mode-pill");
const statusText = document.getElementById("status-text");
const dot = document.getElementById("dot");

function detectDefaultBackend() {
  const stored = localStorage.getItem("zeno.backend");
  if (stored) return stored;
  if (location.protocol.startsWith("http") && location.port === "8000") return location.origin;
  return "http://localhost:8000";
}

function render(mode, text) {
  const line = document.createElement("div");
  line.className = "line-" + mode + (["ok","warn","bad","dim","out"].includes(mode) ? " " + mode : "");
  line.textContent = text;
  consoleEl.appendChild(line);
  consoleEl.scrollTop = consoleEl.scrollHeight;
}

function showJson(value, limit) {
  const text = typeof value === "string" ? value : JSON.stringify(value, null, 2);
  const clipped = limit && text.length > limit ? text.slice(0, limit) + "\n… (" + (text.length - limit) + " more chars)" : text;
  render("out", clipped);
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[character]
  ));
}

function formatExample(value, fallback) {
  if (value && typeof value === "object") {
    return "human: " + (value.human || "?") + "\n" + "zeno : " + (value.zeno || "?");
  }
  return String(value || fallback || "?");
}

function snapshotUrl() {
  try { return new URL(SNAPSHOT_URL, document.baseURI || location.href).toString(); }
  catch (_) { return SNAPSHOT_URL; }
}

async function loadSnapshot() {
  if (state.snapshot) return state.snapshot;
  const response = await fetch(snapshotUrl());
  if (!response.ok) throw new Error("snapshot " + response.status);
  state.snapshot = await response.json();
  return state.snapshot;
}

// Every request carries the stored capability token when there is one: the
// gateway decides whether it is needed, and it is the owner's token to hold.
function freshNonce() {
  try {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  } catch (_) {
    return String(Date.now()) + "-" + Math.random().toString(16).slice(2);
  }
}

function authBody(body) {
  if (!state.token) return body;
  const aegis = Object.assign({}, body.aegis || {}, { token: state.token });
  return Object.assign({}, body, { aegis: aegis });
}

function decoyError() {
  // The guardian has flagged this browser's source: repeated refused attempts
  // are answered with fabricated successes, and the body honestly labels
  // itself ("decoy": true). Nothing actually happened. Fix the refusal
  // underneath — usually a missing or expired owner grant — then try once:
  // a permitted request is never answered with a decoy.
  const failure = new Error(
    "the guardian is tarpitting this browser: repeated refused attempts are answered " +
    "with fabricated decoys, so nothing actually happened. Fix the refusal underneath " +
    "(usually the owner grant) and try once."
  );
  failure.decoy = true;
  return failure;
}

async function api(path, options) {
  const request = Object.assign({}, options);
  if (state.token) {
    // A bearer token belongs in a header: it stays out of URLs, and therefore
    // out of logs, history and referrers.
    request.headers = Object.assign({}, request.headers, { "X-Zeno-Capability": state.token });
  }
  const response = await fetch(state.base + path, request);
  let payload = null;
  try { payload = await response.json(); } catch (_) { payload = null; }
  if (!response.ok) {
    const error = payload && payload.error ? payload.error : null;
    throw new Error(error ? (error.message || error.code || JSON.stringify(error)) : ("HTTP " + response.status));
  }
    if (payload && payload.decoy === true) {
    throw decoyError();
  }
  return payload;
}

function post(path, body) {
  // A fresh nonce per POST: production refuses a request without one, and a
  // captured one is refused on replay — the same contract every page uses.
  return api(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(authBody(Object.assign({ nonce: freshNonce() }, body))),
  });
}

// -- connection -------------------------------------------------------------
async function probe(base, { quiet } = {}) {
  const previous = state.base;
  state.base = base;
  try {
    const health = await api("/api/health");
    state.live = true;
    state.provider = health;
    localStorage.setItem("zeno.backend", base);
    setStatus("live", base === "" ? "connected (same origin)" : "connected to " + base);
    if (!quiet) render("ok", "connected: provider=" + health.provider + " tokenizer=" + health.tokenizer);
    await loadPanels();
    await loadWatchtower({ quiet: true });
    return true;
  } catch (error) {
    state.base = previous;
    state.live = false;
    setStatus(base ? "down" : "snap", base ? "no backend at " + base : "no backend found");
    if (!quiet) render("warn", "could not reach " + (base || "the same origin") + ": " + error.message);
    return false;
  }
}

function setStatus(kind, text) {
  dot.className = "dot " + (kind === "live" ? "live" : kind === "down" ? "down" : "snap");
  modePill.className = "pill " + (kind === "live" ? "live" : kind === "down" ? "down" : "snap");
  modePill.textContent = kind === "live" ? "LIVE" : kind === "down" ? "OFFLINE" : "SNAPSHOT";
  statusText.textContent = text;
  renderStatusPanel();
  renderCapabilityPanel();
}

function renderStatusPanel() {
  const panel = document.getElementById("panel-status");
  const health = state.provider || {};
  const enforcement = health.enforcement || (state.live ? "unknown" : "—");
  const rows = state.live ? [
    ["mode", "live"],
    ["backend", state.base || location.origin],
    ["enforcement", enforcement],
    ["provider", health.provider],
    ["model", health.model || "—"],
    ["tokenizer", health.tokenizer],
    ["policy", health.policy ? (health.policy.strict ? "strict (all eight layers)" : "development") : "—"],
  ] : [
    ["mode", "snapshot (read-only)"],
    ["source", SNAPSHOT_URL],
  ];
  panel.innerHTML = rows.map(([key, value]) =>
    '<div class="stat"><span class="muted">' + escapeHtml(key) + '</span><b>' + escapeHtml(value) + "</b></div>").join("") +
    (state.live ? "" : '<p class="muted" style="margin:10px 0 0">Start a backend to run commands: ' +
      "<code>python -m pip install -e .[dev]</code> then <code>zeno serve</code>, and connect to " +
      "<code>http://localhost:8000</code>.</p>");
}

function decodeToken(token) {
  try {
    const payload = JSON.parse(atob(token));
    return {
      subject: payload.subject || "?",
      capabilities: payload.capabilities || [],
      issuer: payload.issuer || "?",
      epoch: payload.epoch,
      expires_at: payload.expires_at,
      suite: payload.crypto_suite,
    };
  } catch (_) { return null; }
}

function renderCapabilityPanel() {
  const panel = document.getElementById("panel-capability");
  const required = state.provider && state.provider.policy && state.provider.policy.require_capability;
  const info = state.token ? decodeToken(state.token) : null;
  const rows = [];
  rows.push(["owner grant", state.token ? "stored" : (required ? "required" : "not set")]);
  if (info) {
    rows.push(["subject", info.subject]);
    rows.push(["capabilities", (info.capabilities || []).join(", ") || "—"]);
    rows.push(["epoch", info.epoch]);
    rows.push(["suite", String(info.suite || "?").replace("hybrid-", "")]);
    if (info.expires_at) {
      const left = Math.round(info.expires_at - Date.now() / 1000);
      rows.push(["expires in", left > 0 ? left + "s" : "expired"]);
    }
  } else if (required) {
    rows.push(["how", "zeno owner issue --subject you --capability execute:*"]);
  }
  panel.innerHTML = rows.map(([key, value]) =>
    '<div class="stat"><span class="muted">' + escapeHtml(key) + '</span><b>' + escapeHtml(value) + "</b></div>").join("") +
    '<p class="muted" style="margin:10px 0 0">' +
    (state.token
      ? "The token is sent with <code>run</code>/<code>ask</code>. It is decoded here for display only — the server verifies it against the owner's public key."
      : "Paste one with <code>token &lt;encoded&gt;</code>. Tokens are issued by the owner's key, never by this page.") +
    "</p>";
}

// -- panels -----------------------------------------------------------------
async function loadPanels() {
  if (state.live) {
    try {
      const snapshot = await api("/api/snapshot");
      renderPanels(snapshot);
      return;
    } catch (_) { /* fall through to the committed snapshot */ }
  }
  try {
    renderPanels(await loadSnapshot());
  } catch (_) { /* neither a backend nor the snapshot: panels stay empty */ }
}

async function loadWatchtower({ quiet } = {}) {
  const card = document.getElementById("card-watchtower");
  if (!state.live) { if (!quiet) render("warn", "the adversary feed needs a backend"); return; }
  try {
    // A fresh nonce per read: a read is authorized once by the owner's grant and
    // once by this nonce, so a captured request cannot be replayed.
    const data = await api("/api/watchtower?limit=8&nonce=" + encodeURIComponent(freshNonce()));
    state.watchtower = data;
    card.hidden = false;
    renderWatchtowerPanel(data);
  } catch (error) {
    card.hidden = true;
    if (!quiet) render("warn", "adversary feed: " + error.message);
  }
}

function renderWatchtowerPanel(data) {
  const panel = document.getElementById("panel-watchtower");
  if (!data || data.enabled === false) { panel.innerHTML = '<div class="muted">not enabled</div>'; return; }
  const rows = [
    ["refusals", data.records],
    ["sources", data.sources_seen],
    ["flagged", data.intruders && typeof data.intruders === "object" ? Object.keys(data.intruders).length : data.intruders],
    ["decoys served", data.decoys_served],
    ["tarpit total", (data.tarpit_ms_total || 0) + " ms"],
  ];
  const intruders = Object.entries(data.intruders || {}).slice(0, 4)
    .map(([source, info]) => '<div class="stat"><span class="intruder">' + escapeHtml(source) +
      '</span><b>' + escapeHtml(info.strikes) + " strikes</b></div>").join("");
  const recent = (data.recent || []).slice(0, 4).map((record) =>
    '<div class="stat"><span class="muted">' + escapeHtml((record.at_iso || "").replace("T", " ")) + "</span><b>" +
    escapeHtml(record.code || "") + (record.decoy_served ? " 🎭" : "") + "</b></div>").join("");
  panel.innerHTML = rows.map(([key, value]) =>
    '<div class="stat"><span class="muted">' + escapeHtml(key) + '</span><b>' + escapeHtml(value) + "</b></div>").join("") +
    (intruders ? '<p class="muted" style="margin:10px 0 2px">flagged sources</p>' + intruders : "") +
    (recent ? '<p class="muted" style="margin:10px 0 2px">latest attempts</p>' + recent : "") +
    '<p class="muted" style="margin:10px 0 0">🎭 = a fabricated result was served. ' +
    "A tarpit delays, it does not stop; the full feed is in <code>~/.zeno/watchtower.jsonl</code>.</p>";
}

function renderPanels(data) {
  const targets = data.benchmark.targets || {};
  const density = data.benchmark.density, conversation = data.benchmark.conversation;
  const row = (key, value) => '<div class="stat"><span class="muted">' + escapeHtml(key) + "</span><b>" + escapeHtml(value) + "</b></div>";
  const liveNote = '<p class="muted" style="margin:8px 0 0">Connect a backend to measure this host: token counts depend on the counter in use.</p>';

  document.getElementById("panel-density").innerHTML = density
    ? row("pooled reduction", density.reduction.pooled_pct + "%") +
      row("cases", density.cases.length) +
      row("counter", density.tokenizer) +
      row("target", density.target_reduction_pct + "% — " + (density.reduction.meets_target ? "met" : "not met"))
    : row("target", (targets.density_pct || 75) + "%") +
      row("corpus cases", data.benchmark.corpus_cases) + liveNote;

  document.getElementById("panel-conversation").innerHTML = conversation
    ? row("chat → zeno", conversation.totals.chat_tokens + " → " + conversation.totals.zeno_payload_only) +
      row("per hop", conversation.reduction.per_hop_pct + "%") +
      row("break-even", conversation.reduction.break_even_hops + " hops") +
      row("target", conversation.target_reduction_pct + "% — " + (conversation.reduction.meets_target ? "met" : "missed"))
    : row("target", (targets.conversation_pct || 75) + "%") +
      row("measure", "live backend only") + liveNote;

  const tools = data.tools;
  document.getElementById("panel-tools").innerHTML =
    '<div class="stat"><span class="muted">queries</span><b>' + tools.queries.length + "</b></div>" +
    '<div class="stat"><span class="muted">actions</span><b>' + tools.actions.length + "</b></div>" +
    '<p class="muted" style="margin:8px 0 0">' + escapeHtml(tools.queries.join(" · ")) + "<br>" + escapeHtml(tools.actions.join(" · ")) + "</p>";

  const grammar = data.grammar, spec = grammar.spec;
  const size = (value) => (Array.isArray(value) ? value.length
    : value && typeof value === "object" ? Object.keys(value).length : 0);
  document.getElementById("panel-grammar").innerHTML =
    '<div class="row" style="margin-bottom:8px">' +
    '<span class="pill">' + escapeHtml(spec.protocol + " " + spec.grammar_version) + "</span>" +
    '<span class="pill">' + size(spec.sigils) + " sigils</span>" +
    '<span class="pill">' + (size(spec.flow_operators) + size(spec.expression_operators)) + " operators</span>" +
    '<span class="pill">' + size(spec.diagnostics) + " diagnostics</span>" +
    '<span class="pill">' + size(spec.keywords) + " keywords</span></div>" +
    "<pre>" + escapeHtml(formatExample(spec.canonical_example, data.canonical_example)) + "</pre>";
}

// -- commands ----------------------------------------------------------------
const COMMANDS = [
  ["help", "list every command"],
  ["status", "backend, provider, tokenizer, policy"],
  ["encode <text>", "natural language → Zeno payload"],
  ["run <payload>", "execute a payload against the demo tools"],
  ["ask <text>", "encode → execute → decode, one round trip"],
  ["check <payload>", "validate and canonicalise"],
  ["decode <payload>", "execute then render the result as prose"],
  ["tokens <text>", "count tokens (and compare with a payload)"],
  ["grammar [table]", "grammar card, or the raw token table"],
  ["tools", "the vocabularies the kernel exposes"],
  ["benchmark", "density + multi-turn headlines"],
  ["watchtower", "who has been refused, and what happened"],
  ["token <encoded>", "store an owner-issued capability token"],
  ["example", "load the canonical example into the input"],
  ["connect <url>", "point the dashboard at a backend"],
  ["snapshot", "the committed offline data this page ships with"],
  ["clear", "clear the console"],
];

function renderPalette() {
  const palette = document.getElementById("palette");
  palette.innerHTML = "";
  // The chips are the commands people actually reach for, not the whole list:
  // `help` has the rest, and a palette of everything is a palette of nothing.
  const featured = ["encode <text>", "run <payload>", "ask <text>", "tokens <text>",
                    "benchmark", "watchtower", "token <encoded>", "snapshot", "example"];
  COMMANDS.filter(([usage]) => featured.includes(usage)).forEach(([usage, description]) => {
    const chip = document.createElement("span");
    chip.className = "chip";
    chip.textContent = usage;
    chip.title = description;
    chip.addEventListener("click", () => {
      commandInput.value = usage.replace(/[<>]/g, "").replace(/ \[.*\]$/, "");
      commandInput.focus();
    });
    palette.appendChild(chip);
  });
}

function requireLive() {
  if (state.live) return true;
  render("warn", "this command needs a backend. Start one with `zeno serve`, then run: connect http://localhost:8000");
  return false;
}

async function execute(input) {
  const raw = input.trim();
  if (!raw) return;
  render("in", "zeno> " + raw);
  const space = raw.indexOf(" ");
  const name = (space === -1 ? raw : raw.slice(0, space)).toLowerCase();
  const argument = space === -1 ? "" : raw.slice(space + 1).trim();

  switch (name) {
    case "help":
      render("out", COMMANDS.map(([usage, description]) => "  " + usage.padEnd(22) + description).join("\n"));
      return;
    case "clear":
      consoleEl.innerHTML = "";
      return;
    case "example":
      commandInput.value = "ask Check the weather in Tokyo. If it is raining, suggest 3 indoor activities.";
      render("dim", "loaded the canonical round trip into the input — press Run.");
      return;
    case "status": {
      if (!requireLive()) return;
      showJson(await api("/api/version"));
      return;
    }
    case "connect": {
      const target = argument.replace(/\/$/, "");
      const ok = await probe(target, { quiet: false });
      if (ok) render("ok", "the dashboard is now driving " + target);
      return;
    }
    case "token": {
      if (!argument) {
        if (state.token) render("dim", "token stored: " + JSON.stringify(decodeToken(state.token)));
        else render("dim", "no token stored. Usage: token <encoded value from `zeno owner issue`>");
        return;
      }
      if (argument.toLowerCase() === "clear") {
        state.token = "";
        localStorage.removeItem("zeno.token");
        render("warn", "token cleared");
      } else {
        const decoded = decodeToken(argument);
        if (!decoded) { render("bad", "that does not decode as a capability token"); return; }
        state.token = argument;
        localStorage.setItem("zeno.token", argument);
        render("ok", "token stored for " + decoded.subject + " (the server verifies it, not this page)");
      }
      renderCapabilityPanel();
      return;
    }
    case "watchtower": {
      if (!requireLive()) return;
      await loadWatchtower();
      if (!state.watchtower) return;
      const data = state.watchtower;
      render("out", data.records + " refused attempts from " + data.sources_seen + " sources");
      render("out", "flagged: " + String(data.intruders && Object.keys(data.intruders).length || 0) +
        "   decoys served: " + data.decoys_served + "   tarpit: " + (data.tarpit_ms_total || 0) + " ms");
      (data.recent || []).slice(0, 5).forEach((record) => {
        render(record.decoy_served ? "warn" : "dim",
          "  " + record.at_iso + "  " + record.remote + "  " + record.code +
          (record.decoy_served ? "  (decoy served)" : ""));
      });
      render("dim", "full feed: ~/.zeno/watchtower.jsonl   (`zeno watchtower` on the host)");
      return;
    }
    case "snapshot": {
      try {
        const data = await loadSnapshot();
        showJson({
          generated_by: data.generated_by,
          version: data.version,
          canonical_example: data.canonical_example,
        }, 2000);
        render("dim", "full file: " + SNAPSHOT_URL + " (regenerate with `zeno dashboard --write`)");
      } catch (error) {
        render("warn", "no snapshot available here: " + error.message);
      }
      return;
    }
    case "encode": {
      if (!requireLive()) return;
      if (!argument) { render("dim", "usage: encode <natural language>"); return; }
      const result = await post("/api/encode", { text: argument });
      render("ok", String(result.payload || "(no payload produced)").replace(/\n/g, "\n    "));
      if (result.nl_tokens !== undefined) {
        render("dim", result.nl_tokens + " tokens in → " + result.zeno_tokens + " tokens out" +
          (result.token_reduction_pct !== undefined ? "  (" + result.token_reduction_pct + "% fewer)" : "") +
          "   provider=" + result.provider + (result.fell_back ? " (fallback)" : ""));
      }
      if (result.validation && !result.validation.ok) {
        render("warn", (result.validation.diagnostics || []).map((item) => item.code + " " + item.message).join("\n"));
      }
      if (result.warnings && result.warnings.length) render("dim", result.warnings.join("\n"));
      return;
    }
    case "run": {
      if (!requireLive()) return;
      if (!argument) { render("dim", "usage: run <payload>"); return; }
      const result = await post("/api/run", { payload: argument });
      showJson(result.frame);
      if (result.aegis) render(result.aegis.allowed ? "dim" : "warn",
        "aegis: " + (result.aegis.allowed ? "allowed" : "refused") + " (" + result.aegis.enforcement + ")");
      return;
    }
    case "ask": {
      if (!requireLive()) return;
      if (!argument) { render("dim", "usage: ask <natural language>"); return; }
      const result = await post("/api/ask", { text: argument });
      const payload = result.payload || (result.encode && result.encode.payload) || "?";
      render("dim", "zeno> " + String(payload).replace(/\n/g, "\n       "));
      render("ok", result.response || "(no response)");
      if (result.execution && result.execution.frame) showJson({ frame: result.execution.frame }, 900);
      return;
    }
    case "check": {
      if (!requireLive()) return;
      if (!argument) { render("dim", "usage: check <payload>"); return; }
      const result = await post("/api/check", { payload: argument });
      const report = result.report || {};
      render(report.ok ? "ok" : (report.error ? "bad" : "warn"), result.rendered || "");
      if (result.canonical) render("dim", "canonical: " + result.canonical);
      return;
    }
    case "decode": {
      if (!requireLive()) return;
      if (!argument) { render("dim", "usage: decode <payload>"); return; }
      const result = await post("/api/decode", { payload: argument });
      render("ok", result.text || "(nothing)");
      if (result.frame) render("dim", "frame: " + result.frame);
      return;
    }
    case "tokens": {
      if (!requireLive()) return;
      if (!argument) { render("dim", "usage: tokens <text>"); return; }
      const result = await post("/api/tokens", { texts: [argument] });
      render("out", "tokens: " + result.counts[argument] + "   (" + result.method + ")");
      try {
        const encoded = await post("/api/encode", { text: argument });
        if (encoded.payload) {
          const pct = encoded.token_reduction_pct;
          render(pct > 0 ? "ok" : "warn",
            "as Zeno: " + encoded.zeno_tokens + " tokens" +
            (pct !== undefined ? "  (" + pct + "% fewer)" : "") +
            "   ⚠ the benchmark wins on dispatch-style text, not on terse one-liners");
          render("dim", String(encoded.payload).replace(/\n/g, "\n       "));
        }
      } catch (_) { /* the comparison is a bonus, not the command */ }
      return;
    }
    case "grammar": {
      if (!requireLive()) return;
      const grammar = await api("/api/grammar");
      if (argument === "table") return showJson(grammar.spec, 5000);
      render("out", typeof grammar.card === "string" ? grammar.card : JSON.stringify(grammar.card, null, 2));
      render("dim", "raw machine-readable table: grammar table");
      return;
    }
    case "tools": {
      if (!requireLive()) return;
      const tools = await api("/api/tools");
      render("out", "queries: " + tools.queries.join(", "));
      render("out", "actions: " + tools.actions.join(", "));
      return;
    }
    case "benchmark": {
      if (!requireLive()) return;
      const benchmark = await api("/api/benchmark");
      render("out", "density pooled : " + benchmark.density.reduction.pooled_pct + "% (" + benchmark.density.cases.length + " cases, target " +
        benchmark.density.target_reduction_pct + "% — " + (benchmark.density.reduction.meets_target ? "met" : "not met") + ")");
      render("out", "A2A reduction  : " + benchmark.conversation.reduction.per_hop_pct + "% (target " +
        benchmark.conversation.target_reduction_pct + "% — " + (benchmark.conversation.reduction.meets_target ? "met" : "not met") + ")");
      render("dim", "full reports: zeno benchmark / zeno latency");
      return;
    }
    default:
      render("warn", "unknown command: " + name + "  (try `help`)");
  }
}

// -- wiring ------------------------------------------------------------------
function runCommand() {
  const value = commandInput.value;
  if (!value.trim()) return;
  state.history.push(value);
  state.cursor = state.history.length;
  commandInput.value = "";
  execute(value).catch((error) => render("bad", "error: " + error.message));
}

document.getElementById("run").addEventListener("click", runCommand);
commandInput.addEventListener("keydown", (event) => {
  if (event.key === "Enter") { event.preventDefault(); runCommand(); return; }
  if (event.key === "ArrowUp" && state.history.length) {
    state.cursor = Math.max(0, state.cursor - 1);
    commandInput.value = state.history[state.cursor] || "";
    event.preventDefault();
  }
  if (event.key === "ArrowDown") {
    state.cursor = Math.min(state.history.length, state.cursor + 1);
    commandInput.value = state.history[state.cursor] || "";
    event.preventDefault();
  }
  if (event.key === "l" && (event.ctrlKey || event.metaKey)) {
    consoleEl.innerHTML = "";
    event.preventDefault();
  }
});
document.getElementById("connect").addEventListener("click", async () => {
  const target = backendInput.value.trim().replace(/\/$/, "");
  const ok = await probe(target, { quiet: false });
  if (ok) render("ok", "the dashboard is now driving " + target);
});
document.getElementById("use-local").addEventListener("click", async () => {
  const ok = await probe("", { quiet: false });
  if (!ok) render("warn", "this page is not served by a Zeno backend, so there is nothing on this host to use");
});
backendInput.addEventListener("keydown", (event) => { if (event.key === "Enter") document.getElementById("connect").click(); });

(async function start() {
  renderPalette();
  render("dim", "Zeno dashboard. Commands run against a backend you connect; the panels below work offline.");
  render("dim", "Local server:  zeno serve      →  http://localhost:8000");
  const sameOrigin = await probe("", { quiet: true });
  if (!sameOrigin) {
    const target = detectDefaultBackend();
    backendInput.value = target;
    const ok = await probe(target, { quiet: true });
    if (!ok) {
      setStatus("snap", "no backend — panels are read-only");
      await loadPanels();
      render("warn", "no backend reachable at " + target + ".");
      render("dim", "start one:  python -m pip install -e .[dev]  &&  zeno serve");
      render("dim", "then:      connect " + target);
    } else {
      render("ok", "connected to " + target);
    }
  }
})();
