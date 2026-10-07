/**
 * Boot dashboard.html outside a browser, well enough to type into it.
 *
 * The page is not modified for testing. This file reads dashboard.html, takes the
 * inline <script> exactly as the browser would, and runs it in a `vm` context
 * whose globals are a small DOM shim plus a real `fetch` pointed at the server
 * under test. Commands are then delivered the way a person delivers them: into
 * the command input, as an Enter keydown.
 *
 * Input  (environment):
 *   ZENO_DASHBOARD_BASE              origin the page is served from
 *   ZENO_DASHBOARD_STORED_BACKEND    value to pre-seed localStorage["zeno.backend"] with
 *   ZENO_DASHBOARD_COMMANDS          JSON array of command strings to run, in order
 *
 * Output (stdout): one JSON object — mode, console lines, panel HTML, palette.
 *
 * Limits, stated: this is a shim, not a browser. It has no layout, no CSS, no
 * event loop of its own. It proves the page's logic and its requests; it cannot
 * prove the page looks right. `node --check` covers syntax; a human covers taste.
 */
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const base = process.env.ZENO_DASHBOARD_BASE || "";
const storedBackend = process.env.ZENO_DASHBOARD_STORED_BACKEND || "";
const commands = JSON.parse(process.env.ZENO_DASHBOARD_COMMANDS || "[]");
const pageUrl = (base || "http://localhost") + "/dashboard.html";

// -- DOM shim ----------------------------------------------------------------
class Element {
  constructor(tag = "div") {
    this.tagName = String(tag).toUpperCase();
    this.children = [];
    this.listeners = Object.create(null);
    this.className = "";
    this.hidden = false;
    this.value = "";
    this.style = {};
    this.scrollTop = 0;
    this._text = "";
    this._html = "";
  }
  appendChild(child) { this.children.push(child); return child; }
  addEventListener(type, handler) { (this.listeners[type] ||= []).push(handler); }
  dispatch(type, event = {}) {
    const full = { type, key: "", preventDefault() {}, ...event };
    for (const handler of this.listeners[type] || []) handler(full);
  }
  focus() {}
  set innerHTML(value) { this._html = String(value); this.children = []; }
  get innerHTML() { return this._html; }
  set textContent(value) { this._text = String(value); }
  get textContent() { return this._text; }
  get scrollHeight() { return this.children.length; }
}

const html = readFileSync(resolve(ROOT, "dashboard.html"), "utf8");
const script = html.match(/<script>\n([\s\S]*?)<\/script>/);
if (!script) {
  console.error("dashboard.html has no inline script");
  process.exit(2);
}

// Every id in the markup exists before the script runs, as in a browser.
const elements = new Map();
for (const [, id] of html.matchAll(/id="([^"]+)"/g)) elements.set(id, new Element("div"));

const document = {
  baseURI: pageUrl,
  getElementById: (id) => elements.get(id) || null,
  createElement: (tag) => new Element(tag),
  addEventListener() {},
  querySelectorAll: () => [],
};

const storage = new Map();
if (storedBackend) storage.set("zeno.backend", storedBackend);
const localStorage = {
  getItem: (key) => (storage.has(key) ? storage.get(key) : null),
  setItem: (key, value) => storage.set(key, String(value)),
  removeItem: (key) => storage.delete(key),
};

const location = {
  href: pageUrl,
  origin: base || "http://localhost",
  protocol: (base || "http://localhost").split(":")[0] + ":",
  host: (base || "http://localhost").replace(/^\w+:\/\//, ""),
  port: (base || "").match(/:(\d+)$/)?.[1] || "",
  search: "",
};

// Requests go to the server under test. A relative path means the page's own
// origin, exactly as the browser resolves it.
const fetchShim = (url, options) => {
  const target = /^https?:/.test(url) ? url : new URL(url, pageUrl).toString();
  return fetch(target, options);
};

const context = vm.createContext({
  document, localStorage, location, fetch: fetchShim, URL, URLSearchParams, JSON, Math, Date,
  Object, Array, Number, String, Boolean, RegExp, Error, Promise, Map, Set, isNaN, parseInt,
  parseFloat, encodeURIComponent, decodeURIComponent, console, atob, btoa, crypto: globalThis.crypto,
  Uint8Array, setTimeout, clearTimeout,
});
context.globalThis = context;

// -- run the page ------------------------------------------------------------
vm.runInContext(script[1], context, { filename: "dashboard.html" });

const consoleEl = elements.get("console");
const input = elements.get("command");
const lines = () => consoleEl.children.map((child) => child.textContent);

// The page's work is asynchronous and it has no completion signal to hook, so we
// wait for it to go quiet: no new console line for a while. A shim that guessed
// faster than this would report an empty console and call it success.
async function settle(quietFor = 200, limit = 8000) {
  const started = Date.now();
  let seen = -1;
  let quietSince = Date.now();
  while (Date.now() - started < limit) {
    await new Promise((done) => setTimeout(done, 25));
    const count = consoleEl.children.length;
    if (count !== seen) { seen = count; quietSince = Date.now(); continue; }
    if (Date.now() - quietSince >= quietFor) return;
  }
}

await settle(400, 8000); // boot

for (const command of commands) {
  input.value = command;
  input.dispatch("keydown", { key: "Enter" });
  await settle();
}

const panels = {};
for (const [id, element] of elements) {
  if (id.startsWith("panel-")) panels[id.replace("panel-", "")] = element.innerHTML;
}

console.log(JSON.stringify({
  mode: elements.get("mode-pill").textContent,
  mode_text: elements.get("status-text").textContent,
  status_text: elements.get("status-text").textContent,
  palette: elements.get("palette").children.map((chip) => chip.textContent),
  input: input.value,
  backend_field: elements.get("backend").value,
  console: lines(),
  panels,
  storage: Object.fromEntries(storage),
}));
