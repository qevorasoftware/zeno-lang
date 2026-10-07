// Minimal DOM shim so `dashboard.html`'s real script can run under node.
//
// This is a *test* fixture: it implements only what the dashboard touches
// (getElementById, createElement, classList-free attributes, localStorage,
// location, document.baseURI, fetch from node's global). If the dashboard starts
// using a browser API that is not here, this file is the place to add it — the
// shim failing loudly is better than the page failing silently in a browser.
const lines = [];
const elements = new Map();

function makeElement(tag) {
  return {
    tagName: tag,
    children: [],
    listeners: {},
    className: "",
    style: {},
    value: "",
    scrollTop: 0,
    scrollHeight: 0,
    _text: "",
    _html: "",
    get textContent() { return this._text; },
    set textContent(value) { this._text = String(value); this.children = []; },
    get innerHTML() { return this._html; },
    set innerHTML(value) { this._html = String(value); this.children = []; },
    appendChild(child) { this.children.push(child); lines.push(child.textContent); return child; },
    addEventListener(name, handler) { (this.listeners[name] = this.listeners[name] || []).push(handler); },
    focus() {},
  };
}

const ids = [
  "backend", "console", "command", "dot", "mode-pill", "status-text", "palette", "run",
  "connect", "use-local", "hint", "panel-status", "panel-density", "panel-conversation",
  "panel-tools", "panel-grammar", "playground-link",
];
for (const id of ids) elements.set(id, makeElement("div"));

global.document = {
  baseURI: process.env.ZENO_DASHBOARD_BASE || "http://127.0.0.1:8000/dashboard",
  getElementById(id) {
    if (!elements.has(id)) elements.set(id, makeElement("div"));
    return elements.get(id);
  },
  createElement: makeElement,
  addEventListener() {},
};
global.localStorage = {
  // ZENO_DASHBOARD_STORED_BACKEND lets a test pin the "last known backend" so
  // the boot sequence is deterministic (otherwise it would find a real server
  // on port 8000 and go live).
  store: process.env.ZENO_DASHBOARD_STORED_BACKEND
    ? { "zeno.backend": process.env.ZENO_DASHBOARD_STORED_BACKEND }
    : {},
  getItem(key) { return this.store[key] || null; },
  setItem(key, value) { this.store[key] = value; },
};
global.location = {
  protocol: "http:",
  port: (process.env.ZENO_DASHBOARD_BASE || "http://127.0.0.1:8000/dashboard").split(":").pop().split("/")[0],
  origin: "http://127.0.0.1:8000",
  href: process.env.ZENO_DASHBOARD_BASE || "http://127.0.0.1:8000/dashboard",
};
// The dashboard fetches the committed snapshot by a *relative* URL when no
// backend is reachable; node has no base URL, so resolve against baseURI.
const realFetch = global.fetch;
global.fetch = (input, init) => {
  const url = typeof input === "string" && !/^https?:/.test(input)
    ? new URL(input, document.baseURI).toString()
    : input;
  return realFetch(url, init);
};

global.renderLines = lines;
global.elementById = (id) => elements.get(id);
