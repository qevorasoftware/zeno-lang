"use strict";
const state = {
  session: "voice-" + new Date().toISOString().slice(0, 10),
  token: localStorage.getItem("zeno.token") || "",
  listening: false,
  recognition: null,
  recorder: null,
  chunks: [],
  health: null,
};

const $ = (id) => document.getElementById(id);
const log = $("log");

function line(kind, who, text, meta) {
  const wrap = document.createElement("div");
  wrap.className = "turn " + kind;
  const head = document.createElement("div");
  head.className = "who";
  head.textContent = who;
  const body = document.createElement("div");
  body.className = "text";
  body.textContent = text;
  wrap.appendChild(head);
  wrap.appendChild(body);
  if (meta) {
    const metaEl = document.createElement("div");
    metaEl.className = "meta";
    metaEl.textContent = meta;
    wrap.appendChild(metaEl);
  }
  log.appendChild(wrap);
  log.scrollTop = log.scrollHeight;
  return wrap;
}

function freshNonce() {
  try {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  } catch (_) { return String(Date.now()) + Math.random().toString(16).slice(2); }
}

function language() {
  return ($("lang-free").value.trim() || $("lang").value || "en").trim();
}

async function api(path, options) {
  const request = Object.assign({}, options);
  request.headers = Object.assign({"Content-Type": "application/json"}, request.headers || {});
  if (state.token) request.headers["X-Zeno-Capability"] = state.token;
  const response = await fetch(path, request);
  let payload = null;
  try { payload = await response.json(); } catch (_) { payload = null; }
  if (!response.ok) {
    const error = payload && payload.error ? payload.error : null;
    // In development the refusal carries its sentence; in production it carries a
    // code and nothing else, by policy. Show whatever is actually there.
    const detail = error ? [error.code, error.message].filter(Boolean).join(" — ") : ("HTTP " + response.status);
    const failure = new Error(detail);
    failure.status = response.status;
    throw failure;
  }
  return payload;
}

function post(path, body) {
  return api(path, { method: "POST", body: JSON.stringify(Object.assign({nonce: freshNonce()}, body)) });
}

// -- speech ------------------------------------------------------------------
function speak(text) {
  if (!$("speak").checked || !("speechSynthesis" in window) || !text) return;
  try {
    const utterance = new SpeechSynthesisUtterance(text);
    utterance.lang = language();
    speechSynthesis.speak(utterance);
  } catch (_) { /* a browser without speech is still a usable text agent */ }
}

function pcmFromBlob(blob) {
  // The server can only measure a voice it can read: decode here, keep the first
  // channel, resample to 16 kHz, and hand over signed 16-bit little-endian PCM.
  return new Promise((resolve) => {
    const reader = new FileReader();
    reader.onload = async () => {
      try {
        const context = new AudioContext();
        const decoded = await context.decodeAudioData(reader.result.slice(0));
        const source = decoded.getChannelData(0);
        const ratio = decoded.sampleRate / 16000;
        const length = Math.max(1, Math.floor(source.length / ratio));
        const out = new Int16Array(length);
        for (let index = 0; index < length; index += 1) {
          const sample = Math.max(-1, Math.min(1, source[Math.floor(index * ratio)] || 0));
          out[index] = sample < 0 ? sample * 0x8000 : sample * 0x7fff;
        }
        context.close();
        resolve({ pcm: new Uint8Array(out.buffer), sampleRate: 16000 });
      } catch (_) { resolve(null); }
    };
    reader.onerror = () => resolve(null);
    reader.readAsArrayBuffer(blob);
  });
}

function toBase64(bytes) {
  let binary = "";
  const chunk = 0x8000;
  for (let index = 0; index < bytes.length; index += chunk) {
    binary += String.fromCharCode.apply(null, bytes.subarray(index, index + chunk));
  }
  return btoa(binary);
}

// -- the turn ----------------------------------------------------------------
async function turn(text, audioPcm) {
  const body = {session: state.session, text: text || "", lang: language()};
  if (audioPcm) {
    body.audio_b64 = toBase64(audioPcm.pcm);
    body.sample_rate = audioPcm.sampleRate;
    body.channels = 1;
  }
  try {
    const result = await post("/api/voice/turn", body);
    if (!result.ok) {
      line("err", "refused", result.code || "no code", (result.notes || []).join(" "));
      return;
    }
    line("agent", "agent · " + (result.answerer || "?"), result.reply || "(no reply)",
      (result.stored || []).length + " records stored · " + result.understanding + " · " + result.elapsed_ms + " ms" +
      (result.voice && result.voice.dominant_hz ? " · voice " + result.voice.dominant_hz + " Hz" : ""));
    if (result.enforcement === "development") {
      line("sys", "note", "this server is in development enforcement: the turn was allowed without the full eight-layer chain.");
    }
    speak(result.reply || "");
  } catch (error) {
    line("err", "refused", String(error.message || error),
      error.status === 403
        ? "the guardian or the policy refused this turn. Nothing was generated or stored. " +
          "A rapid-fire burst reads as anomalous — a conversation with a human cadence does not. " +
          "The next turn is a new decision."
        : "");
  }
}

async function sendTyped() {
  const text = $("typed").value.trim();
  if (!text) return;
  $("typed").value = "";
  line("me", "you", text);
  await turn(text, null);
}

// -- recording + recognition -------------------------------------------------
async function startListening() {
  const chunks = state.chunks = [];
  if (navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({audio: true});
      const recorder = new MediaRecorder(stream);
      recorder.ondataavailable = (event) => { if (event.data.size) chunks.push(event.data); };
      recorder.onstop = async () => {
        stream.getTracks().forEach((track) => track.stop());
        const blob = new Blob(chunks, {type: chunks[0] ? chunks[0].type : "audio/webm"});
        state.lastAudio = await pcmFromBlob(blob);
      };
      recorder.start();
      state.recorder = recorder;
    } catch (_) { /* no microphone: text still works */ }
  }

  const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
  if (!SpeechRecognition) {
    line("sys", "note", "this browser has no speech recognition; type instead — audio is still recorded and stored.");
    return;
  }
  const recognition = new SpeechRecognition();
  recognition.lang = language();
  recognition.continuous = false;
  recognition.interimResults = true;
  recognition.onresult = (event) => {
    let text = "";
    for (const result of event.results) text += result[0].transcript;
    $("typed").value = text;
  };
  recognition.onerror = (event) => line("sys", "note", "speech recognition: " + event.error);
  recognition.onend = async () => {
    state.listening = false;
    $("mic").classList.remove("listening");
    $("mic").textContent = "🎙 press to talk";
    if (state.recorder && state.recorder.state === "recording") state.recorder.stop();
    const text = $("typed").value.trim();
    if (text) {
      $("typed").value = "";
      line("me", "you", text + (state.lastAudio ? "  🎧" : ""));
      await turn(text, state.lastAudio || null);
      state.lastAudio = null;
    }
  };
  recognition.start();
  state.recognition = recognition;
  state.listening = true;
  $("mic").classList.add("listening");
  $("mic").textContent = "● listening… (press to stop)";
}

function stopListening() {
  state.listening = false;
  if (state.recognition) { try { state.recognition.stop(); } catch (_) {} }
  if (state.recorder && state.recorder.state === "recording") state.recorder.stop();
}

// -- panels ------------------------------------------------------------------
async function loadHealth() {
  try {
    const health = await api("/api/voice/health");
    state.health = health;
    const development = health.enforcement === "development";
    $("pill-enforcement").className = "pill " + (development ? "warn" : "ok");
    $("pill-enforcement").textContent = "enforcement: " + health.enforcement;
    const encrypted = health.memory.encrypted;
    $("pill-memory").className = "pill " + (encrypted ? "ok" : "warn");
    $("pill-memory").textContent = "memory: " + (encrypted ? "sealed" : "NOT sealed");
    $("pill-provider").textContent = "answerer: " + health.provider.provider +
      (health.provider.online ? "" : " (rule-based fallback)");
    const rows = [
      ["enforcement", health.enforcement],
      ["memory store", health.memory.encrypted ? "sealed (" + health.memory.scheme.split(" ")[0] + ")" : "plaintext"],
      ["owner key", health.memory.owner_key],
      ["answerer", health.provider.provider + (health.provider.online ? "" : " (offline, rule-based)")],
      ["connected agents", health.agents.connected + " (concurrency " + health.agents.concurrency + ")"],
      ["session", state.session],
    ];
    $("posture").innerHTML = rows.map(([key, value]) =>
      '<div class="stat"><span>' + key + '</span><b>' + String(value) + "</b></div>").join("") +
      '<p class="muted" style="margin:9px 0 0">' + health.memory.limits.map((item) => "• " + item).join("<br>") + "</p>";
    if (!encrypted) {
      line("sys", "note", "memory is NOT sealed: set ZENO_MEMORY_KEY and restart the server to seal what you say.");
    }
  } catch (error) {
    line("err", "error", "cannot reach the server: " + error.message);
  }
}

async function loadPeers() {
  const box = $("peers");
  box.textContent = "";
  try {
    const {agents} = await api("/api/agents?nonce=" + freshNonce());
    if (!agents.length) {
      const empty = document.createElement("p");
      empty.className = "muted";
      empty.textContent = "no agents connected yet. Paste an endpoint above; a peer that answers "
        + "POST /ask with {\"reply\": …} is enough.";
      box.appendChild(empty);
      return;
    }
    agents.forEach((peer) => {
      const card = document.createElement("div");
      card.className = "peer";
      const name = document.createElement("div");
      name.className = "name";
      name.textContent = peer.name;
      const detail = document.createElement("div");
      detail.className = "muted";
      detail.textContent = peer.endpoint + " · " + (peer.capability ? "grant set" : "no grant")
        + " · calls " + peer.calls + " · failures " + peer.failures
        + (peer.last_error ? " · last: " + peer.last_error : "");
      const actions = document.createElement("div");
      actions.className = "row";
      const askButton = document.createElement("button");
      askButton.textContent = "ask";
      askButton.addEventListener("click", () => askPeer(peer.name));
      const removeButton = document.createElement("button");
      removeButton.textContent = "disconnect";
      removeButton.addEventListener("click", async () => {
        await post("/api/agents/remove", {name: peer.name});
        await loadPeers();
      });
      actions.appendChild(askButton);
      actions.appendChild(removeButton);
      card.appendChild(name);
      card.appendChild(detail);
      card.appendChild(actions);
      box.appendChild(card);
    });
  } catch (error) {
    box.textContent = "";
    const problem = document.createElement("p");
    problem.className = "muted";
    problem.textContent = String(error.message || error);
    box.appendChild(problem);
  }
}

async function askPeer(name) {
  const text = $("typed").value.trim() || window.prompt("ask " + name + ":");
  if (!text) return;
  line("me", "you → " + name, text);
  try {
    const result = await post("/api/agents/ask", {name, text, lang: language(), session: state.session});
    line(result.ok ? "agent" : "err", "peer · " + name, result.reply || result.error || "(nothing)",
      result.ok ? result.elapsed_ms + " ms · stored" : result.code || "");
    if (result.ok) speak(result.reply || "");
  } catch (error) {
    line("err", "peer · " + name, error.message);
  }
}

async function loadSessions() {
  try {
    const {sessions} = await api("/api/memory/sessions?nonce=" + freshNonce());
    $("sessions").innerHTML = sessions.length
      ? sessions.map((item) =>
          '<div class="stat"><span>' + item.id + "</span><b>" + item.turns + " records · " +
          (item.languages.join(", ") || "no tag") + '</b></div>').join("")
      : '<p class="muted">nothing stored yet.</p>';
  } catch (error) {
    $("sessions").innerHTML = '<p class="muted">' + error.message + "</p>";
  }
}

// -- wiring ------------------------------------------------------------------
$("mic").addEventListener("click", () => (state.listening ? stopListening() : startListening()));
$("send").addEventListener("click", sendTyped);
$("typed").addEventListener("keydown", (event) => { if (event.key === "Enter") { event.preventDefault(); sendTyped(); } });
$("new-session").addEventListener("click", () => {
  state.session = "voice-" + new Date().toISOString().replace(/[:.]/g, "-");
  $("session-label").textContent = "session: " + state.session;
  line("sys", "note", "new session: " + state.session);
  loadSessions();
});
$("lang").addEventListener("change", () => { $("pill-lang").textContent = "lang: " + language(); });
$("lang-free").addEventListener("input", () => { $("pill-lang").textContent = "lang: " + language(); });
$("peer-add").addEventListener("click", async () => {
  try {
    await post("/api/agents", {
      name: $("peer-name").value.trim(),
      endpoint: $("peer-url").value.trim(),
      capability: $("peer-grant").value,
    });
    $("peer-name").value = ""; $("peer-url").value = ""; $("peer-grant").value = "";
    await loadPeers();
  } catch (error) { line("err", "connect", error.message); }
});
$("peer-broadcast").addEventListener("click", async () => {
  const text = $("typed").value.trim() || window.prompt("broadcast to every connected agent:");
  if (!text) return;
  line("me", "you → all agents", text);
  try {
    const result = await post("/api/agents/broadcast", {text, lang: language(), session: state.session});
    $("broadcast-out").hidden = false;
    $("broadcast-out").textContent = JSON.stringify(result, null, 2);
    line(result.ok ? "agent" : "err", "broadcast",
      result.answered + "/" + result.asked + " agents answered", result.elapsed_ms + " ms");
  } catch (error) { line("err", "broadcast", error.message); }
});
$("search-go").addEventListener("click", async () => {
  try {
    const result = await post("/api/memory/search", {query: $("search").value});
    $("search-out").hidden = false;
    $("search-out").textContent = result.hits.length
      ? result.hits.map((hit) => hit.at_iso || hit.at + "  " + hit.role + ": " + hit.text).join("\n")
      : "no matches (search is a substring scan over decrypted records, not a semantic index)";
  } catch (error) { $("search-out").hidden = false; $("search-out").textContent = error.message; }
});
$("verify").addEventListener("click", async () => {
  try {
    const report = await api("/api/memory/verify?nonce=" + freshNonce());
    $("verify-out").hidden = false;
    $("verify-out").textContent = JSON.stringify(report, null, 2);
  } catch (error) { $("verify-out").hidden = false; $("verify-out").textContent = error.message; }
});

(async function start() {
  $("session-label").textContent = "session: " + state.session;
  if (state.token) line("sys", "note", "a capability grant is stored in this browser and is sent with every turn.");
  else line("sys", "note", "no grant stored. In production enforcement a turn needs one: `python -m aegis owner issue …`, then paste it in the dashboard's `token` command.");
  line("sys", "note", "press the microphone, or type. Everything you say is stored — sealed, when the server has an owner key.");
  await loadHealth();
  await loadPeers();
  await loadSessions();
})();
