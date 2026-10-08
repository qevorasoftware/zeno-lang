const $ = (id) => document.getElementById(id);
let last = null;

const EXAMPLES = [
  "Hi! Could you please check the current weather conditions in Tokyo for me? I would like to know whether it is raining right now, and if it is raining, please suggest three indoor activities that would work well on a rainy day. Otherwise, if it is not raining, suggest three outdoor activities instead. Thanks so much!",
  "Please help me total up this invoice. We have 3 units at 129.99 each and 2 units at 45.50 each. Once you have the total, I need to know whether we have gone over the 500 budget threshold, and please be sure to tell me the final number along with your verdict. Thank you!",
  "As the planning agent I am delegating to you, the researcher agent: I need you to search for the most important recent academic papers about the Zeno Protocol for inter-agent communication, then produce a summary of the top five results in a form that I can forward to the writing team without further editing.",
  "Please monitor the deployment pipeline for me and let me know the moment it finishes. If the deployment has failed for any reason, immediately open a support ticket so that somebody picks it up, but if everything went through fine then simply record that the deployment succeeded in the log.",
  "[terse] Alert me if the stock drops below 120.",
];
EXAMPLES.forEach((text) => {
  const chip = document.createElement("span");
  chip.className = "chip";
  const label = text.replace(/^\[terse\]\s*/, "");
  chip.textContent = label.length > 52 ? label.slice(0, 49) + "…" : label;
  if (text.startsWith("[terse]")) chip.textContent = "(terse) " + chip.textContent;
  chip.title = text;
  chip.onclick = () => { $("nl").value = text; };
  $("examples").appendChild(chip);
});

function freshNonce() {
  try {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  } catch (_) { return String(Date.now()) + Math.random().toString(16).slice(2); }
}

function explainCode(code) {
  // Public refusal codes, translated for the person driving this page. The
  // codes hide nothing from an attacker, but they stop the owner guessing.
  const hints = {
    "ZN-SEC-0x9A01": "no readable grant reached the server — paste the grant with the grant button (top right) as ONE unbroken line, then try once",
    "ZN-SEC-0x9A05": "the grant was issued for a different audience (check the owner export and issue commands)",
    "ZN-SEC-0x9A06": "the owner epoch moved (rotate-epoch): re-export ZENO_OWNER_PUBLIC",
    "ZN-SEC-0x9A07": "the grant expired — issue a fresh one",
    "ZN-SEC-0x9A08": "the grant was revoked",
    "ZN-SEC-0x9A02": "the grant was not signed by this deployment's owner key — re-export ZENO_OWNER_PUBLIC from the same root that issued the grant",
    "ZN-SEC-0x9A09": "the grant does not cover this action — re-issue it with the right --capability (execute:* to run, settings:* to save, read:* to read)",
    "ZN-SEC-0x9A0A": "the grant was bound to one semantic scope (a particular payload shape) and this request is not it",
    "ZN-SEC-0x9A0D": "this deployment has no owner public key (ZENO_OWNER_PUBLIC), so no grant can be honoured",
    "ZN-SEC-0x0A01": "the request carried no nonce — a stale cached page does that; hard-refresh (Ctrl+Shift+R)"
  };
  return hints[code] || "";
}

async function api(path, body) {
  // The settings page's grant button and the dashboard's `token` command
  // store the grant under the same key: pasted once, it drives every page.
  const token = localStorage.getItem("zeno.token") || "";
  const headers = { "Content-Type": "application/json" };
  if (token) headers["X-Zeno-Capability"] = token;
  const init = { method: body === undefined ? "GET" : "POST", headers };
  if (body === undefined) {
    path = path + (path.includes("?") ? "&" : "?") + "nonce=" + freshNonce();
  } else {
    init.body = JSON.stringify(Object.assign({ nonce: freshNonce() }, body));
  }
  const response = await fetch(path, init);
  const data = await response.json();
  if (!response.ok) throw data;
  if (data && data.decoy === true) {
    throw { error: { code: "TARPIT", message: "the guardian is tarpitting this browser: repeated refused attempts are answered with fabricated decoys, so nothing actually happened — fix the refusal underneath (usually the grant) and try once" } };
  }
  return data;
}

function show(payload) {
  const value = typeof payload === "string" ? payload : JSON.stringify(payload, null, 2);
  $("out").textContent = value;
  return value;
}

function setStats(items) {
  $("stats").innerHTML = items.map(([value, label, cls]) =>
    `<div class="stat"><b class="${cls || ""}">${value}</b><small>${label}</small></div>`).join("");
}

function errorText(payload) {
  const error = payload.error || payload;
  const parts = error && (error.code || error.message)
    ? [error.code, error.message].filter(Boolean)
    : [error.rendered || JSON.stringify(error)];
  const hint = explainCode(error && error.code ? error.code : "");
  if (hint) parts.push(hint);
  return parts.join(" — ");
}

async function doEncode() {
  const text = $("nl").value.trim();
  if (!text) return;
  try {
    const data = await api("/api/encode", { text });
    $("zeno").value = data.payload;
    last = { encode: data };
    setStats([
      [data.nl_tokens, "NL tokens"],
      [data.zeno_tokens, "Zeno tokens"],
      [data.token_reduction_pct.toFixed(1) + "%", "reduction",
        data.token_reduction_pct >= 75 ? "good" : data.token_reduction_pct > 0 ? "mid" : "bad"],
      [data.fell_back ? "rules" : "model", "encoder"],
      [data.attempts, "attempts"],
    ]);
    show({ payload: data.payload, warnings: data.warnings, validation: data.validation });
  } catch (error) { show(errorText(error)); }
}

async function doRun() {
  const payload = $("zeno").value.trim();
  if (!payload) return;
  try {
    const data = await api("/api/run", { payload });
    last = { ...(last || {}), run: data };
    setStats([
      [data.duration_ms.toFixed(2) + " ms", "kernel time"],
      [data.steps.length, "steps"],
      [data.calls.length, "tool calls"],
      [data.returned ? "yes" : "no", "!RET reached"],
    ]);
    show(data.frame + "\n\n" + data.context);
  } catch (error) { show(errorText(error)); }
}

async function doAsk() {
  const text = $("nl").value.trim();
  if (!text) return;
  try {
    const data = await api("/api/ask", { text });
    $("zeno").value = data.payload;
    $("answer").textContent = data.response || "—";
    last = { ask: data };
    setStats([
      [data.encode.nl_tokens, "NL tokens"],
      [data.encode.zeno_tokens, "Zeno tokens"],
      [data.encode.token_reduction_pct.toFixed(1) + "%", "reduction",
        data.encode.token_reduction_pct >= 75 ? "good" : data.encode.token_reduction_pct > 0 ? "mid" : "bad"],
      [data.total_ms.toFixed(1) + " ms", "total latency"],
      [data.decode && data.decode.fell_back ? "deterministic" : "model", "decoder"],
    ]);
    show(data.transcript);
  } catch (error) { show(errorText(error)); }
}

async function doCheck() {
  try {
    const data = await api("/api/run", { payload: $("zeno").value.trim(), state: {} });
    const diagnostics = (data.validation.diagnostics || []);
    const ok = data.validation.ok;
    $("check-out").innerHTML = ok
      ? '<span class="good">valid Zeno Grammar v0.1</span>'
      : '<span class="bad">' + diagnostics.map((d) => d.code + ": " + d.message).join("; ") + "</span>";
  } catch (error) {
    $("check-out").innerHTML = '<span class="bad">' + errorText(error).split("\n")[0] + "</span>";
  }
}

async function doBench() {
  try {
    const data = await api("/api/benchmark");
    const density = data.density.reduction;
    const conversation = data.conversation.reduction;
    show({
      per_message_density: {
        pooled_reduction_pct: density.pooled_pct,
        mean_reduction_pct: density.mean_pct,
        target_pct: data.density.target_reduction_pct,
        meets_target: density.meets_target,
      },
      multi_turn_a2a: {
        per_hop_reduction_pct: conversation.per_hop_pct,
        cold_start_pct: conversation.cold_start_pct,
        steady_state_pct_10_workflows: conversation.steady_state_pct_10_workflows,
        break_even_hops: conversation.break_even_hops,
        meets_target: conversation.meets_target,
      },
      encoder_system_prompt_tokens: data.density.encoder.system_prompt_tokens,
    });
  } catch (error) { show(errorText(error)); }
}

document.querySelectorAll(".tab").forEach((tab) => {
  tab.onclick = () => {
    document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
    tab.classList.add("active");
    const which = tab.dataset.tab;
    if (which === "bench") return doBench();
    if (!last) return show("run something first");
    if (which === "frame" && last.run) return show(last.run.frame + "\n\n" + last.run.context);
    if (which === "trace" && last.run) return show(last.run.calls);
    if (which === "transcript" && last.ask) return show(last.ask.transcript);
    return show(JSON.stringify(last, null, 2));
  };
});

const grantBtn = $("grant-btn");
function paintGrant() {
  if (grantBtn) grantBtn.textContent = localStorage.getItem("zeno.token") ? "🔑 grant ✓" : "🔑 grant";
}
if (grantBtn) grantBtn.onclick = () => {
  const value = window.prompt(
    "Owner grant\n\nPaste an owner-issued grant (python -m aegis owner issue …).\nDevelopment needs none; production refuses every run without one.",
    localStorage.getItem("zeno.token") || ""
  );
  if (value === null) return;
  // A terminal wraps a long grant when it prints it, and a wrapped paste is
  // not a token. Base64 carries no whitespace, so every run of it is damage.
  const token = value.replace(/\s+/g, "");
  if (token) localStorage.setItem("zeno.token", token);
  else localStorage.removeItem("zeno.token");
  paintGrant();
  show(token ? "grant stored in this browser — try once" : "grant cleared");
};
paintGrant();

$("encode").onclick = doEncode;
$("run").onclick = doRun;
$("ask").onclick = doAsk;
$("check").onclick = doCheck;

api("/api/health").then((data) => {
  $("status").innerHTML = data.online
    ? '<span class="good">● live model</span> · ' + data.provider + " · " + data.model
    : '<span class="mid">● offline mode</span> · deterministic demo tools';
  $("provider").textContent = "provider: " + data.provider + " · tokenizer: " + data.tokenizer;
}).catch(() => { $("status").textContent = "server unreachable"; });

doAsk();
