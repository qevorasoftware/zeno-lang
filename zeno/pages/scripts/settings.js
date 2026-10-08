  "use strict";
  const state = { token: localStorage.getItem("zeno.token") || "", presets: [] };
  const $ = (id) => document.getElementById(id);

  function freshNonce() {
    try {
      const bytes = new Uint8Array(16);
      crypto.getRandomValues(bytes);
      return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
    } catch (_) { return String(Date.now()) + Math.random().toString(16).slice(2); }
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

  function explainCode(code) {
    // Public refusal codes, translated for the owner driving this page. The
    // codes live in the repository's docs; saying what they mean hides nothing
    // from an attacker, but it stops the owner from guessing.
    const hints = {
      "ZN-SEC-0x9A01": "no readable grant reached the server — paste the grant with the grant button as ONE unbroken line, then try once",
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

  async function api(path, options) {
    const request = Object.assign({}, options);
    request.headers = Object.assign({ "Content-Type": "application/json" }, request.headers || {});
    if (state.token) request.headers["X-Zeno-Capability"] = state.token;
    const url = (request.method === "GET" || !request.method)
      ? path + (path.includes("?") ? "&" : "?") + "nonce=" + freshNonce()
      : path;
    const response = await fetch(url, request);
    let payload = null;
    try { payload = await response.json(); } catch (_) { payload = null; }
    if (!response.ok) {
      const error = payload && payload.error ? payload.error : null;
      const parts = error ? [error.code, error.message].filter(Boolean) : ["HTTP " + response.status];
      const hint = explainCode(error ? error.code : "");
      if (hint) parts.push(hint);
      const failure = new Error(parts.join(" — "));
      failure.status = response.status;
      failure.code = error ? error.code : "";
      throw failure;
    }
    if (payload && payload.decoy === true) {
      throw decoyError();
    }
    return payload;
  }
  const post = (path, body) => api(path, { method: "POST", body: JSON.stringify(Object.assign({ nonce: freshNonce() }, body)) });

  function toast(title, body, variant) {
    if (typeof bootstrap === "undefined") return;
    const element = document.createElement("div");
    element.className = "toast align-items-center border-0 text-bg-" + (variant || "dark");
    element.setAttribute("role", "alert");
    const flex = document.createElement("div");
    flex.className = "d-flex";
    const content = document.createElement("div");
    content.className = "toast-body";
    const head = document.createElement("strong");
    head.className = "d-block";
    head.textContent = title;
    content.appendChild(head);
    const text = document.createElement("span");
    text.className = "code-chip";
    text.textContent = body;
    content.appendChild(text);
    flex.appendChild(content);
    const close = document.createElement("button");
    close.className = "btn-close me-2 m-auto";
    close.setAttribute("data-bs-dismiss", "toast");
    flex.appendChild(close);
    element.appendChild(flex);
    $("toasts").appendChild(element);
    new bootstrap.Toast(element, { delay: 6000 }).show();
    element.addEventListener("hidden.bs.toast", () => element.remove());
  }

  function timelineItem(list, title, meta) {
    const li = document.createElement("li");
    li.className = "timeline__item";
    const dot = document.createElement("span");
    dot.className = "timeline__dot timeline__dot--muted";
    const t = document.createElement("p");
    t.className = "timeline__title";
    t.textContent = title;
    const m = document.createElement("p");
    m.className = "timeline__meta";
    m.textContent = meta;
    li.appendChild(dot); li.appendChild(t); li.appendChild(m);
    list.appendChild(li);
  }

  function render(info) {
    const rows = $("provider-rows");
    rows.textContent = "";
    const select = $("t-name");
    select.textContent = "";
    (info.profiles || []).forEach((profile) => {
      const tr = document.createElement("tr");
      const status = document.createElement("td");
      const avatar = document.createElement("span");
      avatar.className = "avatar avatar-xs " + (profile.active ? "bg-avatar-3" : "bg-avatar-8");
      status.appendChild(avatar);
      tr.appendChild(status);
      const name = document.createElement("td");
      name.className = "fw-600 text-heading";
      name.textContent = profile.name;
      tr.appendChild(name);
      const provider = document.createElement("td");
      const badge = document.createElement("span");
      badge.className = "badge badge-soft-primary badge-pill";
      badge.textContent = profile.provider;
      provider.appendChild(badge);
      tr.appendChild(provider);
      const model = document.createElement("td");
      model.className = "code-chip fs-7";
      model.textContent = profile.model || "—";
      tr.appendChild(model);
      const key = document.createElement("td");
      if (profile.has_key) {
        const hint = document.createElement("span");
        hint.className = "badge badge-soft-success badge-pill code-chip";
        hint.textContent = profile.key_hint;
        hint.title = "stored — never displayed in full anywhere";
        key.appendChild(hint);
      } else if (profile.ready) {
        const local = document.createElement("span");
        local.className = "badge badge-soft-secondary badge-pill";
        local.textContent = "local, no key needed";
        key.appendChild(local);
      } else {
        const missing = document.createElement("span");
        missing.className = "badge badge-soft-warning badge-pill";
        missing.textContent = "no key yet";
        key.appendChild(missing);
      }
      tr.appendChild(key);
      const active = document.createElement("td");
      const chip = document.createElement("span");
      chip.className = "badge badge-soft-" + (profile.active ? "success" : "secondary") + " badge-pill";
      chip.textContent = profile.active ? "active" : "kept";
      active.appendChild(chip);
      tr.appendChild(active);

      const actions = document.createElement("td");
      actions.className = "text-end";
      if (!profile.active) {
        const activate = document.createElement("button");
        activate.className = "btn btn-sm btn-white me-1";
        activate.textContent = "activate";
        activate.addEventListener("click", async () => {
          try {
            const out = await post("/api/settings/activate", { name: profile.name });
            const good = out && out.provider;
            toast(good ? "Active provider" : "Not switched",
                  good ? out.provider.provider + " · " + (out.provider.model || "")
                       : savedLabel(out),
                  good ? "success" : "warning");
            load();
          } catch (error) { toast("Refused", String(error.message || error), "danger"); }
        });
        actions.appendChild(activate);
      }
      const test = document.createElement("button");
      test.className = "btn btn-sm btn-white me-1";
      test.textContent = "test";
      test.addEventListener("click", () => runTest(profile.name));
      actions.appendChild(test);
      const remove = document.createElement("button");
      remove.className = "btn btn-sm btn-soft-danger";
      remove.textContent = "remove";
      remove.addEventListener("click", async () => {
        if (!window.confirm("Remove " + profile.name + " and forget its key?")) return;
        try {
          await post("/api/settings/remove", { name: profile.name });
          toast("Removed", profile.name, "secondary");
          load();
        } catch (error) { toast("Refused", String(error.message || error), "danger"); }
      });
      actions.appendChild(remove);
      tr.appendChild(actions);
      rows.appendChild(tr);

      const option = document.createElement("option");
      option.value = profile.name;
      // name and provider can be the same word ("openai" named "openai"):
      // saying it twice is noise, not information
      option.textContent = profile.name === profile.provider
        ? profile.name
        : profile.name + " (" + profile.provider + ")";
      select.appendChild(option);
    });

    if (!(info.profiles || []).length) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = 7;
      td.className = "fs-7 text-muted-2";
      td.textContent = "no providers yet — add one below";
      tr.appendChild(td);
      rows.appendChild(tr);
    }

    // header + sidebar state
    const active = info.active;
    $("active-name").value = active ? active.name + " · " + active.model : "no provider yet";
    const pill = $("pill-provider");
    pill.hidden = !active;
    if (active) pill.textContent = "answering through: " + active.provider;
    const sealed = $("pill-sealed");
    sealed.hidden = false;
    sealed.className = "badge badge-soft-" + (info.encrypted ? "success" : "warning") + " badge-pill";
    sealed.textContent = info.encrypted ? "keys: sealed" : "keys: NOT sealed";
    $("store-file").textContent = info.file || "";
    $("store-state").textContent = info.encrypted ? "keys sealed at rest" : "keys stored unsealed (0600)";

    const limits = $("limits");
    limits.textContent = "";
    (info.limits || []).forEach((line) => timelineItem(limits, line.split(":")[0], line.split(":").slice(1).join(":").trim() || "—"));

    // the provider dropdown in the form
    if ((info.presets || []).length && !state.presets.length) {
      state.presets = info.presets;
      const picker = $("f-provider");
      picker.textContent = "";
      info.presets.filter((preset) => preset.slug !== "mock" && preset.slug !== "none").forEach((preset) => {
        const option = document.createElement("option");
        option.value = preset.slug;
        option.textContent = preset.slug + (preset.needs_key ? " (needs a key)" : " (local, no key)");
        picker.appendChild(option);
      });
      picker.addEventListener("change", () => {
        const preset = state.presets.find((item) => item.slug === picker.value);
        if (preset) {
          // The name field is the owner's own label, not the provider: keep its
          // example in step with the provider they are configuring, so the
          // placeholder never looks like a wrong default.
          $("f-name").placeholder = "your own label, e.g. " + preset.slug + "-main";
          $("f-model").value = "";
          $("f-model").placeholder = preset.model || "preset default";
          $("f-base").value = "";
          $("f-base").placeholder = preset.base_url || "preset default";
        }
      });
    }
  }

  async function load() {
    let info;
    try {
      info = await api("/api/settings");
    } catch (error) {
      $("offline-note").hidden = false;
      if (error && error.decoy) toast("Tarpitted", String(error.message || error), "danger");
      return;
    }
    if (info.locked) {
      $("locked-note").hidden = false;
      $("locked-reason").textContent = info.locked;
    }
    render(info);
  }

  // A 200 is not a promise about shape: describe whatever came back, so an
  // unexpected answer is shown as what it is instead of crashing the toast.
  function savedLabel(result) {
    if (result && result.profile && result.profile.name) {
      const info = result.provider || {};
      return result.profile.name + " · " + (info.provider || "?") + (info.online ? " · online" : "");
    }
    if (result && result.error) {
      return [result.error.code, result.error.message].filter(Boolean).join(" — ");
    }
    return "unexpected answer: " + JSON.stringify(result).slice(0, 180);
  }

  async function runTest(name) {
    const out = $("t-out");
    out.hidden = false;
    out.textContent = "testing " + name + " …";
    try {
      const result = await post("/api/settings/test", { name });
      out.textContent = JSON.stringify(result, null, 2);
      toast(name, result.ok ? "answered: " + (result.reply || "").slice(0, 40) : "unavailable", result.ok ? "success" : "warning");
    } catch (error) {
      out.textContent = String(error.message || error);
      toast("Test refused", String(error.code || error.message), "danger");
    }
  }

  $("t-go").addEventListener("click", () => runTest($("t-name").value));

  $("f-save").addEventListener("click", async () => {
    const name = $("f-name").value.trim();
    const provider = $("f-provider").value;
    if (!name || !provider) {
      toast("Missing", "a name and a provider are needed", "warning");
      return;
    }
    const body = { name, provider, model: $("f-model").value.trim(), base_url: $("f-base").value.trim() };
    const key = $("f-key").value;
    if (key) body.api_key = key;  // blank keeps the stored one; that is the documented rule
    try {
      const result = await post("/api/settings/providers", body);
      $("f-key").value = "";
      const good = result && result.profile;
      toast(good ? "Saved" : "Not saved", savedLabel(result), good ? "success" : "warning");
      load();
    } catch (error) {
      toast("Refused", String(error.message || error), "danger");
    }
  });

  $("grant-btn").addEventListener("click", () => {
    const value = window.prompt(
      "Owner grant\n\nPaste an owner-issued grant (python -m aegis owner issue …).\nDevelopment needs none; production refuses every change without one.",
      state.token
    );
    if (value === null) return;
    // A terminal wraps a long grant when it prints it, and a wrapped paste is
    // not a token. Base64 carries no whitespace, so every run of it is damage.
    state.token = value.replace(/\s+/g, "");
    if (state.token) localStorage.setItem("zeno.token", state.token);
    else localStorage.removeItem("zeno.token");
    toast("Grant", state.token ? "stored in this browser" : "cleared", "secondary");
    load();
  });

  load();
  
