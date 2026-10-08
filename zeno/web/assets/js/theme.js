/* ==========================================================================
   Qevora AI SaaS — Bootstrap 5 Admin & UI Kit
   theme.js — Light / dark colour mode
   --------------------------------------------------------------------------
   Uses Bootstrap 5.3's native colour modes: the colour mode is written to the
   <html> element as data-bs-theme="light|dark" and every Qevora token in
   style.css switches with it.

   Public API (window.QevoraTheme):
     QevoraTheme.get()              -> "light" | "dark"
     QevoraTheme.getPreference()    -> "light" | "dark" | "system"
     QevoraTheme.set("dark")        -> applies and stores
     QevoraTheme.toggle()           -> flips light <-> dark
     QevoraTheme.setPreference("system")
     QevoraTheme.onChange(fn)       -> subscribe to changes
   ========================================================================== */

(function () {
  "use strict";

  var STORAGE_KEY = "qevora-theme";
  var MEDIA = window.matchMedia ? window.matchMedia("(prefers-color-scheme: dark)") : null;
  var listeners = [];

  /* localStorage throws in private mode, inside sandboxed frames and when the
     template is opened straight from disk (file://). The choice is mirrored in
     memory so the toggle still works in those previews — it just does not
     survive a reload. */
  var memoryPreference = null;

  function readStored() {
    var stored = null;
    try {
      stored = window.localStorage.getItem(STORAGE_KEY);
    } catch (e) {
      stored = null;
    }
    return stored === null ? memoryPreference : stored;
  }

  function writeStored(value) {
    memoryPreference = value;
    try {
      window.localStorage.setItem(STORAGE_KEY, value);
    } catch (e) {
      /* keep the in-memory value */
    }
  }

  function systemTheme() {
    return MEDIA && MEDIA.matches ? "dark" : "light";
  }

  function getPreference() {
    var stored = readStored();
    if (stored === "light" || stored === "dark" || stored === "system") {
      return stored;
    }
    return "system";
  }

  function resolve(preference) {
    return preference === "system" ? systemTheme() : preference;
  }

  function get() {
    return document.documentElement.getAttribute("data-bs-theme") === "dark" ? "dark" : "light";
  }

  function notify(theme, preference) {
    for (var i = 0; i < listeners.length; i++) {
      try {
        listeners[i](theme, preference);
      } catch (e) {
        /* keep other listeners alive */
      }
    }

    document.dispatchEvent(
      new CustomEvent("qevora:themechange", { detail: { theme: theme, preference: preference } })
    );

    // Let Chart.js pages that listen on the media query re-render.
    window.dispatchEvent(new CustomEvent("qevora:repaint"));
  }

  function apply(theme) {
    document.documentElement.setAttribute("data-bs-theme", theme);
    document.documentElement.style.colorScheme = theme;
  }

  function paint() {
    var preference = getPreference();
    var theme = resolve(preference);
    apply(theme);
    syncToggles(theme);
    return theme;
  }

  function setPreference(preference) {
    if (preference !== "light" && preference !== "dark" && preference !== "system") {
      preference = "system";
    }
    writeStored(preference);
    var theme = paint();
    notify(theme, preference);
    return theme;
  }

  function set(theme) {
    return setPreference(theme === "dark" ? "dark" : "light");
  }

  function toggle() {
    var next = get() === "dark" ? "light" : "dark";
    set(next);
    return next;
  }

  function onChange(fn) {
    if (typeof fn === "function") {
      listeners.push(fn);
    }
  }

  /* Keep every toggle button on the page in sync (icon, label, aria-pressed) */
  function syncToggles(theme) {
    var buttons = document.querySelectorAll("[data-theme-toggle]");
    for (var i = 0; i < buttons.length; i++) {
      var btn = buttons[i];
      var isDark = theme === "dark";
      var icon = btn.querySelector("[data-theme-icon]");
      var label = btn.querySelector("[data-theme-label]");

      if (icon) {
        icon.className = isDark ? "bi bi-sun" : "bi bi-moon-stars";
      }
      if (label) {
        label.textContent = isDark ? "Light mode" : "Dark mode";
      }
      btn.setAttribute("aria-pressed", isDark ? "true" : "false");
      btn.setAttribute("title", isDark ? "Switch to light mode" : "Switch to dark mode");
    }
  }

  /* Apply as early as possible to avoid a flash of the wrong theme */
  paint();

  document.addEventListener("DOMContentLoaded", function () {
    paint();

    document.addEventListener("click", function (event) {
      var trigger = event.target.closest("[data-theme-toggle]");
      if (!trigger) return;
      event.preventDefault();
      toggle();
    });

    if (MEDIA) {
      var mediaListener = function () {
        if (getPreference() === "system") {
          var theme = paint();
          notify(theme, "system");
        }
      };
      if (typeof MEDIA.addEventListener === "function") {
        MEDIA.addEventListener("change", mediaListener);
      } else if (typeof MEDIA.addListener === "function") {
        MEDIA.addListener(mediaListener);
      }
    }
  });

  window.QevoraTheme = {
    get: get,
    set: set,
    toggle: toggle,
    getPreference: getPreference,
    setPreference: setPreference,
    onChange: onChange,
    storageKey: STORAGE_KEY
  };
})();
