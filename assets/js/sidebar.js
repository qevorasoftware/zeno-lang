/* ==========================================================================
   Qevora AI SaaS — Bootstrap 5 Admin & UI Kit
   sidebar.js — Sidebar behaviour (desktop, tablet, mobile) + RTL switching
   --------------------------------------------------------------------------
   Behaviour by breakpoint:
     >= 992px  : expanded sidebar, optional compact/collapsed mode
     992-1200  : compact mode suggested (applied automatically on first visit)
     <  992px  : off-canvas drawer with backdrop

   Public API (window.QevoraSidebar):
     QevoraSidebar.open() / close() / toggle()
     QevoraSidebar.setCompact(true|false)
     QevoraSidebar.toggleCompact()
     QevoraSidebar.setDirection("ltr" | "rtl")
     QevoraSidebar.toggleDirection()
   ========================================================================== */

(function () {
  "use strict";

  var COMPACT_KEY = "qevora-sidebar-compact";
  var DIR_KEY = "qevora-direction";

  var BREAKPOINT = 992;
  var COMPACT_BREAKPOINT = 1200;

  var LTR_HREF = "bootstrap.min.css";
  var RTL_HREF = "bootstrap.rtl.min.css";

  var body = document.body;

  /* Same storage caveat as theme.js: private mode, sandboxed frames and file://
     previews block localStorage, so the last choice is also held in memory. */
  var memory = {};

  function store(key, value) {
    memory[key] = value;
    try {
      window.localStorage.setItem(key, value);
    } catch (e) { /* ignore */ }
  }

  function read(key) {
    try {
      var stored = window.localStorage.getItem(key);
      return stored === null ? (memory[key] !== undefined ? memory[key] : null) : stored;
    } catch (e) {
      return memory[key] !== undefined ? memory[key] : null;
    }
  }

  /* ------------------------------------------------------------------ */
  /* Mobile drawer                                                       */
  /* ------------------------------------------------------------------ */

  /* The backdrop ships in the markup of every page (src/partials/sidebar.html),
     so it always exists by the time this runs. Binding the click only in the
     branch that CREATES the element meant the listener was never attached on a
     real page: tapping the dimmed page behind an open drawer did nothing, and
     the only ways out were the Esc key or a nav link. The handler is bound
     once, whether the element was found or made. */
  function backdrop() {
    var el = document.querySelector(".q-sidebar-backdrop");
    if (!el) {
      el = document.createElement("div");
      el.className = "q-sidebar-backdrop";
      el.setAttribute("aria-hidden", "true");
      body.appendChild(el);
    }
    if (!el.__qBackdropBound) {
      el.__qBackdropBound = true;
      el.addEventListener("click", close);
    }
    return el;
  }

  function isMobile() {
    return window.innerWidth < BREAKPOINT;
  }

  function setDrawerExpanded(value) {
    var togglers = document.querySelectorAll("[data-sidebar-toggle]");
    for (var i = 0; i < togglers.length; i++) {
      togglers[i].setAttribute("aria-expanded", value ? "true" : "false");
    }
  }

  function open() {
    body.classList.add("q-sidebar-open");
    backdrop();
    setDrawerExpanded(true);
  }

  function close() {
    body.classList.remove("q-sidebar-open");
    setDrawerExpanded(false);
  }

  function toggle() {
    if (isMobile()) {
      if (body.classList.contains("q-sidebar-open")) {
        close();
      } else {
        open();
      }
    } else {
      toggleCompact();
    }
  }

  /* ------------------------------------------------------------------ */
  /* Compact (collapsed) desktop sidebar                                 */
  /* ------------------------------------------------------------------ */

  function setCompact(value) {
    body.classList.toggle("q-sidebar-compact", !!value);
    store(COMPACT_KEY, value ? "1" : "0");

    /* Sections opened while the sidebar was wide must not stay open behind the
       rail — they would reappear on the next expand, and a leftover .show can
       only confuse the collapsed state. */
    if (value) {
      var panels = document.querySelectorAll(".q-sidebar .q-nav__sub.show");
      for (var p = 0; p < panels.length; p++) {
        if (window.bootstrap && window.bootstrap.Collapse) {
          window.bootstrap.Collapse.getOrCreateInstance(panels[p], { toggle: false }).hide();
        } else {
          panels[p].classList.remove("show");
        }
      }
    }

    var buttons = document.querySelectorAll("[data-sidebar-compact]");
    for (var i = 0; i < buttons.length; i++) {
      buttons[i].setAttribute("aria-pressed", value ? "true" : "false");
    }

    syncCompactAffordances();
  }

  function isCompact() {
    return body.classList.contains("q-sidebar-compact");
  }

  function toggleCompact() {
    setCompact(!isCompact());
  }

  /* ------------------------------------------------------------------ */
  /* Compact rail affordances (icon-only navigation)                     */
  /* ------------------------------------------------------------------ */

  var HEADER_ICON = "bi-list";
  var EXPAND_ICON = "bi-chevron-double-right";
  var EXPAND_ICON_RTL = "bi-chevron-double-left";

  function isRtl() {
    return (document.documentElement.getAttribute("dir") || "ltr").toLowerCase() === "rtl";
  }

  function isDesktop() {
    return window.innerWidth >= BREAKPOINT;
  }

  function headerToggler() {
    return document.querySelector(".q-header__toggle");
  }

  function navLabel(link) {
    var text = link.querySelector(".q-nav__text");
    return text ? text.textContent.replace(/\s+/g, " ").trim() : "";
  }

  function disposeTooltip(el) {
    if (window.bootstrap && window.bootstrap.Tooltip) {
      var instance = window.bootstrap.Tooltip.getInstance(el);
      if (instance) instance.dispose();
    }
    el.removeAttribute("data-q-tooltip");
    el.removeAttribute("title");
  }

  /* The header button collapses the sidebar on desktop, so it should say what
     it does next: expand (chevron pointing away from the rail) or collapse. */
  function syncHeaderToggler() {
    var btn = headerToggler();
    if (!btn) return;

    var collapsed = isCompact() && isDesktop();
    var label = !isDesktop()
      ? "Toggle navigation"
      : (collapsed ? "Expand navigation" : "Collapse navigation");

    btn.setAttribute("title", label);
    btn.setAttribute("aria-label", label);

    var icon = btn.querySelector("i");
    if (!icon) return;

    icon.classList.remove(HEADER_ICON, EXPAND_ICON, EXPAND_ICON_RTL);
    icon.classList.add(collapsed ? (isRtl() ? EXPAND_ICON_RTL : EXPAND_ICON) : HEADER_ICON);
  }

  /* Tooltips let sighted users read the icon-only rail without expanding it.
     Links are matched to their label, which also stays in the DOM for screen
     readers (see the compact rules in style.css). */
  function syncNavTooltips() {
    var links = document.querySelectorAll(".q-sidebar .q-nav__link");
    var collapsed = isCompact() && isDesktop();

    for (var i = 0; i < links.length; i++) {
      var link = links[i];
      disposeTooltip(link);
      // Links inside a fly-out panel keep their label on screen.
      if (!collapsed || link.closest(".q-nav__sub")) continue;

      var label = navLabel(link);
      if (!label) continue;

      if (window.bootstrap && window.bootstrap.Tooltip) {
        window.bootstrap.Tooltip.getOrCreateInstance(link, {
          title: label,
          placement: isRtl() ? "left" : "right",
          container: "body",
          trigger: "hover focus"
        });
      } else {
        link.setAttribute("title", label);
      }
      link.setAttribute("data-q-tooltip", "1");
    }
  }

  function syncCompactAffordances() {
    syncHeaderToggler();
    syncNavTooltips();
  }

  /* ------------------------------------------------------------------ */
  /* Direction (LTR / RTL)                                               */
  /* ------------------------------------------------------------------ */

  function currentBootstrapLink() {
    var links = document.querySelectorAll('link[rel="stylesheet"]');
    for (var i = 0; i < links.length; i++) {
      var href = links[i].getAttribute("href") || "";
      if (href.indexOf(LTR_HREF) !== -1 || href.indexOf(RTL_HREF) !== -1) {
        return links[i];
      }
    }
    return null;
  }

  function setDirection(dir) {
    dir = dir === "rtl" ? "rtl" : "ltr";

    document.documentElement.setAttribute("dir", dir);
    document.documentElement.setAttribute("lang", "en");

    // Swap Bootstrap's LTR build for its RTL build (and back).
    var link = currentBootstrapLink();
    if (link) {
      var href = link.getAttribute("href") || "";
      var next = dir === "rtl"
        ? href.replace(LTR_HREF, RTL_HREF)
        : href.replace(RTL_HREF, LTR_HREF);
      if (next !== href) link.setAttribute("href", next);
    }

    store(DIR_KEY, dir);

    var buttons = document.querySelectorAll("[data-dir-toggle]");
    for (var i = 0; i < buttons.length; i++) {
      var btn = buttons[i];
      var label = btn.querySelector("[data-dir-label]");
      if (label) label.textContent = dir === "rtl" ? "LTR" : "RTL";
      btn.setAttribute("aria-pressed", dir === "rtl" ? "true" : "false");
      btn.setAttribute("title", dir === "rtl" ? "Switch to LTR layout" : "Switch to RTL layout");
    }

    // The expand chevron and tooltip side follow the text direction.
    syncCompactAffordances();
  }

  function toggleDirection() {
    var next = document.documentElement.getAttribute("dir") === "rtl" ? "ltr" : "rtl";
    setDirection(next);
    return next;
  }

  /* ------------------------------------------------------------------ */
  /* Init                                                                */
  /* ------------------------------------------------------------------ */

  function init() {
    // Restore the saved direction before anything else paints.
    var savedDir = read(DIR_KEY);
    if (savedDir === "rtl") {
      setDirection("rtl");
    } else {
      setDirection("ltr");
    }

    // Restore compact preference, or suggest it on tablet-width screens.
    var savedCompact = read(COMPACT_KEY);
    if (savedCompact === "1") {
      setCompact(true);
    } else if (savedCompact === null && window.innerWidth >= BREAKPOINT && window.innerWidth < COMPACT_BREAKPOINT) {
      setCompact(true);
    }

    // Compact rail labels, tooltips and the header button all describe the
    // current state — refresh them on load, on a direction change and on resize.
    syncCompactAffordances();

    var resizeTimer = null;
    window.addEventListener("resize", function () {
      if (resizeTimer) window.clearTimeout(resizeTimer);
      resizeTimer = window.setTimeout(syncCompactAffordances, 150);
    });

    // In the collapsed rail a section icon has no room for a fly-out panel: the
    // nav is a scroll container that clips it. So a click expands the sidebar
    // and opens that section instead, which also keeps the labels reachable on
    // touch and with the keyboard. Capture phase: Bootstrap's own collapse data
    // API listens on the same element.
    document.addEventListener("click", function (event) {
      if (!isCompact() || !isDesktop()) return;
      var target = event.target;
      if (!target || typeof target.closest !== "function") return;

      var sectionToggle = target.closest('.q-sidebar .q-nav__link[data-bs-toggle="collapse"]');
      if (!sectionToggle) return;

      var selector = sectionToggle.getAttribute("data-bs-target") ||
        (sectionToggle.getAttribute("href") || "").trim();
      if (selector.charAt(0) !== "#") return;

      event.preventDefault();
      event.stopPropagation();

      setCompact(false);

      var panel = document.querySelector(selector);
      if (panel && window.bootstrap && window.bootstrap.Collapse) {
        window.bootstrap.Collapse.getOrCreateInstance(panel, { toggle: false }).show();
      }
      sectionToggle.setAttribute("aria-expanded", "true");
      if (sectionToggle.scrollIntoView) {
        sectionToggle.scrollIntoView({ block: "nearest" });
      }
    }, true);

    document.addEventListener("click", function (event) {
      var toggleBtn = event.target.closest("[data-sidebar-toggle]");
      if (toggleBtn) {
        event.preventDefault();
        toggle();
        return;
      }

      var compactBtn = event.target.closest("[data-sidebar-compact]");
      if (compactBtn) {
        event.preventDefault();
        toggleCompact();
        return;
      }

      var dirBtn = event.target.closest("[data-dir-toggle]");
      if (dirBtn) {
        event.preventDefault();
        toggleDirection();
      }
    });

    // Close the mobile drawer when a navigation link is used.
    document.addEventListener("click", function (event) {
      var link = event.target.closest(".q-sidebar a.q-nav__link[href]");
      if (link && isMobile() && link.getAttribute("href") !== "#") {
        close();
      }
    });

    document.addEventListener("keydown", function (event) {
      if (event.key === "Escape") {
        close();
      }
    });

    window.addEventListener("resize", function () {
      if (!isMobile()) close();
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }

  window.QevoraSidebar = {
    open: open,
    close: close,
    toggle: toggle,
    setCompact: setCompact,
    isCompact: isCompact,
    toggleCompact: toggleCompact,
    setDirection: setDirection,
    toggleDirection: toggleDirection
  };
})();
