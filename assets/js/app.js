/* ==========================================================================
   Qevora AI SaaS — Bootstrap 5 Admin & UI Kit
   app.js — Shared application behaviour
   --------------------------------------------------------------------------
   Contents
   1.  Active navigation state
   2.  Bootstrap component bootstrapping (tooltips, popovers)
   3.  Demo helpers (toasts, confirm, copy, counters)
   4.  Misc UI behaviour (auto-year, table filters, auto-dismiss)
   ========================================================================== */

(function () {
  "use strict";

  /* ====================================================================== */
  /* 1. ACTIVE NAVIGATION STATE                                             */
  /* ====================================================================== */

  /* Marks the sidebar link that matches the current page, opens its parent
     submenu and highlights it. Keeps 60+ static pages consistent without a
     server-side include. */

  function currentPath() {
    var path = window.location.pathname.split("/").pop() || "index.html";
    return path.toLowerCase();
  }

  function markActiveNav() {
    var links = document.querySelectorAll(".q-sidebar .q-nav__link[href]");
    if (!links.length) return;

    var page = currentPath();

    for (var i = 0; i < links.length; i++) {
      var link = links[i];
      var href = (link.getAttribute("href") || "").split("#")[0];

      // Ignore in-page anchors and placeholder links.
      if (!href || href === "#" || href.indexOf("javascript:") === 0) continue;

      var file = href.split("/").pop().toLowerCase();
      if (file === page) {
        link.classList.add("is-active");
        link.setAttribute("aria-current", "page");

        // Highlight the top-level group as well.
        var sub = link.closest(".q-nav__sub");
        if (sub) {
          var parentLink = sub.parentElement.querySelector(":scope > .q-nav__link");
          if (parentLink) {
            parentLink.classList.add("is-active");
            parentLink.setAttribute("aria-expanded", "true");
            var sibling = sub;
            if (window.bootstrap && window.bootstrap.Collapse) {
              var instance = window.bootstrap.Collapse.getOrCreateInstance(sibling, { toggle: false });
              instance.show();
            } else {
              sibling.classList.add("show");
            }
          }
        }
      }
    }
  }

  /* ====================================================================== */
  /* 2. BOOTSTRAP BOOTSTRAP-ING                                            */
  /* ====================================================================== */

  function initBootstrapBits() {
    if (!window.bootstrap) return;

    // getOrCreateInstance keeps this idempotent: the shell (sidebar.js) may have
    // created a tooltip on an element already, and a second instance would warn.
    var tooltips = document.querySelectorAll('[data-bs-toggle="tooltip"]');
    for (var i = 0; i < tooltips.length; i++) {
      window.bootstrap.Tooltip.getOrCreateInstance(tooltips[i]);
    }

    var popovers = document.querySelectorAll('[data-bs-toggle="popover"]');
    for (var j = 0; j < popovers.length; j++) {
      window.bootstrap.Popover.getOrCreateInstance(popovers[j]);
    }
  }

  /* ====================================================================== */
  /* 3. DEMO HELPERS                                                        */
  /* ====================================================================== */

  var ICONS = {
    success: "bi-check-circle",
    danger: "bi-x-circle",
    warning: "bi-exclamation-triangle",
    info: "bi-info-circle",
    primary: "bi-stars"
  };

  /* Floating toast, used by the demo actions across the template. */
  function toast(message, variant, title, action) {
    variant = variant || "primary";

    var host = document.querySelector(".q-toast-host");
    if (!host) {
      host = document.createElement("div");
      host.className = "q-toast-host position-fixed bottom-0 end-0 p-3";
      host.style.zIndex = "1090";
      document.body.appendChild(host);
    }

    var el = document.createElement("div");
    el.className = "toast align-items-center border-0 show mb-2";
    el.setAttribute("role", "status");
    el.setAttribute("aria-live", "polite");
    el.innerHTML =
      '<div class="d-flex">' +
      '  <div class="toast-body d-flex align-items-center gap-2">' +
      '    <i class="bi ' + (ICONS[variant] || ICONS.primary) + ' text-' + variant + '"></i>' +
      '    <span>' + (title ? "<strong>" + title + "</strong> " : "") + message + "</span>" +
      (action && action.label
        ? '    <button type="button" class="btn btn-sm btn-soft-' + variant + ' ms-2 flex-shrink-0" data-toast-action>' + action.label + "</button>"
        : "") +
      "  </div>" +
      '  <button type="button" class="btn-close me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>' +
      "</div>";

    host.appendChild(el);

    /* Optional action on the toast ("Undo" after a delete, for example). */
    var actionButton = el.querySelector("[data-toast-action]");
    if (actionButton && action && typeof action.onClick === "function") {
      actionButton.addEventListener("click", function () {
        action.onClick();
        hideToast(el);
      });
    }

    if (window.bootstrap && window.bootstrap.Toast) {
      var instance = new window.bootstrap.Toast(el, { delay: 3200 });
      instance.show();
      el.addEventListener("hidden.bs.toast", function () {
        el.remove();
      });
    } else {
      window.setTimeout(function () {
        el.remove();
      }, 3200);
    }
  }

  /* Closes a toast whichever way it was created. */
  function hideToast(el) {
    if (window.bootstrap && window.bootstrap.Toast && window.bootstrap.Toast.getInstance(el)) {
      window.bootstrap.Toast.getInstance(el).hide();
    } else {
      el.remove();
    }
  }

  /* Copy text to the clipboard with a safe fallback for file:// previews. */
  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text);
    }

    return new Promise(function (resolve, reject) {
      var area = document.createElement("textarea");
      area.value = text;
      area.setAttribute("readonly", "");
      area.style.position = "fixed";
      area.style.opacity = "0";
      document.body.appendChild(area);
      area.select();
      try {
        document.execCommand("copy");
        resolve();
      } catch (e) {
        reject(e);
      } finally {
        area.remove();
      }
    });
  }

  /* Animated number counters: <span data-counter="128000" data-decimals="0"> */
  function initCounters() {
    var nodes = document.querySelectorAll("[data-counter]");
    if (!nodes.length) return;

    var reduceMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    for (var i = 0; i < nodes.length; i++) {
      (function (node) {
        var target = parseFloat(node.getAttribute("data-counter")) || 0;
        var decimals = parseInt(node.getAttribute("data-decimals") || "0", 10);
        var prefix = node.getAttribute("data-prefix") || "";
        var suffix = node.getAttribute("data-suffix") || "";

        function format(value) {
          return prefix + value.toLocaleString("en-US", {
            minimumFractionDigits: decimals,
            maximumFractionDigits: decimals
          }) + suffix;
        }

        if (reduceMotion) {
          node.textContent = format(target);
          return;
        }

        var duration = 900;
        var start = null;

        function step(timestamp) {
          if (start === null) start = timestamp;
          var progress = Math.min((timestamp - start) / duration, 1);
          var eased = 1 - Math.pow(1 - progress, 3);
          node.textContent = format(target * eased);
          if (progress < 1) window.requestAnimationFrame(step);
        }

        window.requestAnimationFrame(step);
      })(nodes[i]);
    }
  }

  /* ====================================================================== */
  /* 4. MISC UI BEHAVIOUR                                                   */
  /* ====================================================================== */

  function initAutoYear() {
    var nodes = document.querySelectorAll("[data-current-year]");
    var year = new Date().getFullYear();
    for (var i = 0; i < nodes.length; i++) {
      nodes[i].textContent = year;
    }
  }

  /* Live table search and the select filters live in assets/js/demo-ui.js, so
     that one code path decides which rows are visible and the pagination and
     the "showing x of y" counters stay in step with it. */
  /* Demo-only actions: buttons marked data-demo-action show a toast instead of
     needing a backend. */
  function initDemoActions() {
    document.addEventListener("click", function (event) {
      var trigger = event.target.closest("[data-demo-action]");
      if (!trigger) return;
      event.preventDefault();
      var message = trigger.getAttribute("data-demo-action") || "This action is part of the demo interface.";
      toast(message, trigger.getAttribute("data-demo-variant") || "primary");
    });
  }

  /* Placeholder links (#) should not jump the page. */
  function initPlaceholderLinks() {
    document.addEventListener("click", function (event) {
      var link = event.target.closest('a[href="#"]');
      if (link) event.preventDefault();
    });
  }

  /* Keep dropdown menus tidy: close other open dropdowns when one opens. */
  function initDropdownHygiene() {
    document.addEventListener("show.bs.dropdown", function (event) {
      var open = document.querySelectorAll(".dropdown-menu.show");
      for (var i = 0; i < open.length; i++) {
        var parent = open[i].closest(".dropdown");
        if (parent && parent !== event.target) {
          var btn = parent.querySelector('[data-bs-toggle="dropdown"]');
          if (btn && window.bootstrap) {
            window.bootstrap.Dropdown.getOrCreateInstance(btn).hide();
          }
        }
      }
    });
  }

  /* ====================================================================== */
  /* INIT                                                                   */
  /* ====================================================================== */

  function init() {
    markActiveNav();
    initBootstrapBits();
    initCounters();
    initAutoYear();
    initDemoActions();

    /* The derived KPI tiles (demo-ui.js) rewrite data-counter, so the animation
       has to start again from the new value. */
    document.addEventListener("qevora:counters", initCounters);

    /* The derived KPI tiles (demo-ui.js) rewrite data-counter, so the animation
       has to start again from the new value. */
    document.addEventListener("qevora:counters", initCounters);
    initPlaceholderLinks();
    initDropdownHygiene();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }

  window.Qevora = {
    toast: toast,
    copyText: copyText,
    refresh: init
  };
})();
