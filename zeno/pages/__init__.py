"""The dynamic page layer: every page is assembled here, per request.

Nothing in this project is a hand-written HTML document any more. Each page is
built from three kinds of piece — the shared chrome (head, sidebar, UI-kit
scripts), a body fragment, and the page's own script — and the chrome is
generated from data, so five surfaces share one layout instead of five
hand-kept copies of it.

Two hosts, one source of truth:

* the local server renders pages **live**, with the request-time truth baked
  in (the settings page's provider table, the voice page's status pills), so
  what "view source" shows is what was true when the page was served;
* the static GitHub Pages site cannot run Python, so ``zeno pages --write``
  renders the same pages against a baseline and writes them to the repository
  root — and a test fails if those files ever drift from the generator.

The page scripts still fetch the APIs and re-render on load. The server-side
render is the first paint and the no-JavaScript truth, not a replacement for
the live UI.
"""

from __future__ import annotations

import html
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

__all__ = [
    "render_dashboard",
    "render_settings",
    "render_admin",
    "render_voice",
    "render_playground",
    "render_index",
    "render_404",
    "write_static",
    "check_static",
]

PKG = Path(__file__).resolve().parent


def _fragment(kind: str, name: str) -> str:
    """A body or head fragment, exactly as committed."""
    return (PKG / kind / f"{name}.html").read_text(encoding="utf-8").rstrip("\n")


def _script(name: str) -> str:
    """A page's inline script, exactly as committed."""
    return (PKG / "scripts" / f"{name}.js").read_text(encoding="utf-8").rstrip("\n")


#: Applied before first paint so a stored dark mode never flashes light. Kept
#: on one line on purpose: the dashboard's test harness finds the page's main
#: script as the *first* ``<script>`` block that opens with a newline, and a
#: multi-line pre-paint would shadow it.
PRE_PAINT = (
    '<script>(function(){try{var s=localStorage.getItem("qevora-theme");'
    'var d=window.matchMedia("(prefers-color-scheme: dark)").matches;'
    'document.documentElement.setAttribute("data-bs-theme",'
    '(s==="dark"||s==="light")?s:(d?"dark":"light"));}catch(e){}})();</script>'
)

#: The UI kit, vendored at the repository root. Relative paths on purpose: the
#: same markup must resolve on the local server and under the GitHub Pages
#: subpath — absolute paths are how the surfaces 404'd there.
KIT_CSS = """  <!-- UI kit, vendored at the repository root (see assets/CREDITS.md): the same
       relative paths work on the local server and on the GitHub Pages site. -->
  <link rel="stylesheet" href="assets/css/fonts.css">
  <link rel="stylesheet" href="assets/css/bootstrap.min.css">
  <link rel="stylesheet" href="assets/icons/bootstrap-icons/bootstrap-icons.min.css">
  <link rel="stylesheet" href="assets/css/style.css">
  <link rel="stylesheet" href="assets/css/components.css">
  <link rel="stylesheet" href="assets/css/dark.css">"""

_KIT_JS = (
    '  <script src="assets/js/bootstrap.bundle.min.js"></script>\n'
    '  <script src="assets/js/theme.js"></script>\n'
    '  <script src="assets/js/sidebar.js"></script>\n'
    '  <script src="assets/js/app.js"></script>'
)


# ---------------------------------------------------------------------------
# Sidebar — one generator, five surfaces, no hand-kept copies
# ---------------------------------------------------------------------------
def _nav_item(item: Mapping[str, Any]) -> str:
    """One sidebar link. ``item``: href, icon, text, and optional extras."""
    classes = "q-nav__link" + (" is-active" if item.get("active") else "")
    attrs = f'href="{item["href"]}"'
    if item.get("view"):
        attrs += f' data-view="{item["view"]}"'
    if item.get("id"):
        attrs += f' id="{item["id"]}"'
    badge = ""
    if item.get("badge"):
        badge_id, badge_kind = item["badge"]
        badge = (
            f'\n            <span class="badge badge-soft-{badge_kind} badge-pill ms-auto" '
            f'id="{badge_id}" hidden>0</span>'
        )
    return (
        f'        <li class="q-nav-item">\n'
        f'          <a class="{classes}" {attrs}>\n'
        f'            <i class="q-nav__icon bi {item["icon"]}" aria-hidden="true"></i>\n'
        f'            <span class="q-nav__text">{item["text"]}</span>{badge}\n'
        f'          </a>\n'
        f'        </li>'
    )


def _sidebar(
    *,
    aria: str,
    brand_href: str,
    brand_sub: str,
    groups: Sequence[Tuple[str, Sequence[Mapping[str, Any]]]],
    footer: str,
) -> str:
    nav = ""
    for label, items in groups:
        nav += f'      <p class="q-sidebar__group-label">{label}</p>\n      <ul class="q-nav">\n'
        nav += "\n".join(_nav_item(item) for item in items)
        nav += "\n      </ul>\n\n"
    nav = nav.rstrip("\n")
    return f"""  <!-- ================= Sidebar ================= -->
  <aside class="q-sidebar" id="qevora-sidebar" aria-label="{aria}">
    <div class="q-sidebar__brand">
      <a href="{brand_href}" class="d-flex align-items-center gap-2 min-w-0 text-decoration-none">
        <span class="q-brand__mark" aria-hidden="true">Z</span>
        <span class="q-brand__text">
          <span class="q-brand__name">Zeno</span>
          <span class="q-brand__sub">{brand_sub}</span>
        </span>
      </a>
      <button class="btn btn-icon btn-sm btn-ghost ms-auto d-none d-lg-inline-grid" type="button"
              data-sidebar-compact aria-pressed="false" aria-label="Collapse sidebar" title="Collapse sidebar">
        <i class="bi bi-chevron-double-left"></i>
      </button>
      <button class="btn btn-icon btn-sm btn-ghost ms-auto d-lg-none" type="button"
              data-sidebar-toggle aria-expanded="false" aria-controls="qevora-sidebar" aria-label="Close navigation">
        <i class="bi bi-x-lg"></i>
      </button>
    </div>

    <nav class="q-sidebar__body q-scroll">
{nav}

      <div class="q-sidebar__footer">
        {footer}
      </div>
    </nav>
  </aside>
  <div class="q-sidebar-backdrop" aria-hidden="true"></div>"""


# ---------------------------------------------------------------------------
# Document assembly
# ---------------------------------------------------------------------------
def _kit_head(title: str, description: str, head_extra: str = "") -> str:
    extra = f"\n{head_extra}" if head_extra else ""
    return f"""<!doctype html>
<html lang="en" data-bs-theme="light" dir="ltr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="theme-color" content="#4f46e5">
  <title>{title}</title>
  <meta name="description" content="{description}">

  <!-- Apply the stored colour mode before first paint to avoid a theme flash.
       Written on one line so the test harness still finds the page's main
       script as the first script block. -->
  {PRE_PAINT}

{KIT_CSS}{extra}
</head>"""


def _app_page(
    *,
    title: str,
    description: str,
    sidebar: str,
    body: str,
    script: str,
    head_extra: str = "",
    wrapper_id: Optional[str] = "top",
    extra_kit_js: str = "",
) -> str:
    """A full Qevora-kit application page: sidebar chrome + body + scripts."""
    wrapper = f'<div class="q-main" id="{wrapper_id}">' if wrapper_id else '<div class="q-main">'
    kit_js = _KIT_JS
    if extra_kit_js:
        kit_js = _KIT_JS.replace(
            '  <script src="assets/js/theme.js">',
            f"{extra_kit_js}\n  " + '<script src="assets/js/theme.js">',
        )
    return f"""{_kit_head(title, description, head_extra)}

<body class="q-app">
  <a class="visually-hidden-focusable" href="#q-content">Skip to main content</a>

{sidebar}

  {wrapper}
{body}
  </div>

{kit_js}
<script>
{script}
</script>
</body>
</html>
"""


def _plain_page(*, title: str, head_extra: str, body: str, script: str) -> str:
    """A page with its own look (the voice and playground pages): the engine
    still assembles it — head, body, script — it just skips the kit chrome."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
{head_extra}
</head>
<body>
{body}
<script>
{script}
</script>
</body>
</html>
"""


def _bare_page(
    *,
    title: str,
    description: str,
    body: str,
    refresh: Optional[str] = None,
    canonical: Optional[str] = None,
) -> str:
    """A kit-styled page with no sidebar: the site doorway and the 404."""
    links = ""
    if refresh:
        links += f'  <meta http-equiv="refresh" content="{refresh}">\n'
    if canonical:
        links += f'  <link rel="canonical" href="{canonical}">\n'
    return f"""<!doctype html>
<html lang="en" data-bs-theme="light" dir="ltr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="theme-color" content="#4f46e5">
  <title>{title}</title>
  <meta name="description" content="{description}">
{links}  <!-- Apply the stored colour mode before first paint to avoid a theme flash -->
  {PRE_PAINT}

{KIT_CSS}
</head>

<body class="q-app">
{body}
</body>
</html>
"""


# ---------------------------------------------------------------------------
# The five surfaces (+ the doorway and the 404)
# ---------------------------------------------------------------------------
_DASHBOARD_SIDEBAR = _sidebar(
    aria="Dashboard navigation",
    brand_href="#top",
    brand_sub="Protocol dashboard",
    groups=[
        (
            "Dashboard",
            [
                {"href": "#top", "icon": "bi-grid-1x2", "text": "Overview"},
                {"href": "#card-console", "icon": "bi-terminal", "text": "Console"},
                {"href": "#card-watchtower", "icon": "bi-shield-exclamation", "text": "Adversary feed"},
                {"href": "#card-grammar", "icon": "bi-braces", "text": "Grammar"},
                {"href": "#card-tools", "icon": "bi-tools", "text": "Tools"},
            ],
        ),
        (
            "Surfaces",
            [
                {"href": "settings.html", "icon": "bi-key", "text": "Settings"},
                {"href": "admin.html", "icon": "bi-gear", "text": "Admin console"},
                {"href": "voice.html", "icon": "bi-mic", "text": "Talk to the agent"},
                {"href": "playground.html", "icon": "bi-play-circle", "text": "Playground",
                 "id": "playground-link"},
            ],
        ),
    ],
    footer='<p class="fs-8 text-muted-2 mb-0"><i class="bi bi-bar-chart-line me-1"></i> live figures, never demo data</p>',
)

_SETTINGS_SIDEBAR = _sidebar(
    aria="Settings navigation",
    brand_href="#top",
    brand_sub="AEGIS Suite",
    groups=[
        (
            "Settings",
            [
                {"href": "#top", "icon": "bi-gear", "text": "AI providers", "active": True},
            ],
        ),
        (
            "Surfaces",
            [
                {"href": "dashboard.html", "icon": "bi-speedometer2", "text": "Dashboard"},
                {"href": "admin.html", "icon": "bi-shield-check", "text": "Admin console"},
                {"href": "voice.html", "icon": "bi-mic", "text": "Talk to the agent"},
                {"href": "playground.html", "icon": "bi-terminal", "text": "Playground"},
            ],
        ),
    ],
    footer='<p class="fs-8 text-muted-2 mb-0" id="store-state">…</p>',
)

_ADMIN_SIDEBAR = _sidebar(
    aria="Admin navigation",
    brand_href="#overview",
    brand_sub="AEGIS Suite",
    groups=[
        (
            "Console",
            [
                {"href": "#overview", "icon": "bi-grid-1x2", "text": "Overview", "view": "overview"},
            ],
        ),
        (
            "Security",
            [
                {"href": "#audit", "icon": "bi-list-check", "text": "Audit trail", "view": "audit",
                 "badge": ("nav-audit-count", "secondary")},
                {"href": "#adversary", "icon": "bi-shield-exclamation", "text": "Adversary feed",
                 "view": "adversary", "badge": ("nav-alert-count", "danger")},
                {"href": "#posture", "icon": "bi-layers", "text": "Posture", "view": "posture"},
            ],
        ),
        (
            "Intelligence",
            [
                {"href": "#memory", "icon": "bi-database-lock", "text": "Memory", "view": "memory"},
                {"href": "#agents", "icon": "bi-diagram-3", "text": "Agents", "view": "agents",
                 "badge": ("nav-agent-count", "secondary")},
            ],
        ),
        (
            "Surfaces",
            [
                {"href": "settings.html", "icon": "bi-key", "text": "Settings"},
                {"href": "voice.html", "icon": "bi-mic", "text": "Talk to the agent"},
                {"href": "playground.html", "icon": "bi-terminal", "text": "Playground"},
                {"href": "dashboard.html", "icon": "bi-speedometer2", "text": "Language dashboard"},
            ],
        ),
    ],
    footer='<p class="fs-8 text-muted-2 mb-0 code-chip" id="feed-path"></p>',
)


def render_dashboard() -> str:
    """The operator dashboard. Its figures stay client-side by design: the
    page connects to a backend (or reads the committed snapshot) and never
    ships numbers it cannot vouch for in static HTML."""
    return _app_page(
        title="Dashboard | Zeno · AEGIS",
        description="Zeno dashboard — the protocol's status, benchmarks, grammar and "
                    "adversary feed, live from a backend you connect.",
        sidebar=_DASHBOARD_SIDEBAR,
        body=_fragment("bodies", "dashboard"),
        script=_script("dashboard"),
        head_extra=_fragment("heads", "dashboard"),
    )


def render_admin() -> str:
    """The admin console: a view over the live posture, filled route by route."""
    return _app_page(
        title="Admin | Zeno · AEGIS",
        description="Zeno admin console — live posture of the AEGIS gateway: decisions, "
                    "adversary feed, sealed memory, connected agents.",
        sidebar=_ADMIN_SIDEBAR,
        body=_fragment("bodies", "admin"),
        script=_script("admin"),
        head_extra=_fragment("heads", "admin"),
        wrapper_id=None,
        extra_kit_js='  <script src="assets/js/chart.umd.js"></script>',
    )


def _esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def _provider_row(profile: Mapping[str, Any]) -> str:
    """One provider row, server-rendered. The same truth the page's script
    renders client-side — the markup mirrors it on purpose, minus the wired
    buttons, which only exist once the script runs."""
    active = bool(profile.get("active"))
    avatar = "bg-avatar-3" if active else "bg-avatar-8"
    if profile.get("has_key"):
        key = (
            f'<span class="badge badge-soft-success badge-pill code-chip" '
            f'title="stored — never displayed in full anywhere">{_esc(profile.get("key_hint"))}</span>'
        )
    elif profile.get("ready"):
        key = '<span class="badge badge-soft-secondary badge-pill">local, no key needed</span>'
    else:
        key = '<span class="badge badge-soft-warning badge-pill">no key yet</span>'
    chip = (
        '<span class="badge badge-soft-success badge-pill">active</span>'
        if active
        else '<span class="badge badge-soft-secondary badge-pill">kept</span>'
    )
    return f"""          <tr>
            <td><span class="avatar avatar-xs {avatar}"></span></td>
            <td class="fw-600 text-heading">{_esc(profile.get("name"))}</td>
            <td><span class="badge badge-soft-primary badge-pill">{_esc(profile.get("provider"))}</span></td>
            <td class="code-chip fs-7">{_esc(profile.get("model") or "—")}</td>
            <td>{key}</td>
            <td>{chip}</td>
            <td class="text-end">
              <button class="btn btn-sm btn-white me-1" data-activate="{_esc(profile.get("name"))}">activate</button>
              <button class="btn btn-sm btn-white me-1" data-test="{_esc(profile.get("name"))}">test</button>
              <button class="btn btn-sm btn-soft-danger" data-remove="{_esc(profile.get("name"))}">remove</button>
            </td>
          </tr>"""


def _preset_options(presets: Sequence[Mapping[str, Any]]) -> str:
    """The provider picker: every preset except the test doubles."""
    out = []
    for preset in presets:
        if preset.get("slug") in ("mock", "none"):
            continue
        note = " (needs a key)" if preset.get("needs_key") else " (local, no key)"
        out.append(
            f'            <option value="{_esc(preset.get("slug"))}">'
            f'{_esc(preset.get("slug"))}{note}</option>'
        )
    return "\n".join(out)


def _replace_once(page: str, anchor: str, replacement: str, what: str) -> str:
    """An anchored, asserted substitution: if the anchor ever moves, rendering
    fails loudly instead of silently dropping the server-side truth."""
    if anchor not in page:
        raise ValueError(f"the settings page no longer carries its {what} anchor")
    return page.replace(anchor, replacement, 1)


def render_settings(view: Optional[Mapping[str, Any]] = None, *, static: bool = False) -> str:
    """The provider & API-key settings page.

    ``view`` is a :class:`zeno.settings.ProviderStore` ``describe()`` dict.
    With none (the static copy), the page renders its baseline: no profiles,
    the preset picker from the committed presets, and the "this copy is
    static" note already visible — the truth before any script runs.
    """
    body = _fragment("bodies", "settings")
    profiles = list((view or {}).get("profiles") or [])
    presets = list((view or {}).get("presets") or [])

    rows = "\n".join(_provider_row(profile) for profile in profiles)
    body = _replace_once(
        body,
        '<tbody id="provider-rows"></tbody>',
        f'<tbody id="provider-rows">\n{rows}\n          </tbody>' if rows
        else '<tbody id="provider-rows"></tbody>',
        "provider table",
    )
    options = _preset_options(presets)
    if options:
        body = _replace_once(
            body,
            '<select id="f-provider" class="form-select"></select>',
            f'<select id="f-provider" class="form-select">\n{options}\n            </select>',
            "preset picker",
        )
    test_names = "\n".join(
        f'            <option value="{_esc(profile.get("name"))}">'
        f'{_esc(profile.get("name"))} ({_esc(profile.get("provider"))})</option>'
        for profile in profiles
    )
    if test_names:
        body = _replace_once(
            body,
            '<select id="t-name" class="form-select form-select-sm" style="width: auto"></select>',
            '<select id="t-name" class="form-select form-select-sm" style="width: auto">\n'
            f"{test_names}\n            </select>",
            "test picker",
        )

    # where the store lives, and in what state — the request-time truth. The
    # static baseline carries presets only: it knows no store, says nothing.
    state = "locked" if view.get("locked") else ("sealed" if view.get("encrypted") else "plaintext")
    if view.get("file"):
        body = _replace_once(
            body,
            '<span class="fs-8 text-muted-2" id="store-file"></span>',
            f'<span class="fs-8 text-muted-2" id="store-file">{_esc(view.get("file"))} · {state}</span>',
            "store location",
        )
        if view.get("locked"):
            body = _replace_once(
                body,
                '<div class="alert alert-danger q-section" id="locked-note" hidden>',
                '<div class="alert alert-danger q-section" id="locked-note">',
                "locked note",
            )
            body = _replace_once(
                body,
                '<span id="locked-reason"></span>',
                f'<span id="locked-reason">{_esc(view.get("locked"))}</span>',
                "locked reason",
            )

    if static:
        # no server behind this copy: say so in the HTML itself, not only
        # after a script fails to reach one
        body = _replace_once(
            body,
            '<div class="alert alert-warning q-section" id="offline-note" hidden>',
            '<div class="alert alert-warning q-section" id="offline-note">',
            "offline note",
        )

    page = _app_page(
        title="Settings | Zeno · AEGIS",
        description="Zeno settings — AI providers and their keys, models and endpoints. "
                    "Several providers, one active.",
        sidebar=_SETTINGS_SIDEBAR,
        body=body,
        script=_script("settings"),
        head_extra=_fragment("heads", "settings"),
    )
    if view and view.get("file"):
        # the sidebar's footer states the store's at-rest state, server-side
        page = _replace_once(
            page,
            '<p class="fs-8 text-muted-2 mb-0" id="store-state">…</p>',
            f'<p class="fs-8 text-muted-2 mb-0" id="store-state">{_esc(state)} at rest</p>',
            "store state",
        )
    return page


def render_voice(status: Optional[Mapping[str, Any]] = None) -> str:
    """The talking page. ``status`` carries the request-time pills
    (enforcement, memory, answerer); without a server they stay ellipses —
    the honest placeholder — until the page's script connects."""
    body = _fragment("bodies", "voice")
    if status:
        for pill, value in (
            ("pill-enforcement", "enforcement"),
            ("pill-memory", "memory"),
            ("pill-provider", "answerer"),
        ):
            body = _replace_once(
                body,
                f'<span class="pill" id="{pill}">{value}: …</span>',
                f'<span class="pill" id="{pill}">{value}: {_esc(status[value])}</span>',
                f"{value} pill",
            )
    return _plain_page(
        title="Zeno — talk to your agent",
        head_extra=_fragment("heads", "voice"),
        body=body,
        script=_script("voice"),
    )


def render_playground() -> str:
    """The language playground: encode, run, decode, by hand."""
    return _plain_page(
        title="Zeno Protocol — playground",
        head_extra=_fragment("heads", "playground"),
        body=_fragment("bodies", "playground"),
        script=_script("playground"),
    )


def render_index() -> str:
    """The site root: a doorway that opens the dashboard."""
    return _bare_page(
        title="Zeno · dashboard",
        description="Zeno — the dense A2A language and the AEGIS gateway. Opening the dashboard.",
        body=_fragment("bodies", "index"),
        refresh="0; url=dashboard.html",
        canonical="dashboard.html",
    )


def render_404() -> str:
    """The styled missing page: what exists, and what does not."""
    return _bare_page(
        title="Zeno · not found",
        description="This page does not exist. The five that do are one click away.",
        body=_fragment("bodies", "404"),
    )


# ---------------------------------------------------------------------------
# The static site: the same pages, rendered against a baseline
# ---------------------------------------------------------------------------
#: What ``zeno pages --write`` lays down at the repository root for GitHub
#: Pages. Order is load-bearing only for readability; each name is a page.
STATIC_PAGES = (
    "index.html",
    "404.html",
    "dashboard.html",
    "settings.html",
    "admin.html",
    "voice.html",
    "playground.html",
)


def _static_renders() -> Dict[str, str]:
    """Every page as its static copy: no live server behind any of them.

    The settings copy carries no profiles — a public site must not ship even
    profile names — and says so in the HTML before any script runs.
    """
    from ..settings import provider_presets

    return {
        "index.html": render_index(),
        "404.html": render_404(),
        "dashboard.html": render_dashboard(),
        "settings.html": render_settings({"presets": provider_presets()}, static=True),
        "admin.html": render_admin(),
        "voice.html": render_voice(None),
        "playground.html": render_playground(),
    }


def write_static(root: Path) -> List[Path]:
    """Render every static copy into ``root``. Returns the written paths."""
    root = Path(root)
    written = []
    for name, page in _static_renders().items():
        path = root / name
        path.write_text(page + "\n", encoding="utf-8")
        written.append(path)
    return written


def check_static(root: Path) -> List[str]:
    """Names of static copies that no longer match the generator.

    Empty means fresh. This is the tripwire that keeps the Pages site honest:
    a hand-edited page or a stale commit shows up here, and in the test that
    calls this, before a visitor ever sees it.
    """
    root = Path(root)
    stale = []
    for name, page in _static_renders().items():
        path = root / name
        if not path.is_file() or path.read_text(encoding="utf-8") != page + "\n":
            stale.append(name)
    return stale
