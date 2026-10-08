"""The dynamic page layer: pages are rendered, not hand-written.

``zeno.pages`` assembles every surface from generated chrome + body fragments
+ page scripts, and renders live data into the HTML at request time. The
committed ``*.html`` files at the repository root are *artefacts* of that
generator — the GitHub Pages copies — and the tests here keep all of that
true: rendering works, the server-side truth really is in the HTML, no
secret ever reaches a page, and a hand-edited artefact fails the build.
"""

from __future__ import annotations

import re
import threading
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from zeno.pages import (
    check_static,
    render_404,
    render_admin,
    render_dashboard,
    render_index,
    render_playground,
    render_settings,
    render_voice,
)
from zeno.server import ROOT, Playground, _Handler
from zeno.settings import provider_presets

#: A store view with one keyed, active profile and one kept local profile —
#: the shape ``ProviderStore.describe()`` returns, minus anything secret by
#: construction (a view carries ``has_key`` + ``key_hint``, never a key).
VIEW = {
    "file": "/home/operator/.zeno/providers.json",
    "encrypted": True,
    "locked": None,
    "active": {"name": "groq-fast", "provider": "groq", "active": True},
    "profiles": [
        {
            "name": "groq-fast",
            "provider": "groq",
            "model": "llama-3.3-70b-versatile",
            "has_key": True,
            "key_hint": "••• 9999",
            "ready": True,
            "active": True,
        },
        {
            "name": "local",
            "provider": "ollama",
            "model": "llama3.1",
            "has_key": False,
            "key_hint": None,
            "ready": True,
            "active": False,
        },
    ],
    "presets": provider_presets(),
    "limits": ["keys are stored server-side"],
}


# ---------------------------------------------------------------------------
# Every page renders, as a page
# ---------------------------------------------------------------------------
def test_every_page_renders_as_one_document():
    pages = {
        "index": render_index(),
        "404": render_404(),
        "dashboard": render_dashboard(),
        "settings": render_settings(VIEW),
        "admin": render_admin(),
        "voice": render_voice({"enforcement": "development", "memory": "sealed", "answerer": "none"}),
        "playground": render_playground(),
    }
    for name, page in pages.items():
        assert page.count("<body") == 1, f"{name} has more than one <body>"
        assert page.count("</body>") == 1 and page.count("</html>") == 1, name
        assert "<script" in page, f"{name} lost its script"
        # the kit loads with relative paths on every page: the same markup has
        # to resolve on the local server and under the GitHub Pages subpath
        assert 'href="/' not in page and 'src="/' not in page, f"{name} links absolutely"


def test_rendering_is_deterministic():
    """Generated pages must be byte-stable: no clocks, no randomness."""
    assert render_dashboard() == render_dashboard()
    assert render_settings(VIEW) == render_settings(VIEW)
    assert render_admin() == render_admin()


def test_the_sidebar_marks_the_page_you_are_on():
    dashboard = render_dashboard()
    settings = render_settings(VIEW)
    admin = render_admin()
    # the settings page marks its own item; the dashboard does not
    assert 'class="q-nav__link is-active" href="#top"' in settings
    assert 'q-nav__link is-active" href="#top"' not in dashboard
    # every page links the *other* surfaces relatively; itself is the #top item
    others = {
        "dashboard": ("settings.html", "admin.html", "voice.html", "playground.html"),
        "settings": ("dashboard.html", "admin.html", "voice.html", "playground.html"),
        "admin": ("settings.html", "voice.html", "playground.html", "dashboard.html"),
    }
    for name, page in (("dashboard", dashboard), ("settings", settings), ("admin", admin)):
        for surface in others[name]:
            assert f'href="{surface}"' in page, f"{name} lost its link to {surface}"


# ---------------------------------------------------------------------------
# The server-side truth is in the HTML
# ---------------------------------------------------------------------------
def test_the_settings_page_carries_the_store_server_side():
    page = render_settings(VIEW)
    # both profiles, their providers and models, in the HTML itself
    for truth in ("groq-fast", "llama-3.3-70b-versatile", "local", "ollama"):
        assert truth in page, f"the provider table lost {truth!r}"
    # the key shows as its hint — and nothing else of it exists anywhere
    assert "••• 9999" in page
    # the store's location and at-rest state, stated server-side
    assert "/home/operator/.zeno/providers.json" in page
    assert "sealed at rest" in page
    # the pickers are pre-filled: presets in the form, profile names in the tester
    assert 'value="groq"' in page and 'value="groq-fast"' in page


def test_a_locked_store_says_so_in_the_html():
    view = dict(VIEW, locked="providers.json is sealed to an owner key; set ZENO_MEMORY_KEY")
    page = render_settings(view)
    assert 'id="locked-note">' in page and "ZENO_MEMORY_KEY" in page
    assert "locked at rest" in page


def test_the_static_settings_copy_ships_no_profiles_and_says_why():
    """No operator data on a public copy — only the page's own strings.

    The form's ``placeholder="e.g. groq-fast"`` and the script's row-rendering
    code are part of the page, not data; what must never ship is anything the
    server-side render would produce from a real store.
    """
    page = render_settings({"presets": provider_presets()}, static=True)
    # no server-rendered rows, key hints, store paths or states
    assert "data-activate=" not in page, "the static copy carries provider rows"
    assert "\u2022\u2022\u2022" not in page and "•••" not in page, "a key hint shipped"
    assert "/home/" not in page
    # the sidebar's store-state stays the ellipsis baseline — the script's own
    # "keys sealed at rest" string is code, not data
    assert 'id="store-state">…</p>' in page
    # the offline note is visible without any script running
    assert '<div class="alert alert-warning q-section" id="offline-note">' in page
    # but the preset picker still works: presets are committed configuration
    assert 'value="openai"' in page and 'value="ollama"' in page


def test_the_voice_page_carries_its_status_pills():
    page = render_voice(
        {"enforcement": "production", "memory": "NOT sealed", "answerer": "groq (offline, rule-based)"}
    )
    assert "enforcement: production" in page
    assert "memory: NOT sealed" in page
    assert "answerer: groq (offline, rule-based)" in page
    # without a server behind it, the pills stay honest ellipses
    baseline = render_voice(None)
    assert "enforcement: …" in baseline and "answerer: …" in baseline


def test_no_key_material_can_reach_a_page():
    """The view carries hints only — prove it on the rendered page.

    ``sk-…`` (the form placeholder) and ``api_key`` (the field the script
    posts) are the page's own furniture. What must never appear is key
    *material*: a value after api_key, or a provider key prefix as a value.
    """
    page = render_settings(VIEW)
    assert "gsk_" not in page, "a Groq-style key prefix reached the page"
    # every sk- is the form's placeholder, nothing else
    assert page.count("sk-") == page.count('placeholder="sk-')
    # api_key is only ever sent, never embedded with a literal value
    assert not re.search(r'api_key["\']?\s*:\s*["\'][^"\']+["\']', page)


# ---------------------------------------------------------------------------
# The committed static copies are artefacts, kept fresh
# ---------------------------------------------------------------------------
def test_the_committed_pages_match_the_generator():
    """The root *.html files are generated. If this fails, someone edited one
    by hand (or the generator moved on without re-running ``zeno pages
    --write``) — the Pages site would silently drift from the real pages."""
    stale = check_static(ROOT)
    assert stale == [], "stale generated pages — run: zeno pages --write"


def test_the_generated_copies_contain_no_live_data():
    """A public static site ships no operator data — not even profile names."""
    from zeno.pages import _static_renders

    settings = _static_renders()["settings.html"]
    assert "data-activate=" not in settings and "/home/" not in settings
    assert "•••" not in settings, "a key hint shipped to the static site"
    assert 'id="store-state">…</p>' in settings
    voice = _static_renders()["voice.html"]
    assert "enforcement: development" not in voice and "enforcement: …" in voice


# ---------------------------------------------------------------------------
# The live server serves the rendered pages
# ---------------------------------------------------------------------------
@pytest.fixture()
def site():
    playground = Playground()
    handler = type("PagesHandler", (_Handler,), {"playground": playground})
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://{httpd.server_address[0]}:{httpd.server_address[1]}", playground
    httpd.shutdown()
    httpd.server_close()


def _get(base: str, path: str):
    request = urllib.request.Request(base + path)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, response.read().decode("utf-8"), response.headers
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode("utf-8"), error.headers


def test_the_server_renders_pages_with_live_data(site):
    base, playground = site
    # the settings page is rendered from the store this server actually uses
    status, page, headers = _get(base, "/settings")
    assert status == 200 and "text/html" in headers.get("Content-Type", "")
    for truth in ("AI providers", "Your providers"):
        assert truth in page
    # the voice page carries the request-time pills
    status, page, _ = _get(base, "/voice")
    assert status == 200
    assert "enforcement: development" in page
    assert "memory: " in page
    # and the .html aliases still answer, because the pages cross-link that way
    for path in ("/settings.html", "/admin.html", "/voice.html", "/dashboard.html", "/playground.html"):
        status, _, _ = _get(base, path)
        assert status == 200, f"{path} stopped answering"


def test_a_wrong_page_gets_the_styled_404_and_a_wrong_api_stays_a_code(site):
    base, _ = site
    status, page, headers = _get(base, "/nope")
    assert status == 404
    assert "text/html" in headers.get("Content-Type", "")
    assert "This page does not exist" in page
    assert 'href="dashboard.html"' in page
    status, body, _ = _get(base, "/api/nope")
    assert status == 404 and "ZN0000" in body


def test_the_live_settings_page_matches_the_store_it_serves(site):
    """What the HTML says and what the API says must be the same truth."""
    base, playground = site
    _, page, _ = _get(base, "/settings")
    view = playground.provider_store.describe()
    for profile in view.get("profiles") or []:
        assert profile["name"] in page, f"{profile['name']} is in the store but not the HTML"
        if profile.get("has_key"):
            assert profile["key_hint"] in page
