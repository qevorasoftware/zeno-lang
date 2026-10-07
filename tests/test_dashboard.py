"""The dashboard, driven the way a person drives it.

``dashboard.html`` is both the GitHub Pages artefact and a client of a local
``zeno serve``, which makes it the easiest thing in the project to break silently:
nothing imports it, and a typo in the script only shows up as a dead page.

So this file executes the page's own script. The harness in ``tests/js`` provides
just enough DOM for the page to boot — ``getElementById``, listeners, ``fetch``
against a real server — and the tests then type commands into the very input the
browser uses and read back the console the user would see.

Nothing here re-implements the dashboard. If these tests pass and the browser
disagrees, the harness is wrong, not the page — which is stated plainly so nobody
mistakes this for a browser test.
"""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
import threading
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from zeno.server import Playground, _Handler

ROOT = Path(__file__).resolve().parent.parent
HARNESS = ROOT / "tests" / "js" / "dashboard_harness.mjs"
NODE = shutil.which("node")

pytestmark = pytest.mark.skipif(NODE is None, reason="node is not installed")


# ---------------------------------------------------------------------------
# Servers
# ---------------------------------------------------------------------------
def _static_site(root: Path) -> tuple[ThreadingHTTPServer, str]:
    """A stand-in for GitHub Pages: files only, no API, no backend."""

    class Quiet(SimpleHTTPRequestHandler):
        def log_message(self, *args):  # noqa: D102 - silence
            pass

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), partial(Quiet, directory=str(root)))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"http://{httpd.server_address[0]}:{httpd.server_address[1]}"


def _zeno_site(playground: Playground) -> tuple[ThreadingHTTPServer, str]:
    handler = type("DashHandler", (_Handler,), {"playground": playground})
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"http://{httpd.server_address[0]}:{httpd.server_address[1]}"


def _closed_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def as_text(markup: str) -> str:
    """Panel HTML as a reader sees it: the page escapes its own output."""
    for entity, character in (("&lt;", "<"), ("&gt;", ">"), ("&quot;", '"'), ("&#39;", "'")):
        markup = markup.replace(entity, character)
    return markup.replace("&amp;", "&")


def drive(base: str, stored_backend: str, commands: list[str]) -> dict:
    """Boot the page against ``base`` and run ``commands`` through its own UI."""
    env = {
        "ZENO_DASHBOARD_BASE": base,
        # What a previous visit would have left in localStorage. Pointing it at a
        # closed port keeps the snapshot test hermetic: it must not silently pick
        # up a server that happens to be listening on 8000.
        "ZENO_DASHBOARD_STORED_BACKEND": stored_backend,
        "ZENO_DASHBOARD_COMMANDS": json.dumps(commands),
    }
    process = subprocess.run(
        [NODE, str(HARNESS)], cwd=ROOT, env=env, capture_output=True, text=True, timeout=180
    )
    if process.returncode != 0:
        pytest.fail(f"harness failed:\n{process.stdout}\n{process.stderr}")
    return json.loads(process.stdout)


# ---------------------------------------------------------------------------
# Offline: the page that ships to GitHub Pages
# ---------------------------------------------------------------------------
def test_the_page_boots_offline_and_says_so():
    httpd, base = _static_site(ROOT)
    try:
        result = drive(base, f"http://127.0.0.1:{_closed_port()}", ["help"])
    finally:
        httpd.shutdown()
        httpd.server_close()

    assert result["mode"] == "SNAPSHOT", result["mode_text"]
    assert "no backend" in result["status_text"]
    palette = " | ".join(result["palette"])
    assert len(result["palette"]) > 5, "the command palette should be populated offline"
    for entry in ("encode <text>", "run <payload>", "watchtower", "benchmark"):
        assert entry in palette, entry
    assert "help" in "\n".join(result["console"]), "the hint must point at `help`"


def test_offline_panels_come_from_the_committed_snapshot():
    """The numbers on the offline page have to be the committed ones, not blanks."""
    httpd, base = _static_site(ROOT)
    try:
        result = drive(base, f"http://127.0.0.1:{_closed_port()}", ["snapshot"])
    finally:
        httpd.shutdown()
        httpd.server_close()

    committed = json.loads((ROOT / "dashboard-data.json").read_text())
    panels = result["panels"]
    assert "corpus cases" in panels["density"]
    assert str(committed["benchmark"]["corpus_cases"]) in panels["density"]
    assert "live backend only" in panels["conversation"]
    assert committed["generated_by"] in "\n".join(result["console"])
    assert "zeno dashboard --write" in "\n".join(result["console"])
    assert "read-only" in panels["status"]
    assert "zeno v0.1" in as_text(panels["grammar"])
    assert "@LOC[TYO] -> ?WX" in as_text(panels["grammar"])


def test_offline_a_live_command_explains_how_to_get_a_backend():
    httpd, base = _static_site(ROOT)
    try:
        result = drive(base, f"http://127.0.0.1:{_closed_port()}", ["benchmark", "run ?WX"])
    finally:
        httpd.shutdown()
        httpd.server_close()

    text = "\n".join(result["console"])
    assert "needs a backend" in text
    assert "zeno serve" in text
    # and crucially: no invented numbers
    assert "density pooled" not in text


# ---------------------------------------------------------------------------
# Live: the page driving a local server
# ---------------------------------------------------------------------------
def test_the_page_connects_to_a_local_server_and_shows_its_posture():
    playground = Playground()
    httpd, base = _zeno_site(playground)
    try:
        result = drive(base, base, ["status", "benchmark", "tools", "grammar"])
    finally:
        httpd.shutdown()
        httpd.server_close()

    assert result["mode"] == "LIVE"
    text = "\n".join(result["console"])
    assert "connected" in result["status_text"] or "connected" in text
    assert "density pooled" in text and "%" in text
    assert "queries" in text and "actions" in text
    assert "grammar" in text.lower()

    panels = result["panels"]
    assert "development" in panels["status"]
    assert "sigils" in panels["grammar"]


def test_running_a_payload_from_the_page_reaches_the_kernel():
    playground = Playground()
    httpd, base = _zeno_site(playground)
    try:
        result = drive(base, base, ["run @LOC[TYO] -> ?WX", "tokens a b c", "example"])
    finally:
        httpd.shutdown()
        httpd.server_close()

    text = "\n".join(result["console"])
    assert "!RET" in text, "the frame the kernel returned should be on screen"
    assert "tokens:" in text
    assert "canonical" in text.lower(), "`example` should say what it loaded"
    assert "check the weather" in result["input"].lower(), "…and put it in the input, ready to run"


def test_the_ask_command_is_a_full_round_trip():
    playground = Playground()
    httpd, base = _zeno_site(playground)
    try:
        result = drive(base, base, ["ask Check the weather in Tokyo"])
    finally:
        httpd.shutdown()
        httpd.server_close()

    text = "\n".join(result["console"])
    assert "zeno>" in text
    assert "!RET" in text or "weather" in text.lower()


def test_an_unknown_command_is_an_explained_refusal():
    playground = Playground()
    httpd, base = _zeno_site(playground)
    try:
        result = drive(base, base, ["frobnicate the ledger"])
    finally:
        httpd.shutdown()
        httpd.server_close()

    text = "\n".join(result["console"])
    assert "unknown command" in text and "help" in text


def test_the_adversary_panel_shows_real_refusals_only():
    """The one panel that must never be decorative: it names who attacked."""
    from aegis.gate import Policy

    playground = Playground(policy=Policy.strict_policy(), mode="production")
    playground.watchtower.tarpit_base_ms = 1
    playground.watchtower.tarpit_max_ms = 2
    httpd, base = _zeno_site(playground)
    try:
        import urllib.error
        import urllib.request

        request = urllib.request.Request(
            base + "/api/run",
            data=json.dumps({"payload": "@LOC[TYO] -> ?WX"}).encode(),
            headers={"Content-Type": "application/json", "User-Agent": "curl/8.5"},
        )
        with pytest.raises(urllib.error.HTTPError) as refusal:
            urllib.request.urlopen(request, timeout=30)
        assert refusal.value.code == 403

        with pytest.raises(urllib.error.HTTPError) as private:
            urllib.request.urlopen(base + "/api/watchtower", timeout=30)
        assert private.value.code == 403, "the feed is the owner's, not the public's"

        # The owner holds a grant, so the owner's own view sees the attacker.
        from aegis.capability import CapabilityVerifier, OwnerRoot

        owner = OwnerRoot.create(name="owner_root", audience="zeno-local", epoch=1)
        token = owner.issue("owner://dashboard", ["read:watchtower"], ttl=600)
        playground.boundary.capability_verifier = CapabilityVerifier(
            owner.public, audience="zeno-local", epoch=1
        )
        result = drive(base, base, ["token " + token.encode(), "watchtower"])
    finally:
        httpd.shutdown()
        httpd.server_close()

    text = "\n".join(result["console"])
    assert "refused attempts" in text
    assert "127.0.0.1" in text and "ZN-SEC-" in text
    assert "stored" in text  # the token was accepted by the page, not invented by it
    assert "decoy" in result["panels"]["watchtower"].lower() or "🎭" in result["panels"]["watchtower"]

# ---------------------------------------------------------------------------
# The full command list, and the rendering mistakes that only show up on screen
# ---------------------------------------------------------------------------
FULL_SWEEP = [
    "status",
    "encode Check the weather in Tokyo. If it is raining, suggest 3 indoor activities.",
    "run @LOC[TYO] -> ?WX : { $WX.state == RAIN => !GEN[INDOOR, 3] }",
    "check @LOC[TYO] -> ?WX",
    "check @LOC[TYO] ->",           # a broken payload must be diagnosed, not thrown
    "decode @LOC[TYO] -> ?WX",
    "tokens Check the weather in Tokyo",
    "grammar",
    "grammar table",
    "tools",
    "benchmark",
    "snapshot",
    "example",
    "not-a-command",
]


def test_every_command_renders_something_useful():
    playground = Playground()
    httpd, base = _zeno_site(playground)
    try:
        result = drive(base, base, FULL_SWEEP)
    finally:
        httpd.shutdown()
        httpd.server_close()

    text = "\n".join(result["console"])
    # encode produced the canonical payload, and run executed it
    assert "@LOC[TYO] -> ?WX : { $WX.state == RAIN => !GEN[INDOOR, 3]" in text
    assert "!RET[" in text
    # a malformed payload is a diagnostic, never a traceback
    assert "ZN0003" in text
    assert "tokens:" in text
    assert "density pooled" in text
    assert "queries: " in text
    assert "ZENO GRAMMAR v0.1" in text          # the card
    assert "canonical_example" in text          # the raw machine table
    assert "unknown command: not-a-command" in text

    # and none of the ways a JavaScript page fails quietly
    for marker in ("no route", "threw for", "Failed to parse", "undefined%", "NaN", "[object Object]"):
        assert marker not in text, f"the console rendered {marker!r}"


def test_live_panels_render_numbers_not_placeholders():
    playground = Playground()
    httpd, base = _zeno_site(playground)
    try:
        result = drive(base, base, [])
    finally:
        httpd.shutdown()
        httpd.server_close()

    panels = result["panels"]
    assert "pooled reduction" in panels["density"]
    assert "per hop" in panels["conversation"]
    assert "queries" in panels["tools"]
    assert "@LOC[TYO] -> ?WX" in as_text(panels["grammar"]), "the canonical example must be formatted"
    assert "[object Object]" not in panels["grammar"]
    assert "20 operators" in panels["grammar"]  # 4 flow + 16 expression
