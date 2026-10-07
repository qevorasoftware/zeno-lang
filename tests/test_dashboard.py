"""The dashboard's JavaScript, executed against a real server.

The dashboard is a page of JavaScript that a browser runs; a Python test can only
usefully check that it is *served*. This test goes further: it starts the real
handler on an ephemeral port, runs the page's actual ``<script>`` under node with
a small DOM shim, issues commands through the same code path the Run button uses,
and asserts on what was rendered.

Node is not a dependency of this repository, so the test skips when it is absent
(with a stated reason). When it is present it catches the class of bug that
otherwise only shows up in a browser: a renamed response field, a relative URL
resolved against nothing, a command that throws instead of reporting.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from zeno.server import Playground, _Handler

REPO = Path(__file__).resolve().parents[1]
DASHBOARD = REPO / "dashboard.html"
SHIM = REPO / "tests" / "fixtures" / "dashboard_shim.js"

pytestmark = pytest.mark.skipif(
    shutil.which("node") is None, reason="node is not installed: the dashboard script cannot be executed"
)


def _script_of(page: str) -> str:
    match = re.search(r"<script>\n(.*)</script>", page, re.S)
    assert match, "dashboard.html has no inline <script> block"
    return match.group(1)


def _start_server() -> tuple[ThreadingHTTPServer, str]:
    playground = Playground()
    handler = type("TestHandler", (_Handler,), {"playground": playground})
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    host, port = httpd.server_address[0], httpd.server_address[1]
    return httpd, f"http://{host}:{port}"


SNAPSHOT_RUNNER = '''
// Same idea, but the page is served from a plain static file server (as it is on
// GitHub Pages) and no backend answers: the page must degrade to the committed
// snapshot and tell the user how to start a server, never throw.
setTimeout(async () => {
  const problems = [];
  for (const command of ["help", "snapshot", "status", "check @LOC[TYO] -> ?WX"]) {
    try {
      await execute(command);
    } catch (error) {
      problems.push("threw for " + command + ": " + error.message);
    }
  }
  console.log(JSON.stringify({
    problems,
    mode: elementById("mode-pill").textContent,
    status: elementById("status-text").textContent,
    console_text: renderLines.join("\\n"),
    panels: {
      density: elementById("panel-density").innerHTML,
      conversation: elementById("panel-conversation").innerHTML,
      grammar: elementById("panel-grammar").innerHTML,
    },
  }));
  process.exit(0);
}, 2500);
'''


RUNNER = '''
// Commands are issued through the page's own execute(), exactly as the Run
// button does, and every rendered line is checked for the failure markers.
setTimeout(async () => {
  const commands = [
    "status",
    "encode Check the weather in Tokyo. If it is raining, suggest 3 indoor activities.",
    "run @LOC[TYO] -> ?WX : { $WX.state == RAIN => !GEN[INDOOR, 3] }",
    "check @LOC[TYO] -> ?WX",
    "check @LOC[TYO] ->",
    "decode @LOC[TYO] -> ?WX",
    "tokens Check the weather in Tokyo",
    "grammar",
    "grammar table",
    "tools",
    "benchmark",
    "snapshot",
    "not-a-command",
  ];
  const problems = [];
  for (const command of commands) {
    try {
      await execute(command);
    } catch (error) {
      problems.push("threw for " + command + ": " + error.message);
    }
  }
  const text = renderLines.join("\\n");
  for (const marker of ["no route", "threw for", "Failed to parse", "undefined%", "NaN", "object Object"]) {
    if (text.includes(marker)) problems.push("rendered " + marker);
  }
  console.log(JSON.stringify({
    problems,
    mode: (typeof elementById === "function" && elementById("mode-pill") ? elementById("mode-pill").textContent : ""),
    console_text: text,
    panels: {
      density: elementById("panel-density") ? elementById("panel-density").innerHTML : "",
      conversation: elementById("panel-conversation") ? elementById("panel-conversation").innerHTML : "",
      tools: elementById("panel-tools") ? elementById("panel-tools").innerHTML : "",
      grammar: elementById("panel-grammar") ? elementById("panel-grammar").innerHTML : "",
    },
  }));
  process.exit(0);
}, 2500);
'''


@pytest.fixture(scope="module")
def dashboard_run(tmp_path_factory) -> dict:
    """Run the dashboard script under node against a live in-process server."""
    httpd, base = _start_server()
    try:
        workdir = tmp_path_factory.mktemp("dashboard")
        combined = workdir / "combined.js"
        combined.write_text(
            SHIM.read_text()
            + "\n"
            + _script_of(DASHBOARD.read_text(encoding="utf-8"))
            + "\n"
            + RUNNER,
            encoding="utf-8",
        )
        environment = dict(os.environ)
        environment["ZENO_DASHBOARD_BASE"] = f"{base}/dashboard"
        completed = subprocess.run(
            ["node", str(combined)],
            capture_output=True,
            text=True,
            timeout=180,
            env=environment,
            cwd=str(workdir),
        )
        assert completed.returncode == 0, completed.stderr[-2000:]
        payload = json.loads(completed.stdout.strip().splitlines()[-1])
        payload["base"] = base
        payload["stderr"] = completed.stderr
        return payload
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_the_dashboard_script_connects_and_never_throws(dashboard_run):
    assert dashboard_run["problems"] == [], dashboard_run["problems"]
    assert dashboard_run["mode"] == "LIVE", dashboard_run["mode"]


def test_every_command_renders_something_useful(dashboard_run):
    text = dashboard_run["console_text"]
    # encode: the canonical payload was produced
    assert "@LOC[TYO] -> ?WX : { $WX.state == RAIN => !GEN[INDOOR, 3] | !GEN[OUTDOOR, 3] }" in text
    # run: an execution frame came back
    assert "!RET[" in text
    # check: a broken payload reports a diagnostic instead of crashing
    assert "ZN0003" in text
    # tokens / benchmark / tools / grammar all produced output
    assert "tokens:" in text
    assert "density pooled" in text
    assert "queries: " in text
    assert "ZENO GRAMMAR v0.1" in text          # the card (grammar)
    assert "canonical_example" in text          # the raw table (grammar table)
    # an unknown command is reported, not swallowed
    assert "unknown command: not-a-command" in text


def test_panels_render_live_numbers(dashboard_run):
    assert "pooled reduction" in dashboard_run["panels"]["density"]
    assert "per hop" in dashboard_run["panels"]["conversation"]
    assert "queries" in dashboard_run["panels"]["tools"]
    # the canonical example is a {human, zeno} pair: it must be formatted, never
    # rendered as "[object Object]"
    grammar_panel = dashboard_run["panels"]["grammar"]
    assert "@LOC[TYO] -> ?WX" in grammar_panel
    assert "object Object" not in grammar_panel
    assert "20 operators" in grammar_panel  # 4 flow + 16 expression


class _StaticHandler(SimpleHTTPRequestHandler):
    """A plain file server: what GitHub Pages actually is."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(REPO), **kwargs)

    def log_message(self, *args):  # keep pytest output clean
        pass


@pytest.fixture(scope="module")
def snapshot_run(tmp_path_factory) -> dict:
    """Serve the repo statically (no API at all) and load the page from there."""
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _StaticHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        workdir = tmp_path_factory.mktemp("dashboard-static")
        combined = workdir / "combined.js"
        combined.write_text(
            SHIM.read_text() + "\n" + _script_of(DASHBOARD.read_text(encoding="utf-8")) + "\n" + SNAPSHOT_RUNNER,
            encoding="utf-8",
        )
        environment = dict(os.environ)
        environment["ZENO_DASHBOARD_BASE"] = f"{base}/dashboard.html"
        # Pin the remembered backend to a port nothing listens on, so the
        # fallback path is exercised no matter what else runs on this machine.
        environment["ZENO_DASHBOARD_STORED_BACKEND"] = "http://127.0.0.1:9"
        completed = subprocess.run(
            ["node", str(combined)], capture_output=True, text=True, timeout=180, env=environment, cwd=str(workdir)
        )
        assert completed.returncode == 0, completed.stderr[-2000:]
        return json.loads(completed.stdout.strip().splitlines()[-1])
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_page_degrades_to_the_committed_snapshot_without_a_backend(snapshot_run):
    assert snapshot_run["problems"] == [], snapshot_run["problems"]
    assert snapshot_run["mode"] == "SNAPSHOT", snapshot_run["mode"]
    assert "read-only" in snapshot_run["status"]
    # the snapshot command reads the committed file, not the backend
    assert "zeno dashboard --write" in snapshot_run["console_text"]
    # panels work offline, using the portable data
    assert "corpus cases" in snapshot_run["panels"]["density"]
    assert "live backend only" in snapshot_run["panels"]["conversation"]
    assert "zeno v0.1" in snapshot_run["panels"]["grammar"]
    assert "@LOC[TYO] -> ?WX" in snapshot_run["panels"]["grammar"]
    assert "object Object" not in snapshot_run["panels"]["grammar"]
    # a live-only command explains how to start a backend instead of failing
    assert "this command needs a backend" in snapshot_run["console_text"]
    assert "zeno serve" in snapshot_run["console_text"]
