"""The web playground: application object and HTTP surface."""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from zeno.server import _Handler, build_app

CANONICAL = "@LOC[TYO] -> ?WX : { $WX.state == RAIN => !GEN[INDOOR, 3] | !GEN[OUTDOOR, 3] }"


# ---------------------------------------------------------------------------
# Application object
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def app():
    return build_app()


def test_health_reports_the_offline_mode(app):
    info = app.provider_info()
    assert info["provider"] in {"none", "mock"} or info["online"] is True
    assert info["tokenizer"].startswith(("tiktoken:", "estimator:"))


def test_encode_uses_the_rule_based_encoder_offline(app):
    payload = app.encode("Check the weather in Tokyo.")
    assert payload["payload"].startswith("@LOC[TYO]")
    assert payload["nl_tokens"] > 0
    assert payload["validation"]["ok"] is True


def test_run_returns_a_frame_and_trace(app):
    result = app.run(CANONICAL)
    assert result["frame"].startswith("!RET[")
    assert [step["name"] for step in result["steps"]] == ["WX", "GEN"]
    assert result["output"] == ["INDOOR 1", "INDOOR 2", "INDOOR 3"]


def test_run_with_seeded_state(app):
    result = app.run("?LEN[$SEEDED]", {"SEEDED": [1, 2, 3]})
    assert result["output"] == 3


def test_ask_returns_a_full_round_trip(app):
    outcome = app.ask("Check the weather in Tokyo.")
    assert outcome["payload"].startswith("@LOC[TYO]")
    assert outcome["response"]
    assert "TOKENS  :" in outcome["transcript"]


def test_grammar_endpoint_carries_the_spec(app):
    grammar = app.grammar()
    assert "ZENO GRAMMAR" in grammar["card"]
    assert grammar["spec"]["grammar_version"] == "v0.1"


def test_tools_endpoint_lists_the_demo_registry(app):
    tools = app.tools()
    assert "WX" in tools["queries"]
    assert "RET" in tools["actions"]
    assert tools["builtin"]["queries"]


def test_benchmark_endpoint_runs_both_benchmarks(app):
    report = app.benchmark()
    assert report["density"]["reduction"]["pooled_pct"] > 0
    assert report["conversation"]["reduction"]["per_hop_pct"] > 0


def test_playground_rejects_a_broken_payload(app):
    with pytest.raises(Exception):
        app.run("@LOC[TYO] ->")


# ---------------------------------------------------------------------------
# HTTP surface
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def base_url():
    handler = type("BoundHandler", (_Handler,), {"playground": build_app()})
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=2)


def fetch(url: str, payload=None):
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode() if payload is not None else None,
        headers={"Content-Type": "application/json"},
        method="POST" if payload is not None else "GET",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return response.status, json.loads(response.read() or b"{}")


def test_index_serves_html(base_url):
    with urllib.request.urlopen(base_url + "/", timeout=10) as response:
        body = response.read().decode()
    assert response.status == 200
    assert "text/html" in response.headers["Content-Type"]
    assert "ZENO" in body


def test_health_over_http(base_url):
    status, payload = fetch(base_url + "/api/health")
    assert status == 200 and payload["ok"] is True


def test_run_over_http(base_url):
    status, payload = fetch(base_url + "/api/run", {"payload": '!RET[OUT="pong"]'})
    assert status == 200
    assert payload["output"] == "pong"


def test_run_error_is_structured(base_url):
    try:
        fetch(base_url + "/api/run", {"payload": "@LOC[TYO] ->"})
        raise AssertionError("expected an error response")
    except urllib.error.HTTPError as error:
        assert error.code == 400
        payload = json.loads(error.read())
        assert payload["error"]["code"].startswith("ZN")
        assert payload["error"]["hint"]


def test_missing_route_is_404(base_url):
    try:
        fetch(base_url + "/api/nope")
        raise AssertionError("expected a 404")
    except urllib.error.HTTPError as error:
        assert error.code == 404


def test_path_traversal_is_blocked(base_url):
    try:
        fetch(base_url + "/static/../server.py")
        raise AssertionError("expected the traversal to be refused")
    except urllib.error.HTTPError as error:
        assert error.code in (403, 404)
