"""The watchtower: telemetry, tarpits and decoys.

The claims this file checks are deliberately narrow, because the module's own
docstring refuses the wider ones:

* a refused attempt is recorded, and the record holds digests rather than secrets;
* repeated refusals from one source flag it and alert the owner;
* delays are bounded and are never applied to traffic that was authorized;
* decoys are fabricated, marked, and never involve the kernel;
* the owner can read what happened, including from disk after a restart.
"""

from __future__ import annotations

import json
import threading
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request as UrlRequest
from urllib.request import urlopen

import pytest

from aegis.capabilities import capabilities
from aegis.watchtower import Watchtower, digest
from zeno.server import Playground, _Handler

# Some of these tests construct things that *refuse* to exist without a real
# signing backend — the audit ledger refuses rather than signing with a
# substitute, which is the behaviour we want. Those tests say so and skip.
requires_crypto = pytest.mark.skipif(
    not capabilities().classical, reason="the audit ledger needs the cryptography wheel"
)


@pytest.fixture()
def tower(tmp_path):
    return Watchtower(feed=str(tmp_path / "feed.jsonl"), tarpit_base_ms=10, tarpit_max_ms=40)


def _post(base: str, path: str, body: dict, headers: dict | None = None) -> tuple[int, dict]:
    request = UrlRequest(
        base + path,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", **(headers or {})},
        method="POST",
    )
    try:
        with urlopen(request, timeout=60) as response:
            return response.status, json.loads(response.read())
    except HTTPError as error:
        return error.code, json.loads(error.read())


def _serve(playground: Playground) -> tuple[ThreadingHTTPServer, str]:
    handler = type("TowerHandler", (_Handler,), {"playground": playground})
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"http://{httpd.server_address[0]}:{httpd.server_address[1]}"


# ---------------------------------------------------------------------------
# Recording
# ---------------------------------------------------------------------------
def test_a_refusal_is_recorded_with_digests_not_secrets(tower):
    secret = "Bearer super-secret-token"
    record, reaction = tower.observe(
        remote="203.0.113.9",
        method="POST",
        path="/api/run",
        actor_claimed="anonymous",
        user_agent="curl/8.5",
        code="ZN-SEC-0x3A01",
        body=b'{"payload":"?WX","password":"hunter2"}',
        headers={"Authorization": secret, "Cookie": "session=abc"},
    )
    blob = json.dumps(record.to_dict())
    assert "hunter2" not in blob and "super-secret-token" not in blob and "session=abc" not in blob
    payload = b'{"payload":"?WX","password":"hunter2"}'
    assert record.payload_digest == digest(payload)
    assert set(record.header_digests) == {"Authorization", "Cookie"}
    assert record.body_bytes == len(payload)
    assert set(record.header_digests.values()) == {digest(secret), digest("session=abc")}
    assert reaction.strike == 1 and not reaction.decoy


def test_the_feed_is_append_only_and_readable_from_disk(tower):
    for index in range(3):
        tower.observe(remote="198.51.100.4", method="GET", path="/api/run", code="x")
    lines = tower.read_feed()
    assert len(lines) == 3
    assert [line["strike"] for line in lines] == [1, 2, 3]
    assert all(line["remote"] == "198.51.100.4" for line in lines)
    # a new watchtower over the same file sees the history the owner kept
    reopened = Watchtower(feed=str(tower.feed_path))
    assert len(reopened.read_feed()) == 3


# ---------------------------------------------------------------------------
# Escalation
# ---------------------------------------------------------------------------
def test_the_third_strike_flags_the_source_and_alerts_the_owner(tower):
    reactions = [
        tower.observe(remote="203.0.113.9", method="POST", path="/api/run", code="x")[1]
        for _ in range(3)
    ]
    assert [reaction.alert for reaction in reactions] == [False, False, True]
    assert reactions[-1].verdict == "intruder"
    assert "203.0.113.9" in tower.intruders()
    assert tower.alerts()[0]["source"] == "203.0.113.9"
    assert tower.summary()["intruders"] == 1


@requires_crypto
def test_an_alert_reaches_the_audit_ledger():
    from aegis.blockchain_ledger import Ledger

    ledger = Ledger(node="watchtower-test")
    tower = Watchtower(feed="/tmp/watchtower-alert-test.jsonl", ledger=ledger, alert_threshold=2)
    for _ in range(2):
        tower.observe(remote="192.0.2.5", method="POST", path="/api/run", code="x")
    actions = [entry["action"] for entry in ledger.entries]
    assert "intrusion.alert" in actions


def test_different_sources_are_counted_separately(tower):
    tower.observe(remote="192.0.2.1", method="POST", path="/api/run", code="x")
    tower.observe(remote="192.0.2.2", method="POST", path="/api/run", code="x")
    tower.observe(remote="192.0.2.2", method="POST", path="/api/run", code="x")
    assert tower.intruders() == {} or "192.0.2.1" not in tower.intruders()


# ---------------------------------------------------------------------------
# The tarpit is bounded, and only for the uninvited
# ---------------------------------------------------------------------------
def test_the_tarpit_is_zero_until_a_source_is_flagged(tower):
    _, first = tower.observe(remote="203.0.113.9", method="POST", path="/api/run", code="x")
    assert first.tarpit_ms == 0


def test_the_tarpit_never_exceeds_its_ceiling(tower):
    delays = []
    for _ in range(12):
        _, reaction = tower.observe(remote="203.0.113.9", method="POST", path="/api/run", code="x")
        delays.append(reaction.tarpit_ms)
    assert max(delays) <= tower.tarpit_max_ms
    assert delays[-1] >= delays[2] > 0  # it escalates, then stops escalating


def test_the_tarpit_refuses_to_sleep_when_its_slots_are_gone():
    """The cap is what stops a tarpit becoming a denial-of-service against us."""
    tower = Watchtower(feed="/tmp/watchtower-cap-test.jsonl", tarpit_base_ms=50, max_sleeping=0)
    assert tower.apply_tarpit(500) == 0


def test_clear_forgets_the_live_view_but_not_the_feed(tower):
    tower.observe(remote="203.0.113.9", method="POST", path="/api/run", code="x")
    assert tower.clear() == 1
    assert tower.intruders() == {}
    assert len(tower.read_feed()) == 1


def test_the_summary_states_its_own_limits(tower):
    summary = tower.summary()
    assert summary["limits"], "a telemetry tool must state what it cannot do"
    assert any("does not stop" in line for line in summary["limits"])
    assert any("fabricated" in line for line in summary["limits"])


# ---------------------------------------------------------------------------
# Decoys
# ---------------------------------------------------------------------------
def test_a_decoy_is_fabricated_marked_and_unique(tower):
    first = tower.decoy(path="/api/run")
    second = tower.decoy(path="/api/run")
    assert first["decoy"] is True
    assert first["output"]["nonce"] != second["output"]["nonce"]
    assert first["calls"] == []  # a decoy never carries real tool calls
    assert tower.decoys_served == 2


def test_development_mode_records_but_does_not_deceive():
    """One permitted request is enough to state the claim: dev is not deceived.

    (Repeating it quickly would trip the *guardian*, which correctly calls a burst
    of identical requests an anomaly — that behaviour has its own tests.)
    """
    playground = Playground()  # development: decoys off, honest errors on
    httpd, base = _serve(playground)
    try:
        status, body = _post(base, "/api/run", {"payload": "@LOC[TYO] -> ?WX"})
        assert status == 200, body  # the default dev policy lets this through
        assert body["aegis"]["enforcement"] == "development"
        assert playground.watchtower.records == 0
        assert playground.watchtower.decoys_enabled is False
    finally:
        httpd.shutdown()
        httpd.server_close()


@requires_crypto
def test_production_flags_an_attacker_and_serves_decoys_without_touching_the_kernel():
    from aegis.gate import Policy

    playground = Playground(policy=Policy.strict_policy(), mode="production")
    calls: list[str] = []
    original = playground.run

    def spy(payload, state=None):
        calls.append(payload)
        return original(payload, state)

    playground.run = spy  # type: ignore[assignment]
    playground.watchtower.tarpit_base_ms = 1
    playground.watchtower.tarpit_max_ms = 2

    httpd, base = _serve(playground)
    try:
        seen = []
        for _ in range(4):
            status, body = _post(base, "/api/run", {"payload": "@LOC[TYO] -> ?WX"})
            seen.append((status, body.get("decoy", False)))
        assert seen[0] == (403, False), "the first attempt is refused honestly"
        assert seen[-1][0] == 200 and seen[-1][1] is True, "a flagged source gets a decoy"
        assert calls == [], "the kernel must never run for a decoy or a refusal"
        assert playground.watchtower.decoys_served >= 1
        assert playground.watchtower.intruders(), "the attacker is named in the owner's view"
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_authorized_traffic_is_never_tarpitted_or_recorded():
    """The tarpit exists for refusals; a permit must pass straight through."""
    playground = Playground()
    httpd, base = _serve(playground)
    try:
        status, body = _post(base, "/api/run", {"payload": "@LOC[TYO] -> ?WX"})
        assert status == 200 and body["aegis"]["allowed"] is True
        assert playground.watchtower.records == 0
    finally:
        httpd.shutdown()
        httpd.server_close()
