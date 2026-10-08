"""The agent you can talk to: turns, memory, connected agents.

Three things are under test here, and each has an honest centre:

* **A turn goes through AEGIS.** In development the reply is labelled
  ``enforcement: development``; in production a turn without an owner grant is
  refused with an opaque code and *nothing is stored* — not even the attempt,
  unless memory is sealed.
* **Memory is sealed, and says when it is not.** With an owner key, the words are
  ciphertext on disk; without one, every record says ``"encrypted": false`` and
  so does the health endpoint. The chain catches edits.
* **Peers are peers.** The bridge fans out to as many agents as you register, no
  artificial cap, and each reply is remembered as *that peer's claim*.

Nothing in this file needs a network, a model or a microphone: the peer is a
local HTTP server, the answerer is the rule-based fallback, and the audio is a
synthesised tone.
"""

from __future__ import annotations

import base64
import json
import math
import os
import secrets
import stat
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from aegis.capabilities import capabilities

HAVE_CRYPTO = capabilities().classical
requires_crypto = pytest.mark.skipif(not HAVE_CRYPTO, reason="cryptography wheel not installed")

BIOMETRIC = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8]
ACTOR = "owner"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _serve(playground) -> tuple[ThreadingHTTPServer, str]:
    from zeno.server import _Handler

    handler = type("AgentHandler", (_Handler,), {"playground": playground})
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"http://{httpd.server_address[0]}:{httpd.server_address[1]}"


def _post(base: str, path: str, body: dict, headers: dict | None = None) -> tuple[int, dict]:
    request = urllib.request.Request(
        base + path,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json", **(headers or {})},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


def _get(base: str, path: str) -> dict:
    with urllib.request.urlopen(base + path, timeout=30) as response:
        return json.loads(response.read())


def tone_pcm(frequency: float = 220.0, seconds: float = 0.4, rate: int = 16_000) -> bytes:
    """Signed 16-bit little-endian PCM of a pure tone, as a browser would send."""
    count = int(seconds * rate)
    return b"".join(
        int(11000 * math.sin(2 * math.pi * frequency * index / rate)).to_bytes(2, "little", signed=True)
        for index in range(count)
    )


class _FakePeer(BaseHTTPRequestHandler):
    """A stand-in external agent: POST /ask -> {"reply": ...}."""

    server: "_FakeServer"

    def log_message(self, *args) -> None:  # silence the test output
        pass

    def do_POST(self) -> None:  # noqa: N802 - stdlib signature
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length) or b"{}")
        self.server.calls.append(
            {
                "path": self.path,
                "text": body.get("text"),
                "lang": body.get("lang"),
                "authorization": self.headers.get("Authorization", ""),
            }
        )
        payload = json.dumps(
            {"reply": f"[{self.server.label}] heard {body.get('text')!r} in {body.get('lang')}"}
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class _FakeServer(ThreadingHTTPServer):
    def __init__(self, label: str) -> None:
        super().__init__((  # type: ignore[arg-type]
            "127.0.0.1", 0), _FakePeer)
        self.label = label
        self.calls: list[dict] = []


@pytest.fixture()
def fake_peer():
    server = _FakeServer("alpha")
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server
    server.shutdown()
    server.server_close()


# ---------------------------------------------------------------------------
# The language rule
# ---------------------------------------------------------------------------
def test_any_language_tag_travels_unchanged():
    from zeno.agent import language_of, normalise_language

    for tag in ("gu", "gu-IN", "sw-KE", "pt-BR", "zh-Hant-TW", "qaa"):
        assert normalise_language(tag) == tag
    assert language_of("gu-IN") == "gu"
    assert language_of("qaa") == "qaa"
    with pytest.raises(ValueError, match="not a language tag"):
        normalise_language("not a tag!!")


# ---------------------------------------------------------------------------
# Memory
# ---------------------------------------------------------------------------
@requires_crypto
def test_memory_is_ciphertext_on_disk_and_reads_back(tmp_path):
    from zeno.memory import MemoryStore

    key = MemoryStore.create_owner(str(tmp_path / "owner.key"))
    assert stat.S_IMODE(key.stat().st_mode) == 0o600
    owner = MemoryStore.load_owner(str(key))
    store = MemoryStore(str(tmp_path / "mem"), owner=owner)

    assert store.encrypting
    store.record("s1", kind="turn", role="user", text="aaje Surat ma varsad che", lang="gu-IN")
    store.record("s1", kind="turn", role="agent", text="haan, varsad che", lang="gu-IN")

    raw = (tmp_path / "mem" / "s1.jsonl").read_text(encoding="utf-8")
    assert "varsad" not in raw, "the words must not appear in the file"
    assert store.read("s1")[-1]["text"] == "haan, varsad che"
    assert store.verify()["ok"] is True, store.verify()
    assert len(store.search("varsad")) == 2
    assert store.describe()["encrypted"] is True


@requires_crypto
def test_memory_without_a_key_is_visible_about_being_unsealed(tmp_path):
    from zeno.memory import MemoryStore

    store = MemoryStore(str(tmp_path / "mem"))
    assert not store.encrypting
    envelope = store.record("s1", kind="turn", text="plaintext words", lang="en")
    assert envelope["encrypted"] is False
    assert store.describe()["encrypted"] is False
    assert "plaintext words" in (tmp_path / "mem" / "s1.jsonl").read_text(encoding="utf-8")


@requires_crypto
def test_memory_detects_an_edit_and_refuses_a_lax_key_file(tmp_path):
    from zeno.memory import MemoryStore

    key = MemoryStore.create_owner(str(tmp_path / "owner.key"))
    store = MemoryStore(str(tmp_path / "mem"), owner=MemoryStore.load_owner(str(key)))
    store.record("s1", kind="turn", text="one", lang="en")
    store.record("s1", kind="turn", text="two", lang="en")

    target = tmp_path / "mem" / "s1.jsonl"
    lines = target.read_text(encoding="utf-8").splitlines()
    edited = json.loads(lines[0])
    edited["lang"] = "fr"
    lines[0] = json.dumps(edited, sort_keys=True)
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")

    report = store.verify()
    assert not report["ok"]
    assert any("digest" in problem for problem in report["problems"])

    # a key readable by others is refused, not quietly used
    lax = tmp_path / "lax.key"
    lax.write_text(key.read_text(encoding="utf-8"), encoding="utf-8")
    os.chmod(lax, 0o644)
    with pytest.raises(PermissionError, match="must not be readable"):
        MemoryStore.load_owner(str(lax))


@requires_crypto
def test_audio_is_sealed_and_round_trips(tmp_path):
    from zeno.memory import MemoryStore

    key = MemoryStore.create_owner(str(tmp_path / "owner.key"))
    store = MemoryStore(str(tmp_path / "mem"), owner=MemoryStore.load_owner(str(key)))
    blob = tone_pcm(220.0, seconds=0.2)
    stored = store.store_audio("s1", "rec1", blob)
    assert stored["encrypted"] is True
    written = (tmp_path / "mem" / "s1" / "audio" / "rec1.bin").read_text(encoding="utf-8")
    assert str(len(blob)) in written  # only the length and a digest are in the clear
    assert store.load_audio("s1", "rec1") == blob


def test_an_oversized_record_is_refused(tmp_path):
    from zeno.memory import MemoryStore

    store = MemoryStore(str(tmp_path / "mem"))
    with pytest.raises(ValueError, match="MAX_RECORD_BYTES"):
        store.record("s1", kind="turn", text="x" * (256 * 1024 + 1))


def test_forget_deletes_only_that_session(tmp_path):
    from zeno.memory import MemoryStore

    store = MemoryStore(str(tmp_path / "mem"))
    store.record("one", kind="turn", text="first", lang="en")
    store.record("two", kind="turn", text="second", lang="en")
    removed = store.forget("one")
    assert removed == 1
    assert store.sessions()[0]["id"] == "two"
    assert not (tmp_path / "mem" / "one.jsonl").exists()


# ---------------------------------------------------------------------------
# The turn
# ---------------------------------------------------------------------------
def test_a_development_turn_answers_in_any_language_and_remember(tmp_path):
    from zeno.memory import MemoryStore
    from zeno.server import Playground

    playground = Playground(memory=MemoryStore(str(tmp_path / "mem")))
    httpd, base = _serve(playground)
    try:
        status, turn = _post(
            base, "/api/voice/turn", {"session": "s", "text": "Kem cho?", "lang": "gu-IN"}
        )
        assert status == 200
        assert turn["ok"] is True
        assert turn["language"] == "gu-IN"
        assert turn["enforcement"] == "development"
        assert len(turn["stored"]) == 2  # the question and the answer
        assert turn["understanding"] in ("rule-based", "language-model")

        records = _get(base, "/api/memory/session?id=s")["records"]
        assert [record["role"] for record in records] == ["user", "agent"]
        assert {record["lang"] for record in records} == {"gu-IN"}
        assert _get(base, "/api/memory/verify")["ok"] is True
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_a_turn_with_audio_measures_a_voiceprint_and_keeps_it(tmp_path):
    from zeno.agent import wav_from_pcm
    from zeno.memory import MemoryStore
    from zeno.server import Playground

    playground = Playground(memory=MemoryStore(str(tmp_path / "mem")))
    httpd, base = _serve(playground)
    try:
        pcm = tone_pcm(220.0)
        status, turn = _post(
            base,
            "/api/voice/turn",
            {
                "session": "s",
                "text": "aa avaaj sambhalo",
                "lang": "gu-IN",
                "audio_b64": base64.b64encode(pcm).decode("ascii"),
                "sample_rate": 16_000,
            },
        )
        assert status == 200 and turn["ok"] is True
        # the tone is measured for what it is: a signal, never a proof
        assert abs(turn["voice"]["dominant_hz"] - 220.0) < 10.0
        assert "signal, not a proof" in " ".join(turn["voice"]["limits"])
        if playground.memory.encrypting:
            assert turn["audio_stored"]
            assert playground.memory.load_audio("s", turn["stored"][0]) == wav_from_pcm(pcm)
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_a_bad_language_tag_is_rejected_not_guessed(tmp_path):
    from zeno.memory import MemoryStore
    from zeno.server import Playground

    playground = Playground(memory=MemoryStore(str(tmp_path / "mem")))
    httpd, base = _serve(playground)
    try:
        status, body = _post(base, "/api/voice/turn", {"session": "s", "text": "hi", "lang": "!!"})
        assert status == 500 or (status == 200 and body["ok"] is False)
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_the_talking_page_is_served_and_names_its_limits(tmp_path):
    from zeno.server import Playground

    playground = Playground()
    httpd, base = _serve(playground)
    try:
        with urllib.request.urlopen(base + "/voice", timeout=30) as response:
            page = response.read().decode("utf-8")
        assert "talk to your agent" in page
        # the honesty box is part of the page, not a footnote somewhere else
        assert "browser" in page and "signal" in page
        health = _get(base, "/api/voice/health")
        assert "memory" in health and "agents" in health and "provider" in health
    finally:
        httpd.shutdown()
        httpd.server_close()


# ---------------------------------------------------------------------------
# Production: the same turn, behind the whole chain
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def voice_world(tmp_path_factory):
    """A strict gateway whose owner grant covers the agent surface, plus memory."""
    from aegis.boundary import AuthorizationBoundary
    from aegis.capability import CapabilityVerifier, OwnerRoot
    from aegis.gate import Gateway, Policy
    from aegis.geo_hardware_lock import HardwareLock, device_fingerprint
    from aegis.guardian_ai import Sentinel
    from aegis.polymorphic_engine import PolymorphicEngine, RotationPolicy
    from aegis.zkp_validator import Prover, SchnorrGroup, Verifier

    root = tmp_path_factory.mktemp("voice")
    group = SchnorrGroup.generate(1024, quiet=True)
    engine = PolymorphicEngine(b"deployment-key", policy=RotationPolicy(epoch_seconds=21600))
    device = device_fingerprint()
    lock = HardwareLock(device, b"device-secret", keystore=root / "device.json")

    owner = OwnerRoot.create(name="owner_root", audience="zeno-local", epoch=1)
    grant = owner.issue(ACTOR, ["agent:*", "read:memory", "execute:*"], ttl=600)

    gateway = Gateway(
        Policy.strict_policy(),
        verifier=Verifier(group),
        polymorphic=engine,
        hardware=lock,
        # a test suite is machine-paced; the guardian would rightly freeze it.
        # its anomaly behaviour has its own tests.
        sentinel=Sentinel(max_events_per_minute=6000.0),
    )
    gateway.vault.enrol(ACTOR, BIOMETRIC)
    prover = Prover.from_secret(b"owner-identity", group=group, label=ACTOR)
    gateway.register_identity(ACTOR, prover.public)

    def fresh_block() -> dict:
        nonce = secrets.token_urlsafe(24)
        proof = prover.prove(context=f"aegis:{ACTOR}:{nonce}".encode("utf-8"))
        return {
            "actor": ACTOR,
            "token": grant.encode(),
            "nonce": nonce,
            "proof": base64.b64encode(proof.encode()).decode("ascii"),
            "biometric": BIOMETRIC,
            "biometric_subject": ACTOR,
            "device": device.fingerprint,
        }

    from zeno.memory import MemoryStore

    return {
        "owner": owner,
        "grant": grant,
        "fresh_block": fresh_block,
        "memory": MemoryStore(str(root / "mem"), owner=owner.identity),
        "boundary": AuthorizationBoundary(
            gateway=gateway,
            capability_verifier=CapabilityVerifier(owner.public, audience="zeno-local", epoch=1),
        ),
    }


@requires_crypto
def test_production_refuses_a_turn_without_a_grant_and_stores_nothing(voice_world, tmp_path):
    from zeno.server import Playground

    playground = Playground(policy=None, boundary=voice_world["boundary"], memory=voice_world["memory"])
    if playground.watchtower is not None:
        playground.watchtower.tarpit_base_ms = 1
        playground.watchtower.tarpit_max_ms = 2
    httpd, base = _serve(playground)
    try:
        status, body = _post(base, "/api/voice/turn", {"session": "prod", "text": "hello", "lang": "en"})
        assert status == 403
        assert body["error"]["code"].startswith("ZN-SEC-")
        # refused before it began: no reply, and no record of the words
        assert playground.memory.sessions() == []
    finally:
        httpd.shutdown()
        httpd.server_close()


@requires_crypto
def test_a_fully_authorized_production_turn_is_answered_and_sealed(voice_world):
    from zeno.server import Playground

    playground = Playground(boundary=voice_world["boundary"], memory=voice_world["memory"])
    if playground.watchtower is not None:
        playground.watchtower.tarpit_base_ms = 1
        playground.watchtower.tarpit_max_ms = 2
    httpd, base = _serve(playground)
    try:
        block = voice_world["fresh_block"]()
        # the grant rides in the header (the dashboard's habit); the proof,
        # nonce and biometric ride in the aegis block, where the boundary reads them
        status, turn = _post(
            base,
            "/api/voice/turn",
            {
                "session": "prod",
                "text": "Kem cho?",
                "lang": "gu-IN",
                "aegis": {key: value for key, value in block.items() if key != "token"},
            },
            headers={"X-Zeno-Capability": block["token"]},
        )
        assert status == 200, turn
        assert turn["ok"] is True
        assert turn["enforcement"] == "production"
        assert turn["aegis"]["allowed"] is True

        # the words are stored sealed, and the owner's read gate can see them
        raw = Path(playground.memory.root, "prod.jsonl").read_text(encoding="utf-8")
        assert "Kem cho?" not in raw
        # the owner's read of their own memory: a grant, a fresh nonce and the
        # same identity proof as any other authorized request
        read_block = voice_world["fresh_block"]()
        status, view = _post(
            base,
            "/api/memory/search",
            {
                "query": "Kem cho",
                "aegis": {key: value for key, value in read_block.items() if key != "token"},
            },
            headers={"X-Zeno-Capability": read_block["token"]},
        )
        assert status == 200, view
        assert view["hits"] and view["hits"][0]["text"] == "Kem cho?"
    finally:
        httpd.shutdown()
        httpd.server_close()


@requires_crypto
def test_memory_reads_need_a_grant_even_in_production(voice_world):
    from zeno.server import Playground

    playground = Playground(boundary=voice_world["boundary"], memory=voice_world["memory"])
    httpd, base = _serve(playground)
    try:
        status, body = _post(base, "/api/memory/search", {"query": "anything"})
        assert status == 403
        assert body["error"]["code"].startswith("ZN-SEC-")
    finally:
        httpd.shutdown()
        httpd.server_close()


# ---------------------------------------------------------------------------
# Connected agents
# ---------------------------------------------------------------------------
def test_peers_register_ask_and_remember(tmp_path, fake_peer):
    from zeno.memory import MemoryStore
    from zeno.peers import AgentRegistry

    endpoint = f"http://127.0.0.1:{fake_peer.server_address[1]}"
    memory = MemoryStore(str(tmp_path / "mem"))
    registry = AgentRegistry(str(tmp_path / "agents.json"), memory=memory)

    registry.register("alpha", endpoint, capability="grant-for-alpha")
    assert Path(tmp_path / "agents.json").exists()
    # the grant is a bearer secret: it is not handed back by the registry
    listed = registry.peers()[0]
    assert listed["capability"] == "set"

    outcome = registry.ask("alpha", "hello there", lang="gu-IN", session="peers")
    assert outcome["ok"] is True
    assert outcome["reply"].startswith("[alpha]")
    assert fake_peer.calls[0]["text"] == "hello there"
    assert fake_peer.calls[0]["lang"] == "gu-IN"
    assert fake_peer.calls[0]["authorization"] == "Zeno grant-for-alpha"

    # the exchange is remembered, attributed to the peer
    records = memory.read("peers")
    assert any(record.get("role") == "peer:alpha" for record in records)


def test_peers_broadcast_fans_out_and_reports_failures(tmp_path, fake_peer):
    from zeno.memory import MemoryStore
    from zeno.peers import AgentRegistry

    registry = AgentRegistry(str(tmp_path / "agents.json"), memory=MemoryStore(str(tmp_path / "mem")))
    registry.register("alpha", f"http://127.0.0.1:{fake_peer.server_address[1]}")
    registry.register("ghost", "http://127.0.0.1:9", capability="")  # nothing listens there

    summary = registry.broadcast("all of you", lang="en", session="peers")
    assert summary["asked"] == 2
    assert summary["answered"] == 1
    assert summary["failed"] == 1
    assert any(item["peer"] == "alpha" and item["ok"] for item in summary["results"])
    assert any(item["peer"] == "ghost" and not item["ok"] for item in summary["results"])

    # the ghost's failure is a fact about the ghost, recorded as such
    ghost = [peer for peer in registry.peers() if peer["name"] == "ghost"][0]
    assert ghost["failures"] >= 1
    assert ghost["last_error"]

    # and a peer that was never connected is refused by name, not guessed at
    outcome = registry.ask("nobody", "hello")
    assert outcome["ok"] is False
    assert "no connected agent" in outcome["error"]


def test_a_peer_endpoint_must_be_http_and_a_name_must_be_a_name(tmp_path):
    from zeno.peers import AgentRegistry

    registry = AgentRegistry(str(tmp_path / "agents.json"))
    with pytest.raises(ValueError, match="http"):
        registry.register("bad", "ftp://example.invalid")
    with pytest.raises(ValueError, match="name"):
        registry.register("!!", "http://example.invalid")


def test_the_agent_routes_are_served(tmp_path, fake_peer):
    from zeno.memory import MemoryStore
    from zeno.peers import AgentRegistry
    from zeno.server import Playground

    # an explicit registry file: a test must never touch the real ~/.zeno
    registry = AgentRegistry(str(tmp_path / "agents.json"))
    playground = Playground(memory=MemoryStore(str(tmp_path / "mem")), peers=registry)
    registry.register("alpha", f"http://127.0.0.1:{fake_peer.server_address[1]}")
    httpd, base = _serve(playground)
    try:
        listed = _get(base, "/api/agents")
        assert listed["agents"][0]["name"] == "alpha"
        assert listed["bridge"]["connected"] == 1

        status, outcome = _post(
            base, "/api/agents/ask", {"name": "alpha", "text": "via http", "lang": "gu-IN"}
        )
        assert status == 200
        assert outcome["ok"] is True
        assert outcome["reply"].startswith("[alpha]")

        status, removed = _post(base, "/api/agents/remove", {"name": "alpha"})
        assert status == 200 and removed["removed"] is True
    finally:
        httpd.shutdown()
        httpd.server_close()
