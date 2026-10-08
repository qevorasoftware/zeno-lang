"""The admin console: one page, every panel wired to a real endpoint.

The design brief was "modern Bootstrap 5 admin dashboard". What is under test
here is not the pixels but the contract underneath them:

* the page is served, and it names its own honesty box and its data sources;
* the decisions endpoint answers the owner's view (codes, layer verdicts) and
  refuses to answer anyone else in production;
* the page contains no claim a caller was never supposed to see being shown to
  the wrong caller — the owner panels are the owner's because the *route* is
  gated, not because the page hides them.
"""

from __future__ import annotations

import json
import secrets
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from aegis.capabilities import capabilities

HAVE_CRYPTO = capabilities().classical
requires_crypto = pytest.mark.skipif(not HAVE_CRYPTO, reason="cryptography wheel not installed")

ACTOR = "owner"
BIOMETRIC = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8]


def _serve(playground):
    from zeno.server import _Handler

    handler = type("AdminHandler", (_Handler,), {"playground": playground})
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"http://{httpd.server_address[0]}:{httpd.server_address[1]}"


def _get(base: str, path: str, headers: dict | None = None) -> tuple[int, dict | str]:
    request = urllib.request.Request(base + path, headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read().decode("utf-8")
            return response.status, (json.loads(body) if body.lstrip().startswith("{") else body)
    except urllib.error.HTTPError as error:
        payload = error.read().decode("utf-8")
        try:
            return error.code, json.loads(payload)
        except ValueError:
            return error.code, payload


# ---------------------------------------------------------------------------
# The page
# ---------------------------------------------------------------------------
def test_the_admin_console_is_served_and_names_its_contract():
    from zeno.server import Playground

    httpd, base = _serve(Playground())
    try:
        status, page = _get(base, "/admin")
        assert status == 200 and isinstance(page, str)
        assert "Zeno Admin" in page
        # it is the Bootstrap 5 kit the brief asked for
        assert "bootstrap@5.3" in page and "bootstrap-icons" in page
        # and it says what it is not: a view, not a control surface
        assert "not a control surface" in page
        # the honesty box is on the page, not in a footnote elsewhere
        assert "tarpit delays" in page and "does not guess" in page
        # every panel it fills is a real, gated route
        for route in ("/api/health", "/api/admin/decisions", "/api/watchtower", "/api/memory/sessions", "/api/agents"):
            assert route in page, f"the console must fill its panels from {route}"
    finally:
        httpd.shutdown()
        httpd.server_close()


@pytest.mark.skipif(HAVE_CRYPTO, reason="with the crypto backend a boundary exists and is described by its own test")
def test_the_decisions_endpoint_says_when_there_is_no_boundary(tmp_path):
    """Without a crypto backend there is no boundary, so no owner view either.

    The endpoint must say so (``enabled: false``) rather than pretend, and the
    page renders an "off" marker instead of an empty table that looks like
    "no decisions were ever made".
    """
    from zeno.memory import MemoryStore
    from zeno.server import Playground

    playground = Playground(memory=MemoryStore(str(tmp_path / "mem")))
    httpd, base = _serve(playground)
    try:
        status, payload = _get(base, "/api/admin/decisions?limit=5")
        assert status == 200
        assert payload["enabled"] is False
        assert payload["decisions"] == []
    finally:
        httpd.shutdown()
        httpd.server_close()


@requires_crypto
def test_the_decisions_endpoint_answers_in_development_with_the_owner_view(tmp_path):
    from zeno.memory import MemoryStore
    from zeno.server import Playground

    playground = Playground(memory=MemoryStore(str(tmp_path / "mem")))
    request = urllib.request.Request(
        "http://127.0.0.1/x", data=b"{}", headers={"Content-Type": "application/json"}, method="POST"
    )
    httpd, base = _serve(playground)
    try:
        # one allowed decision to look at
        request = urllib.request.Request(
            base + "/api/voice/turn",
            data=json.dumps({"session": "s", "text": "hello", "lang": "en"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            assert response.status == 200

        status, payload = _get(base, "/api/admin/decisions?limit=10")
        assert status == 200
        assert payload["enabled"] is True
        assert payload["attempts"] >= 1
        assert payload["decisions"], "a decision was made and should be in the owner's view"
        # the newest entry is the owner read that authorized this very request:
        # reads are audited like everything else, and marked read_only
        assert payload["decisions"][0].get("read_only") is True
        # the voice turn underneath it is an execution: its owner view carries
        # the layer verdicts and the sentence a caller is never shown
        executed = next(item for item in payload["decisions"] if not item.get("read_only"))
        assert executed["allowed"] is True
        assert "decision_id" in executed
        assert executed.get("layers"), "the owner's view carries the layer verdicts a caller never sees"
        assert "human_reason" in executed
    finally:
        httpd.shutdown()
        httpd.server_close()


# ---------------------------------------------------------------------------
# Production: the owner panels stay the owner's
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def admin_world(tmp_path_factory):
    from aegis.boundary import AuthorizationBoundary
    from aegis.capability import CapabilityVerifier, OwnerRoot
    from aegis.gate import Gateway, Policy
    from aegis.geo_hardware_lock import HardwareLock, device_fingerprint
    from aegis.guardian_ai import Sentinel
    from aegis.polymorphic_engine import PolymorphicEngine, RotationPolicy
    from aegis.zkp_validator import Prover, SchnorrGroup, Verifier

    root = tmp_path_factory.mktemp("admin")
    group = SchnorrGroup.generate(1024, quiet=True)
    engine = PolymorphicEngine(b"deployment-key", policy=RotationPolicy(epoch_seconds=21600))
    device = device_fingerprint()
    lock = HardwareLock(device, b"device-secret", keystore=root / "device.json")
    owner = OwnerRoot.create(name="owner_root", audience="zeno-local", epoch=1)
    grant = owner.issue(ACTOR, ["read:*", "execute:*"], ttl=600)
    gateway = Gateway(
        Policy.strict_policy(),
        verifier=Verifier(group),
        polymorphic=engine,
        hardware=lock,
        sentinel=Sentinel(max_events_per_minute=6000.0),
    )
    gateway.vault.enrol(ACTOR, BIOMETRIC)
    prover = Prover.from_secret(b"owner-identity", group=group, label=ACTOR)
    gateway.register_identity(ACTOR, prover.public)

    return {
        "grant": grant,
        "boundary": AuthorizationBoundary(
            gateway=gateway,
            capability_verifier=CapabilityVerifier(owner.public, audience="zeno-local", epoch=1),
        ),
    }


@requires_crypto
def test_production_refuses_the_decisions_panel_without_a_grant(admin_world):
    from zeno.server import Playground

    playground = Playground(boundary=admin_world["boundary"])
    httpd, base = _serve(playground)
    try:
        status, body = _get(base, "/api/admin/decisions?limit=5")
        assert status == 403
        assert body["error"]["code"].startswith("ZN-SEC-")
    finally:
        httpd.shutdown()
        httpd.server_close()
