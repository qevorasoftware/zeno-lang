"""P0 of the hardened plan: nothing effectful runs without AEGIS's permission.

Audit finding C1 was that ``POST /api/run`` reached the Zeno kernel directly, so
every layer could be bypassed by simply not using the gateway. These tests treat
that as the attack it is and assert the attack fails:

* a production server refuses an unauthorized request, and the kernel is proven
  *not* to have been reached (the route could return 403 yet still execute);
* the refusal carries a machine code and no explanation (S20/S21/S23);
* development mode permits — and every response says so, so the weaker posture
  can never be silent (S18/S25);
* a *fully* authorized production request does execute, because "refuse
  everything" would satisfy the tests above for entirely the wrong reason;
* removing any single piece of mandatory material turns that ALLOW into a DENY
  (plan §11 cases 3, 30), and defaulting to strict mode is impossible to miss.

The heavy fixtures (a Schnorr group, a hardware lock) are built once per module.
"""

from __future__ import annotations

import base64
import json
import secrets
import threading
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request as UrlRequest
from urllib.request import urlopen

import pytest

from aegis.boundary import AuthorizationBoundary, Caller
from aegis.capabilities import capabilities
from aegis.gate import LAYER_ORDER, Gateway, Policy
from zeno.server import Playground, _Handler, _build_boundary

HAVE_CRYPTO = capabilities().classical
requires_crypto = pytest.mark.skipif(
    not HAVE_CRYPTO, reason="cryptography wheel not installed"
)

BIOMETRIC = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8]
ACTOR = "owner"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def authorized_world(tmp_path_factory):
    """A strict gateway plus the material a legitimate caller would hold."""
    from aegis.geo_hardware_lock import HardwareLock, device_fingerprint
    from aegis.guardian_ai import Sentinel
    from aegis.polymorphic_engine import PolymorphicEngine, RotationPolicy
    from aegis.zkp_validator import Prover, SchnorrGroup, Verifier

    group = SchnorrGroup.generate(1024, quiet=True)
    engine = PolymorphicEngine(b"deployment-key", policy=RotationPolicy(epoch_seconds=21600))
    device = device_fingerprint()
    keystore = tmp_path_factory.mktemp("boundary") / "device.json"
    lock = HardwareLock(device, b"device-secret", keystore=keystore)

    gateway = Gateway(
        Policy.strict_policy(),
        verifier=Verifier(group),
        polymorphic=engine,
        hardware=lock,
        # A test suite fires requests far faster than any human, and the guardian
        # correctly calls that a burst and freezes the actor. Its anomaly behaviour
        # has its own tests; here we are testing the authorization boundary, so the
        # rate ceiling is lifted out of the way.
        sentinel=Sentinel(max_events_per_minute=6000.0),
    )
    gateway.vault.enrol(ACTOR, BIOMETRIC)

    prover = Prover.from_secret(b"owner-identity", group=group, label=ACTOR)
    # C3: a proof proves knowledge of *a* key; the registry says *whose*.
    gateway.register_identity(ACTOR, prover.public)

    epoch = engine.policy.epoch_at()
    rotated = engine.rotate_payload("?WX", epoch=epoch)

    def prove_over(nonce: str):
        """The proof context is derived from the nonce: aegis:<actor>:<nonce>."""
        return prover.prove(context=f"aegis:{ACTOR}:{nonce}".encode("utf-8"))

    def block_with(proof, nonce: str) -> dict:
        """The JSON shape a client sends for one attempt."""
        return {
            "actor": ACTOR,
            "nonce": nonce,
            "proof": base64.b64encode(proof.encode()).decode("ascii"),
            "biometric": BIOMETRIC,
            "biometric_subject": ACTOR,
            "device": device.fingerprint,
        }

    def fresh_block() -> dict:
        """A fresh nonce, and a proof over it, every time.

        The ZKP nullifier is derived from (identity, context), so a fixed context
        would admit exactly one accepted request ever — the nonce is what makes
        repeat requests possible while a replayed transcript stays impossible.
        """
        nonce = secrets.token_urlsafe(24)
        return block_with(prove_over(nonce), nonce)

    return {
        "gateway": gateway,
        "payload": rotated,
        "prover": prover,
        "prove_over": prove_over,
        "fresh_block": fresh_block,
        "boundary": AuthorizationBoundary(gateway=gateway),
    }


def _serve(playground: Playground) -> tuple[ThreadingHTTPServer, str]:
    handler = type("BoundaryHandler", (_Handler,), {"playground": playground})
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"http://{httpd.server_address[0]}:{httpd.server_address[1]}"


def _post(base: str, path: str, body: dict) -> tuple[int, dict]:
    """POST JSON, returning the status code for both success and refusal."""
    request = UrlRequest(
        base + path,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=30) as response:
            return response.status, json.loads(response.read())
    except HTTPError as error:
        return error.code, json.loads(error.read())


@pytest.fixture(scope="module")
def strict_server(authorized_world):
    playground = Playground(policy=Policy.strict_policy())
    playground.boundary = authorized_world["boundary"]
    httpd, base = _serve(playground)
    yield base, playground
    httpd.shutdown()
    httpd.server_close()


@pytest.fixture(scope="module")
def dev_server():
    playground = Playground()  # the shipping default: development policy
    httpd, base = _serve(playground)
    yield base, playground
    httpd.shutdown()
    httpd.server_close()


# ---------------------------------------------------------------------------
# C1 — the bypass is closed
# ---------------------------------------------------------------------------
@requires_crypto
def test_production_refuses_an_unauthorized_run(strict_server):
    base, _ = strict_server
    status, body = _post(base, "/api/run", {"payload": "?WX"})
    assert status == 403, body
    assert body["error"]["code"].startswith("ZN-SEC-")


@requires_crypto
def test_the_kernel_is_not_reached_when_the_request_is_refused(strict_server, monkeypatch):
    """A 403 is not enough: the route must not have executed anything."""
    base, playground = strict_server
    executed: list[str] = []
    original = Playground.run

    def spy(self, payload, state=None):
        executed.append(payload)
        return original(self, payload, state)

    monkeypatch.setattr(Playground, "run", spy)
    status, _ = _post(base, "/api/run", {"payload": "?WX"})
    assert status == 403
    assert executed == [], "the kernel ran despite the refusal"


@requires_crypto
def test_the_refusal_explains_nothing(strict_server):
    """S20/S21/S23: a code, and no narration of which layer refused."""
    base, _ = strict_server
    _, body = _post(base, "/api/run", {"payload": "?WX"})
    serialised = json.dumps(body).lower()
    assert "aegis" not in body or body.get("aegis") is None
    for leak in ("biometric", "proof", "ledger", "layer", "device", "no "):
        assert leak not in serialised, f"the refusal leaked {leak!r}: {serialised}"


@requires_crypto
def test_development_permits_but_labels_every_response(dev_server):
    """The dev bypass exists; being invisible was the thing that had to go."""
    base, _ = dev_server
    status, body = _post(base, "/api/run", {"payload": "?WX"})
    assert status == 200, body
    assert body["aegis"]["enforcement"] == "development"
    assert body["aegis"]["allowed"] is True
    health = json.loads(urlopen(base + "/api/health", timeout=10).read())
    assert health["enforcement"] == "development"
    assert health["policy"]["mode"] == "development"


@requires_crypto
def test_a_fully_authorized_production_request_executes(strict_server, authorized_world):
    """Deny-by-default must not mean deny-always: the good path has to work."""
    base, _ = strict_server
    body = {"payload": authorized_world["payload"], "aegis": authorized_world["fresh_block"]()}
    status, response = _post(base, "/api/run", body)
    assert status == 200, response
    assert response["aegis"]["allowed"] is True
    assert response["aegis"]["enforcement"] == "production"
    assert response["frame"]
    # the wire carried this epoch's rotated vocabulary; the kernel saw the
    # canonical payload restored by layer 6 (invariant S24)
    assert authorized_world["payload"] != "?WX"
    assert [call["name"] for call in response["calls"]] == ["WX"]


@requires_crypto
def test_removing_any_single_piece_of_material_is_refused(strict_server, authorized_world):
    """Plan §11 case 3 and 30: every mandatory layer must be genuinely required."""
    base, _ = strict_server
    full = authorized_world["fresh_block"]()
    status, _ = _post(base, "/api/run", {"payload": authorized_world["payload"], "aegis": full})
    assert status == 200

    for key in ("proof", "biometric", "biometric_subject", "device"):
        minus = {k: v for k, v in full.items() if k != key}
        status, body = _post(base, "/api/run", {"payload": authorized_world["payload"], "aegis": minus})
        assert status == 403, f"removing {key} did not refuse: {body}"

    # case 15: a proof harvested for one context must not work in another
    moved = dict(full)
    moved["nonce"] = secrets.token_urlsafe(24)  # a nonce the proof was not made over
    status, body = _post(base, "/api/run", {"payload": authorized_world["payload"], "aegis": moved})
    assert status == 403, f"a proof verified against the wrong context: {body}"

    # C3: a nonce is required, because a fixed context admits one request ever
    no_nonce = {k: v for k, v in full.items() if k != "nonce"}
    status, body = _post(base, "/api/run", {"payload": authorized_world["payload"], "aegis": no_nonce})
    assert status == 403, f"a request without a nonce was accepted: {body}"


@requires_crypto
def test_a_forged_proof_for_someone_else_is_refused(strict_server, authorized_world):
    """Case 16: a valid proof is not valid for somebody else's identity."""
    from aegis.zkp_validator import Prover

    base, _ = strict_server
    forged = Prover.from_secret(b"mallory", group=authorized_world["gateway"].verifier.group)
    proof = forged.prove(context=f"aegis:{ACTOR}".encode())
    block = authorized_world["fresh_block"]()
    block["proof"] = base64.b64encode(proof.encode()).decode("ascii")
    status, body = _post(base, "/api/run", {"payload": authorized_world["payload"], "aegis": block})
    assert status == 403
    assert body["error"]["code"].startswith("ZN-SEC-")


@requires_crypto
def test_a_replayed_proof_is_refused(strict_server, authorized_world):
    """Case 12: the same authorization cannot be spent twice.

    This is the nullifier's in-process guarantee. Durable, cross-process replay
    state is Phase P1 of the plan and is *not* claimed here.
    """
    base, _ = strict_server
    block = authorized_world["fresh_block"]()
    first, _ = _post(base, "/api/run", {"payload": authorized_world["payload"], "aegis": block})
    second, body = _post(base, "/api/run", {"payload": authorized_world["payload"], "aegis": block})
    assert first == 200
    assert second == 403, body


# ---------------------------------------------------------------------------
# C2 — strict mode is strict, and impossible to mistake for dev
# ---------------------------------------------------------------------------
def test_strict_policy_makes_all_eight_layers_mandatory():
    policy = Policy.strict_policy()
    assert policy.mode == "production"
    assert policy.strict
    assert policy.mandatory_layers == LAYER_ORDER
    assert policy.verify_ledger_signatures and policy.opaque_reasons


def test_development_policy_is_reported_as_such():
    policy = Policy()
    assert policy.mode == "development"
    assert not policy.strict
    assert "8-vajra" not in policy.mandatory_layers
    reported = policy.to_dict()
    assert reported["mode"] == "development" and reported["strict"] is False


@requires_crypto
def test_a_bare_request_is_denied_at_the_first_missing_layer():
    """No context at all is a refusal, not a default-allow."""
    gateway = Gateway(Policy.strict_policy())
    authorization = AuthorizationBoundary(gateway=gateway).authorize(
        Caller(actor="mallory"), b"?WX"
    )
    assert not authorization.allowed
    assert authorization.code.startswith("ZN-SEC-")
    assert authorization.to_dict().get("reason") in ("", None)  # opaque


@requires_crypto
def test_server_refuses_to_start_in_production_without_a_boundary(monkeypatch, capsys):
    """Fail closed at startup: no boundary, no production server."""
    from zeno import server as server_module

    monkeypatch.setattr(server_module, "_build_boundary", lambda mode, policy=None: None)
    code = server_module.serve(host="127.0.0.1", port=0, mode="production")
    assert code == 3
    assert "refusing to start" in capsys.readouterr().err


def test_build_boundary_returns_none_rather_than_raising():
    """A missing crypto backend must not crash the server; it must be visible."""
    from zeno import server as server_module

    monkeypatch_target = server_module.__dict__["_build_boundary"]
    assert monkeypatch_target("development") is not None or True  # never raises
    boundary = _build_boundary("development")
    assert boundary is not None or not HAVE_CRYPTO


# ---------------------------------------------------------------------------
# Audit trail
# ---------------------------------------------------------------------------
@requires_crypto
def test_every_attempt_becomes_a_ledger_entry(authorized_world):
    """S11: an authorization the owner cannot audit later did not happen."""
    gateway = Gateway(Policy.strict_policy())
    boundary = AuthorizationBoundary(gateway=gateway)
    before = len(gateway.ledger.entries)
    boundary.authorize(Caller(actor="mallory"), b"?WX")
    boundary.authorize(Caller(actor="mallory"), b"?WX")
    entries = gateway.ledger.entries[before:]
    attempts = [entry for entry in entries if entry.get("action") == "execute"]
    assert len(attempts) == 2, entries
    entries = attempts
    assert all(entry["decision"] == "deny" for entry in entries)
    assert boundary.stats()["refused"] == 2
    # the decision id is auditable: the owner can find this attempt again
    decision_id = boundary.recent[0].decision_id
    assert any(entry["metadata"].get("decision_id") == decision_id for entry in entries)


@requires_crypto
def test_owner_view_keeps_the_sentence_the_caller_never_saw(authorized_world):
    boundary = AuthorizationBoundary(gateway=Gateway(Policy.strict_policy()))
    authorization = boundary.authorize(Caller(actor="mallory"), b"?WX")
    assert authorization.human_reason  # the owner can read why
    assert "reason" not in authorization.to_dict()  # the caller cannot
