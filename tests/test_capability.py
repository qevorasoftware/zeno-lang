"""Owner-issued capability tokens (hardened plan §3-4, findings C3/H2).

The property under test throughout is the one the plan asks for: **only an entity
holding a currently valid grant from the owner can act**, and no part of that
grant can be widened, replayed, downgraded or forged by the holder.

Every test that needs ``cryptography`` skips with a stated reason without it,
because the tokens are hybrid-signed and there is no honest way to sign without a
signing library.
"""

from __future__ import annotations

import base64
import json
import os
import stat
from pathlib import Path

import pytest

from aegis.capabilities import capabilities
from aegis.capability import (
    CAPABILITY_CODES,
    Capability,
    CapabilityError,
    CapabilityVerifier,
    OwnerRoot,
    scope_matches,
)
from aegis.pqc_engine import Signature

HAVE_CRYPTO = capabilities().classical
requires_crypto = pytest.mark.skipif(
    not HAVE_CRYPTO, reason="cryptography wheel not installed"
)

pytestmark = requires_crypto


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture()
def owner():
    return OwnerRoot.create(name="owner_root", audience="zeno-test", epoch=5)


@pytest.fixture()
def verifier(owner):
    return CapabilityVerifier(owner.public, audience="zeno-test", epoch=5)


# ---------------------------------------------------------------------------
# The happy path
# ---------------------------------------------------------------------------
def test_an_owner_issued_token_verifies(owner, verifier):
    token = owner.issue("agent://weather", ["run:weather", "read:ledger"], ttl=300)
    check = verifier.verify(token, action="run:weather")
    assert check.ok, check.reason
    assert check.subject == "agent://weather"
    assert check.epoch == 5
    assert check.token_id == token.token_id


def test_a_token_round_trips_through_its_encoded_form(owner, verifier):
    token = owner.issue("agent://weather", ["run:weather"], ttl=300)
    restored = Capability.decode(token.encode())
    assert restored.token_id == token.token_id
    assert verifier.verify(restored, action="run:weather").ok


def test_an_undecodable_token_is_not_a_token():
    with pytest.raises(CapabilityError):
        Capability.decode("not-base64-at-all!!")


# ---------------------------------------------------------------------------
# Tampering, forging, downgrading
# ---------------------------------------------------------------------------
def test_widening_the_grant_breaks_the_signature(owner, verifier):
    token = owner.issue("agent://weather", ["run:weather"], ttl=300)
    forged = Capability.from_dict(token.to_dict())
    forged.capabilities = ("run:banking", "run:weather")
    check = verifier.verify(forged, action="run:banking")
    assert not check.ok
    assert check.code == CAPABILITY_CODES["signature"]


def test_a_stripped_post_quantum_half_is_a_downgrade(owner, verifier):
    """Finding H2: pqc_engine.verify() accepts a classical-only signature, so
    refusing that downgrade has to be an explicit check here."""
    token = owner.issue("agent://weather", ["run:weather"], ttl=300)
    stripped = Capability.from_dict(token.to_dict())
    stripped.signature = Signature(
        ed25519=token.signature.ed25519,
        mldsa=b"",
        signer=token.signature.signer,
        fingerprint=token.signature.fingerprint,
    )
    check = verifier.verify(stripped)
    assert not check.ok
    assert check.code == CAPABILITY_CODES["downgrade"]


def test_relabelling_the_suite_is_a_downgrade(owner, verifier):
    token = owner.issue("agent://weather", ["run:weather"], ttl=300)
    relabelled = Capability.from_dict(token.to_dict())
    relabelled.crypto_suite = "ed25519"
    relabelled.required_algorithms = ("ed25519",)
    assert verifier.verify(relabelled).code == CAPABILITY_CODES["downgrade"]


def test_a_token_signed_by_somebody_else_is_refused(owner, verifier):
    impostor = OwnerRoot.create(name="owner_root", audience="zeno-test", epoch=5)
    forged = impostor.issue("agent://weather", ["run:weather"], ttl=300)
    check = verifier.verify(forged, action="run:weather")
    assert not check.ok
    assert check.code in {CAPABILITY_CODES["signature"], CAPABILITY_CODES["issuer"]}


def test_the_issuer_name_alone_does_not_authorize(owner):
    """A stolen name is not a stolen key."""
    other = OwnerRoot.create(name="owner_root", audience="zeno-test", epoch=5)
    verifier = CapabilityVerifier(owner.public, audience="zeno-test", epoch=5)
    assert verifier.verify(other.issue("x", ["*"], ttl=60)).code == CAPABILITY_CODES["signature"]


# ---------------------------------------------------------------------------
# Binding: audience, epoch, time, revocation, scope, policy
# ---------------------------------------------------------------------------
def test_a_token_for_another_audience_is_refused(owner, verifier):
    token = owner.issue("agent://w", ["run:weather"], audience="somewhere-else", ttl=300)
    assert verifier.verify(token).code == CAPABILITY_CODES["audience"]


def test_an_old_epoch_token_stops_working_after_rotation(owner, verifier):
    token = owner.issue("agent://w", ["run:weather"], ttl=300)
    assert verifier.verify(token).ok
    owner.rotate_epoch()
    rotated = CapabilityVerifier(owner.public, audience="zeno-test", epoch=owner.epoch)
    assert rotated.verify(token).code == CAPABILITY_CODES["epoch"]


def test_an_expired_token_is_refused(owner, verifier):
    token = owner.issue("agent://w", ["run:weather"], ttl=-1)
    assert verifier.verify(token).code == CAPABILITY_CODES["expired"]


def test_a_token_dated_in_the_future_is_refused(owner, verifier):
    token = owner.issue("agent://w", ["run:weather"], ttl=300)
    token.issued_at += 3600
    assert verifier.verify(token).code == CAPABILITY_CODES["signature"]  # tampering shows up first

    fresh = owner.issue("agent://w", ["run:weather"], ttl=300)
    verifier_clock = CapabilityVerifier(
        owner.public, audience="zeno-test", epoch=5, clock=lambda: fresh.issued_at - 7200
    )
    assert verifier_clock.verify(fresh).code == CAPABILITY_CODES["expired"]


def test_a_revoked_token_is_refused(owner, verifier):
    token = owner.issue("agent://w", ["run:weather"], ttl=300)
    owner.revoke(token)
    after = CapabilityVerifier(
        owner.public, audience="zeno-test", epoch=5, revocations=owner.revocations
    )
    assert after.verify(token, action="run:weather").code == CAPABILITY_CODES["revoked"]


def test_an_ungranted_action_is_refused(owner, verifier):
    token = owner.issue("agent://w", ["run:weather"], ttl=300)
    check = verifier.verify(token, action="run:banking")
    assert not check.ok and check.code == CAPABILITY_CODES["capability"]


def test_a_policy_change_invalidates_old_tokens(owner):
    token = owner.issue("agent://w", ["run:weather"], ttl=300, policy_hash="policy-A")
    strict = CapabilityVerifier(
        owner.public, audience="zeno-test", epoch=5, policy_hash="policy-B"
    )
    assert strict.verify(token).code == CAPABILITY_CODES["policy"]


def test_the_semantic_scope_must_match(owner, verifier):
    token = owner.issue("agent://w", ["run:weather"], ttl=300, semantic_scope_hash="abc123")
    assert verifier.verify(token, semantic_scope_hash="abc123").ok
    assert verifier.verify(token, semantic_scope_hash="different").code == CAPABILITY_CODES["scope"]


def test_scope_matching_is_a_namespace_not_a_substring():
    assert scope_matches("*", "anything:at:all")
    assert scope_matches("execute:*", "execute:zeno")
    assert scope_matches("execute:*", "execute")
    assert not scope_matches("execute:*", "execute2")
    assert not scope_matches("run:weather", "run:weather:extra")
    assert scope_matches("RUN:Weather", "run:weather")


# ---------------------------------------------------------------------------
# Delegation (invariant S6)
# ---------------------------------------------------------------------------
def test_a_child_cannot_exceed_its_parent(owner):
    parent = owner.issue("agent://parent", ["run:weather"], ttl=300)
    with pytest.raises(CapabilityError):
        owner.issue("agent://child", ["run:banking"], parent=parent)


def test_a_child_inherits_the_parents_epoch_and_ceiling(owner):
    parent = owner.issue("agent://parent", ["run:weather"], ttl=120)
    child = owner.issue("agent://child", ["run:weather"], ttl=3600, parent=parent)
    assert child.epoch == parent.epoch
    assert child.expires_at <= parent.expires_at
    assert child.parent == parent.token_id
    assert child.token_id != parent.token_id


def test_issuing_below_the_minimum_suite_is_refused(owner):
    with pytest.raises(CapabilityError):
        owner.issue("agent://w", ["run:weather"], crypto_suite="ed25519")


# ---------------------------------------------------------------------------
# The owner's key file
# ---------------------------------------------------------------------------
def test_the_owner_key_is_written_0600_and_reloads(owner, tmp_path):
    path = tmp_path / "owner.json"
    owner.save(path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    reloaded = OwnerRoot.load(path)
    assert reloaded.fingerprint == owner.fingerprint
    token = reloaded.issue("agent://w", ["run:weather"], ttl=60)
    assert CapabilityVerifier(reloaded.public, audience="zeno-test", epoch=reloaded.epoch).verify(token).ok


def test_a_world_readable_key_is_not_overwritten(owner, tmp_path):
    path = tmp_path / "owner.json"
    owner.save(path)
    os.chmod(path, 0o644)
    with pytest.raises(CapabilityError):
        owner.save(path)


def test_a_redacted_key_file_cannot_be_loaded(tmp_path):
    """A key file without secrets is a public key, and must not be usable as one."""
    public_only = {"identity": OwnerRoot.create().public.to_dict()}
    path = tmp_path / "public.json"
    path.write_text(json.dumps(public_only))
    with pytest.raises((ValueError, KeyError)):
        OwnerRoot.load(path)


def test_a_poisoned_fingerprint_is_detected(owner, tmp_path):
    path = tmp_path / "owner.json"
    owner.save(path)
    data = json.loads(path.read_text())
    data["identity"]["fingerprint"] = "0" * 32
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        OwnerRoot.load(path)


# ---------------------------------------------------------------------------
# The boundary consults the owner, not just the layers
# ---------------------------------------------------------------------------
def test_a_production_boundary_refuses_a_request_without_a_token(owner):
    from aegis.boundary import AuthorizationBoundary, Caller
    from aegis.gate import Gateway, Policy

    verifier = CapabilityVerifier(owner.public, audience="zeno-test", epoch=5)
    boundary = AuthorizationBoundary(
        gateway=Gateway(Policy.strict_policy()), capability_verifier=verifier
    )
    authorization = boundary.authorize(Caller(actor="mallory"), b"?WX", {}, action="execute:zeno")
    assert not authorization.allowed
    assert authorization.to_dict()["code"] == CAPABILITY_CODES["malformed"]


def test_a_boundary_without_an_owner_key_can_honour_no_token():
    """An unconfigured verifier is a refusal, never an implicit pass."""
    from aegis.boundary import AuthorizationBoundary, Caller
    from aegis.gate import Gateway, Policy

    boundary = AuthorizationBoundary(gateway=Gateway(Policy.strict_policy()))
    authorization = boundary.authorize(Caller(actor="mallory"), b"?WX", {})
    assert authorization.to_dict()["code"] == CAPABILITY_CODES["unconfigured"]


def test_a_valid_grant_moves_the_refusal_past_the_capability_layer(owner):
    from aegis.boundary import AuthorizationBoundary, Caller
    from aegis.gate import Gateway, Policy

    verifier = CapabilityVerifier(owner.public, audience="zeno-test", epoch=5)
    boundary = AuthorizationBoundary(
        gateway=Gateway(Policy.strict_policy()), capability_verifier=verifier
    )
    token = owner.issue("agent://w", ["execute:*"], ttl=300)
    authorization = boundary.authorize(
        Caller(actor="agent://w"), b"?WX", {"capability": token}, action="execute:zeno"
    )
    # The capability was accepted, so the refusal (if any) comes from a later
    # requirement — the nonce — not from the token.
    assert authorization.human_reason.startswith("no nonce supplied")
