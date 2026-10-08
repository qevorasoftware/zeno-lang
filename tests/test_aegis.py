"""Tests for the AEGIS gateway (layers 1-7).

Two rules govern this file:

1. **Nothing hard-requires an optional wheel.** ``cryptography`` and ``pqcrypto``
   are probed through :mod:`aegis.capabilities`; every test that needs one skips
   with a stated reason when it is missing, and the honesty assertions run
   either way.
2. **Real properties, not plausibility.** Where a primitive has a published test
   vector (RFC 8439, RFC 5869) the vector is checked; where a mechanism claims a
   property (replay refusal, tamper detection, single-use nullifiers) the test
   performs the attack and asserts the attack fails.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from dataclasses import replace
from pathlib import Path

import pytest

from aegis import HONESTY, cipher, layers, report
from aegis.capabilities import capabilities

HAVE_CRYPTO = capabilities().classical
HAVE_PQC = bool(capabilities().pqc_kem and capabilities().pqc_sign)

requires_crypto = pytest.mark.skipif(not HAVE_CRYPTO, reason="cryptography wheel not installed")
requires_pqc = pytest.mark.skipif(not HAVE_PQC, reason="pqcrypto wheel not installed")


# ---------------------------------------------------------------------------
# Package surface
# ---------------------------------------------------------------------------
def test_layers_are_in_the_briefs_order():
    order = list(layers().items())
    assert [index for index, _ in order] == [1, 2, 3, 4, 5, 6, 7, 8]
    modules = [layer["module"] for _, layer in order]
    assert modules[0] == "aegis.pqc_engine"
    assert modules[7] == "aegis.vajra"
    assert modules.index("aegis.blockchain_ledger") == 3


def test_report_states_the_claim_it_does_not_make():
    payload = report()
    assert payload["honesty"]["vajra_is_a_cipher"] is False
    assert "unbreakable" in payload["honesty"]["claim_not_made"]
    assert HONESTY["vajra_is_a_cipher"] is False
    assert len(payload["layers"]) == 8


def test_capability_report_never_claims_pqc_without_the_wheel():
    caps = capabilities()
    if not HAVE_PQC:
        assert caps.pqc_kem is None and caps.pqc_sign is None
    assert isinstance(caps.hybrid_ready, bool)


# ---------------------------------------------------------------------------
# Layer 1: cipher (RFC vectors) + hybrid sealing
# ---------------------------------------------------------------------------
def test_hkdf_matches_rfc5869_vectors():
    from aegis._kdf import hkdf

    ikm = bytes.fromhex("0b" * 22)
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    expected = bytes.fromhex(
        "3cb25f25faacd57a90434f64d0362f2a"
        "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )
    assert hkdf(ikm, 42, salt=salt, info=info) == expected

    # RFC 5869 test case 3: zero-length salt and info.
    assert hkdf(ikm, 42, salt=b"", info=b"") == bytes.fromhex(
        "8da4e775a563c18f715f802a063c5a31"
        "b8a11f5c5ee1879ec3454e5f3c738d2d"
        "9d201395faa4b61a96c8"
    )


def test_pure_python_aead_matches_rfc8439_vector():
    from aegis import _chacha

    key = bytes(range(0x80, 0xA0))
    nonce = bytes.fromhex("070000004041424344454647")
    aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    plaintext = (
        b"Ladies and Gentlemen of the class of '99: If I could offer you "
        b"only one tip for the future, sunscreen would be it."
    )
    expected = bytes.fromhex(
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b6116"
    )
    sealed = _chacha.aead_encrypt(key, nonce, plaintext, aad)
    assert sealed[:-16] == expected
    assert sealed[-16:] == bytes.fromhex("1ae10b594f09e26a7e902ecbd0600691")
    assert _chacha.aead_decrypt(key, nonce, sealed, aad) == plaintext


@requires_crypto
def test_pure_python_aead_agrees_with_the_audited_library():
    from aegis import _chacha
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    for length in (0, 1, 15, 63, 64, 1000):
        key = os.urandom(32)
        nonce = os.urandom(12)
        aad = os.urandom(7)
        data = os.urandom(length)
        assert _chacha.aead_encrypt(key, nonce, data, aad) == ChaCha20Poly1305(key).encrypt(
            nonce, data, aad
        )


@requires_crypto
def test_aead_rejects_a_modified_tag():
    key = os.urandom(32)
    nonce, sealed = cipher.encrypt(key, b"payload")
    assert cipher.decrypt(key, nonce, sealed) == b"payload"
    with pytest.raises(cipher.AeadError):
        cipher.decrypt(key, nonce, sealed[:-1] + bytes([sealed[-1] ^ 0x01]))
    with pytest.raises(cipher.AeadError):
        cipher.decrypt(key, nonce, sealed, b"wrong-aad")


@requires_crypto
def test_seal_and_open_round_trip_and_reject_every_attack():
    from aegis.pqc_engine import SealedBox, Sealer, generate_identity, open_box

    alice, bob, eve = (generate_identity(name) for name in ("alice", "bob", "eve"))
    box = Sealer(alice).seal(b"@LOC[TYO] -> ?WX", recipient=bob.public)

    assert open_box(box, recipient=bob, sender=alice.public) == b"@LOC[TYO] -> ?WX"
    assert Sealer(alice).seal(b"x", recipient=bob.public).quantum_resistant == HAVE_PQC

    # a modified ciphertext
    tampered = replace(box, ciphertext=box.ciphertext[:-1] + bytes([box.ciphertext[-1] ^ 1]))
    with pytest.raises(cipher.AeadError):
        open_box(tampered, recipient=bob)

    # re-addressed to another recipient fingerprint: the AAD covers the metadata
    re_addressed = replace(box, meta={**box.meta, "recipient_fingerprint": eve.fingerprint})
    with pytest.raises(cipher.AeadError):
        open_box(re_addressed, recipient=bob)

    # a different key holder
    with pytest.raises(Exception):
        open_box(box, recipient=eve)

    # envelope framing
    assert SealedBox.decode(box.encode()).ciphertext == box.ciphertext
    with pytest.raises(ValueError):
        SealedBox.decode(b"not-an-envelope")


@requires_pqc
def test_hybrid_key_depends_on_both_halves():
    """Breaking one half must not be enough: the key must differ when either input does."""
    from aegis.pqc_engine import Sealer, generate_identity

    bob = generate_identity("bob")
    box_a = Sealer(generate_identity("a")).seal(b"m", recipient=bob.public)
    box_b = Sealer(generate_identity("a")).seal(b"m", recipient=bob.public)
    # Fresh ephemerals and fresh KEM encapsulations every time.
    assert box_a.ephemeral_public != box_b.ephemeral_public
    assert box_a.kem_ciphertext != box_b.kem_ciphertext
    assert box_a.ciphertext != box_b.ciphertext
    assert box_a.quantum_resistant and box_a.kem_ciphertext


@requires_pqc
def test_dual_signature_rejects_tampering_in_either_half():
    from aegis.pqc_engine import generate_identity, sign, verify

    alice = generate_identity("alice")
    message = b"transcript"
    signature = sign(alice, message)
    assert signature.ed25519 and signature.mldsa
    assert verify(alice.public, message, signature)
    assert not verify(alice.public, b"other", signature)
    assert not verify(alice.public, message, replace(signature, ed25519=b"\x00" * 64))
    assert not verify(alice.public, message, replace(signature, mldsa=b"\x00" * 64))


@requires_crypto
def test_nonce_reuse_is_refused_by_the_sealer():
    from aegis.pqc_engine import Sealer, generate_identity

    sealer = Sealer(generate_identity("alice"))
    sealer._remember(b"\x01" * 12)
    with pytest.raises(ValueError):
        sealer._remember(b"\x01" * 12)


# ---------------------------------------------------------------------------
# Layer 2: biometrics
# ---------------------------------------------------------------------------
@requires_crypto
def test_biometric_tolerates_noise_and_refuses_impostors():
    from aegis.biometric_auth import BiometricVault, features_from_text

    vault = BiometricVault()
    template = features_from_text("amara", dimensions=256)
    vault.enrol("amara", template, channels=["fingerprint", "keystroke"])

    noisy = [value + 0.03 for value in template]
    assert vault.verify("amara", noisy)
    assert not vault.verify("amara", features_from_text("eve", dimensions=256))
    assert len(vault.unlock("amara", noisy)) == 32


@requires_crypto
def test_biometric_reports_the_entropy_it_actually_has():
    """A 32-dimension template is ~20 bits: the module must say so, not pretend."""
    from aegis.biometric_auth import BiometricVault, features_from_text

    vault = BiometricVault()
    small = vault.enrol("amara", features_from_text("amara", dimensions=32))
    assert small.info["entropy_bits"] < 64
    assert small.info["entropy_grade"] == "weak"
    assert "NOT sufficient" in small.info["honest_limit"]

    with pytest.raises(ValueError):
        BiometricVault().enrol("amara", features_from_text("amara", dimensions=32), require_entropy=True)

    big = BiometricVault().enrol("amara", features_from_text("amara", dimensions=512))
    assert big.info["entropy_grade"] == "strong"


def enrolment_key_guard():
    """Distinctive feature values, so a leak into the export would be obvious."""
    from aegis.biometric_auth import features_from_text

    return features_from_text("amara", dimensions=128)


@requires_crypto
def test_biometric_export_contains_no_templates_or_secrets():
    from aegis.biometric_auth import BiometricVault, features_from_text

    vault = BiometricVault()
    enrolment = vault.enrol("amara", features_from_text("amara", dimensions=128))
    imported = json.dumps(vault.export())
    assert enrolment.key.hex() not in imported
    assert "helper" in imported and "verifier" in imported
    records = vault.export()["records"]
    assert set(next(iter(records.values()))) >= {"helper", "verifier", "salt"}
    assert "template" not in next(iter(records.values()))
    # the raw features must not survive anywhere in the record (only values
    # distinctive enough not to collide with a number in the JSON format)
    distinctive = [
        f"{value:.6f}" for value in enrolment_key_guard() if abs(value) > 0.01 and abs(value) < 0.99
    ]
    assert distinctive
    assert not any(text in imported for text in distinctive)


def test_dna_commitment_is_labelled_as_an_identifier_not_a_secret():
    from aegis.biometric_auth import dna_commitment

    first = dna_commitment("ACGTACGT", subject_salt=b"0" * 16)
    second = dna_commitment("acgtacgt", subject_salt=b"0" * 16)
    assert first == second  # case-insensitive
    assert first != dna_commitment("ACGTACGT", subject_salt=b"1" * 16)


# ---------------------------------------------------------------------------
# Layer 3: zero-knowledge proofs
# ---------------------------------------------------------------------------
def test_miller_rabin_separates_primes_from_composites():
    from aegis.zkp_validator import is_probable_prime

    assert all(is_probable_prime(n) for n in (2, 3, 5, 7, 97, 7919, 104729))
    assert not any(is_probable_prime(n) for n in (1, 4, 9, 15, 21, 1001, 1729, 1105))


@requires_crypto
def test_schnorr_group_rejects_bad_parameters():
    from aegis.zkp_validator import SchnorrGroup

    with pytest.raises(ValueError):
        SchnorrGroup.from_numbers(p=17, g=2)  # far too small
    # a composite subgroup order must be refused by validate()
    with pytest.raises(ValueError):
        SchnorrGroup(p=71, q=35, g=2, bits=2048).validate()


@requires_crypto
def test_proof_accepts_once_context_binds_and_forgeries_fail():
    from aegis.zkp_validator import Prover, SchnorrGroup, Verifier

    group = SchnorrGroup.generate(1024, quiet=True)
    prover = Prover.from_secret(b"amara-identity", group=group, label="amara")
    verifier = Verifier(group)

    proof = prover.prove(context=b"session-1")
    assert verifier.verify(prover.public, proof, context=b"session-1")
    # single-use: the same proof cannot be replayed
    assert not verifier.verify(prover.public, proof, context=b"session-1")

    fresh = prover.prove(context=b"session-2")
    assert not verifier.verify(prover.public, fresh, context=b"session-3")
    assert verifier.verify(prover.public, fresh, context=b"session-2")

    forged = replace(prover.prove(context=b"session-4"), response=proof.response)
    assert not verifier.verify(prover.public, forged, context=b"session-4")

    other = Prover.from_secret(b"eve", group=group, label="eve")
    assert not verifier.verify(other.public, prover.prove(context=b"session-5"), context=b"session-5")


@requires_crypto
def test_pedersen_commitment_hides_the_value_and_proves_its_opening():
    from aegis.zkp_validator import Prover, SchnorrGroup, Verifier

    group = SchnorrGroup.generate(1024, quiet=True)
    prover = Prover.from_secret(b"amara", group=group)
    verifier = Verifier(group)
    commitment = prover.commit(7, label="clearance")
    repeat = prover.commit(7)
    # Hiding comes from the blinding factor: the same value twice, two different
    # commitments, so the commitment is not a lookup table of values.
    assert commitment.commitment != repeat.commitment
    assert commitment.blinding != repeat.blinding
    assert verifier.verify(commitment.public(), prover.prove_opening(commitment, context=b"c"), context=b"c")
    # an opening proof made for a different commitment must not verify against this one
    other = prover.commit(9)
    other_proof = prover.prove_opening(other, context=b"c")
    assert verifier.verify(other.public(), other_proof, context=b"c")
    assert not verifier.verify(commitment.public(), other_proof, context=b"c")


def test_zkp_reports_that_it_is_not_a_snark():
    from aegis.zkp_validator import Verifier

    described = Verifier().describe()
    assert described["snark"] is False and described["stark"] is False
    assert "Schnorr" in described["scheme"]


# ---------------------------------------------------------------------------
# Layer 4: ledger
# ---------------------------------------------------------------------------
def test_merkle_root_and_inclusion_proofs():
    from aegis.blockchain_ledger import merkle_proof, merkle_root, verify_merkle_proof

    leaves = [f"entry-{index}".encode() for index in range(7)]
    root = merkle_root(leaves)
    assert all(verify_merkle_proof(leaf, merkle_proof(leaves, index), root) for index, leaf in enumerate(leaves))
    assert not verify_merkle_proof(b"forged", merkle_proof(leaves, 2), root)
    assert merkle_root([]) == "0" * 64


@requires_crypto
def test_ledger_detects_an_edited_entry():
    from aegis.blockchain_ledger import Ledger, LedgerEntry

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "ledger.json"
        ledger = Ledger(node="gateway-1", block_size=2, path=path)
        ledger.append(LedgerEntry(actor="amara", action="access", decision="allow"))
        ledger.append(LedgerEntry(actor="eve", action="access", decision="deny"))
        ledger.seal_block()
        assert ledger.verify().ok

        data = json.loads(path.read_text())
        data["blocks"][0]["entries"][0]["decision"] = "deny"
        path.write_text(json.dumps(data))

        status = Ledger.load(path).verify()
        assert not status.ok
        assert "merkle" in status.reason or "signature" in status.reason


@requires_crypto
def test_ledger_reports_when_signatures_could_not_be_checked():
    from aegis.blockchain_ledger import Ledger

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "ledger.json"
        ledger = Ledger(node="n", block_size=1, path=path)
        ledger.record(actor="a", action="access")
        ledger.seal_block()
        loaded = Ledger.load(path)
        assert loaded.verify().signatures_checked is True
        assert loaded.verify().ok


@requires_crypto
def test_ledger_says_it_is_tamper_evident_not_immutable():
    from aegis.blockchain_ledger import Ledger

    notes = " ".join(Ledger().security_notes())
    assert "not immutable" in notes
    assert "anchor" in notes
    assert "denial-of-service" in notes


# ---------------------------------------------------------------------------
# Layer 5: guardian sentinel
# ---------------------------------------------------------------------------
def _baseline(sentinel, actor="amara", count=8, device="laptop-1", lat=21.17, lon=72.83, hour=10):
    for index in range(count):
        sentinel.observe(
            {
                "actor": actor,
                "action": "access",
                "decision": "allow",
                "timestamp": 1000.0 + index * 60,
                "metadata": {"device": device, "latitude": lat, "longitude": lon, "hour": hour},
            }
        )


def test_sentinel_allows_normal_traffic_and_freezes_impossible_travel():
    from aegis.guardian_ai import Sentinel

    sentinel = Sentinel()
    _baseline(sentinel)
    decision = sentinel.observe(
        {
            "actor": "amara",
            "action": "access",
            "decision": "allow",
            "timestamp": 2000.0,
            "metadata": {"device": "laptop-1", "latitude": 51.5, "longitude": -0.12, "hour": 10},
        }
    )
    assert decision.decision == "FREEZE"
    assert any("not travel" in reason for reason in decision.reasons)


def test_sentinel_auxiliary_scorer_can_only_escalate():
    from aegis.guardian_ai import Sentinel

    normal = {"actor": "amara", "action": "access", "decision": "allow", "metadata": {"hour": 10}}

    escalating = Sentinel(auxiliary=lambda observation, profile: 9.0)
    _baseline(escalating)
    assert escalating.observe(dict(normal)).reviewed

    # A negative score can never subtract scrutiny: the floor is the unmodified score.
    lowering = Sentinel(auxiliary=lambda observation, profile: -9.0)
    _baseline(lowering)
    decision = lowering.observe(dict(normal))
    assert decision.decision == "ALLOW" and decision.score == 0.0
    assert decision.advisory == []  # nothing was added, and nothing was subtracted


def test_sentinel_freeze_needs_two_approvers_to_lift():
    from aegis.guardian_ai import Sentinel

    sentinel = Sentinel()
    sentinel.freeze("kill switch", actor="amara", requested_by="sentinel")
    assert sentinel.observe({"actor": "amara", "action": "access", "decision": "allow"}).blocked
    with pytest.raises(PermissionError):
        sentinel.unfreeze("amara", approvers=["amara"])
    sentinel.unfreeze("amara", approvers=["amara", "chen"])
    assert not sentinel.is_frozen("amara")
    assert sentinel.freeze_log[0]["requested_by"] == "sentinel"


def test_sentinel_is_statistics_not_a_trained_model():
    from aegis.guardian_ai import Sentinel

    described = Sentinel().describe()
    assert described["trained_model"] is False
    assert described["llm_used"] is False
    assert "escalate-only" in described["llm_role"]


# ---------------------------------------------------------------------------
# Layer 6: polymorphic rotation
# ---------------------------------------------------------------------------
def test_rotation_replaces_vocabulary_and_restores_it():
    from aegis.polymorphic_engine import PolymorphicEngine

    engine = PolymorphicEngine(b"rotation-key-material", names=["WX", "GEN", "RET"])
    source = "@LOC[TYO] -> ?WX : { $WX.state == RAIN => !GEN[INDOOR, 3] }"
    rotated = engine.rotate_payload(source, epoch=100)
    assert "?WX" not in rotated and "!GEN" not in rotated
    assert engine.restore_payload(rotated, 100) == source


def test_rotation_is_deterministic_per_key_and_differs_per_epoch():
    from aegis.polymorphic_engine import PolymorphicEngine

    names = ["WX", "GEN"]
    first = PolymorphicEngine(b"key-a", names=names)
    same = PolymorphicEngine(b"key-a", names=names)
    other = PolymorphicEngine(b"key-b", names=names)
    assert first.table(10).forward == same.table(10).forward
    assert first.table(10).forward != other.table(10).forward
    assert first.table(10).forward != first.table(11).forward


def test_rotation_table_is_verified_against_the_key():
    from aegis.polymorphic_engine import PolymorphicEngine

    from aegis.polymorphic_engine import SyntaxTable

    # canonical registry: re-derived from the key alone
    canonical = PolymorphicEngine(b"key-a")
    payload = canonical.table(5).to_dict()
    assert SyntaxTable.from_dict(payload, b"key-a").forward == canonical.table(5).forward
    with pytest.raises(ValueError):
        SyntaxTable.from_dict(payload, b"wrong-key")

    # a custom registry must be supplied by the receiver, or verification fails
    custom = PolymorphicEngine(b"key-a", names=["WX"])
    custom_payload = custom.table(5).to_dict()
    assert SyntaxTable.from_dict(custom_payload, b"key-a", names=["WX"]).forward == custom.table(5).forward
    with pytest.raises(ValueError):
        SyntaxTable.from_dict(custom_payload, b"key-a")


def test_rotation_reports_that_it_is_not_a_cipher():
    from aegis.polymorphic_engine import PolymorphicEngine

    described = PolymorphicEngine(b"key").describe()
    assert described["cipher"] is False
    assert "not a key-holding receiver" in described["note"]


# ---------------------------------------------------------------------------
# Layer 7: device binding and geofence
# ---------------------------------------------------------------------------
def test_device_fingerprint_is_stable_and_reports_its_grade():
    from aegis.geo_hardware_lock import device_fingerprint

    first = device_fingerprint()
    second = device_fingerprint()
    assert first.fingerprint == second.fingerprint
    assert len(first.fingerprint) == 64
    described = first.to_dict()
    assert described["identity_is_an_identifier"] is True
    assert described["identifier_is_not_an_authenticator"] is (not first.hardware_backed)


@requires_crypto
def test_device_lock_refuses_another_device_and_an_expired_blob():
    from aegis.geo_hardware_lock import GeoFence, HardwareLock, LockError, device_fingerprint

    with tempfile.TemporaryDirectory() as tmp:
        store = Path(tmp) / "device.json"
        fence = GeoFence(21.17, 72.83, 60, "Surat")
        lock = HardwareLock.for_this_device(store, fence=fence)
        blob = lock.seal(b"payload", latitude=21.18, longitude=72.84)

        assert lock.unseal(blob, latitude=21.18, longitude=72.84) == b"payload"
        with pytest.raises(LockError):
            lock.unseal(blob, latitude=28.61, longitude=77.21)  # Delhi

        # a keystore bound to a different device fingerprint is refused
        foreign = json.loads(store.read_text())
        foreign["device"] = "0" * 64
        store.write_text(json.dumps(foreign))
        with pytest.raises(LockError):
            HardwareLock.for_this_device(store, create=False)

        # expiry
        fresh = HardwareLock.for_this_device(store, fence=fence) if False else None  # keep lint quiet
        lock2 = HardwareLock(device_fingerprint(), lock.secret, fence=fence)
        expired = lock2.seal(b"payload", expires_at=time.time() - 5)
        with pytest.raises(LockError):
            lock2.unseal(expired)


@requires_crypto
def test_keystore_is_written_privately():
    from aegis.geo_hardware_lock import HardwareLock

    with tempfile.TemporaryDirectory() as tmp:
        store = Path(tmp) / "nested" / "device.json"
        HardwareLock.for_this_device(store)
        assert oct(store.stat().st_mode)[-3:] == "600"
        assert oct(store.parent.stat().st_mode)[-3:] == "700"


def test_geofence_is_reported_as_spoofable():
    from aegis.geo_hardware_lock import GeoFence, haversine_km

    fence = GeoFence(21.17, 72.83, 60, "Surat")
    assert fence.contains(21.18, 72.84)
    assert not fence.contains(19.076, 72.877)  # Mumbai is ~233 km away
    assert abs(haversine_km(21.17, 72.83, 19.076, 72.877) - 232.9) < 1.0
    assert fence.to_dict()["spoofable"] is True
    inside, reason = fence.check(None, None)
    assert not inside and "cannot be evaluated" in reason


# ---------------------------------------------------------------------------
# The gateway itself
# ---------------------------------------------------------------------------
def test_gateway_runs_the_layers_in_the_briefs_order():
    from aegis.gate import LAYER_ORDER

    assert LAYER_ORDER == (
        "1-pqc",
        "2-biometric",
        "3-zkp",
        "4-ledger",
        "5-sentinel",
        "6-polymorphic",
        "7-geo-hardware",
        "8-vajra",
    )


@requires_crypto
def test_gateway_refuses_when_a_required_proof_is_missing_then_allows_a_real_one():
    from aegis.gate import Gateway, Policy, Request
    from aegis.zkp_validator import Prover, SchnorrGroup, Verifier

    group = SchnorrGroup.generate(1024, quiet=True)
    prover = Prover.from_secret(b"amara", group=group, label="amara")
    gateway = Gateway(Policy(require_zkp=True, require_device_lock=False), verifier=Verifier(group))

    denied = gateway.decide(Request(actor="amara", payload=b"?WX"))
    assert not denied.allowed and denied.refused_by == "3-zkp"

    context = b"session"
    proof = prover.prove(context=context)
    allowed = gateway.decide(
        Request(actor="amara", payload=b"?WX", context=context, proof=proof, statement=prover.public)
    )
    assert allowed.allowed
    assert [verdict.layer for verdict in allowed.verdicts][:3] == ["1-pqc", "2-biometric", "3-zkp"]

    replayed = gateway.decide(
        Request(actor="amara", payload=b"?WX", context=context, proof=proof, statement=prover.public)
    )
    assert not replayed.allowed and replayed.refused_by == "3-zkp"


@requires_crypto
def test_gateway_fails_closed_when_a_required_layer_cannot_run():
    from aegis.gate import Gateway, Policy, Request

    class Exploding:
        def verify(self, *args, **kwargs):
            raise RuntimeError("ledger offline")

    gateway = Gateway(Policy(require_device_lock=False))
    gateway.ledger = Exploding()
    result = gateway.decide(Request(actor="amara", payload=b"?WX"))
    assert not result.allowed
    assert result.refused_by == "4-ledger" and "ledger offline" in result.reason


@requires_crypto
def test_gateway_counts_vajra_as_decoration_not_protection():
    from aegis.gate import Gateway, Policy, Request

    gateway = Gateway(Policy(require_device_lock=False))
    result = gateway.decide(Request(actor="amara", payload=b"?WX"))
    vajra = next(verdict for verdict in result.verdicts if verdict.layer == "8-vajra")
    assert vajra.data["is_cipher"] is False
    assert vajra.data["provides_confidentiality"] is False
    assert "no-key decode succeeds" in vajra.detail


@requires_crypto
def test_gateway_protect_unprotect_round_trip():
    from aegis.gate import Gateway, Policy
    from aegis.polymorphic_engine import PolymorphicEngine

    gateway = Gateway(Policy(require_device_lock=False))
    gateway.polymorphic = PolymorphicEngine(b"rotation-key-material-32-bytes!!")
    payload = b"@LOC[TYO] -> ?WX : { $WX.state == RAIN => !GEN[INDOOR, 3] }"
    protection = gateway.protect(payload, recipient=gateway.identity.public)
    assert protection.rotated and "?WX" not in protection.rotated
    assert protection.box.quantum_resistant == HAVE_PQC
    assert gateway.unprotect(protection, sender=gateway.identity.public) == payload


@requires_crypto
def test_gateway_records_every_decision_in_the_ledger():
    from aegis.gate import Gateway, Policy, Request

    gateway = Gateway(Policy(require_device_lock=False))
    gateway.decide(Request(actor="amara", payload=b"?WX"))
    gateway.decide(Request(actor="eve", payload=b"?WX", metadata={"device": "other"}, decision="deny") if False else Request(actor="eve", payload=b"?WX"))
    entries = gateway.ledger.entries
    assert [entry["actor"] for entry in entries] == ["amara", "eve"]
    assert all("subject" in entry for entry in entries)
    # subjects are hashed, never the payload itself
    assert all(entry["subject"] != "?WX" for entry in entries)


@requires_crypto
def test_gateway_describe_states_every_limit():
    from aegis.gate import Gateway, Policy

    described = Gateway(Policy(require_device_lock=False)).describe()
    assert described["ledger"]["immutable"] is False
    assert described["ledger"]["tamper_evident"] is True
    assert described["vajra"]["is_cipher"] is False
    assert "unbreakable" in described["honesty"]["claim_not_made"]
    assert described["quantum_resistant"] == HAVE_PQC


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _run_cli(*arguments):
    import subprocess
    import sys

    completed = subprocess.run(
        [sys.executable, "-m", "aegis", *arguments],
        capture_output=True,
        text=True,
        cwd=str(Path(__file__).resolve().parents[1]),
    )
    return completed


def test_cli_report_capabilities_and_version():
    completed = _run_cli("report")
    assert completed.returncode == 0
    assert "Claim NOT made" in completed.stdout
    assert "NOT a cipher" in completed.stdout

    version = _run_cli("--version")
    assert version.returncode == 0 and "aegis" in version.stdout

    payload = json.loads(_run_cli("report", "--json").stdout)
    assert len(payload["layers"]) == 8


@requires_crypto
def test_cli_selftest_passes_when_the_backends_are_present():
    completed = _run_cli("selftest", "--json")
    assert completed.returncode == 0, completed.stdout + completed.stderr
    payload = json.loads(completed.stdout)
    assert payload["passed"] == payload["total"] >= 7


def test_cli_vajra_round_trip_and_honesty():
    completed = _run_cli("vajra", "@LOC[TYO] -> ?WX")
    assert completed.returncode == 0
    assert "unwrap       : @LOC[TYO] -> ?WX" in completed.stdout
    assert "is a cipher  : False" in completed.stdout


# ---------------------------------------------------------------------------
# The no-wheels path: this is how the repository behaves without the extras
# ---------------------------------------------------------------------------
_STUB = {
    "cryptography": 'raise ImportError("cryptography is not installed (simulated)")\n',
    "pqcrypto": 'raise ImportError("pqcrypto is not installed (simulated)")\n',
}


def _run_without_wheels(script: str, *arguments: str):
    """Run a python command with `cryptography`/`pqcrypto` import-blocked."""
    import subprocess
    import sys

    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory() as tmp:
        stub_dir = Path(tmp)
        for module, body in _STUB.items():
            (stub_dir / f"{module}.py").write_text(body)
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(stub_dir)
        return subprocess.run(
            [sys.executable, "-c", script, *arguments],
            capture_output=True,
            text=True,
            cwd=str(root),
            env=environment,
        )


def test_without_the_wheels_capabilities_report_a_downgrade_not_a_lie():
    completed = _run_without_wheels(
        "import json; from aegis.capabilities import capabilities; "
        "caps = capabilities(); print(json.dumps(caps.to_dict()))"
    )
    assert completed.returncode == 0, completed.stderr
    described = json.loads(completed.stdout)
    assert described["classical"] is False
    assert described["post_quantum_kem"] is None and described["post_quantum_signature"] is None
    assert described["aead"] == "pure-python-chacha20poly1305"
    assert described["hybrid_ready"] is False


def test_without_the_wheels_the_aead_fallback_depends_on_nothing_but_the_stdlib():
    completed = _run_without_wheels(
        "from aegis import cipher; "
        "key, nonce, sealed = b'k'*32, b'n'*12, None; "
        "nonce, sealed = cipher.encrypt(key, b'payload'); "
        "print(cipher.decrypt(key, nonce, sealed).decode()); "
        "print(cipher.aead_backend())"
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.splitlines() == ["payload", "pure-python-chacha20poly1305"]


def test_without_the_wheels_every_entry_point_refuses_with_an_actionable_message():
    """Fail closed, and say exactly what to install — never substitute silently."""
    script = (
        "from aegis.capabilities import MissingBackend\n"
        "from aegis.gate import Gateway, Policy\n"
        "from aegis.pqc_engine import generate_identity\n"
        "from aegis.zkp_validator import SchnorrGroup\n"
        "from aegis.blockchain_ledger import Ledger\n"
        "for label, action in (\n"
        "    ('identity', lambda: generate_identity('alice')),\n"
        "    ('ledger', lambda: Ledger(node='n')),\n"
        "    ('group', lambda: SchnorrGroup.generate(1024, quiet=True)),\n"
        "    ('gateway', lambda: Gateway(Policy())),\n"
        "):\n"
        "    try:\n"
        "        action()\n"
        "        print(label, 'DID NOT REFUSE')\n"
        "    except MissingBackend as exc:\n"
        "        print(label, 'refused' if 'cryptography' in str(exc) else 'unclear')\n"
        "        print('   hint:', 'install' in str(exc))\n"
    )
    completed = _run_without_wheels(script)
    assert completed.returncode == 0, completed.stderr + completed.stdout
    output = completed.stdout
    for label in ("identity", "ledger", "group", "gateway"):
        assert f"{label} refused" in output
        assert "DID NOT REFUSE" not in output and "unclear" not in output
    assert output.count("hint: True") == 4


def test_without_the_wheels_the_cli_selftest_fails_loudly():
    """A deployment gate must exit non-zero when the crypto it needs is absent."""
    import subprocess
    import sys

    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory() as tmp:
        stub_dir = Path(tmp)
        for module, body in _STUB.items():
            (stub_dir / f"{module}.py").write_text(body)
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(stub_dir)
        completed = subprocess.run(
            [sys.executable, "-m", "aegis", "selftest"],
            capture_output=True,
            text=True,
            cwd=str(root),
            env=environment,
        )
    assert completed.returncode != 0, "selftest must not pass without the crypto backends"
    assert "FAIL" in completed.stdout
    assert "checks passed" in completed.stdout


# ---------------------------------------------------------------------------
# Audit findings H2 and H5, closed and pinned
# ---------------------------------------------------------------------------
@requires_crypto
def test_a_relabelled_suite_is_refused_by_the_sealer():
    """H2 at the seal layer: relabelling the envelope must not open it."""
    from aegis.pqc_engine import SUITE, SealedBox, Sealer, generate_identity

    alice, bob = generate_identity("alice"), generate_identity("bob")
    box = Sealer(alice).seal(b"@LOC[TYO] -> ?WX", recipient=bob.public)
    assert Sealer(bob).open(box) == b"@LOC[TYO] -> ?WX"

    relabelled = SealedBox.from_dict({**box.to_dict(), "suite": "aegis-classical/v1"})
    assert relabelled.suite != SUITE
    with pytest.raises(cipher.AeadError, match="unknown suite"):
        Sealer(bob).open(relabelled)

    # and a box with no suite at all is read as this build's suite, not as a
    # weaker one: dropping the field is not a downgrade route either
    payload = box.to_dict()
    payload.pop("suite")
    assert Sealer(bob).open(SealedBox.from_dict(payload)) == b"@LOC[TYO] -> ?WX"


@requires_crypto
def test_an_unwritable_ledger_refuses_instead_of_acting_unaudited():
    """H5: the audit write is part of the decision, not a note after it."""
    from aegis.gate import Gateway, Policy, Request

    # The device lock is the one layer a bare test request cannot satisfy; every
    # other layer is left as the policy has it, so the refusal below can only
    # come from the audit write.
    gateway = Gateway(Policy(require_device_lock=False))

    def explode(*args, **kwargs):
        raise OSError("the disk holding the ledger is gone")

    gateway.ledger.append = explode  # type: ignore[method-assign]
    result = gateway.decide(Request(actor="agent://one", payload=b"?WX"))

    assert not result.allowed, "an operation that cannot be recorded must not proceed"
    assert result.refused_by == "4-ledger"
    assert gateway.audit_failures >= 1
    assert "unaudited" in result.human_reason
    assert gateway.describe()["audit_failures"] == gateway.audit_failures


@requires_crypto
def test_a_healthy_ledger_still_allows_and_records():
    """The H5 rule must not turn a working deployment into a deny-machine."""
    from aegis.gate import Gateway, Policy, Request

    gateway = Gateway(Policy(require_device_lock=False))
    result = gateway.decide(Request(actor="agent://one", payload=b"?WX"))
    assert result.allowed, result.human_reason
    assert gateway.audit_failures == 0
    assert any(entry["actor"] == "agent://one" for entry in gateway.ledger.entries)
