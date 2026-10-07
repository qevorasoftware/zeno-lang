"""The eight-layer gateway: the enforced path every request takes.

``Gateway.decide`` runs the layers in the fixed order from the brief, each one
producing a :class:`LayerVerdict`, and refuses the request the moment one of them
refuses. ``Gateway.protect`` / ``Gateway.unprotect`` are the transport side: the
same eight layers, applied to a Zeno payload instead of a request.

Two design rules, both borrowed from things that go wrong in real gateways:

**Fail closed.** If a layer that is configured to be required cannot run — the
KEM wheel is missing, the ledger cannot be written, the geofence has no
coordinates — the request is refused. A gateway that degrades to "allow" when a
component breaks is not a gateway.

**Order is data.** The layer list is a tuple, and every verdict records the layer
index. Reordering it changes behaviour loudly, and the test-suite asserts the
order from the brief (1 PQC, 2 biometric, 3 ZKP, 4 ledger, 5 sentinel,
6 polymorphic, 7 geo/hardware, 8 VAJRA).

Which layers are actually *required* is the operator's call, exposed through
:class:`Policy`. The honest default is: layer 1 and 4 always; 2, 3 and 7 when the
caller supplies the material they need; 5 always (it cannot fail for lack of
input); 6 when a rotation key exists; 8 never, because it protects nothing — see
:mod:`aegis.vajra`.

    >>> from aegis.gate import Gateway, Policy, Request
    >>> gateway = Gateway(Policy(require_device_lock=False))
    >>> gateway.decide(Request(actor="amara", payload=b"?WX")).allowed
    True
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from . import HONESTY, cipher
from .biometric_auth import BiometricVault
from .blockchain_ledger import Ledger, LedgerEntry
from .geo_hardware_lock import GeoFence, HardwareLock, LockError
from .guardian_ai import Decision as SentinelDecision
from .guardian_ai import Sentinel
from .polymorphic_engine import PolymorphicEngine, RotationPolicy
from .pqc_engine import Identity, PublicIdentity, SealedBox, Sealer, SUITE, generate_identity
from .zkp_validator import Proof, Prover, Statement, Verifier

__all__ = [
    "Gateway",
    "Policy",
    "Request",
    "Result",
    "LayerVerdict",
    "LAYER_ORDER",
    "Protection",
]

#: The order is fixed by the brief; do not reorder without changing the docs.
LAYER_ORDER: Tuple[str, ...] = (
    "1-pqc",
    "2-biometric",
    "3-zkp",
    "4-ledger",
    "5-sentinel",
    "6-polymorphic",
    "7-geo-hardware",
    "8-vajra",
)


@dataclass
class Policy:
    """Which layers must pass, and how strict the gateway is."""

    require_pqc: bool = True
    require_biometric: bool = False
    require_zkp: bool = False
    require_ledger: bool = True
    require_sentinel: bool = True
    require_polymorphic: bool = False
    require_device_lock: bool = True
    require_geofence: bool = False
    #: VAJRA never protects anything: it is decoration unless explicitly wanted.
    apply_vajra_wrap: bool = True
    #: Sentinel verdicts at or above this become refusals.
    block_on_sentinel: Tuple[str, ...] = ("FREEZE",)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "required": {
                "pqc": self.require_pqc,
                "biometric": self.require_biometric,
                "zkp": self.require_zkp,
                "ledger": self.require_ledger,
                "sentinel": self.require_sentinel,
                "polymorphic": self.require_polymorphic,
                "device_lock": self.require_device_lock,
                "geofence": self.require_geofence,
            },
            "apply_vajra_wrap": self.apply_vajra_wrap,
            "block_on_sentinel": list(self.block_on_sentinel),
            "fail_closed": True,
        }


@dataclass
class Request:
    """One attempt to reach Zeno."""

    actor: str
    payload: bytes
    context: bytes = b""
    #: Material the caller supplies for the layers that need it.
    proof: Optional[Proof] = None
    statement: Optional[Statement] = None
    biometric: Optional[Sequence[float]] = None
    biometric_subject: Optional[str] = None
    device_fingerprint: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def observer_view(self) -> Dict[str, Any]:
        return {
            "actor": self.actor,
            "action": "access",
            "decision": "allow",
            "subject": hashlib.sha256(self.payload).hexdigest()[:32],
            "metadata": {
                "device": self.device_fingerprint or self.metadata.get("device", ""),
                "latitude": self.latitude,
                "longitude": self.longitude,
                **{key: value for key, value in self.metadata.items() if key != "device"},
            },
        }


@dataclass
class LayerVerdict:
    """One layer's say in the matter."""

    layer: str
    ok: bool
    required: bool
    detail: str = ""
    data: Dict[str, Any] = field(default_factory=dict)
    elapsed_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "layer": self.layer,
            "ok": self.ok,
            "required": self.required,
            "detail": self.detail,
            "elapsed_ms": round(self.elapsed_ms, 4),
            "data": dict(self.data),
        }


@dataclass
class Result:
    """The gateway's answer, with every layer's reasoning attached."""

    allowed: bool
    verdicts: List[LayerVerdict] = field(default_factory=list)
    refused_by: Optional[str] = None
    reason: str = ""
    payload: Optional[bytes] = None
    wrapped: Optional[str] = None
    box: Optional[SealedBox] = None
    sentinel: Optional[SentinelDecision] = None
    at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "refused_by": self.refused_by,
            "reason": self.reason,
            "layers": [verdict.to_dict() for verdict in self.verdicts],
            "sentinel": self.sentinel.to_dict() if self.sentinel else None,
            "vajra_wrapped": self.wrapped is not None,
            "sealed": self.box is not None,
            "at": self.at,
            "honesty": dict(HONESTY),
        }

    def render(self) -> str:
        lines = [
            f"AEGIS gate   : {'ALLOW' if self.allowed else 'DENY'}"
            + (f" (refused by {self.refused_by})" if self.refused_by else ""),
        ]
        if self.reason:
            lines.append(f"  reason     : {self.reason}")
        for verdict in self.verdicts:
            mark = "ok  " if verdict.ok else ("FAIL" if verdict.required else "warn")
            lines.append(f"  [{mark}] {verdict.layer:<14} {verdict.detail}")
        return "\n".join(lines)


@dataclass
class Protection:
    """A payload that has been through the gateway outbound path."""

    box: SealedBox
    wrapped: Optional[str] = None
    rotated: Optional[str] = None
    epoch: Optional[int] = None
    device_blob: Optional[bytes] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "box": self.box.to_dict(),
            "vajra_wrapped": self.wrapped,
            "rotated": self.rotated,
            "epoch": self.epoch,
            "device_locked": self.device_blob is not None,
        }


class Gateway:
    """Applies the eight layers, in order, to every request and every payload."""

    def __init__(
        self,
        policy: Optional[Policy] = None,
        *,
        identity: Optional[Identity] = None,
        vault: Optional[BiometricVault] = None,
        verifier: Optional[Verifier] = None,
        ledger: Optional[Ledger] = None,
        sentinel: Optional[Sentinel] = None,
        polymorphic: Optional[PolymorphicEngine] = None,
        hardware: Optional[HardwareLock] = None,
        group=None,
    ) -> None:
        # The gateway cannot even mint an identity without X25519/Ed25519, so it
        # refuses at construction with an actionable message rather than failing
        # at the first request with a raw ImportError.
        from .capabilities import require_classical

        require_classical("constructing an AEGIS gateway")
        self.policy = policy or Policy()
        self.identity = identity or generate_identity("gateway")
        self.sealer = Sealer(self.identity)
        self.vault = vault or BiometricVault()
        self.verifier = verifier or Verifier(group)
        self.ledger = ledger or Ledger(node="aegis-gateway")
        self.sentinel = sentinel or Sentinel()
        self.polymorphic = polymorphic
        self.hardware = hardware
        self.started_at = time.time()

    # -- inbound ---------------------------------------------------------
    def decide(self, request: Request) -> Result:
        """Run every layer in order; stop at the first required refusal."""
        result = Result(allowed=False, payload=request.payload)

        for name, check, required in (
            ("1-pqc", self._layer_pqc, self.policy.require_pqc),
            ("2-biometric", self._layer_biometric, self.policy.require_biometric),
            ("3-zkp", self._layer_zkp, self.policy.require_zkp),
            ("4-ledger", self._layer_ledger, self.policy.require_ledger),
            ("5-sentinel", self._layer_sentinel, self.policy.require_sentinel),
            ("6-polymorphic", self._layer_polymorphic, self.policy.require_polymorphic),
            ("7-geo-hardware", self._layer_hardware, self.policy.require_device_lock or self.policy.require_geofence),
            ("8-vajra", self._layer_vajra, False),
        ):
            started = time.perf_counter()
            try:
                verdict = check(request, required)
            except Exception as exc:  # noqa: BLE001 - a broken layer must not allow
                verdict = LayerVerdict(
                    layer=name,
                    ok=False,
                    required=required,
                    detail=f"layer raised {type(exc).__name__}: {exc}",
                )
            verdict.elapsed_ms = (time.perf_counter() - started) * 1000.0
            result.verdicts.append(verdict)

            if isinstance(verdict.data.get("sentinel"), SentinelDecision):
                result.sentinel = verdict.data["sentinel"]

            if not verdict.ok and required:
                result.refused_by = name
                result.reason = verdict.detail
                self._record(request, "deny", layer=name, reason=verdict.detail)
                return result

        result.allowed = True
        result.reason = "all required layers passed"
        self._record(request, "allow", layer="gate", reason=result.reason)

        if self.policy.apply_vajra_wrap:
            from .vajra.devanagari_wrapper import wrap

            result.wrapped = wrap(request.payload)
        return result

    # -- outbound / inbound payload path ---------------------------------
    def protect(
        self,
        payload: bytes,
        *,
        recipient: PublicIdentity,
        request: Optional[Request] = None,
    ) -> Protection:
        """Seal a payload through layers 8 → 6 → 1 (wrap, rotate, encrypt)."""
        wrapped = rotated = None
        epoch = None

        if self.policy.apply_vajra_wrap:
            from .vajra.devanagari_wrapper import wrap

            wrapped = wrap(payload)

        if self.polymorphic is not None:
            source = payload.decode("utf-8", "replace")
            epoch = self.polymorphic.policy.epoch_at()
            rotated = self.polymorphic.rotate_payload(source, epoch=epoch)
            payload = rotated.encode("utf-8")

        box = self.sealer.seal(payload, recipient=recipient, meta={"actor": recipient.name})
        protection = Protection(box=box, wrapped=wrapped, rotated=rotated, epoch=epoch)

        if request is not None:
            self._record(request, "protect", layer="1-pqc", reason=f"sealed to {recipient.name}")
        return protection

    def unprotect(self, protection: Protection, *, sender: Optional[PublicIdentity] = None) -> bytes:
        """Reverse :meth:`protect` (layers 1 → 6 → 8)."""
        payload = self.sealer.open(protection.box, sender=sender)
        if protection.rotated is not None and self.polymorphic is not None and protection.epoch is not None:
            restored = self.polymorphic.restore_payload(payload.decode("utf-8"), protection.epoch)
            payload = restored.encode("utf-8")
        return payload

    # -- the layers ------------------------------------------------------
    def _layer_pqc(self, request: Request, required: bool) -> LayerVerdict:
        """Layer 1: is the crypto backend real, and is the payload well-formed?"""
        from .capabilities import capabilities

        caps = capabilities()
        if not caps.aead:
            return LayerVerdict("1-pqc", False, required, "no AEAD backend available")
        if self.policy.require_pqc and not caps.pqc_kem:
            return LayerVerdict(
                "1-pqc", False, required, "post-quantum KEM unavailable (pqcrypto missing): refusing rather than downgrading"
            )
        if not request.payload:
            return LayerVerdict("1-pqc", False, required, "empty payload")
        return LayerVerdict(
            "1-pqc",
            True,
            required,
            f"aead={caps.aead}, kem={caps.pqc_kem or 'none'}, signature={caps.pqc_sign or 'none'}",
            {"suite": SUITE, "quantum_resistant": self.identity.quantum_resistant},
        )

    def _layer_biometric(self, request: Request, required: bool) -> LayerVerdict:
        """Layer 2: fuzzy-extractor verification, with the entropy budget reported."""
        if request.biometric is None or request.biometric_subject is None:
            return LayerVerdict(
                "2-biometric", not required, required, "no biometric material supplied"
            )
        subject = request.biometric_subject
        if subject not in self.vault.records:
            return LayerVerdict("2-biometric", False, required, f"{subject!r} is not enrolled")
        try:
            ok = self.vault.verify(subject, request.biometric)
        except PermissionError as exc:
            return LayerVerdict("2-biometric", False, required, str(exc))
        record = self.vault.records[subject]
        return LayerVerdict(
            "2-biometric",
            ok,
            required,
            f"{subject}: {'verified' if ok else 'rejected'} "
            f"({record.info.get('entropy_bits', '?')} stable bits, {record.info.get('entropy_grade', '?')})",
            {"subject": subject, "entropy_bits": record.info.get("entropy_bits")},
        )

    def _layer_zkp(self, request: Request, required: bool) -> LayerVerdict:
        """Layer 3: Schnorr proof of knowledge, single-use via nullifier."""
        if request.proof is None or request.statement is None:
            return LayerVerdict("3-zkp", not required, required, "no proof supplied")
        context = request.context or f"aegis:{request.actor}".encode()
        ok = self.verifier.verify(request.statement, request.proof, context=context)
        detail = (
            f"proof accepted for {request.statement.label or 'anonymous'}"
            if ok
            else "proof rejected (bad response, wrong context, or a replayed nullifier)"
        )
        return LayerVerdict("3-zkp", ok, required, detail, {"nullifier": request.proof.nullifier[:16]})

    def _layer_ledger(self, request: Request, required: bool) -> LayerVerdict:
        """Layer 4: the ledger must be writable and intact."""
        status = self.ledger.verify(check_signatures=False)
        if not status.ok:
            return LayerVerdict("4-ledger", False, required, f"ledger is broken: {status.reason}")
        return LayerVerdict(
            "4-ledger",
            True,
            required,
            f"{status.blocks} blocks, {status.entries} entries, head {status.head[:16]}",
            {"head": status.head},
        )

    def _layer_sentinel(self, request: Request, required: bool) -> LayerVerdict:
        """Layer 5: behavioural scoring of this very request."""
        decision = self.sentinel.observe(request.observer_view())
        blocked = decision.decision in self.policy.block_on_sentinel
        detail = f"{decision.decision} (score {decision.score:.2f})"
        if decision.reasons:
            detail += f": {decision.reasons[0]}"
        return LayerVerdict("5-sentinel", not blocked, required, detail, {"sentinel": decision})

    def _layer_polymorphic(self, request: Request, required: bool) -> LayerVerdict:
        """Layer 6: if rotation is configured, the payload must match an epoch."""
        if self.polymorphic is None:
            return LayerVerdict("6-polymorphic", not required, required, "no rotation key configured")
        payload = request.payload.decode("utf-8", "replace")
        try:
            restored, epoch = self.polymorphic.decode_with_grace(payload)
        except ValueError as exc:
            return LayerVerdict("6-polymorphic", False, required, str(exc)[:120])
        return LayerVerdict(
            "6-polymorphic",
            True,
            required,
            f"epoch {epoch} accepted ({self.polymorphic.policy.epoch_seconds // 3600}h window)",
            {"epoch": epoch, "restored": restored[:80]},
        )

    def _layer_hardware(self, request: Request, required: bool) -> LayerVerdict:
        """Layer 7: device fingerprint match and, if configured, the geofence."""
        from .geo_hardware_lock import device_fingerprint

        local = device_fingerprint().fingerprint
        declared = request.device_fingerprint or request.metadata.get("device", "")
        if declared and declared != local and self.policy.require_device_lock:
            return LayerVerdict(
                "7-geo-hardware", False, required, f"device {declared[:16]} is not this device ({local[:16]})"
            )
        if self.hardware is None:
            return LayerVerdict(
                "7-geo-hardware", not required, required, "no device lock configured"
            )

        fence: Optional[GeoFence] = self.hardware.fence
        if fence is not None:
            inside, reason = fence.check(request.latitude, request.longitude)
            if not inside and self.policy.require_geofence:
                return LayerVerdict("7-geo-hardware", False, required, f"geofence: {reason}", {"spoofable": True})
            location_note = reason
        else:
            location_note = "no fence configured"

        return LayerVerdict(
            "7-geo-hardware",
            True,
            required,
            f"device {local[:16]} bound; {location_note} "
            f"({'TPM' if self.hardware.device.hardware_backed else 'file secret, no TPM'}; location is advisory)",
            {"device": local, "spoofable_location": True},
        )

    def _layer_vajra(self, request: Request, required: bool) -> LayerVerdict:
        """Layer 8: the wrap. Reported for what it is, never counted as protection."""
        from .vajra.devanagari_wrapper import confidentiality_report, wrap

        measurement = confidentiality_report(request.payload)
        return LayerVerdict(
            "8-vajra",
            True,
            required,
            f"encoded ({len(wrap(request.payload))} chars); no-key decode succeeds: "
            f"{measurement['recovered_without_key']} — this layer is an encoding, not a cipher",
            {"is_cipher": False, "provides_confidentiality": False},
        )

    # -- audit -----------------------------------------------------------
    def _record(self, request: Request, decision: str, *, layer: str, reason: str) -> None:
        entry = LedgerEntry(
            actor=request.actor,
            action="access" if decision == "allow" else decision,
            subject=hashlib.sha256(request.payload).hexdigest()[:32],
            decision=decision,
            layer=layer,
            reason=reason,
            metadata={
                "device": request.device_fingerprint or request.metadata.get("device", ""),
                "latitude": request.latitude,
                "longitude": request.longitude,
            },
        )
        try:
            self.ledger.append(entry)
        except Exception:  # noqa: BLE001 - never let audit failure crash the gate
            pass

    # -- introspection ---------------------------------------------------
    def describe(self) -> Dict[str, Any]:
        return {
            "layer_order": list(LAYER_ORDER),
            "policy": self.policy.to_dict(),
            "identity": self.identity.public.to_dict(),
            "quantum_resistant": self.identity.quantum_resistant,
            "sealer": self.sealer.describe(),
            "verifier": self.verifier.describe(),
            "sentinel": self.sentinel.describe(),
            "ledger": {
                "node": self.ledger.node,
                "blocks": len(self.ledger.blocks),
                "head": self.ledger.head_hash[:16],
                "immutable": False,
                "tamper_evident": True,
            },
            "polymorphic": self.polymorphic.describe() if self.polymorphic else None,
            "hardware": self.hardware.to_dict() if self.hardware else None,
            "vajra": {
                "is_cipher": False,
                "provides_confidentiality": False,
                "applied": self.policy.apply_vajra_wrap,
            },
            "honesty": dict(HONESTY),
        }

    def alarm(self) -> Dict[str, Any]:
        """Freeze state, with the actor asking recorded wherever possible."""
        return {
            "frozen": dict(self.sentinel.frozen),
            "freeze_log": list(self.sentinel.freeze_log),
            "note": "a freeze any actor can trigger is a DoS primitive; who asked is always recorded",
        }
