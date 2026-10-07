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
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

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
    "REFUSAL_CODES",
    "refusal_code",
    "Policy",
    "Policy",
    "Request",
    "Result",
    "LayerVerdict",
    "LAYER_ORDER",
    "Protection",
]

#: Machine codes for every refusal. Production mode returns the code and nothing
#: else (invariants S20/S21/S23): an attacker probing the gateway learns that it
#: refused, not which layer or why. The human sentence stays in-process, reachable
#: only by the owner running the CLI on this host.
REFUSAL_CODES: Dict[str, Tuple[str, str]] = {
    "1-pqc": ("ZN-SEC-0x1A01", "ZN-SEC-0x1B01"),
    "2-biometric": ("ZN-SEC-0x2A01", "ZN-SEC-0x2B01"),
    "3-zkp": ("ZN-SEC-0x3A01", "ZN-SEC-0x3B01"),
    "4-ledger": ("ZN-SEC-0x4A01", "ZN-SEC-0x4B01"),
    "5-sentinel": ("ZN-SEC-0x5A01", "ZN-SEC-0x5B01"),
    "6-polymorphic": ("ZN-SEC-0x6A01", "ZN-SEC-0x6B01"),
    "7-geo-hardware": ("ZN-SEC-0x7A01", "ZN-SEC-0x7B01"),
    "8-vajra": ("ZN-SEC-0x8A01", "ZN-SEC-0x8B01"),
    "gate": ("ZN-SEC-0x0A01", "ZN-SEC-0x0B01"),
}


def refusal_code(layer: str, *, missing: bool = False) -> str:
    """The opaque code for a refusal at ``layer``.

    ``missing`` distinguishes "the caller did not supply this layer's material"
    from "the material was supplied and rejected". Both are refusals; the
    distinction is the owner's, not the caller's.
    """
    absent, failed = REFUSAL_CODES.get(layer, REFUSAL_CODES["gate"])
    return absent if missing else failed


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
    """Which layers must pass, how loud the gateway is, and in which mode.

    ``mode`` is not cosmetic. The plan separates two operating states:

    * ``"development"`` — the shipping default of this library, and the honest
      description of it: layers 2, 3, 6 and 8 are *optional* unless the caller
      supplies their material, refusals explain themselves in prose, and ledger
      signatures are not re-verified on every request. Convenient, and not a
      production posture.
    * ``"production"`` — every layer in :data:`LAYER_ORDER` is mandatory, ledger
      signatures are verified, and refusals carry only a machine code. This is
      what :meth:`Policy.strict` returns, and what ``zeno serve --production``
      runs.

    A policy is reported by :meth:`to_dict` in both cases, so no deployment can
    be strict by accident and none can be permissive *silently* (S18, S25).
    """

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
    #: Layer 8 is mandatory in production (the brief makes it the final layer)
    #: even though it is an encoding: what is mandatory is that it *runs*.
    require_vajra: bool = False
    #: Sentinel verdicts at or above this become refusals.
    block_on_sentinel: Tuple[str, ...] = ("FREEZE",)
    #: Re-verify every ledger signature instead of only the hash chain (H4).
    verify_ledger_signatures: bool = False
    #: Require the proof's key to be the one registered to the claimed actor
    #: (audit finding C3). A proof of knowledge of *some* key proves nothing about
    #: *which* entity is asking; without this, any key holder can prove as anyone.
    require_identity_binding: bool = False
    #: Require an owner-issued capability token for effectful actions (plan §4).
    #: Without this, "authorized" means "the layers agreed about this request";
    #: with it, it means "the owner granted exactly this".
    require_capability: bool = False
    #: Require a caller-supplied nonce in the proof context (audit findings C3 and
    #: H3). The ZKP nullifier is derived from (identity, context), so a *fixed*
    #: context allows exactly one accepted request ever. Binding a fresh nonce per
    #: attempt is what makes repeat requests possible while keeping a replayed
    #: transcript impossible.
    require_nonce: bool = False
    #: Refusals carry a code and nothing else (S20/S21/S23).
    opaque_reasons: bool = False
    mode: str = "development"

    #: The layer names that must pass, in order. Derived, never hand-maintained.
    @property
    def mandatory_layers(self) -> Tuple[str, ...]:
        required = {
            "1-pqc": self.require_pqc,
            "2-biometric": self.require_biometric,
            "3-zkp": self.require_zkp,
            "4-ledger": self.require_ledger,
            "5-sentinel": self.require_sentinel,
            "6-polymorphic": self.require_polymorphic,
            "7-geo-hardware": self.require_device_lock or self.require_geofence,
            "8-vajra": self.require_vajra,
        }
        return tuple(layer for layer in LAYER_ORDER if required.get(layer, False))

    @property
    def strict(self) -> bool:
        return self.mode == "production"

    @classmethod
    def strict_policy(cls) -> "Policy":
        """Every layer mandatory, signatures verified, reasons opaque.

        The geofence stays a *signal* rather than a requirement (S14): treating
        spoofable coordinates as a hard gate would trade real security for the
        appearance of it. It still runs, and still refuses when the policy says
        so, but a caller outside a fence is not automatically refused here.
        """
        return cls(
            mode="production",
            require_pqc=True,
            require_biometric=True,
            require_zkp=True,
            require_ledger=True,
            require_sentinel=True,
            require_polymorphic=True,
            require_device_lock=True,
            require_geofence=False,
            require_vajra=True,
            verify_ledger_signatures=True,
            require_identity_binding=True,
            require_nonce=True,
            require_capability=True,
            opaque_reasons=True,
            apply_vajra_wrap=True,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mode": self.mode,
            "strict": self.strict,
            "required": {
                "pqc": self.require_pqc,
                "biometric": self.require_biometric,
                "zkp": self.require_zkp,
                "ledger": self.require_ledger,
                "sentinel": self.require_sentinel,
                "polymorphic": self.require_polymorphic,
                "device_lock": self.require_device_lock,
                "geofence": self.require_geofence,
                "vajra": self.require_vajra,
            },
            "mandatory_layers": list(self.mandatory_layers),
            "verify_ledger_signatures": self.verify_ledger_signatures,
            "require_identity_binding": self.require_identity_binding,
            "require_nonce": self.require_nonce,
            "require_capability": self.require_capability,
            "opaque_reasons": self.opaque_reasons,
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
    #: Machine code for a refusal, filled in by :meth:`Gateway.decide`.
    code: str = ""

    def to_dict(self, *, opaque: bool = False) -> Dict[str, Any]:
        return {
            "layer": self.layer,
            "ok": self.ok,
            "required": self.required,
            # In production the sentence stays on this host; the caller gets the
            # code. ``data`` is withheld too when it would narrate the refusal.
            "detail": "" if opaque else self.detail,
            "code": self.code or None,
            "elapsed_ms": round(self.elapsed_ms, 4),
            "data": {} if (opaque and not self.ok) else dict(self.data),
        }


@dataclass
class Result:
    """The gateway's answer, with every layer's reasoning attached."""

    allowed: bool
    verdicts: List[LayerVerdict] = field(default_factory=list)
    refused_by: Optional[str] = None
    reason: str = ""
    #: The sentence behind :attr:`code`. Never serialised: it is for the owner
    #: reading this host's own console, not for the caller who was refused.
    human_reason: str = ""
    code: str = ""
    opaque: bool = False
    payload: Optional[bytes] = None
    #: The canonical payload after layer 6 restored it from this epoch's rotated
    #: vocabulary. This — not the bytes on the wire — is what may be executed
    #: (invariant S24).
    restored_payload: Optional[bytes] = None
    wrapped: Optional[str] = None
    box: Optional[SealedBox] = None
    sentinel: Optional[SentinelDecision] = None
    at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "refused_by": self.refused_by,
            "reason": self.reason,
            "code": self.code or None,
            "layers": [verdict.to_dict(opaque=self.opaque) for verdict in self.verdicts],
            "sentinel": None if self.opaque else (self.sentinel.to_dict() if self.sentinel else None),
            "vajra_wrapped": self.wrapped is not None,
            "sealed": self.box is not None,
            "at": self.at,
            "honesty": dict(HONESTY),
        }

    def render(self, *, include_human: bool = True) -> str:
        """Human-readable summary. The owner's view; do not serve this."""
        lines = [
            f"AEGIS gate   : {'ALLOW' if self.allowed else 'DENY'}"
            + (f" (refused by {self.refused_by})" if self.refused_by else ""),
        ]
        shown = self.reason if include_human else self.code
        if shown:
            lines.append(f"  reason     : {shown}")
        if include_human and self.code and self.human_reason and self.human_reason != self.reason:
            lines.append(f"  detail     : {self.human_reason}")
        for verdict in self.verdicts:
            mark = "ok  " if verdict.ok else ("FAIL" if verdict.required else "warn")
            text = verdict.detail if include_human else (verdict.code or "")
            lines.append(f"  [{mark}] {verdict.layer:<14} {text}")
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
        identities: Optional[Mapping[str, str]] = None,
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
        #: actor -> the base64 public key registered to that actor. Empty by
        #: default: with ``require_identity_binding`` the strict policy refuses
        #: any proof that cannot be attributed to the actor claiming it.
        self.identities: Dict[str, str] = dict(identities or {})
        self.identity = identity or generate_identity("gateway")
        self.sealer = Sealer(self.identity)
        self.vault = vault or BiometricVault()
        self.verifier = verifier or Verifier(group)
        self.ledger = ledger or Ledger(node="aegis-gateway")
        self.sentinel = sentinel or Sentinel()
        self.polymorphic = polymorphic
        self.hardware = hardware
        self.started_at = time.time()
        #: Audited operations whose record could not be written. Any of these is a
        #: refusal (finding H5), and the count is reported so they cannot hide.
        self.audit_failures = 0
        #: How many audit writes failed. Any of these on an audited operation is a
        #: refusal (finding H5); the count is reported so it cannot go unnoticed.
        self.audit_failures = 0

    def register_identity(self, actor: str, statement: Any) -> str:
        """Bind ``actor`` to a key. ``statement`` may be a Statement or its public string."""
        public = getattr(statement, "public", statement)
        self.identities[actor] = str(public)
        return self.identities[actor]

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
                missing = verdict.data.get("reason_kind") == "missing"
                verdict.code = refusal_code(name, missing=missing)
                result.refused_by = name
                result.code = verdict.code
                result.human_reason = verdict.detail
                result.opaque = self.policy.opaque_reasons
                result.reason = verdict.code if self.policy.opaque_reasons else verdict.detail
                # The audit record always keeps the human sentence: the ledger is
                # the owner's, and an opaque code is useless to them later.
                self._record(request, "deny", layer=name, reason=verdict.detail)
                return result

        result.allowed = True
        result.opaque = self.policy.opaque_reasons
        for verdict in result.verdicts:
            restored = verdict.data.get("restored")
            if verdict.layer == "6-polymorphic" and restored:
                result.restored_payload = str(restored).encode("utf-8")
        result.reason = "all required layers passed"
        audited = self._record(request, "allow", layer="gate", reason=result.reason)
        if not audited and self.policy.require_ledger:
            # Finding H5: an operation that cannot be recorded must not happen.
            result.allowed = False
            result.refused_by = "4-ledger"
            result.code = refusal_code("4-ledger", missing=False)
            result.human_reason = (
                "the ledger could not record this decision: refusing to act unaudited"
            )
            result.reason = result.code if self.policy.opaque_reasons else result.human_reason
            return result

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
                "2-biometric", not required, required, "no biometric material supplied",
                {"reason_kind": "missing"},
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
            return LayerVerdict(
                "3-zkp", not required, required, "no proof supplied", {"reason_kind": "missing"}
            )
        if self.policy.require_identity_binding:
            registered = self.identities.get(request.actor)
            if registered is None:
                return LayerVerdict(
                    "3-zkp",
                    False,
                    required,
                    f"no identity is registered to {request.actor!r}: an unattributable proof "
                    "is not authorization",
                    {"reason_kind": "missing"},
                )
            if request.statement.public != registered:
                return LayerVerdict(
                    "3-zkp",
                    False,
                    required,
                    "the proof is valid for a key that is not registered to this actor",
                )
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
        status = self.ledger.verify(check_signatures=self.policy.verify_ledger_signatures)
        if not status.ok:
            return LayerVerdict("4-ledger", False, required, f"ledger is broken: {status.reason}")
        return LayerVerdict(
            "4-ledger",
            True,
            required,
            f"{status.blocks} blocks, {status.entries} entries, head {status.head[:16]}"
            + ("" if self.policy.verify_ledger_signatures else " (signatures not re-verified in this mode)"),
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
            return LayerVerdict(
                "6-polymorphic", not required, required, "no rotation key configured",
                {"reason_kind": "missing"},
            )
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
                "7-geo-hardware", not required, required, "no device lock configured",
                {"reason_kind": "missing"},
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
    def _record(self, request: Request, decision: str, *, layer: str, reason: str) -> bool:
        """Append the audit entry. Returns whether it was written.

        A swallowed failure is how an audited operation ends up unaudited, so the
        caller gets the outcome and :meth:`decide` refuses on it (finding H5).
        """
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
            self.audit_failures += 1
            return False
        return True

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
            "audit_failures": self.audit_failures,
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
