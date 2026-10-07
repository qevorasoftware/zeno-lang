"""The authorization boundary: the only way from an HTTP request to the kernel.

Audit finding C1 was that a client could reach effectful Zeno execution over HTTP
without AEGIS being consulted at all — ``POST /api/run`` went straight to the
kernel. This module closes that hole structurally rather than by remembering to
be careful: the server no longer calls the kernel directly, it calls
:meth:`AuthorizationBoundary.authorize`, and only a permit from an
:class:`Authorization` unlocks the execution.

What "authorized" means depends on the policy the gateway was built with, and the
answer is always reported — a development permit and a production permit are
different objects:

* **production** (:meth:`aegis.gate.Policy.strict_policy`) — every layer in
  :data:`aegis.gate.LAYER_ORDER` is mandatory, so a request without proof,
  biometric enrolment, device binding, rotation key, and a verifiable ledger is
  refused, and the refusal carries a machine code and nothing else.
* **development** — the layers the policy requires (PQC, ledger, sentinel, device
  lock by default) still run and still refuse; the optional ones are recorded as
  skipped. The permit says ``"development"`` in every response, so a deployment
  cannot be accidentally strict or *silently* permissive (invariants S18, S25).

Every attempt — permitted or refused — becomes one ledger entry keyed by an
auditable ``decision_id``, so "who asked, what happened, why" is answerable
without trusting the caller.

Not in this module yet, by design: capability tokens (plan §4), replay state
across processes (H3), and per-caller quotas (M3). Those are Phase P1/P2 of the
plan; until they land, HTTP authorization means "the eight layers agreed about
this request", not "this caller holds a capability".
"""

from __future__ import annotations

import base64
import hashlib
import time
from collections import deque
from dataclasses import asdict, dataclass, field
from typing import Any, Deque, Dict, Mapping, Optional

from .gate import Gateway, Policy, Request, Result, refusal_code

__all__ = ["Caller", "Authorization", "AuthorizationBoundary", "material_from_payload"]


@dataclass
class Caller:
    """Who is asking, as far as the transport can tell.

    ``remote`` and ``user_agent`` are *claims*: they are useful for the audit
    trail and for rate limiting, never for authorization decisions on their own
    (invariant S7 — external data may inform, never authorize).
    """

    actor: str = "anonymous"
    remote: str = ""
    user_agent: str = ""
    kind: str = "human"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Authorization:
    """The boundary's answer. ``allowed`` is the only field that unlocks execution."""

    allowed: bool
    decision_id: str
    mode: str
    code: str = ""
    #: Caller-facing sentence. Empty in production mode: the caller gets the code.
    reason: str = ""
    #: Owner-side sentence. Never serialised for callers.
    human_reason: str = ""
    ledger_seq: int = 0
    elapsed_ms: float = 0.0
    result: Optional[Result] = field(default=None, repr=False)
    #: The canonical payload, restored from this epoch's rotation. The caller is
    #: permitted to execute *this*, never the bytes it happened to send (S24).
    payload: Optional[bytes] = field(default=None, repr=False)

    @property
    def enforcement(self) -> str:
        """``production`` or ``development`` — what actually ran."""
        return self.mode

    def to_dict(self) -> Dict[str, Any]:
        """What a caller may see: a permit or a code, never a reason why."""
        out: Dict[str, Any] = {
            "allowed": self.allowed,
            "enforcement": self.mode,
            "decision_id": self.decision_id,
            "ledger_seq": self.ledger_seq,
        }
        if self.code:
            out["code"] = self.code
        if self.reason:
            out["reason"] = self.reason
        return out

    def owner_view(self) -> Dict[str, Any]:
        """The owner's view: includes the sentence, the layer verdicts and the code."""
        out = self.to_dict()
        out["human_reason"] = self.human_reason
        if self.result is not None:
            out["layers"] = [
                {"layer": v.layer, "ok": v.ok, "required": v.required, "detail": v.detail, "code": v.code}
                for v in self.result.verdicts
            ]
        return out


def material_from_payload(body: Mapping[str, Any]) -> Dict[str, Any]:
    """Pull layer material out of a request body's ``aegis`` block.

    Everything here is caller-supplied and therefore suspect: a proof is only as
    good as its verification against the gateway's own statement/verifier, and a
    latitude is a claim (S14) that the policy may choose to weigh but never to
    trust. Unknown keys are ignored rather than forwarded blindly.
    """
    block = body.get("aegis") or {}
    if not isinstance(block, Mapping):
        return {}
    material: Dict[str, Any] = {}
    if isinstance(block.get("biometric"), (list, tuple)):
        material["biometric"] = [float(value) for value in block["biometric"]]
    if isinstance(block.get("biometric_subject"), str):
        material["biometric_subject"] = block["biometric_subject"]
    if isinstance(block.get("device"), str):
        material["device_fingerprint"] = block["device"]
    for key in ("latitude", "longitude"):
        if isinstance(block.get(key), (int, float)):
            material[key] = float(block[key])
    if isinstance(block.get("nonce"), str) and block["nonce"].strip():
        material["nonce"] = block["nonce"].strip()[:200]
    if isinstance(block.get("context"), str):
        raw = block["context"]
        try:
            material["context"] = base64.b64decode(raw, validate=True)
        except Exception:  # noqa: BLE001 - a plain string context is legitimate
            material["context"] = raw.encode("utf-8")
    if isinstance(block.get("proof"), str):
        from .zkp_validator import Proof

        try:
            material["proof_blob"] = base64.b64decode(block["proof"], validate=True)
        except Exception:  # noqa: BLE001 - malformed base64 is simply no proof
            material["proof_blob"] = b""
    return material


class AuthorizationBoundary:
    """Turns "an HTTP request arrived" into "execution may proceed, or may not"."""

    def __init__(
        self,
        gateway: Optional[Gateway] = None,
        *,
        policy: Optional[Policy] = None,
    ) -> None:
        # A boundary without a gateway cannot authorize anything, so it builds a
        # strict one: the failure mode of a missing gateway is DENY, not allow.
        self.gateway = gateway if gateway is not None else Gateway(policy or Policy.strict_policy())
        self.attempts = 0
        self.permitted = 0
        self.refused = 0
        #: Nonces already spent on an accepted request (H3). Bounded, and
        #: per-process: durable, cross-node replay state is Phase P1.
        self._spent_nonces: Deque[str] = deque(maxlen=4096)
        self._spent_set: set = set()
        #: Owner-side ring buffer of recent decisions, newest first.
        self.recent: Deque[Authorization] = deque(maxlen=100)

    # -- introspection -----------------------------------------------------
    @property
    def policy(self) -> Policy:
        return self.gateway.policy

    @property
    def mode(self) -> str:
        return self.policy.mode

    def stats(self) -> Dict[str, Any]:
        return {
            "mode": self.mode,
            "attempts": self.attempts,
            "permitted": self.permitted,
            "refused": self.refused,
            "policy": self.policy.to_dict(),
        }

    # -- the decision ------------------------------------------------------
    def authorize(
        self,
        caller: Caller,
        payload: bytes,
        material: Optional[Mapping[str, Any]] = None,
        *,
        action: str = "execute",
    ) -> Authorization:
        """Ask the gateway about this request. The caller must honour the answer."""
        started = time.perf_counter()
        material = dict(material or {})
        self.attempts += 1

        if self.policy.require_nonce and not material.get("nonce"):
            return self._reject(
                caller,
                payload,
                f"no nonce supplied: a fixed proof context admits exactly one accepted request "
                f"on {caller.actor!r} (send a fresh nonce per attempt)",
                started=started,
            )
        if material.get("nonce") and f"{caller.actor}:{material['nonce']}" in self._spent_set:
            return self._reject(
                caller, payload, "this nonce has already authorized a request", started=started
            )

        proof = statement = None
        blob = material.get("proof_blob")
        if blob:
            from .zkp_validator import Proof

            try:
                proof = Proof.decode(blob)
                statement = proof.statement
            except Exception:  # noqa: BLE001 - an undecodable proof is no proof
                proof = statement = None

        nonce = material.get("nonce")
        if nonce:
            # The caller's proof context is derived here and nowhere else, so a
            # proof cannot be presented against a context of the caller's choosing.
            context = f"aegis:{caller.actor}:{nonce}".encode("utf-8")
        else:
            context = material.get("context") or f"aegis:{caller.actor}".encode("utf-8")

        request = Request(
            actor=caller.actor,
            payload=payload,
            context=context,
            proof=proof,
            statement=statement,
            biometric=material.get("biometric"),
            biometric_subject=material.get("biometric_subject"),
            device_fingerprint=material.get("device_fingerprint"),
            latitude=material.get("latitude"),
            longitude=material.get("longitude"),
            metadata={
                "remote": caller.remote,
                "user_agent": caller.user_agent,
                "caller_kind": caller.kind,
                "action": action,
            },
        )
        result = self.gateway.decide(request)

        decision_id = self._decision_id(caller.actor, payload, result.at)

        authorization = Authorization(
            allowed=result.allowed,
            payload=result.restored_payload or (payload if result.allowed else None),
            decision_id=decision_id,
            mode=self.mode,
            code=result.code,
            reason=result.reason if result.allowed else ("" if self.policy.opaque_reasons else result.reason),
            human_reason=result.human_reason,
            elapsed_ms=(time.perf_counter() - started) * 1000.0,
            result=result,
        )
        authorization.ledger_seq = self._record(caller, authorization, action=action)

        if result.allowed:
            self.permitted += 1
            if nonce:
                self._spend(f"{caller.actor}:{nonce}")
        else:
            self.refused += 1
        self.recent.appendleft(authorization)
        return authorization

    # -- nonces ------------------------------------------------------------
    @staticmethod
    def _decision_id(actor: str, payload: bytes, at: float) -> str:
        return hashlib.sha256(
            b"|".join(
                (actor.encode("utf-8"), hashlib.sha256(payload).digest(), f"{at:.6f}".encode("ascii"))
            )
        ).hexdigest()[:32]

    def _spend(self, key: str) -> None:
        """Remember an accepted nonce, evicting the oldest when the buffer is full."""
        if self._spent_nonces.maxlen and len(self._spent_nonces) == self._spent_nonces.maxlen:
            self._spent_set.discard(self._spent_nonces[0])
        self._spent_nonces.append(key)
        self._spent_set.add(key)

    def _reject(self, caller: Caller, payload: bytes, reason: str, *, started: float) -> Authorization:
        """Refuse a malformed attempt without consulting the gateway."""
        self.refused += 1
        authorization = Authorization(
            allowed=False,
            decision_id=self._decision_id(caller.actor, payload, time.time()),
            mode=self.mode,
            code=refusal_code("3-zkp", missing=True),
            reason="" if self.policy.opaque_reasons else reason,
            human_reason=reason,
            elapsed_ms=(time.perf_counter() - started) * 1000.0,
        )
        authorization.ledger_seq = self._record(caller, authorization, action="execute")
        self.recent.appendleft(authorization)
        return authorization

    # -- audit -------------------------------------------------------------
    def _record(self, caller: Caller, authorization: Authorization, *, action: str) -> int:
        """One ledger entry per attempt, keyed by decision id.

        The gateway already records the layer-level verdict; this records the
        *authorization* decision, which is what an auditor asks about. A ledger
        that cannot be written means the attempt leaves no trace, so write
        failures are surfaced to the owner rather than swallowed (finding H5).
        """
        ledger = getattr(self.gateway, "ledger", None)
        if ledger is None:
            return 0
        try:
            entry = ledger.record(
                actor=caller.actor,
                action=action,
                subject=authorization.decision_id,
                decision="allow" if authorization.allowed else "deny",
                layer="boundary",
                reason=authorization.human_reason or authorization.reason or "allowed",
                metadata={
                    "decision_id": authorization.decision_id,
                    "mode": authorization.mode,
                    "remote": caller.remote,
                    "code": authorization.code,
                },
            )
        except Exception as error:  # noqa: BLE001
            # H5: this is deliberately *not* swallowed. In production an unwritable
            # audit trail is itself a refusal, and the boundary applies that rule
            # here rather than leaving it to the caller to notice.
            if self.policy.strict:
                authorization.allowed = False
                authorization.code = "ZN-SEC-0x4C01"
                authorization.reason = "ZN-SEC-0x4C01"
                authorization.human_reason = f"audit unavailable: {type(error).__name__}: {error}"
            return 0
        return int(getattr(entry, "seq", 0) or 0)

    # -- owner-side reporting ---------------------------------------------
    def report(self) -> Dict[str, Any]:
        return {
            "mode": self.mode,
            "policy": self.policy.to_dict(),
            "stats": self.stats(),
            "recent": [authorization.owner_view() for authorization in list(self.recent)[:10]],
            "gateway": self.gateway.describe(),
        }
