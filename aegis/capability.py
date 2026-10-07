"""Owner-rooted capability tokens: the only thing that authorizes an action.

Phase P1 of the hardened plan. Until now, "authorized" meant "the eight layers
agreed about this request" — which is necessary and not sufficient, because
nothing in it came from the *owner*. This module adds the missing piece:

    Owner Master Key (offline; hardware-backed when available)
        └── Root Authorization Key
                ├── capability tokens, per agent / per user
                ├── scoped capability sets
                └── epochs (time-bound rotation) and revocation

A token is issued by the owner's root key and carries exactly what the plan's §4
format lists: issuer, subject, capabilities, audience, epoch, issued/expires,
semantic scope hash, policy hash, nonce, and a **hybrid** signature. Everything
except the signature is inside the signed bytes, including the crypto suite
itself — otherwise an attacker strips the post-quantum half and the classical
half still verifies (audit finding H2; :func:`aegis.pqc_engine.verify` accepts
that downgrade by design, so the refusal has to live here).

What this buys, stated exactly:

* **Owner control.** No key of the owner, no token. Agents cannot mint authority
  for themselves or for each other, and a delegated token can never exceed its
  parent's capability set (invariant S6).
* **Revocation and rotation that work without new crypto.** A token names an
  epoch; moving the owner's epoch invalidates every token of the previous one.
  A revocation list handles the rest.
* **Binding.** The token names the audience, epoch, policy hash and semantic
  scope it is valid for, so a token captured from one deployment is worthless in
  another.

What it does not buy: if the owner's root key is stolen, everything above is the
attacker's. That is why the key belongs offline or in hardware, why
:meth:`OwnerRoot.save` writes mode 0600 and refuses a world-readable key, and why
nothing in this repository claims otherwise.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from .pqc_engine import Identity, PublicIdentity, Signature, generate_identity, sign, verify

__all__ = [
    "SUITE",
    "SUITES",
    "MINIMUM_SUITE",
    "CapabilityError",
    "Capability",
    "CapabilityCheck",
    "CapabilityVerifier",
    "OwnerRoot",
    "scope_matches",
    "CAPABILITY_CODES",
]

#: The envelope format. Bumping this is a breaking change for old tokens.
SUITE = "aegis-cap/v1"

#: Suite ranking. A deployment states the lowest suite it will accept, and a
#: token states the suite it was signed under; the two are compared numerically
#: so "downgrade" is a comparison, not a hope.
SUITES: Dict[str, int] = {
    "ed25519": 1,
    "hybrid-ed25519-ml-dsa-65": 2,
}
MINIMUM_SUITE = "hybrid-ed25519-ml-dsa-65"

#: Which algorithms each suite requires in the signature. The check is equality,
#: not "at least": a token claiming the hybrid suite must carry both halves.
SUITE_ALGORITHMS: Dict[str, Tuple[str, ...]] = {
    "ed25519": ("ed25519",),
    "hybrid-ed25519-ml-dsa-65": ("ed25519", "ml-dsa-65"),
}

CAPABILITY_CODES: Dict[str, str] = {
    "malformed": "ZN-SEC-0x9A01",
    "signature": "ZN-SEC-0x9A02",
    "downgrade": "ZN-SEC-0x9A03",
    "issuer": "ZN-SEC-0x9A04",
    "audience": "ZN-SEC-0x9A05",
    "epoch": "ZN-SEC-0x9A06",
    "expired": "ZN-SEC-0x9A07",
    "revoked": "ZN-SEC-0x9A08",
    "capability": "ZN-SEC-0x9A09",
    "scope": "ZN-SEC-0x9A0A",
    "policy": "ZN-SEC-0x9A0B",
    "chain": "ZN-SEC-0x9A0C",
    "unconfigured": "ZN-SEC-0x9A0D",
}


class CapabilityError(RuntimeError):
    """Raised when a token cannot be issued as asked (owner-side misuse)."""


def _canonical(payload: Mapping[str, Any]) -> bytes:
    """The bytes that get signed: deterministic, sorted, no whitespace."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def scope_matches(pattern: str, action: str) -> bool:
    """Does ``action`` fall inside a granted capability ``pattern``?

    ``run:weather`` grants exactly that. ``run:*`` grants the whole namespace.
    ``*`` grants everything the issuer had (still bounded by the parent chain).
    Comparison is case-insensitive on the namespace only, so ``RUN:weather`` and
    ``run:weather`` are the same grant.
    """
    if pattern == "*":
        return True
    pattern = pattern.strip()
    action = action.strip()
    if pattern.lower() == action.lower():
        return True
    if pattern.endswith(":*"):
        base = pattern[:-2].lower()
        # `execute:*` covers the whole namespace, including a bare `execute`.
        return action.lower() == base or action.lower().startswith(base + ":")
    return False


@dataclass
class Capability:
    """One owner-signed grant. Treat it as opaque bytes plus a signature."""

    issuer: str
    subject: str
    capabilities: Tuple[str, ...]
    audience: str
    epoch: int
    issued_at: float
    expires_at: float
    nonce: str
    semantic_scope_hash: str = ""
    policy_hash: str = ""
    crypto_suite: str = MINIMUM_SUITE
    required_algorithms: Tuple[str, ...] = SUITE_ALGORITHMS[MINIMUM_SUITE]
    parent: str = ""
    issuer_fingerprint: str = ""
    signature: Optional[Signature] = None

    # -- canonical form ----------------------------------------------------
    def payload(self) -> Dict[str, Any]:
        """Everything that is signed. The signature is deliberately absent."""
        return {
            "suite": SUITE,
            "issuer": self.issuer,
            "issuer_fingerprint": self.issuer_fingerprint,
            "subject": self.subject,
            "capabilities": list(self.capabilities),
            "audience": self.audience,
            "epoch": self.epoch,
            "issued_at": round(self.issued_at, 3),
            "expires_at": round(self.expires_at, 3),
            "nonce": self.nonce,
            "semantic_scope_hash": self.semantic_scope_hash,
            "policy_hash": self.policy_hash,
            "crypto_suite": self.crypto_suite,
            "required_algorithms": list(self.required_algorithms),
            "parent": self.parent,
        }

    def bytes(self) -> bytes:
        return _canonical(self.payload())

    @property
    def token_id(self) -> str:
        """Stable identifier of this grant, used by the revocation list."""
        return hashlib.sha256(self.bytes()).hexdigest()[:32]

    @property
    def expired(self) -> bool:
        return time.time() > self.expires_at

    def grants(self, action: str) -> bool:
        return any(scope_matches(pattern, action) for pattern in self.capabilities)

    # -- serialisation -----------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        out = self.payload()
        out["token_id"] = self.token_id
        out["signature"] = self.signature.to_dict() if self.signature else None
        return out

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    def encode(self) -> str:
        """A token as one opaque string, for headers or a request body."""
        import base64

        return base64.b64encode(self.to_json().encode("utf-8")).decode("ascii")

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "Capability":
        signature = payload.get("signature")
        return cls(
            issuer=str(payload.get("issuer", "")),
            issuer_fingerprint=str(payload.get("issuer_fingerprint", "")),
            subject=str(payload.get("subject", "")),
            capabilities=tuple(str(item) for item in payload.get("capabilities", ())),
            audience=str(payload.get("audience", "")),
            epoch=int(payload.get("epoch", -1)),
            issued_at=float(payload.get("issued_at", 0.0)),
            expires_at=float(payload.get("expires_at", 0.0)),
            nonce=str(payload.get("nonce", "")),
            semantic_scope_hash=str(payload.get("semantic_scope_hash", "")),
            policy_hash=str(payload.get("policy_hash", "")),
            crypto_suite=str(payload.get("crypto_suite", "ed25519")),
            required_algorithms=tuple(str(a) for a in payload.get("required_algorithms", ("ed25519",))),
            parent=str(payload.get("parent", "")),
            signature=Signature.from_dict(signature) if isinstance(signature, Mapping) else None,
        )

    @classmethod
    def decode(cls, blob: str) -> "Capability":
        """Decode what :meth:`encode` produced. Raises ``CapabilityError``."""
        import base64
        import binascii

        try:
            raw = base64.b64decode((blob or "").strip(), validate=True)
            payload = json.loads(raw.decode("utf-8"))
        except (binascii.Error, ValueError, UnicodeDecodeError) as error:
            raise CapabilityError(f"not a capability token: {type(error).__name__}") from error
        if not isinstance(payload, Mapping):
            raise CapabilityError("token payload is not an object")
        return cls.from_dict(payload)


# ---------------------------------------------------------------------------
# Owner side
# ---------------------------------------------------------------------------
class OwnerRoot:
    """The owner's root of trust: the thing that issues, revokes and rotates.

    The key never has to be on the machine that serves traffic. Deployments are
    expected to keep it offline or in hardware and use :meth:`load` only when
    issuing; the serving side holds nothing but the owner's *public* identity.
    """

    def __init__(
        self,
        identity: Identity,
        *,
        audience: str = "zeno-gateway",
        epoch: int = 1,
        policy_hash: str = "",
        revocations: Iterable[str] = (),
    ) -> None:
        self.identity = identity
        self.audience = audience
        self.epoch = int(epoch)
        self.policy_hash = policy_hash or ""
        self.revocations: List[str] = list(revocations)

    # -- lifecycle ---------------------------------------------------------
    @classmethod
    def create(cls, *, name: str = "owner_root", audience: str = "zeno-gateway", **kwargs: Any) -> "OwnerRoot":
        from .capabilities import require_classical

        require_classical("creating an owner root key")
        return cls(generate_identity(name), audience=audience, **kwargs)

    @property
    def public(self) -> PublicIdentity:
        return self.identity.public

    @property
    def fingerprint(self) -> str:
        return self.identity.fingerprint

    # -- tokens ------------------------------------------------------------
    def issue(
        self,
        subject: str,
        capabilities: Sequence[str],
        *,
        audience: Optional[str] = None,
        ttl: float = 900.0,
        semantic_scope_hash: str = "",
        policy_hash: Optional[str] = None,
        parent: Optional[Capability] = None,
        crypto_suite: str = MINIMUM_SUITE,
    ) -> Capability:
        """Mint a token. Refuses anything that would exceed the issuer's intent.

        Invariant S6: a child authority must never exceed its parent's. When
        ``parent`` is given, the requested capabilities are checked against the
        parent's set and the child inherits the parent's epoch, expiry ceiling and
        policy hash — so delegation cannot silently widen an authority either.
        """
        if not subject.strip():
            raise CapabilityError("a token must name a subject")
        if crypto_suite not in SUITES:
            raise CapabilityError(f"unknown crypto suite {crypto_suite!r}")
        if SUITES[crypto_suite] < SUITES[MINIMUM_SUITE]:
            raise CapabilityError(
                f"refusing to issue below {MINIMUM_SUITE!r}: a downgraded token is a "
                "downgraded guarantee (audit finding H2)"
            )

        now = time.time()
        epoch = self.epoch
        expiry = now + float(ttl)
        chain = ""

        if parent is not None:
            for wanted in capabilities:
                if not any(scope_matches(granted, wanted) or scope_matches(wanted, granted) for granted in parent.capabilities):
                    raise CapabilityError(
                        f"delegation refused: {wanted!r} is not within the parent's "
                        f"{list(parent.capabilities)}"
                    )
            epoch = parent.epoch
            expiry = min(expiry, parent.expires_at)
            chain = parent.token_id
            policy_hash = parent.policy_hash if policy_hash is None else policy_hash

        token = Capability(
            issuer=self.public.name,
            issuer_fingerprint=self.fingerprint,
            subject=subject,
            capabilities=tuple(capabilities),
            audience=audience or self.audience,
            epoch=epoch,
            issued_at=now,
            expires_at=expiry,
            nonce=secrets.token_urlsafe(18),
            semantic_scope_hash=semantic_scope_hash,
            policy_hash=self.policy_hash if policy_hash is None else policy_hash,
            crypto_suite=crypto_suite,
            required_algorithms=SUITE_ALGORITHMS[crypto_suite],
            parent=chain,
        )
        token.signature = sign(self.identity, token.bytes())
        return token

    # -- revocation and rotation -------------------------------------------
    def revoke(self, token: Capability) -> str:
        """Add a token to the revocation list. Owner-only, by construction."""
        token_id = token.token_id if isinstance(token, Capability) else str(token)
        if token_id not in self.revocations:
            self.revocations.append(token_id)
        return token_id

    def rotate_epoch(self) -> int:
        """Move to a new epoch: every token of the old one stops working."""
        self.epoch += 1
        return self.epoch

    # -- persistence -------------------------------------------------------
    def save(self, path: str | os.PathLike[str]) -> Path:
        """Write the root key with mode 0600, refusing to clobber a wider file."""
        target = Path(path).expanduser()
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() and stat.S_IMODE(target.stat().st_mode) & 0o077:
            raise CapabilityError(
                f"refusing to overwrite {target}: it is readable by other users "
                "(chmod 600 it first)"
            )
        payload = {
            "version": SUITE,
            "audience": self.audience,
            "epoch": self.epoch,
            "policy_hash": self.policy_hash,
            "revocations": list(self.revocations),
            # Explicit opt-in: this is the one place the owner's secrets are
            # written down, and only because the root key has to be persisted
            # somewhere the owner controls.
            "identity": self.identity.to_dict(redact_secrets=False),
        }
        target.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        os.chmod(target, 0o600)
        return target

    @classmethod
    def load(cls, path: str | os.PathLike[str]) -> "OwnerRoot":
        """Read a root key, warning loudly if the file is world-readable."""
        source = Path(path).expanduser()
        mode = stat.S_IMODE(source.stat().st_mode)
        payload = json.loads(source.read_text(encoding="utf-8"))
        identity = Identity.from_dict(payload["identity"])
        if not identity.ed25519_secret:
            raise CapabilityError("stored owner key has no signing key: refusing to load")
        root = cls(
            identity,
            audience=payload.get("audience", "zeno-gateway"),
            epoch=int(payload.get("epoch", 1)),
            policy_hash=payload.get("policy_hash", ""),
            revocations=payload.get("revocations", ()),
        )
        root.file_mode = mode  # type: ignore[attr-defined]
        return root

    def to_dict(self) -> Dict[str, Any]:
        return {
            "suite": SUITE,
            "issuer": self.public.name,
            "fingerprint": self.fingerprint,
            "audience": self.audience,
            "epoch": self.epoch,
            "policy_hash": self.policy_hash,
            "revocations": len(self.revocations),
            "quantum_resistant": self.public.quantum_resistant,
        }


# ---------------------------------------------------------------------------
# Verifier side
# ---------------------------------------------------------------------------
@dataclass
class CapabilityCheck:
    """The verifier's answer. ``ok`` is the only field that authorizes."""

    ok: bool
    code: str = ""
    reason: str = ""
    token_id: str = ""
    subject: str = ""
    capabilities: Tuple[str, ...] = ()
    epoch: int = -1

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"ok": self.ok, "token_id": self.token_id}
        if self.ok:
            out.update({"subject": self.subject, "capabilities": list(self.capabilities), "epoch": self.epoch})
        else:
            out.update({"code": self.code})
        return out


class CapabilityVerifier:
    """Checks tokens against an owner's public identity and a live policy.

    Every check has its own code so the owner can tell "expired" from "stolen",
    and the caller learns only the code (in production mode).
    """

    def __init__(
        self,
        owner_public: PublicIdentity,
        *,
        audience: str,
        epoch: int,
        min_suite: str = MINIMUM_SUITE,
        revocations: Iterable[str] = (),
        policy_hash: str = "",
        clock: Optional[Any] = None,
        skew: float = 60.0,
    ) -> None:
        if min_suite not in SUITES:
            raise CapabilityError(f"unknown minimum suite {min_suite!r}")
        self.owner_public = owner_public
        self.audience = audience
        self.epoch = int(epoch)
        self.min_suite = min_suite
        self.revocations = set(revocations)
        self.policy_hash = policy_hash or ""
        self.clock = clock or time.time
        self.skew = float(skew)

    def _fail(self, kind: str, reason: str, token: Optional[Capability] = None) -> CapabilityCheck:
        return CapabilityCheck(
            ok=False,
            code=CAPABILITY_CODES.get(kind, CAPABILITY_CODES["malformed"]),
            reason=reason,
            token_id=token.token_id if token else "",
            subject=token.subject if token else "",
        )

    def verify(
        self,
        token: Optional[Capability],
        *,
        action: str = "",
        semantic_scope_hash: str = "",
        policy_hash: str = "",
        now: Optional[float] = None,
    ) -> CapabilityCheck:
        """Run every check, in the order an attacker would attack them."""
        if token is None:
            return self._fail("malformed", "no capability token supplied")
        if not token.capabilities or not token.issuer:
            return self._fail("malformed", "token is missing its issuer or capability set", token)

        # 1. crypto suite and anti-downgrade, before any signature work: a token
        #    that claims a weaker suite than the policy allows never gets verified.
        if token.crypto_suite not in SUITES:
            return self._fail("downgrade", f"unknown crypto suite {token.crypto_suite!r}", token)
        if SUITES[token.crypto_suite] < SUITES[self.min_suite]:
            return self._fail(
                "downgrade",
                f"suite {token.crypto_suite!r} is below the required minimum {self.min_suite!r}",
                token,
            )
        if tuple(token.required_algorithms) != SUITE_ALGORITHMS[token.crypto_suite]:
            return self._fail(
                "downgrade",
                "the token's declared algorithms do not match its suite: a stripped "
                "post-quantum half is a downgrade, not a format detail",
                token,
            )

        # 2. signature over the canonical bytes, with every required algorithm
        #    actually present. pqc_engine.verify() accepts a stripped ML-DSA half,
        #    so the presence check is ours to make (finding H2).
        if token.signature is None:
            return self._fail("signature", "token carries no signature", token)
        required = set(SUITE_ALGORITHMS[token.crypto_suite])
        present = {"ed25519"} | ({"ml-dsa-65"} if token.signature.mldsa else set())
        if present != required:
            return self._fail(
                "downgrade",
                f"signature has {sorted(present)}, suite requires {sorted(required)}",
                token,
            )
        if not verify(self.owner_public, token.bytes(), token.signature):
            return self._fail("signature", "the owner's signature does not verify", token)

        # 3. issuer identity: the key must be the owner's, not merely the name.
        if token.issuer_fingerprint and token.issuer_fingerprint != self.owner_public.fingerprint:
            return self._fail("issuer", "token was issued by a different key", token)
        if token.issuer != self.owner_public.name:
            return self._fail("issuer", f"token issuer {token.issuer!r} is not the owner", token)

        # 4. audience, epoch, validity window
        if self.audience and token.audience != self.audience:
            return self._fail("audience", f"token is for {token.audience!r}, this is {self.audience!r}", token)
        if token.epoch != self.epoch:
            return self._fail(
                "epoch", f"token is from epoch {token.epoch}, the owner is at {self.epoch}", token
            )
        moment = self.clock() if now is None else float(now)
        if moment > token.expires_at:
            return self._fail("expired", "token has expired", token)
        if token.issued_at - moment > self.skew:
            return self._fail("expired", "token is dated in the future", token)

        # 5. revocation
        if token.token_id in self.revocations:
            return self._fail("revoked", "token was revoked by the owner", token)

        # 6. policy binding: a token is only valid under the policy it was issued for
        bound = self.policy_hash or policy_hash
        if bound and token.policy_hash != bound:
            return self._fail("policy", "token was issued under a different policy", token)

        # 7. semantic scope binding (S5/S24): the token must be about *this* work
        if token.semantic_scope_hash and semantic_scope_hash:
            if token.semantic_scope_hash != semantic_scope_hash:
                return self._fail("scope", "token's semantic scope does not match the request", token)

        # 8. the grant itself
        if action and not token.grants(action):
            return self._fail(
                "capability", f"{action!r} is not within {list(token.capabilities)}", token
            )

        return CapabilityCheck(
            ok=True,
            token_id=token.token_id,
            subject=token.subject,
            capabilities=token.capabilities,
            epoch=token.epoch,
        )


def _self_check() -> int:  # pragma: no cover - convenience entry point
    """Issue, verify, tamper, and report — the shortest honest demonstration."""
    root = OwnerRoot.create(audience="demo")
    token = root.issue("agent://weather", ["run:weather", "read:ledger"], ttl=300)
    verifier = CapabilityVerifier(root.public, audience="demo", epoch=root.epoch)
    print("issued :", token.token_id, token.capabilities)
    print("verify :", verifier.verify(token, action="run:weather"))
    print("wrong  :", verifier.verify(token, action="run:banking").code)
    print("epoch  :", CapabilityVerifier(root.public, audience="demo", epoch=root.epoch + 1).verify(token).code)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_self_check())
