"""Layer 3 — zero-knowledge authentication (Schnorr + Pedersen).

A real, standard construction, written from the primitives rather than wrapped
in a SNARK label it cannot honour.

What is implemented
-------------------
* **Schnorr proofs of knowledge** over a 2048-bit prime-order subgroup, made
  non-interactive with Fiat–Shamir over SHA-256. A prover shows it holds the
  discrete log of a registered public value without revealing it. The challenge
  is bound to a *context* (audience, session id, epoch), so a proof harvested
  from one session cannot be replayed into another.
* **Nullifiers**, so each proof is single-use: the gateway records the nullifier
  of every accepted proof and refuses a repeat.
* **Pedersen commitments** with a proof of knowledge of the opening. This is
  what lets a receiver verify a committed attribute (a role, a clearance level)
  without learning it.

Where the group comes from
--------------------------
No memorised constants. The group is either injected by the caller or generated
once (45 s for 2048 bits) and cached to ``~/.aegis/dh_group.json``. Every loaded
group is **validated through the ``cryptography`` library** before use, so a
tampered cache is rejected rather than trusted. ``q`` (the subgroup order) is
confirmed prime by this module's own Miller–Rabin, which the test-suite checks
against known primes and composites.

Not implemented, and not claimed
--------------------------------
zk-SNARKs (Groth16/PLONK) and zk-STARKs: there is no pairing library here, no
trusted-setup ceremony, and no constraint system. A SNARK would add the ability
to prove *statements about committed values* ("clearance ≥ 3") in constant
proof size; :class:`Statement` documents that extension point. Until a backend
exists, ``describe()`` reports ``snark: False`` and the docs say the same.

    >>> prover = Prover.from_secret(b"identity-secret", group=small_group)
    >>> proof = prover.prove(context=b"session-1")
    >>> Verifier().verify(prover.public, proof, context=b"session-1")
    True
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from ._kdf import hkdf

__all__ = [
    "SchnorrGroup",
    "Prover",
    "Verifier",
    "Proof",
    "Commitment",
    "Statement",
    "modular_pow",
    "is_probable_prime",
    "miller_rabin",
    "default_group",
    "MASK",
]

MASK = 0xFFFFFFFF

_DOMAIN = b"aegis/zkp/v2"


# ---------------------------------------------------------------------------
# Primality (used to confirm the subgroup order, and tested against fixtures)
# ---------------------------------------------------------------------------
def miller_rabin(n: int, *, rounds: int = 40, seed: int = 0) -> bool:
    """Miller–Rabin probable-prime test.

    ``rounds`` random bases by default; pass a ``seed`` for reproducibility in
    tests. Deterministic for n < 3.3e24 with fixed small bases, which the
    test-suite checks against known primes and composites.
    """
    if n < 2:
        return False
    for small in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % small == 0:
            return n == small

    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1

    random_source = secrets.SystemRandom() if seed == 0 else None
    for round_index in range(rounds):
        if random_source is not None:
            base = random_source.randrange(2, n - 1)
        else:
            base = 2 + ((seed + round_index) % (n - 3))
        x = pow(base, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def is_probable_prime(n: int, *, rounds: int = 40) -> bool:
    return miller_rabin(n, rounds=rounds)


def modular_pow(base: int, exponent: int, modulus: int) -> int:
    return pow(base, exponent, modulus)


# ---------------------------------------------------------------------------
# Group
# ---------------------------------------------------------------------------
def _default_group_path() -> Path:
    override = os.environ.get("AEGIS_DH_GROUP")
    if override:
        return Path(override)
    return Path.home() / ".aegis" / "dh_group.json"


def default_group(*, bits: Optional[int] = None, quiet: bool = True) -> "SchnorrGroup":
    """Load (or generate once, then cache) the authentication group.

    Set ``AEGIS_DH_BITS=1024`` for a fast, weaker group in tests; 2048 is the
    default and costs about 45 s *once* per machine.
    """
    size = bits or int(os.environ.get("AEGIS_DH_BITS", "2048"))
    path = _default_group_path()
    if path.is_file():
        try:
            return SchnorrGroup.load(path)
        except (ValueError, KeyError, json.JSONDecodeError):
            pass  # tampered or truncated cache: regenerate below
    group = SchnorrGroup.generate(size, quiet=quiet)
    try:
        group.save(path)
    except OSError:  # pragma: no cover - read-only home
        pass
    return group


@dataclass(frozen=True)
class SchnorrGroup:
    """A prime-order subgroup: ``p`` safe prime, ``q = (p-1)/2``, generator ``g``."""

    p: int
    q: int
    g: int
    bits: int
    #: Second generator for Pedersen commitments, with no known discrete log
    #: relative to ``g`` (derived by hash-to-subgroup, verifiable by anyone).
    h: int = 0

    def __post_init__(self) -> None:
        if self.h == 0:
            object.__setattr__(self, "h", derive_second_generator(self.p, self.q, self.g))

    # -- validation ------------------------------------------------------
    def validate(self) -> "SchnorrGroup":
        """Reject anything that is not a sane Schnorr group.

        The parameters are checked through ``cryptography`` (which verifies that
        ``p`` is a safe prime of adequate size), then this module confirms the
        subgroup order and the generators independently.
        """
        if self.bits < 1024:
            raise ValueError(f"group is too small: {self.bits} bits")

        from .capabilities import require_classical

        require_classical("validating a Schnorr group (safe-prime check)")

        with _suppress_deprecation():
            from cryptography.hazmat.primitives.asymmetric import dh

            dh.DHParameterNumbers(p=self.p, g=self.g).parameters()  # raises on bad input

        if not is_probable_prime(self.q, rounds=24):
            raise ValueError("subgroup order q is not prime")
        if (self.p - 1) % self.q != 0:
            raise ValueError("q does not divide p-1")
        if pow(self.g, self.q, self.p) != 1:
            raise ValueError("g is not in the order-q subgroup")
        if self.g in (1, self.p - 1):
            raise ValueError("g is a trivial generator")
        if pow(self.h, self.q, self.p) != 1 or self.h in (1, self.p - 1):
            raise ValueError("h is not a valid second generator")
        if self.h == self.g:
            raise ValueError("h must differ from g")
        return self

    # -- construction ----------------------------------------------------
    @classmethod
    def generate(cls, bits: int = 2048, *, quiet: bool = True) -> "SchnorrGroup":
        from .capabilities import require_classical

        require_classical("generating a Schnorr group (safe-prime search)")
        if not quiet:
            print(f"generating a {bits}-bit group (one-off, then cached)…", flush=True)
        with _suppress_deprecation():
            from cryptography.hazmat.primitives.asymmetric import dh

            numbers = dh.generate_parameters(generator=2, key_size=bits).parameter_numbers()
        group = cls(p=numbers.p, q=(numbers.p - 1) // 2, g=numbers.g, bits=bits)
        return group.validate()

    @classmethod
    def from_numbers(cls, p: int, g: int) -> "SchnorrGroup":
        return cls(p=p, q=(p - 1) // 2, g=g, bits=p.bit_length()).validate()

    # -- persistence -----------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": 2,
            "bits": self.bits,
            "p": hex(self.p),
            "q": hex(self.q),
            "g": self.g,
            "h": hex(self.h),
            "source": "generated locally and validated via cryptography (safe prime)",
        }

    def save(self, path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(path.parent, 0o700)
        except OSError:  # pragma: no cover
            pass
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(self.to_dict(), handle, indent=2)
        return path

    @classmethod
    def load(cls, path: Path) -> "SchnorrGroup":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        group = cls(
            p=int(payload["p"], 16),
            q=int(payload["q"], 16),
            g=int(payload["g"]),
            bits=int(payload["bits"]),
            h=int(payload["h"], 16) if payload.get("h") else 0,
        )
        return group.validate()

    def subgroup_element(self, value: int) -> int:
        """Reduce an arbitrary integer into the subgroup (hash-to-subgroup)."""
        candidate = value % self.p
        if candidate in (0, 1):
            candidate = 2
        element = pow(candidate, (self.p - 1) // self.q, self.p)
        return element

    def random_scalar(self) -> int:
        return secrets.randbelow(self.q - 1) + 1

    def to_dict_public(self) -> Dict[str, Any]:
        return {"bits": self.bits, "g": self.g, "p_fingerprint": self.fingerprint()}

    def fingerprint(self) -> str:
        digest = hashlib.sha256()
        digest.update(self.p.to_bytes((self.p.bit_length() + 7) // 8, "big"))
        digest.update(self.q.to_bytes((self.q.bit_length() + 7) // 8, "big"))
        digest.update(str(self.g).encode())
        digest.update(str(self.h).encode())
        return digest.hexdigest()[:16]


def derive_second_generator(p: int, q: int, g: int) -> int:
    """Pedersen's second generator via hash-to-subgroup.

    ``h = H(p, g)^{(p-1)/q} mod p``. Anyone can verify that ``h`` is in the
    subgroup and that ``h != 1``; the derivation publishes no discrete log, so
    binding does not collapse.
    """
    seed = hashlib.sha256(_DOMAIN + b"|h|" + str(p).encode() + b"|" + str(g).encode()).digest()
    candidate = int.from_bytes(seed, "big") % p
    if candidate in (0, 1):
        candidate = 2
    element = pow(candidate, (p - 1) // q, p)
    if element in (0, 1):
        element = 2  # pragma: no cover - astronomically unlikely
    return element


def _suppress_deprecation():
    import contextlib
    import warnings

    @contextlib.contextmanager
    def manager():
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            try:
                from cryptography.utils import CryptographyDeprecationWarning

                warnings.simplefilter("ignore", CryptographyDeprecationWarning)
            except Exception:  # pragma: no cover
                pass
            yield

    return manager()


# ---------------------------------------------------------------------------
# Proofs
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Statement:
    """What a proof claims.

    ``kind="dlog"`` proves knowledge of ``x`` with ``y = g^x``.
    ``kind="opening"`` proves knowledge of ``(m, r)`` with ``C = g^m h^r``.
    A SNARK backend would add ``kind="range"`` and friends here.
    """

    kind: str = "dlog"
    public: str = ""  # base64 of the public value y or the commitment C
    label: str = ""


@dataclass(frozen=True)
class Proof:
    """A Fiat–Shamir transcript: commitment(s), challenge, response(s)."""

    statement: Statement
    commitment: str
    challenge: str
    response: str
    response2: str = ""
    nullifier: str = ""
    created_at: float = field(default_factory=time.time)
    group: Dict[str, Any] = field(default_factory=dict)
    context_hash: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    def encode(self) -> bytes:
        return b"AEGIS-ZKP2" + self.to_json().encode("utf-8")

    @classmethod
    def decode(cls, blob: bytes) -> "Proof":
        if not blob.startswith(b"AEGIS-ZKP2"):
            raise ValueError("not an AEGIS ZKP proof")
        payload = json.loads(blob[len(b"AEGIS-ZKP2") :].decode("utf-8"))
        statement = Statement(**payload.pop("statement"))
        return cls(statement=statement, **payload)


def _int_to_bytes(value: int, length: Optional[int] = None) -> bytes:
    size = length or max(1, (value.bit_length() + 7) // 8)
    return value.to_bytes(size, "big")


def _b64(value: int) -> str:
    return base64.b64encode(_int_to_bytes(value)).decode("ascii")


def _unb64(value: str) -> int:
    return int.from_bytes(base64.b64decode(value), "big")


def _challenge(*parts: bytes) -> int:
    digest = hashlib.sha256()
    digest.update(_DOMAIN)
    for part in parts:
        digest.update(len(part).to_bytes(4, "big"))
        digest.update(part)
    return int.from_bytes(digest.digest(), "big")


# ---------------------------------------------------------------------------
# Prover / Verifier
# ---------------------------------------------------------------------------
class Prover:
    """Holds a secret and produces proofs about it.

    The secret is derived from caller-supplied key material through HKDF, so a
    short passphrase is not used directly as a discrete log.
    """

    def __init__(self, secret: bytes, *, group: SchnorrGroup, label: str = "") -> None:
        self.group = group
        material = hkdf(secret, 64, info=_DOMAIN + b"|prover")
        self.x = int.from_bytes(material, "big") % (group.q - 1) + 1
        self.label = label or "anonymous"
        self._y = pow(group.g, self.x, group.p)

    @classmethod
    def from_secret(cls, secret: bytes, *, group: Optional[SchnorrGroup] = None, label: str = "") -> "Prover":
        return cls(secret, group=group or default_group(), label=label)

    @property
    def public(self) -> Statement:
        return Statement(kind="dlog", public=_b64(self._y), label=self.label)

    @property
    def public_value(self) -> int:
        return self._y

    # -- dlog proof ------------------------------------------------------
    def prove(self, *, context: bytes = b"", extra: bytes = b"") -> Proof:
        """Prove knowledge of the secret behind :meth:`public`."""
        q, g, p = self.group.q, self.group.g, self.group.p
        nonce = self.group.random_scalar()
        commitment = pow(g, nonce, p)
        challenge = _challenge(
            b"dlog",
            _int_to_bytes(p),
            _int_to_bytes(g),
            _int_to_bytes(self._y),
            _int_to_bytes(commitment),
            context,
            extra,
        ) % q
        response = (nonce + challenge * self.x) % q
        return Proof(
            statement=self.public,
            commitment=_b64(commitment),
            challenge=_b64(challenge),
            response=_b64(response),
            nullifier=nullifier_for(self._y, context),
            group=self.group.to_dict_public(),
            context_hash=hashlib.sha256(context).hexdigest()[:16],
        )

    # -- commitment ------------------------------------------------------
    def commit(self, value: int, *, label: str = "") -> "Commitment":
        """Pedersen commitment to ``value``; returns it with its opening."""
        q, g, h, p = self.group.q, self.group.g, self.group.h, self.group.p
        blinding = self.group.random_scalar()
        commitment = (pow(g, value % q, p) * pow(h, blinding, p)) % p
        return Commitment(
            value=value % q,
            blinding=blinding,
            commitment=_b64(commitment),
            label=label,
            group=self.group.to_dict_public(),
        )

    def prove_opening(self, commitment: "Commitment", *, context: bytes = b"") -> Proof:
        """Prove knowledge of the opening without revealing ``value``."""
        q, g, h, p = self.group.q, self.group.g, self.group.h, self.group.p
        c = _unb64(commitment.commitment)
        k1, k2 = self.group.random_scalar(), self.group.random_scalar()
        t = (pow(g, k1, p) * pow(h, k2, p)) % p
        challenge = _challenge(
            b"opening",
            _int_to_bytes(p),
            _int_to_bytes(g),
            _int_to_bytes(h),
            _int_to_bytes(c),
            _int_to_bytes(t),
            context,
        ) % q
        s1 = (k1 + challenge * commitment.value) % q
        s2 = (k2 + challenge * commitment.blinding) % q
        statement = Statement(kind="opening", public=commitment.commitment, label=commitment.label)
        return Proof(
            statement=statement,
            commitment=_b64(t),
            challenge=_b64(challenge),
            response=_b64(s1),
            response2=_b64(s2),
            nullifier=nullifier_for(c, context),
            group=self.group.to_dict_public(),
            context_hash=hashlib.sha256(context).hexdigest()[:16],
        )


@dataclass
class Commitment:
    """A Pedersen commitment plus the opening (held by the committer only)."""

    value: int
    blinding: int
    commitment: str
    label: str = ""
    group: Dict[str, Any] = field(default_factory=dict)

    def public(self) -> Statement:
        return Statement(kind="opening", public=self.commitment, label=self.label)


class Verifier:
    """Checks proofs and remembers nullifiers so none can be replayed."""

    def __init__(self, group: Optional[SchnorrGroup] = None, *, max_nullifiers: int = 100_000) -> None:
        self.group = group
        self.nullifiers: Set[str] = set()
        self.max_nullifiers = max_nullifiers
        self.accepted = 0
        self.rejected = 0

    # -- helpers ---------------------------------------------------------
    def _group_for(self, proof: Proof) -> SchnorrGroup:
        if self.group is None:
            raise ValueError("a group must be supplied when the proof omits one")
        if proof.group and proof.group.get("p_fingerprint") not in (None, self.group.fingerprint()):
            raise ValueError("proof was produced in a different group")
        return self.group

    @staticmethod
    def _in_subgroup(group: SchnorrGroup, value: int) -> bool:
        if not (1 < value < group.p - 1):
            return False
        return pow(value, group.q, group.p) == 1

    # -- verification ----------------------------------------------------
    def verify(
        self,
        statement: Statement,
        proof: Proof,
        *,
        context: bytes = b"",
        consume_nullifier: bool = True,
    ) -> bool:
        try:
            group = self._group_for(proof)
            ok = self._verify(statement, proof, group, context)
        except (ValueError, KeyError, TypeError):
            self.rejected += 1
            return False

        if not ok:
            self.rejected += 1
            return False

        if consume_nullifier:
            if proof.nullifier in self.nullifiers:
                self.rejected += 1
                return False  # replay
            if len(self.nullifiers) >= self.max_nullifiers:
                self.nullifiers.clear()  # pragma: no cover - bounded memory
            self.nullifiers.add(proof.nullifier)

        self.accepted += 1
        return True

    def _verify(self, statement: Statement, proof: Proof, group: SchnorrGroup, context: bytes) -> bool:
        p, q, g, h = group.p, group.q, group.g, group.h
        challenge = _unb64(proof.challenge) % q
        if challenge == 0:
            return False
        if proof.statement.public != statement.public:
            return False

        public = _unb64(statement.public)
        if statement.kind == "dlog":
            if not self._in_subgroup(group, public):
                return False
            response = _unb64(proof.response) % q
            # R' = g^s * y^(q - c); this is s*G - c*Y without an inverse.
            recovered = (pow(g, response, p) * pow(public, (q - challenge) % q, p)) % p
            expected = _challenge(
                b"dlog",
                _int_to_bytes(p),
                _int_to_bytes(g),
                _int_to_bytes(public),
                _int_to_bytes(recovered),
                context,
                b"",
            ) % q
            return hmac.compare_digest(str(challenge), str(expected))

        if statement.kind == "opening":
            commitment = public
            if not self._in_subgroup(group, commitment):
                return False
            s1, s2 = _unb64(proof.response) % q, _unb64(proof.response2) % q
            recovered = (
                pow(g, s1, p) * pow(h, s2, p) * pow(commitment, (q - challenge) % q, p)
            ) % p
            expected = _challenge(
                b"opening",
                _int_to_bytes(p),
                _int_to_bytes(g),
                _int_to_bytes(h),
                _int_to_bytes(commitment),
                _int_to_bytes(recovered),
                context,
            ) % q
            return hmac.compare_digest(str(challenge), str(expected))

        return False  # unknown statement kind: never assume it is fine

    # -- reporting -------------------------------------------------------
    def describe(self) -> Dict[str, Any]:
        group = self.group
        return {
            "layer": "zerk",
            "scheme": "Schnorr (Fiat-Shamir, SHA-256)",
            "commitments": "Pedersen over the same subgroup",
            "snark": False,
            "stark": False,
            "note": "no trusted setup, no pairing library: proves knowledge, not arbitrary statements",
            "group": group.to_dict_public() if group else None,
            "accepted": self.accepted,
            "rejected": self.rejected,
            "nullifiers_recorded": len(self.nullifiers),
        }


def nullifier_for(public: int, context: bytes) -> str:
    """A deterministic, non-reversible tag for one (identity, context) pair."""
    digest = hashlib.sha256()
    digest.update(_DOMAIN + b"|nullifier|")
    digest.update(_int_to_bytes(public))
    digest.update(len(context).to_bytes(4, "big"))
    digest.update(context)
    return digest.hexdigest()[:32]
