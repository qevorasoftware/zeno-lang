"""Layer 2 — biometric verification done the way it actually works.

The brief asked for "SHA-512 of fingerprint + retina + voice + keystroke".
Hashing a biometric like a password is a well-known mistake: biometrics are
low-entropy and cannot be rotated, so a leaked hash is a permanent identity
leak. This module implements what the literature actually prescribes:

1. **A fuzzy extractor.** Biometric readings are noisy — the same finger never
   produces the same bits twice. So the template is *quantised* on a grid, bits
   that sit too close to a grid boundary are marked unstable and dropped, and
   the remaining stable bits are mixed with a random secret on enrolment
   (the **helper data** lets a later reading recover that secret, but does not
   reveal it). This is the Juels–Wattenberg fuzzy-commitment construction.
2. **Slow KDF hardening.** The verifier is stored as a scrypt hash, so
   brute-forcing the enrolment file costs real memory and time.
3. **Per-subject salting and versioning**, so a leak in one deployment cannot be
   replayed against another.

What is *not* here, and is not claimed: actual fingerprint/retina sensors, DNA.
A DNA hash is not implemented because a DNA sequence is not secret — it is an
identifier you leave everywhere. ``dna_commitment`` is provided as a *keyed
digest* for completeness and is labelled exactly as that.

    >>> bio = BiometricVault()
    >>> template = [0.9, -0.4, 0.75, 1.2, -0.9, 0.35]
    >>> record = bio.enrol("amara", template)
    >>> noise = [0.91, -0.38, 0.74, 1.22, -0.88, 0.33]
    >>> bio.verify("amara", noise)
    True
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from ._kdf import derive_key, hkdf

__all__ = [
    "BiometricVault",
    "BiometricRecord",
    "Enrolment",
    "fuzzy_commit",
    "fuzzy_reproduce",
    "features_from_text",
    "entropy_grade",
    "WEAK_ENTROPY_BITS",
    "STRONG_ENTROPY_BITS",
    "dna_commitment",
    "sketch_from_signals",
]

#: Quantisation grid step. A reading must be further than ``MARGIN`` from a
#: bin edge to be trusted: that margin is what absorbs measurement noise.
GRID = 0.25
MARGIN = 0.06


def _bits(value: float, grid: float = GRID) -> int:
    return int(value // grid) & 1


def _stable(value: float, grid: float = GRID, margin: float = MARGIN) -> bool:
    """``True`` when the reading is far enough from a bin edge to be reliable."""
    position = value / grid
    distance = abs(position - round(position))
    return distance * grid > margin


#: Below this many stable bits the derived secret is not a key, it is a hint.
WEAK_ENTROPY_BITS = 64
STRONG_ENTROPY_BITS = 128


def entropy_grade(bits: int) -> str:
    if bits < WEAK_ENTROPY_BITS:
        return "weak"
    if bits < STRONG_ENTROPY_BITS:
        return "moderate"
    return "strong"


def fuzzy_commit(
    template: Sequence[float],
    *,
    grid: float = GRID,
    margin: float = MARGIN,
    require_entropy: bool = False,
) -> Tuple[bytes, bytes, Dict[str, Any]]:
    """Enrol a template. Returns ``(helper, secret, info)``.

    ``helper`` is stored; ``secret`` is *not* stored anywhere — it is mixed into
    whatever the caller protects (a device key, a passphrase-derived key). A
    later noisy reading plus ``helper`` reproduces the same secret, because the
    secret is an HKDF of the recovered stable bits rather than independent
    randomness.

    ``info["entropy_bits"]`` is the honest budget: the secret is only as strong
    as the number of stable bits the template yields. A 32-dimension template
    gives roughly 20 bits — enough to *demonstrate* the construction, not
    enough to be a key. Pass ``require_entropy=True`` to refuse weak enrolments
    outright.
    """
    if not template:
        raise ValueError("a biometric template cannot be empty")

    stable = [_stable(value, grid, margin) for value in template]
    stable_count = sum(stable)
    if not stable_count:
        raise ValueError("template has no stable bits: the reading is too noisy to enrol")

    grade = entropy_grade(stable_count)
    if require_entropy and stable_count < STRONG_ENTROPY_BITS:
        raise ValueError(
            f"template yields only {stable_count} stable bits ({grade}); "
            f"{STRONG_ENTROPY_BITS} are required — feed more features or a better sensor"
        )

    # The secret lives in exactly the bits the reading can reproduce.
    secret_bits = [secrets_bit() for _ in range(stable_count)]
    # Helper bits stay ALIGNED with the template (placeholders at unstable
    # positions) so reproduction cannot zip the wrong readings together.
    helper_bits: List[int] = []
    index = 0
    for value, is_stable in zip(template, stable):
        if not is_stable:
            helper_bits.append(0)
            continue
        helper_bits.append(_bits(value, grid) ^ secret_bits[index])
        index += 1

    helper = base64.b64encode(_pack(helper_bits, stable)).decode("ascii")
    secret = derive_key([_from_bits(secret_bits)], info=b"aegis/fuzzy/v2")
    info = {
        "length": len(template),
        "stable_bits": stable_count,
        "discarded_bits": len(template) - stable_count,
        "entropy_bits": stable_count,
        "entropy_grade": grade,
        "grid": grid,
        "margin": margin,
        "construction": "fuzzy commitment (Juels-Wattenberg) + HKDF-SHA256",
        "honest_limit": (
            f"{stable_count} stable bits of entropy: "
            + ("sufficient as a key factor" if grade == "strong"
               else "NOT sufficient alone — combine with another factor")
        ),
    }
    return helper.encode("ascii"), secret, info


def secrets_bit() -> int:
    """A single unpredictable bit (uses ``secrets`` so it is OS-grade)."""
    import secrets

    return secrets.randbits(1)


def fuzzy_reproduce(
    helper: bytes, template: Sequence[float], *, grid: float = GRID
) -> bytes:
    """Recover the enrolment secret from a *noisy* reading of the same trait."""
    stored = _unpack(base64.b64decode(helper).decode("ascii"))
    if len(stored["bits"]) != len(template):
        raise ValueError(
            f"template length {len(template)} does not match the enrolment ({len(stored['bits'])})"
        )

    recovered: List[int] = []
    for value, is_stable, helper_bit in zip(template, stored["stable"], stored["bits"]):
        if not is_stable:
            continue
        recovered.append(_bits(value, grid) ^ helper_bit)
    if not recovered:
        raise ValueError("no stable bits in the reading: nothing can be reproduced")
    return derive_key([_from_bits(recovered)], info=b"aegis/fuzzy/v2")


def _bits_of(data: bytes, count: int) -> List[int]:
    bits = [int(bit) for byte in data for bit in f"{byte:08b}"]
    while len(bits) < count:  # pragma: no cover - only when count > 256
        bits.extend(bits)
    return bits[:count]


def _from_bits(bits: Sequence[int]) -> bytes:
    padded = list(bits) + [0] * ((8 - len(bits) % 8) % 8)
    return bytes(int("".join(str(bit) for bit in padded[index : index + 8]), 2) for index in range(0, len(padded), 8))


def _pack(bits: Sequence[int], stable: Sequence[bool]) -> bytes:
    """Serialise helper bits and the stability mask, both template-aligned."""
    import json

    if len(bits) != len(stable):
        raise ValueError("helper bits and the stability mask must be the same length")
    return json.dumps(
        {"bits": [int(bit) for bit in bits], "stable": [bool(flag) for flag in stable], "v": 2},
        separators=(",", ":"),
    ).encode("utf-8")


def _unpack(text: str) -> Dict[str, Any]:
    import json

    return json.loads(text)


# ---------------------------------------------------------------------------
# Feature extraction (so the layer can be demonstrated without sensors)
# ---------------------------------------------------------------------------
def features_from_text(text: str, *, dimensions: int = 16) -> List[float]:
    """Deterministic stand-in for a sensor reading, used in tests and demos.

    Real deployments feed it the output of their own feature extractor
    (minutiae counts, retina vessel geometry, MFCCs, keystroke timings). The
    fuzzy extractor above is what makes those noisy numbers workable.
    """
    digest = hashlib.sha512(text.encode("utf-8")).digest()
    values: List[float] = []
    for index in range(dimensions):
        byte = digest[index % len(digest)]
        values.append((byte / 255.0) * 2.0 - 1.0)
    return values


def sketch_from_signals(signals: Sequence[Sequence[float]], *, grid: float = GRID) -> List[float]:
    """Fuse several biometric channels into one template.

    Each channel is normalised, then channels are interleaved so that a single
    channel going missing degrades the template rather than voiding it.
    """
    if not signals:
        raise ValueError("at least one channel is required")
    normalised: List[List[float]] = []
    for channel in signals:
        if not channel:
            continue
        low, high = min(channel), max(channel)
        span = (high - low) or 1.0
        normalised.append([(value - low) / span * 2.0 - 1.0 for value in channel])
    if not normalised:
        raise ValueError("every channel was empty")
    length = min(len(channel) for channel in normalised)
    fused: List[float] = []
    for index in range(length):
        for channel in normalised:
            fused.append(round(channel[index] / grid) * grid)
    return fused


def dna_commitment(sequence: str, *, subject_salt: bytes, pepper: bytes = b"") -> str:
    """Keyed digest of a DNA sequence — **not** a security improvement.

    Included because the brief asked for it, and labelled honestly: a genome is
    an identifier, not a secret, so this is a *privacy* control (it lets you
    match two samples without storing the sequence) and nothing more.
    """
    normalised = "".join(character.upper() for character in sequence if character.isalpha())
    if not normalised:
        raise ValueError("empty DNA sequence")
    key = hkdf(subject_salt, 32, info=b"aegis/dna/v2")
    return hmac.new(key, (normalised + pepper.hex()).encode(), hashlib.blake2b).hexdigest()


# ---------------------------------------------------------------------------
# Vault
# ---------------------------------------------------------------------------
@dataclass
class BiometricRecord:
    """What gets stored. No raw template, no recoverable secret."""

    subject: str
    helper: bytes
    verifier: str
    salt: bytes
    scrypt_cost: Dict[str, int]
    channels: List[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    last_used: Optional[float] = None
    uses: int = 0
    info: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "subject": self.subject,
            "helper": base64.b64encode(self.helper).decode(),
            "verifier": self.verifier,
            "salt": base64.b64encode(self.salt).decode(),
            "scrypt": self.scrypt_cost,
            "channels": list(self.channels),
            "created_at": self.created_at,
            "last_used": self.last_used,
            "uses": self.uses,
            "info": dict(self.info),
        }

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "BiometricRecord":
        return cls(
            subject=payload["subject"],
            helper=base64.b64decode(payload["helper"]),
            verifier=payload["verifier"],
            salt=base64.b64decode(payload["salt"]),
            scrypt_cost=dict(payload["scrypt"]),
            channels=list(payload.get("channels", [])),
            created_at=float(payload.get("created_at", 0.0)),
            last_used=payload.get("last_used"),
            uses=int(payload.get("uses", 0)),
            info=dict(payload.get("info", {})),
        )


@dataclass
class Enrolment:
    """The result of an enrolment: the record plus the key the trait releases."""

    record: BiometricRecord
    #: Derived from the fuzzy secret. This is what an AEGIS session would use;
    #: it is never written to disk by this module.
    key: bytes
    info: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {"record": self.record.to_dict(), "info": self.info}


def _scrypt_parameters() -> Dict[str, int]:
    """Cost parameters, tuned down on memory-constrained hosts but reported."""
    return {"n": 2 ** 14, "r": 8, "p": 1, "dklen": 32}


def _scrypt(secret: bytes, salt: bytes, params: Dict[str, int]) -> bytes:
    from .capabilities import require_classical

    require_classical("hashing a biometric template (scrypt)")
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

    return Scrypt(
        salt=salt, length=params["dklen"], n=params["n"], r=params["r"], p=params["p"]
    ).derive(secret)


class BiometricVault:
    """Enrol and verify subjects without storing biometrics or secrets.

    Store :meth:`export`; the verifier hashes remain one-way, and the helper
    data alone cannot reconstruct the template.
    """

    def __init__(self, *, grid: float = GRID, margin: float = MARGIN, max_attempts: int = 5) -> None:
        self.grid = grid
        self.margin = margin
        self.max_attempts = max_attempts
        self.records: Dict[str, BiometricRecord] = {}
        self._failures: Dict[str, int] = {}

    # -- enrolment -------------------------------------------------------
    def enrol(
        self,
        subject: str,
        template: Sequence[float],
        *,
        channels: Optional[Sequence[str]] = None,
        require_entropy: bool = False,
    ) -> Enrolment:
        helper, secret, info = fuzzy_commit(
            template, grid=self.grid, margin=self.margin, require_entropy=require_entropy
        )
        salt = os.urandom(16)
        params = _scrypt_parameters()
        verifier = base64.b64encode(_scrypt(secret, salt, params)).decode("ascii")
        record = BiometricRecord(
            subject=subject,
            helper=helper,
            verifier=verifier,
            salt=salt,
            scrypt_cost=params,
            channels=list(channels or []),
            info=info,
        )
        self.records[subject] = record
        self._failures[subject] = 0
        key = derive_key([secret], salt=record.salt, info=b"aegis/biometric/v2")
        return Enrolment(record=record, key=key, info=info)

    # -- verification ----------------------------------------------------
    def verify(self, subject: str, template: Sequence[float]) -> bool:
        """``True`` when the noisy reading reproduces the enrolment secret.

        Failures are counted; the vault locks the subject out after
        ``max_attempts`` so the check cannot be used as an oracle.
        """
        record = self.records.get(subject)
        if record is None:
            return False
        if self._failures.get(subject, 0) >= self.max_attempts:
            raise PermissionError(f"subject {subject!r} is locked out after repeated failures")

        try:
            secret = fuzzy_reproduce(record.helper, template, grid=self.grid)
        except ValueError:
            self._failures[subject] = self._failures.get(subject, 0) + 1
            return False

        candidate = base64.b64encode(_scrypt(secret, record.salt, record.scrypt_cost)).decode("ascii")
        ok = hmac.compare_digest(candidate, record.verifier)
        if ok:
            record.uses += 1
            record.last_used = time.time()
            self._failures[subject] = 0
        else:
            self._failures[subject] = self._failures.get(subject, 0) + 1
        return ok

    def unlock(self, subject: str, template: Sequence[float]) -> bytes:
        """Verify, then return the session key the trait releases."""
        if not self.verify(subject, template):
            raise PermissionError("biometric verification failed")
        record = self.records[subject]
        secret = fuzzy_reproduce(record.helper, template, grid=self.grid)
        return derive_key([secret], salt=record.salt, info=b"aegis/biometric/v2")

    def reset(self, subject: str) -> None:
        record = self.records.pop(subject, None)
        if record is not None:
            del record
        self._failures[subject] = 0

    # -- persistence -----------------------------------------------------
    def export(self) -> Dict[str, Any]:
        return {
            "version": 2,
            "grid": self.grid,
            "margin": self.margin,
            "records": {name: record.to_dict() for name, record in self.records.items()},
            "note": "contains helper data and scrypt verifiers only — no templates, no secrets",
        }

    @classmethod
    def load(cls, payload: Dict[str, Any]) -> "BiometricVault":
        vault = cls(grid=float(payload.get("grid", GRID)), margin=float(payload.get("margin", MARGIN)))
        for name, record in payload.get("records", {}).items():
            vault.records[name] = BiometricRecord.from_dict(record)
        return vault
