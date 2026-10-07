"""VAJRA step 3 — bīja-mantra frequencies as labelled salt material.

Read this first
---------------
**A frequency is not a secret.** The pitches below are published in every book on
the subject, reproducible with a tuning fork, and identical for every deployment
on earth. Used the way the brief describes ("apply ॐ + श्रीं hash"), a frequency
adds no entropy whatsoever — an attacker who knows the scheme (Kerckhoffs assumes
they do) knows the frequency too.

So this module does the thing that is actually sound, and says which is which:

1. The bīja frequencies are used as **domain-separation salt** in a real,
   memory-hard KDF (scrypt, with PBKDF2-HMAC-SHA512 fallback), together with a
   caller-supplied secret. The salt is public on purpose; the secret is what
   protects the key. Two deployments that pick different bīja sets and different
   iteration counts cheaply get different keys from the same passphrase.
2. Frequencies are stored as **exact integer milli-hertz**, so a key derived on
   one machine is derived identically on another — floating-point drift would be
   a correctness bug in a KDF.
3. Composition is done on exact rationals (:class:`fractions.Fraction`), because
   "mathematical combinations create infinite unique keys" is only true if the
   combination is well-defined — with floats it is not.

What is emphatically not claimed: that chanting, resonance, or the age of the
tradition contributes cryptographically. The music may be real; the maths is
ordinary KDF maths, and pretending otherwise would be security theatre.

    >>> from aegis.vajra.bija_mantra_keys import derive_key
    >>> key = derive_key(b"passphrase", bijas=["om", "shrim"])
    >>> len(key)
    32
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
from dataclasses import dataclass, field
from fractions import Fraction
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .._kdf import hkdf

__all__ = [
    "BIJAS",
    "BIJA_HZ",
    "BijaSet",
    "derive_key",
    "derive_key_b64",
    "salt_material",
    "frequency_ratio",
    "resonance_pattern",
    "provenance_report",
    "SCRYPT_PARAMS",
]

#: Bīja (seed) mantras with the frequency commonly associated with each, stored
#: as exact milli-hertz. Sources disagree; where they do, the range is noted in
#: ``provenance`` rather than silently averaged.
BIJAS: Dict[str, Dict[str, Any]] = {
    "om": {"devanagari": "ॐ", "milli_hz": 136_100, "provenance": "widely cited 'OM' tone; modern attribution"},
    "hrim": {"devanagari": "ह्रीं", "milli_hz": 256_000, "provenance": "solfeggio-style attribution; not Vedic"},
    "shrim": {"devanagari": "श्रीं", "milli_hz": 417_000, "provenance": "solfeggio-style attribution; not Vedic"},
    "klim": {"devanagari": "क्लीं", "milli_hz": 528_000, "provenance": "solfeggio-style attribution; not Vedic"},
    "aim": {"devanagari": "ऐं", "milli_hz": 741_000, "provenance": "solfeggio-style attribution; not Vedic"},
    "hum": {"devanagari": "हूं", "milli_hz": 852_000, "provenance": "solfeggio-style attribution; not Vedic"},
    "sham": {"devanagari": "शं", "milli_hz": 432_000, "provenance": "'natural' A = 432 Hz claim; disputed"},
    "krim": {"devanagari": "क्रीं", "milli_hz": 639_000, "provenance": "solfeggio-style attribution; not Vedic"},
}

BIJA_HZ: Dict[str, float] = {name: entry["milli_hz"] / 1000 for name, entry in BIJAS.items()}

#: scrypt parameters. ``n`` is memory cost; raising it is the only knob that
#: actually buys resistance to a guessing attacker.
SCRYPT_PARAMS: Dict[str, int] = {"n": 2 ** 15, "r": 8, "p": 1, "dklen": 32}

_MASK = (1 << 64) - 1


@dataclass(frozen=True)
class BijaSet:
    """An ordered selection of bījas plus the parameters that protect the key."""

    names: Tuple[str, ...]
    iterations: int = 1
    domain: str = "aegis/vajra/bija/v2"

    def __post_init__(self) -> None:
        unknown = [name for name in self.names if name not in BIJAS]
        if unknown:
            raise ValueError(f"unknown bīja(s) {unknown}; available: {sorted(BIJAS)}")
        if self.iterations < 1:
            raise ValueError("iterations must be at least 1")

    @property
    def devanagari(self) -> str:
        return " ".join(BIJAS[name]["devanagari"] for name in self.names)

    @property
    def milli_hz(self) -> List[int]:
        return [BIJAS[name]["milli_hz"] for name in self.names]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bijas": list(self.names),
            "devanagari": self.devanagari,
            "milli_hz": self.milli_hz,
            "iterations": self.iterations,
            "domain": self.domain,
            "entropy_from_frequencies": 0,
            "note": "frequencies are public constants used as salt; secrecy comes from the passphrase",
        }


def salt_material(bijas: Sequence[str], *, iterations: int = 1, extra: bytes = b"") -> bytes:
    """Deterministic salt bytes for a bīja set.

    Exact integers, no floats, no locale dependence: the same bīja set produces
    the same salt on every platform, which is what a KDF requires.
    """
    if not bijas:
        raise ValueError("at least one bīja is required")
    parts: List[bytes] = [b"aegis/vajra/bija/v2"]
    for name in bijas:
        if name not in BIJAS:
            raise ValueError(f"unknown bīja {name!r}")
        parts.append(name.encode("utf-8"))
        parts.append(str(BIJAS[name]["milli_hz"]).encode("ascii"))
    parts.append(str(iterations).encode("ascii"))
    if extra:
        parts.append(extra)
    return hkdf(b"|".join(parts), 32, info=b"aegis/vajra/salt")


def frequency_ratio(left: str, right: str) -> Fraction:
    """The exact rational ratio between two bīja frequencies.

    Exact on purpose: the brief's "mathematical combinations create infinite
    unique keys" only holds if the combination is well defined. Here it is a
    :class:`~fractions.Fraction`, so no two machines disagree about it.
    """
    if left not in BIJAS or right not in BIJAS:
        missing = [name for name in (left, right) if name not in BIJAS]
        raise ValueError(f"unknown bīja(s): {missing}")
    return Fraction(BIJAS[left]["milli_hz"], BIJAS[right]["milli_hz"])


def derive_key(
    secret: bytes,
    *,
    bijas: Sequence[str] = ("om", "shrim"),
    iterations: int = 1,
    length: int = 32,
    extra_salt: bytes = b"",
    params: Optional[Dict[str, int]] = None,
) -> bytes:
    """Derive a key from a secret, salted with bīja frequencies.

    ``secret`` is the only secret input. It is hashed through scrypt (or
    PBKDF2-HMAC-SHA512 if ``cryptography`` is unavailable) down to ``length``
    bytes, with the bīja salt mixed in first so that different bīja sets produce
    unrelated keys from the same passphrase.
    """
    if not secret:
        raise ValueError("a secret is required; bīja frequencies alone protect nothing")
    if length <= 0:
        raise ValueError("length must be positive")

    salt = salt_material(bijas, iterations=iterations, extra=extra_salt)
    cost = dict(params or SCRYPT_PARAMS)
    cost["dklen"] = length

    try:
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

        return Scrypt(
            salt=salt, length=length, n=cost["n"], r=cost["r"], p=cost["p"]
        ).derive(secret)
    except Exception:  # pragma: no cover - exercised only without the wheel
        rounds = max(200_000, cost["n"] * 8)
        return hashlib.pbkdf2_hmac("sha512", secret, salt, rounds, dklen=length)


def derive_key_b64(secret: bytes, **kwargs: Any) -> str:
    return base64.b64encode(derive_key(secret, **kwargs)).decode("ascii")


def resonance_pattern(bijas: Sequence[str], *, beats: int = 8) -> Dict[str, Any]:
    """A deterministic rhythm derived from the bīja ratios, for display only.

    Produces a laghu/guru pattern from the exact ratio's numerator and
    denominator — the same mathematics Piṅgala uses, applied to a frequency
    ratio. It is a *mnemonic aid*, not a key schedule: the test-suite asserts
    that two different ratios can be displayed identically.
    """
    if not bijas:
        raise ValueError("at least one bīja is required")
    ratio = Fraction(1, 1)
    for name in bijas:
        if name not in BIJAS:
            raise ValueError(f"unknown bīja {name!r}")
        ratio *= Fraction(BIJAS[name]["milli_hz"], 100_000)
    token = (ratio.numerator ^ (ratio.denominator << 7)) & _MASK
    bits = "".join(str((token >> shift) & 1) for shift in range(beats - 1, -1, -1))
    return {
        "ratio": f"{ratio.numerator}/{ratio.denominator}",
        "bits": bits,
        "pattern": "".join("G" if bit == "1" else "L" for bit in bits),
        "display_only": True,
    }


def provenance_report() -> Dict[str, Any]:
    """State plainly what these numbers are, and what they are not."""
    return {
        "entries": {
            name: {
                "devanagari": entry["devanagari"],
                "hz": entry["milli_hz"] / 1000,
                "provenance": entry["provenance"],
            }
            for name, entry in BIJAS.items()
        },
        "is_vedic": False,
        "claim": (
            "the 'bīja frequency' lists circulating online mix traditional seed syllables with "
            "20th-century 'solfeggio' attributions; the mantras are ancient, the numbers are mostly not"
        ),
        "cryptographic_role": "public salt / domain separation",
        "entropy_contributed": 0,
        "would_still_work_if_frequencies_were_wrong": True,
        "why": "the key depends on the caller's secret and the KDF cost, not on the frequency values",
    }
