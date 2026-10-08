"""VAJRA step 5 — the Devanagari wrap, and a measurement of what it is worth.

The brief asks for "Unicode obfuscation ... impossible to decode without
Sanskrit linguistic knowledge". That claim is false, and this module is built so
that the falseness is *checkable* rather than argued about:

* The wrap is a **bijection** between bytes and Devanagari syllable blocks drawn
  from a fixed, published table. 34 consonants × 13 vowel signs give 442
  combinations; the first 256 in varga order are used, which needs only 20 of the
  consonants. A
  bijection with a public table is an encoding. There is no key in
  :func:`encode`, and :func:`decode` needs no secret.
* :func:`confidentiality_report` therefore **measures** the thing the brief
  asserts. It encodes a sample, strips the decoration, and recovers the plaintext
  with no key — then reports the elapsed time and the fraction of bytes a naive
  frequency attack reads straight off the page.
* The Vedic accents (udātta, anudātta, svarita) are decorative: the decoder drops
  them. They change the rendering and nothing else.

So what is the layer *for*? Two real things, both modest:

1. **Domain separation.** The wrapped form is a distinct alphabet, so a Zeno
   payload accidentally pasted into a Sanskrit dataset (or vice versa) is obvious.
2. **Casual-observer filtering.** Text that is Devanagari with Vedic accent marks
   does not match the expectations of a scanner looking for ASCII protocol
   syntax. This is *not* a security control — it is a speed bump, and any
   attacker who can read this file has already flattened it.

    >>> from aegis.vajra.devanagari_wrapper import encode, decode
    >>> decode(encode(b"@LOC[TYO] -> ?WX"))[:16]
    b'@LOC[TYO] -> ?WX'
"""

from __future__ import annotations

import base64
import hashlib
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .paninian_grammar import ACCENTS, CONSONANTS, SIGNS, VOWELS

__all__ = [
    "encode",
    "decode",
    "wrap",
    "unwrap",
    "confidentiality_report",
    "Invocation",
    "DECORATION",
    "BLOCK_TABLE",
]

#: The syllables used as the final invocation. Decorative, and labelled so.
DECORATION: Dict[str, str] = {
    "prefix": "ॐ ह्रीं श्रीं क्लीं ऐं ॥",
    "suffix": "॥",
    "note": "display only: the decoder ignores it, and it carries no key material",
}


def _build_table() -> List[Tuple[str, str]]:
    """The fixed public table: the first 256 of 442 (consonant, matra) pairs.

    Ordering is documented and stable: consonants in the traditional varga order,
    then vowels by length. Anyone can reconstruct it from this list, which is the
    point of the honesty report.
    """
    consonants = [letter for _, letter in CONSONANTS.items()]  # varga (dictionary) order, stable
    consonants = list(dict.fromkeys(consonants))
    matras = [matra for _, matra in VOWELS.values()]
    matras = list(dict.fromkeys(matras))  # '' first: the implicit 'a'
    table: List[Tuple[str, str]] = []
    for consonant in consonants:
        for matra in matras:
            table.append((consonant, matra))
    return table[:256]


BLOCK_TABLE: List[Tuple[str, str]] = _build_table()
_REVERSE: Dict[str, int] = {
    consonant + matra: index for index, (consonant, matra) in enumerate(BLOCK_TABLE)
}

_ACCENT_CHARS = set(ACCENTS.values()) | {"\u0953", "\u0954", "\u1cdb"}


def _decorate(blocks: Sequence[str], *, seed: str = "") -> List[str]:
    """Add Vedic accents deterministically. Purely cosmetic; the decoder ignores them."""
    if not blocks:
        return []
    digest = hashlib.sha256(seed.encode("utf-8") or b"aegis/vajra/accents").digest()
    accents = [ACCENTS["udatta"], ACCENTS["anudatta"], ACCENTS["svarita"]]
    return [block + accents[digest[index % len(digest)] % 3] for index, block in enumerate(blocks)]


def encode(data: bytes, *, accents: bool = True, seed: str = "") -> str:
    """Bytes -> Devanagari block sequence. No key: this is an encoding."""
    blocks = [BLOCK_TABLE[byte][0] + BLOCK_TABLE[byte][1] for byte in data]
    if accents:
        blocks = _decorate(blocks, seed=seed)
    return "".join(blocks)


def decode(text: str) -> bytes:
    """Inverse of :func:`encode`. Ignores accents, whitespace and punctuation."""
    cleaned = "".join(
        character
        for character in text
        if character not in _ACCENT_CHARS and character not in SIGNS.values()
    )
    output = bytearray()
    index = 0
    while index < len(cleaned):
        # Try the longest block first: consonant + matra, or consonant alone.
        two = cleaned[index : index + 2]
        if len(two) == 2 and two in _REVERSE:
            output.append(_REVERSE[two])
            index += 2
            continue
        one = cleaned[index]
        if one in _REVERSE:
            output.append(_REVERSE[one])
            index += 1
            continue
        index += 1  # decoration, punctuation, or unmapped character
    return bytes(output)


def wrap(data: bytes, *, invocation: bool = True, accents: bool = True, seed: str = "") -> str:
    """The full final wrap described in the brief: invocation + blocks + ॥."""
    body = encode(data, accents=accents, seed=seed)
    if not invocation:
        return body
    return f"{DECORATION['prefix']} {body} {DECORATION['suffix']}"


def unwrap(text: str) -> bytes:
    """Strip the invocation and decode. Requires no key."""
    body = text
    if DECORATION["prefix"] in body:
        body = body.split(DECORATION["prefix"], 1)[1]
    if body.rstrip().endswith(DECORATION["suffix"]):
        body = body.rstrip()[: -len(DECORATION["suffix"])]
    return decode(body)


@dataclass(frozen=True)
class Invocation:
    """The decorative header, kept as data so it can be swapped or disabled."""

    prefix: str = DECORATION["prefix"]
    suffix: str = DECORATION["suffix"]

    def to_dict(self) -> Dict[str, Any]:
        return {"prefix": self.prefix, "suffix": self.suffix, **DECORATION}


def confidentiality_report(sample: bytes = b"@LOC[TYO] -> ?WX : { $WX.state == RAIN }") -> Dict[str, Any]:
    """Attack this layer, in public, and report the result.

    Three measurements, because "impossible to decode" is a measurable claim:

    ``recovered_without_key``
        the whole plaintext, decoded by this function with no secret at all.
    ``decode_ms``
        how long that took.
    ``frequency_attack_recovery``
        the fraction of bytes recovered by a frequency-ranking attack that knows
        nothing but the table — a crude proxy for how little the wrap hides.
    """
    wrapped = wrap(sample)
    started = time.perf_counter()
    recovered = unwrap(wrapped)
    elapsed_ms = (time.perf_counter() - started) * 1000.0

    # Frequency attack: count blocks, map the most common block to the most
    # common byte of English-ish protocol text, and see how much comes back.
    counts: Dict[str, int] = {}
    for index in range(len(sample)):
        block = BLOCK_TABLE[sample[index]][0] + BLOCK_TABLE[sample[index]][1]
        counts[block] = counts.get(block, 0) + 1
    ranked_blocks = sorted(counts, key=lambda block: (-counts[block], block))
    guess_table = {letter: index for index, letter in enumerate(b" etaoinshrdlu@[]$?!-_")}
    hits = 0
    for rank, block in enumerate(ranked_blocks):
        guessed = sorted(guess_table, key=lambda byte: guess_table[byte])[rank % len(guess_table)]
        actual = _REVERSE.get(block, -1)
        if actual == guessed:
            hits += 1
    denominator = max(1, len(set(sample)))

    return {
        "is_encryption": False,
        "requires_a_key": False,
        "recovered_without_key": recovered == sample,
        "decode_ms": round(elapsed_ms, 4),
        "accents_carried_information": False,
        "frequency_attack_recovery": round(hits / denominator, 3),
        "blocks_in_table": len(BLOCK_TABLE),
        "verdict": (
            "an encoding with a public table: it changes how a payload looks and where it "
            "belongs, and provides zero confidentiality"
        ),
        "do_not_claim": "impossible to decode without Sanskrit knowledge — this file decodes it",
    }
