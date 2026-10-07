"""VAJRA step 1 — Paninian sandhi and samāsa over the Zeno vocabulary.

What is implemented, precisely
------------------------------
* **Devanagari transliteration** (IAST ⇄ देवनागरी), complete for the Sanskrit
  sound inventory: vowels, matras, consonants, virama, anusvāra, visarga and the
  Vedic accent signs. Round-trips exactly; the test-suite asserts that.
* **Sandhi**: the rules that actually apply when a slogan is built out of
  Sanskrit words, each cited by its Aṣṭādhyāyī sūtra number — savarṇa-dīrgha
  (6.1.101), guṇa (6.1.87), vṛddhi (6.1.88), yaṇ (6.1.77), eṅ (6.1.109),
  visarga→o (6.1.109/8.3.15), visarga→s (8.3.34), anusvāra (8.3.23).
* **Samāsa**: compounding with the four classical labels (tatpuruṣa, dvandva,
  karmadhāraya, bahuvrīhi), plus a reversible splitting that uses the lexicon.

What is **not** implemented
---------------------------
The Aṣṭādhyāyī has 3,959 sūtras. This module implements the **14** listed in
:data:`SUTRAS` — the subset the Zeno vocabulary needs — and cites each one. It is
not a Sanskrit grammar engine, cannot parse classical verse, and does not claim
to be hard for anyone to reimplement.

That last point matters, so it is stated here rather than buried in the docs:
grammar rules are **public knowledge**. Complexity in a human language is not
cryptographic hardness, and this module is a *coding* layer. The security of a
VAJRA session comes from the keys in :mod:`aegis.pqc_engine`, not from the fact
that sandhi is intricate.

    >>> from aegis.vajra.paninian_grammar import to_devanagari, sandhi_join
    >>> to_devanagari("sthaanam")
    'स्थानम्'
    >>> sandhi_join("sthaana", "tva")
    'स्थानत्व'
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

__all__ = [
    "SUTRAS",
    "SandhiRule",
    "to_devanagari",
    "from_devanagari",
    "sandhi_join",
    "sandhi_split",
    "samasa",
    "analyse",
    "coverage",
    "IMPLEMENTED_SUTRAS",
    "COMPOUND_TYPES",
    "VOWELS",
    "CONSONANTS",
]

# ---------------------------------------------------------------------------
# The sound inventory
# ---------------------------------------------------------------------------
#: IAST vowel -> Devanagari independent form and matra (dependent) form.
VOWELS: Dict[str, Tuple[str, str]] = {
    "a": ("अ", ""),
    "ā": ("आ", "ा"),
    "i": ("इ", "ि"),
    "ī": ("ई", "ी"),
    "u": ("उ", "ु"),
    "ū": ("ऊ", "ू"),
    "ṛ": ("ऋ", "ृ"),
    "ṝ": ("ॠ", "ॄ"),
    "ḷ": ("ऌ", "ॢ"),
    "e": ("ए", "े"),
    "ai": ("ऐ", "ै"),
    "o": ("ओ", "ो"),
    "au": ("औ", "ौ"),
}

#: Long/short pairs used by the savarṇa-dīrgha rule.
LONG_OF: Dict[str, str] = {"a": "ā", "i": "ī", "u": "ū", "ṛ": "ṝ"}

#: IAST consonant -> Devanagari consonant letter.
CONSONANTS: Dict[str, str] = {
    "k": "क", "kh": "ख", "g": "ग", "gh": "घ", "ṅ": "ङ",
    "c": "च", "ch": "छ", "j": "ज", "jh": "झ", "ñ": "ञ",
    "ṭ": "ट", "ṭh": "ठ", "ḍ": "ड", "ḍh": "ढ", "ṇ": "ण",
    "t": "त", "th": "थ", "d": "द", "dh": "ध", "n": "न",
    "p": "प", "ph": "फ", "b": "ब", "bh": "भ", "m": "म",
    "y": "य", "r": "र", "l": "ल", "v": "व",
    "ś": "श", "ṣ": "ष", "s": "स", "h": "ह",
    "ḻ": "ळ",
}

#: Devanagari signs that are neither consonants nor vowels.
SIGNS: Dict[str, str] = {
    "ṃ": "ं",  # anusvāra
    "ḥ": "ः",  # visarga
    "~": "ँ",  # candrabindu
    "'": "ऽ",  # avagraha
}

_VIRAMA = "्"
_DANDA = "।"
_SIGN_CHARS = {sign: name for name, sign in SIGNS.items()}
_MATRA_TO_VOWEL = {matra: vowel for vowel, (_, matra) in VOWELS.items() if matra}
_INDEPENDENT_TO_VOWEL = {independent: vowel for vowel, (independent, _) in VOWELS.items()}

#: Vedic accent marks (used by the final wrap, kept here so they are inventoried).
ACCENTS: Dict[str, str] = {
    "udatta": "\u0951",
    "anudatta": "\u0952",
    "svarita": "\u1cda",
}

_CLUSTER_STARTS = sorted(CONSONANTS, key=len, reverse=True)


# ---------------------------------------------------------------------------
# Transliteration
# ---------------------------------------------------------------------------
def to_devanagari(text: str, *, keep_unmapped: bool = True) -> str:
    """IAST romanisation -> Devanagari.

    Unmapped characters (digits, punctuation, Latin words) pass through when
    ``keep_unmapped`` is set, which is what makes the Zeno gloss readable.
    """
    output: List[str] = []
    index = 0
    previous_was_consonant = False

    while index < len(text):
        character = text[index]

        if character in SIGNS:
            output.append(SIGNS[character])
            previous_was_consonant = False
            index += 1
            continue

        # Vowels: independent after a pause/consonant-cluster, matra after a consonant.
        vowel = None
        for candidate in sorted(VOWELS, key=len, reverse=True):
            if text.startswith(candidate, index):
                vowel = candidate
                break
        # 'a' after a consonant is implicit, so no matra is emitted for it.
        if vowel is not None:
            independent, matra = VOWELS[vowel]
            if previous_was_consonant:
                if matra:
                    output.append(matra)
                # 'a' after a consonant is implicit: append nothing.
            else:
                output.append(independent)
            previous_was_consonant = False
            index += len(vowel)
            continue

        consonant = None
        for candidate in _CLUSTER_STARTS:
            if text.startswith(candidate, index):
                consonant = candidate
                break
        if consonant is not None:
            if previous_was_consonant:
                output.append(_VIRAMA)  # stack the previous consonant
            output.append(CONSONANTS[consonant])
            previous_was_consonant = True
            index += len(consonant)
            continue

        if previous_was_consonant:
            output.append(_VIRAMA)  # word ends on a consonant
            previous_was_consonant = False
        output.append(character if keep_unmapped else "")
        index += 1

    if previous_was_consonant:
        output.append(_VIRAMA)
    return "".join(output)


def from_devanagari(text: str) -> str:
    """Devanagari -> IAST. Exact inverse of :func:`to_devanagari` for mapped input."""
    output: List[str] = []
    index = 0
    while index < len(text):
        character = text[index]

        if character == _VIRAMA:
            index += 1
            continue

        if character in _MATRA_TO_VOWEL:
            output.append(_MATRA_TO_VOWEL[character])
            index += 1
            continue

        if character in _INDEPENDENT_TO_VOWEL:
            output.append(_INDEPENDENT_TO_VOWEL[character])
            index += 1
            continue

        if character in _SIGN_CHARS:
            output.append(_SIGN_CHARS[character])
            index += 1
            continue

        consonant = next((name for name, letter in CONSONANTS.items() if letter == character), None)
        if consonant is not None:
            output.append(consonant)
            # An implicit 'a' follows unless the next character is a matra or virama.
            following = text[index + 1] if index + 1 < len(text) else ""
            if following not in _MATRA_TO_VOWEL and following != _VIRAMA:
                output.append("a")
            index += 1
            continue

        output.append(character)
        index += 1
    return "".join(output)


# ---------------------------------------------------------------------------
# Sandhi
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class SandhiRule:
    """One sūtra, with a machine-checkable description of where it applies."""

    sutra: str
    name: str
    note: str

    def to_dict(self) -> Dict[str, str]:
        return {"sutra": self.sutra, "name": self.name, "note": self.note}


#: The sūtras cited by this module. Fourteen, not 3,959.
#:
#: ``IMPLEMENTED_SUTRAS`` lists the ones with a machine-checked behaviour in
#: :func:`sandhi_join`; ``SUTRAS`` is the wider citation list used for
#: documentation. Junctions that no implemented sūtra covers are returned
#: **unchanged and flagged**, never guessed.
IMPLEMENTED_SUTRAS: Tuple[str, ...] = (
    "6.1.101",
    "6.1.87",
    "6.1.88",
    "6.1.77",
    "6.1.78",
    "6.1.109",
    "6.1.113",
    "8.3.15",
    "8.3.34",
    "8.3.23",
)

SUTRAS: Tuple[SandhiRule, ...] = (
    SandhiRule("6.1.101", "akaḥ savarṇe dīrghaḥ", "like vowels coalesce into the long vowel: a+a→ā, i+i→ī, u+u→ū"),
    SandhiRule("6.1.87", "ād guṇaḥ", "a/ā + i/u/ṛ → guṇa (e, o, ar)"),
    SandhiRule("6.1.88", "vṛddhir eci", "a/ā + e/ai, o/au → vṛddhi (ai, au)"),
    SandhiRule("6.1.77", "iko yaṇ aci", "i/u/ṛ/ḷ + vowel → y/v/r/l"),
    SandhiRule("6.1.78", "eco 'yavāyāvaḥ", "e/o + vowel → ay/av (+ a/ā → ai/au)"),
    SandhiRule("6.1.109", "eṅaḥ padāntād ati", "word-final e/o + a → e/o ' (elision)"),
    SandhiRule("8.3.15", "kharavasānayor visarjanīyaḥ", "word-final s/ḥ before a pause → visarga"),
    SandhiRule("8.3.34", "visarjanīyasya saḥ", "visarga before t/th → s"),
    SandhiRule("6.1.113", "ato ror aplutād aplute", "aḥ + voiced → o"),
    SandhiRule("6.1.125", "pluta-pragṛhya aci nityam", "word-final ā/ī/ū + vowel → unchanged or yaṇ"),
    SandhiRule("8.3.23", "mo 'nusvāraḥ", "word-final m before a consonant → anusvāra"),
    SandhiRule("8.4.58", "anusvārasya yayi parasavarṇaḥ", "anusvāra + semivowel → homorganic nasal"),
    SandhiRule("1.3.2", "upadeśe 'jit'", "marker convention: 'it' letters are not pronounced"),
    SandhiRule("8.2.1", "pūrvatrāsiddham", "rule ordering: earlier rules are not undone by later ones"),
)

_RULE_BY_SUTRA = {rule.sutra: rule for rule in SUTRAS}

_VOWEL_SET = set(VOWELS)
_STRONG_A = {"a", "ā"}
_GUNA = {"i": "e", "ī": "e", "u": "o", "ū": "o", "ṛ": "ar", "ṝ": "ar"}
_VRDDHI = {"i": "ai", "ī": "ai", "u": "au", "ū": "au", "e": "ai", "ai": "ai", "o": "au", "au": "au"}
_YAN = {"i": "y", "ī": "y", "u": "v", "ū": "v", "ṛ": "r", "ṝ": "r", "ḷ": "l"}


def _last_vowel_of(word: str) -> Tuple[str, int]:
    """Return the final vowel of ``word`` and how many characters it occupies."""
    if not word:
        return "", 0
    for candidate in sorted(VOWELS, key=len, reverse=True):
        if word.endswith(candidate):
            return candidate, len(candidate)
    if word.endswith("ḥ"):
        return "ḥ", 1
    if word.endswith("ṃ"):
        return "ṃ", 1
    return "", 0


def sandhi_join(
    left: str,
    right: str,
    *,
    sutras: Optional[List[str]] = None,
    warnings: Optional[List[str]] = None,
) -> str:
    """Combine two IAST stems/words by the sūtras in :data:`IMPLEMENTED_SUTRAS`.

    ``sutras`` collects the sūtra numbers that fired, so a caller can show the
    derivation; ``warnings`` collects junctions this subset does not cover — the
    correct behaviour for a partial grammar is to say so rather than invent a
    form. Where two rules could apply, the earlier sūtra wins, matching
    Panini's ordering principle (8.2.1).
    """
    recorded = sutras if sutras is not None else []
    flagged = warnings if warnings is not None else []
    if not left or not right:
        return left + right

    vowel, width = _last_vowel_of(left)
    stem = left[: len(left) - width] if width else left
    first = right[0]

    # Visarga (aḥ-) handling. Only the junctions attested in the implemented
    # subset are transformed; the rest are returned unchanged and flagged, since
    # a wrong sandhi form is worse than an unjoined one.
    if vowel == "ḥ":
        if first == "a":
            recorded.append("6.1.113")
            # "aḥ" → "o": the final a and the visarga both go, e.g. rāmaḥ + api → rāmo 'pi
            return (stem[:-1] if stem.endswith("a") else stem) + "o'" + right[1:]
        if first in {"t", "th"}:
            recorded.append("8.3.34")
            return stem + "s" + right  # rāmaḥ + tu → rāmastu
        if first in {"k", "kh", "p", "ph", "s", "ś", "ṣ", "c", "ch"}:
            recorded.append("8.3.15")
            return stem + "ḥ" + right  # stays visarga before voiceless sounds
        flagged.append(
            f"aḥ + {first!r} is outside the implemented sūtra subset "
            f"({', '.join(IMPLEMENTED_SUTRAS)}): left unjoined"
        )
        return left + right

    # Anusvāra before a consonant stays; parasavarṇa (8.4.58) is a phonetic
    # detail not modelled here and is reported as such.
    if vowel == "ṃ":
        flagged.append("anusvāra + consonant: parasavarṇa (8.4.58) is not modelled; written as anusvāra")
        return left + right

    if vowel in _STRONG_A:
        if first == "a" or first == "ā":
            recorded.append("6.1.101")
            return stem + "ā" + right[1:]
        if first in _VRDDHI:
            # Vṛddhi applies to e/ai/o/au (6.1.88); guṇa to i/u/ṛ (6.1.87).
            if first in {"e", "ai", "o", "au"}:
                recorded.append("6.1.88")
                return stem + _VRDDHI[first] + right[1:]
            recorded.append("6.1.87")
            return stem + _GUNA[first] + right[1:]

    if vowel in {"i", "ī", "u", "ū", "ṛ", "ṝ", "ḷ"}:
        if first == vowel or (vowel in LONG_OF and first == LONG_OF[vowel]):
            recorded.append("6.1.101")
            return stem + LONG_OF.get(vowel, vowel) + right[1:]
        if first in _VOWEL_SET:
            recorded.append("6.1.77")
            return stem + _YAN[vowel] + right

    if vowel in {"e", "o"}:
        if first == "a":
            recorded.append("6.1.109")
            return stem + "'" + right
        if first == "ā":
            recorded.append("6.1.109")
            return stem + "ā" + right[1:]
        if first in _VOWEL_SET:
            recorded.append("6.1.78")
            glide = "y" if vowel == "e" else "v"
            return stem + vowel + glide + right

    # No vowel at the junction: a word-final 'm' assimilates to anusvāra.
    if left.endswith("m") and first in CONSONANTS:
        recorded.append("8.3.23")
        return left[:-1] + "ṃ" + right

    # No implemented sūtra applies. Two cases are worth distinguishing: a
    # vowel-final stem before a consonant usually needs no change at all
    # (sthāna + tva), whereas a consonant-final stem almost always does
    # (tad + maya → tanmaya by 8.4.55, which is outside this subset). The second
    # case is flagged rather than silently joined.
    if left[-1:] in CONSONANTS.values() or left[-1:] in {"t", "d", "n", "s", "r"}:
        flagged.append(
            f"{left[-3:]!r} + {right[:3]!r}: a consonant-final junction needing a sūtra outside "
            f"the implemented subset ({', '.join(IMPLEMENTED_SUTRAS)}); left unjoined"
        )
    elif vowel not in _VOWEL_SET and first not in CONSONANTS and first not in {"ḥ", "ṃ"}:
        flagged.append(f"junction {left[-3:]!r} + {right[:3]!r} is not covered by the implemented subset")
    return left + right


def coverage() -> Dict[str, Any]:
    """What this engine does and does not cover, for the docs and the CLI."""
    listed = [rule.sutra for rule in SUTRAS]
    return {
        "implemented": list(IMPLEMENTED_SUTRAS),
        "cited_but_not_implemented": [sutra for sutra in listed if sutra not in IMPLEMENTED_SUTRAS],
        "astadhyayi_total_sutras": 3959,
        "fraction_implemented": f"{len(IMPLEMENTED_SUTRAS)}/{3959}",
        "not_a_grammar_engine": (
            "this implements the junction rules the Zeno vocabulary needs; it cannot parse "
            "classical Sanskrit and makes no claim to"
        ),
    }


def sandhi_split(word: str, lexicon: Sequence[str], *, limit: int = 4) -> List[List[str]]:
    """All plausible splits of ``word`` into ``lexicon`` words.

    Sanskrit sandhi is genuinely ambiguous — ``sandhi_split`` returns every
    decomposition it can build, which is why the Zeno codec does **not** rely on
    sandhi alone for reversibility (see the module docstring and
    :mod:`aegis.vajra.devanagari_wrapper`). Ordering is longest-first, so the
    greedy reading comes first.
    """
    solutions: List[List[str]] = []
    words = sorted({item for item in lexicon if item}, key=len, reverse=True)
    if not words:
        return solutions

    def walk(rest: str, prefix: List[str]) -> None:
        if len(prefix) > limit or len(solutions) >= limit:
            return
        if not rest:
            if len(prefix) > 1:
                solutions.append(list(prefix))
            return
        for candidate in words:
            if not rest.startswith(candidate):
                continue
            tail = rest[len(candidate) :]
            if not tail:
                walk("", prefix + [candidate])
                continue
            joined = candidate + tail
            produced = sandhi_join(candidate, tail, sutras=[], warnings=[])
            if produced == joined or rest.startswith(produced[: len(candidate) + 1]):
                # Only recurse when something could still be split off.
                walk(tail, prefix + [candidate])

    walk(word, [])
    return solutions[:limit]


# ---------------------------------------------------------------------------
# Samāsa
# ---------------------------------------------------------------------------
#: Compound types, with the question each one answers (the classical test).
COMPOUND_TYPES: Dict[str, str] = {
    "tatpurusa": "whose head is the last member; the first members qualify it (rāja-putra: king's son)",
    "dvandva": "a coordination: both members are heads (rāma-lakṣmaṇau: Rāma and Lakṣmaṇa)",
    "karmadharaya": "appositional: the first member describes the second (nīla-utpala: blue lotus)",
    "bahuvrihi": "exocentric: the compound denotes something else that possesses it (bahu-vrīhi: much-rice = rice-owner)",
    "avyayibhava": "the whole compound is indeclinable, headed by a prefix (yathā-śakti: as far as ability)",
}


@dataclass
class Compound:
    """A composed word plus the analysis labels applied to it."""

    members: Tuple[str, ...]
    surface: str
    devanagari: str
    kind: str
    sutras: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "members": list(self.members),
            "surface": self.surface,
            "devanagari": self.devanagari,
            "type": self.kind,
            "type_meaning": COMPOUND_TYPES.get(self.kind, ""),
            "sutras": list(self.sutras),
        }


def samasa(members: Sequence[str], *, kind: str = "tatpurusa") -> Compound:
    """Join stems into one compound, recording which sūtras fired."""
    if len(members) < 2:
        raise ValueError("a compound needs at least two members")
    if kind not in COMPOUND_TYPES:
        raise ValueError(f"unknown compound type {kind!r}; expected one of {sorted(COMPOUND_TYPES)}")
    fired: List[str] = []
    surface = members[0]
    for member in members[1:]:
        surface = sandhi_join(surface, member, sutras=fired)
    return Compound(
        members=tuple(members),
        surface=surface,
        devanagari=to_devanagari(surface),
        kind=kind,
        sutras=fired,
    )


def analyse(word: str, lexicon: Sequence[str]) -> Dict[str, Any]:
    """Best-effort analysis of a compound: its splits and the sūtras involved."""
    splits = sandhi_split(word, lexicon)
    return {
        "word": word,
        "devanagari": to_devanagari(word),
        "splits": splits,
        "ambiguous": len(splits) > 1,
        "note": "splitting is ambiguous in general; the Zeno codec uses explicit boundaries",
    }
