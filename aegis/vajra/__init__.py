"""VAJRA — layer 8 of AEGIS, and the honest version of it.

The brief calls this "the final impenetrable layer: an unbreakable Sanskrit
cipher". It is the final layer. It is not impenetrable, and it is not a cipher.
Here is exactly what it is, module by module:

===========================================  ==============================================
module                                       what it actually provides
===========================================  ==============================================
:mod:`~aegis.vajra.paninian_grammar`         Devanagari transliteration (exact, reversible)
                                             and 10 cited sandhi sūtras out of 3,959
:mod:`~aegis.vajra.chandas_binary`           Piṅgala's prastāra/naṣṭam/uddhiṣṭam and the
                                             meru, plus a real prosody analysis: a *binary
                                             encoding*, trivially invertible
:mod:`~aegis.vajra.bija_mantra_keys`         bīja frequencies used as **public salt** for a
                                             real scrypt KDF — the frequency adds zero
                                             entropy and the module proves that in code
:mod:`~aegis.vajra.devanagari_wrapper`       a 256-block bijection with a published table,
                                             with a function that measures how easily it
                                             falls to a keyless decode
:mod:`~aegis.vajra.nada_brahma_voice`        a real FFT voiceprint (verified against a
                                             direct DFT) with liveness caveats attached
===========================================  ==============================================

Why build it at all, if it is not encryption? Because the parts that are genuine
are genuinely useful: a reversible Devanagari alphabet for domain separation, a
correct implementation of Piṅgala's combinatorics, a spectral voiceprint, and a
KDF that uses the bīja constants in the one role where a public constant is
correct — as salt. What it must never be sold as is *confidentiality*: that comes
from :mod:`aegis.pqc_engine`, where the keys live.

``vajra_report()`` writes the whole picture down at runtime, so any consumer of
this package can read the limits without trusting a README.

    >>> from aegis.vajra import wrap, unwrap
    >>> unwrap(wrap(b"@LOC[TYO] -> ?WX"))[:16]
    b'@LOC[TYO] -> ?WX'
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from . import bija_mantra_keys, chandas_binary, devanagari_wrapper, nada_brahma_voice, paninian_grammar
from .bija_mantra_keys import BijaSet, derive_key, provenance_report, salt_material
from .chandas_binary import LAGHU, GURU, prastara, nastam, uddistam, meru, weigh_aksaras
from .devanagari_wrapper import decode, encode, unwrap, wrap
from .nada_brahma_voice import Signature, analyse, comparison, verify
from .paninian_grammar import coverage, from_devanagari, samasa, sandhi_join, to_devanagari

__all__ = [
    # submodules
    "paninian_grammar",
    "chandas_binary",
    "bija_mantra_keys",
    "nada_brahma_voice",
    "devanagari_wrapper",
    # grammar
    "to_devanagari",
    "from_devanagari",
    "sandhi_join",
    "samasa",
    "coverage",
    # chandas
    "LAGHU",
    "GURU",
    "prastara",
    "nastam",
    "uddistam",
    "meru",
    "weigh_aksaras",
    # keys
    "BijaSet",
    "derive_key",
    "salt_material",
    "provenance_report",
    # voice
    "Signature",
    "analyse",
    "comparison",
    "verify",
    # wrapper
    "encode",
    "decode",
    "wrap",
    "unwrap",
    # lexicon + reporting
    "load_dictionary",
    "gloss",
    "vajra_report",
    "DICTIONARY_PATH",
    "IS_A_CIPHER",
]

#: The single most important constant in this package.
IS_A_CIPHER = False

DICTIONARY_PATH = Path(__file__).with_name("sanskrit_dictionary.json")


@lru_cache(maxsize=1)
def load_dictionary() -> Dict[str, Any]:
    """The curated lexicon, loaded once. Braces the codec's vocabulary."""
    with DICTIONARY_PATH.open(encoding="utf-8") as handle:
        return json.load(handle)


def gloss(iast: str) -> Optional[Dict[str, Any]]:
    """Look up a term; ``None`` when it is not in the lexicon."""
    key = iast.strip().lower()
    for term in load_dictionary().get("terms", []):
        if term["iast"].lower() == key:
            return {
                "iast": term["iast"],
                "devanagari": term["devanagari"],
                "gloss": term["gloss"],
                "kind": term.get("kind", ""),
                "confidence": term.get("confidence", "medium"),
            }
    return None


def vajra_report() -> Dict[str, Any]:
    """Everything this layer claims, and everything it does not. Machine-readable."""
    return {
        "layer": "vajra",
        "position": "8 (final)",
        "is_a_cipher": False,
        "provides_confidentiality": False,
        "compression": False,
        "what_it_provides": [
            "a reversible Devanagari alphabet (domain separation, casual-observer filtering)",
            "Pingala's combinatorics: prastara, nastam, uddistam, meru",
            "a real prosody analysis producing laghu/guru weights from sound",
            "a real spectral voiceprint with liveness caveats",
            "a real scrypt KDF salted with the public bija constants",
        ],
        "what_it_does_not_provide": [
            "confidentiality: see aegis.pqc_engine for encryption",
            "integrity: see aegis.cipher for AEAD",
            "resistance to a reader of the source code",
            "any cryptographic advantage from the Sanskrit language itself",
        ],
        "grammar": coverage(),
        "confidentiality_measurement": devanagari_wrapper.confidentiality_report(),
        "chandas_measurement": chandas_binary.confidentiality_report(),
        "bija_provenance": provenance_report(),
        "voice_liveness": nada_brahma_voice.liveness_guidance(),
        "lexicon_terms": len(load_dictionary().get("terms", [])),
        "headline": (
            "VAJRA is an encoding, mnemonic and analysis layer. It is branded 'unbreakable' in "
            "the brief; that claim is not achievable and is not made here."
        ),
    }
