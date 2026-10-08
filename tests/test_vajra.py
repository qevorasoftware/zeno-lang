"""Tests for the VAJRA layer.

The tests are written to hold the layer to the claims actually made, and to
*measure* the ones that are not: the encoding's confidentiality is tested by
breaking it, and the KDF's honesty is tested by showing that the bīja frequencies
contribute nothing.
"""

from __future__ import annotations

import json
import math
import time
from pathlib import Path

import pytest

from aegis.vajra import (
    IS_A_CIPHER,
    coverage,
    from_devanagari,
    gloss,
    load_dictionary,
    to_devanagari,
    vajra_report,
)
from aegis.vajra import chandas_binary as chandas
from aegis.vajra import devanagari_wrapper as wrapper
from aegis.vajra import nada_brahma_voice as voice
from aegis.vajra import paninian_grammar as grammar

SAMPLE = b"@LOC[TYO] -> ?WX : { $WX.state == RAIN }"


# ---------------------------------------------------------------------------
# The honesty contract
# ---------------------------------------------------------------------------
def test_vajra_says_it_is_not_a_cipher_everywhere_it_could_be_read():
    assert IS_A_CIPHER is False
    report = vajra_report()
    assert report["is_a_cipher"] is False
    assert report["provides_confidentiality"] is False
    assert "not achievable" in report["headline"]
    assert report["confidentiality_measurement"]["is_encryption"] is False
    assert report["chandas_measurement"]["is_encryption"] is False
    assert report["bija_provenance"]["entropy_contributed"] == 0


def test_the_wrap_can_be_broken_without_any_key_and_says_how_fast():
    measurement = wrapper.confidentiality_report(SAMPLE)
    assert measurement["recovered_without_key"] is True
    assert measurement["requires_a_key"] is False
    assert measurement["accents_carried_information"] is False
    assert "impossible to decode" in measurement["do_not_claim"]


def test_coverage_admits_how_little_of_the_grammar_is_implemented():
    covered = coverage()
    assert covered["fraction_implemented"] == f"{len(covered['implemented'])}/3959"
    assert len(covered["implemented"]) <= 15
    assert covered["not_a_grammar_engine"]


# ---------------------------------------------------------------------------
# Paninian grammar
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "iast",
    ["sthānam", "tokyo", "gacchati", "vajra", "śrī", "pṛcchati", "maunam", "kṣetra", "saṃskṛtam", "jñānam"],
)
def test_transliteration_round_trips(iast):
    assert from_devanagari(to_devanagari(iast)) == iast


def test_transliteration_produces_real_devanagari():
    assert to_devanagari("sthānam") == "स्थानम्"
    assert to_devanagari("vajra") == "वज्र"
    assert to_devanagari("oṃ") == "ओं"  # the analytic spelling; ॐ is the ligature


def test_every_lexicon_entry_matches_the_transliterator():
    """The dictionary cannot drift away from the code that renders it."""
    mismatches = [
        term["iast"]
        for term in load_dictionary()["terms"]
        if to_devanagari(term["iast"]) != term["devanagari"]
    ]
    assert mismatches == []


@pytest.mark.parametrize(
    "left,right,expected,sutra",
    [
        ("deva", "indra", "devendra", "6.1.87"),      # guṇa: a + i -> e
        ("nara", "aśva", "narāśva", "6.1.101"),      # savarṇa-dīrgha: a + a -> ā
        ("kavi", "indra", "kavīndra", "6.1.101"),    # i + i -> ī
        ("nadī", "amba", "nadyamba", "6.1.77"),      # yaṇ: ī + a -> y
        ("rāmaḥ", "tu", "rāmastu", "8.3.34"),        # visarga + t -> s
        ("rāmaḥ", "api", "rāmo'pi", "6.1.113"),      # aḥ + a -> o '
        ("tam", "maya", "taṃmaya", "8.3.23"),        # final m + consonant -> anusvāra
    ],
)
def test_sandhi_fires_the_right_sutra(left, right, expected, sutra):
    fired, warnings = [], []
    assert grammar.sandhi_join(left, right, sutras=fired, warnings=warnings) == expected
    assert sutra in fired
    assert warnings == []


def test_uncovered_junctions_are_flagged_not_guessed():
    """A partial grammar must refuse to invent a form."""
    fired, warnings = [], []
    joined = grammar.sandhi_join("rāmaḥ", "iti", sutras=fired, warnings=warnings)
    assert joined == "rāmaḥiti" and warnings and "outside the implemented sūtra subset" in warnings[0]

    # tad + maya is tanmaya (8.4.55), which this subset does not implement.
    fired, warnings = [], []
    joined = grammar.sandhi_join("tad", "maya", sutras=fired, warnings=warnings)
    assert joined == "tadmaya" and fired == [] and warnings
    assert "consonant-final" in warnings[0]

    # ...while an ordinary vowel-final junction needs no change and no warning
    fired, warnings = [], []
    assert grammar.sandhi_join("sthāna", "tva", sutras=fired, warnings=warnings) == "sthānatva"
    assert warnings == []


def test_samasa_builds_compounds_and_records_the_rules():
    compound = grammar.samasa(("rāja", "putra"), kind="tatpurusa")
    assert compound.surface == "rājaputra"
    assert compound.devanagari == "राजपुत्र"
    assert compound.to_dict()["type_meaning"]
    with pytest.raises(ValueError):
        grammar.samasa(("rāja",), kind="tatpurusa")
    with pytest.raises(ValueError):
        grammar.samasa(("rāja", "putra"), kind="not-a-compound")


def test_dictionary_entries_carry_confidence_and_glosses():
    entry = gloss("vajra")
    assert entry and entry["devanagari"] == "वज्र" and entry["confidence"] in {"high", "medium"}
    assert gloss("definitely-not-a-sanskrit-word") is None
    assert load_dictionary()["_meta"]["not_a_translation_engine"] is True


# ---------------------------------------------------------------------------
# Chandas
# ---------------------------------------------------------------------------
def test_prastara_and_nastam_agree_with_the_enumeration():
    assert chandas.prastara(3) == ["GGG", "GGL", "GLG", "GLL", "LGG", "LGL", "LLG", "LLL"]
    assert all(chandas.nastam(index, 4) == chandas.prastara(4)[index - 1] for index in range(1, 17))
    assert all(chandas.uddistam(chandas.nastam(index, 4)) == index for index in range(1, 17))


def test_nastam_rejects_positions_outside_the_prastara():
    with pytest.raises(ValueError):
        chandas.nastam(0, 3)
    with pytest.raises(ValueError):
        chandas.nastam(9, 3)


def test_meru_rows_are_binomial_and_sum_to_the_prastara_size():
    triangle = chandas.meru(7)
    for row, values in enumerate(triangle):
        assert values == [math.comb(row, index) for index in range(row + 1)]
        assert sum(values) == 2 ** row


def test_prosody_weighs_syllables_by_sound():
    # ā is long (guru); the conjunct cc in gacchati makes the first syllable guru
    assert chandas.weigh_aksaras("rāma") == [chandas.GURU, chandas.LAGHU]
    assert chandas.weigh_aksaras("gacchati")[0] == chandas.GURU
    assert chandas.weigh_aksaras("kavi") == [chandas.LAGHU, chandas.LAGHU]


def test_bits_and_patterns_map_both_ways():
    assert chandas.pattern_to_bits("GGL") == "110"
    assert chandas.bits_to_pattern("110") == "GGL"
    assert [chandas.pattern_to_bits(chandas.bits_to_pattern(bits)) for bits in ("0", "1", "0111")] == [
        "0",
        "1",
        "0111",
    ]


def test_chandas_encoding_round_trips_and_is_declared_reversible():
    encoded = chandas.encode_bytes(SAMPLE)
    assert chandas.decode_bytes(encoded) == SAMPLE
    measurement = chandas.confidentiality_report(SAMPLE)
    assert measurement["requires_a_key"] is False
    assert measurement["decoded_without_any_secret"] is True
    assert "read chandas_binary.py" in measurement["how_to_break"]


# ---------------------------------------------------------------------------
# Bija KDF
# ---------------------------------------------------------------------------
def test_bija_kdf_is_deterministic_and_domain_separated():
    first = derive_key = __import__("aegis.vajra.bija_mantra_keys", fromlist=["derive_key"]).derive_key
    assert first(b"passphrase", bijas=["om", "shrim"]) == first(b"passphrase", bijas=["om", "shrim"])
    assert first(b"passphrase", bijas=["om", "shrim"]) != first(b"passphrase", bijas=["om", "klim"])
    assert first(b"passphrase", bijas=["om"], iterations=2) != first(b"passphrase", bijas=["om"])


def test_bija_kdf_refuses_to_pretend_frequencies_are_a_secret():
    from aegis.vajra.bija_mantra_keys import derive_key, provenance_report

    with pytest.raises(ValueError):
        derive_key(b"")

    report = provenance_report()
    assert report["is_vedic"] is False
    assert report["entropy_contributed"] == 0
    assert report["would_still_work_if_frequencies_were_wrong"] is True
    assert "solfeggio" in json.dumps(report).lower()


def test_bija_salt_is_exact_integer_arithmetic():
    from aegis.vajra.bija_mantra_keys import BijaSet, frequency_ratio, salt_material

    assert salt_material(["om", "shrim"]) == salt_material(["om", "shrim"])
    assert salt_material(["om"]) != salt_material(["shrim"])
    assert frequency_ratio("om", "shrim").numerator == 1361  # 136100 / 100
    with pytest.raises(ValueError):
        salt_material(["not-a-bija"])
    with pytest.raises(ValueError):
        BijaSet(("om", "not-a-bija"))

    bija_set = BijaSet(("om", "shrim"))
    assert bija_set.devanagari == "ॐ श्रीं"
    assert bija_set.to_dict()["entropy_from_frequencies"] == 0


def test_resonance_pattern_is_labelled_display_only():
    from aegis.vajra.bija_mantra_keys import resonance_pattern

    pattern = resonance_pattern(["om", "shrim"])
    assert pattern["display_only"] is True
    assert set(pattern["bits"]) <= {"0", "1"}


# ---------------------------------------------------------------------------
# Devanagari wrapper
# ---------------------------------------------------------------------------
def test_wrapper_is_a_bijection_over_all_256_bytes():
    assert len(wrapper.BLOCK_TABLE) == 256
    assert all(wrapper.decode(wrapper.encode(bytes([byte]))) == bytes([byte]) for byte in range(256))


def test_wrapper_round_trips_with_and_without_decoration():
    assert wrapper.unwrap(wrapper.wrap(SAMPLE)) == SAMPLE
    assert wrapper.decode(wrapper.encode(SAMPLE)) == SAMPLE
    assert wrapper.wrap(SAMPLE).startswith(wrapper.DECORATION["prefix"])


def test_wrapper_is_not_load_bearing_for_confidentiality():
    """If this ever fails, someone has started treating the wrap as encryption."""
    wrapped = wrapper.wrap(SAMPLE)
    assert wrapper.unwrap(wrapped) == SAMPLE  # no key, no secret, no effort
    measurement = wrapper.confidentiality_report(SAMPLE)
    assert measurement["verdict"].startswith("an encoding with a public table")
    assert measurement["frequency_attack_recovery"] < 0.5  # nothing meaningful to learn


# ---------------------------------------------------------------------------
# Nada-Brahma voice
# ---------------------------------------------------------------------------
def test_fft_matches_a_direct_dft():
    samples = voice.tone(220.0, 512, sample_rate=8000)
    fast = [magnitude for _, magnitude in voice.freq_spectrum(samples, sample_rate=8000, window="none")]
    slow = [magnitude for _, magnitude in voice.dft_reference(samples, sample_rate=8000)]
    assert len(fast) == len(slow)
    assert max(abs(a - b) for a, b in zip(fast, slow)) < 1e-9


@pytest.mark.parametrize("frequency", [136.1, 220.0, 440.0, 1000.0])
def test_dominant_frequency_is_recovered(frequency):
    samples = voice.tone(frequency, 16000, sample_rate=16000)
    assert abs(voice.dominant_frequency(samples, sample_rate=16000) - frequency) < 3.0


def test_amplitude_is_not_shrunk_by_zero_padding():
    samples = voice.tone(220.0, 400, sample_rate=8000, amplitude=0.8)
    peak = max(magnitude for _, magnitude in voice.freq_spectrum(samples, sample_rate=8000, window="none"))
    assert 0.75 < peak < 0.85


def test_signature_separates_tones_and_ignores_window_sidelobes():
    reference = voice.analyse(voice.tone(220.0, 8000, sample_rate=8000), sample_rate=8000)
    assert reference.partials == pytest.approx([220.0], abs=5.0)

    stack = voice.analyse(voice.tone([220.0, 440.0, 660.0], 8000, sample_rate=8000), sample_rate=8000)
    assert len(stack.partials) == 3

    match = voice.verify(reference, voice.analyse(voice.tone(220.0, 8000, sample_rate=8000), sample_rate=8000))
    mismatch = voice.verify(reference, voice.analyse(voice.tone(330.0, 8000, sample_rate=8000), sample_rate=8000))
    assert match["scores"]["cosine"] > mismatch["scores"]["cosine"]


def test_voice_requires_liveness_and_says_why():
    reference = voice.analyse(voice.tone(220.0, 8000, sample_rate=8000), sample_rate=8000)
    replay = voice.analyse(voice.tone(220.0, 8000, sample_rate=8000), sample_rate=8000)
    refused = voice.verify(reference, replay)
    assert refused["ok"] is False
    assert any("recording" in note or "liveness" in note for note in refused["notes"])

    live = voice.analyse(voice.tone(220.0, 8000, sample_rate=8000), sample_rate=8000, liveness_checked=True)
    assert voice.verify(reference, live)["ok"] is True

    guidance = voice.liveness_guidance()
    assert set(guidance) >= {"replay", "clone", "coercion", "minimum"}
    assert "2791" in guidance["source"]


def test_wav_write_and_read_round_trip():
    samples = voice.tone(220.0, 400, sample_rate=8000)
    restored, sample_rate = voice.read_pcm_wav(voice.encode_wav(samples, sample_rate=8000))
    assert sample_rate == 8000 and len(restored) == 400
    assert abs(voice.dominant_frequency(restored, sample_rate=sample_rate) - 220.0) < 5.0
    with pytest.raises(ValueError):
        voice.read_pcm_wav(b"not a wav")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def test_cli_vajra_reports_honestly():
    import subprocess
    import sys

    completed = subprocess.run(
        [sys.executable, "-m", "aegis", "vajra", "@LOC[TYO] -> ?WX"],
        capture_output=True,
        text=True,
        cwd=str(Path(__file__).resolve().parents[1]),
    )
    assert completed.returncode == 0
    assert "unwrap       : @LOC[TYO] -> ?WX" in completed.stdout
    assert "is a cipher  : False" in completed.stdout

    payload = json.loads(
        subprocess.run(
            [sys.executable, "-m", "aegis", "vajra", "@LOC[TYO] -> ?WX", "--json"],
            capture_output=True,
            text=True,
            cwd=str(Path(__file__).resolve().parents[1]),
        ).stdout
    )
    assert payload["is_cipher"] is False
    assert payload["report"]["provides_confidentiality"] is False
