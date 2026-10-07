# VAJRA — the Sanskrit layer, honestly documented

**Status:** implemented · **Layer:** 8 (final) · **Code:** `aegis/vajra/` · **Tests:** `tests/test_vajra.py`

VAJRA is the last of AEGIS's eight layers, and the one with the most imaginative
brief: Paninian grammar, Chandas binary, bīja-mantra frequencies, a ॐ vocal
signature, and Devanagari Unicode obfuscation, together "unbreakable" and
"impossible to decode without Sanskrit linguistic knowledge".

The layer is built. The claim is false, and this document explains exactly why —
with measurements the code performs on itself.

---

## 1. The core problem

> *"Impossible to decode without Sanskrit linguistic knowledge."*

Rot13 is not breakable "without Latin knowledge". The Vigenère cipher was
unbroken for three centuries not because it used French but because it used a
**key**. Obfuscation always reduces to an encoding plus, at most, a secret.

VAJRA's wrap is a **bijection over bytes with a published table**:
33 consonants × 8 vowel signs = 264 blocks, of which 256 are used. The decoder in
`devanagari_wrapper.py` is twelve lines and needs no secret. Nothing about the
Sanskrit language makes the table harder to read: it is in the file.

So the layer is shipped as an **encoding and analysis toolkit**, with the
confidentiality it does not have measured by its own code:

```python
>>> from aegis.vajra.devanagari_wrapper import confidentiality_report
>>> confidentiality_report(b"@LOC[TYO] -> ?WX")
{'is_encryption': False, 'requires_a_key': False, 'recovered_without_key': True,
 'decode_ms': 0.0381, 'accents_carried_information': False,
 'frequency_attack_recovery': 0.036, 'blocks_in_table': 256,
 'verdict': 'an encoding with a public table: ... provides zero confidentiality',
 'do_not_claim': 'impossible to decode without Sanskrit knowledge — this file decodes it'}
```

`tests/test_vajra.py` asserts `recovered_without_key is True`. If someone later
starts treating the wrap as encryption, that test fails.

---

## 2. What each module actually implements

### 2.1 `paninian_grammar.py` — transliteration and 10 sūtras

- **IAST ⇄ Devanagari transliteration**, complete for the Sanskrit inventory
  (vowels, matras, `virama`, anusvāra, visarga, Vedic accents). Exact round trip,
  asserted per sample in the tests, and re-asserted against all 33 lexicon entries
  so the dictionary cannot drift from the renderer.
- **Sandhi**, citing sūtra numbers, in `IMPLEMENTED_SUTRAS`:

  | Sūtra | Name | Junction |
  |---|---|---|
  | 6.1.101 | akaḥ savarṇe dīrghaḥ | `nara + aśva → narāśva` |
  | 6.1.87 | ād guṇaḥ | `deva + indra → devendra` |
  | 6.1.88 | vṛddhir eci | `a/ā + e/ai/o/au → ai/au` |
  | 6.1.77 | iko yaṇ aci | `nadī + amba → nadyamba` |
  | 6.1.78 | eco 'yavāyāvaḥ | `e/o + vowel → ay/av` |
  | 6.1.109 | eṅaḥ padāntād ati | elision after word-final e/o |
  | 6.1.113 | ato ror aplutād aplute | `rāmaḥ + api → rāmo 'pi` |
  | 8.3.15 | kharavasānayor visarjanīyaḥ | word-final s/ḥ before a pause |
  | 8.3.34 | visarjanīyasya saḥ | `rāmaḥ + tu → rāmastu` |
  | 8.3.23 | mo 'nusvāraḥ | `tam + maya → taṃmaya` |

  **10 of the 3,959 sūtras in the Aṣṭādhyāyī.** `coverage()` reports this number
  at runtime. Junctions outside the subset — `tad + maya` (which is *tanmaya* by
  8.4.55) and `rāmaḥ + iti` — are returned **unchanged and flagged in a
  `warnings` list**. A partial grammar that invents a plausible form is worse than
  one that says "I do not implement this", and the tests enforce both behaviours.
- **Samāsa** with the four classical labels plus `avyayibhava`, each carrying the
  question it answers, and reversibility via `sandhi_split` — which returns *all*
  plausible splits, because sandhi is genuinely ambiguous. Nothing cryptographic
  rests on it.

### 2.2 `chandas_binary.py` — Piṅgala, implemented for real

Piṅgala's *Chandaḥśāstra* treats each syllable as **laghu (0)** or **guru (1)**:
a binary alphabet around two millennia before Leibniz. Implemented and tested
against closed-form mathematics:

- `prastara(k)` — all 2ᵏ patterns for k syllables, in the traditional all-guru-first order;
- `nastam(index, k)` — the classic halving algorithm that recovers a pattern from its position;
- `uddistam(pattern)` — its exact inverse (asserted for every pattern up to k = 4);
- `meru(rows)` — the binomial triangle, checked against `math.comb`, with row sums equal to 2ᵏ;
- `weigh_aksaras(line)` — **real prosody**: a long vowel, a conjunct after a short vowel, or a following anusvāra/visarga makes a syllable guru.

Then the honest part, again measured rather than asserted: `confidentiality_report()`
encodes a sample, strips the decoration, decodes it with no key, and reports the
time taken. It requires no key because it is a fixed, published mapping.

### 2.3 `bija_mantra_keys.py` — frequencies used in the one role where public constants are correct

**A frequency is not a secret.** 136.1 Hz is in every book on the subject and
identical for every deployment on Earth. Used as the brief describes — "ॐ + श्रीं
hash" — it adds **zero entropy**, and an attacker who knows the scheme knows the
frequency.

So the module does the sound thing and states which half is which:

- Frequencies are stored as **exact integer milli-hertz** (no floats: a KDF must
  not depend on platform arithmetic), and composed as exact
  `fractions.Fraction` ratios.
- They are used as **public salt / domain separation** inside **scrypt**, together
  with a caller-supplied secret. `derive_key(b"")` raises: the frequencies alone
  protect nothing and the code refuses to pretend otherwise.
- `provenance_report()` records what the numbers actually are: the mantras are
  ancient, most of the numbers are 20th-century "solfeggio" attributions, and the
  module would work exactly as well if every frequency were wrong. The tests
  assert `entropy_contributed == 0`.

### 2.4 `nada_brahma_voice.py` — a real spectrum, with the biometric caveats attached

- A **radix-2 Cooley–Tukey FFT** in ~20 lines, verified against a direct O(N²) DFT
  to < 1e-14, with Hann windowing, zero-padding compensation, parabolic peak
  interpolation, log-spaced band energies, and a WAV reader/writer.
- `analyse()` returns dominant frequency, spectral centroid and the strongest
  partials. Peak-picking carries a −40 dB floor, because without it Hann sidelobes
  are reported as harmonics that are not in the signal (a bug this project hit and
  fixed).
- **`verify()` refuses by default.** A recording defeats spectral matching, so
  unless the capture path marks the sample `liveness_checked`, verification fails
  with the reason attached. `liveness_guidance()` lists what an anti-spoofing path
  must cover (challenge phrase, channel detection, lockout) and cites IEEE
  2791-2020, which classifies voice as *possibly secret*: coerceable, cloneable,
  and replayable. A voiceprint is one factor, never the factor that releases a key.
- **No librosa.** It is not installed, and a security layer should not need a
  numerical stack to produce a number. If librosa is present it could be used as a
  cross-check; the FFT here is verified against mathematics instead.

### 2.5 `devanagari_wrapper.py` — the wrap, and its own attack

- `encode`/`decode`/`wrap`/`unwrap`: a 256-block bijection with a **documented,
  reconstructible table**; the Vedic accents are decorative and the decoder drops
  them (`accents_carried_information: False`).
- `confidentiality_report()` performs a keyless decode and a frequency-ranking
  attack, and reports a verdict that says the layer provides zero confidentiality.

What the wrap *is* good for, stated narrowly: **domain separation** (a Zeno payload
pasted into a Sanskrit corpus, or vice versa, is obvious) and **casual-observer
filtering** (Devanagari with Vedic accents does not match a scanner's idea of
ASCII protocol syntax). Both are conveniences. Neither is a security control.

---

## 3. What the layer does and does not claim

**Does:** exact transliteration; 10 cited sandhi rules with explicit gaps;
Piṅgala's combinatorics verified against closed forms; real prosody; a real FFT
voiceprint verified against a DFT; a scrypt KDF that uses public constants in
their correct role; and a decode-without-key measurement of its own wrap.

**Does not:** provide confidentiality, integrity, compression, or any advantage
from the Sanskrit language itself; resist a reader of the source; stop a receiver
who holds the rotation key; or make a voiceprint sufficient on its own.

`vajra_report()` returns all of this as data, including
`is_a_cipher: False` and `provides_confidentiality: False`, and
`tests/test_vajra.py` opens with `assert IS_A_CIPHER is False`.

---

## 4. Why build it at all

Because four fifths of it is genuine: a correct transliteration engine, a correct
implementation of Piṅgala's algorithms, a correct prosody analyser, a correct FFT,
and a correctly-used KDF are real work with real uses — as a protocol alphabet, a
mnemonic system, an analysis toolkit, and a domain separator. The brief's framing
wrapped them in a promise mathematics cannot keep. The code keeps the parts that
are true and says so about the rest.

The layer that actually protects a Zeno payload is layer 1, and its guarantees are
in `specs/aegis_security.md`.
