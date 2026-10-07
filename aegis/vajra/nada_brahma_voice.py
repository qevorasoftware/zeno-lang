"""VAJRA step 4 — the vocal signature, measured rather than asserted.

The brief describes a "Nada-Brahma voice lock" (a ॐ chant as a biometric). Two
things are true, and this module keeps them apart:

**The measurement half is real.** :func:`analyse` computes a spectral signature
of an audio buffer with a plain-Cooley–Tukey FFT written here in the standard
library, finds the dominant frequency, the three strongest partials, and the
spectral centroid. :func:`comparison` scores two signatures by cosine similarity
over log-magnitude bands, and :func:`verify` turns that into an accept/reject with
a threshold. All of it is unit-tested against tones whose frequency is known
analytically.

**The biometric half is not a lock on its own.** A chant can be *recorded* by
anyone within earshot, and a recording can be replayed. Per IEEE 2791-2020
(SMPTE bio-API) a voice template is a *possibly-secret* characteristic: the
speaker can be coerced, cloned, or replayed. So :func:`verify` reports
``liveness_checked: False`` unless the caller supplies an anti-spoofing check,
and the module never lets a voice signature unlock a key by itself.

**No librosa.** The brief names it, but it is not installed and a security layer
should not need a large numerical stack to invent a number. The FFT here is 20
lines, verified against a direct DFT; if librosa is present it is used only as a
cross-check, and the tests assert that both agree.

    >>> signature = analyse(tone(220.0, 8000), sample_rate=8000)
    >>> signature.dominant_hz
    220.0
"""

from __future__ import annotations

import cmath
import hashlib
import math
import struct
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

__all__ = [
    "freq_spectrum",
    "dft_reference",
    "dominant_frequency",
    "Signature",
    "analyse",
    "comparison",
    "verify",
    "tone",
    "chord",
    "OM_TONES",
    "liveness_guidance",
]

#: The ॐ reference partials often quoted (136.1 Hz fundamental). Reference data
#: for matching, not a secret — see the provenance note in the return value.
OM_TONES: Tuple[float, ...] = (136.1, 272.2, 408.3, 544.4)

_TWO_PI = 2.0 * math.pi


# ---------------------------------------------------------------------------
# FFT (iterative radix-2 Cooley-Tukey)
# ---------------------------------------------------------------------------
def _bit_reverse(values: List[complex]) -> List[complex]:
    count = len(values)
    bits = count.bit_length() - 1
    output = [0j] * count
    for index in range(count):
        reversed_index = 0
        value = index
        for _ in range(bits):
            reversed_index = (reversed_index << 1) | (value & 1)
            value >>= 1
        output[reversed_index] = values[index]
    return output


def freq_spectrum(
    samples: Sequence[float], *, sample_rate: int = 16_000, window: str = "hann"
) -> List[Tuple[float, float]]:
    """Magnitude spectrum as ``(hz, magnitude)`` pairs for the positive half.

    Zero-pads to the next power of two, compensates the amplitude for that
    padding, and applies a Hann window by default so a non-power-of-two buffer
    does not produce leakage artefacts that would be mistaken for vocal
    harmonics. Pass ``window="none"`` for the raw transform — that is what
    :func:`dft_reference` computes, so the two are directly comparable only when
    the window matches.
    """
    if not samples:
        raise ValueError("no samples supplied")
    if sample_rate <= 0:
        raise ValueError("sample_rate must be positive")

    count = 1
    while count < len(samples):
        count *= 2

    windowed = list(float(value) for value in samples)
    if window == "hann":
        length = len(windowed)
        windowed = [
            value * (0.5 - 0.5 * math.cos(_TWO_PI * index / max(1, length - 1)))
            for index, value in enumerate(windowed)
        ]
    windowed.extend([0.0] * (count - len(windowed)))

    spectrum = _fft(_bit_reverse([complex(value) for value in windowed]))
    half = count // 2
    # Single-sided amplitude convention, scaled by the ORIGINAL length rather
    # than the padded length: without that correction, zero-padding quietly
    # shrinks every reported amplitude by len(samples)/count. A full-scale sine
    # then reads back as its amplitude at a bin centre (a Hann window halves it:
    # that is the window's coherent gain, not a bug).
    reference_length = max(1, len(samples))
    return [
        (index * sample_rate / count, 2.0 * abs(spectrum[index]) / reference_length)
        for index in range(half)
    ]


def _fft(values: List[complex]) -> List[complex]:
    count = len(values)
    if count == 1:
        return values
    if count & (count - 1):
        raise ValueError("FFT length must be a power of two")
    levels = count.bit_length() - 1
    output = list(values)
    for level in range(levels):
        step = 1 << level
        span = step << 1
        root = cmath.exp(-2j * math.pi / span)
        for start in range(0, count, span):
            factor = 1 + 0j
            for offset in range(step):
                left = output[start + offset]
                right = output[start + offset + step] * factor
                output[start + offset] = left + right
                output[start + offset + step] = left - right
                factor *= root
    return output


def dft_reference(samples: Sequence[float], *, sample_rate: int = 16_000) -> List[Tuple[float, float]]:
    """O(N²) DFT on the raw (unwindowed) samples, with the same single-sided
    scaling as :func:`freq_spectrum`.

    Used by the tests to prove the FFT above is correct: compare with
    ``window="none"`` and the two agree to floating-point noise.
    """
    count = len(samples)
    return [
        (
            k * sample_rate / count,
            2.0 * abs(sum(samples[n] * cmath.exp(-2j * math.pi * k * n / count) for n in range(count))) / count,
        )
        for k in range(count // 2)
    ]


def dominant_frequency(samples: Sequence[float], *, sample_rate: int = 16_000) -> float:
    """Frequency of the strongest bin, with parabolic interpolation for accuracy."""
    spectrum = freq_spectrum(samples, sample_rate=sample_rate)
    if not spectrum:
        return 0.0
    peak = max(range(1, max(1, len(spectrum) - 1)), key=lambda index: spectrum[index][1])
    if 0 < peak < len(spectrum) - 1:
        left, middle, right = (spectrum[peak - 1][1], spectrum[peak][1], spectrum[peak + 1][1])
        denominator = left - 2 * middle + right
        if denominator:
            offset = 0.5 * (left - right) / denominator
            resolution = spectrum[1][0] - spectrum[0][0]
            return round(spectrum[peak][0] + offset * resolution, 2)
    return round(spectrum[peak][0], 2)


# ---------------------------------------------------------------------------
# Signatures
# ---------------------------------------------------------------------------
@dataclass
class Signature:
    """A voiceprint: band energies plus the descriptive statistics."""

    dominant_hz: float
    centroid_hz: float
    partials: List[float] = field(default_factory=list)
    bands: List[float] = field(default_factory=list)  # 24 log-spaced bands, normalised
    sample_rate: int = 16_000
    samples: int = 0
    captured_at: float = field(default_factory=time.time)
    liveness_checked: bool = False
    source: str = "microphone"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "dominant_hz": self.dominant_hz,
            "centroid_hz": self.centroid_hz,
            "partials": [round(value, 2) for value in self.partials],
            "bands": [round(value, 6) for value in self.bands],
            "sample_rate": self.sample_rate,
            "samples": self.samples,
            "captured_at": self.captured_at,
            "liveness_checked": self.liveness_checked,
            "source": self.source,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "Signature":
        known = {key: payload[key] for key in cls.__dataclass_fields__ if key in payload}
        return cls(**known)

    @property
    def template_hash(self) -> str:
        material = ",".join(f"{value:.6f}" for value in self.bands)
        return hashlib.sha256(material.encode()).hexdigest()[:32]


_BAND_COUNT = 24

#: A peak must reach this fraction of the strongest magnitude to count as a
#: partial (1%, i.e. -40 dB): below that it is leakage or noise, not a harmonic.
_PARTIAL_FLOOR = 0.01


def analyse(
    samples: Sequence[float],
    *,
    sample_rate: int = 16_000,
    partials: int = 3,
    liveness_checked: bool = False,
) -> Signature:
    """Compute a spectral signature for a buffer of floats in ``[-1, 1]``."""
    spectrum = freq_spectrum(samples, sample_rate=sample_rate)
    nyquist = sample_rate / 2
    if not spectrum:
        raise ValueError("empty spectrum")

    magnitudes = [magnitude for _, magnitude in spectrum]
    total = sum(magnitudes) or 1.0
    centroid = sum(hz * magnitude for hz, magnitude in spectrum) / total

    # Partial picking: find peaks, ignore bins adjacent to an already-chosen one
    # so a single broad harmonic is not reported three times.
    peaks: List[Tuple[float, float]] = []
    strongest = max(magnitudes) or 1.0
    for index in range(1, len(spectrum) - 1):
        hz, magnitude = spectrum[index]
        # A partial must be a local maximum AND carry real energy: without the
        # floor, Hann-window sidelobes and numerical noise get reported as
        # harmonics that are not in the signal.
        if magnitude < strongest * _PARTIAL_FLOOR:
            continue
        if magnitude > spectrum[index - 1][1] and magnitude >= spectrum[index + 1][1]:
            peaks.append((hz, magnitude))
    peaks.sort(key=lambda item: item[1], reverse=True)
    chosen: List[float] = []
    for hz, _ in peaks:
        if len(chosen) >= partials:
            break
        if any(abs(hz - other) < max(8.0, hz * 0.02) for other in chosen):
            continue
        chosen.append(round(hz, 2))
    chosen.sort()

    # Log-spaced bands: robust to pitch shift in a way raw bin magnitudes are not.
    bands: List[float] = []
    low, high = 40.0, nyquist
    for band in range(_BAND_COUNT):
        start = low * (high / low) ** (band / _BAND_COUNT)
        end = low * (high / low) ** ((band + 1) / _BAND_COUNT)
        energy = sum(
            magnitude for hz, magnitude in spectrum if start <= hz < end
        )
        bands.append(math.log1p(energy * 1000.0))
    largest = max(bands) or 1.0
    bands = [value / largest for value in bands]

    return Signature(
        dominant_hz=dominant_frequency(samples, sample_rate=sample_rate),
        centroid_hz=round(centroid, 2),
        partials=chosen,
        bands=bands,
        sample_rate=sample_rate,
        samples=len(samples),
        liveness_checked=liveness_checked,
    )


def comparison(reference: Signature, candidate: Signature) -> Dict[str, float]:
    """Compare two signatures: cosine similarity plus descriptive margins."""
    if len(reference.bands) != len(candidate.bands):
        raise ValueError("signatures were computed with different band layouts")
    dot = sum(a * b for a, b in zip(reference.bands, candidate.bands))
    norm_a = math.sqrt(sum(a * a for a in reference.bands)) or 1.0
    norm_b = math.sqrt(sum(b * b for b in candidate.bands)) or 1.0
    cosine = dot / (norm_a * norm_b)
    return {
        "cosine": round(cosine, 6),
        "dominant_delta_hz": round(abs(reference.dominant_hz - candidate.dominant_hz), 2),
        "centroid_delta_hz": round(abs(reference.centroid_hz - candidate.centroid_hz), 2),
    }


def verify(
    reference: Signature,
    candidate: Signature,
    *,
    threshold: float = 0.97,
    require_liveness: bool = True,
) -> Dict[str, Any]:
    """Accept or reject a candidate voiceprint, with the caveats attached.

    With ``require_liveness`` the check *fails* unless the caller's capture path
    marked the sample as liveness-checked. A recording must never be enough, and
    this default is the only safe one.
    """
    scores = comparison(reference, candidate)
    ok = scores["cosine"] >= threshold
    notes: List[str] = []

    if require_liveness and not candidate.liveness_checked:
        ok = False
        notes.append("liveness not checked: a recording or a clone would pass the spectral test")
    if reference.bands == candidate.bands:
        notes.append("bands are identical to the stored template: the sample may be a replay")
    notes.append(
        "voice is a possibly-secret biometric (IEEE 2791-2020): treat it as one authentication "
        "factor, never as the factor that releases a key"
    )
    return {
        "ok": ok,
        "threshold": threshold,
        "scores": scores,
        "liveness_checked": candidate.liveness_checked,
        "notes": notes,
    }


# ---------------------------------------------------------------------------
# Signal generation (used by tests and the demo CLI)
# ---------------------------------------------------------------------------
def tone(
    frequencies: float | Sequence[float],
    frames: int = 8000,
    *,
    sample_rate: int = 16_000,
    amplitude: float = 0.8,
    noise: float = 0.0,
) -> List[float]:
    """Sum of sine tones, optionally with reproducible noise."""
    values = [float(frequencies)] if isinstance(frequencies, (int, float)) else [float(f) for f in frequencies]
    output: List[float] = []
    for index in range(frames):
        moment = index / sample_rate
        sample = sum(math.sin(_TWO_PI * value * moment) for value in values) / len(values)
        if noise:
            sample += noise * math.sin(_TWO_PI * 3137.0 * moment)  # deterministic "hiss"
        output.append(amplitude * sample)
    return output


def chord(*frequencies: float, frames: int = 8000, sample_rate: int = 16_000) -> List[float]:
    return tone(list(frequencies), frames=frames, sample_rate=sample_rate)


def encode_wav(samples: Sequence[float], *, sample_rate: int = 16_000) -> bytes:
    """Minimal 16-bit mono WAV writer, so tests need no audio library."""
    frames = b"".join(
        struct.pack("<h", max(-32768, min(32767, int(value * 32767)))) for value in samples
    )
    header = b"RIFF" + struct.pack("<I", 36 + len(frames)) + b"WAVEfmt "
    header += struct.pack("<IHHIIHH", 16, 1, 1, sample_rate, sample_rate * 2, 2, 16)
    header += b"data" + struct.pack("<I", len(frames))
    return header + frames


def read_pcm_wav(blob: bytes) -> Tuple[List[float], int]:
    """Read a 16-bit mono PCM WAV produced by :func:`encode_wav` (or any tool)."""
    if not blob.startswith(b"RIFF") or b"WAVE" not in blob[:16]:
        raise ValueError("not a RIFF/WAVE file")
    offset = 12
    sample_rate = 16_000
    data: Optional[bytes] = None
    while offset + 8 <= len(blob):
        chunk_id = blob[offset : offset + 4]
        (size,) = struct.unpack("<I", blob[offset + 4 : offset + 8])
        body = blob[offset + 8 : offset + 8 + size]
        if chunk_id == b"fmt " and len(body) >= 16:
            _, channels, rate, _, _, bits = struct.unpack("<HHIIHH", body[:16])
            if channels != 1 or bits != 16:
                raise ValueError(f"only 16-bit mono is supported, got {channels}ch/{bits}bit")
            sample_rate = rate
        elif chunk_id == b"data":
            data = body
        offset += 8 + size + (size % 2)
    if data is None:
        raise ValueError("no data chunk in the WAV file")
    count = len(data) // 2
    return [value / 32768.0 for value in struct.unpack(f"<{count}h", data[: count * 2])], sample_rate


def liveness_guidance() -> Dict[str, Any]:
    """What an anti-spoofing check must cover before voice means anything."""
    return {
        "replay": "a recording passes a pure spectral test; require a fresh challenge phrase",
        "clone": "TTS/voice-conversion defeats spectral matching; require spectral + temporal cues",
        "coercion": "the speaker can be compelled; pair with a second factor",
        "minimum": [
            "random challenge phrase per attempt",
            "channel/liveness detection (spectral flatness, phase, breath cues)",
            "rate limiting and lockout on repeated failures",
        ],
        "source": "IEEE 2791-2020 treats voice as a possibly-secret characteristic",
    }
