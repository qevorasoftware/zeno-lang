"""The voice agent: it listens, it answers, it remembers — through AEGIS.

One turn is:

    authorize -> (optional) verify the speaker's voiceprint -> answer -> remember

Every step that can change anything goes through the AEGIS boundary first, so in
production a turn without an owner-issued grant is refused with an opaque code and
nothing is generated, stored or sent. In development the turn proceeds and the
result says ``enforcement: "development"`` — the weaker posture is labelled on
every answer, never implied.

**Any language, honestly.** The agent accepts any BCP-47 language tag, passes it
to the answerer, stores it with the turn, and hands it to the browser for
speech-in and speech-out, so "support" means the tag travels intact and the text
is never transliterated behind your back. What it does *not* mean: that the
configured answerer understands every language. With a real provider configured it
is an LLM, and its coverage is its own; with none, the fallback is the rule-based
Zeno encoder, which is English-shaped and says so in the response
(``understanding: "rule-based"``). Pretending otherwise would be the same class of
lie this project refuses everywhere else.

**Everything is remembered, unless you turn it off.** Each turn is appended to the
sealed memory store together with the language, the answering engine, the
authorization decision id and the latency. Audio, when supplied, is sealed and
kept beside the session.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

#: Tags are accepted as given; this only rejects things that are not tags at all.
#: Deliberately not a whitelist: a whitelist would make "any language" a lie.
_LANGUAGE = re.compile(r"^[A-Za-z]{2,8}(-[A-Za-z0-9]{1,8})*$")

SYSTEM_PROMPT = (
    "You are the voice of a private Zeno agent. Answer in the language the user "
    "wrote in; if a language is given explicitly, use that one. Keep replies short "
    "enough to be spoken aloud. Never claim a security guarantee: this system's "
    "guarantees are computational and time-bounded, and you say so if asked."
)


def normalise_language(tag: str, fallback: str = "en") -> str:
    """Accept any well-formed BCP-47 tag; refuse the malformed ones loudly."""
    candidate = (tag or "").strip()
    if not candidate:
        return fallback
    if not _LANGUAGE.match(candidate):
        raise ValueError(f"{tag!r} is not a language tag (expected something like 'gu', 'gu-IN' or 'pt-BR')")
    return candidate


def language_of(tag: str) -> str:
    """The primary subtag: ``gu-IN`` speaks Gujarati, and so does ``gu``."""
    return normalise_language(tag).split("-", 1)[0].lower()


@dataclass
class Turn:
    """Everything that happened in one exchange, as the caller may see it."""

    ok: bool
    session: str
    language: str
    reply: Optional[str] = None
    answerer: str = ""
    understanding: str = ""
    code: str = ""
    enforcement: str = ""
    decision_id: str = ""
    voice: Optional[Dict[str, Any]] = None
    stored: List[str] = field(default_factory=list)
    audio_stored: Optional[str] = None
    elapsed_ms: float = 0.0
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "ok": self.ok,
            "session": self.session,
            "language": self.language,
            "answerer": self.answerer,
            "understanding": self.understanding,
            "enforcement": self.enforcement,
            "decision_id": self.decision_id,
            "stored": list(self.stored),
            "elapsed_ms": round(self.elapsed_ms, 2),
            "notes": list(self.notes),
        }
        if self.reply is not None:
            payload["reply"] = self.reply
        if self.code:
            payload["code"] = self.code
        if self.voice is not None:
            payload["voice"] = self.voice
        if self.audio_stored is not None:
            payload["audio_stored"] = self.audio_stored
        return payload


class VoiceAgent:
    """Conversation, memory and voice, behind the authorization boundary."""

    def __init__(
        self,
        app: Any = None,
        *,
        memory: Any = None,
        boundary: Any = None,
        provider: Any = None,
        peers: Any = None,
        history_turns: int = 12,
    ) -> None:
        self.app = app
        self.memory = memory
        self.boundary = boundary if boundary is not None else getattr(app, "boundary", None)
        self.provider = provider if provider is not None else getattr(app, "provider", None)
        self.peers = peers
        #: How much of the session is sent back to the provider as context. This is
        #: a cost and privacy bound, not a capability limit, and it is reported.
        self.history_turns = max(0, int(history_turns))

    # -- the turn ----------------------------------------------------------
    def turn(
        self,
        *,
        session: str,
        text: str,
        lang: str = "",
        audio_wav: Optional[bytes] = None,
        caller: Any = None,
        material: Optional[Dict[str, Any]] = None,
        remember: bool = True,
        authorization: Any = None,
    ) -> Dict[str, Any]:
        started = time.perf_counter()
        language = normalise_language(lang or "")
        message = (text or "").strip()
        session = session or "default"
        outcome = Turn(ok=False, session=session, language=language)

        if not message and audio_wav is None:
            outcome.notes.append("nothing to answer: send `text`, `audio`, or both")
            outcome.elapsed_ms = (time.perf_counter() - started) * 1000.0
            return outcome.to_dict()

        # 1. Authorization first. Nothing is generated, sent or stored before this.
        #    The route may have authorized already (one decision per request); in
        #    that case its permit arrives here rather than being asked for twice.
        if authorization is None:
            authorization = self._authorize(caller, message or "<audio>", material or {})
        outcome.enforcement = str(getattr(authorization, "mode", getattr(authorization, "enforcement", "")))
        outcome.decision_id = str(getattr(authorization, "decision_id", ""))
        if authorization is not None and not getattr(authorization, "allowed", False):
            outcome.code = str(getattr(authorization, "code", "") or "")
            outcome.notes.append("refused by the authorization boundary: nothing was generated or stored")
            if remember and self.memory is not None and getattr(self.memory, "encrypting", False):
                # A refusal is part of the record too -- but only where memory is
                # sealed; an unsealed store does not get to keep refusals either.
                self._remember(session, "user", message, language, {"refused": outcome.code})
            outcome.elapsed_ms = (time.perf_counter() - started) * 1000.0
            return outcome.to_dict()

        # 2. Voice, if any. Advisory, and said to be advisory.
        if audio_wav:
            outcome.voice = self._voiceprint(audio_wav)
            outcome.notes.extend(outcome.voice.get("limits", [])[:1])

        # 3. Answer.
        history = self._history(session) if self.history_turns else []
        reply, answerer, understanding = self._answer(message, language, history)
        outcome.reply = reply
        outcome.answerer = answerer
        outcome.understanding = understanding
        if understanding == "rule-based":
            outcome.notes.append(
                "no language model is configured: the reply comes from the rule-based Zeno "
                "encoder, which reads English-shaped text. Set a provider for other languages; "
                "the language tag itself is still passed through and stored untouched."
            )

        # 4. Remember.
        if remember and self.memory is not None:
            meta = {
                "answerer": answerer,
                "understanding": understanding,
                "decision_id": outcome.decision_id,
                "enforcement": outcome.enforcement,
                "lang": language,
            }
            if outcome.voice:
                meta["voice"] = {
                    key: outcome.voice.get(key)
                    for key in ("dominant_hz", "frames", "sample_rate", "synthetic")
                }
            outcome.stored.append(self._remember(session, "user", message, language, meta)["id"])
            outcome.stored.append(self._remember(session, "agent", reply, language, meta)["id"])
            if audio_wav:
                stored = self.memory.store_audio(session, outcome.stored[0], audio_wav)
                outcome.audio_stored = stored["digest"]
                if not stored.get("encrypted"):
                    outcome.notes.append("audio was stored unsealed: no owner key is configured")

        outcome.ok = True
        outcome.elapsed_ms = (time.perf_counter() - started) * 1000.0
        return outcome.to_dict()

    # -- pieces ------------------------------------------------------------
    def _authorize(self, caller: Any, text: str, material: Dict[str, Any]) -> Any:
        """A turn is effectful: it spends a provider call and writes to memory.

        So it goes through the effectful path — capability, nonce and the layer
        chain — not through the read gate the owner's *views* use. In development
        that means "allowed, and labelled development"; in production it means the
        full AEGIS context is required, exactly as for any other execution.
        """
        if self.boundary is None:
            return None
        from aegis.boundary import Caller

        person = caller if caller is not None else Caller(actor="voice-client")
        return self.boundary.authorize(
            person, text.encode("utf-8"), material, action="agent:turn"
        )

    def _history(self, session: str) -> List[Dict[str, Any]]:
        if self.memory is None:
            return []
        try:
            records = self.memory.read(session, limit=self.history_turns * 2)
        except Exception:  # noqa: BLE001 - memory that cannot be read must not block the turn
            return []
        return [record for record in records if record.get("kind") == "turn"]

    def _answer(self, text: str, language: str, history: Sequence[Dict[str, Any]]) -> tuple:
        """Returns ``(reply, answerer, understanding)``."""
        provider = self.provider
        if provider is not None and provider.available():
            transcript = "\n".join(
                f"{record.get('role', 'user')}: {record.get('text', '')}"
                for record in history
                if record.get("text")
            )
            prompt = (
                f"Language: {language}\n"
                + (f"Conversation so far:\n{transcript}\n" if transcript else "")
                + f"User: {text}\nAgent:"
            )
            try:
                completion = provider.complete(prompt, system=SYSTEM_PROMPT, max_tokens=400)
                return (str(completion.text).strip(), provider.name, "language-model")
            except Exception as error:  # noqa: BLE001 - a provider failure is a fact, not a secret
                note = f"the configured provider failed ({type(error).__name__}); fell back to the rule-based encoder"
                reply, answerer, understanding = self._rule_based(text)
                return (reply, answerer, understanding + " | " + note)
        return self._rule_based(text)

    def _rule_based(self, text: str) -> tuple:
        if self.app is not None:
            try:
                outcome = self.app.ask(text)
                reply = str(outcome.get("response") or outcome.get("text") or "").strip()
                if reply:
                    return (reply, "zeno-rule-based", "rule-based")
            except Exception:  # noqa: BLE001 - the fallback of the fallback is echo
                pass
        return (text, "echo", "rule-based")

    def _voiceprint(self, wav: bytes) -> Dict[str, Any]:
        """Measure the speaker, and say exactly how much that is worth.

        A voiceprint is a *signal*. Every report carries that in its own words:
        it can be recorded and replayed, so it never authorizes anything by itself
        — it can only raise or lower how suspicious a turn looks to the sentinel.
        """
        from aegis.vajra import nada_brahma_voice

        report: Dict[str, Any] = {
            "analyse": "aegis.vajra.nada_brahma_voice",
            "limits": [
                "a voiceprint is a signal, not a proof: recorded speech replays, and every layer here knows it",
            ],
        }
        try:
            samples, rate = nada_brahma_voice.read_pcm_wav(wav)
            signature = nada_brahma_voice.analyse(samples, sample_rate=rate)
            report.update(
                {
                    "frames": len(samples),
                    "sample_rate": rate,
                    "dominant_hz": round(nada_brahma_voice.dominant_frequency(samples, sample_rate=rate), 2),
                    "synthetic": bool(getattr(signature, "synthetic_suspected", False)),
                }
            )
        except Exception as error:  # noqa: BLE001 - a voice we cannot read is not a voice we can judge
            report["error"] = f"{type(error).__name__}: {error}"
        return report

    def _remember(self, session: str, role: str, text: str, language: str, meta: Dict[str, Any]) -> Dict[str, Any]:
        return self.memory.record(session, kind="turn", role=role, text=text, lang=language, meta=meta)


# ---------------------------------------------------------------------------
# Audio helpers
# ---------------------------------------------------------------------------
def wav_from_pcm(data: bytes, *, sample_rate: int = 16_000, channels: int = 1) -> bytes:
    """Wrap raw 16-bit PCM in a WAV header.

    The browser sends PCM it captured at a known rate; the server needs a real
    container to run the voiceprint over it, and a 44-byte header is cheaper than
    an audio library. Refuses anything that is not obviously 16-bit PCM.
    """
    if not data:
        raise ValueError("no samples")
    if len(data) % 2:
        raise ValueError("PCM samples must be 16-bit little-endian: an odd byte count cannot be one")
    from aegis.vajra.nada_brahma_voice import encode_wav

    samples = [
        int.from_bytes(data[index : index + 2], "little", signed=True) / 32768.0
        for index in range(0, min(len(data), 16_000 * 2 * 30), 2)  # at most 30 s, to bound the work
    ]
    if channels and channels > 1:  # take the first channel; the voiceprint is mono
        samples = samples[::channels]
    return encode_wav(samples, sample_rate=sample_rate)
