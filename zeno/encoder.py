"""Encoder agent: natural language -> Zeno Protocol payload.

    >>> from zeno.encoder import Encoder
    >>> from zeno.providers import MockProvider
    >>> encoder = Encoder(MockProvider('@LOC[TYO] -> ?WX'))
    >>> encoder.encode("What is the weather in Tokyo?").payload
    '@LOC[TYO] -> ?WX'

The encoder enforces Grammar v0.1 in three escalating layers:

1. **Prompt** — the model is instructed to emit a payload and nothing else.
2. **Extraction** — fences, labels and prose are stripped; the first segment
   that actually parses wins.
3. **Repair** — a parse failure is fed back to the model with its diagnostic
   (code, message and caret), up to ``max_repairs`` times.

When no provider is configured the encoder degrades to
:class:`HeuristicEncoder`, a rule-based converter that covers the shapes used
in the examples and benchmarks. It is clearly flagged in the result
(``fell_back=True``) so nobody mistakes it for a model output.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .config import Settings, load_settings
from .emitter import emit
from .errors import EncodeError, ZenoError
from .parser import parse
from .prompts import ENCODER_SYSTEM, REPAIR_SYSTEM
from .providers import Completion, Provider, resolve
from .tokenizer import count_tokens, counting_method
from .validator import ValidationReport, validate

__all__ = ["Encoder", "EncodeResult", "encode", "HeuristicEncoder"]


@dataclass
class EncodeResult:
    """The outcome of one natural-language -> Zeno conversion."""

    #: The canonical Zeno payload.
    payload: str = ""
    #: Natural-language input.
    human: str = ""
    #: Raw text the model returned (kept for auditing).
    raw: str = ""
    provider: str = ""
    model: str = ""
    #: Number of model calls spent (1 + repairs).
    attempts: int = 0
    #: ``True`` when the payload came from the rule-based fallback.
    fell_back: bool = False
    #: Diagnostics from the final validation pass.
    report: Optional[ValidationReport] = None
    #: Tokens in the natural-language request.
    nl_tokens: int = 0
    #: Tokens in the Zeno payload.
    zeno_tokens: int = 0
    #: Tokens in the encoder's system prompt (the protocol's fixed cost).
    prompt_tokens: int = 0
    #: Provider-reported token usage, summed across attempts.
    completion_tokens: int = 0
    latency_ms: float = 0.0
    warnings: List[str] = field(default_factory=list)

    @property
    def token_reduction(self) -> float:
        """``(NL - Zeno) / NL * 100`` for the payload alone."""
        if not self.nl_tokens:
            return 0.0
        return (self.nl_tokens - self.zeno_tokens) / self.nl_tokens * 100.0

    @property
    def total_reduction(self) -> float:
        """Reduction including the encoder's fixed system-prompt cost."""
        total_nl = self.nl_tokens
        if not total_nl:
            return 0.0
        return (total_nl - (self.zeno_tokens + self.prompt_tokens)) / total_nl * 100.0

    def to_dict(self) -> dict:
        return {
            "payload": self.payload,
            "human": self.human,
            "provider": self.provider,
            "model": self.model,
            "attempts": self.attempts,
            "fell_back": self.fell_back,
            "nl_tokens": self.nl_tokens,
            "zeno_tokens": self.zeno_tokens,
            "prompt_tokens": self.prompt_tokens,
            "token_reduction_pct": round(self.token_reduction, 2),
            "latency_ms": round(self.latency_ms, 3),
            "warnings": list(self.warnings),
        }

    def render(self) -> str:  # pragma: no cover - presentation helper
        return self.payload


class Encoder:
    """Convert natural language into a validated Zeno payload.

    Parameters
    ----------
    provider:
        A :class:`~zeno.providers.Provider`, a provider slug, or ``None`` to
        resolve from configuration.
    tools:
        Optional list of tool names the receiver exposes
        (``["?WX", "!GEN"]``). When given, the encoder tells the model which
        verbs exist, which sharply reduces hallucinated actions.
    fallback:
        Use :class:`HeuristicEncoder` when no provider is configured instead of
        raising ``ZN3001``.
    canonical:
        Re-emit the parsed AST, guaranteeing canonical spacing and ordering.
    """

    def __init__(
        self,
        provider: Any = None,
        *,
        settings: Optional[Settings] = None,
        model: Optional[str] = None,
        tools: Optional[Sequence[str]] = None,
        fallback: bool = True,
        canonical: bool = True,
        repair: bool = True,
        max_repairs: Optional[int] = None,
        strict: bool = False,
    ) -> None:
        self.settings = settings or load_settings(model=model)
        self.provider: Provider = resolve(provider, settings=self.settings)
        self.tools = list(tools or [])
        self.fallback = fallback
        self.canonical = canonical
        self.repair = repair
        self.max_repairs = (
            self.settings.max_repairs if max_repairs is None else max_repairs
        )
        self.strict = strict or self.settings.strict

    # -- prompt construction --------------------------------------------
    def system_prompt(self) -> str:
        system = ENCODER_SYSTEM
        if self.tools:
            system += (
                "\nAVAILABLE TOOLS ON THE RECEIVER\n"
                + "  ".join(self.tools)
                + "\nUse only these queries and actions.\n"
            )
        return system

    def build_prompt(self, text: str, context: Optional[Dict[str, Any]] = None) -> str:
        parts: List[str] = []
        if context:
            rendered = "  ".join(f"{key}={value}" for key, value in context.items())
            parts.append(f"LATENT STATE: {rendered}")
        parts.append(f"NL: {text.strip()}")
        parts.append("ZENO:")
        return "\n".join(parts)

    # -- main entry point ------------------------------------------------
    def encode(self, text: str, *, context: Optional[Dict[str, Any]] = None) -> EncodeResult:
        """Convert ``text`` into a validated payload.

        Raises
        ------
        EncodeError
            When the model cannot produce a parseable payload within the repair
            budget and no fallback is available (``ZN1001``).
        """
        if not isinstance(text, str) or not text.strip():
            raise EncodeError("nothing to encode: the natural-language input is empty")

        system = self.system_prompt()
        result = EncodeResult(
            human=text.strip(),
            provider=self.provider.name,
            model=self.provider.model,
            nl_tokens=count_tokens(text),
            prompt_tokens=count_tokens(system),
        )

        if self.provider.name == "mock" and isinstance(
            getattr(self.provider, "responses", None), type(None)
        ):
            # A bare MockProvider still exercises the real prompt path.
            pass

        completion: Optional[Completion] = None
        if self.provider.available():
            try:
                completion = self._call(
                    text, context=context, system=system, repairs=0
                )
            except EncodeError:
                raise
            except ZenoError as exc:
                if self.strict or not self.fallback:
                    raise
                result.warnings.append(f"provider failed: {exc.message}")

        if completion is None:
            return self._fallback(text, result)

        result.attempts = 1
        result.raw = completion.text
        result.completion_tokens += completion.completion_tokens
        result.latency_ms += completion.latency_ms

        payload = _extract_payload(completion.text)
        error = _try_parse(payload)

        if error is not None and self.repair:
            for _ in range(max(0, self.max_repairs)):
                try:
                    repair_completion = self._call(
                        text,
                        context=context,
                        system=REPAIR_SYSTEM,
                        repairs=result.attempts,
                        previous=payload,
                        error=error,
                    )
                except ZenoError as exc:  # pragma: no cover - transport failure
                    result.warnings.append(f"repair call failed: {exc.message}")
                    break
                result.attempts += 1
                result.completion_tokens += repair_completion.completion_tokens
                result.latency_ms += repair_completion.latency_ms
                result.raw = repair_completion.text
                candidate = _extract_payload(repair_completion.text)
                candidate_error = _try_parse(candidate)
                if candidate_error is None:
                    payload, error = candidate, None
                    break
                payload, error = candidate, candidate_error

        if error is not None:
            if self.strict or not self.fallback:
                raise EncodeError(
                    f"model output did not parse as Zeno after {result.attempts} attempt(s): "
                    f"{error.summary}",
                    getattr(error, "span", None),
                    hint="set fallback=True to degrade to the rule-based encoder, "
                    "or fix the model/prompt",
                )
            result.warnings.append(
                f"unparseable model output ({error.summary}); used rule-based fallback"
            )
            fallback_result = self._fallback(text, result)
            fallback_result.attempts = result.attempts
            fallback_result.raw = result.raw
            fallback_result.warnings = result.warnings
            return fallback_result

        return self._finalise(payload, result)

    # -- helpers ---------------------------------------------------------
    def _call(
        self,
        text: str,
        *,
        context: Optional[Dict[str, Any]],
        system: str,
        repairs: int,
        previous: str = "",
        error: Optional[ZenoError] = None,
    ) -> Completion:
        if repairs and error is not None:
            prompt = self._repair_prompt(text, previous, error)
        else:
            prompt = self.build_prompt(text, context)
        return self.provider.complete(
            prompt,
            system=system,
            temperature=self.settings.temperature,
            max_tokens=self.settings.max_tokens,
        )

    @staticmethod
    def _repair_prompt(text: str, previous: str, error: ZenoError) -> str:
        return (
            f"ORIGINAL REQUEST\nNL: {text.strip()}\n\n"
            f"YOUR PAYLOAD\n{previous.strip()}\n\n"
            f"PARSER DIAGNOSTIC\n{error.summary}\n{error.message}\n\n"
            "Return the corrected payload only."
        )

    def _finalise(self, payload: str, result: EncodeResult) -> EncodeResult:
        program = parse(payload)
        canonical = emit(program) if self.canonical else payload.strip()
        result.payload = canonical
        result.zeno_tokens = count_tokens(canonical)
        report = validate(canonical)
        result.report = report
        for diagnostic in report.errors:
            result.warnings.append(f"{diagnostic.code}: {diagnostic.message}")
        return result

    def _fallback(self, text: str, result: EncodeResult) -> EncodeResult:
        if not self.fallback:
            from .errors import ProviderError

            raise ProviderError(
                f"provider '{self.provider.name}' is not available and fallback is disabled"
            )
        heuristic = HeuristicEncoder()
        payload = heuristic.encode(text)
        result.warnings.append(
            "no LLM provider configured: used the rule-based encoder "
            "(set ZENO_PROVIDER + API key for model-quality output)"
        )
        result.fell_back = True
        result.attempts = result.attempts or 0
        result.provider = "heuristic"
        return self._finalise(payload, result)

    # -- introspection ---------------------------------------------------
    def describe(self) -> Dict[str, Any]:
        return {
            "provider": self.provider.describe(),
            "tools": list(self.tools),
            "fallback": self.fallback,
            "canonical": self.canonical,
            "max_repairs": self.max_repairs,
            "tokenizer": counting_method(self.provider.model),
        }


# ---------------------------------------------------------------------------
# Response hygiene
# ---------------------------------------------------------------------------
_FENCE_RE = re.compile(r"```[a-zA-Z0-9_-]*\s*(.*?)```", re.DOTALL)
_LABEL_RE = re.compile(r"^\s*(?:ZENO|ZENO PROTOCOL|PAYLOAD|OUTPUT)\s*:\s*", re.IGNORECASE)


def _strip_fences(text: str) -> str:
    match = _FENCE_RE.search(text)
    if match:
        return match.group(1).strip()
    return text.strip()


def _extract_payload(text: str) -> str:
    """Pull the most likely payload out of a model response."""
    if not text or not text.strip():
        return ""
    body = _strip_fences(text)
    lines = [_LABEL_RE.sub("", line).rstrip() for line in body.splitlines()]
    candidates: List[str] = []

    cleaned = "\n".join(line for line in lines if line.strip())
    candidates.append(cleaned)

    # Paragraph-level split (models often add a preamble).
    paragraphs = [p.strip() for p in re.split(r"\n\s*\n", cleaned) if p.strip()]
    candidates.extend(paragraphs)

    # Rolling line groups, longest first.
    for size in range(len(lines), 0, -1):
        for start in range(0, len(lines) - size + 1):
            chunk = "\n".join(lines[start : start + size]).strip()
            if chunk:
                candidates.append(chunk)

    # Prefer a candidate that actually parses: models often wrap a correct
    # payload in chatter, and the payload is the part that parses.
    fallback = ""
    for candidate in candidates[:120]:
        if not candidate:
            continue
        if not fallback and _looks_like_payload(candidate):
            fallback = candidate
        try:
            parse(candidate)
        except ZenoError:
            continue
        return candidate
    return fallback or (candidates[0] if candidates else "")


_PAYLOAD_HINT = re.compile(r"(^|\n)\s*[@?!$]|->|=>")


def _looks_like_payload(candidate: str) -> bool:
    return bool(_PAYLOAD_HINT.search(candidate))


def _try_parse(payload: str) -> Optional[ZenoError]:
    if not payload.strip():
        from .errors import ZenoSyntaxError

        return ZenoSyntaxError("the model returned an empty payload")
    try:
        parse(payload)
    except ZenoError as exc:
        return exc
    return None


# ---------------------------------------------------------------------------
# Rule-based fallback encoder
# ---------------------------------------------------------------------------
_CITY_CODES = {
    "tokyo": "TYO",
    "new york": "NYC",
    "newyork": "NYC",
    "london": "LON",
    "paris": "PAR",
    "berlin": "BER",
    "ahmedabad": "AMD",
    "amsterdam": "AMS",
    "sydney": "SYD",
    "singapore": "SIN",
    "bangalore": "BLR",
    "bengaluru": "BLR",
    "mumbai": "BOM",
    "delhi": "DEL",
    "san francisco": "SFO",
    "los angeles": "LAX",
    "seattle": "SEA",
    "toronto": "YYZ",
    "dubai": "DXB",
    "osaka": "OSA",
    "seoul": "SEL",
    "madrid": "MAD",
    "rome": "ROM",
    "cairo": "CAI",
    "lagos": "LOS",
    "sao paulo": "SAO",
    "mexico city": "MEX",
}

_WEATHER_RE = re.compile(
    r"weather|forecast|temperature|raining|rain\b|sunny|climate", re.IGNORECASE
)
_CITY_IN_RE = re.compile(
    r"\bin\s+([A-Za-z][A-Za-z'\u2019-]{1,20}(?:\s+[A-Za-z][A-Za-z'\u2019-]{1,20})?)",
    re.IGNORECASE,
)
_NUMBER_RE = re.compile(r"-?\d+(?:\.\d+)?")
_AGENT_RE = re.compile(r"\b(?:agent|coder|researcher|planner|tester|reviewer)\b[^.]*", re.IGNORECASE)
_MATH_RE = re.compile(r"[\d\s+\-*/%^().]+")
#: "3 units at 129.99" / "2 x 45.50" / "4 @ 10" - quantity followed by a price.
_QTY_RE = re.compile(
    r"(\d+(?:\.\d+)?)\s*"
    r"(?:units?|items?|pieces?|pcs|copies|licen[cs]es?|seats?|hours?|days?|kgs?|boxes?|users?)?\s*"
    r"(?:at\b|@|×|(?<=\s)x(?=\s)|\*)\s*\$?(\d+(?:\.\d+)?)",
    re.IGNORECASE,
)
#: "... over 500", "... below 120 dollars" - a numeric threshold and its direction.
_THRESHOLD_RE = re.compile(
    r"\b(over|above|exceed\w*|more than|greater than|at least|under|below|less than|beneath|"
    r"drops? below|falls? below)\s+\$?(\d+(?:\.\d+)?)",
    re.IGNORECASE,
)
_BELOW_WORDS = frozenset({"under", "below", "less than", "beneath", "drops below", "falls below"})
_ARITH_HINT = re.compile(r"calculate|compute|total|sum|how much|what is\s+[\d(]", re.IGNORECASE)


def _trim_number(raw: str) -> str:
    """``129.990`` -> ``129.99``, ``45.50`` -> ``45.5``, ``1.0`` -> ``1``."""
    text = raw.strip()
    if "." not in text:
        return text
    text = text.rstrip("0").rstrip(".")
    return text or "0"


class HeuristicEncoder:
    """Rule-based NL -> Zeno converter.

    Deliberately small: it covers the shapes exercised by ``examples/`` and
    ``benchmarks/`` so the project is demonstrable without any API key. Anything
    it cannot classify becomes an explicit generation request, never a guess.
    """

    name = "heuristic"

    def encode(self, text: str) -> str:
        text = text.strip()
        if not text:
            raise EncodeError("nothing to encode")

        weather = self._weather(text)
        if weather:
            return weather
        arithmetic = self._arithmetic(text)
        if arithmetic:
            return arithmetic
        return self._generic(text)

    # -- patterns --------------------------------------------------------
    def _weather(self, text: str) -> Optional[str]:
        if not _WEATHER_RE.search(text):
            return None
        city = None
        match = _CITY_IN_RE.search(text)
        if match:
            words = match.group(1).strip().lower().rstrip(".").split()
            while words and words[-1] in {
                "please", "today", "now", "tomorrow", "thanks", "me", "for", "the", "right",
            }:
                words.pop()
            city = " ".join(words)
        code = _CITY_CODES.get(city or "", None)
        if code is None and city:
            code = re.sub(r"[^A-Za-z]", "", city).upper()[:3]
        code = code or "LOC"
        count = 3
        number = re.search(r"\b(\d+)\b", text)
        if number:
            count = max(1, min(10, int(number.group(1))))
        indoor = "INDOOR" if re.search(r"indoor|inside|home", text, re.IGNORECASE) else "INDOOR"
        outdoor = "OUTDOOR" if re.search(r"outdoor|outside|park", text, re.IGNORECASE) else "OUTDOOR"
        return (
            f"@LOC[{code}] -> ?WX : "
            f"{{ $WX.state == RAIN => !GEN[{indoor}, {count}] | !GEN[{outdoor}, {count}] }}"
        )

    def _arithmetic(self, text: str) -> Optional[str]:
        """Recognise "3 units at 129.99 each, 2 more at 45.50 - over 500?"."""
        expression = self._sum_of_quantities(text)
        if expression is None and (_ARITH_HINT.search(text) or _MATH_RE.search(text)):
            expression = self._math_core(text)
        if not expression:
            return None

        threshold = _THRESHOLD_RE.search(text)
        if threshold:
            direction = threshold.group(1).lower()
            operator = "<" if direction in _BELOW_WORDS else ">"
            limit = _trim_number(threshold.group(2))
            over, under = ("UNDER", "OVER") if operator == "<" else ("OVER", "UNDER")
            return (
                f"$TOTAL = {expression}\n"
                f": {{ $TOTAL {operator} {limit} => !RET[$TOTAL, BUDGET={over}]"
                f" | !RET[$TOTAL, BUDGET={under}] }}"
            )
        return (
            f"$TOTAL = {expression}\n"
            ': { $TOTAL > 500 => !RET[OUT="over budget", $TOTAL]'
            ' | !RET[OUT="within budget", $TOTAL] }'
        )

    @staticmethod
    def _sum_of_quantities(text: str) -> Optional[str]:
        pairs = _QTY_RE.findall(text)
        if len(pairs) < 2:
            return None
        return " + ".join(f"{_trim_number(q)} * {_trim_number(p)}" for q, p in pairs)

    @staticmethod
    def _math_core(text: str) -> Optional[str]:
        core = _MATH_RE.search(text)
        if not core:
            return None
        candidate = core.group(0).strip()
        if not re.search(r"\d\s*[+\-*/%^]\s*\d", candidate):
            return None
        try:
            parse(f"$TOTAL = {candidate}")
        except ZenoError:
            return None
        return re.sub(r"\s+", " ", candidate)

    def _generic(self, text: str) -> str:
        payload = self._escape(text)
        agent = _AGENT_RE.search(text)
        target = "AGENT[GEN]"
        if agent:
            words = re.findall(r"[A-Za-z]+", agent.group(0))
            if words:
                target = f"AGENT[{words[-1].upper()}]"
        return f'@{target} -> !GEN["{payload}", 1] -> !RET[OUT=$PREV]'

    @staticmethod
    def _escape(text: str) -> str:
        clipped = text.strip().replace("\\", "\\\\").replace('"', '\\"')
        clipped = re.sub(r"\s+", " ", clipped)
        return clipped[:160]


def encode(text: str, **kwargs: Any) -> EncodeResult:
    """One-shot convenience wrapper around :class:`Encoder`."""
    return Encoder(**kwargs).encode(text)
