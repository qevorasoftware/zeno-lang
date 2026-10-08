"""Decoder agent: execution result -> human language.

    >>> from zeno.decoder import Decoder
    >>> from zeno.providers import MockProvider
    >>> from zeno.runtime import Kernel
    >>> kernel = Kernel(generator=lambda topic, n, kw, env: ["Museum", "Aquarium", "Tea house"])
    >>> kernel.register_query("WX", lambda a, kw, e, c: {"state": "RAIN"})
    >>> result = kernel.execute('@LOC[TYO] -> ?WX : { $WX.state == RAIN => !GEN[INDOOR, 3] }')
    >>> decoder = Decoder(MockProvider("Tokyo is rainy, so here are three indoor ideas: …"))
    >>> decoder.decode(result, request="Weather in Tokyo?").text[:8]
    'Tokyo is'

The decoder receives a *dense render of the run* — not a raw JSON blob — because
the kernel already knows what happened. ``fallback=True`` (the default) renders
the result deterministically when no provider is reachable, so the pipeline
never dead-ends on a missing API key.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union

from .config import Settings, load_settings
from .errors import ZenoError
from .prompts import DECODER_SYSTEM
from .providers import Completion, Provider, resolve
from .runtime import ExecutionResult, Kernel, result_frame
from .tokenizer import count_tokens
from .values import render, to_jsonable

__all__ = ["Decoder", "DecodeResult", "decode"]


@dataclass
class DecodeResult:
    """The outcome of one result -> prose conversion."""

    text: str = ""
    provider: str = ""
    model: str = ""
    #: The dense context that was sent to the model.
    context: str = ""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    latency_ms: float = 0.0
    attempts: int = 0
    fell_back: bool = False
    frame: str = ""
    warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "text": self.text,
            "provider": self.provider,
            "model": self.model,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "latency_ms": round(self.latency_ms, 3),
            "fell_back": self.fell_back,
            "warnings": list(self.warnings),
        }

    def __str__(self) -> str:  # pragma: no cover - presentation helper
        return self.text


class Decoder:
    """Turn an :class:`~zeno.runtime.ExecutionResult` back into human language."""

    def __init__(
        self,
        provider: Any = None,
        *,
        settings: Optional[Settings] = None,
        model: Optional[str] = None,
        style: str = "prose",
        fallback: bool = True,
        strict: bool = False,
    ) -> None:
        self.settings = settings or load_settings(model=model)
        self.provider: Provider = resolve(provider, settings=self.settings)
        self.style = style
        self.fallback = fallback
        self.strict = strict or self.settings.strict

    # -- prompt ----------------------------------------------------------
    def build_prompt(
        self,
        result: ExecutionResult,
        *,
        request: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> str:
        parts: List[str] = []
        if request:
            parts.append(f"ORIGINAL REQUEST\n{request.strip()}\n")
        parts.append("EXECUTION RESULT\n" + result.as_context(style=self.style))
        if extra:
            parts.append(
                "ADDITIONAL CONTEXT\n"
                + "\n".join(f"{key}: {render(value)}" for key, value in extra.items())
            )
        parts.append("\nAnswer the request in natural language. Reply with the answer only.")
        return "\n".join(parts)

    # -- main entry point ------------------------------------------------
    def decode(
        self,
        result: Union[ExecutionResult, str, Dict[str, Any]],
        *,
        request: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> DecodeResult:
        """Render ``result`` as human language."""
        execution = self._coerce(result)
        context = self.build_prompt(execution, request=request, extra=extra)
        out = DecodeResult(
            provider=self.provider.name,
            model=self.provider.model,
            context=context,
            frame=result_frame(execution),
            prompt_tokens=count_tokens(context) + count_tokens(DECODER_SYSTEM),
        )

        if not self.provider.available():
            return self._fallback(execution, out, reason="provider is not configured")

        try:
            completion: Completion = self.provider.complete(
                context,
                system=DECODER_SYSTEM,
                temperature=self.settings.temperature,
                max_tokens=self.settings.max_tokens,
            )
        except ZenoError as exc:
            if self.strict or not self.fallback:
                raise
            return self._fallback(execution, out, reason=exc.message)

        out.attempts = 1
        out.text = _clean(completion.text)
        out.completion_tokens = completion.completion_tokens
        out.latency_ms = completion.latency_ms
        if not out.text:
            return self._fallback(execution, out, reason="model returned an empty answer")
        return out

    # -- helpers ---------------------------------------------------------
    @staticmethod
    def _coerce(result: Union[ExecutionResult, str, Dict[str, Any]]) -> ExecutionResult:
        if isinstance(result, ExecutionResult):
            return result
        if isinstance(result, str):
            return Kernel().execute(result)
        if isinstance(result, dict):
            execution = ExecutionResult(
                output=result.get("output"),
                bindings=dict(result.get("bindings") or {}),
                payload=str(result.get("payload") or ""),
                returned=bool(result.get("returned")),
            )
            return execution
        raise TypeError(
            f"cannot decode {type(result).__name__}; pass an ExecutionResult, payload or dict"
        )

    def _fallback(
        self, result: ExecutionResult, out: DecodeResult, *, reason: str
    ) -> DecodeResult:
        out.fell_back = True
        out.provider = "deterministic"
        out.warnings.append(f"{reason}; rendered the result deterministically")
        out.text = self.deterministic(result)
        return out

    @staticmethod
    def deterministic(result: ExecutionResult) -> str:
        """A provider-free rendering of the run.

        Numbers, lists and mappings keep their shape; the phrasing stays plain
        so a human sees exactly what the kernel produced.
        """
        answer = result.answer
        lines: List[str] = []
        if isinstance(answer, dict) and not result.returned:
            lines.append("Result:")
            for key, value in answer.items():
                lines.append(f"- {key}: {render(value, style='prose')}")
        elif isinstance(answer, list):
            lines.append(f"Result ({len(answer)} items):")
            for index, item in enumerate(answer, start=1):
                lines.append(f"{index}. {render(item, style='prose')}")
        else:
            lines.append(render(answer, style="prose"))
        if result.errors:
            lines.append("Notes: " + "; ".join(result.errors))
        return "\n".join(lines).strip()

    # -- introspection ---------------------------------------------------
    def describe(self) -> Dict[str, Any]:
        return {
            "provider": self.provider.describe(),
            "style": self.style,
            "fallback": self.fallback,
        }


def _clean(text: str) -> str:
    text = (text or "").strip()
    if text.startswith("```"):
        text = text.strip("`")
        if "\n" in text:
            first, _, rest = text.partition("\n")
            if first.strip().lower() in {"text", "markdown", "md", ""}:
                text = rest
        text = text.strip("`").strip()
    for prefix in ("ANSWER:", "Answer:", "OUTPUT:", "Output:"):
        if text.startswith(prefix):
            text = text[len(prefix) :].strip()
    return text


def decode(result: Union[ExecutionResult, str, Dict[str, Any]], **kwargs: Any) -> DecodeResult:
    """One-shot convenience wrapper around :class:`Decoder`."""
    request = kwargs.pop("request", None)
    decoder_kwargs = {k: v for k, v in kwargs.items() if k in {"provider", "settings", "model", "style", "fallback", "strict"}}
    return Decoder(**decoder_kwargs).decode(result, request=request)
