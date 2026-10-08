"""End-to-end orchestration: natural language -> Zeno -> execution -> natural language.

This is the three-stage architecture from the project brief wired together::

    [ HUMAN PROMPT ]
           |
           v
    STAGE 1: Encoder  (LLM)      zeno/encoder.py
           |
           v
    [ ZENO PAYLOAD ]
           |
           v
    STAGE 2: Kernel   (tools)    zeno/runtime.py
           |
           v
    STAGE 3: Decoder  (LLM)      zeno/decoder.py
           |
           v
    [ HUMAN OUTPUT ]

Each stage is independently swappable; :class:`Pipeline` only glues them and
records timings so latency can be attributed per stage.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence

from .decoder import DecodeResult, Decoder
from .encoder import EncodeResult, Encoder
from .runtime import ExecutionResult, Kernel
from .tokenizer import count_tokens
from .values import to_jsonable

__all__ = ["Pipeline", "PipelineResult", "default_kernel"]


@dataclass
class PipelineResult:
    """Everything that happened during one round trip."""

    human: str = ""
    payload: str = ""
    response: str = ""
    encode: Optional[EncodeResult] = None
    execution: Optional[ExecutionResult] = None
    decode: Optional[DecodeResult] = None
    timings_ms: Dict[str, float] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.execution is not None and not (
            self.execution.errors and not self.execution.answer
        )

    @property
    def total_ms(self) -> float:
        return round(sum(self.timings_ms.values()), 3)

    @property
    def token_reduction(self) -> float:
        return self.encode.token_reduction if self.encode else 0.0

    def to_dict(self) -> dict:
        return {
            "human": self.human,
            "payload": self.payload,
            "response": self.response,
            "timings_ms": {key: round(value, 3) for key, value in self.timings_ms.items()},
            "total_ms": self.total_ms,
            "encode": self.encode.to_dict() if self.encode else None,
            "decode": self.decode.to_dict() if self.decode else None,
            "execution": self.execution.to_dict() if self.execution else None,
        }

    def transcript(self) -> str:  # pragma: no cover - presentation helper
        lines = [
            f"NL      : {self.human}",
            f"ZENO    : {self.payload}",
            f"OUTPUT  : {self.response}",
            f"LATENCY : {self.total_ms:.1f} ms "
            f"(encode {self.timings_ms.get('encode', 0):.1f}, "
            f"execute {self.timings_ms.get('execute', 0):.1f}, "
            f"decode {self.timings_ms.get('decode', 0):.1f})",
        ]
        if self.encode:
            lines.append(
                f"TOKENS  : {self.encode.nl_tokens} NL -> {self.encode.zeno_tokens} Zeno "
                f"({self.encode.token_reduction:.1f} % reduction)"
            )
        return "\n".join(lines)


def default_kernel(**kwargs: Any) -> Kernel:
    """A kernel with the built-in tools and no external dependencies."""
    return Kernel(**kwargs)


class Pipeline:
    """Compose encoder, kernel and decoder into a single call."""

    def __init__(
        self,
        encoder: Optional[Encoder] = None,
        kernel: Optional[Kernel] = None,
        decoder: Optional[Decoder] = None,
        *,
        provider: Any = None,
        tools: Optional[Dict[str, Any]] = None,
        generator: Optional[Callable[..., Any]] = None,
        echo: Optional[Callable[[str], None]] = None,
        decode: bool = True,
    ) -> None:
        self.encoder = encoder or Encoder(provider)
        self.kernel = kernel or default_kernel(generator=generator, echo=echo)
        self.decoder = decoder if decoder is not None else (Decoder(provider) if decode else None)
        if tools:
            for name, fn in tools.items():
                self.kernel.register(name, fn)

    # -- registry passthrough -------------------------------------------
    def register(self, name: str, fn: Callable[..., Any]) -> "Pipeline":
        self.kernel.register(name, fn)
        return self

    def register_query(self, name: str, fn: Callable[..., Any]) -> "Pipeline":
        self.kernel.register_query(name, fn)
        return self

    def register_action(self, name: str, fn: Callable[..., Any]) -> "Pipeline":
        self.kernel.register_action(name, fn)
        return self

    # -- main entry point ------------------------------------------------
    def run(
        self,
        text: str,
        *,
        state: Optional[Dict[str, Any]] = None,
        tools: Optional[Dict[str, Any]] = None,
        decode: Optional[bool] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> PipelineResult:
        """Run one full round trip."""
        result = PipelineResult(human=text.strip())

        started = time.perf_counter()
        encoded = self.encoder.encode(text, context=context)
        result.timings_ms["encode"] = (time.perf_counter() - started) * 1000.0
        result.encode = encoded
        result.payload = encoded.payload

        started = time.perf_counter()
        execution = self.kernel.execute(encoded.payload, state=state, tools=tools)
        result.timings_ms["execute"] = (time.perf_counter() - started) * 1000.0
        result.execution = execution

        should_decode = self.decoder is not None if decode is None else decode
        if should_decode and self.decoder is not None:
            started = time.perf_counter()
            decoded = self.decoder.decode(execution, request=text)
            result.timings_ms["decode"] = (time.perf_counter() - started) * 1000.0
            result.decode = decoded
            result.response = decoded.text
        else:
            result.response = Decoder.deterministic(execution)
        return result

    __call__ = run

    # -- introspection ---------------------------------------------------
    def describe(self) -> Dict[str, Any]:
        return {
            "encoder": self.encoder.describe(),
            "decoder": self.decoder.describe() if self.decoder else None,
            "tools": self.kernel.available(),
        }
