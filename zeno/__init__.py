"""Zeno Protocol — the universal AI language for Agent-to-Agent (A2A) communication.

Zeno is a dense, unambiguous surface syntax that compresses natural-language
instructions into a token-efficient payload, executes them deterministically
against latent state, and expands the result back into human language.

Quick start
-----------

::

    from zeno import Kernel, Encoder, Decoder, Pipeline

    # 1. Deterministic execution
    kernel = Kernel()
    kernel.register_query("WX", lambda args, kwargs, env, call: {"state": "RAIN"})
    result = kernel.execute(
        "@LOC[TYO] -> ?WX : { $WX.state == RAIN => !GEN[INDOOR, 3] | !GEN[OUTDOOR, 3] }"
    )
    print(result.output)

    # 2. Full three-stage round trip
    pipeline = Pipeline()
    outcome = pipeline.run("Check the weather in Tokyo and suggest three indoor ideas.")
    print(outcome.transcript())

Everything below is re-exported for convenience; the submodules remain the
canonical home of each component.
"""

from __future__ import annotations

from .ast import (
    Binding,
    BinaryOp,
    Call,
    Conditional,
    Flow,
    ListLiteral,
    Literal,
    Node,
    Path,
    Program,
    ScopeBlock,
    UnaryOp,
)
from .config import Settings, load_settings
from .decoder import DecodeResult, Decoder, decode
from .emitter import canonicalize, emit, emit_expression
from .encoder import EncodeResult, Encoder, HeuristicEncoder, encode
from .errors import (
    DIAGNOSTICS,
    DivisionByZero,
    EncodeError,
    ProviderError,
    TypeMismatch,
    UndefinedVariable,
    UnknownAction,
    UnresolvedQuery,
    ZenoError,
    ZenoRuntimeError,
    ZenoSyntaxError,
)
from .parser import Parser, parse
from .pipeline import Pipeline, PipelineResult, default_kernel
from .providers import (
    Completion,
    MockProvider,
    NullProvider,
    Provider,
    SequenceProvider,
    list_providers,
    resolve,
)
from .runtime import ExecutionResult, Kernel, StepResult, ToolInvocation, result_frame
from .spec import GRAMMAR_VERSION, SPEC_VERSION, canonical_example, diagnostics, drift_report, tokens
from .tokenizer import count_tokens, counting_method
from .validator import ValidationReport, validate
from .values import Env, render, to_jsonable

__version__ = "0.1.0"
__protocol__ = f"Zeno Grammar {GRAMMAR_VERSION}"

__all__ = [
    "__version__",
    "__protocol__",
    # spec
    "GRAMMAR_VERSION",
    "SPEC_VERSION",
    "canonical_example",
    "diagnostics",
    "drift_report",
    "tokens",
    # syntax
    "Parser",
    "parse",
    "emit",
    "emit_expression",
    "canonicalize",
    "validate",
    "ValidationReport",
    "Node",
    "Program",
    "ScopeBlock",
    "Binding",
    "Flow",
    "Call",
    "Literal",
    "Path",
    "ListLiteral",
    "UnaryOp",
    "BinaryOp",
    "Conditional",
    # execution
    "Kernel",
    "ExecutionResult",
    "StepResult",
    "ToolInvocation",
    "result_frame",
    "Env",
    "render",
    "to_jsonable",
    # agents
    "Encoder",
    "Encoder",
    "EncodeResult",
    "encode",
    "HeuristicEncoder",
    "Decoder",
    "DecodeResult",
    "decode",
    # orchestration
    "Pipeline",
    "PipelineResult",
    "default_kernel",
    # providers
    "Provider",
    "Completion",
    "MockProvider",
    "NullProvider",
    "SequenceProvider",
    "resolve",
    "list_providers",
    "Settings",
    "load_settings",
    "count_tokens",
    "counting_method",
    # errors
    "ZenoError",
    "ZenoSyntaxError",
    "ZenoRuntimeError",
    "EncodeError",
    "ProviderError",
    "UnresolvedQuery",
    "UnknownAction",
    "UndefinedVariable",
    "TypeMismatch",
    "DivisionByZero",
    "DIAGNOSTICS",
]
