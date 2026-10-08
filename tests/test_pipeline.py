"""The three-stage pipeline, the tokenizer and the tool registry."""

from __future__ import annotations

import json

import pytest

from zeno.encoder import Encoder
from zeno.errors import ZenoError
from zeno.pipeline import Pipeline, PipelineResult, default_kernel
from zeno.providers import MockProvider, NullProvider
from zeno.tokenizer import count_tokens, counting_method
from zeno.tools import demo_generator, demo_tools

CANONICAL = "@LOC[TYO] -> ?WX : { $WX.state == RAIN => !GEN[INDOOR, 3] | !GEN[OUTDOOR, 3] }"


# ---------------------------------------------------------------------------
# Tokenizer
# ---------------------------------------------------------------------------
def test_counting_method_is_labelled():
    method = counting_method()
    assert method.startswith(("tiktoken:", "estimator:")), method


def test_counts_are_positive_and_monotonic():
    assert count_tokens("") == 0
    short = count_tokens("hello")
    longer = count_tokens("hello there, general kenobi")
    assert 0 < short <= longer


def test_zeno_payload_is_counted_as_tokens():
    tokens = count_tokens(CANONICAL)
    assert 10 < tokens < 80


def test_estimator_is_deterministic():
    assert count_tokens(CANONICAL) == count_tokens(CANONICAL)


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------
def test_demo_tools_are_stable():
    first = demo_tools()
    second = demo_tools()
    assert sorted(first) == sorted(second)
    assert "?WX" in first and "!SEND" in first


def test_demo_tools_do_not_shadow_kernel_builtins():
    kernel = default_kernel()
    builtin_queries = set(kernel.queries)
    for name in demo_tools():
        assert name not in builtin_queries or builtin_queries.intersection({name}) == set(), (
            f"{name} would override a built-in"
        )


def test_demo_generator_is_deterministic():
    assert demo_generator("IDEA", 3, {}, None) == ["IDEA 1", "IDEA 2", "IDEA 3"]


def test_demo_tools_execute_the_canonical_example():
    kernel = default_kernel(tools=demo_tools(), generator=demo_generator)
    result = kernel.execute(CANONICAL)
    assert result.output == ["INDOOR 1", "INDOOR 2", "INDOOR 3"]


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------
def test_pipeline_runs_all_three_stages(mock_provider):
    pipe = Pipeline(encoder=Encoder(mock_provider), kernel=default_kernel(tools=demo_tools(), generator=demo_generator))
    outcome = pipe.run("weather in Tokyo?")
    assert outcome.payload == CANONICAL
    assert outcome.execution.output == ["INDOOR 1", "INDOOR 2", "INDOOR 3"]
    assert outcome.response
    assert set(outcome.timings_ms) >= {"encode", "execute", "decode"}


def test_pipeline_can_skip_the_decoder(mock_provider):
    pipe = Pipeline(encoder=Encoder(mock_provider), kernel=default_kernel(tools=demo_tools(), generator=demo_generator))
    outcome = pipe.run("weather in Tokyo?", decode=False)
    # Skipping the decoder still yields a deterministic rendering, never an
    # empty answer: `decode=None` marks that no model was called.
    assert outcome.decode is None
    assert "INDOOR 1" in outcome.response


def test_pipeline_registers_tools(mock_provider):
    pipe = Pipeline(encoder=Encoder(mock_provider), kernel=default_kernel())
    pipe.register_query("DOUBLE", lambda args, kwargs, env, call: args[0] * 2)
    assert pipe.kernel.execute("?DOUBLE[21]").output == 42


def test_pipeline_transcript_and_dict(mock_provider):
    outcome = Pipeline(
        encoder=Encoder(mock_provider), kernel=default_kernel(tools=demo_tools(), generator=demo_generator)
    ).run("weather in Tokyo?")
    transcript = outcome.transcript()
    for label in ("NL      :", "ZENO    :", "OUTPUT  :", "LATENCY :", "TOKENS  :"):
        assert label in transcript
    payload = outcome.to_dict()
    json.dumps(payload)
    assert payload["payload"] == CANONICAL
    assert payload["encode"]["nl_tokens"] == outcome.encode.nl_tokens
    assert payload["encode"]["zeno_tokens"] == outcome.encode.zeno_tokens
    assert payload["execution"]["output"] == ["INDOOR 1", "INDOOR 2", "INDOOR 3"]


def test_pipeline_result_ok_flag():
    assert PipelineResult(human="x", payload="!RET[1]").ok is False  # no execution yet


def test_pipeline_needs_a_provider_or_falls_back():
    # NullProvider is not available, so the rule-based encoder takes over.
    outcome = Pipeline(provider=NullProvider(), kernel=default_kernel(tools=demo_tools(), generator=demo_generator)).run(
        "Check the weather in Tokyo."
    )
    assert outcome.encode.fell_back is True
    assert outcome.execution.errors == [] or outcome.execution.output is not None


def test_default_kernel_has_builtins():
    kernel = default_kernel()
    assert {"LEN", "COUNT", "TYPE", "STR"} <= set(kernel.queries)
    assert {"RET", "LOG", "PRINT", "GEN", "NOOP"} <= set(kernel.actions)


def test_pipeline_rejects_unparseable_model_output():
    pipe = Pipeline(encoder=Encoder(MockProvider("not a payload at all"), fallback=False))
    with pytest.raises(ZenoError):
        pipe.run("does not matter")
