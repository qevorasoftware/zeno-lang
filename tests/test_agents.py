"""Encoder, decoder, provider and validator behaviour."""

from __future__ import annotations

import pytest

from zeno.config import Settings, load_settings
from zeno.decoder import Decoder
from zeno.encoder import Encoder, HeuristicEncoder
from zeno.errors import EncodeError, ProviderError, ZenoError
from zeno.providers import (
    MockProvider,
    NullProvider,
    SequenceProvider,
    list_providers,
    resolve,
)
from zeno.runtime import Kernel
from zeno.validator import validate

CANONICAL = "@LOC[TYO] -> ?WX : { $WX.state == RAIN => !GEN[INDOOR, 3] | !GEN[OUTDOOR, 3] }"


# ---------------------------------------------------------------------------
# Providers
# ---------------------------------------------------------------------------
def test_null_provider_is_not_available():
    provider = NullProvider()
    assert provider.available() is False
    with pytest.raises(ProviderError):
        provider.complete("hello")


def test_mock_provider_cycles_responses():
    provider = MockProvider(["one", "two"])
    assert provider.complete("x").text == "one"
    assert provider.complete("x").text == "two"
    assert provider.complete("x").text == "one"


def test_mock_provider_counts_tokens():
    completion = MockProvider("hello there").complete("say hi")
    assert completion.prompt_tokens > 0
    assert completion.completion_tokens > 0
    assert completion.provider == "mock"


def test_sequence_provider_records_prompts():
    provider = SequenceProvider(["a", "b"])
    provider.complete("first")
    provider.complete("second")
    assert provider.calls == ["first", "second"]


def test_provider_registry_covers_the_documented_slugs():
    known = list_providers()
    for slug in ("openai", "groq", "ollama", "mock", "none", "custom"):
        assert slug in known


def test_resolve_returns_null_when_nothing_is_configured(monkeypatch):
    for variable in ("ZENO_PROVIDER", "OPENAI_API_KEY", "GROQ_API_KEY", "TOGETHER_API_KEY",
                     "OPENROUTER_API_KEY", "ZENO_BASE_URL", "ZENO_API_KEY"):
        monkeypatch.delenv(variable, raising=False)
    assert isinstance(resolve(), NullProvider)


def test_resolve_autodetects_a_key(monkeypatch):
    monkeypatch.delenv("ZENO_PROVIDER", raising=False)
    monkeypatch.setenv("GROQ_API_KEY", "test-key")
    provider = resolve()
    assert provider.name == "groq"
    assert provider.available() is True


def test_resolve_passes_through_instances():
    provider = MockProvider("x")
    assert resolve(provider) is provider


def test_settings_redacts_the_key():
    settings = Settings(provider="openai", api_key="sk-secret")
    assert settings.to_dict()["api_key"] == "***"
    assert settings.to_dict(redact=False)["api_key"] == "sk-secret"


def test_settings_prefers_explicit_overrides():
    settings = load_settings(provider="ollama", model="llama3.2")
    assert settings.provider == "ollama"
    assert settings.model == "llama3.2"


def test_env_settings_are_coerced(monkeypatch):
    monkeypatch.setenv("ZENO_MAX_REPAIRS", "5")
    monkeypatch.setenv("ZENO_TIMEOUT", "12.5")
    settings = load_settings()
    assert settings.max_repairs == 5
    assert settings.timeout == 12.5


def test_load_dotenv(tmp_path, monkeypatch):
    from zeno.config import load_dotenv

    env_file = tmp_path / ".env"
    env_file.write_text("ZENO_TEST_VALUE=42\n# comment\n", encoding="utf-8")
    monkeypatch.delenv("ZENO_TEST_VALUE", raising=False)
    applied = load_dotenv(env_file)
    assert applied["ZENO_TEST_VALUE"] == "42"


# ---------------------------------------------------------------------------
# Encoder
# ---------------------------------------------------------------------------
def test_encoder_returns_a_canonical_payload(mock_provider):
    result = Encoder(mock_provider).encode("weather in Tokyo?")
    assert result.payload == CANONICAL
    assert result.fell_back is False
    assert result.report.ok


def test_encoder_strips_markdown_fences():
    provider = MockProvider(f"```zeno\n{CANONICAL}\n```")
    assert Encoder(provider).encode("q").payload == CANONICAL


def test_encoder_strips_labels_and_preamble():
    provider = MockProvider(f"Sure! Here you go:\n\nZENO: {CANONICAL}\n\nLet me know!")
    assert Encoder(provider).encode("q").payload == CANONICAL


def test_encoder_repairs_invalid_output():
    provider = SequenceProvider(["this is not a payload", CANONICAL])
    result = Encoder(provider).encode("weather")
    assert result.payload == CANONICAL
    assert result.attempts == 2


def test_encoder_gives_up_with_zn1001():
    provider = MockProvider("still not zeno at all")
    with pytest.raises(EncodeError) as excinfo:
        Encoder(provider, fallback=False, max_repairs=1).encode("weather")
    assert excinfo.value.code == "ZN1001"


def test_encoder_falls_back_to_rules_without_a_provider():
    result = Encoder(NullProvider(), tools=None).encode("What is the weather in Paris?")
    assert result.fell_back is True
    assert "@LOC[PAR]" in result.payload
    assert result.report.ok


def test_encoder_fallback_can_be_disabled():
    with pytest.raises(ProviderError):
        Encoder(NullProvider(), fallback=False).encode("hi")


def test_encoder_rejects_empty_input(mock_provider):
    with pytest.raises(EncodeError):
        Encoder(mock_provider).encode("   ")


def test_encoder_reports_token_stats(mock_provider):
    result = Encoder(mock_provider).encode(
        "Please check whether it is raining in Tokyo right now and suggest three indoor things to do"
    )
    assert result.nl_tokens > 0
    assert result.zeno_tokens > 0
    assert result.prompt_tokens > 0
    assert isinstance(result.token_reduction, float)


def test_encoder_prompt_lists_available_tools(mock_provider):
    encoder = Encoder(mock_provider, tools=["?WX", "!GEN"])
    assert "?WX" in encoder.system_prompt()
    assert "!GEN" in encoder.system_prompt()


def test_encoder_describes_itself(mock_provider):
    described = Encoder(mock_provider).describe()
    assert described["provider"]["provider"] == "mock"
    assert "tokenizer" in described


def test_encoder_keeps_the_raw_model_output():
    provider = MockProvider(f"```\n{CANONICAL}\n```")
    assert CANONICAL in Encoder(provider).encode("q").raw


# ---------------------------------------------------------------------------
# Heuristic encoder
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "text,expected_fragment",
    [
        ("What's the weather like in Tokyo?", "@LOC[TYO]"),
        ("Check the weather in San Francisco today", "@LOC[SFO]"),
        ("weather in Ahmedabad please", "@LOC[AMD]"),
        ("Is it raining in Berlin?", "@LOC[BER]"),
    ],
)
def test_heuristic_weather(text, expected_fragment):
    assert expected_fragment in HeuristicEncoder().encode(text)


def test_heuristic_arithmetic():
    payload = HeuristicEncoder().encode("Calculate 3 * 129.99 + 2 * 45.50")
    assert "$TOTAL = " in payload
    assert "!RET[" in payload
    assert validate(payload).ok


def test_heuristic_falls_back_to_a_generation_request():
    payload = HeuristicEncoder().encode("Write a haiku about rain")
    assert payload.startswith("@")
    assert "!GEN[" in payload
    assert validate(payload).ok


def test_heuristic_output_is_always_parseable():
    from zeno.parser import parse

    for text in [
        "hello",
        "summarise the meeting notes from last week",
        'quote "unusual" characters \\ and more',
        "weather in Tokyo and also 3 + 4",
    ]:
        parse(HeuristicEncoder().encode(text))


# ---------------------------------------------------------------------------
# Decoder
# ---------------------------------------------------------------------------
@pytest.fixture
def execution(weather_kernel) -> object:
    return weather_kernel.execute(CANONICAL)


def test_decoder_uses_the_provider(execution):
    provider = MockProvider("It is raining in Tokyo, so here are three indoor ideas.")
    result = Decoder(provider).decode(execution, request="weather?")
    assert result.text.startswith("It is raining")
    assert result.fell_back is False


def test_decoder_falls_back_deterministically(execution):
    result = Decoder(NullProvider()).decode(execution, request="weather?")
    assert result.fell_back is True
    assert "INDOOR-0" in result.text or "INDOOR" in result.text


def test_decoder_accepts_a_payload_string():
    result = Decoder(NullProvider()).decode('!RET[OUT="done"]')
    assert "done" in result.text


def test_decoder_accepts_a_dict():
    result = Decoder(NullProvider()).decode({"output": [1, 2], "bindings": {"X": 1}})
    assert "1" in result.text and "2" in result.text


def test_decoder_rejects_other_types():
    with pytest.raises(TypeError):
        Decoder(NullProvider()).decode(42)  # type: ignore[arg-type]


def test_decoder_prompt_contains_the_request(execution):
    prompt = Decoder(MockProvider("x")).build_prompt(execution, request="What is the weather?")
    assert "What is the weather?" in prompt
    assert "EXECUTION RESULT" in prompt


def test_decoder_strips_answer_prefixes():
    provider = MockProvider("ANSWER: it is raining")
    assert Decoder(provider).decode(Kernel().execute('!RET[OUT=1]'), request="q").text == (
        "it is raining"
    )


def test_deterministic_rendering_of_mappings():
    result = Kernel().execute('!RET[A=1, B="two words", OUT=NIL]')
    text = Decoder.deterministic(result)
    assert "two words" in text


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------
def test_valid_payload_has_no_diagnostics():
    report = validate("@LOC[TYO] -> ?WX : { $WX.state == RAIN => !GEN[INDOOR, 3] }")
    assert report.ok
    assert report.diagnostics == []


def test_undefined_variable_is_flagged():
    report = validate(": { $MISSING == 1 => !X }")
    assert not report.ok
    assert any(d.code == "ZL0001" for d in report.errors)


def test_missing_terminal_action_is_flagged():
    report = validate("?A")
    assert any(d.code == "ZL0004" for d in report.warnings)
    assert report.ok  # a warning, not an error


def test_empty_scope_block_is_flagged():
    report = validate("@A[x] { }")
    assert any(d.code == "ZL0003" for d in report.diagnostics)


def test_shadowing_atom_is_flagged():
    report = validate('$RAIN = 1\n!RET[$RAIN, RAIN]')
    assert any(d.code == "ZL0005" for d in report.warnings)


def test_parse_failure_is_reported_without_raising():
    report = validate("@LOC[TYO] ->")
    assert not report.ok
    assert report.error is not None
    assert report.program is None


def test_report_serialises_and_renders():
    report = validate("?A")
    assert report.to_dict()["ok"] is True
    assert "ZL0004" in report.render()


def test_validator_accepts_the_whole_corpus():
    import json
    from pathlib import Path

    corpus = Path(__file__).resolve().parent.parent / "benchmarks" / "corpus.json"
    data = json.loads(corpus.read_text(encoding="utf-8"))
    for case in data["cases"]:
        report = validate(case["zeno"])
        assert report.error is None, f"{case['id']}: {report.error}"
        assert not report.errors, f"{case['id']}: {[d.message for d in report.errors]}"
