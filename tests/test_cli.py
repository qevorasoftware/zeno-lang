"""Command line surface: every subcommand, in-process."""

from __future__ import annotations

import json

import pytest

from zeno.cli import main

CANONICAL = "@LOC[TYO] -> ?WX : { $WX.state == RAIN => !GEN[INDOOR, 3] | !GEN[OUTDOOR, 3] }"


def run(capsys, *argv):
    code = main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_encode_prints_a_payload(capsys):
    code, out, _ = run(capsys, "encode", "book 30 minutes with Amara next week")
    assert code == 0
    assert out.strip().startswith("@") or out.strip().startswith("$")
    # The rule-based encoder is used when no provider is configured.
    assert "!GEN[" in out or "!RET[" in out or "!BOOK[" in out or "!MSG[" in out


def test_encode_json_includes_stats(capsys):
    code, out, _ = run(capsys, "encode", "--json", "weather in Tokyo")
    assert code == 0
    payload = json.loads(out)
    assert payload["payload"].startswith("@LOC[TYO]")
    assert payload["nl_tokens"] > 0
    assert "token_reduction_pct" in payload


def test_encode_with_a_mock_provider(capsys):
    code, out, _ = run(capsys, "encode", "--provider", "mock", "anything")
    assert code == 0
    assert out.strip().startswith("@")


def test_run_executes_a_payload(capsys):
    code, out, err = run(capsys, "run", '!RET[OUT="pong", OK=TRUE]')
    assert code == 0
    assert "!RET[" in out
    assert "pong" in err


def test_run_accepts_seeded_state(capsys):
    code, out, _ = run(capsys, "run", "?LEN[$SEEDED]", "--state", '{"SEEDED": [1, 2]}')
    assert code == 0
    assert "LEN=2" in out


def test_run_json_shape(capsys):
    code, out, _ = run(capsys, "run", "--json", '!RET[OUT=1]')
    payload = json.loads(out)
    assert payload["output"] == 1
    assert payload["frame"].startswith("!RET[")


def test_run_reports_missing_tools_as_an_error(capsys):
    code, out, err = run(capsys, "run", "?UNREGISTERED[1]")
    assert code == 2
    assert "ZN2001" in err


def test_ask_full_pipeline(capsys):
    code, out, _ = run(capsys, "ask", "total 3 * 129.99 + 2 * 45.5")
    assert code == 0
    assert "NL      :" in out
    assert "ZENO    :" in out
    assert "TOKENS  :" in out


def test_ask_json_shape(capsys):
    code, out, _ = run(capsys, "ask", "--json", "total 3 * 129.99 + 2 * 45.5")
    payload = json.loads(out)
    assert payload["encode"]["fell_back"] is True  # no provider configured
    assert payload["execution"]["output"] is not None


def test_ask_can_skip_the_decoder(capsys):
    code, out, _ = run(capsys, "ask", "--no-decode", "total 2 + 2")
    assert code == 0
    assert "OUTPUT  :" in out


def test_check_accepts_a_valid_payload(capsys):
    code, out, _ = run(capsys, "check", CANONICAL, "--canonical")
    assert code == 0
    assert "ok:" in out
    assert CANONICAL in out


def test_check_rejects_an_invalid_payload(capsys):
    code, out, _ = run(capsys, "check", "$A -> ?B : { $X = 1 }")
    assert code == 1
    assert "ZN0005" in out


def test_check_json(capsys):
    code, out, _ = run(capsys, "check", "--json", "$MISSING == 1 => !X")
    payload = json.loads(out)
    assert payload["ok"] is False
    assert payload["diagnostics"][0]["code"] == "ZL0001"


def test_tokens_command(capsys):
    code, out, _ = run(capsys, "tokens", "hello world", CANONICAL)
    assert code == 0
    assert "tokenizer:" in out
    assert len(out.strip().splitlines()) == 3


def test_tokens_json(capsys):
    code, out, _ = run(capsys, "tokens", "--json", "hello")
    payload = json.loads(out)
    assert payload["method"].startswith(("tiktoken:", "estimator:"))
    assert payload["counts"]["hello"] > 0


def test_grammar_command(capsys):
    code, out, _ = run(capsys, "grammar")
    assert code == 0
    assert "ZENO GRAMMAR" in out
    assert "@TARGET" in out or "@TARGET scope" in out


def test_grammar_json_is_the_token_table(capsys):
    code, out, _ = run(capsys, "grammar", "--json")
    payload = json.loads(out)
    assert payload["grammar_version"] == "v0.1"
    assert payload["sigils"][0]["token"] == "@"


def test_providers_command(capsys):
    code, out, _ = run(capsys, "providers")
    assert code == 0
    assert "default provider" in out


def test_providers_json(capsys):
    code, out, _ = run(capsys, "providers", "--json")
    payload = json.loads(out)
    assert "groq" in payload["available"]


def test_benchmark_command(capsys):
    code, out, _ = run(capsys, "benchmark")
    assert code in (0, 1)  # 1 when the corpus misses the brief's target
    assert "TOKEN DENSITY BENCHMARK" in out


def test_latency_command(capsys):
    code, out, _ = run(capsys, "latency", "--repeat", "2")
    assert code == 0
    assert "LATENCY BENCHMARK" in out


def test_missing_command_is_a_usage_error():
    with pytest.raises(SystemExit):
        main([])


def test_tools_module_import(tmp_path, monkeypatch, capsys):
    module = tmp_path / "my_tools.py"
    module.write_text(
        "def tools():\n"
        "    return {'?DOUBLE': lambda args, kwargs, env, call: args[0] * 2}\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    code, out, _ = run(capsys, "run", "?DOUBLE[21]", "--tools", "my_tools:tools")
    assert code == 0
    assert "DOUBLE=42" in out
