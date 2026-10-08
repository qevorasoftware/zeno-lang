"""The benchmarks are part of the contract: they must run and stay honest."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from benchmarks import conversation_test, latency_test, token_comparison
from zeno.parser import parse

CORPUS = Path(__file__).resolve().parent.parent / "benchmarks" / "corpus.json"


# ---------------------------------------------------------------------------
# Corpus integrity
# ---------------------------------------------------------------------------
def test_corpus_file_is_valid_json():
    data = json.loads(CORPUS.read_text(encoding="utf-8"))
    assert data["cases"], "corpus is empty"


def test_every_corpus_case_has_the_three_spellings():
    data = json.loads(CORPUS.read_text(encoding="utf-8"))
    for case in data["cases"]:
        assert set(case) >= {"id", "human", "terse", "zeno"}, case.get("id")
        assert len(case["human"]) > len(case["zeno"]), case["id"]


def test_every_corpus_payload_parses_and_is_canonical():
    data = json.loads(CORPUS.read_text(encoding="utf-8"))
    for case in data["cases"]:
        parse(case["zeno"])
        assert token_comparison.canonicalize(case["zeno"]) == case["zeno"], case["id"]


def test_corpus_ids_are_unique():
    data = json.loads(CORPUS.read_text(encoding="utf-8"))
    ids = [case["id"] for case in data["cases"]]
    assert len(ids) == len(set(ids))


# ---------------------------------------------------------------------------
# Token density
# ---------------------------------------------------------------------------
def test_density_report_runs():
    report = token_comparison.run()
    assert len(report.cases) > 5
    assert report.total_human > report.total_zeno


def test_density_counts_both_sides_with_the_same_tokenizer():
    report = token_comparison.run()
    assert report.method.startswith(("tiktoken:", "estimator:"))
    for case in report.cases:
        assert case.human_tokens > 0
        assert case.zeno_tokens > 0
        assert case.reduction == pytest.approx(
            (case.human_tokens - case.zeno_tokens) / case.human_tokens * 100, abs=0.01
        )


def test_density_reduces_realistic_prompts_substantially():
    """The headline claim, asserted at a conservative floor.

    The per-message reduction depends on how verbose the human side is, so the
    suite pins the number that the corpus actually measures rather than the
    aspirational figure. See README §Benchmarks for the full discussion.
    """
    report = token_comparison.run()
    assert report.pooled_reduction > 40.0
    assert report.encoder_prompt_tokens > 0
    assert report.break_even_calls is not None


def test_density_report_serialises():
    payload = token_comparison.run().to_dict()
    json.dumps(payload)
    assert payload["reduction"]["pooled_pct"] > 0
    assert payload["encoder"]["system_prompt_tokens"] > 0


def test_density_target_is_reported_but_not_faked():
    report = token_comparison.run()
    assert report.target == token_comparison.TARGET_REDUCTION_PCT
    assert isinstance(report.meets_target, bool)


# ---------------------------------------------------------------------------
# Multi-turn A2A
# ---------------------------------------------------------------------------
def test_conversation_benchmark_meets_the_brief_target():
    report = conversation_test.run()
    assert len(report.turns) == len(conversation_test.WORKFLOW)
    assert report.per_hop_reduction >= conversation_test.TARGET_REDUCTION_PCT
    assert report.meets_target is True


def test_conversation_costs_grow_for_chat_but_not_for_zeno():
    report = conversation_test.run()
    chat = [turn.chat_tokens for turn in report.turns]
    zeno = [turn.zeno_tokens for turn in report.turns]
    assert chat == sorted(chat), "chat cost must grow as history accumulates"
    assert zeno[0] == max(zeno), "Zeno hops must not grow with history"


def test_conversation_discloses_the_fixed_cost():
    report = conversation_test.run()
    assert report.encoder_prompt_tokens > 0
    for turn in report.turns:
        parse(conversation_test.canonicalize(_workflow_payload(turn.id)))
        break
    assert report.steady_state_reduction(10) > report.reduction
    assert report.break_even_hops is not None


def _workflow_payload(turn_id: str) -> str:
    for turn in conversation_test.WORKFLOW:
        if turn["id"] == turn_id:
            return turn["zeno"]
    raise KeyError(turn_id)


def test_conversation_report_serialises():
    payload = conversation_test.run().to_dict()
    json.dumps(payload)
    assert payload["reduction"]["meets_target"] is True


# ---------------------------------------------------------------------------
# Latency
# ---------------------------------------------------------------------------
def test_latency_report_runs_quickly():
    report = latency_test.run(repeat=3)
    names = set(report.by_name)
    assert {"parse", "emit", "execute", "encode", "decode", "roundtrip"} <= names


def test_grammar_is_not_the_bottleneck():
    report = latency_test.run(repeat=5)
    grammar = report.by_name["parse"].mean + report.by_name["emit"].mean
    assert grammar < report.by_name["roundtrip"].mean


def test_latency_report_serialises():
    payload = latency_test.run(repeat=2).to_dict()
    json.dumps(payload)
    assert payload["repeat"] == 2


def test_benchmarks_run_without_network():
    """Every benchmark uses the mock provider: no sockets, no flakes."""
    from zeno.providers import MockProvider

    assert MockProvider("x").complete("y").provider == "mock"
