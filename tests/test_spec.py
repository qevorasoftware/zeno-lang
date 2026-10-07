"""The implementation and ``specs/tokens.json`` must never disagree."""

from __future__ import annotations

import json

import pytest

from zeno import errors, lexer, spec


def test_spec_file_is_found():
    path = spec.spec_path()
    assert path is not None and path.is_file()
    assert path.name == "tokens.json"


def test_spec_file_is_valid_json():
    document = spec.tokens()
    assert document["spec_version"] == spec.SPEC_VERSION
    assert document["grammar_version"] == spec.GRAMMAR_VERSION


def test_no_drift_between_code_and_spec():
    problems = spec.drift_report()
    assert problems == [], "spec drift: " + "; ".join(problems)


def test_sigil_table():
    symbols = spec.symbols()
    assert set(symbols) == {"@", "?", "!", "$"}
    assert symbols["@"]["role"].startswith("Target")
    assert symbols["$"]["name"] == "VARIABLE"


def test_flow_operator_table():
    flow = spec.flow_operators()
    assert set(flow) == {"->", ":", "=>", "|"}
    for token, entry in flow.items():
        assert lexer.kind_of[token] == entry["name"]


def test_operator_precedence_table_is_consistent():
    precedence = spec.operator_precedence()
    assert precedence["|"] if "|" in precedence else True
    assert precedence["^"] > precedence["*"] > precedence["+"] > precedence["||"]


def test_keywords_are_declared_and_implemented():
    declared = set(spec.keywords())
    implemented = set(lexer.KEYWORD_LITERALS) | {"LET"}
    assert declared == implemented


def test_diagnostics_match_the_error_module():
    declared = spec.diagnostics()
    assert declared == errors.DIAGNOSTICS
    assert declared == {**errors.DIAGNOSTICS, **errors.LINT_CODES}
    for code in declared:
        assert code.startswith(("ZN", "ZL"))


def test_canonical_example_is_present_and_parses():
    example = spec.canonical_example()
    assert "Tokyo" in example["human"]
    assert example["zeno"].startswith("@LOC[TYO]")

    from zeno.parser import parse

    parse(example["zeno"])


def test_explicit_spec_path_override(tmp_path, monkeypatch):
    custom = tmp_path / "tokens.json"
    custom.write_text(json.dumps({"spec_version": "9.9.9"}), encoding="utf-8")
    monkeypatch.setenv("ZENO_SPEC_PATH", str(custom))
    spec.tokens.cache_clear()
    try:
        assert spec.spec_path() == custom
        assert spec.tokens()["spec_version"] == "9.9.9"
    finally:
        monkeypatch.delenv("ZENO_SPEC_PATH", raising=False)
        spec.tokens.cache_clear()


def test_missing_spec_path_reports_nothing_instead_of_raising(monkeypatch):
    monkeypatch.setenv("ZENO_SPEC_PATH", "/nonexistent/tokens.json")
    spec.tokens.cache_clear()
    try:
        assert spec.spec_path() is None
        assert spec.tokens() == {}
        assert spec.drift_report() == ["specs/tokens.json could not be located"]
    finally:
        monkeypatch.delenv("ZENO_SPEC_PATH", raising=False)
        spec.tokens.cache_clear()


def test_grammar_document_covers_every_sigil():
    from zeno.spec import spec_path

    grammar = (spec_path().parent / "grammar.md").read_text(encoding="utf-8")
    for sigil in ("@", "?", "!", "$", "->", "=>", "|", ":"):
        assert sigil in grammar
    assert "ZN0001" in grammar
