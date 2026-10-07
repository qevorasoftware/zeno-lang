"""Canonical form: round-trips, idempotence and the density of the output."""

from __future__ import annotations

import pytest

from zeno.ast import Binding, Call, Conditional, Flow, Literal, Path, ScopeBlock
from zeno.emitter import canonicalize, emit, emit_expression
from zeno.parser import parse
from zeno.tokenizer import count_tokens

ROUND_TRIP_CASES = [
    "@LOC[TYO] -> ?WX : { $WX.state == RAIN => !GEN[INDOOR, 3] | !GEN[OUTDOOR, 3] }",
    "@LOC[TYO] -> ?WX : $WX.state == RAIN => !GEN[INDOOR, 3] | !GEN[OUTDOOR, 3]",
    "$PRICE = 129.99\n$QTY = 3\n!PRINT[$PRICE * $QTY]",
    "@AGENT[Coder] {\n  ?REPO -> !RUN[tests]\n  $RESULT ~= \"failed\" => !GEN[Hotfix, 1] | !LOG[green]\n}",
    '@AGENT[Researcher] -> ?SEARCH["Zeno Protocol"] -> !SUMMARIZE[$PREV, 5]',
    "?A -> !B -> $C",
    ": { TRUE => !X | !Y }",
    '@USER[me] -> ?ASK["what is 2 + 2?"] -> !RET[OUT=$PREV]',
    "LET $X = 2 ^ 3 ^ 2",
    '!RET[$WX.state=RAIN, $WX.temp=31, OUT="Museum, Aquarium, Tea house"]',
    "?PRICE[ACME].price < 120 => !ALERT[phone, LOW] | !NOOP",
    "?LEN[[1, 2]] + 1 -> !LOG[$PREV]",
    '"a" == "b" => !X | !Y',
    "?A; ?B; ?C",
]


@pytest.mark.parametrize("source", ROUND_TRIP_CASES)
def test_canonical_form_is_idempotent(source):
    once = canonicalize(source)
    assert canonicalize(once) == once


@pytest.mark.parametrize("source", ROUND_TRIP_CASES)
def test_ast_round_trip(source):
    program = parse(source)
    assert parse(emit(program)) == program


@pytest.mark.parametrize("source", ROUND_TRIP_CASES)
def test_emit_does_not_change_meaning(source):
    assert parse(canonicalize(source)) == parse(source)


def test_canonical_spacing():
    assert canonicalize("@SYS[x]  ->   ?A:{$A==1=>!B|!C}") == "@SYS[x] -> ?A : { $A == 1 => !B | !C }"


def test_braces_are_kept_for_standalone_conditionals():
    assert canonicalize("$A == 1 => !B") == ": { $A == 1 => !B }"


def test_pipeline_conditional_keeps_its_shape():
    assert (
        canonicalize("@A -> ?B : $B == 1 => !C | !D")
        == "@A -> ?B : { $B == 1 => !C | !D }"
    )


def test_numbers_are_normalised():
    assert emit(parse("$X = 3.50")) == "$X = 3.5"
    assert emit(parse("$X = 1e3")) == "$X = 1000"
    assert emit(parse("$X = -2")) == "$X = -2"


def test_strings_are_escaped():
    assert emit(parse('!RET[OUT="say \\"hi\\""]')) == '!RET[OUT="say \\"hi\\""]'
    assert '"a\\nb"' in emit(parse('$X = "a\\nb"'))


def test_scope_block_is_pretty_printed():
    rendered = emit(parse("@A[x] {\n?B\n?C\n}"))
    assert rendered.splitlines()[0] == "@A[x] {"
    assert rendered.splitlines()[-1] == "}"
    assert all(line.startswith("  ") for line in rendered.splitlines()[1:-1])


def test_empty_scope_block_is_compact():
    assert emit(parse("@A[x] { }")) == "@A[x] {}"


def test_explicit_bindings_documentation_form():
    rendered = emit(parse("@A -> ?B -> !C"), explicit_bindings=True)
    assert "$B = ?B" in rendered
    assert rendered.rstrip().endswith("!C")


def test_emit_expression_on_a_path():
    assert emit_expression(Path(("WX", "state"), sigil="$")) == "$WX.state"


def test_emit_expression_on_a_list():
    node = parse("[1, 2]").statements[0].steps[0]
    assert emit_expression(node) == "[1, 2]"


def test_emit_rejects_non_nodes():
    with pytest.raises(TypeError):
        emit_expression("not a node")  # type: ignore[arg-type]


def test_emitter_preserves_state_addressed_keys():
    assert canonicalize("!RET[$WX.temp=31]") == "!RET[$WX.temp=31]"


def test_canonical_example_is_dense(canonical_payload):
    assert canonicalize(canonical_payload) == canonical_payload
    assert count_tokens(canonical_payload) < 60


def test_emitting_a_bare_binding_without_value_is_empty():
    assert emit(Binding(("X",), None)) == ""


def test_emit_program_of_statements(canonical_payload):
    program = parse(f"{canonical_payload}\n?ECHO[done]")
    rendered = emit(program)
    assert rendered.count("\n") == 1


def test_round_trip_keeps_named_arguments():
    source = '!RET[OUT="done", CODE=0, $WX.state=RAIN]'
    assert canonicalize(source) == source


def test_conditional_inside_scope_block(canonical_payload):
    source = f"@AGENT[x] {{\n{canonical_payload}\n}}"
    rendered = canonicalize(source)
    assert "@AGENT[x] {" in rendered
    assert "$WX.state == RAIN" in rendered
