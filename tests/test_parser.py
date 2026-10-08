"""Parser behaviour: the brief's examples, AST shape, and diagnostics."""

from __future__ import annotations

import pytest

from zeno.ast import Binding, Call, Conditional, Flow, Literal, Path, Program, ScopeBlock
from zeno.errors import (
    MissingThenBranch,
    StrayElse,
    UnbalancedDelimiter,
    ZenoSyntaxError,
)
from zeno.parser import Parser, parse

from .conftest import CANONICAL


# ---------------------------------------------------------------------------
# The examples from the brief
# ---------------------------------------------------------------------------
def test_canonical_example_parses(canonical_payload):
    program = parse(canonical_payload)
    assert isinstance(program, Program)
    assert len(program.statements) == 1
    flow = program.statements[0]
    assert isinstance(flow, Flow)
    assert flow.scope.name == "LOC"
    assert [step.name for step in flow.steps] == ["WX"]
    assert isinstance(flow.conditional, Conditional)


def test_scope_block_example():
    program = parse(
        "@AGENT[Coder] {\n  ?REPO -> !RUN[tests]\n"
        '  $RESULT ~= "failed" => !GEN[Hotfix, 1] | !LOG[green]\n}'
    )
    block = program.statements[0]
    assert isinstance(block, ScopeBlock)
    assert block.call.name == "AGENT"
    assert len(block.body) == 2


def test_pipeline_example():
    flow = parse("@LOC[TYO] -> ?WX -> !GEN[OUTDOOR]").statements[0]
    assert [step.name for step in flow.steps] == ["WX", "GEN"]


def test_binding_example():
    statements = parse("$PRICE = 129.99\n$QTY = 3").statements
    assert all(isinstance(statement, Binding) for statement in statements)
    assert statements[0].path == ("PRICE",)
    assert isinstance(statements[0].value, Literal)


def test_let_prefix_is_recorded():
    binding = parse("LET $X = 2").statements[0]
    assert binding.explicit is True
    assert parse("$X = 2").statements[0].explicit is False


# ---------------------------------------------------------------------------
# Structure
# ---------------------------------------------------------------------------
def test_multiple_statements_on_one_line():
    program = parse("?A; ?B; ?C")
    assert [statement.steps[0].name for statement in program.statements] == ["A", "B", "C"]


def test_comments_and_blank_lines():
    program = parse("# comment\n\n?A\n# another\n?B\n")
    assert len(program.statements) == 2


def test_named_arguments():
    call = parse('!RET[OUT="done", CODE=0]').statements[0].steps[0]
    kwargs = dict(call.kwargs)
    assert kwargs["CODE"].value == 0
    assert kwargs["OUT"].value == "done"
    assert call.args == ()


def test_state_addressed_named_argument():
    call = parse("!RET[$WX.state=RAIN]").statements[0].steps[0]
    assert call.kwargs[0][0] == "WX.state"


def test_dotted_query_result():
    flow = parse("?PRICE[ACME].price").statements[0]
    node = flow.steps[0]
    assert type(node).__name__ == "Attr"
    assert node.parts == ("price",)


def test_call_inside_expression():
    flow = parse("?LEN[[1,2,3]] + 1").statements[0]
    assert type(flow.steps[0]).__name__ == "BinaryOp"


def test_comparison_step_is_an_expression():
    flow = parse("?PRICE[ACME] < 120 => !ALERT").statements[0]
    assert isinstance(flow.conditional, Conditional)
    assert type(flow.conditional.test).__name__ == "BinaryOp"


def test_operator_precedence():
    node = parse("$X = 1 + 2 * 3").statements[0].value
    assert node.op == "+"
    assert node.right.op == "*"


def test_power_is_right_associative():
    node = parse("$X = 2 ^ 3 ^ 2").statements[0].value
    assert node.op == "^"
    assert node.right.op == "^"


def test_parentheses_override_precedence():
    node = parse("$X = (1 + 2) * 3").statements[0].value
    assert node.op == "*"
    assert node.left.op == "+"


def test_implicit_binding_is_annotated():
    flow = parse("@LOC[TYO] -> ?WX : { $WX.state == RAIN => !GEN[INDOOR, 3] }").statements[0]
    assert flow.steps[0].implicit_binding is True


def test_last_step_without_reader_is_not_annotated():
    flow = parse("@SYS[PING] -> ?WX").statements[0]
    assert flow.steps[0].implicit_binding is False


def test_result_frame_shape():
    call = parse('!RET[$WX.state=RAIN, $WX.temp=31, OUT="Museum, Aquarium"]').statements[0].steps[0]
    keys = [key for key, _ in call.kwargs]
    assert keys == ["WX.state", "WX.temp", "OUT"]


def test_bare_conditional_form():
    flow = parse("$WX == RAIN => !INDOOR | !OUTDOOR").statements[0]
    assert isinstance(flow.conditional, Conditional)
    assert flow.conditional.braced is False


def test_braced_and_bare_conditionals_produce_the_same_ast():
    braced = parse("@A -> ?B : { $B == 1 => !C | !D }").statements[0].conditional
    bare = parse("@A -> ?B : $B == 1 => !C | !D").statements[0].conditional
    # `braced` records the source form and is excluded from equality.
    assert braced == bare
    assert (braced.braced, bare.braced) == (True, False)


def test_nested_conditional():
    conditional = parse(": { $A => : { $B => !C | !D } | !E }").statements[0].conditional
    assert isinstance(conditional.then_branch.conditional, Conditional)


def test_soft_newlines_inside_brackets_and_conditionals():
    payload = """@AGENT[X] -> ?QUERY[
        "multi word",
        2
    ] : {
        $QUERY.count > 1
        => !GEN[REPORT, 2]
        | !LOG[quiet]
    }"""
    flow = parse(payload).statements[0]
    assert len(flow.steps[0].args) == 2


def test_newlines_are_statement_separators_in_scope_blocks():
    block = parse("@A[x] {\n ?B\n ?C\n}").statements[0]
    assert len(block.body) == 2


def test_statements_produce_spans():
    program = parse("?A\n?B")
    assert program.statements[1].line == 2
    assert program.statements[0].span.text == "?A"


def test_parser_accepts_pretokenized_input():
    from zeno.lexer import tokenize

    source = "@A -> ?B"
    assert Parser(source, tokenize(source)).parse_program() == parse(source)


# ---------------------------------------------------------------------------
# Diagnostics
# ---------------------------------------------------------------------------
def test_missing_then_branch_is_zn0005():
    with pytest.raises(MissingThenBranch) as excinfo:
        parse("$A -> ?B : { $X = 1 }")
    assert excinfo.value.code == "ZN0005"


def test_stray_else_is_zn0006():
    with pytest.raises(StrayElse) as excinfo:
        parse("!A | !B")
    assert excinfo.value.code == "ZN0006"


def test_unclosed_argument_list_is_zn0004():
    with pytest.raises(UnbalancedDelimiter) as excinfo:
        parse("!GEN[INDOOR, 3")
    assert excinfo.value.code == "ZN0004"


def test_unclosed_scope_block_is_zn0004():
    with pytest.raises(UnbalancedDelimiter):
        parse("@A[x] {\n ?B\n")


def test_unclosed_group_is_zn0004():
    with pytest.raises(UnbalancedDelimiter):
        parse("$X = (1 + 2")


def test_trailing_arrow_is_zn0003():
    with pytest.raises(ZenoSyntaxError) as excinfo:
        parse("@LOC[TYO] ->")
    assert excinfo.value.code == "ZN0003"


def test_scope_without_operation_is_rejected():
    with pytest.raises(ZenoSyntaxError):
        parse("@LOC[TYO]")


def test_error_carries_line_and_column():
    with pytest.raises(ZenoSyntaxError) as excinfo:
        parse("?A\n@B -> ")
    error = excinfo.value
    assert error.span is not None
    assert error.span.start.line == 2


def test_error_render_includes_source_preview():
    with pytest.raises(ZenoSyntaxError) as excinfo:
        parse("$A -> ?B : { $X = 1 }")
    rendered = excinfo.value.render()
    assert "$A -> ?B" in rendered
    assert "ZN0005" in rendered
    assert "hint:" in rendered


def test_error_serialises_to_dict():
    with pytest.raises(ZenoSyntaxError) as excinfo:
        parse("@LOC[TYO] ->")
    payload = excinfo.value.to_dict()
    assert payload["code"] == "ZN0003"
    assert payload["location"]["line"] == 1


def test_empty_payload_is_an_empty_program():
    assert parse("   \n\n# only a comment\n").statements == ()
