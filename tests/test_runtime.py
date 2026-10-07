"""Kernel behaviour: evaluation, bindings, scopes, frames and diagnostics."""

from __future__ import annotations

import pytest

from zeno.errors import (
    DivisionByZero,
    TypeMismatch,
    UndefinedVariable,
    UnknownAction,
    UnresolvedQuery,
    ZenoRuntimeError,
)
from zeno.runtime import ExecutionResult, Kernel, result_frame
from zeno.values import Env, render, to_jsonable, truthy


@pytest.fixture
def kernel() -> Kernel:
    return Kernel()


# ---------------------------------------------------------------------------
# Expressions
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "expression,expected",
    [
        ("1 + 2", 3),
        ("7 - 2", 5),
        ("3 * 4", 12),
        ("7 / 2", 3.5),
        ("10 % 3", 1),
        ("2 ^ 10", 1024),
        ("2 ^ 3 ^ 2", 512),  # right associative
        ("-3 + 1", -2),
        ("(1 + 2) * 3", 9),
        ("1 < 2", True),
        ("2 <= 2", True),
        ("3 > 4", False),
        ('"a" == "a"', True),
        ('"RAIN" == rain', True),
        ('"rain" != snow', True),
        ('"the deploy failed" ~= failed', True),
        ("[1, 2] + [3]", [1, 2, 3]),
        ('"a" + "b"', "ab"),
        ("~FALSE", True),
        ("TRUE && FALSE", False),
        ("TRUE || FALSE", True),
        ("FALSE && ?MISSING[1]", False),  # short circuits before the query
    ],
)
def test_expression_semantics(kernel, expression, expected):
    assert kernel.evaluate(expression) == expected


def test_bare_atoms_are_symbols(kernel):
    # Inside an expression an unbound bare name is a self-describing symbol.
    assert kernel.execute("!RET[RAIN]").output == "RAIN"
    assert kernel.execute("$A = RAIN\n!RET[$A == RAIN]").output is True
    assert kernel.evaluate("?LEN[[a, b, c]]") == 3


def test_bare_atom_is_not_a_valid_step(kernel):
    from zeno.errors import ZenoSyntaxError

    with pytest.raises(ZenoSyntaxError):
        kernel.execute("RAIN")


def test_unsupported_construct_raises_syntax_error(kernel):
    from zeno.errors import ZenoSyntaxError

    with pytest.raises(ZenoSyntaxError):
        kernel.evaluate("!PRINT[1")


# ---------------------------------------------------------------------------
# Diagnostics
# ---------------------------------------------------------------------------
def test_division_by_zero(kernel):
    with pytest.raises(DivisionByZero) as excinfo:
        kernel.evaluate("1 / 0")
    assert excinfo.value.code == "ZN2005"


def test_modulo_by_zero(kernel):
    with pytest.raises(DivisionByZero):
        kernel.evaluate("1 % 0")


def test_type_mismatch(kernel):
    with pytest.raises(TypeMismatch) as excinfo:
        kernel.evaluate('"a" - 1')
    assert excinfo.value.code == "ZN2004"


def test_comparing_incomparable_types(kernel):
    with pytest.raises(TypeMismatch):
        kernel.evaluate("$X = ?ENV[1].nope > 2")


def test_undefined_variable(kernel):
    with pytest.raises(UndefinedVariable) as excinfo:
        kernel.evaluate("$NOPE + 1")
    assert excinfo.value.code == "ZN2003"


def test_unresolved_query(kernel):
    with pytest.raises(UnresolvedQuery) as excinfo:
        kernel.evaluate("?NOPE[1]")
    assert excinfo.value.code == "ZN2001"


def test_unknown_action(kernel):
    with pytest.raises(UnknownAction) as excinfo:
        kernel.evaluate("!NOPE[1]")
    assert excinfo.value.code == "ZN2002"


def test_lenient_mode_records_instead_of_raising():
    kernel = Kernel(strict_queries=False)
    result = kernel.execute("@SYS[x] -> ?NOPE")
    assert result.output is None
    assert any("NOPE" in message for message in result.errors)


# ---------------------------------------------------------------------------
# Flows, bindings, scopes
# ---------------------------------------------------------------------------
def test_implicit_binding(weather_kernel):
    result = weather_kernel.execute("@LOC[TYO] -> ?WX")
    assert result.binding("WX") == {"state": "RAIN", "temp": 18}
    assert result.state["WX"]["state"] == "RAIN"


def test_previous_value_is_available(weather_kernel):
    result = weather_kernel.execute("?WX -> !PRINT[$PREV.state]")
    assert result.output == "RAIN"


def test_conditional_takes_the_true_branch(weather_kernel):
    result = weather_kernel.execute(
        "@LOC[TYO] -> ?WX : { $WX.state == RAIN => !PRINT[INDOOR] | !PRINT[OUTDOOR] }"
    )
    assert result.output == "INDOOR"


def test_conditional_takes_the_false_branch(weather_kernel):
    weather_kernel.register_query("WX", lambda args, kwargs, env, call: {"state": "CLEAR"})
    result = weather_kernel.execute(
        "@LOC[TYO] -> ?WX : { $WX.state == RAIN => !PRINT[INDOOR] | !PRINT[OUTDOOR] }"
    )
    assert result.output == "OUTDOOR"


def test_conditional_without_else_yields_nothing(weather_kernel):
    weather_kernel.register_query("WX", lambda args, kwargs, env, call: {"state": "CLEAR"})
    result = weather_kernel.execute("@LOC[TYO] -> ?WX : { $WX.state == RAIN => !PRINT[INDOOR] }")
    assert result.output is None


def test_scope_is_written_into_state(weather_kernel):
    result = weather_kernel.execute("@LOC[TYO] -> ?WX", state={"USER": "amara"})
    assert result.state["LOC"] == "TYO"
    assert result.state["USER"] == "amara"


def test_scope_block_scopes_are_recorded(kernel):
    result = kernel.execute('@AGENT[Coder] {\n  ?LEN[[1,2,3]] -> !LOG["ok"]\n}')
    assert result.scopes == [("AGENT",)]
    assert result.state["AGENT"] == "Coder"


def test_nested_pipelines_run_left_to_right(kernel):
    order = []
    kernel.register_query("STEP", lambda args, kwargs, env, call: order.append("query") or 1)
    kernel.register_action("MARK", lambda args, kwargs, env, call: order.append("action"))
    kernel.execute("?STEP -> !MARK")
    assert order == ["query", "action"]


def test_ret_terminates_the_payload(kernel):
    result = kernel.execute('!RET[OUT="stop"]\n!PRINT["never"]')
    assert result.returned is True
    assert result.output == "stop"
    assert all(step.name != "PRINT" for step in result.steps)


def test_ret_named_arguments_become_bindings(kernel):
    result = kernel.execute("$T = 480.97\n$T > 500 => !RET[BUDGET=OVER, $T] | !RET[BUDGET=UNDER, $T]")
    assert result.binding("BUDGET") == "UNDER"
    assert result.output == 480.97


def test_binding_statement_records_state(kernel):
    result = kernel.execute("$PRICE = 10\n!PRINT[$PRICE * 2]")
    assert result.binding("PRICE") == 10
    assert result.output == 20


def test_seeded_state_is_readable_case_insensitively(kernel):
    result = kernel.execute("?LEN[$SEEDED]", state={"seeded": [1, 2, 3]})
    assert result.output == 3


def test_state_addressed_kwarg_writes_nested_state(kernel):
    result = kernel.execute('!RET[$WX.state=RAIN, OUT="Museum"]')
    assert result.state["WX"] == {"state": "RAIN"}
    assert result.binding("WX.state") == "RAIN"
    assert result.output == "Museum"


def test_assert_failure_raises(kernel):
    with pytest.raises(ZenoRuntimeError):
        kernel.execute("!ASSERT[FALSE, blocked]")


def test_tools_can_be_passed_per_call(kernel):
    result = kernel.execute("?DOUBLE[21]", tools={"?DOUBLE": lambda args, kwargs, env, call: args[0] * 2})
    assert result.output == 42


def test_tools_are_restored_after_a_call(kernel):
    kernel.execute("?TEMP[1]", tools={"?TEMP": lambda args, *rest: 1})
    assert "TEMP" not in kernel.queries


def test_generator_hook_is_used(kernel):
    kernel.generator = lambda topic, count, kwargs, env: [f"{topic}{index}" for index in range(count)]
    result = kernel.execute("!GEN[IDEA, 2]")
    assert result.output == ["IDEA0", "IDEA1"]


def test_default_gen_is_a_pending_request(kernel):
    result = kernel.execute("!GEN[IDEA, 2]")
    assert result.output["status"] == "pending"


def test_execution_is_deterministic(kernel):
    payload = '?LEN[[1,2,3]] -> !PRINT["size " + ?STR[$PREV]]'
    first = kernel.execute(payload)
    second = kernel.execute(payload)
    assert result_frame(first) == result_frame(second)
    assert first.bindings == second.bindings
    assert [step.name for step in first.steps] == [step.name for step in second.steps]


# ---------------------------------------------------------------------------
# Introspection
# ---------------------------------------------------------------------------
def test_steps_and_calls_are_recorded(weather_kernel):
    result = weather_kernel.execute("@LOC[TYO] -> ?WX -> !PRINT[$WX.state]")
    assert [step.name for step in result.steps] == ["WX", "PRINT"]
    assert [(call.kind, call.name) for call in result.calls] == [
        ("target", "LOC"),
        ("query", "WX"),
        ("action", "PRINT"),
    ]


def test_duration_is_measured(weather_kernel):
    result = weather_kernel.execute("?WX")
    assert result.duration_ms >= 0.0
    assert result.to_dict()["duration_ms"] >= 0.0


def test_to_dict_and_json_round_trip(weather_kernel):
    import json

    result = weather_kernel.execute("@LOC[TYO] -> ?WX")
    payload = json.loads(result.to_json())
    assert payload["bindings"]["WX"]["state"] == "RAIN"
    assert payload["state"]["LOC"] == "TYO"


def test_as_context_is_dense_and_readable(weather_kernel):
    context = weather_kernel.execute("@LOC[TYO] -> ?WX").as_context()
    assert "payload:" in context
    assert "result:" in context


def test_result_frame_reparses(weather_kernel):
    from zeno.parser import parse

    result = weather_kernel.execute("@LOC[TYO] -> ?WX")
    frame = result_frame(result)
    assert frame.startswith("!RET[")
    parse(frame)


def test_result_frame_of_an_empty_run():
    assert result_frame(ExecutionResult()) == "!RET[]"


def test_kernel_alias_run(weather_kernel):
    assert weather_kernel.run("?WX").output == {"state": "RAIN", "temp": 18}


def test_available_lists_builtins(kernel):
    available = kernel.available()
    assert "LOG" in available["actions"]
    assert "LEN" in available["queries"]


def test_echo_is_used_by_log_and_print():
    seen = []
    kernel = Kernel(echo=seen.append)
    kernel.execute('@SYS[x] -> !LOG["hello"]')
    assert seen == ["hello"]


def test_trace_flag_emits_lines():
    seen = []
    kernel = Kernel(trace=True, echo=seen.append)
    kernel.execute("?LEN[[1,2]] -> !LOG[ok]")
    assert any(line.startswith("[zeno]") for line in seen)


def test_max_steps_guard():
    kernel = Kernel(max_steps=2)
    with pytest.raises(ZenoRuntimeError):
        kernel.execute("?LEN[[1]] -> ?LEN[[2]] -> ?LEN[[3]]")


# ---------------------------------------------------------------------------
# Values
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "value,expected",
    [
        (None, False),
        (False, False),
        (0, False),
        (0.0, False),
        ("", False),
        ([], False),
        ({}, False),
        (True, True),
        (1, True),
        ("x", True),
        ([0], True),
    ],
)
def test_truthiness(value, expected):
    assert truthy(value) is expected


def test_env_reads_are_case_insensitive():
    env = Env({"PRICE": 10})
    env.set("WX.state", "RAIN")
    assert env.get("wx.STATE") == "RAIN"
    assert env.get("price") == 10
    assert env.get("missing") is not None  # UNSET sentinel, not None


def test_env_child_inherits_without_mutating():
    parent = Env({"A": 1})
    child = parent.child(("SCOPE",))
    child.set("B", 2)
    assert child.get("A") == 1
    assert parent.get("B") is not None and "B" not in parent.as_dict()


def test_env_snapshot_is_detached():
    env = Env({"WX": {"state": "RAIN"}})
    snapshot = env.snapshot()
    snapshot["WX"]["state"] = "CLEAR"
    assert env.get("WX.state") == "RAIN"


def test_rendering_styles():
    assert render({"a": 1}) == "{a=1}"
    assert render(True) == "TRUE"
    assert render(None) == "NIL"
    assert render([1, "two"]) == "[1, two]"
    assert render(["two words"]) == '["two words"]'
    assert "{" in render({"a": 1}, style="json")
    assert "mapping" in render({"a": 1}, style="prose")


def test_to_jsonable_handles_environments():
    assert to_jsonable(Env({"A": [1, 2]})) == {"A": [1, 2]}
