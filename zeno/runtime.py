"""Execution kernel for Zeno Grammar v0.1.

The kernel evaluates a parsed payload against a *latent state* (:class:`~zeno.values.Env`)
and a registry of tools. It never calls an LLM by itself — that is the job of
:mod:`zeno.runtime.provider` style backends wired in by the caller. What the
kernel does provide is:

* deterministic evaluation of flows, pipelines and conditionals,
* implicit binding of every step (grammar §3.1),
* a dense machine-readable result frame (:func:`result_frame`),
* structured traces so the decoder knows exactly what happened.

    >>> from zeno.runtime import Kernel
    >>> kernel = Kernel()
    >>> kernel.register_action("LOG", lambda args, kwargs, env, call: args[0])
    >>> result = kernel.execute("@SYS[PING] -> !LOG[liveness]")
    >>> result.output
    'liveness'
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple, Union

from .ast import (
    Attr,
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
from .emitter import emit
from .errors import (
    DivisionByZero,
    TypeMismatch,
    UndefinedVariable,
    UnknownAction,
    UnresolvedQuery,
    ZenoRuntimeError,
)
from .parser import parse
from .values import UNSET, Env, render, to_jsonable, truthy, walk_path

__all__ = ["Kernel", "Tool", "ToolInvocation", "StepResult", "ExecutionResult", "result_frame"]

#: Signature of a tool implementation.
#:
#: ``fn(args, kwargs, env, call) -> value``
Tool = Callable[[List[Any], Dict[str, Any], Env, Call], Any]

_MAX_RECORDED_STEPS = 512


# ---------------------------------------------------------------------------
# Result records
# ---------------------------------------------------------------------------
@dataclass
class ToolInvocation:
    """One query or action that the kernel actually executed."""

    kind: str  # "query" | "action"
    name: str
    args: List[Any] = field(default_factory=list)
    kwargs: Dict[str, Any] = field(default_factory=dict)
    value: Any = None
    scope: Tuple[str, ...] = ()
    line: int = 0

    def to_dict(self) -> dict:
        payload = {
            "kind": self.kind,
            "name": self.name,
            "line": self.line,
            "value": to_jsonable(self.value),
        }
        if self.args:
            payload["args"] = to_jsonable(self.args)
        if self.kwargs:
            payload["kwargs"] = to_jsonable(self.kwargs)
        if self.scope:
            payload["scope"] = list(self.scope)
        return payload


@dataclass
class StepResult:
    """The value produced by one pipeline step."""

    index: int
    name: str
    value: Any
    scope: Tuple[str, ...] = ()

    def to_dict(self) -> dict:
        payload = {"index": self.index, "name": self.name, "value": to_jsonable(self.value)}
        if self.scope:
            payload["scope"] = list(self.scope)
        return payload


@dataclass
class ExecutionResult:
    """Everything the kernel observed while evaluating a payload."""

    #: Value the payload evaluated to (``!RET`` output wins when present).
    output: Any = None
    #: Every binding recorded into latent state, including implicit step binds.
    bindings: Dict[str, Any] = field(default_factory=dict)
    #: Ordered pipeline trace.
    steps: List[StepResult] = field(default_factory=list)
    #: Ordered tool invocations, including nested ones inside expressions.
    calls: List[ToolInvocation] = field(default_factory=list)
    #: Scope that was active for each statement, in order.
    scopes: List[Tuple[str, ...]] = field(default_factory=list)
    #: ``True`` when the payload ended through ``!RET``.
    returned: bool = False
    #: Wall-clock duration of the run, in milliseconds.
    duration_ms: float = 0.0
    #: The payload as executed, in canonical form.
    payload: str = ""
    #: The environment after execution (detached snapshot).
    state: Dict[str, Any] = field(default_factory=dict)
    #: Non-fatal problems encountered while executing.
    errors: List[str] = field(default_factory=list)

    # -- convenience -----------------------------------------------------
    #: Bindings that represent an answer rather than a side effect.
    _ANSWER_KEYS = ("RET", "OUT", "RESULT", "ANSWER", "PRINT", "GEN", "SUMMARY")

    @property
    def answer(self) -> Any:
        """The value the decoder should turn back into human language."""
        if self.output is not None:
            return self.output
        for name in self._ANSWER_KEYS:
            value = self.binding(name)
            if value is not None:
                return value
        for step in reversed(self.steps):
            if step.value is not None:
                return step.value
        return self.bindings or None

    @property
    def actions(self) -> List[ToolInvocation]:
        return [call for call in self.calls if call.kind == "action"]

    @property
    def queries(self) -> List[ToolInvocation]:
        return [call for call in self.calls if call.kind == "query"]

    def binding(self, name: str, default: Any = None) -> Any:
        if name in self.bindings:
            return self.bindings[name]
        lowered = name.lower()
        for key, value in self.bindings.items():
            if key.lower() == lowered:
                return value
        return default

    def to_dict(self) -> dict:
        return {
            "output": to_jsonable(self.output),
            "bindings": to_jsonable(self.bindings),
            "steps": [step.to_dict() for step in self.steps],
            "calls": [call.to_dict() for call in self.calls],
            "scopes": [list(scope) for scope in self.scopes],
            "returned": self.returned,
            "duration_ms": round(self.duration_ms, 3),
            "payload": self.payload,
            "state": self.state,
            "errors": self.errors,
        }

    def to_json(self, *, indent: Optional[int] = 2) -> str:
        import json

        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def as_context(self, *, style: str = "compact") -> str:
        """A dense textual description of the run, for a decoder prompt."""
        lines: List[str] = []
        if self.payload:
            lines.append(f"payload: {self.payload}")
        for step in self.steps:
            lines.append(f"step[{step.index}] {step.name} = {render(step.value, style=style)}")
        for call in self.calls:
            if call.kind == "action":
                args = ", ".join(render(arg, style=style) for arg in call.args)
                lines.append(f"action !{call.name}[{args}]")
        lines.append(f"result: {render(self.answer, style=style)}")
        if self.errors:
            lines.append("warnings: " + "; ".join(self.errors))
        return "\n".join(lines)


class _ReturnSignal(Exception):
    """Internal control-flow signal raised by ``!RET``."""

    def __init__(self, value: Any) -> None:
        super().__init__("return")
        self.value = value


# ---------------------------------------------------------------------------
# Kernel
# ---------------------------------------------------------------------------
class Kernel:
    """Evaluate Zeno payloads against latent state and a tool registry.

    Parameters
    ----------
    tools:
        Optional mapping of tool-name to implementation, as either
        ``{"?NAME": fn}`` or with explicit kinds via :meth:`register_query` /
        :meth:`register_action`.
    generator:
        Callable used by the built-in ``!GEN`` action. Given the requested
        topic and count it should return the generated payload. When omitted,
        ``!GEN`` returns a structured *pending* request instead of inventing
        content.
    strict_queries:
        When ``True`` (default) an unknown ``?QUERY`` raises
        :class:`~zeno.errors.UnresolvedQuery`. When ``False`` it resolves to
        ``NIL`` and the failure is recorded in ``result.errors``, which is
        useful for best-effort planning runs.
    """

    def __init__(
        self,
        tools: Optional[Dict[str, Tool]] = None,
        *,
        generator: Optional[Callable[[Any, int, Dict[str, Any], Env], Any]] = None,
        strict_queries: bool = True,
        max_steps: int = 10_000,
        trace: bool = False,
        echo: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.queries: Dict[str, Tool] = {}
        self.actions: Dict[str, Tool] = {}
        self.strict_queries = strict_queries
        self.generator = generator
        self.max_steps = max_steps
        self.trace = trace
        self.echo = echo
        self._step_budget = max_steps
        self._install_builtins()
        if tools:
            for name, fn in tools.items():
                self.register(name, fn)

    # -- registration ----------------------------------------------------
    @staticmethod
    def _normalise(name: str) -> str:
        name = name.strip()
        if name.startswith(("?", "!")):
            return name[1:].upper()
        return name.upper()

    def register(self, name: str, fn: Tool) -> None:
        """Register ``fn`` under ``name``; a leading sigil selects the kind."""
        stripped = name.strip()
        if stripped.startswith("!"):
            self.actions[self._normalise(stripped)] = fn
        elif stripped.startswith("?"):
            self.queries[self._normalise(stripped)] = fn
        else:
            self.actions[self._normalise(stripped)] = fn

    def register_query(self, name: str, fn: Tool) -> None:
        self.queries[self._normalise(name)] = fn

    def register_action(self, name: str, fn: Tool) -> None:
        self.actions[self._normalise(name)] = fn

    def available(self) -> Dict[str, List[str]]:
        return {"queries": sorted(self.queries), "actions": sorted(self.actions)}

    # -- public API ------------------------------------------------------
    def execute(
        self,
        source: Union[str, Program, Node],
        *,
        state: Optional[Dict[str, Any]] = None,
        tools: Optional[Dict[str, Any]] = None,
    ) -> ExecutionResult:
        """Parse (if needed) and evaluate a payload.

        Parameters
        ----------
        source:
            Payload text, a :class:`~zeno.ast.Program`, or any AST node.
        state:
            Seed values merged into latent state before execution, e.g.
            ``{"USER": "amara"}`` or ``{"WX": {"state": "RAIN"}}``.
        tools:
            One-off tool bindings layered on top of the registry.
        """
        program = self._as_program(source)
        env = Env(state)
        saved_queries, saved_actions = self.queries, self.actions
        if tools:
            self.queries = dict(self.queries)
            self.actions = dict(self.actions)
            for name, fn in tools.items():
                self.register(name, fn)

        result = ExecutionResult(payload=emit(program))
        started = time.perf_counter()
        self._step_budget = self.max_steps
        try:
            try:
                value = self._execute_program(program, env, result)
                result.output = value
            except _ReturnSignal as signal:
                result.output = signal.value
                result.returned = True
        finally:
            self.queries, self.actions = saved_queries, saved_actions
            result.duration_ms = (time.perf_counter() - started) * 1000.0
            result.state = env.snapshot()
            for name, value in result.bindings.items():
                if name not in result.state:
                    result.state[name] = to_jsonable(value)
        return result

    run = execute

    def evaluate(self, expression: str, *, state: Optional[Dict[str, Any]] = None) -> Any:
        """Evaluate a single expression, e.g. ``"$PRICE * 2"``."""
        program = parse(expression)
        env = Env(state)
        self._step_budget = self.max_steps
        result = ExecutionResult()
        node = program.statements[0] if program.statements else None
        if node is None:
            return None
        if isinstance(node, Flow):
            value = self._eval_flow(node, env, result)
        else:
            value = self._eval_node(node, env, result)
        return value

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _as_program(self, source: Union[str, Program, Node]) -> Program:
        if isinstance(source, Program):
            return source
        if isinstance(source, Node):
            return Program((source,), span=source.span)
        return parse(source)

    def _tick(self, node: Node) -> None:
        self._step_budget -= 1
        if self._step_budget <= 0:  # pragma: no cover - defensive
            raise ZenoRuntimeError("execution budget exhausted (possible runaway payload)")

    def _record_call(self, invocation: ToolInvocation, result: ExecutionResult) -> None:
        if len(result.calls) < _MAX_RECORDED_STEPS:
            result.calls.append(invocation)
        if self.trace and self.echo:
            self.echo(
                f"[zeno] {invocation.kind} {invocation.name} -> "
                f"{render(invocation.value)}"
            )

    def _execute_program(self, program: Program, env: Env, result: ExecutionResult) -> Any:
        value: Any = None
        for statement in program.statements:
            self._tick(statement)
            value = self._eval_statement(statement, env, result)
        return value

    def _eval_statement(self, statement: Node, env: Env, result: ExecutionResult) -> Any:
        if isinstance(statement, ScopeBlock):
            return self._eval_scope_block(statement, env, result)
        if isinstance(statement, Binding):
            if statement.value is None:  # parser-synthesised marker
                return None
            value = self._eval_node(statement.value, env, result)
            env.set(statement.name, value)
            result.bindings[statement.name] = value
            return value
        if isinstance(statement, Flow):
            return self._eval_flow(statement, env, result)
        return self._eval_node(statement, env, result)

    def _eval_scope_block(self, block: ScopeBlock, env: Env, result: ExecutionResult) -> Any:
        label, value = self._scope_pair(block.call)
        scope = (*env.scope, label) if env.scope else (label,)
        scoped = env.child(scope)
        if label:
            scoped.set(label, value)
            scoped.set("SCOPE", value)
        result.scopes.append(scope)
        self._record_call(
            ToolInvocation("target", block.call.name, self._arg_values(block.call, env, result), {}, value, scope, block.call.line),
            result,
        )
        produced: Any = None
        for statement in block.body:
            self._tick(statement)
            produced = self._eval_statement(statement, scoped, result)
        # The block ran in its own frame, but its results belong to the caller:
        # `@AGENT[Coder] { ?REPO -> !RUN[tests] }` leaves $REPO readable after.
        for name, value in scoped.as_dict().items():
            env.set(name, value)
        return produced

    @staticmethod
    def _scope_pair(call: Call) -> Tuple[str, Any]:
        if call.args:
            first = call.args[0]
            value = first.value if isinstance(first, Literal) else emit(first)
            return call.name, value
        return call.name, call.name

    def _eval_flow(self, flow: Flow, env: Env, result: ExecutionResult) -> Any:
        if flow.scope is not None:
            label, value = self._scope_pair(flow.scope)
            env.set(label, value)
            env.set("SCOPE", value)
            scope = (*env.scope, label) if env.scope else (label,)
            self._record_call(
                ToolInvocation(
                    "target", flow.scope.name, self._arg_values(flow.scope, env, result), {}, value,
                    scope, flow.scope.line,
                ),
                result,
            )

        previous: Any = UNSET
        last: Any = UNSET

        for index, step in enumerate(flow.steps):
            self._tick(step)
            env.set("PREV", None if previous is UNSET else previous)
            env.set("_", None if previous is UNSET else previous)
            value = self._eval_node(step, env, result)
            if isinstance(step, Call):
                name = step.name
                env.set(name, value)
                if "." in name:
                    leaf = name.rsplit(".", 1)[-1]
                    if env.get(leaf) is UNSET:
                        env.set(leaf, value)
                result.bindings[name] = value
                result.steps.append(StepResult(index, name, value, env.scope))
                if name == "RET":
                    raise _ReturnSignal(value)
            previous = value
            last = value

        env.set("PREV", None if previous is UNSET else previous)
        env.set("_", None if previous is UNSET else previous)

        if flow.conditional is not None:
            return self._eval_conditional(flow.conditional, env, result)
        return None if last is UNSET else last

    def _eval_conditional(self, node: Conditional, env: Env, result: ExecutionResult) -> Any:
        self._tick(node)
        test = self._eval_node(node.test, env, result)
        branch = node.then_branch if truthy(test) else node.else_branch
        if branch is None:
            return None
        if isinstance(branch, Flow):
            return self._eval_flow(branch, env, result)
        return self._eval_node(branch, env, result)

    # -- expressions -----------------------------------------------------
    def _eval_node(self, node: Optional[Node], env: Env, result: ExecutionResult) -> Any:
        if node is None:
            return None
        if isinstance(node, Literal):
            return node.value
        if isinstance(node, Path):
            return self._eval_path(node, env)
        if isinstance(node, Attr):
            base = self._eval_node(node.base, env, result)
            found = walk_path(base, node.parts)
            return None if found is UNSET else found
        if isinstance(node, ListLiteral):
            return [self._eval_node(item, env, result) for item in node.items]
        if isinstance(node, UnaryOp):
            return self._eval_unary(node, env, result)
        if isinstance(node, BinaryOp):
            return self._eval_binary(node, env, result)
        if isinstance(node, Call):
            return self._invoke(node, env, result)
        if isinstance(node, Conditional):
            return self._eval_conditional(node, env, result)
        if isinstance(node, Flow):
            return self._eval_flow(node, env, result)
        if isinstance(node, ScopeBlock):
            return self._eval_scope_block(node, env, result)
        if isinstance(node, Binding):
            return self._eval_statement(node, env, result)
        if isinstance(node, Program):  # pragma: no cover - defensive
            return self._execute_program(node, env, result)
        raise ZenoRuntimeError(f"cannot evaluate node of type {type(node).__name__}")

    def _eval_path(self, node: Path, env: Env) -> Any:
        parts = node.parts
        if not parts:
            return None
        value = env.get(parts[0])
        if value is UNSET:
            if node.sigil == "$":
                raise UndefinedVariable(
                    f"variable '${node.name}' is not bound",
                    node.span,
                    hint="bind it first, e.g. `$"
                    + node.name
                    + " = <expression>`, or query it with `?"
                    + parts[0]
                    + "`",
                )
            # Bare atoms are self-describing symbols: `RAIN`, `INDOOR`, `HIGH`.
            return ".".join(parts).upper()
        if len(parts) > 1:
            value = walk_path(value, parts[1:])
            if value is UNSET:
                return None
        return value

    def _eval_unary(self, node: UnaryOp, env: Env, result: ExecutionResult) -> Any:
        operand = self._eval_node(node.operand, env, result)
        if node.op == "~":
            return not truthy(operand)
        if node.op == "-":
            number = _as_number(operand, node, "-")
            return -number
        raise ZenoRuntimeError(f"unknown unary operator {node.op!r}")  # pragma: no cover

    def _eval_binary(self, node: BinaryOp, env: Env, result: ExecutionResult) -> Any:
        op = node.op

        if op == "&&":
            left = self._eval_node(node.left, env, result)
            if not truthy(left):
                return False
            return truthy(self._eval_node(node.right, env, result))
        if op == "||":
            left = self._eval_node(node.left, env, result)
            if truthy(left):
                return True
            return truthy(self._eval_node(node.right, env, result))

        left = self._eval_node(node.left, env, result)
        right = self._eval_node(node.right, env, result)

        if op == "==":
            return _values_equal(left, right)
        if op == "!=":
            return not _values_equal(left, right)
        if op == "~=":
            return _matches(left, right)
        if op in (">", ">=", "<", "<="):
            return _ordered_compare(op, left, right, node)
        if op == "+":
            return _add(left, right, node)
        if op in ("-", "*", "/", "%", "^"):
            return _arithmetic(op, left, right, node)
        raise ZenoRuntimeError(f"unknown binary operator {op!r}")  # pragma: no cover

    # -- calls -----------------------------------------------------------
    def _invoke(self, call: Call, env: Env, result: ExecutionResult) -> Any:
        self._tick(call)
        args = self._arg_values(call, env, result)
        kwargs = self._kwarg_values(call, env, result)
        key = call.name.upper()

        if call.sigil == "@":
            label, value = self._scope_pair(call)
            env.set(label, value)
            self._record_call(
                ToolInvocation("target", key, args, kwargs, value, env.scope, call.line), result
            )
            return value

        table = self.queries if call.sigil == "?" else self.actions
        fn = table.get(key)
        if fn is None:
            return self._handle_missing(call, key, args, kwargs, env, result)

        value = fn(args, kwargs, env, call)
        if call.sigil == "!" and key == "RET":
            # Named arguments of !RET are part of the answer, not just of state.
            for name, kw_value in kwargs.items():
                if name.upper() in {"OUT", "RET", "RESULT", "ANSWER"}:
                    continue
                result.bindings.setdefault(name, kw_value)
        if call.sigil in {"?", "!"} and env.get(key) is UNSET:
            # §3.1: a query or action always binds its own name, including when
            # it appears inside a larger expression.
            env.set(call.name, value)
            result.bindings.setdefault(call.name, value)
        self._record_call(
            ToolInvocation(
                "query" if call.sigil == "?" else "action",
                key,
                args,
                kwargs,
                value,
                env.scope,
                call.line,
            ),
            result,
        )
        return value

    def _handle_missing(
        self,
        call: Call,
        key: str,
        args: List[Any],
        kwargs: Dict[str, Any],
        env: Env,
        result: ExecutionResult,
    ) -> Any:
        if call.sigil == "?":
            if not self.strict_queries:
                message = f"unresolved query ?{key}"
                if message not in result.errors:
                    result.errors.append(message)
                self._record_call(
                    ToolInvocation("query", key, args, kwargs, None, env.scope, call.line), result
                )
                return None
            raise UnresolvedQuery(
                f"no implementation is registered for '?{key}'",
                call.span,
                hint="register one with `kernel.register_query('"
                + key
                + "', fn)`, or pass tools={'?"
                + key
                + "': fn} to execute()",
            )
        raise UnknownAction(
            f"no implementation is registered for '!{key}'",
            call.span,
            hint="register one with `kernel.register_action('"
            + key
            + "', fn)`, or pass tools={'!"
            + key
            + "': fn} to execute()",
        )

    def _arg_values(self, call: Call, env: Env, result: ExecutionResult) -> List[Any]:
        return [self._eval_node(arg, env, result) for arg in call.args]

    def _kwarg_values(
        self, call: Call, env: Env, result: ExecutionResult
    ) -> Dict[str, Any]:
        return {key: self._eval_node(value, env, result) for key, value in call.kwargs}

    # ------------------------------------------------------------------
    # Built-in tools
    # ------------------------------------------------------------------
    def _install_builtins(self) -> None:
        q = self.register_query
        a = self.register_action

        q("LEN", lambda args, kwargs, env, call: len(args[0]) if args else 0)
        q("COUNT", lambda args, kwargs, env, call: _count(args[0]) if args else 0)
        q("TYPE", lambda args, kwargs, env, call: _type_name(args[0]) if args else "nil")
        q("ABS", lambda args, kwargs, env, call: abs(_as_number(args[0], call, "ABS")))
        q("ROUND", lambda args, kwargs, env, call: round(float(args[0]), int(args[1]) if len(args) > 1 else 0))
        q("MIN", lambda args, kwargs, env, call: min(args) if args else None)
        q("MAX", lambda args, kwargs, env, call: max(args) if args else None)
        q("SUM", lambda args, kwargs, env, call: sum(_as_number(v, call, "SUM") for v in args))
        q("UPPER", lambda args, kwargs, env, call: str(args[0]).upper())
        q("LOWER", lambda args, kwargs, env, call: str(args[0]).lower())
        q("STR", lambda args, kwargs, env, call: _stringify(args[0]) if args else "")
        q("ENV", lambda args, kwargs, env, call: env.snapshot())
        q("NOW", lambda args, kwargs, env, call: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        q("ECHO", lambda args, kwargs, env, call: args[0] if args else None)

        def action_log(args: List[Any], kwargs: Dict[str, Any], env: Env, call: Call) -> Any:
            text = render(args[0]) if args else render(kwargs or None)
            if self.echo:
                self.echo(text)
            return args[0] if args else None

        def action_print(args: List[Any], kwargs: Dict[str, Any], env: Env, call: Call) -> Any:
            value = args[0] if len(args) == 1 else list(args) or None
            if self.echo:
                self.echo(render(value))
            return value

        def action_gen(args: List[Any], kwargs: Dict[str, Any], env: Env, call: Call) -> Any:
            topic = args[0] if args else kwargs.get("TOPIC")
            count = int(args[1]) if len(args) > 1 else int(kwargs.get("COUNT", 1) or 1)
            if self.generator is not None:
                return self.generator(topic, count, kwargs, env)
            return {"task": "GENERATE", "topic": topic, "count": count, "status": "pending"}

        def action_set(args: List[Any], kwargs: Dict[str, Any], env: Env, call: Call) -> Any:
            if len(args) >= 2:
                env.set(str(args[0]), args[1])
                return args[1]
            for key, value in kwargs.items():
                env.set(key, value)
            return kwargs

        def action_assert(args: List[Any], kwargs: Dict[str, Any], env: Env, call: Call) -> Any:
            if not args:
                raise ZenoRuntimeError("!ASSERT requires a condition")
            if not truthy(args[0]):
                message = render(args[1]) if len(args) > 1 else "assertion failed"
                raise ZenoRuntimeError(f"assertion failed: {message}", call.span)
            return True

        def action_ret(args: List[Any], kwargs: Dict[str, Any], env: Env, call: Call) -> Any:
            # Writes every named argument into latent state, then returns the
            # human-facing payload (OUT, else the single positional argument).
            for key, value in kwargs.items():
                if key.upper() in {"OUT", "RET", "RESULT", "ANSWER"}:
                    continue
                env.set(key, value)
            if "OUT" in kwargs:
                return kwargs["OUT"]
            if args:
                return args[0] if len(args) == 1 else list(args)
            payload = {k: v for k, v in kwargs.items()}
            return payload or None

        a("LOG", action_log)
        a("PRINT", action_print)
        a("GEN", action_gen)
        a("SET", action_set)
        a("ASSERT", action_assert)
        a("RET", action_ret)
        a("NOOP", lambda args, kwargs, env, call: None)


# ---------------------------------------------------------------------------
# Operator helpers
# ---------------------------------------------------------------------------
def _type_name(value: Any) -> str:
    if value is None or value is UNSET:
        return "nil"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, (list, tuple, set, frozenset)):
        return "list"
    if isinstance(value, (dict, Env)):
        return "map"
    return type(value).__name__


def _stringify(value: Any) -> str:
    """Text form of a value: strings pass through, everything else renders."""
    if isinstance(value, str):
        return value
    if value is None or value is UNSET:
        return ""
    return render(value)


def _count(value: Any) -> int:
    if value is None or value is UNSET:
        return 0
    if isinstance(value, (str, list, tuple, set, frozenset, dict)):
        return len(value)
    return 1


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _as_number(value: Any, node: Node, operator: str) -> Union[int, float]:
    if _is_number(value):
        return value
    if isinstance(value, str):
        try:
            return float(value) if ("." in value or "e" in value.lower()) else int(value)
        except ValueError:
            pass
    raise TypeMismatch(
        f"operator '{operator}' needs a number but received {_type_name(value)}",
        node.span if isinstance(node, Node) else None,
        hint="cast with `?ROUND[...]` or `?ABS[...]`, or fix the upstream value",
    )


def _values_equal(left: Any, right: Any) -> bool:
    if left is UNSET:
        left = None
    if right is UNSET:
        right = None
    if left is None or right is None:
        return left is None and right is None
    if isinstance(left, bool) and isinstance(right, bool):
        return left is right
    if isinstance(left, bool) or isinstance(right, bool):
        flag = left if isinstance(left, bool) else right
        other = right if isinstance(left, bool) else left
        if _is_number(other):
            return int(flag) == int(other)
        if isinstance(other, str):
            return ("TRUE" if flag else "FALSE") == other.strip().upper()
        return False
    if _is_number(left) and _is_number(right):
        return float(left) == float(right)
    if isinstance(left, str) and isinstance(right, str):
        return left.strip().lower() == right.strip().lower()
    if isinstance(left, (list, tuple)) and isinstance(right, (list, tuple)):
        return len(left) == len(right) and all(
            _values_equal(a, b) for a, b in zip(left, right)
        )
    if isinstance(left, dict) and isinstance(right, dict):
        return left == right
    return left == right


def _matches(left: Any, right: Any) -> bool:
    """``~=`` — substring for text, membership for lists, key-presence for maps."""
    if left is None or left is UNSET:
        return False
    if isinstance(left, str):
        return str(right).lower() in left.lower()
    if isinstance(left, (list, tuple, set, frozenset)):
        return any(_values_equal(item, right) for item in left)
    if isinstance(left, (dict, Env)):
        mapping = left.snapshot() if isinstance(left, Env) else left
        target = str(right).lower()
        return any(str(key).lower() == target for key in mapping)
    return _values_equal(left, right)


def _ordered_compare(op: str, left: Any, right: Any, node: Node) -> bool:
    if _is_number(left) and _is_number(right):
        a, b = float(left), float(right)
    elif isinstance(left, str) and isinstance(right, str):
        try:
            a, b = float(left), float(right)
        except ValueError:
            a, b = left.strip().lower(), right.strip().lower()
    else:
        raise TypeMismatch(
            f"cannot compare {_type_name(left)} with {_type_name(right)} using '{op}'",
            node.span,
            hint="compare like with like, e.g. numbers with numbers",
        )
    if op == ">":
        return a > b
    if op == ">=":
        return a >= b
    if op == "<":
        return a < b
    return a <= b


def _add(left: Any, right: Any, node: Node) -> Any:
    if _is_number(left) and _is_number(right):
        return left + right
    if isinstance(left, str) and isinstance(right, str):
        return left + right
    if isinstance(left, (list, tuple)) and isinstance(right, (list, tuple)):
        return list(left) + list(right)
    if _is_number(left) and isinstance(right, str):
        return render(left) + right
    if isinstance(left, str) and _is_number(right):
        return left + render(right)
    raise TypeMismatch(
        f"cannot add {_type_name(left)} to {_type_name(right)}",
        node.span,
        hint="' + ' concatenates text and adds numbers; convert first with `?STR[...]`",
    )


def _arithmetic(op: str, left: Any, right: Any, node: Node) -> Any:
    a = _as_number(left, node, op)
    b = _as_number(right, node, op)
    if op == "-":
        return a - b
    if op == "*":
        if isinstance(left, str) and isinstance(right, int):
            return left * right
        if isinstance(left, (list, tuple)) and isinstance(right, int):
            return list(left) * right
        return a * b
    if op == "/":
        if b == 0:
            raise DivisionByZero("division by zero", node.span)
        return a / b
    if op == "%":
        if b == 0:
            raise DivisionByZero("modulo by zero", node.span)
        return a % b
    result = a ** b
    if isinstance(result, float) and result.is_integer() and abs(result) < 1e16:
        return int(result)
    return result


# ---------------------------------------------------------------------------
# Result frame
# ---------------------------------------------------------------------------
def result_frame(
    result: ExecutionResult,
    *,
    include_state: bool = True,
    max_pairs: int = 32,
    flatten_depth: int = 2,
) -> str:
    """Render a run as the dense ``!RET`` frame described in grammar §3.4.

    The frame is built through the emitter, so it is guaranteed to parse back:

    >>> frame = result_frame(Kernel().execute('!RET[TEMP=31,OUT="sunny"]'))
    >>> parse(frame).statements[0].steps[0].name
    'RET'
    """
    pairs: List[Tuple[str, Any]] = []
    if include_state:
        for key, value in result.bindings.items():
            if key in {"PREV", "_"}:
                continue
            pairs.extend(_flatten_for_frame(key, value, flatten_depth))
    if result.output is not None:
        pairs.append(("OUT", result.output))
    if not pairs:
        return "!RET[]"
    seen = set()
    unique: List[Tuple[str, Any]] = []
    for key, value in pairs:
        if key in seen:
            continue
        seen.add(key)
        unique.append((key, value))
    ast_pairs = tuple((key, _value_to_ast(value)) for key, value in unique[:max_pairs])
    return emit(Call("!", "RET", (), ast_pairs))


def _flatten_for_frame(key: str, value: Any, depth: int) -> List[Tuple[str, Any]]:
    if depth <= 0 or not isinstance(value, (dict, Env)):
        return [(key, value)]
    mapping = value.snapshot() if isinstance(value, Env) else value
    if not mapping:
        return [(key, mapping)]
    pairs: List[Tuple[str, Any]] = []
    for sub_key, sub_value in mapping.items():
        pairs.extend(_flatten_for_frame(f"{key}.{sub_key}", sub_value, depth - 1))
    return pairs


def _value_to_ast(value: Any) -> Node:
    """Convert a runtime value into an AST node the emitter can render."""
    if value is None or value is UNSET:
        return Literal(None, "NIL", "nil")
    if isinstance(value, bool):
        return Literal(value, "TRUE" if value else "FALSE", "bool")
    if isinstance(value, (int, float)):
        return Literal(value, None, "number")
    if isinstance(value, str):
        return Literal(value, None, "string")
    if isinstance(value, (list, tuple, set, frozenset)):
        return ListLiteral(tuple(_value_to_ast(item) for item in value))
    if isinstance(value, (dict, Env)):
        mapping = value.snapshot() if isinstance(value, Env) else value
        return Literal(render(mapping, style="compact"), None, "string")
    return Literal(render(value, style="compact"), None, "string")
