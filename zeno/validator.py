"""Static analysis for Zeno payloads.

``parse`` tells you a payload is *well-formed*; :func:`validate` also tells you
whether it is *coherent* — that every ``$variable`` it reads has been bound, and
that nothing suspicious (stray else-branch, unreachable atoms, missing
terminal action) slipped through.

    >>> from zeno.validator import validate
    >>> report = validate("@LOC[TYO] -> ?WX : { $WX.state == RAIN => !GEN[INDOOR, 3] }")
    >>> report.ok
    True
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

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
from .errors import LINT_CODES, ZenoError
from .parser import parse
from .span import Span

__all__ = ["Diagnostic", "ValidationReport", "validate", "validate_program", "LINT_CODES"]

#: Built-ins the kernel always provides; never reported as undefined.
_IMPLICIT_VARIABLES = {"PREV", "_", "SCOPE"}


@dataclass
class Diagnostic:
    """One lint finding."""

    code: str
    message: str
    span: Optional[Span] = None
    severity: str = "warning"

    @property
    def canonical(self) -> str:
        return LINT_CODES.get(self.code, self.message)

    def to_dict(self) -> dict:
        payload = {
            "code": self.code,
            "severity": self.severity,
            "message": self.message,
            "canonical": self.canonical,
        }
        if self.span is not None:
            payload["location"] = {
                "line": self.span.start.line,
                "column": self.span.start.column,
            }
        return payload

    def render(self, *, color: bool = False) -> str:
        where = ""
        if self.span is not None:
            where = f" (line {self.span.start.line}, col {self.span.start.column})"
        tint = "\033[33m" if color else ""
        reset = "\033[0m" if color else ""
        return f"{tint}{self.severity}{reset} {self.code}{where}: {self.message}"


@dataclass
class ValidationReport:
    """The outcome of :func:`validate`."""

    payload: str = ""
    diagnostics: List[Diagnostic] = field(default_factory=list)
    program: Optional[Program] = None
    error: Optional[ZenoError] = None

    @property
    def ok(self) -> bool:
        return self.error is None and not self.errors

    @property
    def errors(self) -> List[Diagnostic]:
        return [d for d in self.diagnostics if d.severity == "error"]

    @property
    def warnings(self) -> List[Diagnostic]:
        return [d for d in self.diagnostics if d.severity == "warning"]

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "payload": self.payload,
            "diagnostics": [d.to_dict() for d in self.diagnostics],
            "parse_error": self.error.to_dict() if self.error else None,
        }

    def render(self, *, color: bool = False) -> str:
        lines: List[str] = []
        if self.error is not None:
            lines.append(self.error.render(color=color))
        for diagnostic in self.diagnostics:
            lines.append(diagnostic.render(color=color))
        if not lines:
            lines.append("ok: payload is valid Zeno Grammar v0.1")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def validate(source: str) -> ValidationReport:
    """Parse ``source`` then lint it. Never raises for bad input."""
    report = ValidationReport(payload=source)
    try:
        program = parse(source)
    except ZenoError as exc:
        report.error = exc
        # A parse failure is a finding like any other, so callers that only look
        # at `diagnostics` still see why the payload was rejected.
        report.diagnostics.append(
            Diagnostic(
                exc.code,
                exc.message,
                getattr(exc, "span", None),
                "error",
            )
        )
        return report
    report.program = program
    report.diagnostics.extend(validate_program(program))
    return report


def validate_program(program: Program) -> List[Diagnostic]:
    """Lint an already-parsed program."""
    diagnostics: List[Diagnostic] = []
    bound: Set[str] = set(_IMPLICIT_VARIABLES)
    reads: List[Tuple[str, Span]] = []
    shadowed: Dict[str, Span] = {}

    def note_path(node: Path) -> None:
        if node.sigil == "$":
            reads.append((node.root.upper(), node.span))
        elif node.parts:
            root = node.parts[0].upper()
            if root in bound:
                shadowed.setdefault(root, node.span)

    for statement in program.statements:
        _walk(statement, note_path)
        _collect_bindings(statement, bound)

    for name, span in reads:
        if name not in bound:
            diagnostics.append(
                Diagnostic(
                    "ZL0001",
                    f"$<{name}> is read but never bound by this payload",
                    span,
                    "error",
                )
            )
    for name, span in shadowed.items():
        diagnostics.append(
            Diagnostic(
                "ZL0005",
                f"bare atom '{name}' may be shadowed by the variable ${name}",
                span,
                "warning",
            )
        )

    for statement in program.statements:
        diagnostics.extend(_lint_statement(statement))

    if not _has_terminal_action(program) and program.statements:
        last = program.statements[-1]
        diagnostics.append(
            Diagnostic(
                "ZL0004",
                "payload has no terminal action (!RET, !GEN, !PRINT, !LOG …)",
                last.span,
                "warning",
            )
        )
    return diagnostics


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _walk(node: Optional[Node], visit_path) -> None:
    if node is None:
        return
    if isinstance(node, Path):
        visit_path(node)
    for child in node.children():
        _walk(child, visit_path)


def _collect_bindings(node: Optional[Node], bound: Set[str]) -> None:
    if node is None:
        return
    if isinstance(node, Binding):
        bound.add(node.path[0].upper())
    if isinstance(node, Call) and node.sigil in {"?", "!"}:
        bound.add(node.name.split(".")[0].upper())
    if isinstance(node, ScopeBlock):
        bound.add(node.call.name.upper())
        for index, arg in enumerate(node.call.args):
            if isinstance(arg, Literal) and isinstance(arg.value, str):
                bound.add(arg.value.upper())
        for name in _scope_bindings(node.call):
            bound.add(name)
    if isinstance(node, Flow) and node.scope is not None:
        bound.add(node.scope.name.upper())
        for name in _scope_bindings(node.scope):
            bound.add(name)
    for child in node.children():
        _collect_bindings(child, bound)


def _scope_bindings(call: Call) -> Iterable[str]:
    """``@AGENT[Coder]`` also makes the scope *value* readable as a name."""
    for arg in call.args:
        if isinstance(arg, Literal) and isinstance(arg.value, str):
            value = str(arg.value)
            if value.isidentifier():
                yield value.upper()


def _lint_statement(statement: Node) -> List[Diagnostic]:
    diagnostics: List[Diagnostic] = []
    if isinstance(statement, ScopeBlock):
        if not statement.body:
            diagnostics.append(
                Diagnostic(
                    "ZL0003",
                    f"'@{statement.call.name}' block is empty",
                    statement.span,
                    "warning",
                )
            )
        for inner in statement.body:
            diagnostics.extend(_lint_statement(inner))
    elif isinstance(statement, Flow):
        diagnostics.extend(_lint_flow(statement))
    elif isinstance(statement, Binding) and statement.value is None:
        diagnostics.append(
            Diagnostic("ZL0002", f"binding ${statement.name} has no value", statement.span, "error")
        )
    return diagnostics


def _lint_flow(flow: Flow) -> List[Diagnostic]:
    diagnostics: List[Diagnostic] = []
    if flow.scope is not None and not flow.steps and flow.conditional is None:
        diagnostics.append(
            Diagnostic(
                "ZL0003",
                f"'@{flow.scope.name}' is not applied to any operation",
                flow.scope.span,
                "error",
            )
        )
    if flow.conditional is not None:
        diagnostics.extend(_lint_conditional(flow.conditional))
    for step in flow.steps:
        if isinstance(step, Path) and step.sigil == "" and len(step.parts[0]) > 24:
            diagnostics.append(
                Diagnostic(
                    "ZL0006",
                    f"atom '{step.parts[0]}' is long; free text should be quoted",
                    step.span,
                    "warning",
                )
            )
    return diagnostics


def _lint_conditional(node: Conditional) -> List[Diagnostic]:
    diagnostics: List[Diagnostic] = []
    if node.braced and isinstance(node.then_branch, Flow) and not node.then_branch.steps and (
        node.then_branch.conditional is None
    ):
        diagnostics.append(
            Diagnostic("ZL0007", "conditional has an empty then-branch", node.span, "warning")
        )
    for branch in (node.then_branch, node.else_branch):
        if isinstance(branch, Flow):
            diagnostics.extend(_lint_flow(branch))
    return diagnostics


def _has_terminal_action(program: Program) -> bool:
    """True when the payload performs at least one action.

    Any ``!ACTION`` qualifies: an action is by definition an observable effect,
    so the check is purely structural and never guesses at a verb vocabulary.
    """
    found = False

    def visit(node: Optional[Node]) -> None:
        nonlocal found
        if node is None or found:
            return
        if isinstance(node, Call) and node.sigil == "!":
            found = True
            return
        for child in node.children():
            visit(child)

    for statement in program.statements:
        visit(statement)
    return found
