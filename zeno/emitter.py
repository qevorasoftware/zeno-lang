"""AST -> canonical Zeno source.

The emitter defines the *canonical form* of a payload. Compilers should always
emit through this module so that semantically identical payloads become byte
identical, which keeps prompt caches warm and makes diffs reviewable.

Guarantees checked by the test-suite:

* ``emit(parse(emit(parse(src)))) == emit(parse(src))`` (idempotence)
* ``parse(emit(ast)) == ast`` (round-trip)

Set ``explicit_bindings=True`` to render ``$X = ?X`` for every implicitly bound
step. That form is self-documenting for humans and for smaller target models,
at the cost of a handful of tokens.
"""

from __future__ import annotations

from typing import List, Optional, Sequence

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

__all__ = ["emit", "emit_expression", "canonicalize"]

_STRING_ESCAPES = {
    "\\": "\\\\",
    '"': '\\"',
    "\n": "\\n",
    "\t": "\\t",
    "\r": "\\r",
    "\0": "\\0",
}


def _format_number(value) -> str:
    if isinstance(value, bool):  # pragma: no cover - bools are literals elsewhere
        return "TRUE" if value else "FALSE"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if value.is_integer() and abs(value) < 1e16:
            return str(int(value))
        return repr(value)
    return str(value)


def _quote(value: str) -> str:
    out: List[str] = ['"']
    for char in value:
        out.append(_STRING_ESCAPES.get(char, char))
    out.append('"')
    return "".join(out)


def _emit_literal(node: Literal) -> str:
    if node.literal_type == "bool":
        return "TRUE" if node.value else "FALSE"
    if node.literal_type == "nil":
        return "NIL"
    if node.literal_type == "number":
        return _format_number(node.value)
    return _quote(str(node.value))


def _emit_kwarg_key(key: str) -> str:
    """``WX.temp`` renders back as the state-addressed ``$WX.temp``."""
    return f"${key}" if "." in key else key


def _emit_call(node: Call) -> str:
    head = f"{node.sigil}{node.name}"
    if not node.args and not node.kwargs:
        return head
    parts = [emit_expression(arg) for arg in node.args]
    parts.extend(f"{_emit_kwarg_key(key)}={emit_expression(value)}" for key, value in node.kwargs)
    return f"{head}[{', '.join(parts)}]"


def _emit_path(node: Path) -> str:
    return f"{node.sigil}{'.'.join(node.parts)}"


def emit_expression(node: Node) -> str:
    """Render any expression node as canonical Zeno source."""
    if isinstance(node, Call):
        return _emit_call(node)
    if isinstance(node, Path):
        return _emit_path(node)
    if isinstance(node, Literal):
        return _emit_literal(node)
    if isinstance(node, Attr):
        return f"{emit_expression(node.base)}.{'.'.join(node.parts)}"
    if isinstance(node, ListLiteral):
        return "[" + ", ".join(emit_expression(item) for item in node.items) + "]"
    if isinstance(node, UnaryOp):
        operand = emit_expression(node.operand)
        if node.op == "~":
            return f"~{operand}"
        return f"-{operand}"
    if isinstance(node, BinaryOp):
        return f"{emit_expression(node.left)} {node.op} {emit_expression(node.right)}"
    if isinstance(node, Conditional):
        return _emit_conditional(node)
    if isinstance(node, Flow):
        return emit_flow(node)
    raise TypeError(f"cannot emit node of type {type(node).__name__}")  # pragma: no cover


def _emit_conditional(node: Conditional) -> str:
    """Canonical form always uses the braced variant: it is unambiguous."""
    test = emit_expression(node.test)
    body = f"{test} => {emit_flow(node.then_branch)}"
    if node.else_branch is not None:
        body += f" | {emit_flow(node.else_branch)}"
    return f": {{ {body} }}"


def emit_flow(node: Flow, *, include_scope: bool = True) -> str:
    """Render a flow, optionally with its leading ``@scope``."""
    chunks: List[str] = []
    if include_scope and node.scope is not None:
        chunks.append(_emit_call(node.scope))
    chunks.extend(emit_expression(step) for step in node.steps)
    text = " -> ".join(chunks)
    if node.conditional is not None:
        body = _emit_conditional(node.conditional)
        text = f"{text} {body}".strip() if text else body
    return text


def emit(node: Node, *, explicit_bindings: bool = False) -> str:
    """Render ``node`` as canonical Zeno source.

    Parameters
    ----------
    node:
        Any AST node; :class:`~zeno.ast.Program` renders as a multi-line payload.
    explicit_bindings:
        Also render the ``$X = `` prefix for every step the parser marked as
        implicitly binding. Off by default: the implicit form is shorter and
        the parser restores the same AST.
    """
    if isinstance(node, Program):
        lines: List[str] = []
        for statement in node.statements:
            lines.append(emit(statement, explicit_bindings=explicit_bindings))
        return "\n".join(lines)
    if isinstance(node, ScopeBlock):
        header = _emit_call(node.call)
        if not node.body:
            return f"{header} {{}}"
        inner = "\n".join(
            "  " + emit(statement, explicit_bindings=explicit_bindings).replace("\n", "\n  ")
            for statement in node.body
        )
        return f"{header} {{\n{inner}\n}}"
    if isinstance(node, Binding):
        prefix = "LET " if node.explicit else ""
        if node.value is None:
            # Parser-synthesised binding marker: no source form of its own.
            return ""
        return f"{prefix}${'.'.join(node.path)} = {emit_expression(node.value)}"
    if isinstance(node, Flow):
        text = emit_flow(node)
        if explicit_bindings and node.bindings:
            prefix = " ".join(
                f"${binding.name} = ?{binding.name};" for binding in node.bindings
            )
            return f"{prefix} {text}"
        return text
    return emit_expression(node)


def canonicalize(source: str, *, explicit_bindings: bool = False) -> str:
    """Parse ``source`` and re-emit it in canonical form."""
    from .parser import parse

    return emit(parse(source), explicit_bindings=explicit_bindings)
