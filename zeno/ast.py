"""Abstract syntax tree for Zeno Grammar v0.1.

Every node is a frozen dataclass carrying a :class:`~zeno.span.Span` (excluded
from equality so that ASTs can be compared structurally across parses) and an
``implicit_binding`` marker.

``implicit_binding`` encodes §3.1 of the grammar: a step binds its own name into
the environment, and a step whose results feed another step also binds
``$PREV`` and ``$_``. The parser sets the marker; the emitter writes the
``$X = ?X`` form for the compiler; the interpreter records the values.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any, List, Optional, Tuple, Union

from .span import Span

__all__ = [
    "Node",
    "Program",
    "ScopeBlock",
    "Binding",
    "Flow",
    "Call",
    "Literal",
    "Path",
    "ListLiteral",
    "Attr",
    "UnaryOp",
    "BinaryOp",
    "Conditional",
    "TypeRef",
    "Statement",
]


# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Node:
    """Base class for every AST node.

    ``span`` is keyword-only so that subclasses can keep natural positional
    field order (``Call("!", "GEN", args)``) despite inheriting from this base.
    """

    span: Span = field(default=None, compare=False, repr=False, kw_only=True)

    def __post_init__(self) -> None:
        if self.span is None:
            object.__setattr__(self, "span", Span.synthetic())

    @property
    def line(self) -> int:
        return self.span.start.line

    @property
    def column(self) -> int:
        return self.span.start.column

    def children(self) -> Tuple["Node", ...]:
        """Direct child nodes, in source order."""
        return ()

    def with_span(self, span: Span) -> "Node":
        return replace(self, span=span)

    def to_dict(self) -> dict:  # pragma: no cover - overridden everywhere
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Structure
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Program(Node):
    """A whole payload: an ordered list of statements."""

    statements: Tuple["Statement", ...] = ()

    def children(self) -> Tuple[Node, ...]:
        return tuple(self.statements)

    def to_dict(self) -> dict:
        return {"type": "Program", "statements": [s.to_dict() for s in self.statements]}


@dataclass(frozen=True)
class ScopeBlock(Node):
    """``@KIND[args] { ... }`` — applies a scope to every inner statement."""

    call: "Call" = None
    body: Tuple["Statement", ...] = ()

    def children(self) -> Tuple[Node, ...]:
        return (self.call, *self.body)

    @property
    def scope(self) -> "Call":
        return self.call

    def to_dict(self) -> dict:
        return {
            "type": "ScopeBlock",
            "scope": self.call.to_dict(),
            "body": [node.to_dict() for node in self.body],
        }


@dataclass(frozen=True)
class Binding(Node):
    """``$NAME = <expr>`` (optionally prefixed with ``LET``)."""

    path: Tuple[str, ...] = ()
    value: Optional["Node"] = None
    explicit: bool = False

    def children(self) -> Tuple[Node, ...]:
        return (self.value,) if self.value is not None else ()

    @property
    def name(self) -> str:
        return ".".join(self.path)

    def to_dict(self) -> dict:
        return {
            "type": "Binding",
            "name": self.name,
            "path": list(self.path),
            "explicit": self.explicit,
            "value": self.value.to_dict() if self.value else None,
        }


@dataclass(frozen=True)
class Flow(Node):
    """``@scope? step (-> step)* conditional?``

    ``scope`` holds the leading ``@TARGET`` call for bare flows (the equivalent
    information lives in :class:`ScopeBlock` when braces are used).
    """

    scope: Optional["Call"] = None
    steps: Tuple["Node", ...] = ()
    conditional: Optional["Conditional"] = None
    bindings: Tuple[Binding, ...] = field(default=(), compare=False)

    def children(self) -> Tuple[Node, ...]:
        nodes: List[Node] = []
        if self.scope is not None:
            nodes.append(self.scope)
        nodes.extend(self.steps)
        if self.conditional is not None:
            nodes.append(self.conditional)
        return tuple(nodes)

    def to_dict(self) -> dict:
        return {
            "type": "Flow",
            "scope": self.scope.to_dict() if self.scope else None,
            "steps": [step.to_dict() for step in self.steps],
            "conditional": self.conditional.to_dict() if self.conditional else None,
            "bindings": [b.to_dict() for b in self.bindings],
        }


# ---------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Call(Node):
    """``?NAME[args]``, ``!NAME[args]`` or ``@NAME[args]``."""

    sigil: str = "?"  # one of "@", "?", "!"
    name: str = ""
    args: Tuple["Node", ...] = ()
    kwargs: Tuple[Tuple[str, "Node"], ...] = ()
    implicit_binding: bool = field(default=False, compare=False)

    def children(self) -> Tuple[Node, ...]:
        return (*self.args, *[value for _, value in self.kwargs])

    @property
    def kind(self) -> str:
        return {"@": "target", "?": "query", "!": "action"}[self.sigil]

    def arg(self, index: int, default: Any = None) -> Any:
        return self.args[index] if index < len(self.args) else default

    def to_dict(self) -> dict:
        return {
            "type": "Call",
            "kind": self.kind,
            "name": self.name,
            "args": [arg.to_dict() for arg in self.args],
            "kwargs": {key: value.to_dict() for key, value in self.kwargs},
        }


# ---------------------------------------------------------------------------
# Expressions
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Literal(Node):
    """A number, string, boolean or nil literal."""

    value: Any = None
    raw: Optional[str] = None
    #: ``number`` | ``string`` | ``bool`` | ``nil``
    literal_type: str = "nil"

    def to_dict(self) -> dict:
        return {"type": "Literal", "value": self.value, "value_type": self.literal_type}

    def __str__(self) -> str:  # pragma: no cover - debugging aid
        return self.raw if self.raw is not None else repr(self.value)


@dataclass(frozen=True)
class Path(Node):
    """``$WX.state.temp`` — a dotted reference into latent state."""

    parts: Tuple[str, ...] = ()
    implicit_binding: bool = field(default=False, compare=False)
    #: ``$`` for variables, or the empty string for a bare atom such as ``RAIN``.
    sigil: str = "$"

    def children(self) -> Tuple[Node, ...]:
        return ()

    @property
    def name(self) -> str:
        return ".".join(self.parts)

    @property
    def root(self) -> str:
        return self.parts[0] if self.parts else ""

    def __str__(self) -> str:  # pragma: no cover - debugging aid
        return f"{self.sigil}{self.name}"

    def to_dict(self) -> dict:
        return {"type": "Path", "name": self.name, "parts": list(self.parts), "sigil": self.sigil}


@dataclass(frozen=True)
class ListLiteral(Node):
    """``[a, b, c]``"""

    items: Tuple[Node, ...] = ()

    def children(self) -> Tuple[Node, ...]:
        return self.items

    def to_dict(self) -> dict:
        return {"type": "ListLiteral", "items": [item.to_dict() for item in self.items]}


@dataclass(frozen=True)
class Attr(Node):
    """``<expr>.property`` — property access on a non-path expression.

    ``?PRICE[ACME].price`` keeps the call (which binds ``$PRICE``) and reads a
    field from its result.
    """

    base: Optional[Node] = None
    parts: Tuple[str, ...] = ()

    def children(self) -> Tuple[Node, ...]:
        return (self.base,) if self.base is not None else ()

    @property
    def name(self) -> str:
        return ".".join(self.parts)

    def to_dict(self) -> dict:
        return {
            "type": "Attr",
            "base": self.base.to_dict() if self.base else None,
            "parts": list(self.parts),
        }


@dataclass(frozen=True)
class UnaryOp(Node):
    """``~x`` (logical not) or ``-x`` (negation)."""

    op: str = "~"
    operand: Optional[Node] = None

    def children(self) -> Tuple[Node, ...]:
        return (self.operand,) if self.operand else ()

    def to_dict(self) -> dict:
        return {"type": "UnaryOp", "op": self.op, "operand": self.operand.to_dict()}


@dataclass(frozen=True)
class BinaryOp(Node):
    """Any binary expression, arithmetic, comparison or logical."""

    op: str = ""
    left: Optional[Node] = None
    right: Optional[Node] = None

    def children(self) -> Tuple[Node, ...]:
        return tuple(node for node in (self.left, self.right) if node is not None)

    def to_dict(self) -> dict:
        return {
            "type": "BinaryOp",
            "op": self.op,
            "left": self.left.to_dict(),
            "right": self.right.to_dict(),
        }


@dataclass(frozen=True)
class Conditional(Node):
    """``: { <test> => <then-flow> | <else-flow> }``"""

    test: Optional[Node] = None
    then_branch: Optional[Node] = None
    else_branch: Optional[Node] = None
    #: ``True`` when the source used ``: { ... }``. Presentation only: the
    #: grammar guarantees both spellings produce the same tree, so this field
    #: is excluded from equality.
    braced: bool = field(default=False, compare=False)

    def children(self) -> Tuple[Node, ...]:
        return tuple(
            node for node in (self.test, self.then_branch, self.else_branch) if node is not None
        )

    def to_dict(self) -> dict:
        return {
            "type": "Conditional",
            "test": self.test.to_dict() if self.test else None,
            "then": self.then_branch.to_dict() if self.then_branch else None,
            "else": self.else_branch.to_dict() if self.else_branch else None,
            "braced": self.braced,
        }


# ---------------------------------------------------------------------------
# Optional type annotations (used by ?ASK[...] signatures / future type checking)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class TypeRef(Node):
    """``:NUMBER``, ``:[STRING]`` — a lightweight type annotation."""

    name: str = ""
    args: Tuple["TypeRef", ...] = ()

    def to_dict(self) -> dict:
        return {"type": "TypeRef", "name": self.name, "args": [a.to_dict() for a in self.args]}


#: Union alias for readability in signatures.
Statement = Union[ScopeBlock, Binding, Flow]
