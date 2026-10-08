"""The linguist agent: natural language ⇄ Zeno, with human-readable output.

Where :class:`zeno.encoder.Encoder` is the wire-level converter, the linguist
owns the *language* work around it:

* ``encode``    — natural language -> canonical Zeno (delegates to the Encoder)
* ``explain``   — Zeno -> English, deterministically, from the AST
* ``normalise`` — any spelling -> the one canonical spelling
* ``check``     — is this payload well-formed and coherent?

``explain`` never calls a model. That is the point: it is a pure function of
the AST, so it can be used to audit what a payload actually says, and it is the
reference semantics the encoder is aiming at.

    $ python -m agents.linguist explain '@LOC[TYO] -> ?WX : { $WX.state == RAIN => !GEN[INDOOR, 3] }'
    $ python -m agents.linguist encode "check the weather in Tokyo"
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from typing import Any, List, Optional

from zeno.ast import (
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
from zeno.emitter import canonicalize, emit
from zeno.encoder import EncodeResult, Encoder
from zeno.errors import ZenoError
from zeno.parser import parse
from zeno.validator import ValidationReport, validate

__all__ = ["Linguist", "explain_payload", "explain_node", "main"]

_BINARY_WORDS = {
    "==": "equals",
    "!=": "differs from",
    "~=": "matches",
    ">": "is greater than",
    "<": "is less than",
    ">=": "is at least",
    "<=": "is at most",
    "+": "plus",
    "-": "minus",
    "*": "times",
    "/": "divided by",
    "%": "modulo",
    "^": "to the power of",
    "&&": "and",
    "||": "or",
}


def _literal(node: Literal) -> str:
    if node.literal_type == "string":
        return f'"{node.value}"'
    if node.literal_type == "number":
        return str(node.value)
    return str(node.value).upper()


def explain_node(node: Optional[Node]) -> str:
    """Render one AST node as English (used by ``explain`` and by tests)."""
    if node is None:
        return "nothing"

    if isinstance(node, Flow):
        return explain_flow(node)
    if isinstance(node, Conditional):
        # With no own flow the colon hangs off the enclosing flow; the text
        # below is reused by explain_flow, which knows that context.
        return explain_conditional(node)
    if isinstance(node, Call):
        return explain_call(node)
    if isinstance(node, BinaryOp):
        return (
            f"{explain_node(node.left)} {_BINARY_WORDS.get(node.op, node.op)} "
            f"{explain_node(node.right)}"
        )
    if isinstance(node, UnaryOp):
        if node.op == "~":
            return f"the text of {explain_node(node.operand)}"
        return f"not {explain_node(node.operand)}"
    if isinstance(node, Attr):
        return f"{explain_node(node.base)}.{'.'.join(node.parts)}"
    if isinstance(node, Path):
        dotted = ".".join(node.parts)
        if node.sigil == "$":
            return f"the variable ${dotted}"
        if node.sigil == "?":
            return f"the query result ?{dotted}"
        if node.sigil == "!":
            return f"the action result !{dotted}"
        return str(node.parts[-1]).upper() if node.parts else "nothing"
    if isinstance(node, ListLiteral):
        return "the list [" + ", ".join(explain_node(item) for item in node.items) + "]"
    if isinstance(node, Literal):
        return _literal(node)
    if isinstance(node, Binding):
        return f"bind ${'.'.join(node.name)} to {explain_node(node.value)}"
    if isinstance(node, ScopeBlock):
        inner = " ".join(explain_statement(statement) for statement in node.body)
        return f"in the scope {explain_call(node.scope)}, {inner}"
    if isinstance(node, Program):
        return " ".join(explain_statement(statement) for statement in node.statements)
    return emit(node)  # pragma: no cover - defensive


def explain_call(call: Call) -> str:
    """``!GEN[INDOOR, 3]`` -> ``generate INDOOR, 3``."""
    name = call.name.upper()
    arguments = [explain_node(arg) for arg in call.args]
    arguments += [f"{key}={explain_node(value)}" for key, value in call.kwargs]

    if call.sigil == "@":
        return f"{name}" + (f" of {arguments[0]}" if arguments else "")
    if call.sigil == "?":
        verb = f"fetch {name}"
    else:
        verb = {
            "GEN": "generate",
            "RET": "return",
            "PRINT": "print",
            "LOG": "log",
            "SET": "set",
            "ASSERT": "assert",
        }.get(name, f"run {name}")
    return f"{verb} " + ", ".join(arguments) if arguments else verb


def explain_conditional(node: Conditional) -> str:
    then_text = explain_flow(node.then_branch) if node.then_branch else "do nothing"
    text = f"if {explain_node(node.test)} then {then_text}"
    if node.else_branch is not None:
        text += f", otherwise {explain_flow(node.else_branch)}"
    return text


def explain_flow(flow: Flow) -> str:
    """Explain one flow: its scope, its steps and its conditional."""
    parts: List[str] = []
    if flow.scope is not None:
        parts.append(f"scope {explain_call(flow.scope)}")

    verb = "fetch" if flow.conditional is None else "fetch"
    if flow.steps:
        step_texts = [explain_node(step) for step in flow.steps]
        parts.append(f"{verb} " + ", then ".join(step_texts) if len(step_texts) > 1 else step_texts[0])
    if flow.conditional is not None:
        parts.append(explain_conditional(flow.conditional))

    return "; ".join(part for part in parts if part) or "do nothing"


def explain_statement(statement: Node) -> str:
    if isinstance(statement, Binding):
        return explain_node(statement)
    if isinstance(statement, ScopeBlock):
        return explain_node(statement)
    if isinstance(statement, Flow):
        return explain_flow(statement)
    return explain_node(statement)


def explain_payload(payload: str) -> str:
    """Explain a whole payload, one statement per line."""
    program = parse(payload)
    lines = [explain_statement(statement) for statement in program.statements]
    return "\n".join(line + "." for line in lines if line)


@dataclass
class Linguist:
    """The language specialist in the cast of Zeno agents."""

    encoder: Optional[Encoder] = None
    provider: Any = None
    tools: Optional[List[str]] = None

    name = "linguist"

    def _make_encoder(self) -> Encoder:
        if self.encoder is None:
            self.encoder = Encoder(self.provider, tools=self.tools)
        return self.encoder

    # -- capabilities ----------------------------------------------------
    def encode(self, text: str, **kwargs: Any) -> EncodeResult:
        """Natural language -> canonical Zeno."""
        return self._make_encoder().encode(text, **kwargs)

    def explain(self, payload: str) -> str:
        """Zeno -> English, deterministically."""
        return explain_payload(payload)

    def normalise(self, payload: str) -> str:
        """Any legal spelling -> the canonical spelling."""
        return canonicalize(payload)

    def check(self, payload: str) -> ValidationReport:
        """Structural and semantic lint."""
        return validate(payload)

    def describe(self) -> dict:
        return {
            "agent": self.name,
            "capabilities": ["encode", "explain", "normalise", "check"],
            "model_backed": self._make_encoder().provider.available(),
        }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _read_text(arguments: List[str]) -> str:
    text = " ".join(arguments).strip()
    return text or sys.stdin.read().strip()


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m agents.linguist",
        description="The linguist agent: encode, explain, normalise, check.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    encoder = sub.add_parser("encode", help="natural language -> Zeno")
    encoder.add_argument("text", nargs="*")
    encoder.add_argument("--provider")
    encoder.add_argument("--model")
    encoder.add_argument("--json", action="store_true")

    explain = sub.add_parser("explain", help="Zeno -> English")
    explain.add_argument("payload", nargs="*")
    explain.add_argument("--json", action="store_true")

    normalise = sub.add_parser("normalise", help="print the canonical spelling")
    normalise.add_argument("payload", nargs="*")

    check = sub.add_parser("check", help="validate a payload")
    check.add_argument("payload", nargs="*")
    check.add_argument("--json", action="store_true")

    args = parser.parse_args(argv)
    linguist = Linguist()

    try:
        if args.command == "encode":
            result = linguist.encode(_read_text(args.text))
            if args.json:
                print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
            else:
                print(result.payload)
                if result.fell_back:
                    print("# rule-based fallback (no provider configured)", file=sys.stderr)
            return 0

        if args.command == "explain":
            payload = _read_text(args.payload)
            explanation = linguist.explain(payload)
            if args.json:
                print(json.dumps({"payload": payload, "english": explanation}, indent=2))
            else:
                print(explanation)
            return 0

        if args.command == "normalise":
            print(linguist.normalise(_read_text(args.payload)))
            return 0

        if args.command == "check":
            report = linguist.check(_read_text(args.payload))
            if args.json:
                print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
            else:
                print(report.render())
            return 0 if report.ok else 1

    except ZenoError as exc:
        print(exc.render(), file=sys.stderr)
        return 2

    return 0  # pragma: no cover - argparse rejects unknown commands


if __name__ == "__main__":
    raise SystemExit(main())
