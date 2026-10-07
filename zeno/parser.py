"""Recursive-descent parser for Zeno Grammar v0.1.

The parser is single-pass with one token of lookahead plus a bounded
lookahead probe used to disambiguate ``$X = ...`` bindings from ``$X ...``
flow steps. Every failure carries a diagnostic code from
:mod:`zeno.errors`.

    >>> from zeno.parser import parse
    >>> program = parse("@LOC[TYO] -> ?WX : { $WX.state == RAIN => !GEN[INDOOR, 3] | !GEN[OUTDOOR, 3] }")
    >>> type(program.statements[0]).__name__
    'Flow'
"""

from __future__ import annotations

from typing import List, Optional, Sequence, Tuple

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
from .errors import (
    MissingThenBranch,
    StrayElse,
    UnbalancedDelimiter,
    ZenoSyntaxError,
)
from .lexer import Token, tokenize
from .span import Span

__all__ = ["Parser", "parse"]

#: NAME spellings that lex to literal atoms rather than identifiers.
_BOOL_LITERALS = {"TRUE": True, "FALSE": False}
_NIL_LITERALS = {"NIL", "NULL", "NONE"}
_LET = "LET"

_COMPARISON_KINDS = {"EQ", "NEQ", "MATCH", "GT", "GTE", "LT", "LTE"}
_COMPARISON_TEXT = {
    "EQ": "==",
    "NEQ": "!=",
    "MATCH": "~=",
    "GT": ">",
    "GTE": ">=",
    "LT": "<",
    "LTE": "<=",
}

_STEP_KINDS = {"QUERY", "ACTION"}


class Parser:
    """Turn Zeno source into an :class:`~zeno.ast.Program`."""

    def __init__(self, source: str, tokens: Optional[Sequence[Token]] = None) -> None:
        self.source = source
        self.tokens: List[Token] = list(tokens) if tokens is not None else tokenize(source)
        self.index = 0
        self._soft_depth = 0
        self._pending_primary: Optional[Node] = None

    # ------------------------------------------------------------------
    # Token plumbing
    # ------------------------------------------------------------------
    def _skip_soft(self) -> None:
        """Skip newlines when the surrounding construct ignores line breaks."""
        if not self._soft_depth:
            return
        tokens = self.tokens
        index = self.index
        limit = len(tokens)
        while index < limit and tokens[index].kind == "NEWLINE":
            index += 1
        self.index = index

    def peek(self, ahead: int = 0) -> Token:
        self._skip_soft()
        index = self.index + ahead
        if self._soft_depth:
            while index < len(self.tokens) - 1 and self.tokens[index].kind == "NEWLINE":
                index += 1
        if index >= len(self.tokens):
            return self.tokens[-1]
        return self.tokens[index]

    def advance(self) -> Token:
        token = self.peek()
        if token.kind != "EOF":
            self.index += 1
        return token

    def at(self, kind: str) -> bool:
        return self.peek().kind == kind

    def enter_soft(self) -> None:
        self._soft_depth += 1

    def leave_soft(self) -> None:
        self._soft_depth = max(0, self._soft_depth - 1)

    # ------------------------------------------------------------------
    # Errors
    # ------------------------------------------------------------------
    def error(
        self,
        message: str,
        token: Optional[Token] = None,
        *,
        cls: type = ZenoSyntaxError,
        hint: Optional[str] = None,
        span: Optional[Span] = None,
    ):
        token = token or self.peek()
        if span is None:
            span = token.span
        return cls(message, span, hint=hint)

    def expect(
        self,
        kind: str,
        what: str,
        *,
        cls: type = ZenoSyntaxError,
        hint: Optional[str] = None,
    ) -> Token:
        token = self.peek()
        if token.kind != kind:
            found = "end of payload" if token.kind == "EOF" else f"{token.text!r}"
            raise self.error(f"expected {what}, found {found}", token, cls=cls, hint=hint)
        return self.advance()

    def _span_from(self, start_index: int) -> Span:
        start_token = self.tokens[start_index]
        end_index = max(start_index, self.index - 1)
        end_token = self.tokens[end_index]
        return start_token.span.merge(end_token.span)

    # ------------------------------------------------------------------
    # Program
    # ------------------------------------------------------------------
    def parse_program(self) -> Program:
        start_index = self.index
        statements: List[Node] = []
        self.skip_separators()
        while not self.at("EOF"):
            statements.append(self.parse_statement())
            if not self.at("EOF"):
                self.skip_separators()
        span = self._span_from(start_index)
        return Program(tuple(statements), span=span)

    def skip_separators(self) -> None:
        while self.peek().kind in ("NEWLINE", "SEMI"):
            self.advance()

    def parse_statement(self) -> Node:
        token = self.peek()
        if token.kind == "ELSE":
            raise StrayElse(span=token.span)
        if token.kind == "TARGET":
            return self.parse_target_statement()
        if token.kind == "VARIABLE" and self._binding_ahead(0):
            return self.parse_binding()
        if token.kind == "NAME" and token.text.upper() == _LET:
            return self.parse_binding()
        return self.parse_flow()

    # -- bindings -------------------------------------------------------
    def _binding_ahead(self, offset: int) -> bool:
        """``True`` when the tokens ahead form ``$PATH =``."""
        index = self.index + offset
        if index >= len(self.tokens) or self.tokens[index].kind != "VARIABLE":
            return False
        index += 1
        if index >= len(self.tokens) or self.tokens[index].kind != "NAME":
            return False
        index += 1
        while (
            index + 1 < len(self.tokens)
            and self.tokens[index].kind == "DOT"
            and self.tokens[index + 1].kind == "NAME"
        ):
            index += 2
        return index < len(self.tokens) and self.tokens[index].kind == "ASSIGN"

    def parse_binding(self) -> Binding:
        start_index = self.index
        explicit = False
        token = self.peek()
        if token.kind == "NAME" and token.text.upper() == _LET:
            explicit = True
            self.advance()
        self.expect("VARIABLE", "'$' to start a variable binding")
        parts = self.parse_path_parts()
        self.expect("ASSIGN", "'=' to assign a variable", hint=f"did you mean '==' or '=>'?")
        value = self.parse_expression()
        return Binding(tuple(parts), value, explicit, span=self._span_from(start_index))

    def parse_path_parts(self, first: Optional[str] = None) -> List[str]:
        head = first if first is not None else self.expect("NAME", "a variable name").text
        parts = [head]
        while self.at("DOT") and self.peek(1).kind == "NAME":
            self.advance()
            parts.append(self.advance().text)
        return parts

    # -- targets --------------------------------------------------------
    def parse_target_statement(self) -> Node:
        start_index = self.index
        scope = self.parse_scope_call()

        # Reuse the untouched arg list as the block header arguments.
        if self.at("LBRACE"):
            self.advance()
            body: List[Node] = []
            self.skip_separators()
            while not self.at("RBRACE"):
                if self.at("EOF"):
                    raise self.error(
                        "unclosed scope block",
                        cls=UnbalancedDelimiter,
                        hint="add a '}' to close the block opened by '@"
                        + scope.name
                        + " { ... }'",
                    )
                body.append(self.parse_statement())
                self.skip_separators()
            self.advance()  # consume '}'
            block = ScopeBlock(
                call=scope, body=tuple(body), span=self._span_from(start_index)
            )
            # A scope block may itself drive a pipeline: `@A[X] { ... } -> ?Y` is not
            # part of v0.1, but a trailing conditional is tolerated for readability.
            if self.at("COLON"):
                conditional = self.parse_conditional()
                return Flow(
                    scope=None,
                    steps=(),
                    conditional=conditional,
                    span=self._span_from(start_index),
                )
            return block

        if self.at("SEMI") or self.at("NEWLINE") or self.at("EOF"):
            raise self.error(
                f"scope '@{scope.name}' has no operation",
                hint="append a step such as '-> ?STATE' or a block '{ ... }'",
            )
        return self.parse_flow(leading_scope=scope, start_index=start_index)

    def parse_scope_call(self) -> Call:
        start_index = self.index
        self.expect("TARGET", "'@' to start a scope")
        name_token = self.expect("NAME", "a scope name after '@'")
        args, kwargs = self.parse_arguments()
        return Call(
            "@", name_token.text.upper(), args, kwargs, span=self._span_from(start_index)
        )

    def parse_arguments(self) -> Tuple[Tuple[Node, ...], Tuple[Tuple[str, Node], ...]]:
        if not self.at("LBRACKET"):
            return (), ()
        self.advance()
        self.enter_soft()
        args: List[Node] = []
        kwargs: List[Tuple[str, Node]] = []
        if self.at("RBRACKET"):
            self.advance()
            self.leave_soft()
            return (), ()
        while True:
            key = self.parse_named_argument_key()
            if key is not None:
                kwargs.append((key, self.parse_expression()))
            else:
                args.append(self.parse_expression())
            if self.at("COMMA"):
                self.advance()
                if self.at("RBRACKET"):
                    break
                continue
            break
        if self.at("EOF"):
            raise self.error(
                "unclosed argument list",
                cls=UnbalancedDelimiter,
                hint="add a ']' to close this argument list",
            )
        self.expect("RBRACKET", "']' to close the argument list", cls=UnbalancedDelimiter)
        self.leave_soft()
        return tuple(args), tuple(kwargs)

    #: Token kinds that continue an expression after a call head.
    _CONTINUATION_KINDS = {
        "ADD",
        "SUB",
        "MUL",
        "DIV",
        "MOD",
        "POW",
        "EQ",
        "NEQ",
        "MATCH",
        "GT",
        "GTE",
        "LT",
        "LTE",
        "AND",
        "OR",
        "DOT",
    }

    def _operator_follows_call(self) -> bool:
        """``True`` when ``?NAME[args]`` is the head of a larger expression."""
        index = self.index
        tokens = self.tokens
        if tokens[index].kind not in _STEP_KINDS:
            return False
        index += 1
        if index < len(tokens) and tokens[index].kind == "NAME":
            index += 1
        else:
            return False
        if index < len(tokens) and tokens[index].kind == "LBRACKET":
            depth = 0
            while index < len(tokens):
                kind = tokens[index].kind
                if kind == "LBRACKET":
                    depth += 1
                elif kind == "RBRACKET":
                    depth -= 1
                    if depth == 0:
                        index += 1
                        break
                elif kind == "EOF":
                    return False
                index += 1
        return index < len(tokens) and tokens[index].kind in self._CONTINUATION_KINDS

    def parse_named_argument_key(self) -> Optional[str]:
        """Consume a ``NAME=`` or ``$PATH=`` prefix, returning the binding key.

        Accepts both spellings from the grammar: ``TOP=5`` and the
        state-addressed ``$WX.temp=31`` used by ``!RET`` result frames.
        """
        if self.at("NAME") and self.peek(1).kind == "ASSIGN":
            name = self.advance()
            self.advance()  # '='
            return name.text
        if self.at("VARIABLE") and self._binding_ahead(0):
            self.advance()  # '$'
            parts = self.parse_path_parts()
            self.advance()  # '='
            return ".".join(parts)
        return None

    # -- flow -----------------------------------------------------------
    def parse_flow(self, leading_scope: Optional[Call] = None, start_index: Optional[int] = None) -> Flow:
        if start_index is None:
            start_index = self.index
        scope = leading_scope
        if scope is None and self.at("TARGET"):
            scope = self.parse_scope_call()

        if scope is not None and not self.at("ARROW"):
            raise self.error(
                f"scope '@{scope.name}' is not applied to any operation",
                scope.span,
                hint="wire the scope into a pipeline with '->', e.g. '@"
                + scope.name
                + " -> ?STATE'",
            )

        if scope is not None:
            self.advance()  # consume the '->' that wires the scope into the flow

        steps: List[Node] = []
        if not self.at("COLON"):
            steps.append(self.parse_step())
            while self.at("ARROW"):
                self.advance()
                steps.append(self.parse_step())

        conditional = None
        if self.at("COLON"):
            conditional = self.parse_conditional()
        elif self.at("THEN"):
            # Brace-free evaluator: `$WX == RAIN => !INDOOR | !OUTDOOR`
            if not steps or isinstance(steps[-1], Call):
                raise MissingThenBranch(span=self._span_from(start_index))
            test = steps.pop()
            conditional = self.parse_conditional_tail(
                test, braced=False, start_index=start_index
            )

        if not steps and conditional is None:
            token = self.peek()
            raise self.error(
                f"expected an operation, found {token.text!r}",
                token,
                hint="a flow needs at least one '?query' or '!action' step",
            )

        flow = Flow(
            scope=scope,
            steps=tuple(steps),
            conditional=conditional,
            span=self._span_from(start_index),
        )
        return self._annotate_bindings(flow)

    def parse_step(self) -> Node:
        token = self.peek()
        if token.kind in _STEP_KINDS:
            if not self._operator_follows_call():
                return self.parse_call()
            call = self.parse_call()
            self._pending_primary = call
            return self.parse_expression()
        if token.kind in ("ARROW", "ELSE", "THEN", "RBRACE", "RBRACKET", "SEMI", "NEWLINE", "EOF"):
            raise self.error(
                f"expected an operation, found {token.text!r}",
                token,
                hint="every '->' must be followed by a '?query' or '!action'",
            )
        node = self.parse_expression()
        if (
            isinstance(node, Path)
            and node.sigil == ""
            and not self.at("THEN")
        ):
            raise self.error(
                f"bare atom {node.name!r} is not an operation",
                hint="a step must be a '?query' or '!action'; quote free text as a "
                "string argument instead",
            )
        return node

    def parse_call(self) -> Call:
        start_index = self.index
        sigil_token = self.advance()
        sigil = {"QUERY": "?", "ACTION": "!", "TARGET": "@"}[sigil_token.kind]
        name_token = self.expect("NAME", "a name after '" + sigil + "'")
        args, kwargs = self.parse_arguments()
        return Call(
            sigil,
            name_token.text.upper(),
            args,
            kwargs,
            span=self._span_from(start_index),
        )

    # -- conditional ----------------------------------------------------
    def parse_conditional(self) -> Conditional:
        """``: [ { ] <test> => <then> [ | <else> ] [ } ]``"""
        start_index = self.index
        self.expect("COLON", "':' to open an evaluator block")
        braced = False
        if self.at("LBRACE"):
            braced = True
            self.advance()
            self.enter_soft()
        test = self.parse_expression()
        return self.parse_conditional_tail(test, braced=braced, start_index=start_index)

    def parse_conditional_tail(
        self, test: Node, *, braced: bool, start_index: int
    ) -> Conditional:
        """Parse ``=> <then-flow> [ | <else-flow> ] [ } ]`` around a known test."""
        if not self.at("THEN"):
            if braced:
                raise MissingThenBranch(span=self._span_from(start_index))
            raise self.error(
                "expected '=>' after the evaluator test",
                hint="write `: <test> => <then-flow> | <else-flow>`",
            )
        self.advance()
        then_branch = self.parse_flow()
        else_branch = None
        if self.at("ELSE"):
            self.advance()
            else_branch = self.parse_flow()
        if braced:
            if not self.at("RBRACE"):
                raise self.error(
                    "unclosed evaluator block",
                    cls=UnbalancedDelimiter,
                    hint="add a '}' to close this conditional",
                )
            self.advance()
            self.leave_soft()
        return Conditional(
            test=test,
            then_branch=then_branch,
            else_branch=else_branch,
            braced=braced,
            span=self._span_from(start_index),
        )

    # ------------------------------------------------------------------
    # Expressions
    # ------------------------------------------------------------------
    def parse_expression(self) -> Node:
        return self.parse_or()

    def parse_or(self) -> Node:
        start_index = self.index
        node = self.parse_and()
        while self.at("OR"):
            self.advance()
            right = self.parse_and()
            node = BinaryOp("||", node, right, span=self._span_from(start_index))
        return node

    def parse_and(self) -> Node:
        start_index = self.index
        node = self.parse_comparison()
        while self.at("AND"):
            self.advance()
            right = self.parse_comparison()
            node = BinaryOp("&&", node, right, span=self._span_from(start_index))
        return node

    def parse_comparison(self) -> Node:
        start_index = self.index
        node = self.parse_additive()
        while self.peek().kind in _COMPARISON_KINDS:
            op = _COMPARISON_TEXT[self.advance().kind]
            right = self.parse_additive()
            node = BinaryOp(op, node, right, span=self._span_from(start_index))
        return node

    def parse_additive(self) -> Node:
        start_index = self.index
        node = self.parse_multiplicative()
        while self.peek().kind in ("ADD", "SUB"):
            op = "+" if self.advance().kind == "ADD" else "-"
            right = self.parse_multiplicative()
            node = BinaryOp(op, node, right, span=self._span_from(start_index))
        return node

    def parse_multiplicative(self) -> Node:
        start_index = self.index
        node = self.parse_unary()
        while self.peek().kind in ("MUL", "DIV", "MOD"):
            kind = self.advance().kind
            op = {"MUL": "*", "DIV": "/", "MOD": "%"}[kind]
            right = self.parse_unary()
            node = BinaryOp(op, node, right, span=self._span_from(start_index))
        return node

    def parse_unary(self) -> Node:
        start_index = self.index
        token = self.peek()
        if token.kind == "NOT":
            self.advance()
            operand = self.parse_unary()
            return UnaryOp("~", operand, span=self._span_from(start_index))
        if token.kind == "SUB":
            self.advance()
            operand = self.parse_unary()
            return UnaryOp("-", operand, span=self._span_from(start_index))
        return self.parse_power()

    def parse_power(self) -> Node:
        start_index = self.index
        node = self.parse_postfix()
        if self.at("POW"):
            self.advance()
            exponent = self.parse_unary()  # right associative
            return BinaryOp("^", node, exponent, span=self._span_from(start_index))
        return node

    def parse_postfix(self) -> Node:
        start_index = self.index
        node = self.parse_primary()
        while self.at("DOT") and self.peek(1).kind == "NAME":
            self.advance()
            part = self.advance().text
            if isinstance(node, Path):
                # `$WX.state` stays a single dotted Path (§4.1).
                node = Path(
                    (*node.parts, part),
                    node.implicit_binding,
                    node.sigil,
                    span=self._span_from(start_index),
                )
            elif isinstance(node, Attr):
                node = Attr(
                    node.base, (*node.parts, part), span=self._span_from(start_index)
                )
            else:
                # `?PRICE[ACME].price` keeps the call and reads from its result.
                node = Attr(node, (part,), span=self._span_from(start_index))
        return node

    def parse_primary(self) -> Node:
        start_index = self.index
        if self._pending_primary is not None:
            # A step call was already parsed; reuse it as the leftmost operand
            # so that `?PRICE[ACME] < 120` is one comparison expression.
            node, self._pending_primary = self._pending_primary, None
            return node
        token = self.peek()

        if token.kind == "NUMBER":
            self.advance()
            return Literal(
                token.value, token.text, "number", span=self._span_from(start_index)
            )
        if token.kind == "STRING":
            self.advance()
            return Literal(
                token.value, token.text, "string", span=self._span_from(start_index)
            )
        if token.kind == "VARIABLE":
            self.advance()
            parts = self.parse_path_parts()
            return Path(tuple(parts), sigil="$", span=self._span_from(start_index))
        if token.kind == "NAME":
            upper = token.text.upper()
            if upper in _BOOL_LITERALS:
                self.advance()
                return Literal(
                    _BOOL_LITERALS[upper], token.text, "bool", span=self._span_from(start_index)
                )
            if upper in _NIL_LITERALS:
                self.advance()
                return Literal(None, token.text, "nil", span=self._span_from(start_index))
            self.advance()
            parts = self.parse_path_parts(token.text)
            return Path(tuple(parts), sigil="", span=self._span_from(start_index))
        if token.kind in _STEP_KINDS or token.kind == "TARGET":
            return self.parse_call()
        if token.kind == "LPAREN":
            self.advance()
            self.enter_soft()
            inner = self.parse_expression()
            if not self.at("RPAREN"):
                raise self.error(
                    "unclosed group",
                    cls=UnbalancedDelimiter,
                    hint="add a ')' to close this group",
                )
            self.advance()
            self.leave_soft()
            return inner.with_span(self._span_from(start_index))
        if token.kind == "LBRACKET":
            self.advance()
            self.enter_soft()
            items: List[Node] = []
            if not self.at("RBRACKET"):
                while True:
                    items.append(self.parse_expression())
                    if self.at("COMMA"):
                        self.advance()
                        if self.at("RBRACKET"):
                            break
                        continue
                    break
            if not self.at("RBRACKET"):
                raise self.error(
                    "unclosed list literal",
                    cls=UnbalancedDelimiter,
                    hint="add a ']' to close this list",
                )
            self.advance()
            self.leave_soft()
            return ListLiteral(tuple(items), span=self._span_from(start_index))
        if token.kind == "ELSE":
            raise StrayElse(span=token.span)
        if token.kind == "RBRACE":
            raise self.error(
                "unexpected '}'",
                token,
                cls=UnbalancedDelimiter,
                hint="this '}' does not close any open block",
            )

        found = "end of payload" if token.kind == "EOF" else f"{token.text!r}"
        raise self.error(f"expected an expression, found {found}", token)

    # ------------------------------------------------------------------
    # Implicit bindings (§3.1)
    # ------------------------------------------------------------------
    def _annotate_bindings(self, flow: Flow) -> Flow:
        """Mark calls whose result must be recorded into latent state.

        A call is bound when it is *read later* by the same flow, or when it is
        not the last step of the flow (its value feeds ``$PREV`` / ``$_``).
        """
        steps = list(flow.steps)
        if not steps:
            return flow

        referenced = _collect_variable_roots(flow.conditional)
        bound_names = set()
        annotated: List[Node] = []
        last_index = len(steps) - 1
        for index, step in enumerate(steps):
            if isinstance(step, Call):
                root = step.name.split(".", 1)[0]
                is_last = index == last_index
                needs_binding = (not is_last) or (root in referenced)
                if needs_binding:
                    step = Call(
                        step.sigil,
                        step.name,
                        step.args,
                        step.kwargs,
                        span=step.span,
                        implicit_binding=True,
                    )
                    bound_names.add(root)
            annotated.append(step)

        if not bound_names:
            return Flow(flow.scope, tuple(annotated), flow.conditional, (), span=flow.span)
        bindings = tuple(
            Binding((name,), None, False, span=flow.span) for name in sorted(bound_names)
        )
        return Flow(flow.scope, tuple(annotated), flow.conditional, bindings, span=flow.span)


def _collect_variable_roots(node: Optional[Node]) -> set:
    """Every ``$NAME`` root referenced anywhere inside ``node``."""
    roots: set = set()

    def walk(current: Optional[Node]) -> None:
        if current is None:
            return
        if isinstance(current, Path) and current.sigil == "$" and current.parts:
            roots.add(current.parts[0])
        for child in current.children():
            walk(child)

    walk(node)
    return roots


def parse(source: str) -> Program:
    """Parse a Zeno payload into a :class:`~zeno.ast.Program`.

    >>> parse("@LOC[TYO] -> ?WX").statements[0].steps[1].name
    'WX'
    """
    return Parser(source).parse_program()
