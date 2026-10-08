"""Diagnostics for the Zeno Protocol.

Every error carries a stable diagnostic code from ``specs/tokens.json`` so that
agents can react to failures programmatically without parsing prose.
"""

from __future__ import annotations

from typing import Optional

from .span import Position, Span

__all__ = [
    "ZenoError",
    "LexError",
    "UnterminatedString",
    "ZenoSyntaxError",
    "UnbalancedDelimiter",
    "MissingThenBranch",
    "StrayElse",
    "EncodeError",
    "ZenoRuntimeError",
    "UnresolvedQuery",
    "UnknownAction",
    "UndefinedVariable",
    "TypeMismatch",
    "DivisionByZero",
    "ProviderError",
]

#: Lint codes produced by :mod:`zeno.validator`. Declared here, next to the
#: exception codes, so ``DIAGNOSTICS`` is the single source of truth for every
#: ZN/ZL code in the language.
LINT_CODES = {
    "ZL0001": "Undefined variable: the payload reads a $VARIABLE that nothing binds.",
    "ZL0002": "Unused binding: a query or action result is never read.",
    "ZL0003": "Empty scope: '@TARGET' applies to nothing.",
    "ZL0004": "No terminal action: the payload produces no observable output.",
    "ZL0005": "Atom shadows a binding: a bare name matches a variable name exactly.",
    "ZL0006": "Suspicious atom: a bare name is very long (probably unquoted free text).",
    "ZL0007": "Redundant braces: the conditional body is a single statement.",
}

#: Canonical messages, mirrored from ``specs/tokens.json``.
DIAGNOSTICS = {
    "ZN0001": "Lexical error: unexpected character.",
    "ZN0002": "Unterminated string literal.",
    "ZN0003": "Parse error: unexpected token.",
    "ZN0004": "Parse error: unbalanced delimiter.",
    "ZN0005": "Parse error: conditional requires a '=>' branch.",
    "ZN0006": "Parse error: '|' else-branch used outside a conditional.",
    "ZN1001": "Encode error: model output did not parse as Zeno after the repair budget was exhausted.",
    "ZN2001": "Runtime error: unresolved query target.",
    "ZN2002": "Runtime error: unknown action.",
    "ZN2003": "Runtime error: undefined variable.",
    "ZN2004": "Runtime error: type mismatch in operator.",
    "ZN2005": "Runtime error: division by zero.",
    "ZN3001": "Provider error: no LLM provider is configured or reachable.",
}
DIAGNOSTICS.update(LINT_CODES)



class ZenoError(Exception):
    """Base class for every Zeno diagnostic.

    Parameters
    ----------
    message:
        Human readable detail. The terse `code` catalogue entry is prepended
        when the error is rendered.
    span:
        Optional source location used to render a caret preview.
    hint:
        Optional actionable suggestion, surfaced as a ``hint:`` line.
    """

    code = "ZN0000"
    label = "ZenoError"

    def __init__(
        self,
        message: str,
        span: Optional[Span] = None,
        *,
        hint: Optional[str] = None,
        source: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.hint = hint
        if span is None and source is not None:
            span = Span.at(Position(0, 1, 1), source)
        elif span is not None and source is not None and not span.source:
            span = Span(span.start, span.end, source)
        self.span = span

    # -- presentation ----------------------------------------------------
    @property
    def summary(self) -> str:
        """``ZN0003: Parse error: unexpected token.``"""
        base = DIAGNOSTICS.get(self.code, self.__class__.__doc__ or "").strip()
        return f"{self.code}: {base}"

    @property
    def detail(self) -> str:
        """The code-free, instance-specific message."""
        return self.message

    def render(self, *, color: bool = False) -> str:
        bold = "\033[1m" if color else ""
        red = "\033[31m" if color else ""
        cyan = "\033[36m" if color else ""
        dim = "\033[2m" if color else ""
        reset = "\033[0m" if color else ""

        lines = [f"{red}{bold}{self.label}{reset} [{bold}{self.code}{reset}]: {self.message}"]
        span = self.span
        if span is not None and span.source:
            line_no = span.start.line
            col_no = span.start.column
            gutter = len(str(line_no))
            lines.append(f"{dim}  --> payload:{line_no}:{col_no}{reset}")
            lines.append(f"{dim}{' ' * gutter} |{reset}")
            lines.append(f"{cyan}{line_no:>{gutter}} |{reset} {span.line_text}")
            lines.append(f"{dim}{' ' * gutter} |{reset} {red}{span.caret()}{reset}")
        if self.hint:
            lines.append(f"{cyan}hint:{reset} {self.hint}")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        payload = {"code": self.code, "label": self.label, "message": self.message}
        if self.span is not None:
            payload["location"] = {
                "line": self.span.start.line,
                "column": self.span.start.column,
                "end_line": self.span.end.line,
                "end_column": self.span.end.column,
            }
        if self.hint:
            payload["hint"] = self.hint
        return payload

    def __str__(self) -> str:
        return self.render()


# ---------------------------------------------------------------------------
# Lexical
# ---------------------------------------------------------------------------
class LexError(ZenoError):
    """Raised when the tokenizer meets a character it cannot classify."""

    code = "ZN0001"
    label = "ZenoLexError"


class UnterminatedString(LexError):
    code = "ZN0002"
    label = "ZenoLexError"

    def __init__(self, span: Optional[Span] = None, **kwargs) -> None:
        super().__init__(
            "unterminated string literal",
            span,
            hint='close the literal with a double quote, e.g. "READY"',
            **kwargs,
        )


# ---------------------------------------------------------------------------
# Syntax
# ---------------------------------------------------------------------------
class ZenoSyntaxError(ZenoError):
    """Raised when a token stream does not match Grammar v0.1."""

    code = "ZN0003"
    label = "ZenoSyntaxError"


class UnbalancedDelimiter(ZenoSyntaxError):
    code = "ZN0004"
    label = "ZenoSyntaxError"


class MissingThenBranch(ZenoSyntaxError):
    code = "ZN0005"
    label = "ZenoSyntaxError"

    def __init__(self, span: Optional[Span] = None, **kwargs) -> None:
        super().__init__(
            "conditional block evaluated without a '=>' branch",
            span,
            hint="write `: { <test> => <then-flow> | <else-flow> }`",
            **kwargs,
        )


class StrayElse(ZenoSyntaxError):
    code = "ZN0006"
    label = "ZenoSyntaxError"

    def __init__(self, span: Optional[Span] = None, **kwargs) -> None:
        super().__init__(
            "'|' else-branch used outside of a conditional block",
            span,
            hint="'|' is only valid after a '=>' branch; use '||' for logical OR",
            **kwargs,
        )


# ---------------------------------------------------------------------------
# Encoding
# ---------------------------------------------------------------------------
class EncodeError(ZenoError):
    """Raised when an encoder cannot produce a parseable payload.

    Raised once the encoder's repair budget (``max_repairs``) is exhausted and
    no fallback is available.
    """

    code = "ZN1001"
    label = "ZenoEncodeError"


# ---------------------------------------------------------------------------
# Runtime
# ---------------------------------------------------------------------------
class ZenoRuntimeError(ZenoError):
    """Base class for evaluation failures."""

    label = "ZenoRuntimeError"


class UnresolvedQuery(ZenoRuntimeError):
    code = "ZN2001"
    label = "ZenoRuntimeError"


class UnknownAction(ZenoRuntimeError):
    code = "ZN2002"
    label = "ZenoRuntimeError"


class UndefinedVariable(ZenoRuntimeError):
    code = "ZN2003"
    label = "ZenoRuntimeError"


class TypeMismatch(ZenoRuntimeError):
    code = "ZN2004"
    label = "ZenoRuntimeError"


class DivisionByZero(ZenoRuntimeError):
    code = "ZN2005"
    label = "ZenoRuntimeError"


# ---------------------------------------------------------------------------
# Providers
# ---------------------------------------------------------------------------
class ProviderError(ZenoError):
    """Raised when an LLM backend is missing, misconfigured or unreachable."""

    code = "ZN3001"
    label = "ZenoProviderError"
