"""Tokenizer for Zeno Grammar v0.1.

The lexer is a single-pass, constant-lookahead scanner. It is deliberately
tiny: Zeno's density comes from the grammar, not from a large vocabulary.

    >>> from zeno.lexer import tokenize
    >>> [t.kind for t in tokenize("@LOC[TYO] -> ?WX")][:-1]
    ['TARGET', 'NAME', 'LBRACKET', 'NAME', 'RBRACKET', 'ARROW', 'QUERY', 'NAME']
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional

from .errors import LexError, UnterminatedString
from .span import Position, Span

__all__ = ["Token", "tokenize", "TOKEN_KINDS", "KEYWORD_LITERALS", "SIGILS", "kind_of"]


# ---------------------------------------------------------------------------
# Token kinds
# ---------------------------------------------------------------------------
TOKEN_KINDS: FrozenSet[str] = frozenset(
    {
        # sigils
        "TARGET",
        "QUERY",
        "ACTION",
        "VARIABLE",
        # flow
        "ARROW",
        "COLON",
        "THEN",
        "ELSE",
        # operators
        "OR",
        "AND",
        "EQ",
        "NEQ",
        "MATCH",
        "GT",
        "GTE",
        "LT",
        "LTE",
        "ADD",
        "SUB",
        "MUL",
        "DIV",
        "MOD",
        "POW",
        "NOT",
        "ASSIGN",
        # delimiters
        "LPAREN",
        "RPAREN",
        "LBRACKET",
        "RBRACKET",
        "LBRACE",
        "RBRACE",
        "COMMA",
        "DOT",
        "SEMI",
        "NEWLINE",
        # literals
        "NUMBER",
        "STRING",
        "NAME",
        # sentinel
        "EOF",
    }
)

#: Names that lex as literal atoms rather than user identifiers.
KEYWORD_LITERALS: FrozenSet[str] = frozenset({"TRUE", "FALSE", "NIL", "NULL", "NONE"})

#: Sigil character -> token kind.
SIGILS: Dict[str, str] = {"@": "TARGET", "?": "QUERY", "!": "ACTION", "$": "VARIABLE"}

#: Sorted longest-first so the scanner always performs maximal munch.
_OPERATORS: List = [
    ("->", "ARROW"),
    ("=>", "THEN"),
    ("==", "EQ"),
    ("!=", "NEQ"),
    ("~=", "MATCH"),
    (">=", "GTE"),
    ("<=", "LTE"),
    ("&&", "AND"),
    ("||", "OR"),
    (":", "COLON"),
    ("|", "ELSE"),
    ("~", "NOT"),
    ("!", "ACTION"),
    ("?", "QUERY"),
    ("@", "TARGET"),
    ("$", "VARIABLE"),
    (">", "GT"),
    ("<", "LT"),
    ("+", "ADD"),
    ("-", "SUB"),
    ("*", "MUL"),
    ("/", "DIV"),
    ("%", "MOD"),
    ("^", "POW"),
    ("=", "ASSIGN"),
    ("(", "LPAREN"),
    (")", "RPAREN"),
    ("[", "LBRACKET"),
    ("]", "RBRACKET"),
    ("{", "LBRACE"),
    ("}", "RBRACE"),
    (",", "COMMA"),
    (".", "DOT"),
    (";", "SEMI"),
]

_MULTI_CHAR = [entry for entry in _OPERATORS if len(entry[0]) > 1]

# Reversed-lookup used by the emitter and by drift detection.
kind_of: Dict[str, str] = {text: kind for text, kind in _OPERATORS}

_ESCAPES = {
    "n": "\n",
    "t": "\t",
    "r": "\r",
    "0": "\0",
    "b": "\b",
    "f": "\f",
    "\\": "\\",
    '"': '"',
    "'": "'",
    "/": "/",
}


@dataclass(frozen=True)
class Token:
    """A classified lexeme with its source span."""

    kind: str
    text: str
    span: Span
    value: Any = field(default=None)

    #: Newlines are separators but are never significant inside brackets or
    #: conditional bodies; the parser uses this flag to skip soft newlines.
    @property
    def is_soft_skip(self) -> bool:
        return self.kind == "NEWLINE"

    def __str__(self) -> str:  # pragma: no cover - debugging aid
        if self.value is not None and self.value != self.text:
            return f"{self.kind}({self.text!r}={self.value!r})"
        return f"{self.kind}({self.text!r})"

    __repr__ = __str__


class _Scanner:
    def __init__(self, source: str) -> None:
        self.source = source
        self.length = len(source)
        self.offset = 0
        self.line = 1
        self.column = 1
        self.tokens: List[Token] = []

    # -- position helpers ------------------------------------------------
    def position(self) -> Position:
        return Position(self.offset, self.line, self.column)

    def peek(self, ahead: int = 0) -> str:
        index = self.offset + ahead
        return self.source[index] if index < self.length else ""

    def advance(self, count: int = 1) -> str:
        text = self.source[self.offset : self.offset + count]
        for char in text:
            if char == "\n":
                self.line += 1
                self.column = 1
            else:
                self.column += 1
        self.offset += count
        return text

    def emit(self, kind: str, start: Position, value: Any = None) -> Token:
        end = self.position()
        text = self.source[start.offset : end.offset]
        token = Token(kind, text, Span(start, end, self.source), value)
        self.tokens.append(token)
        return token

    def error(self, message: str, start: Position, hint: Optional[str] = None) -> LexError:
        return LexError(message, Span(start, self.position(), self.source), hint=hint)

    # -- main loop -------------------------------------------------------
    def run(self) -> List[Token]:
        while self.offset < self.length:
            char = self.peek()

            if char == "\n":
                start = self.position()
                self.advance()
                self.emit("NEWLINE", start)
                continue
            if char in " \t\r\v\f":
                self.advance()
                continue
            if char == "#" or (char == "/" and self.peek(1) == "/"):
                while self.offset < self.length and self.peek() != "\n":
                    self.advance()
                continue
            if char == '"':
                self.scan_string()
                continue
            if char.isdigit() or (char == "." and self.peek(1).isdigit()):
                self.scan_number()
                continue
            if char.isalpha() or char == "_":
                self.scan_name()
                continue

            self.scan_operator()

        start = self.position()
        self.emit("EOF", start)
        return self.tokens

    # -- scanners --------------------------------------------------------
    def scan_string(self) -> None:
        start = self.position()
        self.advance()  # opening quote
        chunks: List[str] = []
        while True:
            if self.offset >= self.length:
                raise UnterminatedString(Span(start, self.position(), self.source))
            char = self.peek()
            if char == "\n":
                raise UnterminatedString(Span(start, self.position(), self.source))
            if char == "\\":
                self.advance()
                escape = self.peek()
                if not escape:
                    raise UnterminatedString(Span(start, self.position(), self.source))
                if escape == "u":
                    self.advance()
                    digits = self.source[self.offset : self.offset + 4]
                    if len(digits) < 4 or any(d not in "0123456789abcdefABCDEF" for d in digits):
                        raise self.error("invalid \\u escape in string literal", start)
                    self.advance(4)
                    chunks.append(chr(int(digits, 16)))
                    continue
                if escape == "x":
                    self.advance()
                    digits = self.source[self.offset : self.offset + 2]
                    if len(digits) < 2 or any(d not in "0123456789abcdefABCDEF" for d in digits):
                        raise self.error("invalid \\x escape in string literal", start)
                    self.advance(2)
                    chunks.append(chr(int(digits, 16)))
                    continue
                if escape in _ESCAPES:
                    self.advance()
                    chunks.append(_ESCAPES[escape])
                    continue
                raise self.error(f"unknown escape sequence '\\{escape}'", start)
            if char == '"':
                self.advance()
                break
            chunks.append(self.advance())
        self.emit("STRING", start, "".join(chunks))

    def scan_number(self) -> None:
        start = self.position()
        saw_dot = False
        saw_exp = False
        if self.peek() == ".":
            saw_dot = True
            self.advance()
        while self.offset < self.length:
            char = self.peek()
            if char.isdigit():
                self.advance()
            elif char == "." and not saw_dot and not saw_exp and self.peek(1).isdigit():
                saw_dot = True
                self.advance()
            elif char in "eE" and not saw_exp:
                nxt = self.peek(1)
                if nxt.isdigit() or (nxt in "+-" and self.peek(2).isdigit()):
                    saw_exp = True
                    self.advance()
                    if self.peek() in "+-":
                        self.advance()
                else:
                    break
            else:
                break
        text = self.source[start.offset : self.offset]
        try:
            value: Any = float(text) if (saw_dot or saw_exp) else int(text)
        except ValueError:  # pragma: no cover - guarded by the scanner
            raise self.error(f"malformed numeric literal {text!r}", start)
        self.emit("NUMBER", start, value)

    def scan_name(self) -> None:
        start = self.position()
        while self.offset < self.length:
            char = self.peek()
            if char.isalnum() or char == "_":
                self.advance()
            else:
                break
        self.emit("NAME", start)

    def scan_operator(self) -> None:
        start = self.position()
        for text, kind in _MULTI_CHAR:
            if self.source.startswith(text, self.offset):
                self.advance(len(text))
                self.emit(kind, start)
                return
        char = self.peek()
        if char in SIGILS:
            self.advance()
            self.emit(SIGILS[char], start)
            return
        for text, kind in _OPERATORS:
            if char == text:
                self.advance()
                self.emit(kind, start)
                return
        raise self.error(f"unexpected character {char!r}", start)


def tokenize(source: str) -> List[Token]:
    """Split ``source`` into tokens, always terminated by an ``EOF`` token.

    Raises
    ------
    LexError
        On any character the grammar cannot classify (``ZN0001``).
    UnterminatedString
        When a string literal is not closed on its own line (``ZN0002``).
    """
    if not isinstance(source, str):
        raise TypeError(f"source must be str, got {type(source).__name__}")
    return _Scanner(source).run()
