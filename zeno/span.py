"""Source positions and spans.

Kept in its own module so that :mod:`zeno.lexer`, :mod:`zeno.ast` and
:mod:`zeno.errors` can all depend on it without creating an import cycle.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class Position:
    """A 1-based line/column pair plus a 0-based character offset."""

    offset: int
    line: int
    column: int

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"{self.line}:{self.column}"

    def advance(self, text: str) -> "Position":
        """Return the position reached after consuming ``text``."""
        offset = self.offset
        line = self.line
        column = self.column
        for char in text:
            offset += 1
            if char == "\n":
                line += 1
                column = 1
            else:
                column += 1
        return Position(offset, line, column)


@dataclass(frozen=True)
class Span:
    """A half-open range ``[start, end)`` within a source payload."""

    start: Position
    end: Position
    source: str = field(default="", compare=False, repr=False)

    # -- constructors ----------------------------------------------------
    @classmethod
    def at(cls, position: Position, source: str = "") -> "Span":
        return cls(position, position, source)

    @classmethod
    def synthetic(cls, source: str = "") -> "Span":
        """A span for generated nodes that have no source location."""
        origin = Position(0, 1, 1)
        return cls(origin, origin, source)

    # -- combinators -----------------------------------------------------
    def merge(self, other: Optional["Span"]) -> "Span":
        if other is None:
            return self
        source = self.source or other.source
        start = self.start if self.start.offset <= other.start.offset else other.start
        end = self.end if self.end.offset >= other.end.offset else other.end
        return Span(start, end, source)

    # -- rendering -------------------------------------------------------
    @property
    def text(self) -> str:
        if not self.source:
            return ""
        return self.source[self.start.offset : self.end.offset]

    @property
    def line_text(self) -> str:
        return self._line(self.start.line)

    def _line(self, line_number: int) -> str:
        if not self.source:
            return ""
        lines = self.source.splitlines()
        index = line_number - 1
        if 0 <= index < len(lines):
            return lines[index]
        return ""

    def caret(self, marker: str = "^") -> str:
        """A caret underline aligned with :attr:`line_text`."""
        width = 1
        if self.end.line == self.start.line:
            width = max(1, self.end.column - self.start.column)
        pad = " " * max(0, self.start.column - 1)
        return pad + marker * width

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"{self.start.line}:{self.start.column}-{self.end.line}:{self.end.column}"
