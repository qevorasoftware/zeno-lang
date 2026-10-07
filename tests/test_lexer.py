"""Lexer behaviour, including the diagnostics it must raise."""

from __future__ import annotations

import pytest

from zeno.errors import LexError, UnterminatedString
from zeno.lexer import KEYWORD_LITERALS, TOKEN_KINDS, tokenize


def kinds(source: str) -> list:
    return [token.kind for token in tokenize(source)][:-1]  # drop EOF


def test_empty_source_is_just_eof():
    tokens = tokenize("")
    assert len(tokens) == 1
    assert tokens[0].kind == "EOF"


def test_sigils():
    assert kinds("@LOC") == ["TARGET", "NAME"]
    assert kinds("?WX") == ["QUERY", "NAME"]
    assert kinds("!GEN") == ["ACTION", "NAME"]
    assert kinds("$PRICE") == ["VARIABLE", "NAME"]


def test_maximal_munch_on_operators():
    assert kinds("A -> B") == ["NAME", "ARROW", "NAME"]
    assert kinds("A - > B") == ["NAME", "SUB", "GT", "NAME"]
    assert kinds("A == B") == ["NAME", "EQ", "NAME"]
    assert kinds("A = B") == ["NAME", "ASSIGN", "NAME"]
    assert kinds("A => B") == ["NAME", "THEN", "NAME"]
    assert kinds("A != B") == ["NAME", "NEQ", "NAME"]
    assert kinds("A ~= B") == ["NAME", "MATCH", "NAME"]
    assert kinds("A || B") == ["NAME", "OR", "NAME"]
    assert kinds("A | B") == ["NAME", "ELSE", "NAME"]
    assert kinds("A && B") == ["NAME", "AND", "NAME"]
    assert kinds("A >= B") == ["NAME", "GTE", "NAME"]
    assert kinds("A <= B") == ["NAME", "LTE", "NAME"]


def test_delimiters_and_separators():
    assert kinds("[A, B]") == ["LBRACKET", "NAME", "COMMA", "NAME", "RBRACKET"]
    assert kinds(": { A }") == ["COLON", "LBRACE", "NAME", "RBRACE"]
    assert kinds("A; B") == ["NAME", "SEMI", "NAME"]
    assert kinds("A\nB") == ["NAME", "NEWLINE", "NAME"]


def test_numbers():
    assert tokenize("42")[0].value == 42
    assert tokenize("3.5")[0].value == 3.5
    assert tokenize("1e3")[0].value == 1000.0
    assert tokenize(".5")[0].value == 0.5
    assert isinstance(tokenize("42")[0].value, int)
    assert isinstance(tokenize("42.0")[0].value, float)


def test_minus_is_not_part_of_the_number():
    # `-3` is unary negation applied to 3, exactly as documented in the spec.
    assert kinds("-3") == ["SUB", "NUMBER"]


def test_strings_and_escapes():
    assert tokenize('"hello"')[0].value == "hello"
    assert tokenize(r'"a\nb"')[0].value == "a\nb"
    assert tokenize(r'"quote: \""')[0].value == 'quote: "'
    assert tokenize(r'"\u00e9"')[0].value == "é"
    assert tokenize(r'"\\"')[0].value == "\\"
    assert tokenize('""')[0].value == ""


def test_string_keeps_its_source_span():
    token = tokenize('!RET[OUT="hello"]')[5]
    assert token.kind == "STRING"
    assert token.span.text == '"hello"'


def test_comments_are_dropped():
    assert kinds("@A # comment\n?B") == ["TARGET", "NAME", "NEWLINE", "QUERY", "NAME"]
    assert kinds("@A // comment\n?B") == ["TARGET", "NAME", "NEWLINE", "QUERY", "NAME"]


def test_whitespace_is_insignificant():
    assert kinds("  @A\t->   ?B  ") == ["TARGET", "NAME", "ARROW", "QUERY", "NAME"]


def test_names_allow_underscores_and_digits():
    assert kinds("_private VAR_2") == ["NAME", "NAME"]


def test_unicode_identifiers_scan_as_names():
    # Non-ASCII letters are accepted in names; comparison stays case-insensitive.
    assert kinds("café") == ["NAME"]


def test_unexpected_character_reports_zn0001():
    with pytest.raises(LexError) as excinfo:
        tokenize("@A €")
    assert excinfo.value.code == "ZN0001"
    assert excinfo.value.span.start.line == 1
    assert "unexpected character" in excinfo.value.message


def test_unterminated_string_reports_zn0002():
    with pytest.raises(UnterminatedString) as excinfo:
        tokenize('!GEN["never closed ')
    assert excinfo.value.code == "ZN0002"


def test_newline_inside_string_is_rejected():
    with pytest.raises(UnterminatedString):
        tokenize('!GEN["line\nbreak"]')


def test_unknown_escape_is_rejected():
    with pytest.raises(LexError):
        tokenize(r'"\q"')


def test_token_kinds_cover_everything_the_spec_declares():
    for kind in ("TARGET", "QUERY", "ACTION", "VARIABLE", "ARROW", "COLON", "THEN", "ELSE"):
        assert kind in TOKEN_KINDS


def test_keyword_literals_are_plain_names():
    # Keywords lex as NAME; the parser decides what they mean. That keeps
    # `?TRUE` a legal query name.
    assert tokenize("TRUE")[0].kind == "NAME"
    assert {"TRUE", "FALSE", "NIL"} <= KEYWORD_LITERALS


def test_token_type_check():
    with pytest.raises(TypeError):
        tokenize(b"bytes are not text")  # type: ignore[arg-type]
