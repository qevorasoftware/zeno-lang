"""Programmatic access to the machine-readable grammar specification.

``specs/tokens.json`` is the single source of truth for the protocol surface.
This module loads it, exposes convenience views over it, and provides
:func:`drift_report` which the test-suite uses to guarantee that the lexer in
:mod:`zeno.lexer` and the spec file never disagree.
"""

from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional

__all__ = [
    "SPEC_VERSION",
    "GRAMMAR_VERSION",
    "spec_path",
    "tokens",
    "symbols",
    "operators",
    "flow_operators",
    "keywords",
    "canonical_example",
    "diagnostics",
    "drift_report",
]

#: Version of the JSON document itself.
SPEC_VERSION = "0.1.0"
#: Version of the grammar the JSON document describes.
GRAMMAR_VERSION = "v0.1"

_ENV_VAR = "ZENO_SPEC_PATH"


def spec_path() -> Optional[Path]:
    """Locate ``specs/tokens.json``.

    Search order:

    1. ``$ZENO_SPEC_PATH`` (explicit override, handy for CI and vendored use).
    2. ``<repo>/specs/tokens.json`` walking up from this file.
    3. ``<package>/_data/tokens.json`` for installed wheels.
    """
    override = os.environ.get(_ENV_VAR)
    if override:
        path = Path(override).expanduser()
        return path if path.is_file() else None

    here = Path(__file__).resolve()
    for parent in [here.parent, *here.parents]:
        candidate = parent / "specs" / "tokens.json"
        if candidate.is_file():
            return candidate

    bundled = here.parent / "_data" / "tokens.json"
    return bundled if bundled.is_file() else None


@lru_cache(maxsize=1)
def tokens() -> Dict[str, Any]:
    """The parsed contents of ``specs/tokens.json``.

    Returns an empty mapping when the file cannot be found so that the library
    stays importable in stripped-down deployments.
    """
    path = spec_path()
    if path is None:
        return {}
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


# ---------------------------------------------------------------------------
# Convenience views
# ---------------------------------------------------------------------------
def symbols() -> Dict[str, Dict[str, Any]]:
    """Sigil table, keyed by sigil character (``@``, ``?``, ``!``, ``$``)."""
    return {entry["token"]: entry for entry in tokens().get("sigils", [])}


def flow_operators() -> Dict[str, Dict[str, Any]]:
    """Control-flow tokens, keyed by token text."""
    return {entry["token"]: entry for entry in tokens().get("flow_operators", [])}


def operators() -> Dict[str, Dict[str, Any]]:
    """Expression operators, keyed by ``(token, name)``."""
    return {(entry["token"], entry["name"]): entry for entry in tokens().get("expression_operators", [])}


def keywords() -> Dict[str, str]:
    """Keyword text -> canonical spelling (e.g. ``NULL`` -> ``NIL``)."""
    return {entry["token"].upper(): entry["canonical"].upper() for entry in tokens().get("keywords", [])}


def canonical_example() -> Dict[str, str]:
    """The §4.1 worked example: ``{"human": ..., "zeno": ...}``."""
    return dict(tokens().get("canonical_example", {}))


def diagnostics() -> Dict[str, str]:
    """Diagnostic code -> canonical message."""
    return dict(tokens().get("diagnostics", {}))


def operator_precedence() -> Dict[str, int]:
    """Token text -> precedence level (higher binds tighter)."""
    table: Dict[str, int] = {}
    for entry in tokens().get("expression_operators", []):
        precedence = entry.get("precedence")
        if precedence is not None:
            table[entry["token"]] = precedence
    return table


# ---------------------------------------------------------------------------
# Drift detection
# ---------------------------------------------------------------------------
def drift_report() -> List[str]:
    """Return a list of disagreements between this module and the spec file.

    The test-suite asserts this is empty. A non-empty list means the lexer and
    ``specs/tokens.json`` have drifted apart and must be reconciled.
    """
    from . import errors, lexer

    problems: List[str] = []
    document = tokens()
    if not document:
        return ["specs/tokens.json could not be located"]

    if document.get("spec_version") != SPEC_VERSION:
        problems.append(
            f"spec_version drift: file={document.get('spec_version')!r} code={SPEC_VERSION!r}"
        )
    if document.get("grammar_version") != GRAMMAR_VERSION:
        problems.append(
            f"grammar_version drift: file={document.get('grammar_version')!r} code={GRAMMAR_VERSION!r}"
        )

    # Every sigil in the spec must be a token kind known to the lexer.
    for sigil, entry in symbols().items():
        if entry["name"] not in lexer.TOKEN_KINDS:
            problems.append(f"sigil {sigil!r} declares unknown token kind {entry['name']!r}")

    # Every edge in the operator table must round-trip through the lexer.
    for entry in document.get("expression_operators", []) + document.get("flow_operators", []):
        probe = entry["token"]
        if probe.startswith("\\n"):
            continue
        try:
            kinds = [token.kind for token in lexer.tokenize(probe) if token.kind != "EOF"]
        except errors.ZenoError as exc:  # pragma: no cover - defensive
            problems.append(f"operator {probe!r} does not lex: {exc.message}")
            continue
        if entry["name"] not in kinds:
            problems.append(f"operator {probe!r} lexes to {kinds!r}, expected {entry['name']!r}")

    # Delimiters.
    for entry in document.get("delimiters", []):
        if entry["name"] not in lexer.TOKEN_KINDS:
            problems.append(f"delimiter {entry['token']!r} declares unknown kind {entry['name']!r}")

    # Keywords.
    declared = {entry["token"].upper() for entry in document.get("keywords", [])}
    implemented = set(lexer.KEYWORD_LITERALS) | {"LET"}
    for missing in sorted(declared - implemented):
        problems.append(f"keyword {missing!r} is declared in the spec but not implemented")
    for extra in sorted(implemented - declared):
        problems.append(f"keyword {extra!r} is implemented but not declared in the spec")

    # Diagnostics.
    for code, message in diagnostics().items():
        if errors.DIAGNOSTICS.get(code) != message:
            problems.append(
                f"diagnostic {code} drift: file={message!r} code={errors.DIAGNOSTICS.get(code)!r}"
            )
    for code in errors.DIAGNOSTICS:
        if code not in diagnostics():
            problems.append(f"diagnostic {code} is missing from specs/tokens.json")

    return problems
