"""The negative corpus: every malformed payload raises the promised code.

``tests/invalid/cases.json`` is the machine-readable half of the conformance
contract promised in the README: each entry names a payload, whether it must be
rejected outright and the diagnostic code that must appear.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from zeno.errors import DIAGNOSTICS, ZenoError
from zeno.parser import parse
from zeno.validator import validate

CORPUS = Path(__file__).resolve().parent / "invalid" / "cases.json"
CASES = json.loads(CORPUS.read_text(encoding="utf-8"))["cases"]


def test_the_corpus_is_not_empty_and_ids_are_unique():
    assert len(CASES) >= 15
    ids = [case["id"] for case in CASES]
    assert len(ids) == len(set(ids))


def test_every_declared_code_is_a_real_diagnostic():
    for case in CASES:
        assert case["code"] in DIAGNOSTICS, case["id"]


@pytest.mark.parametrize("case", CASES, ids=[case["id"] for case in CASES])
def test_case_reports_its_code(case):
    report = validate(case["payload"])
    codes = [diagnostic.code for diagnostic in report.diagnostics]
    assert case["code"] in codes, f"{case['id']}: got {codes}, note: {case['note']}"
    assert report.ok is case["ok"]
    if not case["ok"]:
        assert any(d.severity == "error" for d in report.diagnostics)
        if case["code"].startswith("ZN"):
            assert report.error is not None
        else:
            assert report.program is not None  # lint findings still parse


@pytest.mark.parametrize(
    "case",
    [case for case in CASES if case["code"].startswith("ZN")],
    ids=lambda c: c["id"],
)
def test_syntax_cases_raise_when_parsed_directly(case):
    """ZN codes come from the lexer/parser, so ``parse`` itself must raise.

    ZL codes are lint findings: the payload parses, the analyser rejects it.
    """
    with pytest.raises(ZenoError):
        parse(case["payload"])
