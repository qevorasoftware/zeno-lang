"""The tester agent: continuous conformance QA for the protocol itself.

It answers one question — *does this checkout still honour Grammar v0.1?* — by
running every payload in the repository through the full toolchain and checking
the invariants the spec promises:

======================  =====================================================
check                   invariant
======================  =====================================================
parse                   every shipped payload parses
canonical               ``canonicalize`` is idempotent and lossless
ast:round-trip          ``emit(parse(x))`` parses back to an equal tree
frame:round-trip        every execution result frame parses as a payload
validate                shipped payloads produce no error diagnostics
reject                  malformed payloads raise the declared code
execute                 every corpus payload runs on stub tools
determinism             two runs of one payload agree
======================  =====================================================

    $ python -m agents.tester              # human-readable report, exit 0/1
    $ python -m agents.tester --json       # machine-readable

Adding a payload to ``benchmarks/corpus.json`` automatically enrols it here,
which is the point: the suite grows with the corpus.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

from zeno.emitter import canonicalize, emit
from zeno.errors import DIAGNOSTICS, ZenoError
from zeno.parser import parse
from zeno.runtime import Kernel, result_frame
from zeno.validator import validate

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "benchmarks" / "corpus.json"
INVALID = ROOT / "tests" / "invalid" / "cases.json"

__all__ = ["run_suite", "SuiteReport", "CheckResult", "main"]


@dataclass
class CheckResult:
    """One invariant, checked for one subject."""

    check: str
    subject: str
    ok: bool
    detail: str = ""

    def to_dict(self) -> dict:
        return {"check": self.check, "subject": self.subject, "ok": self.ok, "detail": self.detail}


@dataclass
class SuiteReport:
    """The whole run."""

    results: List[CheckResult] = field(default_factory=list)

    @property
    def passed(self) -> List[CheckResult]:
        return [result for result in self.results if result.ok]

    @property
    def failed(self) -> List[CheckResult]:
        return [result for result in self.results if not result.ok]

    @property
    def ok(self) -> bool:
        return not self.failed

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "total": len(self.results),
            "passed": len(self.passed),
            "failed": len(self.failed),
            "results": [result.to_dict() for result in self.results],
            "failures": [result.to_dict() for result in self.failed],
        }

    def render(self, *, verbose: bool = False) -> str:
        width = 78
        lines = ["=" * width, "  ZENO CONFORMANCE SUITE", "=" * width]
        by_check: Dict[str, List[CheckResult]] = {}
        for result in self.results:
            by_check.setdefault(result.check, []).append(result)
        for check, results in by_check.items():
            failures = [result for result in results if not result.ok]
            flag = "ok  " if not failures else "FAIL"
            lines.append(f"  [{flag}] {check:<22} {len(results) - len(failures):>3}/{len(results):<3}")
            for result in failures:
                lines.append(f"         - {result.subject}: {result.detail}")
        lines.append("-" * width)
        lines.append(f"  {len(self.passed)} passed, {len(self.failed)} failed")
        if self.failed and not verbose:
            lines.append("  re-run with --verbose for the full list of failures")
        lines.append("=" * width)
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
def load_corpus(path: Path = CORPUS) -> List[Dict[str, str]]:
    if not path.is_file():
        return []
    document = json.loads(path.read_text(encoding="utf-8"))
    return list(document.get("cases", []))


def load_invalid(path: Path = INVALID) -> List[Dict[str, Any]]:
    if not path.is_file():
        return []
    document = json.loads(path.read_text(encoding="utf-8"))
    return list(document.get("cases", []))


def stub_tools(
    payloads: Sequence[str], kernel: Optional[Kernel] = None
) -> Dict[str, Callable[..., Any]]:
    """Register a deterministic stub for every tool the payloads mention.

    The suite checks *protocol* behaviour, not business logic, so each stub
    answers with a small fixed mapping containing exactly the attributes the
    payloads read (``$REVIEW.issues`` and friends), and every action echoes its
    first argument. Names the kernel already provides (``?LEN``, ``!RET`` ...)
    are left alone, which is why a kernel can be passed in.
    """
    from zeno.ast import Attr, Call, Path, Program

    attributes: Dict[str, set] = {}
    sigils: Dict[str, set] = {}

    def note(name: str, sigil: str = "?") -> None:
        attributes.setdefault(name.upper(), set())
        sigils.setdefault(name.upper(), set()).add(sigil)

    def note_attributes(name: str, parts: Sequence[str]) -> None:
        note(name)
        attributes[name.upper()].update(str(part) for part in parts)

    def collect(node: Any) -> None:
        if isinstance(node, Program):
            for statement in node.statements:
                collect(statement)
            return
        if isinstance(node, Call):
            if node.sigil in {"?", "!"}:
                note(node.name, node.sigil)
            for argument in node.args:
                collect(argument)
            for _, value in node.kwargs:
                collect(value)
            return
        if isinstance(node, Attr):
            if isinstance(node.base, Call):
                note_attributes(node.base.name, node.parts)
            else:
                collect(node.base)
            return
        if isinstance(node, Path):
            if node.sigil == "$" and len(node.parts) > 1:
                note_attributes(node.parts[0], node.parts[1:])
            return
        for child in _children(node):
            collect(child)

    for payload in payloads:
        try:
            collect(parse(payload))
        except ZenoError:
            continue

    taken = set()
    if kernel is not None:
        taken = set(kernel.queries) | set(kernel.actions)

    def make(name: str) -> Callable[..., Any]:
        def stub(args: List[Any], kwargs: Dict[str, Any], env: Any, call: Any) -> Any:
            known = {attribute: 1 for attribute in sorted(attributes.get(name, ()))}
            if args:
                # Keep the positional argument addressable, e.g. ?PRICE[ACME].price
                known.setdefault("value", args[0])
            return known or (args[0] if args else f"{call.name}")

        return stub

    registry: Dict[str, Callable[..., Any]] = {}
    for name in sorted(attributes):
        if name in taken:
            continue
        for sigil in sorted(sigils.get(name, {"?"})):
            registry[f"{sigil}{name}"] = make(name)
    return registry


def _children(node: Any) -> List[Any]:
    """Every dataclass field of an AST node that holds a node or a tuple of them."""
    produced: List[Any] = []
    for value in getattr(node, "__dict__", {}).values():
        if hasattr(value, "__dataclass_fields__"):
            produced.append(value)
        elif isinstance(value, (tuple, list)):
            produced.extend(item for item in value if hasattr(item, "__dataclass_fields__"))
    return produced


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------
def _check_parse(report: SuiteReport, subject: str, payload: str) -> bool:
    try:
        parse(payload)
        report.results.append(CheckResult("parse", subject, True))
        return True
    except ZenoError as exc:
        report.results.append(CheckResult("parse", subject, False, exc.message))
        return False


def _check_canonical(report: SuiteReport, subject: str, payload: str) -> None:
    try:
        once = canonicalize(payload)
        twice = canonicalize(once)
        if once != twice:
            report.results.append(
                CheckResult("canonical", subject, False, "canonicalize is not idempotent")
            )
            return
        if parse(once) != parse(payload):
            report.results.append(
                CheckResult("canonical", subject, False, "canonicalisation changed the AST")
            )
            return
        report.results.append(CheckResult("canonical", subject, True))
    except ZenoError as exc:
        report.results.append(CheckResult("canonical", subject, False, exc.message))


def _check_ast_round_trip(report: SuiteReport, subject: str, payload: str) -> None:
    try:
        tree = parse(payload)
        again = parse(emit(tree))
        if again != tree:
            report.results.append(
                CheckResult("ast:round-trip", subject, False, "emit/parse is not an exact inverse")
            )
            return
        report.results.append(CheckResult("ast:round-trip", subject, True))
    except ZenoError as exc:
        report.results.append(CheckResult("ast:round-trip", subject, False, exc.message))


def _check_validate(report: SuiteReport, subject: str, payload: str) -> None:
    outcome = validate(payload)
    errors = [diagnostic for diagnostic in outcome.diagnostics if diagnostic.severity == "error"]
    if errors:
        report.results.append(
            CheckResult("validate", subject, False, "; ".join(d.code for d in errors))
        )
        return
    report.results.append(CheckResult("validate", subject, True))


def _check_execute(report: SuiteReport, kernel: Kernel, subject: str, payload: str) -> None:
    try:
        first = kernel.execute(payload)
    except ZenoError as exc:
        report.results.append(CheckResult("execute", subject, False, f"{exc.code}: {exc.message}"))
        return
    report.results.append(CheckResult("execute", subject, True))

    try:
        second = kernel.execute(payload)
    except ZenoError as exc:  # pragma: no cover - would already have failed above
        report.results.append(CheckResult("determinism", subject, False, exc.message))
        return
    same = (
        first.output == second.output
        and first.bindings == second.bindings
        and [step.name for step in first.steps] == [step.name for step in second.steps]
    )
    report.results.append(
        CheckResult(
            "determinism",
            subject,
            same,
            "" if same else "two runs of the same payload disagreed",
        )
    )

    try:
        parse(result_frame(first))
        report.results.append(CheckResult("frame:round-trip", subject, True))
    except ZenoError as exc:
        report.results.append(CheckResult("frame:round-trip", subject, False, exc.message))


def _check_reject(report: SuiteReport, cases: Sequence[Dict[str, Any]]) -> None:
    for case in cases:
        subject = case.get("id", case.get("payload", "?"))
        outcome = validate(case["payload"])
        codes = [diagnostic.code for diagnostic in outcome.diagnostics]
        expected = case["code"]
        if expected not in DIAGNOSTICS:
            report.results.append(
                CheckResult("reject", subject, False, f"{expected} is not a declared diagnostic")
            )
            continue
        if codes != [expected] and expected not in codes:
            report.results.append(
                CheckResult("reject", subject, False, f"got {codes}, expected {expected}")
            )
            continue
        if outcome.ok is not case["ok"]:
            report.results.append(
                CheckResult("reject", subject, False, f"ok={outcome.ok}, expected {case['ok']}")
            )
            continue
        report.results.append(CheckResult("reject", subject, True))


def _check_intent(report: SuiteReport, cases: Sequence[Dict[str, str]]) -> None:
    """Every corpus payload must say something about its own intent.

    The offline check is structural: the payload has to carry at least one
    query or action, and it may not simply echo the natural-language request
    back as free text.
    """
    for case in cases:
        subject = case["id"]
        payload = case["zeno"]
        has_operation = any(sigil in payload for sigil in ("?", "!"))
        echoed = len(payload.split('"')[1]) > 40 if payload.count('"') >= 2 else False
        if not has_operation:
            report.results.append(
                CheckResult("intent", subject, False, "payload contains no query or action")
            )
        elif echoed:
            report.results.append(
                CheckResult("intent", subject, False, "payload embeds the request verbatim")
            )
        else:
            report.results.append(CheckResult("intent", subject, True))


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------
def run_suite(
    corpus: Optional[Sequence[Dict[str, str]]] = None,
    invalid: Optional[Sequence[Dict[str, Any]]] = None,
    *,
    include_intent: bool = False,
) -> SuiteReport:
    """Run every check. Never raises for a bad payload: it records it."""
    cases = list(corpus if corpus is not None else load_corpus())
    invalid_cases = list(invalid if invalid is not None else load_invalid())
    report = SuiteReport()

    payloads = [case["zeno"] for case in cases]
    from zeno.spec import canonical_example

    example = canonical_example()
    if example:
        payloads.insert(0, example["zeno"])
        cases = [{"id": "canonical-example", "zeno": example["zeno"], **example}] + cases

    kernel = Kernel()
    for name, fn in stub_tools(payloads, kernel).items():
        kernel.register(name, fn)

    for case in cases:
        subject, payload = case["id"], case["zeno"]
        if _check_parse(report, subject, payload):
            _check_canonical(report, subject, payload)
            _check_ast_round_trip(report, subject, payload)
            _check_validate(report, subject, payload)
            _check_execute(report, kernel, subject, payload)

    _check_reject(report, invalid_cases)
    if include_intent:
        _check_intent(report, [case for case in cases if case["id"] != "canonical-example"])

    return report


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m agents.tester",
        description="Zeno conformance suite (Grammar v0.1).",
    )
    parser.add_argument("--json", action="store_true", help="machine-readable report")
    parser.add_argument("--verbose", action="store_true", help="list every failure")
    parser.add_argument(
        "--intent-check",
        action="store_true",
        help="also check that each payload expresses a real operation",
    )
    args = parser.parse_args(argv)

    report = run_suite(include_intent=args.intent_check)
    if args.json:
        json.dump(report.to_dict(), sys.stdout, indent=2, ensure_ascii=False)
        sys.stdout.write("\n")
    else:
        print(report.render(verbose=args.verbose))
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
