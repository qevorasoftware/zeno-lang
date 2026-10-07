"""Token-density benchmark: does Zeno actually save ~75 % of the tokens?

    $ python -m benchmarks.token_comparison
    $ python -m zeno benchmark --json

Method
------
Every case in ``benchmarks/corpus.json`` carries the same intent written three
ways:

``human``
    A realistic dispatch: the framing, politeness and format requirements that
    real agent traffic carries. This is the number the project brief compares
    against, because it is what actually travels over the wire today.
``terse``
    The same intent compressed by a human writing as densely as they can. This
    is the *pessimistic bound* — the protocol should still win here, and if it
    does not, that is reported rather than hidden.
``zeno``
    The canonical payload emitted by :func:`zeno.emit`.

Both sides are counted with the same tokenizer (:mod:`zeno.tokenizer`), so the
comparison is apples to apples. ``--model`` selects the encoding; when
``tiktoken`` cannot reach its BPE files the run says so and reports estimates,
never silent guesses.

Reduction is ``(NL - ZENO) / NL * 100`` per the project brief.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

if __package__ in (None, ""):  # allow `python benchmarks/token_comparison.py`
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from zeno.emitter import canonicalize  # noqa: E402
from zeno.parser import parse  # noqa: E402
from zeno.prompts import ENCODER_SYSTEM  # noqa: E402
from zeno.tokenizer import count_tokens, counting_method  # noqa: E402

#: The target the project brief commits to.
TARGET_REDUCTION_PCT = 75.0

DEFAULT_CORPUS = Path(__file__).resolve().parent / "corpus.json"


@dataclass
class CaseResult:
    """Token accounting for one corpus entry."""

    id: str
    intent: str
    human_tokens: int
    terse_tokens: int
    zeno_tokens: int
    human_chars: int
    zeno_chars: int
    canonical_matches: bool = True

    @property
    def reduction(self) -> float:
        """Reduction against the realistic dispatch."""
        if not self.human_tokens:
            return 0.0
        return (self.human_tokens - self.zeno_tokens) / self.human_tokens * 100.0

    @property
    def terse_reduction(self) -> float:
        if not self.terse_tokens:
            return 0.0
        return (self.terse_tokens - self.zeno_tokens) / self.terse_tokens * 100.0

    @property
    def char_reduction(self) -> float:
        if not self.human_chars:
            return 0.0
        return (self.human_chars - self.zeno_chars) / self.human_chars * 100.0

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "intent": self.intent,
            "human_tokens": self.human_tokens,
            "terse_tokens": self.terse_tokens,
            "zeno_tokens": self.zeno_tokens,
            "reduction_pct": round(self.reduction, 2),
            "terse_reduction_pct": round(self.terse_reduction, 2),
            "char_reduction_pct": round(self.char_reduction, 2),
            "canonical_matches": self.canonical_matches,
        }


@dataclass
class BenchmarkReport:
    """Aggregate results plus the caveats needed to read them honestly."""

    cases: List[CaseResult] = field(default_factory=list)
    model: Optional[str] = None
    method: str = ""
    encoder_prompt_tokens: int = 0
    corpus: str = ""
    target: float = TARGET_REDUCTION_PCT

    # -- aggregates ------------------------------------------------------
    @property
    def total_human(self) -> int:
        return sum(case.human_tokens for case in self.cases)

    @property
    def total_terse(self) -> int:
        return sum(case.terse_tokens for case in self.cases)

    @property
    def total_zeno(self) -> int:
        return sum(case.zeno_tokens for case in self.cases)

    @property
    def mean_reduction(self) -> float:
        return statistics.fmean([case.reduction for case in self.cases]) if self.cases else 0.0

    @property
    def pooled_reduction(self) -> float:
        """Token-weighted reduction — what a batch of traffic actually saves."""
        if not self.total_human:
            return 0.0
        return (self.total_human - self.total_zeno) / self.total_human * 100.0

    @property
    def mean_terse_reduction(self) -> float:
        return (
            statistics.fmean([case.terse_reduction for case in self.cases]) if self.cases else 0.0
        )

    @property
    def median_reduction(self) -> float:
        return statistics.median([case.reduction for case in self.cases]) if self.cases else 0.0

    @property
    def best(self) -> Optional[CaseResult]:
        return max(self.cases, key=lambda case: case.reduction, default=None)

    @property
    def worst(self) -> Optional[CaseResult]:
        return min(self.cases, key=lambda case: case.reduction, default=None)

    @property
    def meets_target(self) -> bool:
        return self.pooled_reduction >= self.target

    @property
    def break_even_calls(self) -> Optional[float]:
        """Calls needed to repay the encoder's system prompt.

        The prompt is a fixed cost paid once per process (or per cached prompt);
        the payload saving is paid on every single hop. This is the number of
        encoded calls after which the protocol is net-negative in tokens.
        """
        saved = self.total_human - self.total_zeno
        if saved <= 0 or not self.cases:
            return None
        per_call = saved / len(self.cases)
        return self.encoder_prompt_tokens / per_call

    def to_dict(self) -> dict:
        return {
            "corpus": self.corpus,
            "model": self.model,
            "tokenizer": self.method,
            "target_reduction_pct": self.target,
            "totals": {
                "human_tokens": self.total_human,
                "terse_tokens": self.total_terse,
                "zeno_tokens": self.total_zeno,
            },
            "reduction": {
                "pooled_pct": round(self.pooled_reduction, 2),
                "mean_pct": round(self.mean_reduction, 2),
                "median_pct": round(self.median_reduction, 2),
                "terse_pooled_pct": round(self.mean_terse_reduction, 2),
                "meets_target": self.meets_target,
            },
            "encoder": {
                "system_prompt_tokens": self.encoder_prompt_tokens,
                "break_even_calls": (
                    round(self.break_even_calls, 2) if self.break_even_calls else None
                ),
            },
            "cases": [case.to_dict() for case in self.cases],
        }


def load_corpus(path: Optional[Path] = None) -> Dict[str, Any]:
    target = Path(path) if path else DEFAULT_CORPUS
    with target.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def run(
    corpus_path: Optional[Path] = None,
    *,
    model: Optional[str] = None,
    canonicalise: bool = True,
) -> BenchmarkReport:
    """Count tokens for every case and aggregate the result."""
    data = load_corpus(corpus_path)
    report = BenchmarkReport(
        model=model,
        method=counting_method(model),
        encoder_prompt_tokens=count_tokens(ENCODER_SYSTEM, model=model),
        corpus=str(corpus_path or DEFAULT_CORPUS),
    )
    for entry in data.get("cases", []):
        zeno = entry["zeno"]
        matches = True
        if canonicalise:
            canonical = canonicalize(zeno)
            matches = canonical == zeno
            zeno = canonical
            parse(zeno)  # every corpus payload must parse
        report.cases.append(
            CaseResult(
                id=entry["id"],
                intent=entry.get("intent", ""),
                human_tokens=count_tokens(entry["human"], model=model),
                terse_tokens=count_tokens(entry.get("terse", ""), model=model),
                zeno_tokens=count_tokens(zeno, model=model),
                human_chars=len(entry["human"]),
                zeno_chars=len(zeno),
                canonical_matches=matches,
            )
        )
    return report


# ---------------------------------------------------------------------------
# Presentation
# ---------------------------------------------------------------------------
def render_report(report: BenchmarkReport, *, width: int = 78) -> str:
    lines: List[str] = []
    rule = "=" * width
    thin = "-" * width
    lines.append(rule)
    lines.append("  ZENO PROTOCOL — TOKEN DENSITY BENCHMARK")
    lines.append(f"  tokenizer: {report.method}   corpus: {Path(report.corpus).name}")
    lines.append(rule)
    lines.append(
        f"{'case':<18}{'human':>7}{'terse':>7}{'zeno':>7}{'vs human':>11}{'vs terse':>11}"
    )
    lines.append(thin)
    for case in report.cases:
        lines.append(
            f"{case.id:<18}{case.human_tokens:>7}{case.terse_tokens:>7}{case.zeno_tokens:>7}"
            f"{case.reduction:>10.1f}%{case.terse_reduction:>10.1f}%"
        )
    lines.append(thin)
    lines.append(
        f"{'TOTAL':<18}{report.total_human:>7}{report.total_terse:>7}{report.total_zeno:>7}"
        f"{report.pooled_reduction:>10.1f}%{report.mean_terse_reduction:>10.1f}%"
    )
    lines.append(rule)
    lines.append("  SUMMARY")
    lines.append(f"    pooled reduction vs realistic prompts : {report.pooled_reduction:6.1f} %")
    lines.append(f"    mean reduction                        : {report.mean_reduction:6.1f} %")
    lines.append(f"    median reduction                      : {report.median_reduction:6.1f} %")
    if report.best and report.worst:
        lines.append(
            f"    best / worst case                     : "
            f"{report.best.id} {report.best.reduction:.1f} % / "
            f"{report.worst.id} {report.worst.reduction:.1f} %"
        )
    lines.append(
        f"    reduction vs terse prompts (lower bnd) : {report.mean_terse_reduction:6.1f} %"
    )
    lines.append(thin)
    lines.append("  FIXED COST")
    lines.append(
        f"    encoder system prompt                 : {report.encoder_prompt_tokens:6d} tokens"
    )
    if report.break_even_calls:
        lines.append(
            f"    calls to repay that prompt            : {report.break_even_calls:6.1f} "
            "(amortised across a session)"
        )
    else:
        lines.append("    calls to repay that prompt            : n/a (no net saving)")
    lines.append(rule)
    verdict = (
        f"  RESULT: {report.pooled_reduction:.1f} % vs the {report.target:.0f} % brief target — "
        + ("TARGET MET" if report.meets_target else "TARGET NOT MET")
    )
    lines.append(verdict)
    if not report.meets_target:
        lines.append(
            "  Note: the corpus is deliberately adversarial. Read the per-case column\n"
            "  `vs terse` for the pessimistic bound and see README §Benchmarks for the\n"
            "  discussion of when the protocol wins."
        )
    lines.append(rule)
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Measure Zeno's token reduction.")
    parser.add_argument("--corpus", type=Path, default=None)
    parser.add_argument("--model", default=None, help="model id used to pick the encoding")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--no-canonical", action="store_true")
    args = parser.parse_args(argv)

    report = run(args.corpus, model=args.model, canonicalise=not args.no_canonical)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(render_report(report))
    return 0 if report.meets_target else 1


if __name__ == "__main__":
    raise SystemExit(main())
