"""Latency benchmark: how much of the round trip is *our* code.

Measures each stage in isolation and end to end, with no network access:

``parse``      text -> AST
``emit``       AST -> canonical text
``execute``    AST -> result against registered stub tools
``encode``     NL -> payload (scripted provider, so this is the client-side cost)
``decode``     result -> prose (scripted provider)
``roundtrip``  the whole three-stage pipeline

The LLM stages are measured with :class:`~zeno.providers.MockProvider` on
purpose: they isolate the protocol's own overhead from network variance. Any
production latency is dominated by the model, not by Zeno — the numbers below
show how much of the budget Zeno is responsible for.

    $ python -m benchmarks.latency_test --repeat 50
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from zeno.decoder import Decoder  # noqa: E402
from zeno.emitter import emit  # noqa: E402
from zeno.encoder import Encoder  # noqa: E402
from zeno.parser import parse  # noqa: E402
from zeno.pipeline import Pipeline  # noqa: E402
from zeno.providers import MockProvider  # noqa: E402
from zeno.runtime import Kernel  # noqa: E402

PAYLOAD = "@LOC[TYO] -> ?WX : { $WX.state == RAIN => !GEN[INDOOR, 3] | !GEN[OUTDOOR, 3] }"
REQUEST = (
    "Check the current weather conditions in Tokyo and, if it is raining, "
    "suggest three indoor activities; otherwise suggest three outdoor activities."
)


def stub_weather(args: List[Any], kwargs: Dict[str, Any], env: Any, call: Any) -> Dict[str, Any]:
    return {"state": "RAIN", "temp": 18, "city": "TYO"}


def build_kernel() -> Kernel:
    kernel = Kernel(generator=lambda topic, count, kwargs, env: [f"{topic}-{i}" for i in range(1, count + 1)])
    kernel.register_query("WX", stub_weather)
    return kernel


@dataclass
class StageTiming:
    """Aggregated timings for one stage."""

    name: str
    samples: List[float] = field(default_factory=list)

    def add(self, milliseconds: float) -> None:
        self.samples.append(milliseconds)

    @property
    def mean(self) -> float:
        return statistics.fmean(self.samples) if self.samples else 0.0

    @property
    def median(self) -> float:
        return statistics.median(self.samples) if self.samples else 0.0

    @property
    def p95(self) -> float:
        return _percentile(self.samples, 95)

    @property
    def worst(self) -> float:
        return max(self.samples) if self.samples else 0.0

    def to_dict(self) -> dict:
        return {
            "stage": self.name,
            "runs": len(self.samples),
            "mean_ms": round(self.mean, 4),
            "median_ms": round(self.median, 4),
            "p95_ms": round(self.p95, 4),
            "max_ms": round(self.worst, 4),
        }


def _percentile(values: List[float], percent: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int(round(percent / 100 * len(ordered))) - 1))
    return ordered[index]


@dataclass
class LatencyReport:
    """Timings for every stage plus the pipeline total."""

    stages: List[StageTiming] = field(default_factory=list)
    repeat: int = 0

    def stage(self, name: str) -> StageTiming:
        for entry in self.stages:
            if entry.name == name:
                return entry
        created = StageTiming(name)
        self.stages.append(created)
        return created

    @property
    def by_name(self) -> Dict[str, StageTiming]:
        return {entry.name: entry for entry in self.stages}

    def to_dict(self) -> dict:
        return {
            "repeat": self.repeat,
            "payload": PAYLOAD,
            "stages": [entry.to_dict() for entry in self.stages],
        }


def _time(func: Callable[[], Any], timing: StageTiming) -> Any:
    started = time.perf_counter()
    result = func()
    timing.add((time.perf_counter() - started) * 1000.0)
    return result


def run(repeat: int = 20) -> LatencyReport:
    """Measure every stage ``repeat`` times."""
    report = LatencyReport(repeat=repeat)
    kernel = build_kernel()
    program = parse(PAYLOAD)
    provider = MockProvider(PAYLOAD)
    decoder_provider = MockProvider("Tokyo is rainy, so here are three indoor ideas.")
    encoder = Encoder(provider)
    decoder = Decoder(decoder_provider)

    parse_stage = report.stage("parse")
    emit_stage = report.stage("emit")
    execute_stage = report.stage("execute")
    encode_stage = report.stage("encode")
    decode_stage = report.stage("decode")
    pipeline_stage = report.stage("roundtrip")

    for _ in range(repeat):
        _time(lambda: parse(PAYLOAD), parse_stage)
        _time(lambda: emit(program), emit_stage)
        execution = _time(lambda: kernel.execute(program), execute_stage)
        _time(lambda: encoder.encode(REQUEST), encode_stage)
        _time(lambda: decoder.decode(execution, request=REQUEST), decode_stage)

        pipeline = Pipeline(
            encoder=Encoder(MockProvider(PAYLOAD)),
            kernel=build_kernel(),
            decoder=Decoder(MockProvider("Tokyo is rainy, so here are three indoor ideas.")),
        )
        _time(lambda: pipeline.run(REQUEST), pipeline_stage)
    return report


def render_report(report: LatencyReport, *, width: int = 78) -> str:
    rule = "=" * width
    lines = [rule, "  ZENO PROTOCOL — LATENCY BENCHMARK", f"  repeats per stage: {report.repeat}", rule]
    lines.append(f"{'stage':<12}{'mean':>10}{'median':>10}{'p95':>10}{'max':>10}   (milliseconds)")
    lines.append("-" * width)
    for stage in report.stages:
        lines.append(
            f"{stage.name:<12}{stage.mean:>10.3f}{stage.median:>10.3f}"
            f"{stage.p95:>10.3f}{stage.worst:>10.3f}"
        )
    lines.append(rule)
    by_name = report.by_name
    total = by_name.get("roundtrip")
    if total and total.mean:
        parse_share = (
            (by_name["parse"].mean + by_name["emit"].mean)
            / total.mean
            * 100.0
            if "parse" in by_name
            else 0.0
        )
        lines.append(f"  full three-stage round trip : {total.mean:.3f} ms mean")
        lines.append(f"  grammar (parse + emit) share: {parse_share:.1f} % of that budget")
    lines.append("  Model calls are mocked here, so these numbers are the protocol's own")
    lines.append("  overhead — in production the LLM dominates and Zeno's share is noise.")
    lines.append(rule)
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Measure Zeno's own latency.")
    parser.add_argument("--repeat", type=int, default=20)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    report = run(max(1, args.repeat))
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(render_report(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
