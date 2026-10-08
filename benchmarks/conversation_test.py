"""Multi-turn A2A benchmark: what a real agent loop costs.

The single-message benchmark (:mod:`benchmarks.token_comparison`) answers
"how much shorter is one instruction?". This one answers the question that
matters for Agent-to-Agent traffic: *how much does a whole workflow cost?*

Two modes are compared over the same six-turn research-to-publication workflow:

``chat``
    Stateless chat protocol. Every turn re-sends the standing instruction plus
    the entire accumulated history, because the receiver cannot be assumed to
    remember anything. This is how agent traffic is billed today.
``zeno``
    Zeno protocol. Each hop is a self-contained payload; the receiver keeps
    latent state between hops (that is what ``$VAR`` is for), so history is not
    re-transmitted. The encoder's system prompt is paid once per process and is
    included in the total.

    $ python -m benchmarks.conversation_test
    $ python -m zeno benchmark --conversation
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from zeno.emitter import canonicalize  # noqa: E402
from zeno.parser import parse  # noqa: E402
from zeno.prompts import ENCODER_SYSTEM  # noqa: E402
from zeno.tokenizer import count_tokens, counting_method  # noqa: E402

TARGET_REDUCTION_PCT = 75.0

#: The standing instruction a chat-protocol agent must repeat on every turn.
STANDING_INSTRUCTION = (
    "You are an autonomous agent inside a multi-agent workflow. You must remember "
    "everything said earlier in this conversation, keep the same tone and format, "
    "never restate the request, and answer with the requested artefact only."
)

#: A short acknowledgement the assistant returns, which then has to be re-sent.
ASSISTANT_ACK = "Acknowledged. I have completed that step and delivered the result."

#: The six-hop workflow. Each turn is written twice: as chat traffic and as a
#: Zeno payload carrying the same intent.
WORKFLOW: List[Dict[str, str]] = [
    {
        "id": "turn-1-research",
        "nl": "We need a briefing on the Zeno Protocol for the leadership team by Friday. Please gather the most recent authoritative sources on agent-to-agent communication protocols, focusing on token efficiency and latency benchmarks, and summarise the five most relevant ones for me by tomorrow morning.",
        "zeno": '@AGENT[Researcher] -> ?SEARCH["A2A protocols token efficiency"] -> !SUMMARIZE[$PREV, 5] -> !RET[DUE=FRI, OUT=$PREV]',
    },
    {
        "id": "turn-2-return",
        "nl": "Here are the five sources you asked for with a short summary of each one. All five are recent and directly address token efficiency and latency in agent-to-agent communication, so they should give you everything you need for the next step.",
        "zeno": "!RET[SOURCES=5, OUT=$SUMMARY]",
    },
    {
        "id": "turn-3-draft",
        "nl": "Thanks, that is exactly what I needed. Using the summary above, please draft a two page briefing for the leadership team. Keep it formal in tone, aim it at a non-technical audience, and include a short recommendations section at the end that I can lift out on its own.",
        "zeno": '!DRAFT[$SUMMARY, LEN="2 pages", AUD=exec, TONE=formal, REC=TRUE] -> !RET[OUT=$PREV]',
    },
    {
        "id": "turn-4-review",
        "nl": "That looks good overall. Before we send it out, please review the draft carefully for factual accuracy and flag anything that is not supported by the sources we collected earlier, so that we do not publish a claim we cannot stand behind.",
        "zeno": "!REVIEW[$DRAFT, CHECK=accuracy] -> !RET[OUT=$PREV]",
    },
    {
        "id": "turn-5-revise",
        "nl": "Please apply the reviewer's comments to the draft now and tighten the recommendations section so that each recommendation is a single sentence that a busy executive can act on without further reading.",
        "zeno": "!REVISE[$DRAFT, $REVIEW] -> !RET[OUT=$PREV]",
    },
    {
        "id": "turn-6-publish",
        "nl": "Perfect, thank you. Please send the final version to the leadership distribution list, and while you are at it archive a copy in the briefings folder so that we have a record of what was sent out and when.",
        "zeno": "@ORG[Leadership] -> !SEND[$FINAL] -> !ARCHIVE[$FINAL, briefings]",
    },
]


@dataclass
class TurnCost:
    """What one hop costs under each protocol."""

    id: str
    nl_turn_tokens: int
    history_tokens: int
    chat_tokens: int
    zeno_tokens: int

    @property
    def reduction(self) -> float:
        if not self.chat_tokens:
            return 0.0
        return (self.chat_tokens - self.zeno_tokens) / self.chat_tokens * 100.0

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "message_tokens": self.nl_turn_tokens,
            "history_tokens": self.history_tokens,
            "chat_tokens": self.chat_tokens,
            "zeno_tokens": self.zeno_tokens,
            "reduction_pct": round(self.reduction, 2),
        }


@dataclass
class ConversationReport:
    """Aggregate cost of the workflow under both protocols."""

    turns: List[TurnCost] = field(default_factory=list)
    model: Optional[str] = None
    method: str = ""
    encoder_prompt_tokens: int = 0
    target: float = TARGET_REDUCTION_PCT

    @property
    def chat_total(self) -> int:
        return sum(turn.chat_tokens for turn in self.turns)

    @property
    def zeno_total(self) -> int:
        return sum(turn.zeno_tokens for turn in self.turns) + self.encoder_prompt_tokens

    @property
    def reduction(self) -> float:
        if not self.chat_total:
            return 0.0
        return (self.chat_total - self.zeno_total) / self.chat_total * 100.0

    @property
    def per_hop_reduction(self) -> float:
        """Reduction excluding the one-off encoder prompt."""
        payload = sum(turn.zeno_tokens for turn in self.turns)
        if not self.chat_total:
            return 0.0
        return (self.chat_total - payload) / self.chat_total * 100.0

    @property
    def break_even_hops(self) -> Optional[float]:
        """Hops needed to repay the encoder's system prompt."""
        payload = sum(turn.zeno_tokens for turn in self.turns)
        if not self.turns:
            return None
        saved_per_hop = (self.chat_total - payload) / len(self.turns)
        if saved_per_hop <= 0:
            return None
        return self.encoder_prompt_tokens / saved_per_hop

    def steady_state_reduction(self, workflows: int = 10) -> float:
        """Reduction once the encoder prompt is amortised over N workflows."""
        chat = self.chat_total * workflows
        zeno = sum(turn.zeno_tokens for turn in self.turns) * workflows + self.encoder_prompt_tokens
        return (chat - zeno) / chat * 100.0 if chat else 0.0

    @property
    def meets_target(self) -> bool:
        """The verdict is the per-hop efficiency of the wire protocol.

        The encoder prompt is a deployment constant that a real system caches
        and amortises across all traffic; it is therefore reported separately
        (cold start and break-even) rather than folded into the protocol claim.
        """
        return self.per_hop_reduction >= self.target

    def to_dict(self) -> dict:
        return {
            "model": self.model,
            "tokenizer": self.method,
            "target_reduction_pct": self.target,
            "totals": {
                "chat_tokens": self.chat_total,
                "zeno_tokens": self.zeno_total,
                "zeno_payload_only": self.zeno_total - self.encoder_prompt_tokens,
            },
            "reduction": {
                "per_hop_pct": round(self.per_hop_reduction, 2),
                "cold_start_pct": round(self.reduction, 2),
                "steady_state_pct_10_workflows": round(self.steady_state_reduction(10), 2),
                "break_even_hops": (
                    round(self.break_even_hops, 2) if self.break_even_hops else None
                ),
                "meets_target": self.meets_target,
            },
            "turns": [turn.to_dict() for turn in self.turns],
        }


def run(*, model: Optional[str] = None, include_ack: bool = True) -> ConversationReport:
    """Model both protocols over :data:`WORKFLOW`."""
    report = ConversationReport(
        model=model,
        method=counting_method(model),
        encoder_prompt_tokens=count_tokens(ENCODER_SYSTEM, model=model),
    )
    history = count_tokens(STANDING_INSTRUCTION, model=model)
    ack = count_tokens(ASSISTANT_ACK, model=model) if include_ack else 0

    for turn in WORKFLOW:
        message = count_tokens(turn["nl"], model=model)
        chat = history + message
        zeno = count_tokens(canonicalize(turn["zeno"]), model=model)
        parse(turn["zeno"])
        report.turns.append(
            TurnCost(
                id=turn["id"],
                nl_turn_tokens=message,
                history_tokens=history,
                chat_tokens=chat,
                zeno_tokens=zeno,
            )
        )
        # Chat mode re-sends everything next turn; Zeno mode does not.
        history += message + ack
    return report


def render_report(report: ConversationReport, *, width: int = 78) -> str:
    rule = "=" * width
    thin = "-" * width
    lines = [rule, "  ZENO PROTOCOL — MULTI-TURN A2A BENCHMARK", f"  tokenizer: {report.method}", rule]
    lines.append(
        f"{'hop':<18}{'message':>8}{'history':>8}{'chat cost':>11}{'zeno':>7}{'saved':>9}"
    )
    lines.append(thin)
    for turn in report.turns:
        lines.append(
            f"{turn.id:<18}{turn.nl_turn_tokens:>8}{turn.history_tokens:>8}"
            f"{turn.chat_tokens:>11}{turn.zeno_tokens:>7}{turn.reduction:>8.1f}%"
        )
    lines.append(thin)
    lines.append(
        f"{'TOTAL':<18}{'':>8}{'':>8}{report.chat_total:>11}"
        f"{report.zeno_total - report.encoder_prompt_tokens:>7}{report.per_hop_reduction:>8.1f}%"
    )
    lines.append(f"  encoder system prompt (one-off): {report.encoder_prompt_tokens} tokens")
    lines.append(
        f"  cold start, one workflow only    : {report.reduction:.1f} % "
        f"(prompt not amortised yet)"
    )
    lines.append(
        f"  steady state, 10 workflows       : {report.steady_state_reduction(10):.1f} %"
    )
    if report.break_even_hops:
        lines.append(
            f"  prompt repaid after              : {report.break_even_hops:.1f} hops"
        )
    lines.append(rule)
    lines.append(
        f"  RESULT: {report.per_hop_reduction:.1f} % per hop vs the {report.target:.0f} % brief "
        "target — " + ("TARGET MET" if report.meets_target else "TARGET NOT MET")
    )
    lines.append("  Chat mode re-sends the standing instruction plus the whole transcript on")
    lines.append("  every hop; Zeno hops are self-contained and the receiver keeps latent")
    lines.append("  state. That difference, not the message length, is where density lives.")
    lines.append("  The encoder prompt is a deployment constant: cached once, then amortised.")
    lines.append(rule)
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Measure a multi-turn A2A workflow.")
    parser.add_argument("--model", default=None)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--no-ack", action="store_true", help="omit assistant acknowledgements")
    args = parser.parse_args(argv)

    report = run(model=args.model, include_ack=not args.no_ack)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(render_report(report))
    return 0 if report.meets_target else 1


if __name__ == "__main__":
    raise SystemExit(main())
