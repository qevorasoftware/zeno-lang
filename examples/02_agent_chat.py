"""Example 2 — two agents talking in Zeno.

This runs the full three-stage pipeline (encoder -> kernel -> decoder) offline:
a :class:`~zeno.providers.MockProvider` replays what a model would answer, so
the example exercises the protocol end to end without an API key.

To see it run against a real model::

    GROQ_API_KEY=... python examples/02_agent_chat.py

The interesting part is the middle: the payload on the ``zeno`` line is what
would actually travel on the wire. The last block reports what that traffic
costs compared to sending the natural-language requests instead.
"""

from __future__ import annotations

from typing import List, Tuple

from zeno.emitter import canonicalize
from zeno.pipeline import Pipeline
from zeno.providers import MockProvider, resolve
from zeno.runtime import Kernel
from zeno.tools import demo_generator, demo_tools

#: (identifier word in the request, payload a model would emit for it).
SCRIPT: List[Tuple[str, str]] = [
    ("weather", "@LOC[TYO] -> ?WX : { $WX.state == RAIN => !GEN[INDOOR, 3] | !GEN[OUTDOOR, 3] }"),
    ("share price", "?PRICE[ACME].price < 120 => !ALERT[phone, ACME_LOW] | !NOOP"),
    ("catch-up", "?SLOTS[week, 30] : { $SLOTS.count > 0 => !BOOK[$SLOTS.first] | !MSG[propose] }"),
]

#: The conversation, as an agent would phrase it.
TURNS: List[str] = [
    "Check the weather in Tokyo. If it is raining, suggest three indoor activities, "
    "otherwise suggest three outdoor activities.",
    "Alert me if the ACME share price drops below 120 dollars, and otherwise do nothing.",
    "Book a 30 minute catch-up with Amara next week if she is free, or ask her to propose a time.",
]


def scripted(prompt: str, system: str | None = None) -> str:
    """Answer encoder prompts with the scripted payloads, decoders in prose."""
    if "ENCODER" not in (system or "").upper():
        return "Done — the receiver acted on the payload and reported back."
    lowered = prompt.lower()
    for marker, payload in SCRIPT:
        if marker in lowered:
            return payload
    return SCRIPT[-1][1]


def main() -> None:
    provider = resolve()
    online = provider.available()
    if online:
        print(f"Using provider {provider.name!r} ({provider.model}).\n")
    else:
        print("No provider configured — replaying scripted payloads (offline mode).\n")
        provider = MockProvider(scripted)

    kernel = Kernel(tools=demo_tools(), generator=demo_generator)
    pipeline = Pipeline(provider=provider, kernel=kernel)

    human_total = zeno_total = 0
    for index, message in enumerate(TURNS, start=1):
        outcome = pipeline.run(message)
        human_total += outcome.encode.nl_tokens
        zeno_total += outcome.encode.zeno_tokens

        answer = (outcome.response or "—").splitlines()[0]
        print(f"turn {index}")
        print(f"  human →  {message}")
        print(f"  zeno  →  {canonicalize(outcome.payload)}")
        print(f"  answer   {answer}")
        print(
            f"  cost     {outcome.encode.nl_tokens} NL tokens → "
            f"{outcome.encode.zeno_tokens} Zeno tokens"
        )
        print()

    saved = human_total - zeno_total
    print(f"three turns: {human_total} NL tokens → {zeno_total} Zeno tokens")
    if saved > 0:
        print(f"saved {saved} tokens ({saved / human_total * 100:.1f} %) on the wire")
    else:
        print(
            "the payloads are not smaller here: each request is a single short\n"
            "sentence, and the encoder prompt is a fixed cost paid once per session.\n"
            "Run `python -m zeno benchmark` for the corpus-level and per-hop numbers."
        )
    if not online:
        print("\nSet GROQ_API_KEY (or ZENO_PROVIDER=ollama) to run this against a real model.")


if __name__ == "__main__":
    main()
