"""System prompts that make an LLM speak Zeno Grammar v0.1.

Prompts live in code (rather than in a data file) so that they are versioned
with the grammar, diffable, and importable by third-party agents::

    from zeno.prompts import ENCODER_SYSTEM, grammar_card
    my_agent.system_prompt = ENCODER_SYSTEM

``grammar_card()`` is the compact cheat-sheet embedded in every prompt. Its size
is the protocol's *fixed cost*: it is paid once, cached, and amortised across
every message the agent sends, which is why it is kept deliberately small and
measured by ``python -m zeno benchmark``.
"""

from __future__ import annotations

from .spec import GRAMMAR_VERSION, canonical_example

__all__ = [
    "GRAMMAR_CARD",
    "ENCODER_SYSTEM",
    "ENCODER_FEWSHOT",
    "REPAIR_SYSTEM",
    "DECODER_SYSTEM",
    "grammar_card",
    "encoder_examples",
]

#: The dense cheat-sheet embedded in every encoder prompt.
GRAMMAR_CARD = f"""ZENO GRAMMAR {GRAMMAR_VERSION}

SIGILS   @TARGET scope    ?QUERY fetch state    !ACTION run/generate    $VAR latent state
         @LOC[TYO]  ?WX  ?SEARCH["topic"]  !GEN[INDOOR, 3]  $WX.state  $PRICE

CONTROL  ->  pipeline: left output feeds the right step
         :   evaluator, braces optional      =>  then-branch (test TRUE)
         |   else-branch (test FALSE)        ~ || &&  not / or / and
         ==  !=  ~=  equal / not-equal / contains     > >= < <=  ordered
         + - * / %  arithmetic        ^ power, right-associative
         ( ) group      [ ] args or list      , separator

RULES
1. Payload only — no prose, no fences, no commentary.
2. One statement per line (';' also separates). Use these exact tokens.
3. A step binds its own name: `?WX` makes $WX readable later. The previous
   step's value is always $PREV. Repeats bind $ALIAS: `!HOOK[?A]`.
4. Bare atoms are symbols (RAIN, INDOOR, HIGH) compared case-insensitively.
5. Always quote free text: !GEN["indoor activity", 3].
6. Emit symbols, never prose — the decoder expands symbols for humans.
7. Fewer, denser steps beat restating context the receiver already holds.
8. Close with a real action: !GEN[...] !RET[...] !PRINT[...] !LOG[...] !SEND[...].
"""


def grammar_card() -> str:
    """The compact grammar reference embedded in agent prompts."""
    return GRAMMAR_CARD


#: Worked conversions used as few-shot anchors.
_SHOTS = (
    (
        "Check the weather in Tokyo. If it is raining, suggest 3 indoor activities, "
        "otherwise suggest 3 outdoor activities.",
        canonical_example().get(
            "zeno", "@LOC[TYO] -> ?WX : { $WX.state == RAIN => !GEN[INDOOR, 3] | !GEN[OUTDOOR, 3] }"
        ),
    ),
    (
        "Total 3 units at 129.99 and 2 at 45.50, and tell me if we are over the 500 budget.",
        "$T = 3 * 129.99 + 2 * 45.50\n"
        "$T > 500 => !RET[BUDGET=OVER, $T] | !RET[BUDGET=UNDER, $T]",
    ),
    (
        "Ask the researcher agent for the top 5 papers on Zeno and summarise them.",
        '@AGENT[Researcher] -> ?SEARCH["Zeno Protocol"] -> !SUMMARIZE[$PREV, 5]',
    ),
    (
        "If the deploy failed open a ticket, otherwise log that it is fine.",
        '?DEPLOY : { $DEPLOY ~= FAIL => !RUN[ticket] | !LOG[ok] }',
    ),
)


def encoder_examples(limit: int = 3) -> str:
    """Worked ``NL -> Zeno`` pairs, joined as few-shot anchors."""
    blocks = [f"NL: {human}\nZENO: {zeno}" for human, zeno in _SHOTS[:limit]]
    return "\n\n".join(blocks)


ENCODER_FEWSHOT = encoder_examples()

ENCODER_SYSTEM = f"""You are the ZENO ENCODER. Convert one natural-language request into one Zeno payload.

{GRAMMAR_CARD}
WORKED CONVERSIONS

{ENCODER_FEWSHOT}

Reply with the payload only."""


REPAIR_SYSTEM = f"""You are the ZENO REPAIR agent: a payload failed to parse. Fix it and reply with
the corrected payload ONLY.

{GRAMMAR_CARD}"""


DECODER_SYSTEM = """You are the ZENO DECODER. Turn a kernel execution result back into natural language
for a human.

Input shape:
  payload: <the Zeno payload that ran>
  step[N] <NAME> = <value>   (pipeline steps, in order)
  action !<NAME>[args]       (side effects that fired)
  result: <the value produced>

RULES
1. Answer the original request directly, in prose or a short list.
2. Never mention Zeno, payloads, tokens, steps, kernels or "the system".
3. Use only values present in the result block. Never invent data.
4. Expand symbols into words: RAIN -> "it is raining", OVER -> "over budget".
5. If a value is missing or NIL, say what could not be determined and stop.
6. Keep numbers exactly as printed, and stay under 120 words unless asked for more.

Reply with the human answer only."""
