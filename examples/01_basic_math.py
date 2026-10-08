"""Example 1 — the protocol without any model.

Everything here is deterministic: no network, no API key, no dependency beyond
the standard library. Run it with::

    python examples/01_basic_math.py

It shows the four things a Zeno payload can do: bind, query, decide, answer.
"""

from __future__ import annotations

from zeno.emitter import canonicalize
from zeno.runtime import Kernel, result_frame
from zeno.tokenizer import count_tokens, counting_method

PAYLOAD = '''$UNIT = 129.99
$QTY = 3
$SHIPPING = 2 * 45.50
$TOTAL = $UNIT * $QTY + $SHIPPING
$TOTAL > 500 => !RET[BUDGET=OVER, $TOTAL] | !RET[BUDGET=UNDER, $TOTAL]'''


def main() -> None:
    kernel = Kernel()
    print(f"kernels are deterministic, tokenizer: {counting_method()}\n")
    print("payload:")
    for line in canonicalize(PAYLOAD).splitlines():
        print(f"    {line}")

    result = kernel.execute(PAYLOAD)

    print("\nresult frame:")
    print(f"    {result_frame(result)}")

    print("\nanswer:", result.answer)
    print("bindings:", ", ".join(f"${name}={value}" for name, value in result.bindings.items()))
    print(f"steps: {[step.name for step in result.steps]}")
    print(f"executed in {result.duration_ms:.3f} ms")

    # The same payload in the machine-readable form another agent would read.
    print("\nas context:")
    print("\n".join(f"    {line}" for line in result.as_context().splitlines()))

    # The conditional runs the *other* branch when the total changes; the
    # payload itself never has to change.
    cheap = kernel.execute(PAYLOAD.replace("129.99", "9.99"))
    print(f"\nwith a cheaper unit price: {cheap.answer} ({result_frame(cheap)})")

    tokens = count_tokens(canonicalize(PAYLOAD))
    print(f"\ncanonical payload: {len(canonicalize(PAYLOAD))} chars, {tokens} tokens")


if __name__ == "__main__":
    main()
