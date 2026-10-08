"""Fail if the source starts claiming a guarantee the project cannot make.

Run as ``python -m tools.no_overclaim``.

The words themselves are not forbidden — the honest docstrings say "the brief
calls this unbreakable, and it is not", which is the point of the exercise. What
is forbidden is a *claim*: a superlative that is not denied, attributed, or
quoted on the same line. This is a crude instrument, and deliberately so: it is
cheap enough to run on every push, and a false positive costs one `# noqa`-style
comment rather than an unnoticed overclaim.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import List, Tuple

ROOT = Path(__file__).resolve().parent.parent

#: Words that may only appear as part of a denial, an attribution to the brief,
#: or a quoted claim.
SUPERLATIVES = re.compile(
    r"unbreakable|impenetrable|inescapable|unhackable|uncrackable|100% secure|"
    r"military[- ]grade|unbypassable",
    re.IGNORECASE,
)

#: Signals that the line is *about* the claim rather than making it.
CONTEXT = re.compile(
    r"\bnot\b|\bnever\b|\bno\b|\bcannot\b|\bcan't\b|\bisn't\b|\bdoesn't\b|\bdeny\b|"
    r"\brefuse\w*\b|\bclaim\w*\b|\bbrief\b|\bbranded\b|\bquoted?\b|\bsays?\b|"
    r"\bcalled?\b|\bcalls?\b|\bdescribes?\b|\bhonest\w*\b|\bno_?such\b|"
    r"\bwithout\b|\bavoid\w*\b|\boverclaim\w*\b",
    re.IGNORECASE,
)

SCAN_SUFFIXES = (".py", ".md", ".html")
SCAN_DIRS = ("aegis", "zeno", "specs", "tools")
SCAN_FILES = ("README.md", "SECURITY.md", "dashboard.html", "pyproject.toml")


def offending_lines() -> List[Tuple[Path, int, str]]:
    found: List[Tuple[Path, int, str]] = []
    targets: List[Path] = []
    for directory in SCAN_DIRS:
        targets.extend(sorted((ROOT / directory).rglob("*")))
    targets.extend(ROOT / name for name in SCAN_FILES)
    for path in targets:
        if not path.is_file() or path.suffix not in SCAN_SUFFIXES or path.name == "no_overclaim.py":
            continue
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        for number, line in enumerate(lines, 1):
            if not SUPERLATIVES.search(line) or CONTEXT.search(line):
                continue
            # Prose wraps: look one line either side of a superlative before
            # calling it a claim. A window rather than a paragraph, so a denial
            # three paragraphs away cannot excuse it.
            window = " ".join(lines[max(0, number - 2):number + 1])
            if not CONTEXT.search(window):
                found.append((path.relative_to(ROOT), number, line.strip()))
    return found


def main() -> int:
    # The statement of what is *not* claimed has to stay in the package, or every
    # docstring that points at it points at nothing.
    sys.path.insert(0, str(ROOT))
    from aegis import HONESTY

    if HONESTY.get("vajra_is_a_cipher") is not False:
        print("::error::aegis.HONESTY no longer states that VAJRA is not a cipher", file=sys.stderr)
        return 1
    if not HONESTY.get("claim_not_made"):
        print("::error::aegis.HONESTY does not name the claim it refuses to make", file=sys.stderr)
        return 1

    problems = offending_lines()
    for path, number, line in problems:
        print(f"::error file={path},line={number}::unearned guarantee: {line}")
    if problems:
        print(f"\n{len(problems)} overclaim(s): deny the claim, attribute it, or drop it.", file=sys.stderr)
        return 1
    print("no unearned guarantees")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
