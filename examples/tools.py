"""Example tool registry.

A "tool" is any callable with the signature ``fn(args, kwargs, env, call)``:

* ``args``    positional arguments, already evaluated
* ``kwargs``  named arguments, already evaluated
* ``env``     the live :class:`zeno.values.Env` (scope, bindings, ``$PREV``)
* ``call``    the :class:`zeno.ast.Call` node, so a tool can read its own name

Register a tool under a sigil-prefixed name to say whether it answers a query
(``?``) or performs an action (``!``)::

    $ python -m zeno run '@REPO["zeno-lang"] -> ?CI' --tools examples.tools:tools

Note the quotes: an unquoted ``zeno-lang`` is an expression (``zeno - lang``),
which the parser rejects rather than guessing what you meant.
"""

from __future__ import annotations

from typing import Any, Dict, List

from zeno.tools import demo_tools


def _repo(name: str) -> Dict[str, Any]:
    return {
        "name": name,
        "branch": "main",
        "open_prs": 3,
        "last_commit": "65d6dde",
        "ci": "green",
    }


def repository(args: List[Any], kwargs: Dict[str, Any], env: Any, call: Any) -> Dict[str, Any]:
    return _repo(str(args[0]) if args else "zeno-lang")


def ci_status(args: List[Any], kwargs: Dict[str, Any], env: Any, call: Any) -> Dict[str, Any]:
    repo = _repo(str(env.get("REPO") or (args[0] if args else "zeno-lang")))
    return {"state": repo["ci"], "branch": repo["branch"], "failures": 0}


def tools() -> Dict[str, Any]:
    """Return every tool this example exposes.

    Starts from :func:`zeno.tools.demo_tools` (weather, prices, orders ...) and
    adds two repository tools, which is the pattern for a real deployment:
    one registry per service, keyed by the names its contract advertises.
    """
    registry = demo_tools()
    registry.update(
        {
            "?REPO": repository,
            "?CI": ci_status,
        }
    )
    return registry


if __name__ == "__main__":  # pragma: no cover - manual demo
    from zeno.runtime import Kernel

    kernel = Kernel(tools=tools())
    print(kernel.execute('@REPO["zeno-lang"] -> ?CI').output)
