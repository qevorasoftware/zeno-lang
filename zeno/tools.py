"""A small, deterministic toolset used by the examples, the CLI and the web
playground.

Built-ins (``?LEN``, ``?COUNT``, ``?STR``, ``!LOG``, ``!PRINT``, ``!RET``,
``!GEN`` ...) are provided by :class:`zeno.runtime.Kernel` and are deliberately
*not* overridden here.

Every tool is a plain callable with the signature ``fn(args, kwargs, env, call)``
and every value is fixed, so results are reproducible and no network access is
required. The tools exist to make the protocol *runnable*, not to be useful in
production: swap them for your own with ``kernel.register_query`` /
``kernel.register_action``.

    >>> from zeno.runtime import Kernel
    >>> from zeno.tools import demo_tools, demo_generator
    >>> kernel = Kernel(tools=demo_tools(), generator=demo_generator)
    >>> kernel.execute("@LOC[TYO] -> ?WX").output["state"]
    'RAIN'
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List

__all__ = ["demo_tools", "demo_generator", "FORECASTS", "PRICES"]

#: Fixed forecasts per city code. ``?WX`` returns the entry for the current
#: ``@LOC`` scope.
FORECASTS: Dict[str, Dict[str, Any]] = {
    "TYO": {"state": "RAIN", "temp": 18, "humidity": 82, "city": "Tokyo"},
    "PAR": {"state": "CLEAR", "temp": 24, "humidity": 41, "city": "Paris"},
    "NYC": {"state": "SNOW", "temp": -2, "humidity": 70, "city": "New York"},
    "AMD": {"state": "CLEAR", "temp": 34, "humidity": 25, "city": "Ahmedabad"},
    "SFO": {"state": "FOG", "temp": 15, "humidity": 88, "city": "San Francisco"},
    "BER": {"state": "RAIN", "temp": 11, "humidity": 77, "city": "Berlin"},
    "LON": {"state": "CLOUD", "temp": 13, "humidity": 74, "city": "London"},
}

#: Fixed quotes per ticker.
PRICES: Dict[str, Dict[str, Any]] = {
    "ACME": {"symbol": "ACME", "price": 118.4, "currency": "USD", "change": -1.6},
    "GLOB": {"symbol": "GLOB", "price": 342.1, "currency": "USD", "change": 4.2},
    "ZENO": {"symbol": "ZENO", "price": 7.05, "currency": "USD", "change": 0.15},
}

#: A fixed week of availability for ``?SLOTS``.
SLOTS: Dict[str, Any] = {
    "count": 2,
    "next": "2026-10-14T09:00Z",
    "first": "2026-10-14T09:00Z",
    "duration": 30,
    "owner": "Amara",
    "state": "OPEN",
}


def _first(args: List[Any], default: Any = None) -> Any:
    return args[0] if args else default


def demo_generator(topic: Any, count: int, kwargs: Dict[str, Any], env: Any) -> List[str]:
    """Deterministic stand-in for a generative model, wired to ``!GEN``.

    ``!GEN[INDOOR, 3]`` produces ``['INDOOR 1', 'INDOOR 2', 'INDOOR 3']``.
    """
    label = str(topic if topic is not None else "ITEM")
    size = 1
    try:
        size = max(1, min(10, int(count)))
    except (TypeError, ValueError):  # pragma: no cover - defensive
        size = 1
    return [f"{label} {index}" for index in range(1, size + 1)]


def demo_tools() -> Dict[str, Callable[..., Any]]:
    """Return a fresh tool registry keyed by sigil-prefixed name."""

    def weather(args: List[Any], kwargs: Dict[str, Any], env: Any, call: Any) -> Dict[str, Any]:
        requested = _first(args)
        code = str(_first([requested], None) or env.get("LOC") or "TYO").upper()
        if requested and isinstance(requested, str) and requested.upper() in FORECASTS:
            code = requested.upper()
        return dict(FORECASTS.get(code, {"state": "UNKNOWN", "city": code}))

    def price(args: List[Any], kwargs: Dict[str, Any], env: Any, call: Any) -> Dict[str, Any]:
        symbol = str(_first(args, kwargs.get("SYMBOL")) or "ACME").upper()
        return dict(PRICES.get(symbol, {"symbol": symbol, "price": 0.0, "currency": "USD"}))

    def slots(args: List[Any], kwargs: Dict[str, Any], env: Any, call: Any) -> Dict[str, Any]:
        window = str(_first(args, "week"))
        duration = kwargs.get("DUR") or kwargs.get("DURATION") or (args[1] if len(args) > 1 else 30)
        return dict(SLOTS, window=window, duration=duration)

    def deploy(args: List[Any], kwargs: Dict[str, Any], env: Any, call: Any) -> Dict[str, Any]:
        return {"status": "success", "commit": "65d6dde", "environment": "prod", "failed": False}

    def order(args: List[Any], kwargs: Dict[str, Any], env: Any, call: Any) -> Dict[str, Any]:
        return {
            "id": "ORD-1042",
            "state": "in_transit",
            "tracking": "1Z-TRACK-1042",
            "overdue_days": 6,
            "customer": "amara",
        }

    def eta(args: List[Any], kwargs: Dict[str, Any], env: Any, call: Any) -> Dict[str, Any]:
        overdue = 6
        first = _first(args)
        if isinstance(first, dict) and "overdue_days" in first:
            overdue = first["overdue_days"]
        return {"overdue": overdue, "delivery": "2026-10-09", "carrier": "RapidShip"}

    def ticket(args: List[Any], kwargs: Dict[str, Any], env: Any, call: Any) -> Dict[str, Any]:
        return {"subject": "customer cannot log in", "priority": "high", "state": "open"}

    def alert(args: List[Any], kwargs: Dict[str, Any], env: Any, call: Any) -> Dict[str, Any]:
        return {"id": "ALT-77", "severity": "CRITICAL", "service": "payments-api", "cluster": "prod"}

    def doc(args: List[Any], kwargs: Dict[str, Any], env: Any, call: Any) -> Dict[str, Any]:
        name = str(_first(args, "document"))
        return {"name": name, "pages": 12, "language": "en", "text": f"text of {name}"}

    def docs(args: List[Any], kwargs: Dict[str, Any], env: Any, call: Any) -> List[str]:
        return [f"{_first(args, 'doc')}-{index}" for index in range(1, 4)]

    def record(args: List[Any], kwargs: Dict[str, Any], env: Any, call: Any) -> Any:
        """Echo-side-effect action: returns its argument and a status symbol."""
        return _first(args, call.name)

    tools: Dict[str, Callable[..., Any]] = {
        "?WX": weather,
        "?PRICE": price,
        "?SLOTS": slots,
        "?DEPLOY": deploy,
        "?ORDER": order,
        "?ETA": eta,
        "?TICKET": ticket,
        "?ALERT": alert,
        "?DOC": doc,
        "?DOCS": docs,
        "!SEND": record,
        "!BOOK": record,
        "!MSG": record,
        "!REFUND": record,
        "!ESCALATE": record,
        "!ROUTE": record,
        "!ALERT": record,
        "!RUN": record,
        "!ACK": record,
        "!APPEND": record,
        "!PAGE": record,
        "!OPEN": record,
        "!CLOSE": record,
        "!FLAG": record,
        "!ARCHIVE": record,
        "!PUBLISH": record,
    }
    return tools
