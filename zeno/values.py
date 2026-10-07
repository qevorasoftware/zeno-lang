"""Value model, latent-state environment and rendering helpers.

Zeno's runtime deliberately uses plain Python values (``int``/``float``/
``str``/``bool``/``None``/``list``/``dict``) so that results can be JSON
encoded without a conversion pass. This module adds the two things Python
lacks for our purposes:

* :class:`Env` — a *latent state* store with case-insensitive, dotted-path
  access (``$WX.state`` resolves ``env["WX"]["state"]``).
* :func:`render` — deterministic, compact value formatting shared by the
  decoder and the CLI.
"""

from __future__ import annotations

import json
import math
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

__all__ = ["UNSET", "Unset", "Env", "truthy", "render", "to_jsonable", "walk_path"]


class Unset:
    """Sentinel for "no such variable" — distinct from a stored ``NIL``."""

    __slots__ = ()

    def __bool__(self) -> bool:
        return False

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return "UNSET"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return "UNSET"


#: Singleton sentinel instance.
UNSET = Unset()


# ---------------------------------------------------------------------------
# Truthiness (grammar §1.2)
# ---------------------------------------------------------------------------
def truthy(value: Any) -> bool:
    """Grammar §1.2 truthiness.

    ``NIL``/``FALSE``/``0``/``0.0``/``""``/``[]``/``{}``/``UNSET`` are falsy,
    everything else is truthy.
    """
    if value is None or value is UNSET or value is False:
        return False
    if value is True:
        return True
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value != 0
    if isinstance(value, (str, bytes, list, tuple, dict, set)):
        return len(value) > 0
    return True


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------
def walk_path(root: Any, parts: Iterable[str]) -> Any:
    """Follow a dotted path, returning :data:`UNSET` at the first miss."""
    current = root
    for part in parts:
        if current is UNSET:
            return UNSET
        if isinstance(current, Env):
            current = current.get_one(part)
            continue
        if isinstance(current, dict):
            current = _lookup_case_insensitive(current, part)
            continue
        if isinstance(current, (list, tuple)):
            if part.isdigit() and int(part) < len(current):
                current = current[int(part)]
                continue
            return UNSET
        current = getattr(current, part, UNSET)
    return current


def _lookup_case_insensitive(mapping: Dict[str, Any], key: str) -> Any:
    if key in mapping:
        return mapping[key]
    lowered = key.lower()
    for candidate, value in mapping.items():
        if candidate.lower() == lowered:
            return value
    return UNSET


# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------
class Env:
    """Latent state: a scoped, case-insensitive variable store.

    >>> env = Env({"PRICE": 10})
    >>> env.set("WX.state", "RAIN")
    >>> env.get("wx.STATE")
    'RAIN'
    """

    __slots__ = ("_data", "parent", "scope")

    def __init__(
        self,
        initial: Optional[Dict[str, Any]] = None,
        parent: Optional["Env"] = None,
        scope: Tuple[str, ...] = (),
    ) -> None:
        self._data: Dict[str, Any] = {}
        self.parent = parent
        self.scope = scope
        if initial:
            self.update(initial)

    # -- construction ----------------------------------------------------
    def child(self, scope: Tuple[str, ...] = ()) -> "Env":
        """A nested scope that falls back to this one for reads."""
        return Env(parent=self, scope=scope or self.scope)

    # -- reads -----------------------------------------------------------
    def get_one(self, name: str) -> Any:
        """Look up a single (non-dotted) key in this scope or its parents."""
        env: Optional[Env] = self
        while env is not None:
            found = _lookup_case_insensitive(env._data, name)
            if found is not UNSET:
                return found
            env = env.parent
        return UNSET

    def get(self, name: str, default: Any = UNSET) -> Any:
        """Look up ``name``, which may be a dotted path such as ``WX.state``."""
        parts = name.split(".") if name else []
        if not parts:
            return default
        found = self.get_one(parts[0])
        if found is UNSET:
            return default
        result = walk_path(found, parts[1:]) if len(parts) > 1 else found
        return default if result is UNSET else result

    def __getitem__(self, name: str) -> Any:
        value = self.get(name)
        if value is UNSET:
            raise KeyError(name)
        return value

    def __contains__(self, name: str) -> bool:
        return self.get(name) is not UNSET

    # -- writes ----------------------------------------------------------
    def set(self, name: str, value: Any) -> None:
        """Assign ``name`` (dotted paths create nested mappings)."""
        parts = name.split(".") if name else []
        if not parts:
            return
        if len(parts) == 1:
            existing = _lookup_case_insensitive(self._data, parts[0])
            key = parts[0]
            if existing is UNSET:
                for candidate in self._data:
                    if candidate.lower() == parts[0].lower():
                        key = candidate
                        break
            self._data[key] = value
            return
        root_key = parts[0]
        container = _lookup_case_insensitive(self._data, root_key)
        if not isinstance(container, (dict, Env)):
            container = {}
            for candidate in list(self._data):
                if candidate.lower() == root_key.lower():
                    root_key = candidate
                    break
            self._data[root_key] = container
        _assign_path(container, parts[1:], value)

    def set_local(self, name: str, value: Any) -> None:
        """Assign without consulting the parent scope."""
        self._data[name] = value

    def update(self, mapping: Dict[str, Any]) -> None:
        for key, value in mapping.items():
            self.set(key, value)

    def unset(self, name: str) -> None:
        self._data.pop(name, None)

    # -- views -----------------------------------------------------------
    def as_dict(self) -> Dict[str, Any]:
        """Flatten every visible binding into a plain dictionary."""
        collected: Dict[str, Any] = {}
        env: Optional[Env] = self
        chain: List[Env] = []
        while env is not None:
            chain.append(env)
            env = env.parent
        for frame in reversed(chain):
            collected.update(frame._data)
        return collected

    def snapshot(self) -> Dict[str, Any]:
        """A detached, JSON-encodable copy (parents merged in)."""
        merged: Dict[str, Any] = {}
        for key, value in self.as_dict().items():
            merged[key] = to_jsonable(value)
        return merged

    def names(self) -> List[str]:
        return sorted(self.as_dict().keys())

    def __len__(self) -> int:
        return len(self.as_dict())

    def __iter__(self) -> Iterator[str]:
        return iter(self.as_dict())

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Env({self.as_dict()!r})"


def _assign_path(container: Any, parts: List[str], value: Any) -> None:
    if isinstance(container, Env):
        container.set(".".join(parts), value)
        return
    if len(parts) == 1:
        key = parts[0]
        for candidate in container:
            if candidate.lower() == key.lower():
                key = candidate
                break
        container[key] = value
        return
    head = parts[0]
    existing = _lookup_case_insensitive(container, head)
    if not isinstance(existing, dict):
        key = head
        for candidate in container:
            if candidate.lower() == head.lower():
                key = candidate
                break
        existing = {}
        container[key] = existing
    _assign_path(existing, parts[1:], value)


# ---------------------------------------------------------------------------
# JSON conversion & rendering
# ---------------------------------------------------------------------------
def to_jsonable(value: Any) -> Any:
    """Best-effort conversion into JSON-encodable structures."""
    if value is UNSET:
        return None
    if isinstance(value, Env):
        return value.snapshot()
    if isinstance(value, dict):
        return {str(key): to_jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [to_jsonable(item) for item in value]
    if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
        return repr(value)
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return repr(value)


def render(value: Any, *, style: str = "compact", max_string: int = 240) -> str:
    """Render a runtime value for a human or for a decoder prompt.

    Parameters
    ----------
    style:
        * ``"compact"`` — dense single-line form used inside payloads.
        * ``"json"`` — indented JSON.
        * ``"prose"`` — natural-language friendly lista for the decoder.
    """
    value = value if value is not UNSET else None
    if style == "json":
        return json.dumps(to_jsonable(value), indent=2, ensure_ascii=False, sort_keys=True)
    if style == "prose":
        return _render_prose(value, max_string)
    return _render_compact(value, max_string)


def _render_compact(value: Any, max_string: int) -> str:
    if value is None or value is UNSET:
        return "NIL"
    if value is True:
        return "TRUE"
    if value is False:
        return "FALSE"
    if isinstance(value, float):
        if value.is_integer() and abs(value) < 1e16:
            return str(int(value))
        return f"{value:g}"
    if isinstance(value, (int,)):
        return str(value)
    if isinstance(value, str):
        text = value if len(value) <= max_string else value[: max_string - 1] + "…"
        if _is_bare_atom(text):
            return text
        return json.dumps(text, ensure_ascii=False)
    if isinstance(value, (list, tuple, set, frozenset)):
        return "[" + ", ".join(_render_compact(item, max_string) for item in value) + "]"
    if isinstance(value, dict):
        return (
            "{"
            + ", ".join(
                f"{key}={_render_compact(item, max_string)}" for key, item in value.items()
            )
            + "}"
        )
    if isinstance(value, Env):
        return _render_compact(value.snapshot(), max_string)
    return repr(value)


def _is_bare_atom(text: str) -> bool:
    if not text or len(text) > 48:
        return False
    if text.upper() in {"TRUE", "FALSE", "NIL"}:
        return False
    return all(char.isalnum() or char == "_" for char in text) and not text[0].isdigit()


def _render_prose(value: Any, max_string: int) -> str:
    if isinstance(value, dict):
        if not value:
            return "an empty mapping"
        lines = ["a mapping with:"] + [
            f"  - {key}: {_render_prose(item, max_string)}" for key, item in value.items()
        ]
        return "\n".join(lines)
    if isinstance(value, (list, tuple)):
        if not value:
            return "an empty list"
        lines = [f"a list of {len(value)} items:"]
        for index, item in enumerate(value, start=1):
            lines.append(f"  {index}. {_render_prose(item, max_string)}")
        return "\n".join(lines)
    if isinstance(value, str):
        text = value if len(value) <= max_string else value[: max_string - 1] + "…"
        return text if text else "an empty string"
    if value is None or value is UNSET:
        return "nothing (NIL)"
    if value is True:
        return "true"
    if value is False:
        return "false"
    return _render_compact(value, max_string)
