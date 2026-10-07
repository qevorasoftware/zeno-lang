"""Layer 6 — polymorphic syntax rotation.

What it does
------------
Zeno's *vocabulary* is rotated on a timer: for a given epoch, every registered
tool name is replaced by a short alias derived as
``HMAC-SHA256(rotation_key, epoch || canonical_name)``. Payloads written for
epoch N do not run in epoch N+1 without the mapping, so a copy of yesterday's
captured payload — or a leaked integration script — stops being useful.

What it is not
--------------
This is a **keyed deterministic transform, not encryption**. Anyone with the
rotation key can invert it instantly, and the key must reach every legitimate
receiver. So:

* it protects against *static* copies of payloads and against an attacker who
  cannot obtain the key — that is a real and useful property;
* it does **not** protect against a compromised receiver (they hold the key by
  definition), and it does not stop the attacker from *learning* the mapping
  from a single observed (alias, tool) pair if they can watch both ends;
* rotation is a deliberate availability trade-off: long-lived sessions break at
  epoch boundaries, so the gateway re-issues syntax with a skew window.

Kerckhoffs's principle still applies: the transform is public, the key is not.
The canonical Grammar v0.1 registry is the source of truth and is never
"morphed into oblivion" — if it were, no two AEGIS deployments could interoperate.

    >>> engine = PolymorphicEngine(b"rotation-key", epoch_seconds=21600)
    >>> table = engine.table(epoch=100)
    >>> engine.rotate_payload("@LOC[TYO] -> ?WX", epoch=100) != "@LOC[TYO] -> ?WX"
    True
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from ._kdf import hkdf

__all__ = [
    "PolymorphicEngine",
    "SyntaxTable",
    "RotationPolicy",
    "DEFAULT_EPOCH_SECONDS",
    "canonical_names",
]

#: The brief's six-hour window. Made a parameter because the right value is an
#: operational decision: shorter = tighter window, more churn.
DEFAULT_EPOCH_SECONDS = 6 * 60 * 60

_ALIAS_ALPHABET = "BCDFGHJKLMNPQRSTVWXZ"  # no vowels, so aliases cannot spell words
_ALIAS_LENGTH = 4
_PAYLOAD_TOKEN = re.compile(r"[?!]([A-Za-z][A-Za-z0-9_]*)")


def canonical_names(extra: Optional[Iterable[str]] = None) -> List[str]:
    """Every name AEGIS will rotate: the Grammar v0.1 registry plus extras."""
    from zeno.runtime import Kernel

    kernel = Kernel()
    names: Set[str] = set(kernel.queries) | set(kernel.actions)
    from zeno.tools import demo_tools

    for name in demo_tools():
        names.add(name.lstrip("?!"))
    from zeno.spec import tokens

    for entry in tokens().get("keywords", []):
        names.add(str(entry["token"]).upper())
    if extra:
        names.update(str(name).lstrip("?!").upper() for name in extra)
    return sorted(names)


@dataclass(frozen=True)
class RotationPolicy:
    """How fast the vocabulary rotates, and how tolerant the edges are."""

    epoch_seconds: int = DEFAULT_EPOCH_SECONDS
    #: Accept the previous epoch too, so a handoff in flight still completes.
    grace_epochs: int = 1

    def epoch_at(self, when: Optional[float] = None) -> int:
        return int((when if when is not None else time.time()) // self.epoch_seconds)

    def accepts(self, epoch: int, now: Optional[float] = None) -> bool:
        current = self.epoch_at(now)
        return current - self.grace_epochs <= epoch <= current

    def to_dict(self) -> Dict[str, Any]:
        return {
            "epoch_seconds": self.epoch_seconds,
            "hours": self.epoch_seconds / 3600,
            "grace_epochs": self.grace_epochs,
        }


@dataclass
class SyntaxTable:
    """The bidirectional alias map for one epoch.

    ``to_alias``/``to_canonical`` are the only things a receiver needs; the
    table is authenticated by the fact that it is derived from a shared key.
    """

    epoch: int
    forward: Dict[str, str]
    reverse: Dict[str, str]
    policy: RotationPolicy
    digest: str = ""

    def __post_init__(self) -> None:
        if not self.digest:
            material = json.dumps(
                {"epoch": self.epoch, "forward": dict(sorted(self.forward.items()))},
                sort_keys=True,
                separators=(",", ":"),
            )
            self.digest = hashlib.sha256(material.encode()).hexdigest()[:16]

    def to_alias(self, canonical: str) -> str:
        return self.forward.get(canonical.upper(), canonical)

    def to_canonical(self, alias: str) -> str:
        return self.reverse.get(alias.upper(), alias)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "epoch": self.epoch,
            "digest": self.digest,
            "policy": self.policy.to_dict(),
            "aliases": dict(sorted(self.forward.items())),
            "size": len(self.forward),
        }

    @classmethod
    def from_dict(
        cls,
        payload: Dict[str, Any],
        key: bytes,
        policy: Optional[RotationPolicy] = None,
        names: Optional[Sequence[str]] = None,
    ) -> "SyntaxTable":
        """Re-derive the table from the key rather than trusting the payload.

        A receiver that merely trusted the transmitted table would accept an
        attacker's mapping, so the alias list is verified against HMAC output
        and rejected if it does not match the key.

        ``names`` must be the same registry the sender used. Omit it for the
        canonical Zeno registry; a sender that rotated a custom name list must
        pass that list here, because a table built from different names simply
        will not reproduce — which is the correct outcome, not a bug.
        """
        policy = policy or RotationPolicy(
            epoch_seconds=int(payload.get("policy", {}).get("epoch_seconds", DEFAULT_EPOCH_SECONDS))
        )
        epoch = int(payload["epoch"])
        engine = PolymorphicEngine(key, policy=policy, names=names)
        derived = engine.table(epoch)
        if derived.digest != payload.get("digest", derived.digest):
            raise ValueError(
                "syntax table does not match the rotation key (or was built from a different name registry)"
            )
        return derived


class PolymorphicEngine:
    """Derives per-epoch alias tables and rewrites payloads with them."""

    def __init__(
        self,
        key: bytes,
        *,
        policy: Optional[RotationPolicy] = None,
        names: Optional[Sequence[str]] = None,
    ) -> None:
        if not key:
            raise ValueError("the rotation key cannot be empty")
        self.key = key
        self.policy = policy or RotationPolicy()
        self.names = [name.upper() for name in (names or canonical_names())]
        self._cache: Dict[int, SyntaxTable] = {}
        self.rotations = 0

    # -- derivation ------------------------------------------------------
    def _alias(self, epoch: int, name: str, length: int) -> str:
        material = f"aegis/syntax/v2|{epoch}|{name}".encode()
        digest = hmac.new(self.key, material, hashlib.sha256).digest()
        alphabet = _ALIAS_ALPHABET
        return "".join(alphabet[byte % len(alphabet)] for byte in digest[:length])

    def table(self, epoch: Optional[int] = None) -> SyntaxTable:
        """Build (and cache) the alias table for ``epoch``."""
        epoch = self.policy.epoch_at() if epoch is None else int(epoch)
        if epoch in self._cache:
            return self._cache[epoch]

        forward: Dict[str, str] = {}
        reverse: Dict[str, str] = {}
        length = _ALIAS_LENGTH
        for name in self.names:
            alias = self._alias(epoch, name, length)
            # Collisions are astronomically unlikely, but resolve them anyway:
            # two tools sharing an alias would be an authentication bypass.
            while alias in reverse:
                length += 1
                alias = self._alias(epoch, name, length)
            forward[name] = alias
            reverse[alias] = name
            length = _ALIAS_LENGTH

        table = SyntaxTable(epoch=epoch, forward=forward, reverse=reverse, policy=self.policy)
        self._cache[epoch] = table
        return table

    # -- payload rewriting ----------------------------------------------
    def rotate_payload(self, payload: str, epoch: Optional[int] = None) -> str:
        """Rename every registered tool in ``payload`` to its alias."""
        table = self.table(epoch)
        return _rename(payload, table.forward)

    def restore_payload(self, payload: str, epoch: int) -> str:
        """Undo :meth:`rotate_payload`, then re-emit in canonical form."""
        from zeno.emitter import canonicalize

        table = self.table(epoch)
        restored = _rename(payload, table.reverse)
        return canonicalize(restored)

    def decode_with_grace(self, payload: str, now: Optional[float] = None) -> Tuple[str, int]:
        """Try the current epoch, then the grace epoch; return (payload, epoch)."""
        current = self.policy.epoch_at(now)
        last_error: Optional[Exception] = None
        for epoch in range(current, current - self.policy.grace_epochs - 1, -1):
            try:
                return self.restore_payload(payload, epoch), epoch
            except Exception as exc:  # noqa: BLE001 - reported to the caller
                last_error = exc
        raise ValueError(f"payload does not match any accepted epoch: {last_error}")

    # -- introspection ---------------------------------------------------
    def describe(self) -> Dict[str, Any]:
        table = self.table()
        return {
            "layer": "polymorphic-syntax",
            "policy": self.policy.to_dict(),
            "current_epoch": table.epoch,
            "table_digest": table.digest,
            "names": len(table.forward),
            "rotations": self.rotations,
            "cipher": False,
            "note": "keyed vocabulary rotation: defeats static copies, not a key-holding receiver",
        }

    def fingerprint(self, epoch: Optional[int] = None) -> str:
        return self.table(epoch).digest


def _rename(payload: str, mapping: Dict[str, str]) -> str:
    """Rewrite ``?NAME``/``!NAME`` tokens; leave everything else untouched."""

    def replace(match: re.Match) -> str:
        sigil = match.group(0)[0]
        name = match.group(1).upper()
        return f"{sigil}{mapping.get(name, match.group(1))}"

    return _PAYLOAD_TOKEN.sub(replace, payload)
