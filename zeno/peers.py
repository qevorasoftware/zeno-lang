"""Connected agents: your agent can talk to other agents, including not-your-own.

What this is: a registry of external agents, each addressed by URL, each holding
its own owner-issued capability grant, each call authorized by the same AEGIS
boundary as everything else and recorded in the same ledger and memory. What it is
*not*: a claim that you can connect to anything. Three limits are real and are
reported rather than hidden:

* **No artificial cap, real limits.** There is no maximum number of connected
  agents: the registry is a mapping and the fan-out is bounded only by the
  concurrency and per-call timeout you configure. What *does* bound you is the
  network, the peer's own rate limits, and your machine.
* **Every call is authenticated outbound and gated inbound.** Outbound, the peer
  is given the grant you issued it — not your owner key. Inbound, this server
  applies its own boundary, so a peer cannot use this registry as a way around
  authorization.
* **A peer is a peer.** Its answers are recorded as coming from that peer, with its
  name attached; nothing here verifies what a remote agent claims about itself
  beyond the transport succeeding. Treat a peer's reply as that peer's claim.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

DEFAULT_REGISTRY = "~/.zeno/agents.json"
#: How many peers are contacted at once. This bounds *this process's* fan-out, not
#: the number of peers: 500 registered agents still all get called, 16 at a time.
DEFAULT_CONCURRENCY = 16
DEFAULT_TIMEOUT = 20.0
MAX_REPLY_BYTES = 128 * 1024


@dataclass
class Peer:
    """One connected agent."""

    name: str
    endpoint: str
    capability: str = ""
    languages: List[str] = field(default_factory=list)
    description: str = ""
    added_at: float = field(default_factory=time.time)
    calls: int = 0
    failures: int = 0
    last_error: str = ""
    last_ms: float = 0.0

    def to_dict(self, *, redact: bool = True) -> Dict[str, Any]:
        payload = asdict(self)
        if redact:
            # The grant is a bearer secret: the owner's own view may show that one
            # exists, never what it is.
            payload["capability"] = "set" if self.capability else ""
        return payload


class AgentRegistry:
    """Connect, list, address and fan out to external agents."""

    def __init__(
        self,
        path: Optional[str] = None,
        *,
        boundary: Any = None,
        memory: Any = None,
        concurrency: int = DEFAULT_CONCURRENCY,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self.path = Path(os.path.expanduser(path or os.environ.get("ZENO_AGENTS_FILE") or DEFAULT_REGISTRY))
        self.boundary = boundary
        self.memory = memory
        self.concurrency = max(1, int(concurrency))
        self.timeout = float(timeout)
        self._peers: Dict[str, Peer] = {}
        self._load()

    # -- persistence -------------------------------------------------------
    def _load(self) -> None:
        if not self.path.is_file():
            return
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        for name, record in (payload.get("peers") or {}).items():
            try:
                self._peers[name] = Peer(**{**record, "name": name})
            except TypeError:
                continue

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "note": "capability grants are bearer secrets: this file is written 0600",
            "peers": {name: asdict(peer) for name, peer in self._peers.items()},
        }
        self.path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        try:
            os.chmod(self.path, 0o600)
        except OSError:  # pragma: no cover
            pass

    # -- the registry ------------------------------------------------------
    def register(
        self,
        name: str,
        endpoint: str,
        *,
        capability: str = "",
        languages: Sequence[str] = (),
        description: str = "",
    ) -> Dict[str, Any]:
        clean = "".join(character for character in (name or "") if character.isalnum() or character in "-_.")[:64]
        if not clean:
            raise ValueError("a peer needs a name of letters, digits, '-', '_' or '.'")
        if not endpoint.startswith(("http://", "https://")):
            raise ValueError("a peer endpoint must be an http(s) URL")
        peer = self._peers.get(clean) or Peer(name=clean, endpoint=endpoint)
        peer.endpoint = endpoint.rstrip("/")
        if capability:
            peer.capability = capability
        if languages:
            peer.languages = [str(item) for item in languages]
        if description:
            peer.description = description
        self._peers[clean] = peer
        self._save()
        return peer.to_dict()

    def unregister(self, name: str) -> bool:
        removed = self._peers.pop(name, None) is not None
        if removed:
            self._save()
        return removed

    def peers(self) -> List[Dict[str, Any]]:
        return [peer.to_dict() for peer in self._peers.values()]

    def get(self, name: str) -> Optional[Peer]:
        return self._peers.get(name)

    def describe(self) -> Dict[str, Any]:
        return {
            "path": str(self.path),
            "connected": len(self._peers),
            "concurrency": self.concurrency,
            "timeout_seconds": self.timeout,
            "limits": [
                "no maximum number of peers is imposed; concurrency and timeout are bounded",
                "a peer's reply is a claim made by that peer, not a verified fact",
                "the grant stored per peer is a bearer secret; the file is 0600",
            ],
        }

    # -- talking -----------------------------------------------------------
    def ask(
        self,
        name: str,
        text: str,
        *,
        lang: str = "en",
        session: str = "peers",
        caller: Any = None,
        material: Optional[Dict[str, Any]] = None,
        remember: bool = True,
        authorization: Any = None,
    ) -> Dict[str, Any]:
        """Ask one peer, through the boundary, and record what came back."""
        peer = self.get(name)
        if peer is None:
            return {"ok": False, "peer": name, "error": f"no connected agent named {name!r}"}
        if authorization is None:
            authorization = self._authorize(caller, name, text, material or {})
        if authorization is not None and not getattr(authorization, "allowed", False):
            return {
                "ok": False,
                "peer": name,
                "code": str(getattr(authorization, "code", "") or ""),
                "error": "refused by the authorization boundary: nothing was sent",
            }
        outcome = self._call(peer, text, lang=lang, session=session)
        if remember and self.memory is not None:
            self._remember(session, f"peer:{name}", text, lang, outcome)
        return outcome

    def broadcast(
        self,
        text: str,
        *,
        lang: str = "en",
        session: str = "peers",
        names: Optional[Sequence[str]] = None,
        caller: Any = None,
        material: Optional[Dict[str, Any]] = None,
        remember: bool = True,
        authorization: Any = None,
    ) -> Dict[str, Any]:
        """Ask every connected peer (or the ones named) at once.

        Every peer is asked; the answers are collected as they arrive. A peer that
        fails does not stop the others, and its failure is reported as its own
        result rather than folded into a single verdict.
        """
        if authorization is None:
            authorization = self._authorize(caller, "broadcast", text, material or {})
        if authorization is not None and not getattr(authorization, "allowed", False):
            return {
                "ok": False,
                "code": str(getattr(authorization, "code", "") or ""),
                "error": "refused by the authorization boundary: nothing was sent",
                "results": [],
            }
        targets = [self._peers[name] for name in names if name in self._peers] if names else list(self._peers.values())
        started = time.perf_counter()
        results: List[Dict[str, Any]] = []
        if targets:
            workers = min(self.concurrency, len(targets))
            with ThreadPoolExecutor(max_workers=workers) as pool:
                futures = {
                    pool.submit(self._call, peer, text, lang=lang, session=session): peer
                    for peer in targets
                }
                for future in futures:
                    results.append(future.result())
        answered = [item for item in results if item.get("ok")]
        summary = {
            "ok": bool(answered) or not targets,
            "asked": len(targets),
            "answered": len(answered),
            "failed": len(results) - len(answered),
            "lang": lang,
            "elapsed_ms": round((time.perf_counter() - started) * 1000.0, 2),
            "results": results,
        }
        if remember and self.memory is not None:
            self._remember(session, "broadcast", text, lang, summary)
        return summary

    # -- pieces ------------------------------------------------------------
    def _authorize(self, caller: Any, name: str, text: str, material: Dict[str, Any]) -> Any:
        if self.boundary is None:
            return None
        from aegis.boundary import Caller

        person = caller if caller is not None else Caller(actor="agent-bridge")
        return self.boundary.authorize(
            person, f"{name}:{text}".encode("utf-8"), material, action="agent:peer"
        )

    def _call(self, peer: Peer, text: str, *, lang: str, session: str) -> Dict[str, Any]:
        """One peer, one call. The peer's grant travels in the header, not the URL."""
        url = f"{peer.endpoint}/ask"
        request = urllib.request.Request(
            url,
            data=json.dumps({"text": text, "lang": lang, "from": session}).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "User-Agent": "zeno-agent-bridge/1",
                **({"Authorization": f"Zeno {peer.capability}"} if peer.capability else {}),
            },
            method="POST",
        )
        started = time.perf_counter()
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read(MAX_REPLY_BYTES + 1)
            if len(raw) > MAX_REPLY_BYTES:
                raise ValueError(f"reply exceeded {MAX_REPLY_BYTES} bytes")
            payload = json.loads(raw.decode("utf-8") or "{}")
            peer.calls += 1
            peer.last_ms = (time.perf_counter() - started) * 1000.0
            peer.last_error = ""
            return {
                "ok": True,
                "peer": peer.name,
                "lang": lang,
                "reply": payload.get("reply", payload.get("text", "")),
                "elapsed_ms": round(peer.last_ms, 2),
            }
        except urllib.error.HTTPError as error:
            reason = f"HTTP {error.code}"
        except Exception as error:  # noqa: BLE001 - the peer's failure is reported, not raised
            reason = f"{type(error).__name__}: {error}"
        peer.calls += 1
        peer.failures += 1
        peer.last_error = reason
        peer.last_ms = (time.perf_counter() - started) * 1000.0
        return {"ok": False, "peer": peer.name, "error": reason, "elapsed_ms": round(peer.last_ms, 2)}

    def _remember(self, session: str, role: str, text: str, lang: str, outcome: Dict[str, Any]) -> None:
        meta = {
            "kind": "peer",
            "ok": bool(outcome.get("ok")),
            "error": outcome.get("error", ""),
            "answered": outcome.get("answered"),
            "asked": outcome.get("asked"),
        }
        self.memory.record(session, kind="peer", role="user", text=text, lang=lang, meta=meta)
        reply = outcome.get("reply")
        if reply:
            self.memory.record(
                session, kind="peer", role=role, text=str(reply), lang=lang, meta=meta
            )
