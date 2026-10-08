"""The watchtower: what happens *after* a refusal.

You asked for a system where a hacker's attempts come to you and where they keep
going in circles without ever getting out. This module is that, built with the
part that is actually achievable and without the part that is not:

**What it really does**

1. **Captures every refused attempt** — time, source, user agent, claimed actor,
   path, a digest of the body, the refusal code, and a fingerprint of the client.
   Secrets are never stored verbatim: tokens, cookies and authorization headers
   are hashed, and the raw body is never written to disk.
2. **Counts strikes per source** and, past a threshold, classifies the source as
   an intruder and raises an **alert to the owner**: a JSONL feed at
   ``~/.zeno/watchtower.jsonl``, an owner-readable summary, an entry in the audit
   ledger, and optionally a webhook (``ZENO_WATCHTOWER_WEBHOOK``).
3. **Wastes their time** — a bounded tarpit: every refused attempt from a flagged
   source is delayed, up to a hard ceiling. Bounded matters: an unbounded tarpit
   is a denial-of-service against *us*, so there is a per-request ceiling, a cap
   on how many requests may be sleeping at once, and authorized traffic is never
   delayed at all.
4. **Feeds them decoys** — once a source is flagged, refusals turn into
   plausible-looking fake results. The attacker sees something that looks like
   success and stays engaged, while the owner watches and the kernel is never
   touched. Decoys are *generated*, never sampled from real output, and only in
   strict (production) mode; in development the server keeps answering honestly,
   because a developer needs to know what actually happened.

**What it does not do, and will not claim**

* It cannot make a system impossible to escape. Nothing can. A tarpit delays; an
  attacker with unlimited patience, a fresh source IP per request, or your keys
  walks past all of it.
* Decoys are not a defence. They are a detection and delay tool. A determined
  attacker who fingerprints the decoy learns that they are being watched — which
  is fine, because the owner already knows about them by then.
* It is not a WAF, and IP-based flagging is weak by design: shared addresses
  (corporate NAT, Tor exits, cloud egress) can be flagged wrongly. That is why
  flagging only ever *delays and observes*, never blocks a legitimate principal,
  and why the owner's feed says exactly why each source was flagged.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import threading
import time
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Deque, Dict, List, Mapping, Optional, Sequence

__all__ = ["IntrusionRecord", "Reaction", "Watchtower", "DEFAULT_FEED"]

DEFAULT_FEED = "~/.zeno/watchtower.jsonl"

#: Headers whose values are evidence, not data: stored as digests only.
_SENSITIVE_HEADERS = ("authorization", "cookie", "set-cookie", "x-api-key", "proxy-authorization")


def digest(value: str | bytes) -> str:
    """A short, stable digest. What we store instead of the thing itself."""
    data = value.encode("utf-8", "replace") if isinstance(value, str) else value
    return hashlib.sha256(data).hexdigest()[:24]


@dataclass
class IntrusionRecord:
    """One refused attempt, as the owner will see it."""

    at: float
    remote: str
    method: str
    path: str
    actor_claimed: str
    user_agent: str
    code: str
    payload_digest: str
    body_bytes: int
    header_digests: Dict[str, str] = field(default_factory=dict)
    client_fingerprint: str = ""
    strike: int = 1
    verdict: str = "refused"
    tarpit_ms: int = 0
    decoy_served: bool = False
    note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        out = asdict(self)
        out["at_iso"] = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(self.at))
        return out

    def to_jsonl(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


@dataclass
class Reaction:
    """What the server should do about this attempt, beyond saying no."""

    tarpit_ms: int = 0
    decoy: bool = False
    alert: bool = False
    strike: int = 1
    verdict: str = "refused"
    note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class Watchtower:
    """Observes refusals, remembers sources, and decides how to answer them."""

    def __init__(
        self,
        *,
        feed: Optional[str] = None,
        alert_threshold: int = 3,
        tarpit_base_ms: int = 250,
        tarpit_max_ms: int = 8000,
        max_sleeping: int = 8,
        max_sources: int = 4096,
        decoys: bool = True,
        ledger: Any = None,
        webhook: Optional[str] = None,
        clock: Optional[Any] = None,
    ) -> None:
        self.feed_path = Path(os.path.expanduser(feed or os.environ.get("ZENO_WATCHTOWER_FEED") or DEFAULT_FEED))
        self.alert_threshold = max(1, int(alert_threshold))
        self.tarpit_base_ms = max(0, int(tarpit_base_ms))
        self.tarpit_max_ms = max(self.tarpit_base_ms, int(tarpit_max_ms))
        #: Hard ceiling on how many requests may be delayed at once. Without it a
        #: tarpit is a denial-of-service against the host running it.
        self.max_sleeping = max(0, int(max_sleeping))
        self.max_sources = max(8, int(max_sources))
        self.decoys = bool(decoys)
        self.ledger = ledger
        #: Optional webhook for alerts. Absent by default: no silent egress.
        self.webhook = webhook or os.environ.get("ZENO_WATCHTOWER_WEBHOOK") or ""
        self.clock = clock or time.time
        self._lock = threading.Lock()
        self._strikes: Dict[str, int] = defaultdict(int)
        self._first_seen: Dict[str, float] = {}
        self._last_seen: Dict[str, float] = {}
        self._agents: Dict[str, str] = {}
        self._intruders: Dict[str, str] = {}
        self._alerts: Deque[Dict[str, Any]] = deque(maxlen=200)
        self._recent: Deque[IntrusionRecord] = deque(maxlen=500)
        self._sleeping = 0
        self.records = 0
        self.decoys_served = 0
        self.tarpit_ms_total = 0

    # -- recording ---------------------------------------------------------
    def observe(
        self,
        *,
        remote: str,
        method: str,
        path: str,
        actor_claimed: str = "",
        user_agent: str = "",
        code: str = "",
        body: bytes = b"",
        headers: Optional[Mapping[str, str]] = None,
        note: str = "",
    ) -> "tuple[IntrusionRecord, Reaction]":
        """Record one refused attempt and decide the reaction.

        Called only for refusals. An authorized request never reaches this, which
        is what keeps the tarpit from touching legitimate traffic.
        """
        source = remote or "unknown"
        header_digests = {
            name: digest(value)
            for name, value in (headers or {}).items()
            if name.lower() in _SENSITIVE_HEADERS
        }
        agent = (user_agent or "")[:200]
        fingerprint = digest(f"{agent}|{source}|{','.join(sorted(header_digests))}")

        with self._lock:
            strike = self._strikes[source] + 1
            self._strikes[source] = strike
            self._first_seen.setdefault(source, self.clock())
            self._last_seen[source] = self.clock()
            self._agents[source] = agent
            flagged = strike >= self.alert_threshold
            if flagged:
                self._intruders.setdefault(source, fingerprint)
            self._trim()

        tarpit_ms = self._tarpit_for(strike, flagged)
        alert = flagged and strike == self.alert_threshold
        record = IntrusionRecord(
            at=self.clock(),
            remote=source,
            method=method,
            path=path,
            actor_claimed=actor_claimed,
            user_agent=agent,
            code=code,
            payload_digest=digest(body) if body else "",
            body_bytes=len(body or b""),
            header_digests=header_digests,
            client_fingerprint=fingerprint,
            strike=strike,
            verdict="intruder" if flagged else "refused",
            tarpit_ms=tarpit_ms,
            decoy_served=False,
            note=note,
        )
        self.records += 1
        with self._lock:
            self._recent.appendleft(record)

        if alert:
            self._raise_alert(source, strike, fingerprint, agent)
        reaction = Reaction(
            tarpit_ms=tarpit_ms,
            decoy=flagged and self.decoys,
            alert=alert,
            strike=strike,
            verdict=record.verdict,
            note=note,
        )
        record.decoy_served = reaction.decoy
        self.write(record)
        return record, reaction

    def _trim(self) -> None:
        """Forget the quietest sources rather than growing without bound."""
        if len(self._strikes) <= self.max_sources:
            return
        cutoff = self.clock() - 3600.0
        stale = [source for source, seen in self._last_seen.items() if seen < cutoff]
        for source in stale[: max(1, len(stale) // 2)]:
            self._strikes.pop(source, None)
            self._last_seen.pop(source, None)
            self._agents.pop(source, None)

    def _tarpit_for(self, strike: int, flagged: bool) -> int:
        """A bounded, escalating delay. Never above the ceiling, never unbounded."""
        if not flagged or self.tarpit_max_ms == 0:
            return 0
        steps = min(4, strike - self.alert_threshold + 1)
        delay = self.tarpit_base_ms * (2**steps)
        return int(min(delay, self.tarpit_max_ms))

    # -- tarpit execution --------------------------------------------------
    def apply_tarpit(self, milliseconds: int) -> int:
        """Sleep, if there is a concurrency slot. Returns the milliseconds slept.

        The cap is the point: a tarpit that accepts unbounded sleeping requests
        exhausts the host's threads, which is the attacker's goal, not ours.
        """
        if milliseconds <= 0:
            return 0
        with self._lock:
            if self._sleeping >= self.max_sleeping:
                return 0
            self._sleeping += 1
        try:
            time.sleep(milliseconds / 1000.0)
            self.tarpit_ms_total += milliseconds
            return milliseconds
        finally:
            with self._lock:
                self._sleeping -= 1

    # -- decoys ------------------------------------------------------------
    def decoy(self, *, path: str, payload: str = "") -> Dict[str, Any]:
        """A plausible-looking fake result, generated — never sampled from real data.

        Values are fabricated from a per-call nonce. The shape mirrors the real
        API closely enough to be worth the attacker's time, and it contains
        nothing that came from this deployment: no real tools, no real state, no
        real results. If you are reading this because you *believed* a decoy, the
        deployment you hit was not yours to use.
        """
        nonce = secrets.token_hex(6)
        self.decoys_served += 1
        if path.endswith("/api/ask"):
            return {
                "payload": f"!RET[state=FAKE, id={nonce}]",
                "response": f"Completed. (marker {nonce})",
                "execution": {"output": {"ok": True, "nonce": nonce}, "steps": [], "calls": []},
                "aegis": {"allowed": True, "enforcement": "production", "decision_id": nonce},
                "decoy": True,
            }
        return {
            "frame": f"!RET[ok=true, nonce={nonce}]",
            "output": {"ok": True, "nonce": nonce},
            "bindings": {},
            "steps": [],
            "calls": [],
            "state": {},
            "returned": True,
            "errors": [],
            "aegis": {"allowed": True, "enforcement": "production", "decision_id": nonce},
            "decoy": True,
        }

    # -- owner-facing ------------------------------------------------------
    def _raise_alert(self, source: str, strike: int, fingerprint: str, agent: str) -> None:
        alert = {
            "at": self.clock(),
            "at_iso": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(self.clock())),
            "source": source,
            "strike": strike,
            "client_fingerprint": fingerprint,
            "user_agent": agent,
            "message": (
                f"{source} reached {strike} refused attempts; tarpit and decoys are now active "
                "for this source"
            ),
        }
        with self._lock:
            self._alerts.appendleft(alert)
        if self.ledger is not None:
            try:
                self.ledger.record(
                    actor=source,
                    action="intrusion.alert",
                    subject=fingerprint,
                    decision="deny",
                    layer="watchtower",
                    reason=alert["message"],
                    metadata={"source": source, "strike": strike, "fingerprint": fingerprint},
                )
            except Exception:  # noqa: BLE001 - the feed is the primary record
                pass
        if self.webhook:
            self._post(alert)

    def _post(self, alert: Mapping[str, Any]) -> None:
        """Best-effort webhook. Failure is recorded, never raised into a request."""
        import urllib.request

        try:
            request = urllib.request.Request(
                self.webhook,
                data=json.dumps(dict(alert)).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(request, timeout=3).close()
            alert_note = "webhook delivered"
        except Exception as error:  # noqa: BLE001
            alert_note = f"webhook failed: {type(error).__name__}"
        with self._lock:
            if self._alerts:
                self._alerts[0]["webhook"] = alert_note

    def write(self, record: IntrusionRecord) -> None:
        """Append one record to the owner's feed. Never fails a request."""
        try:
            self.feed_path.parent.mkdir(parents=True, exist_ok=True)
            with self.feed_path.open("a", encoding="utf-8") as handle:
                handle.write(record.to_jsonl() + "\n")
        except Exception:  # noqa: BLE001 - a full disk must not take the server down
            pass

    def alerts(self, limit: int = 20) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._alerts)[:limit]

    def intruders(self) -> Dict[str, Dict[str, Any]]:
        with self._lock:
            return {
                source: {
                    "strikes": self._strikes.get(source, 0),
                    "first_seen": self._first_seen.get(source, 0.0),
                    "last_seen": self._last_seen.get(source, 0.0),
                    "user_agent": self._agents.get(source, ""),
                    "client_fingerprint": fingerprint,
                }
                for source, fingerprint in self._intruders.items()
            }

    def recent(self, limit: int = 20) -> List[Dict[str, Any]]:
        with self._lock:
            return [record.to_dict() for record in list(self._recent)[:limit]]

    def summary(self) -> Dict[str, Any]:
        with self._lock:
            strikes = sorted(self._strikes.items(), key=lambda item: item[1], reverse=True)[:5]
        return {
            "enabled": True,
            "feed": str(self.feed_path),
            "records": self.records,
            "sources_seen": len(self._strikes),
            "intruders": len(self._intruders),
            "alerts": len(self._alerts),
            "decoys_served": self.decoys_served,
            "tarpit_ms_total": self.tarpit_ms_total,
            "tarpit": {
                "base_ms": self.tarpit_base_ms,
                "max_ms": self.tarpit_max_ms,
                "max_sleeping": self.max_sleeping,
                "sleeping": self._sleeping,
            },
            "thresholds": {"alert_after_strikes": self.alert_threshold},
            "top_sources": [{"source": source, "strikes": count} for source, count in strikes],
            "webhook": "configured" if self.webhook else "none",
            "limits": [
                "a tarpit delays, it does not stop",
                "decoy results are fabricated: no real data is ever served to an attacker",
                "legitimate traffic is never delayed — only refusals are",
                "IP flagging can catch shared addresses (NAT, Tor exits, cloud egress)",
                "the feed stores digests, never tokens, cookies or request bodies",
            ],
        }

    def clear(self) -> int:
        """Owner-side: forget the current source statistics (the feed file stays)."""
        with self._lock:
            count = len(self._strikes)
            self._strikes.clear()
            self._intruders.clear()
            self._alerts.clear()
            self._first_seen.clear()
            self._last_seen.clear()
            self._agents.clear()
            self._recent.clear()
        return count

    @property
    def decoys_enabled(self) -> bool:
        """Whether a flagged source is deceived, as opposed to merely delayed."""
        return bool(self.decoys)

    def read_feed(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Read the tail of the on-disk feed, oldest-first."""
        try:
            lines = self.feed_path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return []
        out: List[Dict[str, Any]] = []
        for line in lines[-limit:]:
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
        return out


def _self_check() -> int:  # pragma: no cover - convenience entry point
    tower = Watchtower(feed="/tmp/watchtower-selfcheck.jsonl", decoys=True)
    for attempt in range(1, 5):
        record, reaction = tower.observe(
            remote="203.0.113.7",
            method="POST",
            path="/api/run",
            actor_claimed="anonymous",
            user_agent="curl/8",
            code="ZN-SEC-0x3A01",
            body=b'{"payload":"?WX"}',
        )
        print(
            f"strike {reaction.strike}: tarpit={reaction.tarpit_ms}ms "
            f"decoy={reaction.decoy} alert={reaction.alert} verdict={reaction.verdict}"
        )
    print(json.dumps(tower.summary(), indent=2))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_self_check())
