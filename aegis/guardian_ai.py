"""Layer 5 — the guardian sentinel.

What this is: a deterministic, explainable behavioural anomaly detector over the
access ledger. It learns each actor's normal *statistics* (rates, hours, devices,
locations, failure ratios) with exponentially weighted updates, scores each new
observation against them, and emits one of three decisions **with the reasons
attached**:

``ALLOW``
    Nothing unusual. The observation is still recorded.
``CHALLENGE``
    Something deviates — require a fresh proof, a biometric re-read, or a second
    factor before the session continues.
``FREEZE``
    The session (and, if the caller chooses, the whole gateway) stops.

What this is not: a trained model, and not an LLM. There is no gradient descent,
no transformer, no self-modifying code. An LLM *can* be attached through
``auxiliary``, and it is deliberately constrained: its output can only *raise*
scrutiny, never lower it, because a single un-auditable model must never be the
thing that unlocks a system.

Honest limits, stated up front:

* Skewed baselines. A patient attacker who acts normally for weeks can shift the
  profile. :meth:`Sentinel.describe` reports how many observations each profile
  was built from; below ``minimum_history`` the sentinel stays conservative and
  says so.
* Statistics are not understanding. Impossible travel is real evidence; a novel
  action name is weak evidence. The weights in :data:`WEIGHTS` are a starting
  point to tune against your own traffic, not a validated model.
* Freezing is availability. See :mod:`aegis.blockchain_ledger` — a freeze any
  actor can trigger is a denial-of-service primitive, so every freeze records
  who asked and unmuting needs two distinct approvers.

    >>> sentinel = Sentinel()
    >>> sentinel.observe({"actor": "amara", "action": "access", "decision": "allow"}).decision
    'ALLOW'
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from .geo_hardware_lock import haversine_km

__all__ = ["Sentinel", "Decision", "ActorProfile", "WEIGHTS", "DecisionKind"]

DecisionKind = str  # "ALLOW" | "CHALLENGE" | "FREEZE"

#: Feature weights. Each contributes ``weight * normalised_deviation`` to the
#: score; anything above ``CHALLENGE_THRESHOLD`` is reviewed, above
#: ``FREEZE_THRESHOLD`` stops the session.
WEIGHTS: Dict[str, float] = {
    "failure_ratio": 1.4,
    "rate": 1.0,
    "impossible_travel": 2.0,
    "new_device": 0.8,
    "new_location": 0.6,
    "off_hours": 0.5,
    "novel_action": 0.4,
    "device_churn": 0.7,
    "replay_attempts": 1.6,
}

CHALLENGE_THRESHOLD = 0.5
FREEZE_THRESHOLD = 1.5

#: Speed above which two consecutive observations cannot be one traveller.
IMPOSSIBLE_TRAVEL_KMH = 950.0

#: Observations needed before a profile is trusted for anomaly scoring.
MINIMUM_HISTORY = 5


@dataclass
class ActorProfile:
    """Running statistics for one actor. Updated incrementally (EWMA)."""

    actor: str
    observations: int = 0
    denials: int = 0
    actions: Dict[str, int] = field(default_factory=dict)
    devices: Dict[str, int] = field(default_factory=dict)
    locations: Dict[str, int] = field(default_factory=dict)
    hours: Dict[int, int] = field(default_factory=dict)
    events_per_minute: float = 0.0
    failure_ratio: float = 0.0
    last_seen: float = 0.0
    last_event_at: float = 0.0
    last_location: Optional[Tuple[float, float]] = None
    replay_attempts: int = 0
    _device_changes: int = 0
    _previous_device: Optional[str] = None

    @property
    def warm(self) -> bool:
        return self.observations >= MINIMUM_HISTORY

    def to_dict(self) -> Dict[str, Any]:
        return {
            "actor": self.actor,
            "observations": self.observations,
            "denials": self.denials,
            "failure_ratio": round(self.failure_ratio, 3),
            "events_per_minute": round(self.events_per_minute, 3),
            "devices": len(self.devices),
            "locations": len(self.locations),
            "actions": sorted(self.actions),
            "replay_attempts": self.replay_attempts,
            "warm": self.warm,
        }


@dataclass
class Decision:
    """A sentinel verdict, with the evidence that produced it."""

    decision: DecisionKind
    score: float
    reasons: List[str] = field(default_factory=list)
    features: Dict[str, float] = field(default_factory=dict)
    advisory: List[str] = field(default_factory=list)
    profile: Optional[Dict[str, Any]] = None
    warm: bool = True
    at: float = field(default_factory=time.time)

    @property
    def blocked(self) -> bool:
        return self.decision == "FREEZE"

    @property
    def reviewed(self) -> bool:
        return self.decision in {"CHALLENGE", "FREEZE"}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision": self.decision,
            "score": round(self.score, 3),
            "reasons": list(self.reasons),
            "features": {name: round(value, 3) for name, value in self.features.items()},
            "advisory": list(self.advisory),
            "profile": self.profile,
            "profile_warm": self.warm,
            "at": self.at,
        }

    def render(self) -> str:
        lines = [f"sentinel      : {self.decision} (score {self.score:.2f})"]
        for reason in self.reasons:
            lines.append(f"  ! {reason}")
        for note in self.advisory:
            lines.append(f"  ~ {note}")
        if not self.warm:
            lines.append("  ~ profile has little history: conservative defaults in effect")
        return "\n".join(lines)


class Sentinel:
    """Behavioural anomaly detection over ledger observations."""

    def __init__(
        self,
        *,
        weights: Optional[Dict[str, float]] = None,
        challenge_threshold: float = CHALLENGE_THRESHOLD,
        freeze_threshold: float = FREEZE_THRESHOLD,
        decay: float = 0.2,
        max_events_per_minute: float = 30.0,
        auxiliary: Optional[Callable[[Dict[str, Any], ActorProfile], float]] = None,
    ) -> None:
        self.weights = dict(weights or WEIGHTS)
        self.challenge_threshold = challenge_threshold
        self.freeze_threshold = freeze_threshold
        self.decay = decay
        self.max_events_per_minute = max_events_per_minute
        self.auxiliary = auxiliary
        self.profiles: Dict[str, ActorProfile] = {}
        self.frozen: Dict[str, str] = {}
        self.freeze_log: List[Dict[str, Any]] = []
        self.decisions = 0
        self.escalations = 0

    # -- freeze control --------------------------------------------------
    def freeze(self, reason: str, *, actor: str = "", requested_by: str = "system") -> None:
        """Stop a session/actor. Records who asked, for the audit trail."""
        key = actor or "*"
        self.frozen[key] = reason
        self.freeze_log.append(
            {"at": time.time(), "actor": key, "reason": reason, "requested_by": requested_by}
        )

    def unfreeze(self, actor: str = "", *, approvers: Sequence[str]) -> None:
        """Two-person rule: unfreezing needs two *distinct* named approvers."""
        if len({name.strip().lower() for name in approvers if name.strip()}) < 2:
            raise PermissionError("unfreezing requires two distinct approvers")
        key = actor or "*"
        if key not in self.frozen:
            raise KeyError(f"{key!r} is not frozen")
        del self.frozen[key]
        self.freeze_log.append(
            {"at": time.time(), "actor": key, "reason": "unfrozen", "requested_by": ",".join(approvers)}
        )

    def is_frozen(self, actor: str) -> bool:
        return "*" in self.frozen or actor in self.frozen

    # -- observation -----------------------------------------------------
    def observe(self, observation: Dict[str, Any]) -> Decision:
        """Score one ledger entry and update the actor's profile."""
        actor = str(observation.get("actor") or "anonymous")
        profile = self.profiles.setdefault(actor, ActorProfile(actor=actor))
        features, reasons = self._extract(observation, profile)

        score = sum(self.weights.get(name, 0.0) * value for name, value in features.items())
        advisory: List[str] = []
        if self.auxiliary is not None:
            try:
                extra, note = self._advisory(observation, profile)
                if extra > 0:
                    # Monotonic by construction: an auxiliary model can only add
                    # scrutiny, never subtract it.
                    score += extra
                    advisory.append(note)
            except Exception as exc:  # noqa: BLE001 - never let the hook break the gate
                advisory.append(f"auxiliary scorer unavailable ({type(exc).__name__}); ignored")

        self._update(observation, profile)

        if self.is_frozen(actor):
            return Decision(
                "FREEZE", max(score, self.freeze_threshold), reasons + [f"frozen: {self.frozen.get(actor) or self.frozen['*']}"],
                features, advisory, profile.to_dict(), profile.warm,
            )

        if score >= self.freeze_threshold:
            kind: DecisionKind = "FREEZE"
            self.escalations += 1
        elif score >= self.challenge_threshold:
            kind = "CHALLENGE"
            self.escalations += 1
        else:
            kind = "ALLOW"
        self.decisions += 1

        if not profile.warm and kind != "ALLOW":
            reasons.append(
                f"only {profile.observations} observations for this actor so far "
                f"(below the {MINIMUM_HISTORY} needed for a stable baseline)"
            )

        return Decision(kind, score, reasons, features, advisory, profile.to_dict(), profile.warm)

    # -- features --------------------------------------------------------
    def _extract(self, observation: Dict[str, Any], profile: ActorProfile) -> Tuple[Dict[str, float], List[str]]:
        features: Dict[str, float] = {}
        reasons: List[str] = []

        metadata = dict(observation.get("metadata") or {})
        denied = str(observation.get("decision", "")).lower() in {"deny", "denied", "block", "blocked"}

        # 1. failure ratio, including this observation
        observations = profile.observations + 1
        denials = profile.denials + (1 if denied else 0)
        ratio = denials / observations
        if ratio > 0.34:
            features["failure_ratio"] = min(2.0, (ratio - 0.34) / 0.33)
            reasons.append(f"{denials}/{observations} observations were refused")

        # 2. rate vs the actor's own norm
        now = float(observation.get("timestamp") or time.time())
        if profile.last_event_at:
            gap = max(1e-3, (now - profile.last_event_at) / 60.0)
            rate = 1.0 / gap
            baseline = profile.events_per_minute or rate
            if rate > max(baseline * 3, 3.0):
                features["rate"] = min(2.0, rate / max(baseline * 3, 3.0))
                reasons.append(f"{rate:.1f} events/min against a {baseline:.1f}/min baseline")
        if profile.events_per_minute > self.max_events_per_minute:
            features["rate"] = max(features.get("rate", 0.0), 1.0)
            reasons.append(f"sustained rate {profile.events_per_minute:.1f}/min above the ceiling")

        # 3. impossible travel between consecutive declared locations
        location = self._location_of(metadata)
        if location and profile.last_location and profile.last_event_at:
            distance = haversine_km(*profile.last_location, *location)
            minutes = max(1e-3, (now - profile.last_event_at) / 60.0)
            speed = distance / (minutes / 60.0)
            if distance > 25 and speed > IMPOSSIBLE_TRAVEL_KMH:
                features["impossible_travel"] = min(2.0, speed / IMPOSSIBLE_TRAVEL_KMH)
                reasons.append(
                    f"{distance:.0f} km in {minutes:.0f} min ({speed:.0f} km/h) is not travel"
                )
            elif location not in profile.locations:
                # New but not impossible: informational, weakly weighted.
                if profile.locations:
                    features["new_location"] = 0.5
                    reasons.append("first activity from this group of coordinates")

        # 4. unseen device for a warm profile
        device = str(metadata.get("device") or "")
        if device:
            if profile.devices and device not in profile.devices and profile.warm:
                features["new_device"] = 1.0
                reasons.append(f"device {device[:12]} has not been used by {profile.actor} before")
            previous = profile._previous_device
            if previous and previous != device:
                features["device_churn"] = 1.0
                reasons.append("device changed since the previous observation")

        # 5. off-hours: the actor's own clock, not a global assumption
        hour = int(metadata.get("hour", time.gmtime(now).tm_hour))
        if profile.hours and hour not in profile.hours and profile.warm:
            features["off_hours"] = 1.0
            reasons.append(f"{hour:02d}:00 is outside this actor's usual hours")

        # 6. action never seen from this actor
        action = str(observation.get("action") or "")
        if action and profile.actions and action not in profile.actions and profile.warm:
            features["novel_action"] = 1.0
            reasons.append(f"first time {profile.actor} has performed {action!r}")

        # 7. replay attempts reported by the ZKP layer
        replays = float(metadata.get("replay_attempts") or 0)
        if replays:
            features["replay_attempts"] = min(2.0, replays)
            reasons.append(f"{int(replays)} rejected proof replays")

        return features, reasons

    def _advisory(self, observation: Dict[str, Any], profile: ActorProfile) -> Tuple[float, str]:
        """Run the auxiliary scorer and normalise its output to ``[0, 2]``."""
        raw = self.auxiliary(observation, profile) if self.auxiliary else 0.0
        try:
            value = float(raw)
        except (TypeError, ValueError):
            return 0.0, "auxiliary scorer returned a non-number; ignored"
        value = max(0.0, min(2.0, value))
        if value <= 0:
            return 0.0, "auxiliary scorer raised no concern"
        return value, f"auxiliary scorer added {value:.2f} to the score (advisory, escalate-only)"

    @staticmethod
    def _location_of(metadata: Dict[str, Any]) -> Optional[Tuple[float, float]]:
        latitude = metadata.get("latitude", metadata.get("lat"))
        longitude = metadata.get("longitude", metadata.get("lon", metadata.get("lng")))
        if latitude is None or longitude is None:
            return None
        try:
            return float(latitude), float(longitude)
        except (TypeError, ValueError):
            return None

    # -- learning (statistics, not gradient descent) ---------------------
    def _update(self, observation: Dict[str, Any], profile: ActorProfile) -> None:
        now = float(observation.get("timestamp") or time.time())
        denied = str(observation.get("decision", "")).lower() in {"deny", "denied", "block", "blocked"}
        metadata = dict(observation.get("metadata") or {})

        profile.observations += 1
        profile.denials += 1 if denied else 0
        decay = self.decay
        profile.failure_ratio = (1 - decay) * profile.failure_ratio + decay * (1.0 if denied else 0.0)

        if profile.last_event_at:
            gap_minutes = max(1e-3, (now - profile.last_event_at) / 60.0)
            instant = 1.0 / gap_minutes
            profile.events_per_minute = (1 - decay) * profile.events_per_minute + decay * instant
        profile.last_event_at = now
        profile.last_seen = now

        action = str(observation.get("action") or "")
        if action:
            profile.actions[action] = profile.actions.get(action, 0) + 1

        device = str(metadata.get("device") or "")
        if device:
            if profile._previous_device and profile._previous_device != device:
                profile._device_changes += 1
            profile._previous_device = device
            profile.devices[device] = profile.devices.get(device, 0) + 1

        location = self._location_of(metadata)
        if location:
            key = f"{location[0]:.1f},{location[1]:.1f}"
            profile.locations[key] = profile.locations.get(key, 0) + 1
            profile.last_location = location

        hour = int(metadata.get("hour", time.gmtime(now).tm_hour))
        profile.hours[hour] = profile.hours.get(hour, 0) + 1
        profile.replay_attempts += int(float(metadata.get("replay_attempts") or 0))

    # -- introspection ---------------------------------------------------
    def describe(self) -> Dict[str, Any]:
        return {
            "layer": "guardian-sentinel",
            "method": "deterministic behavioural statistics (EWMA profile + weighted deviations)",
            "trained_model": False,
            "llm_used": False,
            "llm_role": "optional auxiliary scorer, escalate-only",
            "weights": dict(self.weights),
            "thresholds": {
                "challenge": self.challenge_threshold,
                "freeze": self.freeze_threshold,
                "impossible_travel_kmh": IMPOSSIBLE_TRAVEL_KMH,
            },
            "profiles": len(self.profiles),
            "decisions": self.decisions,
            "escalations": self.escalations,
            "frozen": dict(self.frozen),
            "limits": [
                "a patient attacker can shift a baseline over time",
                "novel action names are weak evidence; impossible travel is strong evidence",
                "freezing is an availability trade-off, not a free win",
            ],
        }
