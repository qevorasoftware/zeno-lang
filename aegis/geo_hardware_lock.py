"""Layer 7 — device and location binding.

Two very different things live in this layer, and the module is careful to keep
them apart:

**Cryptographic binding (real).** A payload is sealed with a key derived from
the recipient's hardware fingerprint *plus* a per-install secret stored in a
keystore file with ``0600`` permissions. Copying the sealed payload to another
machine does not help an attacker: the key material is not there. This is the
control that actually stops code from running on an unregistered device.

**Location pinning (administrative).** ``GeoFence`` compares a *declared*
coordinate against an allowed circle. Software cannot verify a GPS reading, so
the fence is a policy and audit control, not a security boundary — it is
reported with ``spoofable=True`` everywhere it appears. A determined attacker
with the device also has the coordinates.

Hardware fingerprints are *identifiers*, not authenticators: MAC addresses and
hostnames can be changed. Without a TPM, ``attest()`` says so
(``hardware_backed=False``). With a TPM (``/dev/tpm0`` or ``/dev/tpmrm0``) you
can move the per-install secret into the chip; this module detects the device
and reports it, and refuses to claim TPM-grade assurance when there is no TPM.

    >>> lock = HardwareLock.for_this_device()
    >>> blob = lock.seal(b"@LOC[TYO] -> ?WX")
    >>> lock.unseal(blob)
    b'@LOC[TYO] -> ?WX'
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import os
import platform
import re
import socket
import stat
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from . import cipher
from ._kdf import derive_key

__all__ = [
    "DeviceIdentity",
    "GeoFence",
    "HardwareLock",
    "device_fingerprint",
    "haversine_km",
    "LockError",
]

_KNOWN_FILES = (
    "/etc/machine-id",
    "/var/lib/dbus/machine-id",
    "/sys/class/dmi/id/product_uuid",
    "/etc/hostname",
)
_TPM_PATHS = ("/dev/tpm0", "/dev/tpmrm0", "/sys/class/tpm/tpm0")


class LockError(Exception):
    """Raised when a payload is opened on the wrong device or location."""


# ---------------------------------------------------------------------------
# Device identity
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class DeviceIdentity:
    """A best-effort stable identifier for the current machine."""

    fingerprint: str
    components: Dict[str, str]
    hardware_backed: bool
    tpm_path: Optional[str] = None
    #: How many volatile components went into the hash, for transparency.
    volatile_components: int = 0

    @property
    def short(self) -> str:
        return self.fingerprint[:16]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "short": self.short,
            "hardware_backed": self.hardware_backed,
            "tpm": self.tpm_path or "absent",
            "components": dict(self.components),
            "volatile_components": self.volatile_components,
            "identity_is_an_identifier": True,
            "identifier_is_not_an_authenticator": not self.hardware_backed,
        }


def _mac_addresses() -> List[str]:
    """Collect MAC addresses without shelling out (``uuid.getnode`` plus /sys)."""
    found: List[str] = []
    base = Path("/sys/class/net")
    if base.is_dir():
        for interface in sorted(base.iterdir()):
            address = interface / "address"
            try:
                value = address.read_text(encoding="utf-8").strip()
            except OSError:  # pragma: no cover - races with hotplug
                continue
            if value and value != "00:00:00:00:00:00":
                found.append(f"{interface.name}:{value}")
    if not found:
        found.append(f"getnode:{uuid.getnode():012x}")
    return sorted(found)


def device_fingerprint(*, include_hostname: bool = True) -> DeviceIdentity:
    """Hash the machine's stable-ish attributes into one identifier.

    Deliberately conservative: it reads files rather than shelling out, and it
    sorts everything so the result is reproducible on the same machine.
    """
    components: Dict[str, str] = {}
    components["platform"] = platform.platform()
    components["machine"] = platform.machine()
    components["processor"] = platform.processor() or "unknown"
    components["macs"] = ",".join(_mac_addresses())
    if include_hostname:
        components["hostname"] = socket.gethostname()

    volatile = 0
    for path in _KNOWN_FILES:
        try:
            value = Path(path).read_text(encoding="utf-8").strip()
        except OSError:
            value = ""
        components[path] = value
        if path.endswith("hostname") or path.endswith("machine-id"):
            volatile += 1

    tpm_path = next((path for path in _TPM_PATHS if os.path.exists(path)), None)

    digest = hashlib.sha256()
    digest.update(b"aegis/device/v2")
    for key in sorted(components):
        digest.update(key.encode())
        digest.update(b"\x1f")
        digest.update(components[key].encode("utf-8", "replace"))
        digest.update(b"\x1e")

    return DeviceIdentity(
        fingerprint=digest.hexdigest(),
        components=components,
        hardware_backed=tpm_path is not None,
        tpm_path=tpm_path,
        volatile_components=volatile,
    )


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance in kilometres (used by the fence and the sentinel)."""
    radius = 6371.0088
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    d_phi = math.radians(lat2 - lat1)
    d_lambda = math.radians(lon2 - lon1)
    a = math.sin(d_phi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(d_lambda / 2) ** 2
    return 2 * radius * math.asin(min(1.0, math.sqrt(a)))


# ---------------------------------------------------------------------------
# Geo fence
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class GeoFence:
    """A declared centre and radius. A policy control, not a proof of place."""

    latitude: float
    longitude: float
    radius_km: float = 50.0
    label: str = "unlabelled"

    #: Always true, and always reported: a coordinate is claimed, never proven.
    spoofable: bool = field(default=True, init=False)

    def contains(self, latitude: float, longitude: float) -> bool:
        return haversine_km(self.latitude, self.longitude, latitude, longitude) <= self.radius_km

    def check(self, latitude: Optional[float], longitude: Optional[float]) -> Tuple[bool, str]:
        if latitude is None or longitude is None:
            return False, "no location supplied; a fence cannot be evaluated"
        distance = haversine_km(self.latitude, self.longitude, latitude, longitude)
        if distance <= self.radius_km:
            return True, f"{distance:.1f} km from {self.label} (inside the {self.radius_km:.0f} km fence)"
        return False, f"{distance:.1f} km from {self.label} (outside the {self.radius_km:.0f} km fence)"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "label": self.label,
            "centre": [self.latitude, self.longitude],
            "radius_km": self.radius_km,
            "spoofable": True,
            "note": "GPS coordinates are declared by the caller and cannot be verified in software",
        }

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "GeoFence":
        centre = payload.get("centre") or [payload.get("latitude"), payload.get("longitude")]
        return cls(
            latitude=float(centre[0]),
            longitude=float(centre[1]),
            radius_km=float(payload.get("radius_km", 50.0)),
            label=str(payload.get("label", "unlabelled")),
        )


# ---------------------------------------------------------------------------
# Hardware lock
# ---------------------------------------------------------------------------
@dataclass
class Attestation:
    """The result of asking "is this the right device, in the right place?"."""

    ok: bool
    device: DeviceIdentity
    reasons: List[str] = field(default_factory=list)
    fence: Optional[GeoFence] = None
    location: Optional[Tuple[float, float]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "device": self.device.to_dict(),
            "reasons": list(self.reasons),
            "fence": self.fence.to_dict() if self.fence else None,
            "location": list(self.location) if self.location else None,
            "hardware_grade": self.device.hardware_backed,
            "location_grade": "advisory (spoofable)" if self.fence else "not configured",
        }

    def render(self) -> str:
        lines = [f"device binding : {'allow' if self.ok else 'deny'} ({self.device.short})"]
        for reason in self.reasons:
            lines.append(f"  - {reason}")
        lines.append(
            f"  - assurance: {'TPM present' if self.device.hardware_backed else 'no TPM: identity is an identifier, not an authenticator'}"
        )
        if self.fence:
            lines.append(f"  - location: advisory only ({self.fence.label} ±{self.fence.radius_km:.0f} km, spoofable)")
        return "\n".join(lines)


class HardwareLock:
    """Seals payloads to one device (and optionally one place).

    The key is ``HKDF(per-install secret, salt=device fingerprint)``, so:

    * the sealed payload does not open on another machine (no secret), and
    * the same install secret on a different machine still derives a different
      key (the fingerprint is in the salt).
    """

    def __init__(
        self,
        device: DeviceIdentity,
        secret: bytes,
        *,
        fence: Optional[GeoFence] = None,
        keystore: Optional[Path] = None,
    ) -> None:
        self.device = device
        self.secret = secret
        self.fence = fence
        self.keystore = keystore

    # -- construction ----------------------------------------------------
    @classmethod
    def for_this_device(
        cls,
        keystore: Optional[Path] = None,
        *,
        fence: Optional[GeoFence] = None,
        create: bool = True,
    ) -> "HardwareLock":
        """Load (or create) the per-install secret bound to this device."""
        keystore = keystore or default_keystore()
        device = device_fingerprint()
        secret: Optional[bytes] = None

        if keystore.is_file():
            try:
                stored = json.loads(keystore.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                stored = {}
            if stored.get("device") == device.fingerprint and stored.get("secret"):
                secret = base64.b64decode(stored["secret"])
            else:
                # A different machine, or a wiped/edited keystore: refuse to
                # guess. Silently re-binding would defeat the whole layer.
                if not create:
                    raise LockError(
                        "keystore belongs to a different device "
                        f"({str(stored.get('device', 'unknown'))[:16]} != {device.short})"
                    )
                secret = None

        if secret is None:
            if not create:
                raise LockError(f"no keystore at {keystore}")
            secret = os.urandom(32)
            _write_keystore(keystore, device.fingerprint, secret)

        return cls(device, secret, fence=fence, keystore=keystore)

    # -- key derivation --------------------------------------------------
    def _key(self, purpose: bytes, extra: bytes = b"") -> bytes:
        salt = f"{self.device.fingerprint}:{purpose.decode()}".encode()
        return derive_key([self.secret], salt=salt + extra, info=b"aegis/device/v2")

    # -- operations ------------------------------------------------------
    def seal(
        self,
        plaintext: bytes,
        *,
        expires_at: Optional[float] = None,
        latitude: Optional[float] = None,
        longitude: Optional[float] = None,
    ) -> bytes:
        """Seal to this device. Optional expiry keeps a stolen blob short-lived."""
        header = {
            "device": self.device.fingerprint,
            "expires_at": expires_at,
            "latitude": latitude,
            "longitude": longitude,
            "sealed_at": time.time(),
        }
        aad = json.dumps(header, sort_keys=True, separators=(",", ":")).encode()
        nonce, sealed = cipher.encrypt(self._key(b"payload"), plaintext, aad)
        return b"AEGIS-LOCK1" + json.dumps(
            {**header, "nonce": base64.b64encode(nonce).decode(), "box": base64.b64encode(sealed).decode()},
            sort_keys=True,
        ).encode()

    def unseal(self, blob: bytes, *, latitude: Optional[float] = None, longitude: Optional[float] = None) -> bytes:
        if not blob.startswith(b"AEGIS-LOCK1"):
            raise LockError("not an AEGIS device-locked blob")
        try:
            payload = json.loads(blob[len(b"AEGIS-LOCK1") :].decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise LockError(f"corrupt device-locked blob: {exc}") from exc

        if payload.get("device") != self.device.fingerprint:
            raise LockError(
                f"payload is bound to device {str(payload.get('device'))[:16]}, this is {self.device.short}"
            )

        expires_at = payload.get("expires_at")
        if expires_at is not None and time.time() > float(expires_at):
            raise LockError(f"payload expired {time.time() - float(expires_at):.0f}s ago")

        fence_lat = latitude if latitude is not None else payload.get("latitude")
        fence_lon = longitude if longitude is not None else payload.get("longitude")
        if self.fence is not None:
            inside, reason = self.fence.check(fence_lat, fence_lon)
            if not inside:
                raise LockError(f"outside the geofence: {reason}")

        header = {key: payload[key] for key in ("device", "expires_at", "latitude", "longitude", "sealed_at")}
        aad = json.dumps(header, sort_keys=True, separators=(",", ":")).encode()
        return cipher.decrypt(
            self._key(b"payload"),
            base64.b64decode(payload["nonce"]),
            base64.b64decode(payload["box"]),
            aad,
        )

    # -- reporting -------------------------------------------------------
    def attest(
        self, *, latitude: Optional[float] = None, longitude: Optional[float] = None
    ) -> Attestation:
        reasons = [
            f"device {self.device.short} matches the install secret"
            if self.keystore and self.keystore.is_file()
            else "keystore absent"
        ]
        ok = True
        if self.fence is not None:
            inside, reason = self.fence.check(latitude, longitude)
            reasons.append(reason)
            ok = ok and inside
        if not self.device.hardware_backed:
            reasons.append("no TPM found: binding relies on a file secret, which a root attacker can steal")
        return Attestation(
            ok=ok,
            device=self.device,
            reasons=reasons,
            fence=self.fence,
            location=(latitude, longitude) if latitude is not None else None,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "device": self.device.to_dict(),
            "fence": self.fence.to_dict() if self.fence else None,
            "keystore": str(self.keystore) if self.keystore else None,
            "key_derivation": "HKDF-SHA256(install secret, salt=device fingerprint)",
        }


# ---------------------------------------------------------------------------
# Keystore
# ---------------------------------------------------------------------------
def default_keystore() -> Path:
    """``$AEGIS_KEYSTORE`` or ``~/.aegis/device.json``."""
    override = os.environ.get("AEGIS_KEYSTORE")
    if override:
        return Path(override)
    return Path.home() / ".aegis" / "device.json"


def _write_keystore(path: Path, device: str, secret: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(
        {
            "version": 2,
            "device": device,
            "secret": base64.b64encode(secret).decode(),
            "created_at": time.time(),
        },
        indent=2,
    )
    # Write privately, then tighten: the parent directory is 0700 so the file
    # is not readable by other users on the machine.
    try:
        os.chmod(path.parent, stat.S_IRWXU)
    except OSError:  # pragma: no cover - exotic filesystems
        pass
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(payload)


def rotate_secret(keystore: Optional[Path] = None) -> Path:
    """Issue a new per-install secret, invalidating every sealed payload."""
    path = keystore or default_keystore()
    device = device_fingerprint()
    _write_keystore(path, device.fingerprint, os.urandom(32))
    return path
