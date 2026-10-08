"""Provider profiles: the API keys and models the agent answers through.

What this is for: the owner should be able to keep *several* AI providers —
OpenAI here, Groq there, a local Ollama — each with its own key and model, and
switch the active one without editing environment variables and restarting.

Where the keys live, honestly:

* **Server-side, in one file** — ``~/.zeno/providers.json`` (mode 0600). The key
  is handed to the server once, stored, and from then on the settings views
  report only ``has_key`` and the last four characters. A key that has been
  saved is never echoed back by any endpoint, page or CLI in this repository.
* **Sealed at rest when a memory key is configured.** With
  ``ZENO_MEMORY_KEY`` (or an owner passed by a test), the whole file is sealed
  with the AEGIS hybrid sealer to the owner's identity: ciphertext on disk, the
  same as conversation memory. Without a key the file is plaintext, mode 0600,
  and every view says ``"encrypted": false``.
* **Sent to exactly one place** — the provider's own endpoint, as a bearer
  token, when a completion is requested or the test button is pressed. Nothing
  else in this codebase reads it.

What this is not: a secret manager. Rotation, scoping, audit of key use and
per-key quotas are not implemented. Treat the file's security as the machine's
security.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from zeno.config import PROVIDER_PRESETS

DEFAULT_FILE = "~/.zeno/providers.json"


def _now() -> float:
    return time.time()


class SettingsError(ValueError):
    """A profile that cannot be stored, with the reason a person can act on."""


def provider_presets() -> List[Dict[str, Any]]:
    """The known provider slugs, for the settings page's dropdown."""
    return [
        {
            "slug": slug,
            "model": preset["model"],
            "base_url": preset["base_url"],
            "needs_key": bool(preset["key_env"]),
        }
        for slug, preset in sorted(PROVIDER_PRESETS.items())
    ]


class ProviderStore:
    """Named provider profiles: several keys, one active at a time."""

    def __init__(
        self,
        path: Optional[str] = None,
        *,
        owner: Any = None,
        locked: str = "",
    ) -> None:
        self.path = Path(
            os.path.expanduser(path or os.environ.get("ZENO_PROVIDERS_FILE") or DEFAULT_FILE)
        )
        self.owner = owner
        #: When the file exists but cannot be read (sealed, no key), the store
        #: refuses to write over it: a clobbered key file is worse than a
        #: locked one. Every view carries the reason.
        self.locked = locked
        self.profiles: Dict[str, Dict[str, Any]] = {}
        self.active: str = ""
        if not locked:
            self._load()

    @classmethod
    def locked_store(cls, reason: str) -> "ProviderStore":
        """A store that can neither read nor write, and says why."""
        return cls(locked=reason)

    # -- keys ---------------------------------------------------------------
    @classmethod
    def create_owner(cls, path: str) -> Path:
        """Mint a standalone identity file to seal providers with (0600)."""
        from zeno.memory import MemoryStore

        return MemoryStore.create_owner(path)

    @staticmethod
    def load_owner(path: str) -> Any:
        """Load an owner identity from a key file (see zeno.memory)."""
        from zeno.memory import MemoryStore

        return MemoryStore.load_owner(path)

    @property
    def encrypting(self) -> bool:
        return self.owner is not None

    def _sealer(self) -> Any:
        from aegis.pqc_engine import Sealer

        return Sealer(self.owner)

    # -- persistence --------------------------------------------------------
    def _load(self) -> None:
        if not self.path.is_file():
            return
        raw = self.path.read_bytes()
        if not raw.strip():
            return
        try:
            payload = json.loads(raw.decode("utf-8"))
            if isinstance(payload.get("sealed"), dict):
                # Sealed at rest: without the owner's key this is a stop, not a
                # guess. The caller gets the reason, never the contents.
                if self.owner is None:
                    raise SettingsError(
                        f"{self.path} is sealed to an owner key; set ZENO_MEMORY_KEY "
                        "to the key file so the server can open it"
                    )
                from aegis.pqc_engine import SealedBox

                payload = json.loads(self._sealer().open(SealedBox.from_dict(payload["sealed"])))
            self.profiles = dict(payload.get("profiles") or {})
            self.active = str(payload.get("active") or "")
            for name in list(self.profiles):
                if not isinstance(self.profiles[name], dict):
                    del self.profiles[name]
        except SettingsError:
            raise
        except Exception as error:  # noqa: BLE001 - a store that cannot be read is a stop
            raise SettingsError(f"cannot read {self.path}: {type(error).__name__}: {error}") from error

    def _save(self) -> None:
        if self.locked:
            raise SettingsError(self.locked)
        payload = {
            "profiles": self.profiles,
            "active": self.active,
            "note": "provider API keys live here; this file is 0600 and sealed when an owner key is configured",
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.encrypting:
            body: Any = {"sealed": self._sealer().seal(
                json.dumps(payload, sort_keys=True).encode("utf-8"), recipient=self.owner.public
            ).to_dict()}
        else:
            body = payload
        self.path.write_text(json.dumps(body, indent=2, sort_keys=True), encoding="utf-8")
        try:
            os.chmod(self.path, 0o600)
        except OSError:  # pragma: no cover - a filesystem that will not allow it
            pass

    # -- the registry -------------------------------------------------------
    def add(
        self,
        name: str,
        provider: str,
        *,
        model: str = "",
        base_url: str = "",
        api_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Add or update a profile. ``api_key=None`` keeps the existing key.

        An empty ``api_key`` string clears it — so the settings page can let a
        person edit a model without re-typing a key, and still delete one
        deliberately.
        """
        clean = "".join(c for c in (name or "") if c.isalnum() or c in "-_.")[:64]
        if not clean:
            raise SettingsError("a profile needs a name of letters, digits, '-' '_' or '.'")
        slug = (provider or "").strip().lower()
        if slug not in PROVIDER_PRESETS:
            raise SettingsError(
                f"unknown provider {slug!r}: choose one of {', '.join(sorted(PROVIDER_PRESETS))}"
            )
        if slug in {"none", "mock"}:
            raise SettingsError(
                f"{slug!r} is a testing backend, not something to keep a key for; "
                "the active provider can be set to it with ZENO_PROVIDER"
            )
        preset = PROVIDER_PRESETS[slug]
        base = (base_url or "").strip() or preset["base_url"]
        if not base and slug not in {"ollama", "vllm"}:
            raise SettingsError(f"{slug!r} needs a base URL")
        chosen_model = (model or "").strip() or preset["model"]

        existing = self.profiles.get(clean, {})
        key = existing.get("api_key", "") if api_key is None else str(api_key)
        if preset["key_env"] and not key and slug not in {"ollama", "vllm"}:
            # allowed, but visible: a profile without its key is marked not
            # ready everywhere it is shown
            pass
        self.profiles[clean] = {
            "provider": slug,
            "model": chosen_model,
            "base_url": base,
            "api_key": key,
            "added_at": float(existing.get("added_at") or _now()),
            "updated_at": _now(),
        }
        if not self.active:
            self.active = clean
        self._save()
        return self.view(clean)

    def remove(self, name: str) -> bool:
        removed = self.profiles.pop(name, None)
        if removed is None:
            return False
        if self.active == name:
            self.active = next(iter(self.profiles), "")
        self._save()
        return True

    def activate(self, name: str) -> Dict[str, Any]:
        if name not in self.profiles:
            raise SettingsError(f"no provider profile named {name!r}")
        self.active = name
        self._save()
        return self.view(name)

    def get(self, name: str) -> Optional[Dict[str, Any]]:
        return self.profiles.get(name)

    # -- views and providers ------------------------------------------------
    def view(self, name: str) -> Dict[str, Any]:
        """One profile as the owner may see it: never the key itself."""
        profile = self.profiles.get(name)
        if profile is None:
            raise SettingsError(f"no provider profile named {name!r}")
        key = str(profile.get("api_key") or "")
        return {
            "name": name,
            "provider": profile["provider"],
            "model": profile["model"],
            "base_url": profile["base_url"],
            "has_key": bool(key),
            "key_hint": ("…" + key[-4:]) if key else "",
            "ready": bool(key) or profile["provider"] in {"ollama", "vllm"},
            "active": self.active == name,
            "added_at": profile.get("added_at"),
            "updated_at": profile.get("updated_at"),
        }

    def describe(self) -> Dict[str, Any]:
        profiles = [self.view(name) for name in sorted(self.profiles)]
        return {
            "file": str(self.path),
            "encrypted": self.encrypting,
            "locked": self.locked or None,
            "active": self.view(self.active) if self.active and self.active in self.profiles else None,
            "profiles": profiles,
            "presets": provider_presets(),
            "limits": [
                "keys are stored server-side and never echoed back by any endpoint, page or CLI",
                "sealed at rest when an owner key is configured; otherwise plaintext, mode 0600, and every view says so",
                "a key is sent to exactly one place: its own provider's endpoint",
                "this is not a secret manager: rotation, scoping and per-key quotas are not implemented",
            ],
        }

    def provider_for(self, name: str) -> Any:
        """Build a live provider from a profile (see zeno.providers.resolve)."""
        profile = self.profiles.get(name)
        if profile is None:
            raise SettingsError(f"no provider profile named {name!r}")
        from zeno.providers import resolve

        return resolve(
            profile["provider"],
            model=profile.get("model") or None,
            api_key=profile.get("api_key") or None,
            base_url=profile.get("base_url") or None,
        )
