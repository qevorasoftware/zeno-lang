"""Configuration for Zeno.

Settings resolve in this order (first hit wins):

1. explicit keyword arguments,
2. environment variables (``ZENO_*`` and the provider-specific API keys),
3. a ``.env`` file found by walking up from the current directory,
4. built-in defaults.

Nothing here ever raises for a missing key — :func:`zeno.providers.resolve`
turns "no credentials" into a clear ``ZN3001`` diagnostic only when a network
call is actually attempted.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

__all__ = [
    "Settings",
    "load_settings",
    "load_dotenv",
    "autodetect_provider",
    "DEFAULTS",
    "PROVIDER_PRESETS",
]

#: Provider presets: base URL + the environment variable holding the key.
PROVIDER_PRESETS: Dict[str, Dict[str, str]] = {
    "openai": {
        "base_url": "https://api.openai.com/v1",
        "key_env": "OPENAI_API_KEY",
        "model": "gpt-4o-mini",
    },
    "groq": {
        "base_url": "https://api.groq.com/openai/v1",
        "key_env": "GROQ_API_KEY",
        "model": "llama-3.3-70b-versatile",
    },
    "together": {
        "base_url": "https://api.together.xyz/v1",
        "key_env": "TOGETHER_API_KEY",
        "model": "meta-llama/Llama-3.3-70B-Instruct-Turbo",
    },
    "openrouter": {
        "base_url": "https://openrouter.ai/api/v1",
        "key_env": "OPENROUTER_API_KEY",
        "model": "meta-llama/llama-3.3-70b-instruct",
    },
    "ollama": {
        "base_url": "http://localhost:11434/v1",
        "key_env": "OLLAMA_API_KEY",  # usually unset; Ollama ignores it
        "model": "llama3.1",
    },
    "vllm": {
        "base_url": "http://localhost:8000/v1",
        "key_env": "VLLM_API_KEY",
        "model": "meta-llama/Llama-3.1-8B-Instruct",
    },
    "mock": {"base_url": "", "key_env": "", "model": "zeno-mock-1"},
    "none": {"base_url": "", "key_env": "", "model": ""},
}

#: Order in which provider API keys are probed by :func:`autodetect_provider`.
AUTODETECT_ORDER = ("openai", "groq", "together", "openrouter")

DEFAULTS: Dict[str, Any] = {
    "provider": "auto",
    "model": "",
    "base_url": "",
    "api_key": "",
    "timeout": 30.0,
    "temperature": 0.0,
    "max_tokens": 512,
    "max_repairs": 2,
    "strict": False,
    "dotenv": True,
}


@dataclass
class Settings:
    """Resolved configuration for one encode/decode call."""

    provider: str = "mock"
    model: str = ""
    base_url: str = ""
    api_key: str = ""
    timeout: float = 30.0
    temperature: float = 0.0
    max_tokens: int = 512
    #: How many times the encoder may ask the model to repair invalid output.
    max_repairs: int = 2
    #: When true, provider failures raise instead of silently degrading.
    strict: bool = False
    #: Extra provider-specific headers.
    headers: Dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.provider = (self.provider or "auto").strip().lower()
        if self.provider == "auto":
            # Never silently pretend a model is behind us: fall back to the
            # explicit "none" backend, which reports itself unavailable.
            self.provider = autodetect_provider() or "none"
        preset = PROVIDER_PRESETS.get(self.provider)
        if preset:
            if not self.base_url:
                self.base_url = os.environ.get("ZENO_BASE_URL") or preset["base_url"]
            if not self.model:
                self.model = os.environ.get("ZENO_MODEL") or preset["model"]
            if not self.api_key and preset["key_env"]:
                self.api_key = os.environ.get(preset["key_env"], "")
        else:
            if not self.base_url:
                self.base_url = os.environ.get("ZENO_BASE_URL", "")
            if not self.model:
                self.model = os.environ.get("ZENO_MODEL", "")
            if not self.api_key:
                self.api_key = os.environ.get("ZENO_API_KEY", "")

    @property
    def configured(self) -> bool:
        if self.provider == "mock":
            return True
        if not self.base_url:
            return False
        if self.provider in {"ollama", "vllm"}:
            return True
        return bool(self.api_key)

    def to_dict(self, *, redact: bool = True) -> Dict[str, Any]:
        payload = {
            "provider": self.provider,
            "model": self.model,
            "base_url": self.base_url,
            "timeout": self.timeout,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "max_repairs": self.max_repairs,
        }
        payload["api_key"] = "***" if (redact and self.api_key) else self.api_key
        return payload


def autodetect_provider() -> Optional[str]:
    """The first provider slug whose API key is present in the environment."""
    for slug in AUTODETECT_ORDER:
        key_env = PROVIDER_PRESETS[slug]["key_env"]
        if key_env and os.environ.get(key_env):
            return slug
    if os.environ.get("ZENO_BASE_URL") and os.environ.get("ZENO_API_KEY"):
        return "custom"
    return None


def load_dotenv(path: Optional[Path] = None, *, override: bool = False) -> Dict[str, str]:
    """Load a ``.env`` file into ``os.environ``; returns the values applied."""
    applied: Dict[str, str] = {}
    candidates = [path] if path else _dotenv_candidates()
    for candidate in candidates:
        if candidate is None or not candidate.is_file():
            continue
        for raw in candidate.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if not key:
                continue
            if override or key not in os.environ:
                os.environ[key] = value
                applied[key] = value
        break
    return applied


def _dotenv_candidates() -> list:
    candidates = [Path.cwd() / ".env"]
    here = Path(__file__).resolve()
    candidates.extend(parent / ".env" for parent in here.parents)
    return candidates


def load_settings(**overrides: Any) -> Settings:
    """Build :class:`Settings` from defaults, env vars and explicit overrides."""
    values = dict(DEFAULTS)
    values["provider"] = os.environ.get("ZENO_PROVIDER", values["provider"])
    values["model"] = os.environ.get("ZENO_MODEL", values["model"])
    values["base_url"] = os.environ.get("ZENO_BASE_URL", values["base_url"])
    values["api_key"] = os.environ.get("ZENO_API_KEY", values["api_key"])
    if values["dotenv"]:
        load_dotenv()
    for key, value in os.environ.items():
        if not key.startswith("ZENO_"):
            continue
        name = key[5:].lower()
        if name in {"timeout", "temperature", "max_tokens", "max_repairs", "strict"}:
            values[name] = _coerce(name, value)
    values.pop("dotenv", None)
    for key, value in overrides.items():
        if value is None:
            continue
        values[key] = value
    known = {field_name for field_name in Settings.__dataclass_fields__}
    values = {key: value for key, value in values.items() if key in known}
    return Settings(**values)


def _coerce(name: str, value: str) -> Any:
    if name == "timeout":
        return float(value)
    if name == "temperature":
        return float(value)
    if name in {"max_tokens", "max_repairs"}:
        return int(value)
    if name == "strict":
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return value
