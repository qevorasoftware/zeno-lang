"""LLM backends for the encoder and decoder agents.

Everything except :class:`MockProvider` speaks the OpenAI *chat completions*
wire format, which covers OpenAI, Groq, Together, OpenRouter, vLLM, Ollama and
most self-hosted stacks. There is therefore exactly one HTTP code path to
maintain, and switching providers is a configuration change rather than a code
change::

    settings = load_settings(provider="groq", model="llama-3.3-70b-versatile")
    agent = Encoder(settings)

Transport uses :mod:`urllib.request` from the standard library so Zeno has no
hard third-party dependency. ``requests`` is used automatically when present.
"""

from __future__ import annotations

import json
import os
import random
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence

from .config import Settings, autodetect_provider, load_settings
from .errors import ProviderError

__all__ = [
    "Completion",
    "Provider",
    "OpenAICompatibleProvider",
    "MockProvider",
    "NullProvider",
    "SequenceProvider",
    "resolve",
    "list_providers",
    "autodetect_provider",
]


@dataclass
class Completion:
    """A single model response plus its accounting metadata."""

    text: str
    provider: str = ""
    model: str = ""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    latency_ms: float = 0.0
    #: 1-4 attempts were needed to get this response.
    attempts: int = 1
    #: The exact prompt that was sent (kept for benchmarks and audits).
    prompt: str = ""
    raw: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "provider": self.provider,
            "model": self.model,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "latency_ms": round(self.latency_ms, 3),
            "attempts": self.attempts,
        }


class Provider:
    """Base class. Implementations must override :meth:`complete`."""

    name = "base"

    def __init__(self, settings: Optional[Settings] = None) -> None:
        self.settings = settings or load_settings()
        self.name = self.settings.provider

    # -- capability probes ----------------------------------------------
    @property
    def model(self) -> str:
        return self.settings.model

    def available(self) -> bool:
        return self.settings.configured

    def describe(self) -> Dict[str, Any]:
        return self.settings.to_dict() | {"provider_class": type(self).__name__}

    # -- main entry point ------------------------------------------------
    def complete(
        self,
        prompt: str,
        *,
        system: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        stop: Optional[Sequence[str]] = None,
        model: Optional[str] = None,
    ) -> Completion:  # pragma: no cover - abstract
        raise NotImplementedError

    def __call__(self, prompt: str, **kwargs: Any) -> str:
        return self.complete(prompt, **kwargs).text


# ---------------------------------------------------------------------------
# OpenAI-compatible HTTP provider
# ---------------------------------------------------------------------------
class OpenAICompatibleProvider(Provider):
    """Chat-completions provider for any OpenAI-compatible endpoint."""

    def __init__(self, settings: Optional[Settings] = None, *, retries: int = 3) -> None:
        super().__init__(settings)
        self.retries = retries
        self._requests = _try_import_requests()

    # -- transport -------------------------------------------------------
    def _endpoint(self) -> str:
        base = (self.settings.base_url or "").rstrip("/")
        if not base:
            raise ProviderError(
                "no base URL configured for provider '" + self.settings.provider + "'",
                hint="set ZENO_BASE_URL or choose a known provider preset",
            )
        if base.endswith("/chat/completions"):
            return base
        return base + "/chat/completions"

    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.settings.api_key:
            headers["Authorization"] = f"Bearer {self.settings.api_key}"
        headers.update(self.settings.headers)
        if self.settings.provider == "openrouter":
            headers.setdefault("HTTP-Referer", "https://github.com/qevorasoftware/zeno-lang")
            headers.setdefault("X-Title", "Zeno Protocol")
        return headers

    def _payload(
        self,
        prompt: str,
        system: Optional[str],
        temperature: Optional[float],
        max_tokens: Optional[int],
        stop: Optional[Sequence[str]],
        model: Optional[str],
    ) -> Dict[str, Any]:
        messages: List[Dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})
        payload: Dict[str, Any] = {
            "model": model or self.settings.model,
            "messages": messages,
            "temperature": (
                self.settings.temperature if temperature is None else temperature
            ),
        }
        limit = self.settings.max_tokens if max_tokens is None else max_tokens
        if limit:
            payload["max_tokens"] = int(limit)
        if stop:
            payload["stop"] = list(stop)
        return payload

    def complete(
        self,
        prompt: str,
        *,
        system: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        stop: Optional[Sequence[str]] = None,
        model: Optional[str] = None,
    ) -> Completion:
        if not self.settings.configured:
            raise ProviderError(
                f"provider '{self.settings.provider}' is not configured",
                hint="export the provider API key (see PROVIDER_PRESETS) or use ZENO_PROVIDER=mock",
            )
        payload = self._payload(prompt, system, temperature, max_tokens, stop, model)
        started = time.perf_counter()
        last_error: Optional[Exception] = None
        for attempt in range(1, self.retries + 1):
            try:
                body = self._post(payload)
                latency = (time.perf_counter() - started) * 1000.0
                return self._parse(body, prompt, latency, attempt)
            except ProviderError as exc:
                last_error = exc
                if getattr(exc, "fatal", False) or attempt == self.retries:
                    break
            except _Retryable as exc:
                last_error = exc
                if attempt == self.retries:
                    break
            time.sleep(min(8.0, 0.4 * 2 ** (attempt - 1)) * (0.75 + random.random() / 2))
        raise ProviderError(
            f"provider '{self.settings.provider}' failed after {self.retries} attempts: {last_error}",
            hint="check credentials, quota and network access",
        )

    def _post(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        url = self._endpoint()
        headers = self._headers()
        data = json.dumps(payload).encode("utf-8")
        if self._requests is not None:
            return self._post_with_requests(url, headers, data)
        return self._post_with_urllib(url, headers, data)

    def _post_with_requests(self, url, headers, data):  # pragma: no cover - network
        try:
            response = self._requests.post(
                url, headers=headers, data=data, timeout=self.settings.timeout
            )
        except self._requests.exceptions.Timeout as exc:
            raise _Retryable(f"timeout after {self.settings.timeout}s") from exc
        except self._requests.exceptions.RequestException as exc:
            raise _Retryable(str(exc)) from exc
        if response.status_code >= 500:
            raise _Retryable(f"HTTP {response.status_code}: {response.text[:200]}")
        if response.status_code >= 400:
            error = ProviderError(
                f"HTTP {response.status_code} from {self.settings.provider}: {response.text[:400]}",
                hint="a 401/403 usually means a bad API key; 404 usually means a wrong model name",
            )
            error.fatal = response.status_code in (400, 401, 403, 404, 422, 429)
            raise error
        try:
            return response.json()
        except ValueError as exc:
            raise ProviderError(
                f"provider returned non-JSON body: {response.text[:200]}"
            ) from exc

    def _post_with_urllib(self, url, headers, data):  # pragma: no cover - network
        request = urllib.request.Request(url, data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=self.settings.timeout) as response:
                raw = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", "replace")[:400]
            if exc.code >= 500:
                raise _Retryable(f"HTTP {exc.code}: {body}") from exc
            error = ProviderError(
                f"HTTP {exc.code} from {self.settings.provider}: {body}",
                hint="a 401/403 usually means a bad API key; 404 usually means a wrong model name",
            )
            error.fatal = exc.code in (400, 401, 403, 404, 422, 429)
            raise error
        except urllib.error.URLError as exc:
            raise _Retryable(str(exc.reason)) from exc
        except TimeoutError as exc:
            raise _Retryable(f"timeout after {self.settings.timeout}s") from exc
        try:
            return json.loads(raw)
        except ValueError as exc:
            raise ProviderError(f"provider returned non-JSON body: {raw[:200]}") from exc

    @staticmethod
    def _parse(body: Dict[str, Any], prompt: str, latency: float, attempt: int) -> Completion:
        choices = body.get("choices") or []
        if not choices:
            raise ProviderError(f"provider returned no choices: {json.dumps(body)[:200]}")
        first = choices[0]
        message = first.get("message") or {}
        text = message.get("content")
        if text is None:
            text = first.get("text") or ""
        usage = body.get("usage") or {}
        return Completion(
            text=text.strip(),
            provider=str(body.get("provider") or ""),
            model=str(body.get("model") or ""),
            prompt_tokens=int(usage.get("prompt_tokens") or 0),
            completion_tokens=int(usage.get("completion_tokens") or 0),
            total_tokens=int(usage.get("total_tokens") or 0),
            latency_ms=latency,
            attempts=attempt,
            prompt=prompt,
            raw=body,
        )


class _Retryable(Exception):
    """Internal marker for transient transport failures."""


def _try_import_requests():  # pragma: no cover - optional dependency
    try:
        import requests  # type: ignore

        return requests
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Offline providers
# ---------------------------------------------------------------------------
class MockProvider(Provider):
    """Deterministic offline backend.

    Accepts a fixed string, a list of strings (cycled), or a callable that
    receives the prompt and returns text. Useful for tests, examples, CI and
    for demonstrating the full pipeline without any API key.
    """

    name = "mock"

    def __init__(
        self,
        responses: Any = None,
        settings: Optional[Settings] = None,
    ) -> None:
        super().__init__(settings or load_settings(provider="mock"))
        self.responses = responses
        self.calls: List[Dict[str, Any]] = []

    def _next(self, prompt: str, system: Optional[str]) -> str:
        self.calls.append({"prompt": prompt, "system": system})
        if callable(self.responses):
            return str(self.responses(prompt, system))
        if isinstance(self.responses, (list, tuple)):
            if not self.responses:
                return ""
            index = (len(self.calls) - 1) % len(self.responses)
            return str(self.responses[index])
        if isinstance(self.responses, str):
            return self.responses
        return _default_mock_response(prompt, system)

    def complete(
        self,
        prompt: str,
        *,
        system: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        stop: Optional[Sequence[str]] = None,
        model: Optional[str] = None,
    ) -> Completion:
        started = time.perf_counter()
        text = self._next(prompt, system)
        latency = (time.perf_counter() - started) * 1000.0
        return Completion(
            text=text.strip(),
            provider="mock",
            model=model or self.settings.model or "zeno-mock-1",
            prompt_tokens=_approx_tokens(prompt) + _approx_tokens(system or ""),
            completion_tokens=_approx_tokens(text),
            total_tokens=_approx_tokens(prompt) + _approx_tokens(system or "") + _approx_tokens(text),
            latency_ms=latency,
            prompt=prompt,
        )


class NullProvider(Provider):
    """The "no backend" backend.

    Returned by :func:`resolve` when nothing is configured. It reports itself as
    unavailable so the encoder degrades to its rule-based path and the decoder
    to its deterministic renderer — instead of a mock silently pretending to be
    a model.
    """

    name = "none"

    def available(self) -> bool:
        return False

    def complete(self, prompt: str, **kwargs: Any) -> Completion:
        raise ProviderError(
            "no LLM provider is configured",
            hint="set ZENO_PROVIDER and a provider API key, or construct the agent "
            "with MockProvider() to work offline",
        )


class SequenceProvider(Provider):
    """Answers in order from a list; used by tests to script agent behaviour."""

    def __init__(self, responses: Sequence[str], settings: Optional[Settings] = None) -> None:
        super().__init__(settings or load_settings(provider="mock"))
        self._responses = list(responses)
        self._index = 0
        self.calls: List[str] = []

    def complete(self, prompt: str, *, system: Optional[str] = None, **kwargs: Any) -> Completion:
        self.calls.append(prompt)
        if self._index < len(self._responses):
            text = self._responses[self._index]
            self._index += 1
        else:
            text = self._responses[-1] if self._responses else ""
        return Completion(
            text=text.strip(),
            provider="sequence",
            model=self.settings.model or "scripted",
            prompt_tokens=_approx_tokens(prompt),
            completion_tokens=_approx_tokens(text),
            prompt=prompt,
        )


def _default_mock_response(prompt: str, system: Optional[str]) -> str:
    """A canned answer keyed off the agent marker in the prompt.

    Encoder prompts end with a ``ZENO:`` marker; decoder prompts contain an
    ``EXECUTION RESULT`` block. Anything else gets a neutral no-op payload.
    """
    from .spec import canonical_example

    if "EXECUTION RESULT" in prompt:
        first = next(
            (line for line in prompt.splitlines() if line.startswith("result:")),
            "result: NIL",
        )
        return f"Mock decoder report. {first.removeprefix('result:').strip()}"
    if prompt.rstrip().endswith("ZENO:") or "\nZENO:" in prompt:
        return canonical_example().get("zeno", "@SYS[ZENO] -> !NOOP[ready]")
    return "@SYS[ZENO] -> !NOOP[ready]"


def _approx_tokens(text: str) -> int:
    from .tokenizer import count_tokens

    return count_tokens(text)


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------
_PROVIDER_CLASSES: Dict[str, type] = {
    "none": NullProvider,
    "mock": MockProvider,
    "sequence": SequenceProvider,
    "openai": OpenAICompatibleProvider,
    "groq": OpenAICompatibleProvider,
    "together": OpenAICompatibleProvider,
    "openrouter": OpenAICompatibleProvider,
    "ollama": OpenAICompatibleProvider,
    "vllm": OpenAICompatibleProvider,
    "openai-compatible": OpenAICompatibleProvider,
    "custom": OpenAICompatibleProvider,
}


def list_providers() -> Dict[str, str]:
    """Every known provider slug mapped to its transport class name."""
    return {slug: cls.__name__ for slug, cls in sorted(_PROVIDER_CLASSES.items())}


def resolve(
    provider: Any = None,
    *,
    settings: Optional[Settings] = None,
    model: Optional[str] = None,
    api_key: Optional[str] = None,
    base_url: Optional[str] = None,
    **overrides: Any,
) -> Provider:
    """Return a ready-to-use provider.

    ``provider`` may be a slug (``"groq"``), a :class:`Provider` instance (used
    as-is), or ``None`` to fall back to configuration / the mock backend.
    """
    if isinstance(provider, Provider):
        return provider
    if provider is not None and not isinstance(provider, str):
        raise TypeError(
            f"provider must be a slug or Provider instance, got {type(provider).__name__}"
        )

    if settings is None:
        slug = provider or os.environ.get("ZENO_PROVIDER") or autodetect_provider()
        if not slug:
            # Nothing configured: an explicit null backend keeps behaviour
            # honest (agents degrade instead of hallucinating through a mock).
            return NullProvider(load_settings(provider="none"))
        settings = load_settings(
            provider=slug,
            model=model,
            api_key=api_key,
            base_url=base_url,
            **overrides,
        )
    slug = settings.provider.lower()
    if slug == "none":
        return NullProvider(settings)
    cls = _PROVIDER_CLASSES.get(slug, OpenAICompatibleProvider)
    return cls(settings)
