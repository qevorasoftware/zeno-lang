"""Local web playground for the Zeno Protocol.

A dependency-free HTTP server (standard library only) that exposes the encoder,
kernel, decoder and benchmarks to a single-page UI.

    $ python -m zeno serve --port 8000

Routes
------
``GET  /``                 the playground page
``GET  /api/health``       liveness probe
``GET  /api/grammar``      the grammar card and token table
``GET  /api/tools``        the tools the demo kernel exposes
``GET  /api/benchmark``    density + multi-turn headline numbers
``POST /api/encode``       ``{"text": ...}`` -> payload + token stats
``POST /api/run``          ``{"payload": ..., "state": {...}}`` -> result frame
``POST /api/ask``          ``{"text": ...}`` -> encode, execute, decode

The server binds ``0.0.0.0`` and answers any ``Host`` so that it works behind a
proxy; the page itself only ever calls relative URLs.
"""

from __future__ import annotations

import json
import os
import posixpath
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

from .decoder import Decoder
from .encoder import Encoder, HeuristicEncoder
from .errors import ZenoError
from .pipeline import Pipeline, default_kernel
from .prompts import grammar_card
from .providers import MockProvider, Provider, resolve
from .tools import demo_generator, demo_tools
from .runtime import ExecutionResult, Kernel, result_frame
from .tokenizer import count_tokens, counting_method
from .validator import validate

__all__ = ["serve", "build_app"]

WEB_ROOT = Path(__file__).resolve().parent / "web"
MAX_BODY = 256 * 1024


class Playground:
    """Everything the HTTP layer needs, with no per-request global state."""

    def __init__(self, provider: Optional[Provider] = None) -> None:
        self.provider = provider or resolve()
        self.heuristic = HeuristicEncoder()
        self.kernel = default_kernel(generator=demo_generator)
        for name, tool in demo_tools().items():
            self.kernel.register(name, tool)

    # -- helpers ---------------------------------------------------------
    def _encoder(self, text: str) -> Encoder:
        """An encoder for ``text``.

        Without credentials the rule-based encoder answers the *same* prompt the
        model would see, so the round trip below is honest about the pipeline
        even though no network call happens.
        """
        provider = self.provider
        if not provider.available():
            provider = MockProvider(lambda prompt, system: self.heuristic.encode(text))
        return Encoder(
            provider,
            tools=sorted(list(self.kernel.queries) + list(self.kernel.actions)),
            fallback=True,
        )

    def _decoder(self) -> Decoder:
        provider = self.provider
        if not provider.available():
            provider = MockProvider(lambda prompt, system: _extract_result(prompt))
        return Decoder(provider, fallback=True)

    def provider_info(self) -> Dict[str, Any]:
        return {
            "provider": self.provider.name,
            "model": self.provider.model,
            "online": self.provider.available(),
            "tokenizer": counting_method(),
        }

    # -- endpoints -------------------------------------------------------
    def encode(self, text: str) -> Dict[str, Any]:
        result = self._encoder(text).encode(text)
        payload = result.to_dict()
        payload["validation"] = (
            result.report.to_dict() if result.report else {"ok": False, "diagnostics": []}
        )
        payload["heuristic"] = self.heuristic.encode(text) if not result.payload else None
        return payload

    def run(self, payload: str, state: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        execution = self.kernel.execute(payload, state=state or {})
        report = validate(payload)
        return {
            "frame": result_frame(execution),
            "output": execution.output,
            "bindings": execution.bindings,
            "steps": [step.to_dict() for step in execution.steps],
            "calls": [call.to_dict() for call in execution.calls],
            "state": execution.state,
            "returned": execution.returned,
            "duration_ms": round(execution.duration_ms, 3),
            "errors": execution.errors,
            "context": execution.as_context(),
            "validation": report.to_dict(),
        }

    def ask(self, text: str, state: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        pipeline = Pipeline(
            encoder=self._encoder(text), kernel=self.kernel, decoder=self._decoder()
        )
        outcome = pipeline.run(text, state=state or {})
        return outcome.to_dict() | {"transcript": outcome.transcript()}

    def grammar(self) -> Dict[str, Any]:
        from .spec import tokens

        return {"card": grammar_card(), "spec": tokens()}

    def tools(self) -> Dict[str, Any]:
        return {
            "queries": sorted(self.kernel.queries),
            "actions": sorted(self.kernel.actions),
            "builtin": self.kernel.available(),
        }

    def benchmark(self) -> Dict[str, Any]:
        from benchmarks.conversation_test import run as conversation
        from benchmarks.token_comparison import run as density

        density_report = density()
        conversation_report = conversation()
        return {
            "density": density_report.to_dict(),
            "conversation": conversation_report.to_dict(),
        }


def _extract_result(prompt: str) -> str:
    """Deterministic stand-in decoder used when no provider is configured.

    It reads the execution frame out of the *real* decoder prompt and restates
    it, so the offline path exercises the same prompt the model would receive.
    """
    lines = prompt.splitlines()
    collected: list = []
    for index, line in enumerate(lines):
        if line.strip().lower().startswith("result:"):
            collected.append(line.split(":", 1)[1].strip())
            for following in lines[index + 1:]:
                if following.strip() and not following.startswith((" ", "\t")):
                    break
                collected.append(following.strip())
            break
    body = " ".join(part for part in collected if part).strip()
    return f"The kernel produced: {body}" if body else "The kernel produced no result."


# ---------------------------------------------------------------------------
# HTTP layer
# ---------------------------------------------------------------------------
class _Handler(BaseHTTPRequestHandler):
    server_version = "ZenoPlayground/0.1"
    protocol_version = "HTTP/1.1"

    playground: Playground

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - stdlib signature
        if os.environ.get("ZENO_HTTP_LOG") == "1":
            super().log_message(format, *args)

    # -- helpers ---------------------------------------------------------
    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, payload: Any, status: int = 200) -> None:
        self._send(status, json.dumps(payload, default=str).encode("utf-8"), "application/json")

    def _error(self, exc: Exception, status: int = 400) -> None:
        if isinstance(exc, ZenoError):
            self._json({"error": exc.to_dict(), "rendered": exc.render()}, status)
        else:  # pragma: no cover - defensive
            self._json({"error": {"code": "ZN0000", "message": str(exc)}}, 500)

    def _body(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        if length > MAX_BODY:
            raise ValueError("request body too large")
        raw = self.rfile.read(length).decode("utf-8")
        return json.loads(raw or "{}")

    def _file(self, relative: str) -> None:
        target = (WEB_ROOT / relative.lstrip("/")).resolve()
        if WEB_ROOT not in target.parents and target != WEB_ROOT:
            self._send(403, b"forbidden", "text/plain; charset=utf-8")
            return
        if not target.is_file():
            self._send(404, b"not found", "text/plain; charset=utf-8")
            return
        suffix = target.suffix.lower()
        content_type = {
            ".html": "text/html; charset=utf-8",
            ".css": "text/css; charset=utf-8",
            ".js": "text/javascript; charset=utf-8",
            ".json": "application/json",
            ".svg": "image/svg+xml",
        }.get(suffix, "application/octet-stream")
        self._send(200, target.read_bytes(), content_type)

    # -- verbs -----------------------------------------------------------
    def do_OPTIONS(self) -> None:  # noqa: N802 - stdlib signature
        self._send(204, b"", "text/plain")

    def do_GET(self) -> None:  # noqa: N802 - stdlib signature
        path = posixpath.normpath(self.path.split("?", 1)[0])
        try:
            if path in ("/", "/index.html"):
                self._file("index.html")
                return
            if path == "/api/health":
                self._json({"ok": True, "time": time.time(), **self.playground.provider_info()})
                return
            if path == "/api/grammar":
                self._json(self.playground.grammar())
                return
            if path == "/api/tools":
                self._json(self.playground.tools())
                return
            if path == "/api/benchmark":
                self._json(self.playground.benchmark())
                return
            if path.startswith("/static/"):
                self._file(path.removeprefix("/static/"))
                return
            self._json({"error": {"code": "ZN0000", "message": f"no route {path}"}}, 404)
        except Exception as exc:  # pragma: no cover - defensive
            self._error(exc)

    def do_POST(self) -> None:  # noqa: N802 - stdlib signature
        path = posixpath.normpath(self.path.split("?", 1)[0])
        try:
            body = self._body()
        except Exception as exc:
            self._json({"error": {"code": "ZN0000", "message": f"bad request body: {exc}"}}, 400)
            return

        try:
            if path == "/api/encode":
                self._json(self.playground.encode(str(body.get("text", ""))))
                return
            if path == "/api/run":
                payload = str(body.get("payload", ""))
                state = body.get("state") or {}
                if not payload.strip():
                    self._json(
                        {"error": {"code": "ZN0003", "message": "payload is required"}}, 400
                    )
                    return
                self._json(self.playground.run(payload, state))
                return
            if path == "/api/ask":
                text = str(body.get("text", ""))
                if not text.strip():
                    self._json({"error": {"code": "ZN0003", "message": "text is required"}}, 400)
                    return
                self._json(self.playground.ask(text, body.get("state") or {}))
                return
            self._json({"error": {"code": "ZN0000", "message": f"no route {path}"}}, 404)
        except ZenoError as exc:
            self._error(exc, 400)
        except Exception as exc:  # pragma: no cover - defensive
            self._error(exc)


def build_app(provider: Optional[Provider] = None) -> Playground:
    """The application object behind the HTTP handler (used by tests too)."""
    return Playground(provider)


def serve(host: str = "0.0.0.0", port: int = 8000, *, provider: Optional[Provider] = None) -> None:
    """Run the playground until interrupted."""
    playground = build_app(provider)
    handler = type("BoundHandler", (_Handler,), {"playground": playground})
    httpd = ThreadingHTTPServer((host, port), handler)
    httpd.daemon_threads = True
    info = playground.provider_info()
    print(f"Zeno playground on http://{host}:{port}  (provider: {info['provider']}, "
          f"tokenizer: {info['tokenizer']})", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:  # pragma: no cover - interactive
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":  # pragma: no cover
    serve(port=int(os.environ.get("ZENO_PORT", "8000")))
