"""Local web playground for the Zeno Protocol.

A dependency-free HTTP server (standard library only) that exposes the encoder,
kernel, decoder and benchmarks to a single-page UI.

    $ python -m zeno serve --port 8000

Routes
------
``GET  /``                 the playground page
``GET  /dashboard``        the operator dashboard (root ``dashboard.html``)
``GET  /dashboard-data.json``  the committed snapshot the dashboard uses offline
``GET  /api/health``       liveness probe
``GET  /api/version``      library, protocol and runtime versions
``GET  /api/grammar``      the grammar card and token table
``GET  /api/tools``        the tools the demo kernel exposes
``GET  /api/benchmark``    density + multi-turn headline numbers
``GET  /api/snapshot``     the dashboard snapshot, built live
``GET  /api/tokens``       ``?text=...`` -> token counts
``POST /api/encode``       ``{"text": ...}`` -> payload + token stats
``POST /api/run``          ``{"payload": ..., "state": {...}}`` -> result frame
``POST /api/ask``          ``{"text": ...}`` -> encode, execute, decode
``POST /api/check``        ``{"payload": ...}`` -> validation report + canonical form
``POST /api/decode``       ``{"payload": ..., "state": {...}}`` -> rendered prose
``POST /api/tokens``       ``{"texts": [...]}`` -> token counts

The server binds ``0.0.0.0`` and answers any ``Host`` so that it works behind a
proxy; the page itself only ever calls relative URLs.

Cross-origin access
-------------------
The dashboard also ships as a static page on GitHub Pages, which has no Python
runtime. To let that page drive a locally running server, cross-origin requests
are answered for an allowlist: the Pages origin, anything on ``localhost`` /
``127.0.0.1``, and whatever ``--allow-origin`` (or ``ZENO_ALLOWED_ORIGINS``)
adds. It is deliberately not ``*``: the server has no authentication, and the
demo tools would otherwise be callable from any page the operator happens to
visit. Pass ``--allow-origin '*'`` if you really want that.
"""

from __future__ import annotations

import json
import os
import platform
import posixpath
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Sequence, Tuple

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

__all__ = ["serve", "build_app", "origin_allowed", "CANONICAL_EXAMPLE"]

#: The reference payload from ``specs/tokens.json`` — the one the whole
#: toolchain is tested against, and the example the dashboard opens with.
CANONICAL_EXAMPLE = (
    "@LOC[TYO] -> ?WX : { $WX.state == RAIN => !GEN[INDOOR, 3] | !GEN[OUTDOOR, 3] }"
)

WEB_ROOT = Path(__file__).resolve().parent / "web"
#: The repository root, for the two files the dashboard needs. Only the names in
#: :data:`ROOT_FILES` are servable, so this is not a path-traversal surface.
ROOT = WEB_ROOT.parent.parent
ROOT_FILES = ("dashboard.html", "dashboard-data.json")
MAX_BODY = 256 * 1024

#: Origins allowed to call this server from a different page. The dashboard on
#: GitHub Pages is served from a different origin than a locally running server,
#: so it needs an explicit CORS grant. ``localhost`` is allowed because the page
#: itself is often opened from a local file or another local port.
DEFAULT_ALLOWED_ORIGINS = ("https://qevorasoftware.github.io",)
LOCAL_HOSTS = ("localhost", "127.0.0.1", "[::1]", "0.0.0.0")


def origin_allowed(origin: str, extra: Tuple[str, ...] = ()) -> bool:
    """Is ``origin`` allowed to read responses from this server?"""
    if not origin:
        return False
    if "*" in extra or origin in extra:
        return True
    if origin in DEFAULT_ALLOWED_ORIGINS:
        return True
    host = origin.split("//", 1)[-1].split("/", 1)[0].rsplit(":", 1)[0]
    return host in LOCAL_HOSTS


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

    def check(self, payload: str) -> Dict[str, Any]:
        """Validate a payload and, when it parses, show the canonical form.

        Mirrors ``zeno check``: a lint failure still returns the program, and a
        parse failure sets ``error`` with the diagnostic attached.
        """
        report = validate(payload)
        result: Dict[str, Any] = {"report": report.to_dict(), "rendered": report.render()}
        if report.program is not None:
            from .emitter import emit

            result["canonical"] = emit(report.program)
        return result

    def decode_payload(self, payload: str, state: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Execute a payload and render the result as prose (``zeno decode``)."""
        execution = self.kernel.execute(payload, state=state or {})
        rendered = self._decoder().decode(execution, request=payload)
        return {
            "text": rendered.text,
            "decoded": rendered.to_dict(),
            "frame": result_frame(execution),
        }

    def tokens(self, texts: Sequence[str]) -> Dict[str, Any]:
        """Token counts for strings, with the counter named (``zeno tokens``)."""
        return {
            "method": counting_method(),
            "counts": {text: count_tokens(text) for text in texts},
        }

    def version(self) -> Dict[str, Any]:
        from . import __protocol__, __version__

        return {
            "library": "zeno-lang",
            "version": __version__,
            "protocol": __protocol__,
            "python": platform.python_version(),
            **self.provider_info(),
        }

    def snapshot(self, *, portable: bool = False) -> Dict[str, Any]:
        """The data the static dashboard shows when no backend is reachable.

        ``portable=True`` is what gets committed as ``dashboard-data.json`` and
        what CI compares against, so it must be byte-identical on any machine:
        the host's Python version, whichever provider is configured, and every
        token count (which depends on whether ``tiktoken`` is installed) are all
        excluded. What remains — the grammar, the tools, the canonical example,
        the corpus size and the declared targets — is a property of the protocol,
        not of the host.

        ``portable=False`` is the live view (``GET /api/snapshot``), which does
        include the numbers, labelled with the counter that produced them.
        """
        from benchmarks.conversation_test import TARGET_REDUCTION_PCT as A2A_TARGET
        from benchmarks.token_comparison import DEFAULT_CORPUS, TARGET_REDUCTION_PCT, load_corpus

        version = self.version()
        if portable:
            version = {"library": version["library"], "version": version["version"],
                       "protocol": version["protocol"]}
        payload: Dict[str, Any] = {
            "generated_by": "zeno dashboard --write",
            "portable": portable,
            "version": version,
            "canonical_example": CANONICAL_EXAMPLE,
            "tools": self.tools(),
            "grammar": self.grammar(),
        }
        if portable:
            payload["benchmark"] = {
                "targets": {
                    "density_pct": TARGET_REDUCTION_PCT,
                    "conversation_pct": A2A_TARGET,
                },
                "corpus_cases": len(load_corpus(DEFAULT_CORPUS).get("cases", [])),
                "note": (
                    "token counts are excluded on purpose: they depend on the counter in "
                    "use (tiktoken vs estimate), so they are only reported by a live backend"
                ),
            }
        else:
            payload["benchmark"] = self.benchmark()
        return payload

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
    #: Extra origins, set by ``serve()`` from --allow-origin / ZENO_ALLOWED_ORIGINS.
    allowed_origins: Tuple[str, ...] = ()

    def _cors_headers(self) -> None:
        """Grant cross-origin read access, but only to the allowlist."""
        origin = self.headers.get("Origin", "")
        if not origin or not origin_allowed(origin, self.allowed_origins):
            return
        self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Max-Age", "600")
        # Chrome's Private Network Access: a public page (GitHub Pages) reaching a
        # private address (localhost) sends a preflight asking for this grant.
        if self.headers.get("Access-Control-Request-Private-Network") == "true":
            self.send_header("Access-Control-Allow-Private-Network", "true")

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        # Cross-origin grants used to be a blanket "*", which let any page the
        # operator happened to visit drive this server. They are now decided per
        # request by _cors_headers() against the allowlist.
        self._cors_headers()
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

    def _root_file(self, name: str) -> None:
        """Serve one of :data:`ROOT_FILES` from the repository root."""
        if name not in ROOT_FILES or name not in {"dashboard.html", "dashboard-data.json"}:
            self._send(404, b"not found", "text/plain; charset=utf-8")
            return
        target = (ROOT / name).resolve()
        if not target.is_file():
            self._send(
                404,
                b"not found: run `zeno dashboard --write` to create dashboard-data.json",
                "text/plain; charset=utf-8",
            )
            return
        content_type = "text/html; charset=utf-8" if name.endswith(".html") else "application/json"
        self._send(200, target.read_bytes(), content_type)

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
        """Preflight. Headers only; the allowlist decides whether any are granted."""
        self._send(204, b"", "text/plain")

    def do_GET(self) -> None:  # noqa: N802 - stdlib signature
        path = posixpath.normpath(self.path.split("?", 1)[0])
        try:
            if path in ("/", "/index.html"):
                self._file("index.html")
                return
            if path in ("/dashboard", "/dashboard/", "/dashboard.html"):
                self._root_file("dashboard.html")
                return
            if path == "/dashboard-data.json":
                self._root_file("dashboard-data.json")
                return
            if path == "/api/snapshot":
                self._json(self.playground.snapshot())
                return
            if path == "/api/version":
                self._json(self.playground.version())
                return
            if path == "/api/tokens":
                text = (self.path.split("?", 1)[1] if "?" in self.path else "")
                query = dict(
                    pair.split("=", 1) for pair in text.split("&") if "=" in pair
                )
                from urllib.parse import unquote_plus

                self._json(self.playground.tokens([unquote_plus(query.get("text", ""))]))
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
            if path == "/api/check":
                payload = str(body.get("payload", ""))
                if not payload.strip():
                    self._json({"error": {"code": "ZN0003", "message": "payload is required"}}, 400)
                    return
                self._json(self.playground.check(payload))
                return
            if path == "/api/decode":
                payload = str(body.get("payload", ""))
                if not payload.strip():
                    self._json({"error": {"code": "ZN0003", "message": "payload is required"}}, 400)
                    return
                self._json(self.playground.decode_payload(payload, body.get("state") or {}))
                return
            if path == "/api/tokens":
                texts = body.get("texts")
                if texts is None:
                    texts = [str(body.get("text", ""))]
                if not isinstance(texts, list) or not texts:
                    self._json({"error": {"code": "ZN0003", "message": "texts is required"}}, 400)
                    return
                self._json(self.playground.tokens([str(item) for item in texts]))
                return
            self._json({"error": {"code": "ZN0000", "message": f"no route {path}"}}, 404)
        except ZenoError as exc:
            self._error(exc, 400)
        except Exception as exc:  # pragma: no cover - defensive
            self._error(exc)


def build_app(provider: Optional[Provider] = None) -> Playground:
    """The application object behind the HTTP handler (used by tests too)."""
    return Playground(provider)


def snapshot_bytes(playground: Optional[Playground] = None) -> bytes:
    """The dashboard snapshot as committed bytes.

    ``sort_keys`` plus a trailing newline keep the file diff-friendly and make
    "is the committed snapshot current?" a byte comparison in CI.
    """
    app = playground or build_app()
    payload = app.snapshot(portable=True)
    return (json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n").encode("utf-8")


def resolve_allowed_origins(explicit: Optional[Sequence[str]] = None) -> Tuple[str, ...]:
    """Origins from ``--allow-origin``, else ``ZENO_ALLOWED_ORIGINS``, else none."""
    if explicit:
        return tuple(origin.strip() for origin in explicit if origin.strip())
    raw = os.environ.get("ZENO_ALLOWED_ORIGINS", "")
    return tuple(part.strip() for part in raw.split(",") if part.strip())


def serve(
    host: str = "0.0.0.0",
    port: int = 8000,
    *,
    provider: Optional[Provider] = None,
    allowed_origins: Optional[Sequence[str]] = None,
) -> None:
    """Run the playground until interrupted."""
    playground = build_app(provider)
    origins = resolve_allowed_origins(allowed_origins)
    handler = type(
        "BoundHandler", (_Handler,), {"playground": playground, "allowed_origins": origins}
    )
    httpd = ThreadingHTTPServer((host, port), handler)
    httpd.daemon_threads = True
    info = playground.provider_info()
    print(f"Zeno playground on http://{host}:{port}  (provider: {info['provider']}, "
          f"tokenizer: {info['tokenizer']})", flush=True)
    print(f"  playground: http://{host}:{port}/    dashboard: http://{host}:{port}/dashboard",
          flush=True)
    granted = ", ".join((*DEFAULT_ALLOWED_ORIGINS, *origins)) or "none"
    print(f"  cross-origin readers allowed: {granted} (+ localhost)", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:  # pragma: no cover - interactive
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":  # pragma: no cover
    serve(port=int(os.environ.get("ZENO_PORT", "8000")))
