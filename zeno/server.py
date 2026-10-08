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
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Mapping, Optional, Sequence, Tuple

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


def _development_policy(policy: Any = None) -> Any:
    """The policy the HTTP surface runs under when it is not production.

    PQC, the ledger and the sentinel stay required — they need nothing from the
    caller, so there is no reason to skip them. The device lock is *not* required
    here: a browser cannot know this host's own fingerprint, so requiring it would
    make the playground unusable rather than safer. Every response still reports
    ``enforcement: development``.
    """
    if policy is not None:
        return policy
    from aegis.gate import Policy

    return Policy(mode="development", require_device_lock=False)


def _build_boundary(mode: str, policy: Any = None) -> Any:
    """Build the authorization boundary, or return ``None`` if it cannot exist.

    ``None`` is not permission: see :class:`_NoBoundary`.
    """
    try:
        from aegis.boundary import AuthorizationBoundary
        from aegis.gate import Gateway, Policy

        chosen = (policy or Policy.strict_policy()) if mode == "production" else _development_policy(policy)
        return AuthorizationBoundary(gateway=Gateway(chosen, sentinel=_build_sentinel()), policy=chosen)
    except Exception:  # noqa: BLE001 - no crypto backend, no boundary
        return None


def _build_sentinel() -> Any:
    """The guardian, with its burst heuristic configurable on purpose.

    A conversation is a burst of requests by nature: twenty turns a minute is a
    person talking, not an attack. The default heuristic is tuned for a machine
    interface, so a voice deployment will trip it — which is the guardian working,
    not a bug. ``ZENO_SENTINEL_MAX_EVENTS_PER_MINUTE`` raises the ceiling for a
    deployment that has decided a conversation is expected traffic; leaving it
    unset keeps the library's own (stricter) default, and nothing is lowered
    silently.
    """
    from aegis.guardian_ai import Sentinel

    configured = os.environ.get("ZENO_SENTINEL_MAX_EVENTS_PER_MINUTE", "").strip()
    if not configured:
        return Sentinel()
    try:
        return Sentinel(max_events_per_minute=float(configured))
    except ValueError:
        print(
            f"ZENO_SENTINEL_MAX_EVENTS_PER_MINUTE={configured!r} is not a number; "
            "using the guardian's own default",
            file=sys.stderr,
            flush=True,
        )
        return Sentinel()


def _build_memory() -> Any:
    """The conversation store, sealed to the owner when a key is configured.

    ``ZENO_MEMORY_KEY`` points at the owner's private identity (a ``zeno memory
    init-key`` file, or an ``aegis owner init`` root). Without it the store runs
    unsealed and says so in every record and in ``/api/health``.
    """
    from zeno.memory import MemoryStore

    path = os.environ.get("ZENO_MEMORY_KEY", "").strip()
    if path:
        try:
            return MemoryStore(owner=MemoryStore.load_owner(path))
        except Exception as error:  # noqa: BLE001 - report, never silently continue unsealed
            print(
                f"memory key {path!r} could not be used ({type(error).__name__}: {error}); "
                "conversation memory will be stored UNSEALED",
                file=sys.stderr,
                flush=True,
            )
    return MemoryStore(seal=False)


def _build_watchtower(mode: str, boundary: Any) -> Any:
    """Build the attacker-facing watchtower for this mode."""
    try:
        from aegis.watchtower import Watchtower

        ledger = getattr(getattr(boundary, "gateway", None), "ledger", None)
        return Watchtower(decoys=(mode == "production"), ledger=ledger)
    except Exception:  # noqa: BLE001 - telemetry must never stop the server
        return None


@dataclass
class _NoBoundary:
    """What the server answers with when AEGIS cannot be constructed at all.

    Without the optional crypto wheels there is no gateway to consult. In
    production that is a refusal (the server refuses to start at all); in
    development it is an explicitly labelled permit, so the reduced posture is
    visible in every single response instead of being an invisible bypass.
    """

    mode: str
    allowed: bool = field(init=False)
    #: No boundary means no rotation layer ran, so the caller's own bytes stand.
    payload: Any = None
    code: str = ""
    reason: str = ""
    human_reason: str = ""
    decision_id: str = ""
    ledger_seq: int = 0

    def __post_init__(self) -> None:
        self.allowed = self.mode != "production"
        if self.allowed:
            self.decision_id = "none"
            self.human_reason = "no crypto backend: AEGIS cannot be constructed"
        else:
            self.code = "ZN-SEC-0x4C02"
            self.reason = self.code
            self.human_reason = "no crypto backend: AEGIS cannot be constructed"

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "allowed": self.allowed,
            "enforcement": self.mode,
            "decision_id": self.decision_id,
            "aegis_available": False,
        }
        if self.code:
            out["code"] = self.code
        return out

    def owner_view(self) -> Dict[str, Any]:
        return self.to_dict() | {"human_reason": self.human_reason}


class Playground:
    """Everything the HTTP layer needs, with no per-request global state."""

    def __init__(
        self,
        provider: Optional[Provider] = None,
        *,
        policy: Any = None,
        boundary: Any = None,
        mode: Optional[str] = None,
        memory: Any = None,
        peers: Any = None,
    ) -> None:
        self.provider = provider or resolve()
        self.heuristic = HeuristicEncoder()
        self.kernel = default_kernel(generator=demo_generator)
        for name, tool in demo_tools().items():
            self.kernel.register(name, tool)
        # The authorization boundary is what stands between an HTTP request and
        # this kernel. ``mode`` decides how hard it is: see aegis/boundary.py.
        self.mode = mode or os.environ.get("ZENO_ENV") or "development"
        self.boundary = boundary if boundary is not None else _build_boundary(self.mode, policy)
        # The watchtower records every refusal, and in production it starts
        # tarpitting and feeding decoys once a source is flagged. Development mode
        # records too, but keeps answering honestly: a developer needs to see the
        # real error, not a plausible fake.
        self.watchtower = _build_watchtower(self.mode, self.boundary)
        # What the agent hears is kept, sealed to the owner's key when one is
        # configured; where it is not, the store says so on every record and the
        # health endpoint repeats it. Same rule as everywhere else: a degraded
        # posture is labelled, never implied.
        from zeno.memory import MemoryStore

        self.memory = memory if memory is not None else _build_memory()
        from zeno.peers import AgentRegistry

        self.peers = (
            peers
            if peers is not None
            else AgentRegistry(boundary=self.boundary, memory=self.memory)
        )
        from zeno.agent import VoiceAgent

        self.agent = VoiceAgent(
            self, memory=self.memory, boundary=self.boundary, provider=self.provider, peers=self.peers
        )
        #: Set by :meth:`authorize` for the duration of one request, so the
        #: handler can attach the permit (or the refusal) to its response.
        self.kernel_calls = 0

    # -- authorization -----------------------------------------------------
    @property
    def enforcement(self) -> str:
        """What is actually guarding effectful execution on this server."""
        if self.boundary is None:
            return "unavailable"
        return self.boundary.mode

    def authorize(
        self, caller: Any, payload: bytes, body: Mapping[str, Any], *, action: str = "execute"
    ) -> Any:
        """Ask AEGIS about this request, or refuse because AEGIS cannot be asked.

        A missing boundary is never an implicit permit: in production the server
        will not start without one, and in development every response says
        ``enforcement: development`` so the weaker posture is never silent.
        """
        from aegis.boundary import Caller, material_from_payload

        if self.boundary is None:
            return _NoBoundary(self.mode)
        return self.boundary.authorize(
            caller, payload, material_from_payload(body), action=action
        )

    def authorize_read(
        self, caller: Any, body: Mapping[str, Any], *, action: str = "read"
    ) -> Any:
        """Authorize the owner reading a view of this server.

        Reads are not executions: they are gated by the owner's grant and a
        nonce, not by the eight-layer execution chain. See
        :meth:`aegis.boundary.AuthorizationBoundary.authorize_read`.
        """
        from aegis.boundary import Caller, material_from_payload

        if self.boundary is None:
            return _NoBoundary(self.mode)
        return self.boundary.authorize_read(
            caller, material_from_payload(body), action=action
        )

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
        # X-Zeno-Capability carries the owner's grant on cross-origin reads (the
        # owner's own dashboard, reading the adversary feed from another origin).
        self.send_header(
            "Access-Control-Allow-Headers", "Content-Type, X-Zeno-Capability, Authorization"
        )
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

    #: The parsed body of the request in flight, for digesting. Never persisted raw.
    _last_body: bytes = b""

    def _caller(self, body: Mapping[str, Any]) -> Any:
        """The caller as the transport sees them. Claims, not identity."""
        self._last_body = b""
        from aegis.boundary import Caller

        actor = body.get("actor")
        if not (isinstance(actor, str) and actor.strip()):
            # clients that keep everything security-related in one block may put
            # the claimed identity there instead; either way it is a claim
            block = body.get("aegis")
            if isinstance(block, Mapping):
                candidate = block.get("actor")
                actor = candidate if isinstance(candidate, str) else actor
        return Caller(
            actor=actor if isinstance(actor, str) and actor.strip() else "anonymous",
            remote=str(self.client_address[0]) if self.client_address else "",
            user_agent=str(self.headers.get("User-Agent", ""))[:200],
            kind="agent" if isinstance(actor, str) and actor else "human",
        )

    def _refusal(self, permit: Any, *, path: str, body: Mapping[str, Any]) -> None:
        """Say no, watch who asked, and decide what they get.

        Production answers with a code and nothing else: which layer refused, and
        why, is the owner's information (invariants S20/S21/S23). Development
        answers readably, because a developer needs the sentence.
        """
        production = getattr(permit, "mode", "development") == "production"
        tower = self.playground.watchtower
        if tower is not None:
            actor = ""
            block = body.get("aegis")
            if isinstance(block, Mapping) and isinstance(block.get("actor"), str):
                actor = block["actor"]
            elif isinstance(body.get("actor"), str):
                actor = body["actor"]
            record, reaction = tower.observe(
                remote=str(self.client_address[0]) if self.client_address else "",
                method=str(self.command),
                path=path,
                actor_claimed=actor,
                user_agent=str(self.headers.get("User-Agent", "")),
                code=permit.code or "ZN-SEC-0x0B01",
                body=self._last_body,
                headers=dict(self.headers),
                note=permit.human_reason or permit.reason or "",
            )
            if reaction.tarpit_ms:
                slept = tower.apply_tarpit(reaction.tarpit_ms)
                record.tarpit_ms = slept
            if reaction.decoy:
                # Flagged source: answer with a fabricated success instead of a
                # refusal, so the attempt continues to be observable while the
                # kernel is never touched. Fabricated means fabricated: see
                # aegis/watchtower.py.
                self._json(tower.decoy(path=path), 200)
                return

        if production:
            self._json({"error": {"code": permit.code or "ZN-SEC-0x0B01"}}, 403)
            return
        self._json(
            {
                "error": {
                    "code": permit.code or "ZN-SEC-0x0B01",
                    "message": permit.human_reason or permit.reason or "refused",
                },
                "aegis": permit.to_dict(),
            },
            403,
        )

    def _watchtower_view(self, limit: int = 20) -> Dict[str, Any]:
        tower = self.playground.watchtower
        if tower is None:
            return {"enabled": False}
        return tower.summary() | {
            "alerts": tower.alerts(limit),
            "intruders": tower.intruders(),
            "recent": tower.recent(limit),
        }

    def _json(self, payload: Any, status: int = 200) -> None:
        self._send(status, json.dumps(payload, default=str).encode("utf-8"), "application/json")

    def _error(self, exc: Exception, status: int = 400) -> None:
        if isinstance(exc, ZenoError):
            self._json({"error": exc.to_dict(), "rendered": exc.render()}, status)
        else:  # pragma: no cover - defensive
            self._json({"error": {"code": "ZN0000", "message": str(exc)}}, 500)

    def _query(self) -> Dict[str, str]:
        """The query string as a dict. Values are length-capped; this is input."""
        from urllib.parse import unquote_plus

        raw = self.path.split("?", 1)[1] if "?" in self.path else ""
        pairs = (pair.split("=", 1) for pair in raw.split("&") if "=" in pair)
        return {key: unquote_plus(value)[:200] for key, value in pairs}

    def _authorize_once(
        self,
        *,
        action: str,
        read: bool = False,
        body: Optional[Mapping[str, Any]] = None,
        payload: bytes = b"",
    ) -> Any:
        """Ask the boundary exactly once for this request.

        The authorization is passed on to whatever does the work, so a single
        request is one decision -- authorizing twice would double-count the request
        in the guardian's behavioural profile, and a conversation is already a
        burst of requests by nature.

        The grant may arrive in the ``aegis`` block of the body or in the
        ``X-Zeno-Capability`` header (the dashboard's habit); the header wins only
        when the body did not carry one, so a body cannot be downgraded by a
        stray header.
        """
        merged = dict(body or {})
        block = merged.get("aegis")
        block = dict(block) if isinstance(block, Mapping) else {}
        header = self._capability_block()
        if header.get("token") and not (block.get("token") or "").strip():
            block["token"] = header["token"]
        query_nonce = self._query().get("nonce", "")
        if query_nonce and not (block.get("nonce") or "").strip():
            block["nonce"] = query_nonce
        if block:
            merged["aegis"] = block
        caller = self._caller(merged)
        if read:
            return self.playground.authorize_read(caller, merged, action=action)
        return self.playground.authorize(caller, payload, merged, action=action)

    def _permit(
        self,
        path: str,
        *,
        action: str,
        read: bool = False,
        body: Optional[Mapping[str, Any]] = None,
        payload: bytes = b"",
    ) -> bool:
        """``_authorize_once`` plus the standard refusal answer.

        Returns ``True`` when a refusal has already been sent, ``False`` when the
        caller may proceed. Reads go through the read gate, effects through the
        effectful one -- the same split the boundary documents.
        """
        permit = self._authorize_once(action=action, read=read, body=body, payload=payload)
        if not permit.allowed:
            self._refusal(permit, path=path, body=body or {})
            return True
        return False

    def _capability_block(self) -> Dict[str, Any]:
        """The owner's grant, when it arrives in a header.

        A header keeps a bearer token out of URLs, and therefore out of logs and
        referrers. ``Authorization: Zeno <token>`` and ``X-Zeno-Capability`` are
        both accepted; anything else is not looked at.
        """
        token = self.headers.get("X-Zeno-Capability", "").strip()
        if not token:
            header = self.headers.get("Authorization", "").strip()
            if header.lower().startswith("zeno "):
                token = header[5:].strip()
        return {"token": token} if token else {}

    def _body(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        if length > MAX_BODY:
            raise ValueError("request body too large")
        payload = self.rfile.read(length)
        # Kept for the watchtower to *digest*, never to store: what an attacker
        # sent is evidence, and evidence is hashed, not archived.
        self._last_body = payload
        return json.loads(payload.decode("utf-8") or "{}")

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
                health = {"ok": True, "time": time.time(), **self.playground.provider_info()}
                health["enforcement"] = self.playground.enforcement
                if self.playground.boundary is not None:
                    health["policy"] = self.playground.boundary.policy.to_dict()
                else:
                    health["policy"] = {"mode": self.playground.mode, "aegis_available": False}
                health["memory"] = self.playground.memory.describe()
                health["agents"] = self.playground.peers.describe()
                self._json(health)
                return
            if path == "/api/grammar":
                self._json(self.playground.grammar())
                return
            if path == "/api/tools":
                self._json(self.playground.tools())
                return
            if path in ("/admin", "/admin/"):
                # The admin console is a page: downloading it needs no grant, and
                # every panel it can fill is authorized route by route.
                self._file("admin.html")
                return
            if path in ("/voice", "/voice/"):
                # The page is a page: it needs no authorization to be downloaded,
                # and everything it can *do* is authorized route by route.
                self._file("voice.html")
                return
            if path == "/api/memory/sessions":
                if self._permit(path, action="read:memory", read=True):
                    return
                self._json({"sessions": self.playground.memory.sessions()})
                return
            if path == "/api/memory/session":
                if self._permit(path, action="read:memory", read=True):
                    return
                query = self._query()
                session = query.get("id", "")
                try:
                    limit = max(1, min(int(query.get("limit", "200")), 2000))
                except ValueError:
                    limit = 200
                self._json(
                    {
                        "session": session,
                        "records": self.playground.memory.read(session, limit=limit),
                        "memory": self.playground.memory.describe(),
                    }
                )
                return
            if path == "/api/memory/verify":
                if self._permit(path, action="read:memory", read=True):
                    return
                self._json(self.playground.memory.verify())
                return
            if path == "/api/agents":
                if self._permit(path, action="read:agents", read=True):
                    return
                self._json({"agents": self.playground.peers.peers(), "bridge": self.playground.peers.describe()})
                return
            if path == "/api/admin/decisions":
                if self._permit(path, action="read:decisions", read=True):
                    return
                boundary = self.playground.boundary
                if boundary is None:
                    self._json({"enabled": False, "decisions": []})
                    return
                query = self._query()
                try:
                    limit = max(1, min(int(query.get("limit", "25")), 100))
                except ValueError:
                    limit = 25
                # The owner's view of each decision: code, sentence, layer
                # verdicts -- exactly what a caller is never shown (S20/S21/S23).
                decisions = [item.owner_view() for item in list(boundary.recent)[:limit]]
                self._json(
                    {
                        "enabled": True,
                        "attempts": boundary.attempts,
                        "permitted": boundary.permitted,
                        "refused": boundary.refused,
                        "decisions": decisions,
                    }
                )
                return
            if path == "/api/voice/health":
                self._json(
                    {
                        "memory": self.playground.memory.describe(),
                        "agents": self.playground.peers.describe(),
                        "provider": self.playground.provider_info(),
                        "enforcement": self.playground.enforcement,
                    }
                )
                return
            if path == "/api/watchtower":
                # The feed names who attacked this host and how often: that is the
                # owner's business. It is a read, so it is authorized as one — the
                # owner's grant plus a fresh nonce, never an execution.
                query = self._query()
                material = {**self._capability_block(), "nonce": query.get("nonce", "")}
                permit = self.playground.authorize_read(
                    self._caller({}), {"aegis": material}, action="read:watchtower"
                )
                if not permit.allowed:
                    self._refusal(permit, path=path, body={})
                    return
                try:
                    limit = max(1, min(int(query.get("limit", "25")), 200))
                except ValueError:
                    limit = 25
                self._json(self._watchtower_view(limit))
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
                # Audit finding C1: this route used to call the kernel directly.
                # Nothing effectful runs until the boundary permits it.
                permit = self.playground.authorize(
                    self._caller(body), payload.encode("utf-8"), body, action="execute:zeno"
                )
                if not permit.allowed:
                    self._refusal(permit, path=path, body=body)
                    return
                executed = getattr(permit, "payload", None)
                result = self.playground.run(
                    executed.decode("utf-8") if isinstance(executed, (bytes, bytearray)) else payload,
                    state,
                )
                result["aegis"] = permit.to_dict()
                self._json(result)
                return
            if path == "/api/ask":
                text = str(body.get("text", ""))
                if not text.strip():
                    self._json({"error": {"code": "ZN0003", "message": "text is required"}}, 400)
                    return
                permit = self.playground.authorize(
                    self._caller(body), text.encode("utf-8"), body, action="execute:ask"
                )
                if not permit.allowed:
                    self._refusal(permit, path=path, body=body)
                    return
                executed = getattr(permit, "payload", None)
                result = self.playground.ask(
                    executed.decode("utf-8") if isinstance(executed, (bytes, bytearray)) else text,
                    body.get("state") or {},
                )
                result["aegis"] = permit.to_dict()
                self._json(result)
                return
            if path == "/api/voice/turn":
                # The utterance is authorized in its encoded wire form: a canonical
                # Zeno payload, which is what layer 6 can vouch for. Encoding is the
                # same pure, public transform as /api/encode -- nothing is answered,
                # sent or stored until the boundary has allowed the turn.
                text = str(body.get("text", ""))
                wire = text
                try:
                    encoded = self.playground.encode(text).get("payload")
                    if isinstance(encoded, str) and encoded.strip():
                        wire = encoded
                except ZenoError:
                    pass
                permit = self._authorize_once(
                    action="agent:turn", body=body, payload=wire.encode("utf-8")
                )
                if not permit.allowed:
                    self._refusal(permit, path=path, body=body)
                    return
                wav = None
                if body.get("audio_b64"):
                    import base64

                    from zeno.agent import wav_from_pcm

                    try:
                        wav = wav_from_pcm(
                            base64.b64decode(str(body["audio_b64"]), validate=True),
                            sample_rate=int(body.get("sample_rate") or 16_000),
                            channels=int(body.get("channels") or 1),
                        )
                    except Exception as error:  # noqa: BLE001 - unreadable audio is not a reason to fail the turn
                        wav = None
                        body["_audio_error"] = f"{type(error).__name__}: {error}"
                turn = self.playground.agent.turn(
                    session=str(body.get("session") or "voice"),
                    text=str(body.get("text", "")),
                    lang=str(body.get("lang", "")),
                    audio_wav=wav,
                    caller=self._caller(body),
                    authorization=permit,
                )
                turn["aegis"] = permit.to_dict()
                if body.get("_audio_error"):
                    turn.setdefault("notes", []).append(f"audio was not readable: {body['_audio_error']}")
                self._json(turn)
                return
            if path == "/api/memory/search":
                if self._permit(path, action="read:memory", read=True, body=body):
                    return
                query = str(body.get("query", ""))
                limit = max(1, min(int(body.get("limit") or 50), 500))
                self._json({"query": query, "hits": self.playground.memory.search(query, limit=limit)})
                return
            if path == "/api/memory/forget":
                session = str(body.get("session", ""))
                if not session:
                    self._json({"error": {"code": "ZN0003", "message": "session is required"}}, 400)
                    return
                if self._permit(path, action="memory:forget", body=body, payload=session.encode("utf-8")):
                    return
                removed = self.playground.memory.forget(session)
                self._json({"session": session, "removed": removed})
                return
            if path == "/api/agents":
                action = "agent:register" if body.get("name") else "agent:ask"
                if self._permit(path, action=action, body=body, payload=str(body).encode("utf-8")[:512]):
                    return
                self._json(
                    {
                        "agent": self.playground.peers.register(
                            str(body.get("name", "")),
                            str(body.get("endpoint", "")),
                            capability=str(body.get("capability", "")),
                            languages=[str(item) for item in (body.get("languages") or [])],
                            description=str(body.get("description", "")),
                        )
                    }
                )
                return
            if path == "/api/agents/remove":
                if self._permit(path, action="agent:register", body=body, payload=str(body.get("name", "")).encode("utf-8")):
                    return
                name = str(body.get("name", ""))
                self._json({"removed": self.playground.peers.unregister(name), "name": name})
                return
            if path == "/api/agents/ask":
                permit = self._authorize_once(
                    action="agent:peer", body=body, payload=str(body.get("text", "")).encode("utf-8")
                )
                if not permit.allowed:
                    self._refusal(permit, path=path, body=body)
                    return
                self._json(
                    self.playground.peers.ask(
                        str(body.get("name", "")),
                        str(body.get("text", "")),
                        lang=str(body.get("lang") or "en"),
                        session=str(body.get("session") or "peers"),
                        caller=self._caller(body),
                        authorization=permit,
                    )
                )
                return
            if path == "/api/agents/broadcast":
                permit = self._authorize_once(
                    action="agent:peer", body=body, payload=str(body.get("text", "")).encode("utf-8")
                )
                if not permit.allowed:
                    self._refusal(permit, path=path, body=body)
                    return
                names = body.get("names")
                self._json(
                    self.playground.peers.broadcast(
                        str(body.get("text", "")),
                        lang=str(body.get("lang") or "en"),
                        session=str(body.get("session") or "peers"),
                        names=[str(item) for item in names] if isinstance(names, list) else None,
                        caller=self._caller(body),
                        authorization=permit,
                    )
                )
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


def build_app(provider: Optional[Provider] = None, *, mode: Optional[str] = None) -> Playground:
    """The application object behind the HTTP handler (used by tests too)."""
    return Playground(provider, mode=mode)


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
    mode: Optional[str] = None,
) -> int:
    """Run the playground until interrupted.

    Returns a process exit code: production mode refuses to start without a
    working AEGIS boundary, because a production server whose authorization
    layer is unavailable is exactly the hole this is meant to close.
    """
    mode = mode or os.environ.get("ZENO_ENV") or "development"
    playground = build_app(provider, mode=mode)
    if mode == "production" and playground.boundary is None:
        print(
            "refusing to start: production mode needs the AEGIS boundary, which could not "
            "be constructed.\nInstall the crypto backend: python -m pip install -e .[aegis]",
            file=sys.stderr,
            flush=True,
        )
        return 3
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
    if playground.enforcement == "production":
        mandatory = ", ".join(playground.boundary.policy.mandatory_layers)
        print(f"  enforcement: PRODUCTION — all layers mandatory: {mandatory}", flush=True)
        print("  refusals return machine codes only; the ledger holds the reasons", flush=True)
    else:
        why = (
            "no crypto backend: AEGIS cannot be constructed, so /api/run and /api/ask "
            "execute with no authorization layer"
            if playground.boundary is None
            else "layers 2, 3, 6 and 8 are not required"
        )
        print(f"  enforcement: DEVELOPMENT — not a production posture ({why})", flush=True)
        print("  run with --production (or ZENO_ENV=production) to require all eight layers",
              flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:  # pragma: no cover - interactive
        pass
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(serve(port=int(os.environ.get("ZENO_PORT", "8000"))))
