"""Command line interface: ``python -m zeno <command>``.

    $ python -m zeno encode "Check the weather in Tokyo and suggest three indoor ideas"
    @LOC[TYO] -> ?WX : { $WX.state == RAIN => !GEN[INDOOR, 3] | !GEN[OUTDOOR, 3] }

    $ python -m zeno run '@LOC[TYO] -> ?WX'
    $ python -m zeno run --tools examples.tools:tools '?DEPLOY.status' 
    $ python -m zeno tokens "@LOC[TYO] -> ?WX"
    $ python -m zeno check "@LOC[TYO] -> ?WX : { $WX.state == RAIN => !GEN[INDOOR, 3] }"

Commands are intentionally composable: every command accepts ``--json`` so the
CLI doubles as a scripting surface for other agents.
"""

from __future__ import annotations

import argparse
import importlib
import json
import os
import time
import sys
from typing import Any, Dict, List, Optional

from .config import PROVIDER_PRESETS, load_settings
from .decoder import Decoder
from .emitter import emit
from .encoder import Encoder
from .errors import ZenoError
from .parser import parse
from .pipeline import Pipeline
from .prompts import grammar_card
from .providers import list_providers, resolve
from .runtime import Kernel, result_frame
from .tools import demo_generator, demo_tools
from .tokenizer import count_tokens, counting_method
from .validator import validate

__all__ = ["main", "build_parser"]


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
def _print_json(payload: Any) -> None:
    json.dump(payload, sys.stdout, indent=2, ensure_ascii=False, default=str)
    sys.stdout.write("\n")


def _load_state(raw: Optional[str]) -> Dict[str, Any]:
    if not raw:
        return {}
    if raw.startswith("@"):
        with open(raw[1:], "r", encoding="utf-8") as handle:
            return json.load(handle)
    try:
        loaded = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"--state must be JSON or @file.json ({exc})") from exc
    if not isinstance(loaded, dict):
        raise SystemExit("--state must be a JSON object")
    return loaded


def _load_tools(spec: Optional[str]) -> Dict[str, Any]:
    """``module:factory`` import hook so the CLI can run real tools."""
    if not spec:
        return {}
    module_name, _, attribute = spec.partition(":")
    module = importlib.import_module(module_name)
    factory = getattr(module, attribute) if attribute else module
    produced = factory() if callable(factory) else factory
    if not isinstance(produced, dict):
        raise SystemExit(f"tools factory {spec!r} must return a dict of tools")
    return produced


def _build_kernel(args: argparse.Namespace) -> Kernel:
    """Build the kernel the run/ask/decode commands execute against.

    The bundled demo tools load first so the CLI works out of the box
    (``zeno run '@LOC[TYO] -> ?WX'``); ``--tools module:factory`` adds or
    overrides entries and ``--no-tools`` gives a bare kernel.
    """
    kernel = Kernel(
        generator=demo_generator,
        trace=getattr(args, "trace", False),
        echo=lambda text: print(text, file=sys.stderr),
    )
    if not getattr(args, "no_tools", False):
        for name, fn in demo_tools().items():
            kernel.register(name, fn)
    for name, fn in _load_tools(getattr(args, "tools", None)).items():
        kernel.register(name, fn)
    return kernel


def _provider_for(args: argparse.Namespace):
    provider = getattr(args, "provider", None)
    model = getattr(args, "model", None)
    if provider is None and model is None:
        return resolve()
    return resolve(provider, model=model)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
def cmd_encode(args: argparse.Namespace) -> int:
    text = " ".join(args.text).strip() or sys.stdin.read().strip()
    encoder = Encoder(_provider_for(args), tools=args.available)
    result = encoder.encode(text)
    if args.json:
        _print_json(result.to_dict())
    else:
        print(result.payload)
        if args.stats:
            print(
                f"# {result.nl_tokens} NL tokens -> {result.zeno_tokens} Zeno tokens "
                f"({result.token_reduction:.1f} % reduction)",
                file=sys.stderr,
            )
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    source = " ".join(args.payload).strip() or sys.stdin.read().strip()
    kernel = _build_kernel(args)
    result = kernel.execute(source, state=_load_state(args.state))
    if args.json:
        _print_json(result.to_dict() | {"frame": result_frame(result)})
    else:
        print(result_frame(result))
        print(f"# output: {result.output}", file=sys.stderr)
    return 0


def cmd_ask(args: argparse.Namespace) -> int:
    text = " ".join(args.text).strip() or sys.stdin.read().strip()
    provider = _provider_for(args)
    pipeline = Pipeline(
        encoder=Encoder(provider, tools=args.available),
        kernel=_build_kernel(args),
        decoder=None if args.no_decode else Decoder(provider),
    )
    outcome = pipeline.run(text, state=_load_state(args.state))
    if args.json:
        _print_json(outcome.to_dict())
    else:
        print(outcome.transcript())
    return 0


def cmd_decode(args: argparse.Namespace) -> int:
    source = " ".join(args.payload).strip() or sys.stdin.read().strip()
    execution = Kernel().execute(source, state=_load_state(args.state))
    decoded = Decoder(_provider_for(args)).decode(execution, request=args.request)
    if args.json:
        _print_json(decoded.to_dict())
    else:
        print(decoded.text)
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    source = " ".join(args.payload).strip() or sys.stdin.read().strip()
    report = validate(source)
    if args.json:
        _print_json(report.to_dict())
    else:
        print(report.render(color=sys.stdout.isatty()))
    if report.program is not None and args.canonical:
        print(emit(report.program))
    return 0 if report.ok else 1


def cmd_tokens(args: argparse.Namespace) -> int:
    counts: Dict[str, int] = {}
    for chunk in args.text:
        counts[chunk] = count_tokens(chunk)
    if args.json:
        _print_json({"method": counting_method(args.model), "counts": counts})
        return 0
    print(f"# tokenizer: {counting_method(args.model)}")
    for chunk, count in counts.items():
        preview = chunk if len(chunk) <= 60 else chunk[:57] + "..."
        print(f"{count:6d}  {preview}")
    return 0


def cmd_grammar(args: argparse.Namespace) -> int:
    if args.json:
        from .spec import tokens

        _print_json(tokens())
    else:
        print(grammar_card())
    return 0


def cmd_providers(args: argparse.Namespace) -> int:
    detected = load_settings().provider
    payload = {
        "default": detected,
        "settings": load_settings().to_dict(),
        "available": list_providers(),
        "presets": {slug: preset["model"] for slug, preset in PROVIDER_PRESETS.items()},
    }
    if args.json:
        _print_json(payload)
        return 0
    print(f"default provider : {detected}")
    print(f"model            : {load_settings().model or '(unset)'}")
    print(f"configured       : {load_settings().configured}")
    print("transports       : " + ", ".join(sorted(list_providers())))
    print("presets          : " + ", ".join(sorted(PROVIDER_PRESETS)))
    return 0


def cmd_benchmark(args: argparse.Namespace) -> int:
    """Density (per message) and, unless asked otherwise, the A2A loop."""
    from benchmarks.token_comparison import main as density_main

    argv: List[str] = []
    if args.json:
        argv.append("--json")
    if args.corpus:
        argv.extend(["--corpus", args.corpus])
    status = density_main(argv)

    if getattr(args, "density_only", False):
        return status

    from benchmarks.conversation_test import main as conversation_main

    conversation_status = conversation_main(["--json"] if args.json else [])
    # A miss on the 75 % brief target is a finding, not a crash; both benchmarks
    # report exit 1 for it, and the caller sees the same from `zeno benchmark`.
    return status or conversation_status


def cmd_latency(args: argparse.Namespace) -> int:
    from benchmarks.latency_test import main as latency_main

    argv = ["--json"] if args.json else []
    if args.repeat:
        argv.extend(["--repeat", str(args.repeat)])
    return latency_main(argv)


def cmd_serve(args: argparse.Namespace) -> int:
    from .server import serve

    mode = "production" if args.production else ("development" if args.development else None)
    if args.production and args.development:
        print("--production and --dev contradict each other", file=sys.stderr)
        return 2
    return serve(
        host=args.host,
        port=args.port,
        allowed_origins=args.allow_origin,
        mode=mode,
    )


def cmd_dashboard(args: argparse.Namespace) -> int:
    """Export the snapshot the static (GitHub Pages) dashboard reads offline."""
    from .server import build_app, snapshot_bytes

    payload = snapshot_bytes(build_app())

    from pathlib import Path

    target = Path(args.path).expanduser().resolve()
    if args.check:
        try:
            current = target.read_bytes()
        except OSError as error:
            print(f"cannot read {target}: {error}", file=sys.stderr)
            return 1
        if current == payload:
            print(f"up to date: {target} ({len(payload)} bytes)")
            return 0
        print(
            f"STALE: {target} differs from the generated snapshot "
            f"({len(current)} bytes on disk, {len(payload)} expected).\n"
            f"Run: zeno dashboard --write",
            file=sys.stderr,
        )
        return 1
    if args.stdout or args.json or not args.write:
        sys.stdout.write(payload.decode("utf-8"))
        return 0

    target.write_bytes(payload)
    print(f"wrote {target} ({len(payload)} bytes)")
    if args.print_path:
        print(target)
    return 0


def cmd_voice(args: argparse.Namespace) -> int:
    """Serve the whole thing and hand you the URL of the talking page."""
    from zeno.server import serve

    print("voice agent: open  http://{host}:{port}/voice".format(
        host="localhost" if args.host in ("0.0.0.0", "::") else args.host, port=args.port))
    if args.memory_key:
        os.environ["ZENO_MEMORY_KEY"] = args.memory_key
    print(f"  memory key : {os.environ.get('ZENO_MEMORY_KEY') or 'not set — memory will be stored UNSEALED'}")
    print("  languages  : any BCP-47 tag; speech in/out is done by your browser")
    return serve(host=args.host, port=args.port, mode=args.mode)


def cmd_memory(args: argparse.Namespace) -> int:
    """The owner's view of what was said, from the command line."""
    from zeno.memory import MemoryStore

    action = args.memory_action
    if action == "init-key":
        if not args.key:
            args.key = os.path.expanduser("~/.zeno/memory.key")
        try:
            target = MemoryStore.create_owner(args.key)
        except FileExistsError as error:
            print(str(error), file=sys.stderr)
            return 1
        print(f"memory key created: {target} (mode 0600)")
        print("point the server at it:  export ZENO_MEMORY_KEY=" + str(target))
        return 0

    owner = None
    if args.key or os.environ.get("ZENO_MEMORY_KEY"):
        from zeno.memory import MemoryStore as _Store

        try:
            owner = _Store.load_owner(args.key or os.environ["ZENO_MEMORY_KEY"])
        except Exception as error:  # noqa: BLE001 - the owner is told, not guessed at
            print(f"cannot use the memory key: {error}", file=sys.stderr)
            return 1
    store = MemoryStore(args.root, owner=owner)

    if action == "list":
        sessions = store.sessions()
        if not sessions:
            print("nothing stored yet")
            return 0
        print(f"{'session':<28} {'records':>8}  {'languages':<16} last")
        for item in sessions:
            print(
                f"{item['id']:<28} {item['turns']:>8}  "
                f"{(','.join(item['languages']) or '-'):<16} {time.strftime('%Y-%m-%d %H:%M', time.localtime(item['last_at']))}"
            )
        return 0
    if action == "show":
        if not args.session:
            print("which session? `zeno memory list` shows them", file=sys.stderr)
            return 1
        for record in store.read(args.session, limit=args.limit):
            stamp = time.strftime("%H:%M:%S", time.localtime(record.get("at", 0)))
            print(f"[{stamp}] {record.get('role', '?'):>6}: {record.get('text', '')}")
        return 0
    if action == "search":
        if not args.query:
            print("what should I look for?", file=sys.stderr)
            return 1
        hits = store.search(args.query, limit=args.limit)
        for record in hits:
            print(f"{record.get('session')} {record.get('role')}: {record.get('text')}")
        print(f"--- {len(hits)} match(es): a substring scan over decrypted records, not a semantic index")
        return 0
    if action == "verify":
        report = store.verify(args.session or None)
        print(json.dumps(report, indent=2, default=str))
        return 0 if report["ok"] else 2
    if action == "forget":
        if not args.session:
            print("which session?", file=sys.stderr)
            return 1
        removed = store.forget(args.session)
        print(f"forgot {args.session}: {removed} record(s) deleted")
        return 0
    if action == "where":
        print(json.dumps(store.describe(), indent=2, default=str))
        return 0
    print(f"unknown memory action {action!r}", file=sys.stderr)
    return 2


def cmd_agents(args: argparse.Namespace) -> int:
    """Connected agents, from the command line."""
    from zeno.peers import AgentRegistry

    registry = AgentRegistry(args.file)
    action = args.agents_action
    if action == "list":
        print(json.dumps(registry.describe(), indent=2))
        for peer in registry.peers():
            print(f"  {peer['name']:<20} {peer['endpoint']:<44} calls={peer['calls']} failures={peer['failures']}")
        return 0
    if action == "add":
        if not args.name or not args.endpoint:
            print("need --name and --endpoint", file=sys.stderr)
            return 1
        print(json.dumps(registry.register(args.name, args.endpoint, capability=args.capability or ""), indent=2))
        return 0
    if action == "remove":
        print("removed" if registry.unregister(args.name or "") else "no such agent")
        return 0
    if action == "ask":
        if not args.name or not args.text:
            print("need --name and --text", file=sys.stderr)
            return 1
        outcome = registry.ask(args.name, args.text, lang=args.lang, session="cli")
        print(json.dumps(outcome, indent=2, default=str))
        return 0 if outcome.get("ok") else 1
    if action == "broadcast":
        if not args.text:
            print("need --text", file=sys.stderr)
            return 1
        outcome = registry.broadcast(args.text, lang=args.lang, session="cli")
        print(json.dumps(outcome, indent=2, default=str))
        return 0 if outcome.get("ok") else 1
    print(f"unknown agents action {action!r}", file=sys.stderr)
    return 2


def cmd_watchtower(args: argparse.Namespace) -> int:
    """Show who has been attacking this deployment.

    Reads the on-disk feed by default, so it works even when the server is down;
    ``--server`` asks a running server instead, which also shows what is currently
    tarpitted and how many decoys have been served.
    """
    from aegis.watchtower import DEFAULT_FEED, Watchtower

    live: Optional[Dict[str, Any]] = None
    if args.server:
        import urllib.request

        url = args.server.rstrip("/") + "/api/watchtower?limit=" + str(args.tail)
        try:
            with urllib.request.urlopen(url, timeout=args.timeout) as response:
                live = json.loads(response.read())
        except Exception as error:  # noqa: BLE001
            print(f"could not read {url}: {type(error).__name__}: {error}", file=sys.stderr)
            return 1

    tower = Watchtower(feed=args.feed)
    records = tower.read_feed(args.tail)
    if live:
        records = list(reversed(live.get("recent", []))) or records

    if args.clear:
        removed = tower.clear()
        try:
            pathlib.Path(os.path.expanduser(args.feed)) if False else None
        except Exception:
            pass
        print(f"cleared {removed} source entries from the live view (the feed file is kept)")
        if not records:
            return 0

    payload = {
        "feed": os.path.expanduser(args.feed or DEFAULT_FEED),
        "records": records,
        "count": len(records),
        "summary": (live or {}).get("summary") if args.summary and live else None,
        "alerts": (live or {}).get("alerts", []),
        "intruders": (live or {}).get("intruders", {}),
    }
    if args.json:
        print(json.dumps(payload, indent=2, default=str))
        return 0

    if not records:
        print("no refused attempts recorded yet")
        print(f"  feed: {payload['feed']}")
        return 0

    print(f"{len(records)} refused attempts  ({payload['feed']})")
    print(f"{'when':<20} {'source':<16} {'strikes':>7} {'code':<16} {'path':<12} note")
    for record in records:
        print(
            f"{record.get('at_iso', ''):<20} {record.get('remote', ''):<16} "
            f"{record.get('strike', 0):>7} {record.get('code', ''):<16} "
            f"{record.get('path', ''):<12} {str(record.get('note', ''))[:40]}"
        )
    intruders = payload["intruders"]
    if intruders:
        print()
        print(f"flagged sources ({len(intruders)}):")
        for source, info in intruders.items():
            print(
                f"  {source:<16} strikes={info.get('strikes')} "
                f"user-agent={info.get('user_agent') or '-'} fp={info.get('client_fingerprint', '')[:12]}"
            )
    for alert in payload["alerts"]:
        print(f"  ALERT {alert.get('at_iso', '')} {alert.get('message', '')}")
    print()
    print("limits: a tarpit delays rather than stops; decoys are fabricated;")
    print("        legitimate traffic is never delayed and never receives a decoy")
    return 0


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="zeno",
        description="Zeno Protocol — dense A2A language tooling (Grammar v0.1).",
    )
    from . import __version__

    parser.add_argument("--version", action="version", version=f"zeno-lang {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_provider_flags(target: argparse.ArgumentParser) -> None:
        target.add_argument("--provider", help="openai | groq | ollama | mock | none …")
        target.add_argument("--model", help="override the model id")
        target.add_argument("--json", action="store_true", help="machine-readable output")

    encode = sub.add_parser("encode", help="convert natural language into Zeno")
    encode.add_argument("text", nargs="*")
    encode.add_argument("--available", nargs="*", help="tool names the receiver exposes")
    encode.add_argument("--stats", action="store_true", help="print token stats to stderr")
    add_provider_flags(encode)
    encode.set_defaults(func=cmd_encode)

    run = sub.add_parser("run", help="execute a Zeno payload")
    run.add_argument("payload", nargs="*")
    run.add_argument("--state", help="JSON object or @file.json seed for latent state")
    run.add_argument("--tools", help="module:factory providing {name: fn} tools")
    run.add_argument("--no-tools", action="store_true", help="do not load the bundled demo tools")
    run.add_argument("--trace", action="store_true", help="log each tool call to stderr")
    run.add_argument("--json", action="store_true")
    run.set_defaults(func=cmd_run)

    ask = sub.add_parser("ask", help="full round trip: NL -> Zeno -> execute -> NL")
    ask.add_argument("text", nargs="*")
    ask.add_argument("--state")
    ask.add_argument("--tools")
    ask.add_argument("--no-tools", action="store_true")
    ask.add_argument("--available", nargs="*")
    ask.add_argument("--no-decode", action="store_true", help="skip stage 3")
    ask.add_argument("--trace", action="store_true")
    add_provider_flags(ask)
    ask.set_defaults(func=cmd_ask)

    decode = sub.add_parser("decode", help="execute then render a payload as prose")
    decode.add_argument("payload", nargs="*")
    decode.add_argument("--request", help="the original natural-language request")
    decode.add_argument("--state")
    add_provider_flags(decode)
    decode.set_defaults(func=cmd_decode)

    check = sub.add_parser("check", help="validate and canonicalise a payload")
    check.add_argument("payload", nargs="*")
    check.add_argument("--canonical", action="store_true", help="print the canonical form")
    check.add_argument("--json", action="store_true")
    check.set_defaults(func=cmd_check)

    tokens = sub.add_parser("tokens", help="count tokens for one or more strings")
    tokens.add_argument("text", nargs="+")
    tokens.add_argument("--model", help="model id used to pick the encoding")
    tokens.add_argument("--json", action="store_true")
    tokens.set_defaults(func=cmd_tokens)

    grammar = sub.add_parser("grammar", help="print the grammar card or the token table")
    grammar.add_argument("--json", action="store_true")
    grammar.set_defaults(func=cmd_grammar)

    providers = sub.add_parser("providers", help="show provider configuration")
    providers.add_argument("--json", action="store_true")
    providers.set_defaults(func=cmd_providers)

    benchmark = sub.add_parser("benchmark", help="run the token-reduction benchmark")
    benchmark.add_argument("--corpus", help="path to a JSON corpus")
    benchmark.add_argument(
        "--density-only", action="store_true", help="skip the multi-turn A2A benchmark"
    )
    benchmark.add_argument("--json", action="store_true")
    benchmark.set_defaults(func=cmd_benchmark)

    latency = sub.add_parser("latency", help="run the stage latency benchmark")
    latency.add_argument("--repeat", type=int, default=5)
    latency.add_argument("--json", action="store_true")
    latency.set_defaults(func=cmd_latency)

    tower = sub.add_parser(
        "watchtower", help="who has been refused, and what was done about it"
    )
    tower.add_argument("--feed", default="", help="path to the intrusion feed (default ~/.zeno/watchtower.jsonl)")
    tower.add_argument("--tail", type=int, default=25, help="how many recent attempts to show")
    tower.add_argument("--server", default="", help="query a running server instead of the file")
    tower.add_argument("--timeout", type=float, default=5.0, help="seconds to wait for the server")
    tower.add_argument("--summary", action="store_true", help="include the live counters")
    tower.add_argument("--clear", action="store_true", help="clear the live view (the feed file is kept)")
    tower.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
    tower.set_defaults(func=cmd_watchtower)

    dashboard = sub.add_parser(
        "dashboard", help="export the static dashboard snapshot (dashboard-data.json)"
    )
    dashboard.add_argument(
        "--check", action="store_true", help="verify the committed snapshot is up to date; exit 1 if stale"
    )
    dashboard.add_argument("--write", action="store_true", help="write the file instead of printing it")
    dashboard.add_argument("--path", default="dashboard-data.json", help="where to write the snapshot")
    dashboard.add_argument("--stdout", action="store_true", help="print the snapshot to stdout")
    dashboard.add_argument("--print-path", action="store_true", help="print the absolute path as well")
    dashboard.add_argument("--json", action="store_true")
    dashboard.set_defaults(func=cmd_dashboard)

    voice = sub.add_parser(
        "voice", help="serve the agent you can talk to: audio in, audio out, any language"
    )
    voice.add_argument("--host", default=os.environ.get("ZENO_HOST", "0.0.0.0"))
    voice.add_argument("--port", type=int, default=int(os.environ.get("ZENO_PORT", "8000")))
    voice.add_argument(
        "--memory-key",
        default="",
        help="owner identity that seals what you say (defaults to $ZENO_MEMORY_KEY)",
    )
    voice.add_argument(
        "--mode",
        choices=["development", "production"],
        default=None,
        help="enforcement for the agent surface (default: $ZENO_ENV or development)",
    )
    voice.set_defaults(func=cmd_voice)

    memory = sub.add_parser(
        "memory", help="what the agent heard, read by the owner who holds the key"
    )
    memory.add_argument(
        "memory_action",
        choices=["list", "show", "search", "verify", "forget", "where", "init-key"],
        help="list sessions, show one, search, verify the chain, forget one, where it lives, or mint a key",
    )
    memory.add_argument("--root", default=None, help="memory root (default ~/.zeno/memory)")
    memory.add_argument("--key", default="", help="owner identity file that seals memory")
    memory.add_argument("--session", default="", help="session id (show / verify / forget)")
    memory.add_argument("--query", default="", help="what to look for (search)")
    memory.add_argument("--limit", type=int, default=100, help="how many records (show / search)")
    memory.set_defaults(func=cmd_memory)

    agents = sub.add_parser("agents", help="connect, list and talk to other agents")
    agents.add_argument(
        "agents_action", choices=["list", "add", "remove", "ask", "broadcast"], help="what to do"
    )
    agents.add_argument("--file", default=None, help="registry file (default ~/.zeno/agents.json)")
    agents.add_argument("--name", default="", help="the agent's name")
    agents.add_argument("--endpoint", default="", help="its base URL; the bridge POSTs to <url>/ask")
    agents.add_argument("--capability", default="", help="the grant that agent was issued")
    agents.add_argument("--text", default="", help="what to ask it")
    agents.add_argument("--lang", default="en", help="language tag to send")
    agents.set_defaults(func=cmd_agents)

    serve = sub.add_parser("serve", help="run the local web playground")
    serve.add_argument("--host", default=os.environ.get("ZENO_HOST", "0.0.0.0"))
    serve.add_argument("--port", type=int, default=int(os.environ.get("ZENO_PORT", "8000")))
    serve.add_argument(
        "--production",
        action="store_true",
        help="require all eight AEGIS layers and hide refusal reasons (refuses to start "
        "without the crypto backend); ZENO_ENV=production does the same",
    )
    serve.add_argument(
        "--dev",
        dest="development",
        action="store_true",
        help="force development mode even when ZENO_ENV=production is set",
    )
    serve.add_argument(
        "--allow-origin",
        action="append",
        default=[],
        metavar="ORIGIN",
        help="extra origin allowed to call the API from another page (repeatable; '*' for any)",
    )
    serve.set_defaults(func=cmd_serve)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    # Subparsers declare --json with SUPPRESS so a global --json (given before the
    # subcommand) is not clobbered; that means the attribute may not exist at all.
    args.json = bool(getattr(args, "json", False)) or "--json" in (argv or sys.argv[1:])
    if not getattr(args, "command", None) and not hasattr(args, "func"):
        parser.print_help()
        return 0
    try:
        return int(args.func(args) or 0)
    except ZenoError as exc:
        print(exc.render(color=sys.stderr.isatty()), file=sys.stderr)
        return 2
    except KeyboardInterrupt:  # pragma: no cover - interactive
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
