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

    serve(host=args.host, port=args.port)
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

    serve = sub.add_parser("serve", help="run the local web playground")
    serve.add_argument("--host", default=os.environ.get("ZENO_HOST", "0.0.0.0"))
    serve.add_argument("--port", type=int, default=int(os.environ.get("ZENO_PORT", "8000")))
    serve.set_defaults(func=cmd_serve)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args) or 0)
    except ZenoError as exc:
        print(exc.render(color=sys.stderr.isatty()), file=sys.stderr)
        return 2
    except KeyboardInterrupt:  # pragma: no cover - interactive
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
