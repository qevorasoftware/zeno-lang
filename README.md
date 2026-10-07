# Zeno Protocol — `zeno-lang`

**A dense, unambiguous wire language for agent-to-agent communication.**

Zeno replaces polite natural-language chatter between agents with a single
canonical payload that parses deterministically, executes locally, and costs a
fraction of the tokens. This repository is a complete, dependency-free
implementation of Grammar v0.1: lexer, parser, emitter, validator, kernel,
encoder/decoder agents, benchmarks, CLI and a web playground.

```zeno
@LOC[TYO] -> ?WX : { $WX.state == RAIN => !GEN[INDOOR, 3] | !GEN[OUTDOOR, 3] }
```

```text
scope: LOC of TYO · fetch WX · if $WX.state equals RAIN
  then generate INDOOR, 3 · otherwise generate OUTDOOR, 3
```

That payload is the canonical example in `specs/tokens.json`, and it is the
reference the whole toolchain is tested against.

---

## Install

```bash
git clone https://github.com/qevorasoftware/zeno-lang && cd zeno-lang
python -m pip install -e .          # zero runtime dependencies

# optional extras
python -m pip install -e .[tiktoken]  # exact BPE token counts
python -m pip install -e .[dev]       # pytest + tiktoken
```

Python 3.10+. The library is standard-library only; `tiktoken` is optional and
every report says which counter produced its numbers
(`tiktoken:o200k_base` or `estimator:subword`).

## Quickstart

```bash
# natural language -> Zeno
zeno encode "Check the weather in Tokyo. If it is raining, suggest 3 indoor activities."

# execute a payload against the bundled demo tools
zeno run '@LOC[TYO] -> ?WX : { $WX.state == RAIN => !GEN[INDOOR, 3] | !GEN[OUTDOOR, 3] }'

# the full round trip: encode -> execute -> decode
zeno ask "total 3 * 129.99 + 2 * 45.5, and tell me if we are over 500"

# validate / canonicalise / lint
zeno check --canonical '@SYS[x]  ->  ?A:{$A==1=>!B|!C}'
zeno check --json '@LOC[TYO] -> ?WX : { $MISSING == 1 }'

# inspect the language itself
zeno grammar --json | head -40

# benchmarks and the playground
zeno benchmark            # token density + multi-turn A2A cost
zeno latency --repeat 30  # per-stage overhead
zeno serve --port 8000    # web playground on http://localhost:8000
```

Every command accepts `--json`, so the CLI is also a scripting surface for
other agents. `run`/`ask` execute against the bundled demo tools; point them at
your own with `--tools module:factory` or `--no-tools`.

## The language in 60 seconds

| Sigil / operator | Meaning | Example |
| --- | --- | --- |
| `@TARGET[args]` | scope / addressee | `@AGENT[Researcher]`, `@LOC[TYO]` |
| `?query[args]` | read state | `?WX`, `?SEARCH["Zeno Protocol"]` |
| `!action[args]` | do something | `!GEN[INDOOR, 3]`, `!RET[$T]` |
| `$VAR` | latent state, bound by every step | `$WX.state`, `$PRICE` |
| `->` | pipeline: then | `?A -> !B` |
| `: { … }` | conditional | `$X > 0 => !A | !B` |
| `=>` / `|` | then-branch / else-branch | `TRUE => !A | !B` |
| `== != ~= < <= > >=` | comparison (`~=` is text match) | `$WX.state == RAIN` |
| `&& \|\| ~ - * / % ^` | logic and arithmetic | `$T > 500 && $Q > 0` |
| `[ … ]`, `"…"`, `3.5`, `TRUE` | lists, strings, numbers, literals | `!MAP[SUMMARIZE, 3]` |

Three rules carry most of the weight:

1. **Every step binds its own name.** `?WX` makes `$WX` readable later, so a
   payload needs no "please remember the previous result" boilerplate (§3.1).
2. **`$PREV` is always the previous step's value.** Simple chains never name
   anything: `?SEARCH["…"] -> !SUMMARIZE[$PREV, 5]`.
3. **Two spellings, one AST.** `$X == 1 => !A | !B` and
   `: { $X == 1 => !A | !B }` parse to the same tree; `emit()` prints the one
   canonical form, so payloads compare byte-for-byte.

The full grammar — symbol matrix, precedence table, EBNF, semantics, error
codes — is in [`specs/grammar.md`](specs/grammar.md) and, machine-readably, in
[`specs/tokens.json`](specs/tokens.json). The implementation asserts it does not
drift from that file (`zeno.spec.drift_report() == []`, checked in CI).

## Architecture

```
                ┌──────────── encoder agent ────────────┐
 human text ──▶ │ grammar card ▸ model ▸ extract ▸ repair │ ──▶ Zeno payload
                └───────────────────────────────────────┘
 Zeno payload ─▶ lexer ▸ parser ▸ validator ▸ kernel (tools) ─▶ result frame
                ┌──────────── decoder agent ────────────┐
 result frame ▶ │ deterministic render ▸ model ▸ prose  │ ──▶ human answer
                └───────────────────────────────────────┘
```

| Module | Role |
| --- | --- |
| `zeno/lexer.py` `parser.py` `ast.py` | hand-written, no dependencies, precise spans |
| `zeno/emitter.py` | canonical printing; `canonicalize()` is idempotent |
| `zeno/validator.py` | lints coherence: unbound `$VARS`, empty scopes, shadowed atoms |
| `zeno/runtime.py` | the kernel: scopes, bindings, `$PREV`, `!RET`, result frames |
| `zeno/encoder.py` `decoder.py` `pipeline.py` | the two model-backed stages and their composition |
| `zeno/prompts.py` | grammar card + system prompts (encoder prompt: 551 tokens) |
| `zeno/tools.py` | deterministic demo tools so everything runs offline |
| `zeno/cli.py` `server.py` `web/index.html` | CLI and the playground |
| `agents/linguist.py` `agents/tester.py` | language agent and conformance agent |
| `benchmarks/` | density, multi-turn A2A and latency benchmarks |

Errors are diagnostic, not fatal: every failure has a code, a span, a caret
rendering and a hint.

```
ZenoSyntaxError [ZN0005]: conditional block evaluated without a '=>' branch
  --> payload:1:18
  |
1 | @LOC[TYO] -> ?WX : { $X = 1 }
  |                  ^^^^^^
hint: write `: { <test> => <then-flow> | <else-flow> }`
```

## Benchmarks

Reproduce everything below with `zeno benchmark`, `zeno latency` and
`python -m agents.tester`. Numbers use the labelled token estimator when
`tiktoken` cannot download its tables (this sandbox has no such access), and the
benchmark prints which counter it used.

### 1. Per-message density — `benchmarks/token_comparison.py`

16 intents, each written three ways: a realistic dispatch (`human`), the same
intent compressed by a human (`terse`), and its canonical payload (`zeno`).

| | human | terse | zeno |
| --- | --- | --- | --- |
| tokens (pooled) | 1162 | 275 | **530** |
| reduction vs human | — | — | **54.4 %** |
| reduction vs terse | — | — | **−100.8 %** |

Per case, the honest spread: best `math-answer` 78.1 %, median 58.8 %,
worst `invoice-total` 32.3 % (because `3 * 129.99 + 2 * 45.5` is irreducible —
the payload can only remove the prose around it).

**Read this before quoting the 75 % target.** Zeno beats a realistic prompt by
roughly half, and it loses to a human who compresses the same intent to
telegraphic English, because the human silently drops structure the payload has
to state explicitly (which branch, which field, which format). Single short
messages are therefore *not* where the protocol wins; the win appears when the
natural-language side carries the framing that real dispatches carry, and in
multi-turn loops where the alternative is replaying history.

### 2. Multi-turn A2A cost — `benchmarks/conversation_test.py`

A six-hop research → draft → review → revise → publish handoff. Chat mode
re-sends the standing instruction plus the whole transcript on every hop (how
chat APIs work); Zeno hops are self-contained and the receiver keeps state.

| | chat | zeno | reduction |
| --- | --- | --- | --- |
| per hop, pooled | 1696 | 159 | **90.6 %** |
| first hop (prompt not amortised) | 113 | 47 | 58.4 % |
| steady state, 10 workflows | — | — | 87.4 % |

The encoder's system prompt (551 tokens) is a deployment constant: cached once,
repaid after 2.2 hops. This is the number that matters for A2A, and it is where
the brief's 75 % target is met.

### 3. Protocol overhead — `benchmarks/latency_test.py`

Mean of 30 runs, on a laptop-class CPU, with model calls mocked:

| parse | emit | execute | decode | full round trip |
| --- | --- | --- | --- | --- |
| 0.26 ms | 0.016 ms | 0.07 ms | 0.64 ms | 3.1 ms |

Grammar (parse + emit) is **8.9 %** of the round trip; the rest is the pipeline
around it, and in production the model call dominates everything.

## Conformance

```bash
python -m agents.tester --intent-check   # 138 checks, exit 0/1
python -m pytest tests/                  # 373 tests
python -m agents.linguist explain '<payload>'   # Zeno -> English, deterministically
```

`agents.tester` re-checks every shipped payload for parseability, canonical
idempotence, exact AST round-tripping, validation, execution, determinism and
result-frame re-parseability, and it replays `tests/invalid/cases.json` to prove
malformed payloads still raise the declared code. Add a case to
`benchmarks/corpus.json` and it is enrolled automatically.

`agents.linguist explain` is the reference semantics in English; it never calls
a model, so it doubles as an audit tool.

## Design decisions and limits

* **Deterministic by construction.** Parsing, emission and execution are pure
  functions; `zeno run` needs no network. Only the encoder and decoder stages
  talk to a model, and they degrade to a clearly-labelled rule-based encoder
  (`fell_back=true`) or a deterministic renderer.
* **Symbols, not prose, on the wire.** `!RET[BUDGET=OVER]` travels; the decoder
  expands it for humans. Payloads that embed full English sentences forfeit the
  density the protocol exists for.
* **No silent guessing.** A bare atom is not a step (`RAIN` alone is ZN0003),
  free text must be quoted (`@REPO["zeno-lang"]`, not `@REPO[zeno-lang]`), and
  a query with no implementation raises ZN2001 rather than inventing a value.
* **Failures carry a code.** 20 ZN/ZL diagnostics (`zeno grammar --json`),
  every one with a span, a caret rendering and a hint.
* **What it is not:** not a type system (runtime type errors are ZN2004), not a
  transport (payloads are strings; hand them to your transport of choice), and
  not a workflow engine (control flow is one conditional deep — deliberately).

## Repository layout

```
agents/        linguist + tester agents (runnable as python -m agents.<name>)
benchmarks/    corpus.json, density / conversation / latency benchmarks
examples/      01_basic_math.py, 02_agent_chat.py, tools.py
specs/         grammar.md (EBNF, semantics) and tokens.json (machine-readable)
tests/         373 tests incl. tests/invalid/cases.json negative corpus
zeno/          the library: lexer → parser → validator → runtime, plus
               encoder/decoder agents, CLI, web playground
```

## Contributing

```bash
python -m pytest tests/ -q
python -m agents.tester --intent-check
python -c "from zeno import drift_report; assert not drift_report()"
```

Changes to the language must update `specs/tokens.json` and `specs/grammar.md`
in the same commit — CI fails on drift — and must extend the negative corpus in
`tests/invalid/cases.json` when they add a way to be wrong.

## License

MIT © Qevora Software
