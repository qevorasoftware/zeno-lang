# Zeno Protocol — `zeno-lang`

**A dense, unambiguous wire language for agent-to-agent communication.**

Zeno replaces polite natural-language chatter between agents with a single
canonical payload that parses deterministically, executes locally, and costs a
fraction of the tokens. This repository is a complete, dependency-free
implementation of Grammar v0.1: lexer, parser, emitter, validator, kernel,
encoder/decoder agents, benchmarks, CLI and a web playground.

> ### ▶ [Open the dashboard](https://qevorasoftware.github.io/zeno-lang/)
>
> The dashboard drives a Zeno server running on your own machine: type commands,
> encode text, run payloads, and watch the benchmarks. If no server is reachable it
> stays open in **read-only snapshot** mode and shows you how to start one.
>
> ```bash
> python -m pip install -e .[dev]   # once
> zeno serve                        # then open the dashboard and press Connect
> ```
>
> Prefer it from the server itself? `zeno serve` also serves it at
> <http://localhost:8000/dashboard>.

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

## The project guide

New here? **[`GUIDE.md`](GUIDE.md)** is the one-file tour: what the project is,
every command, how each piece works, what is verified today, and a ranked list
of what to build next (with a Gujarati quick-start at the top).

## Install

```bash
git clone https://github.com/qevorasoftware/zeno-lang && cd zeno-lang
python -m pip install -e .          # zero runtime dependencies

# optional extras
python -m pip install -e .[tiktoken]  # exact BPE token counts
python -m pip install -e .[dev]       # pytest + tiktoken
python -m pip install -e .[aegis]     # cryptography + pqcrypto, for the gateway below
```

Python 3.10+. The Zeno library itself is standard-library only; `tiktoken` is
optional and every report says which counter produced its numbers
(`tiktoken:o200k_base` or `estimator:subword`). AEGIS is the one part that wants
optional wheels, and it degrades loudly rather than silently: see its section.

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
zeno serve --port 8000    # playground at /, dashboard at /dashboard
zeno dashboard --write    # refresh dashboard-data.json (the offline snapshot)
zeno dashboard --check    # fail if that snapshot is stale (used by CI)
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
| `zeno/cli.py` `server.py` | CLI, the playground and every page route |
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

## AEGIS — the gateway in front of Zeno

Every effectful HTTP call goes through the gateway, and there are two postures.
The default is honest about being a development posture; the other is the one to
deploy:

```bash
zeno serve                 # development: labels every response `development`
zeno serve --production    # all eight layers mandatory, opaque refusals,
                           # ledger signatures verified, nonce-bound proofs
```

In production mode an unauthorized `POST /api/run` is answered with nothing but a
machine code (`{"error": {"code": "ZN-SEC-0x3A01"}}`), the kernel is not called,
and the reason why lives in the owner's ledger instead of in the reply. The
server refuses to start in production mode without the crypto backend, rather than
running with an authorization layer it cannot enforce. `SECURITY.md` states the
disclosure policy and what is deliberately out of scope.

`aegis/` is an eight-layer gateway that sits between a caller and the Zeno
kernel: post-quantum hybrid crypto, biometric verification, zero-knowledge
proofs, an audit ledger, a behavioural sentinel, syntax rotation, device
binding, and the VAJRA Sanskrit encoding layer.

```bash
python -m aegis report         # layers, capabilities on this machine, limits
python -m aegis selftest       # 7 real attacks, each asserted to fail
python -m aegis demo           # one request through all eight layers
python -m aegis vajra "@LOC[TYO] -> ?WX"
```

### The owner's key, and the adversary feed

Authority is rooted in a key only you hold. Create it once, keep it offline, and
issue short-lived grants from it:

```bash
python -m aegis owner init --audience zeno-local
python -m aegis owner issue --subject agent://agent-1 \
    --capability run:weather --capability read:ledger --ttl 900 --out token.txt
python -m aegis owner rotate-epoch            # invalidates every old grant
python -m aegis owner revoke --token token.txt
```

Meanwhile every refusal is evidence. In production a flagged source is delayed,
then answered with a fabricated result that never touched the kernel, and the
owner can see all of it — who, from where, how often, and with what excuse:

```bash
python -m zeno watchtower                     # the feed, read from disk
python -m zeno watchtower --server http://127.0.0.1:8000 --summary
```

The same feed appears on the dashboard as an *Adversary feed* panel, once you
paste a grant with `token <encoded>` and refresh it with `watchtower` — the panel
is the owner's, so it needs the owner's grant. What this is **not**: a claim that
an attacker can never leave. A tarpit delays and a decoy misleads; the security
value is that the attack stops being invisible, and that the attacker's
fingerprints end up in your hands. `specs/aegis_security.md` §9 states the limits
in full, including the ones that can flag innocent callers behind shared NAT.

| # | Layer | What it provides |
|---|---|---|
| 1 | `pqc_engine` | X25519 **+** ML-KEM-768 hybrid key agreement, Ed25519 **+** ML-DSA-65 dual signatures, ChaCha20-Poly1305 sealing (RFC 8439) |
| 2 | `biometric_auth` | Fuzzy-extractor biometrics: no stored templates, no raw hashes, entropy budget reported |
| 3 | `zkp_validator` | Schnorr proofs over a validated 2048-bit group, Pedersen commitments, single-use nullifiers |
| 4 | `blockchain_ledger` | Hash-chained, Ed25519-signed, Merkle-committed audit log — tamper-evident, **not** immutable |
| 5 | `guardian_ai` | Deterministic behavioural sentinel with explainable verdicts; an LLM may advise, never unlock |
| 6 | `polymorphic_engine` | Six-hour keyed vocabulary rotation (`?WX` → `?KHKP`) |
| 7 | `geo_hardware_lock` | Device binding via a 0600 keystore + fingerprint; geofence reported as advisory |
| 8 | `vajra/` | Devanagari encoding, Piṅgala's combinatorics, real prosody, FFT voiceprint — **an encoding, not a cipher** |

### Talk to it: the voice agent, its memory, and other agents

`zeno voice` serves a page you can speak to. Speech in and speech out are done by
*your browser* (so which languages work depends on the browser and OS — the
language tag itself always travels unchanged and is stored with the turn). One
turn is `authorize → measure the voice if audio came → answer → remember`, in that
order: in production a turn without a currently valid owner grant is refused with
an opaque code, and nothing is generated, sent or stored.

```bash
python -m zeno memory init-key                # the key that seals what you say
python -m zeno voice --memory-key ~/.zeno/memory.key
#   → open http://localhost:8000/voice
```

Everything said is kept — **sealed to your key** with the AEGIS hybrid sealer
(X25519+ML-KEM-768, ChaCha20-Poly1305), in an append-only log chained by digest,
so an edit or deletion is detectable by `zeno memory verify`. The words are
ciphertext on disk; without a key the store runs unsealed and says so on every
record, in `/api/health`, and on the page. Reading it back is the owner's:

```bash
python -m zeno memory list --key ~/.zeno/memory.key
python -m zeno memory show --session voice-2026-10-08 --key ~/.zeno/memory.key
python -m zeno memory search --query varsad --key ~/.zeno/memory.key
python -m zeno memory forget --session voice-2026-10-07   # destructive, on purpose
```

Any language tag is accepted (`gu-IN`, `sw-KE`, `pt-BR`…). What "support" means
honestly: the tag travels and is stored untouched; the *answerer* is whoever you
configured as the provider — with none configured it is the rule-based Zeno
encoder, which is English-shaped, and the reply says so.

The same page connects **other agents** to yours — out-sourced, multi-agent, no
artificial cap on how many:

```bash
python -m zeno agents add weather --endpoint https://agent.example --capability <its grant>
python -m zeno agents ask weather --text "will it rain in Surat" --lang gu-IN
python -m zeno agents broadcast --text "report in"      # every connected agent, at once
```

Each peer holds **its own** grant (never your owner key), each call is authorized
by the same boundary as everything else, and a reply is remembered as *that
peer's claim* with its name attached. The real limits are reported, not hidden:
no maximum peer count is imposed — concurrency (16 at a time) and timeout are the
bounds; a peer that fails is reported as its own failure; nothing verifies what a
remote agent claims about itself beyond the transport succeeding.

The **admin console** lives at `/admin` on the same server, built with the
house **Qevora AI SaaS UI** kit (Bootstrap 5, Inter, light/dark without a
flash) and served from assets vendored into the repo — no CDN, so it renders
even where third-party hosts are blocked. It is a dashboard over the live
posture: decisions (owner view: codes and layer verdicts a caller never sees),
the adversary feed, sealed-memory sessions and search, connected agents, and
the eight layers with what this deployment actually requires. It is a view, not a control surface: nothing on it can weaken
a policy or issue a grant, and every panel is gated route by route
(`read:decisions`, `read:memory`, `read:agents` — the same owner grants as the
CLI).

Two things a conversation deployment should know: the guardian watches request
*rate*, and a machine-paced client reads as a burst — raise the ceiling
deliberately with `ZENO_SENTINEL_MAX_EVENTS_PER_MINUTE` when a fast client is
expected; and a voiceprint, when audio is attached, is measured as a **signal**
(recorded speech replays) — it never authorizes anything by itself.

### What AEGIS does not claim

The brief that specified AEGIS asked for a payload that stays secret until 2126
against "any human, AI, quantum computer or agency". No implementation can meet
that, so AEGIS does not claim it. What it claims instead: standard primitives
composed correctly, **fail-closed** behaviour when a layer cannot run, every
decision recorded, and every layer reporting its own limits in code.

Three consequences worth knowing before reading the code:

- **VAJRA is not encryption.** It is a bijection over bytes with a published
  table; a test decodes its output with no key and asserts success, so the claim
  cannot quietly come back. See `specs/vajra_sanskrit.md`.
- **The ledger is tamper-evident, not immutable.** An attacker with write access
  *and* the node signing key can rewrite and re-sign; publish `ledger.anchor()`
  in a second trust domain to make that provable.
- **Geofencing is advisory.** Coordinates are declared, never proven, and every
  report says `spoofable: true`. Device binding is the real control in that layer.

Status against the hardening plan's audit findings — including the ones still
open, and the reasons — is in `specs/aegis_hardening_status.md`. Without
`pqcrypto`, layer 1 runs classical-only and says
`quantum_resistant: false`; without `cryptography` it refuses and points at the
pure-Python AEAD that exists for tests. Threat models, the cryptographic
inventory, and the deliberate divergences from the brief are in
`specs/aegis_security.md`.

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
aegis/         the eight-layer gateway in front of Zeno (see below), with
               vajra/ the Sanskrit encoding layer
dashboard.html the dashboard: drives a local `zeno serve` over CORS, or reads the
               committed snapshot when no server is reachable (served on Pages)
dashboard-data.json  that snapshot, generated by `zeno dashboard --write`
agents/        linguist + tester agents (runnable as python -m agents.<name>)
benchmarks/    corpus.json, density / conversation / latency benchmarks
examples/      01_basic_math.py, 02_agent_chat.py, tools.py
SECURITY.md    disclosure policy, in-scope/out-of-scope, known limits
specs/         grammar.md (EBNF, semantics), tokens.json (machine-readable),
               aegis_security.md and vajra_sanskrit.md (threat models + limits)
tests/         491 tests incl. tests/invalid/cases.json negative corpus
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
