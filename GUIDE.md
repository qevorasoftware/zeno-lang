# The Zeno project guide

*આ ગાઇડ પ્રોજેક્ટનો હેતુ, બધી વસ્તુ કેવી રીતે ચાલે છે, અને હવે શું કરવું — બધું એક જગ્યાએ. ઝડપી શરૂઆત ગુજરાતીમાં છે, પછી આખી વિગત અંગ્રેજીમાં.*

---

## ઝડપી શરૂઆત (Gujarati)

```bash
pip install -e ".[aegis]"          # ક્રિપ્ટો વ્હીલ્સ સાથે ઇન્સ્ટોલ
python -m zeno memory init-key     # તમારી કી — જે કંઈ બોલો એ સીલ થાય
python -m zeno voice               # → http://localhost:8000/voice  (વાત કરો, કોઈ પણ ભાષામાં)
```

| જોવાનું | URL |
|---|---|
| Dashboard (Qevora design) | http://localhost:8000/dashboard |
| Admin console | http://localhost:8000/admin |
| Voice agent | http://localhost:8000/voice |
| Online site | https://qevorasoftware.github.io/zeno-lang/ |

**આ પ્રોજેક્ટનો મુખ્ય હેતુ એક વાક્યમાં:** AI એજન્ટ્સ વચ્ચેની વાતચીત સસ્તી (૯૦% ઓછા ટોકન) અને સુરક્ષિત (માલિકની કી વગર કંઈ ચાલે નહીં) બનાવવાની ભાષા + ગેટવે + એજન્ટ.

---

## 1. The main point (what this project *is*)

Three things, built one on top of the other:

**Zeno — the language.** A dense, tiny grammar (`v0.1`) that says everything an
agent needs to say to another agent — *where I am, what I want, what to do when
the answer comes back* — in a fraction of the tokens English needs:

```
@LOC[TYO] -> ?WX : { $WX.state == RAIN => !GEN[INDOOR, 3] | !GEN[OUTDOOR, 3] }
```

That is "if it's raining in Tokyo, generate 3 indoor plans, else 3 outdoor
ones." Measured, not claimed: multi-turn A2A conversations use **90.62% fewer
tokens** than English (target 75%, met); token density is 54.39% against the
brief's 75% target (**not met, and said so**) — closing that gap is real,
open work.

**AEGIS — the gateway.** Eight layers sit in front of every effectful call:
PQC hybrids → biometrics → zero-knowledge proofs → signed audit ledger →
guardian AI → vocabulary rotation → device lock → VAJRA encoding. Nothing
executes without the owner's say-so; refusals are opaque codes; every decision
is recorded. Authority is rooted in **your key**: `python -m aegis owner init`
mints it, grants are short-lived and revocable, and rotating the epoch kills
every old grant at once.

**The agent — the surface.** You can *talk* to it (`zeno voice`): speech in and
speech out in any language the browser speaks, every turn authorized by AEGIS,
and everything you say remembered **sealed to your key** (ciphertext on disk,
tamper-evident chain). It can call other agents you connect — out-sourced,
multi-agent, no cap — each with its own grant.

## 2. Run everything

```bash
pip install -e ".[aegis]"                  # with crypto wheels
python -m zeno serve                       # playground + dashboard
python -m zeno voice                       # + the talking agent (or: --memory-key ~/.zeno/memory.key)
python -m zeno voice --production          # all 8 layers required, refusals are codes only
```

Every command, one line each:

| Command | What it does |
|---|---|
| `zeno encode "what is the weather in Tokyo"` | English → Zeno payload |
| `zeno run '<payload>'` | Execute a payload |
| `zeno ask "..."` | Encode + run + answer in prose |
| `zeno benchmark` | The honest numbers (density, A2A reduction) |
| `zeno memory init-key / list / show / search / verify / forget` | Your conversation memory, sealed |
| `zeno agents add/ask/broadcast/list` | Connect and talk to other agents |
| `zeno watchtower` | Who was refused, and what was done about it |
| `python -m aegis owner init/issue/verify/revoke/rotate-epoch` | Your root of trust |
| `python -m aegis selftest` / `report` | What this machine can actually do |
| `python -m pytest tests/` | The whole suite (564 tests) |

## 3. How it works, piece by piece

- **Language pipeline** (`zeno/lexer→parser→ast→emitter`, `runtime.py`): text
  becomes a payload; the kernel executes tools (`?WX`, `!GEN`…) against state;
  the decoder turns results back into prose. `zeno check` lints, `zeno tokens`
  shows the tokenizer's savings.
- **AEGIS boundary** (`aegis/boundary.py`): every effectful HTTP call is
  authorized *before* anything runs — capability → nonce → identity-bound proof
  → the eight layers. A missing AEGIS context is a hard DENY, in every mode.
- **Capabilities** (`aegis/capability.py`): grants are hybrid-signed
  (Ed25519 + ML-DSA-65), carry subject, scope, audience, epoch, expiry; the
  server only ever holds your *public* half.
- **Watchtower** (`aegis/watchtower.py`): refusals become evidence (digests
  only). Repeat offenders get delayed, then served fabricated decoys that never
  touch the kernel. It states its own limits: *a tarpit delays, it does not
  stop.*
- **Memory** (`zeno/memory.py`): sealed with the AEGIS hybrid sealer, chained
  by digest, `forget` is destructive on purpose. No key → plaintext, and every
  record says so.
- **Surfaces**: `dashboard.html` (Qevora UI kit, live figures or the committed
  snapshot), `/admin` (CRM-style console over the live posture), `/voice` (the
  talking page), the Pages site at
  [qevorasoftware.github.io/zeno-lang](https://qevorasoftware.github.io/zeno-lang/).

## 4. Is it working? (verified 2026-10-08, commit `df33660`)

| Check | Result |
|---|---|
| Full test suite | **564 passed, 1 skipped** |
| AEGIS selftest | **7/7** |
| Language end to end (encode → run → decode) | **works** |
| Owner CLI lifecycle (init → issue → verify → revoke → rotate) | **works** |
| Voice turn (any language, sealed memory, chain verify) | **works** |
| Dashboard / admin / voice pages + all API routes | **works** |
| Honesty scan (`tools/no_overclaim`) | **clean** |
| CI on every push (tests, security red-team, Pages) | **green** |

"Working" here means: everything the project *claims* is tested and true.
The things it does **not** claim are written down, not hidden — the full list
is in `specs/aegis_hardening_status.md`. The short version: replay state is
per-process (not multi-node), there are no rate quotas yet, the request
envelope is not signed at the HTTP layer, memory search is substring (not
semantic), and no external audit has happened. Those are the next work, not
broken promises.

## 5. What to do next — pick one

**As a user, today:**
1. **Connect a real brain.** Without a provider the agent answers with the
   rule-based encoder (honest, but English-shaped). Give it an LLM:
   `export ZENO_PROVIDER=openai OPENAI_API_KEY=…` (presets: `openai`, `groq`,
   `openrouter`, `together`, `ollama`, `vllm`, or any `openai-compatible`
   endpoint) — then talk to it in Gujarati and it answers in Gujarati.
2. **Use it as your private assistant** — everything you say is sealed to your
   key and searchable (`zeno memory search`).
3. **Give your other agents grants** (`python -m aegis owner issue`), connect
   them (`zeno agents add`), and broadcast questions across all of them.

**As a developer, next builds (real, ranked):**
1. **Semantic memory** — embed the sealed records, search by meaning, not
   substring. (A `where` clause in the design, not implemented.)
2. **P2 hardening** — rate limits/quotas per caller, a signed request envelope
   at HTTP, durable cross-node replay state, anchoring the ledger externally.
3. **Close the density gap** — 54.39% vs the 75% target: a genuinely open
   encoder/grammar problem, with the benchmark already in place to prove wins.
4. **Tools for the kernel** — every new tool (`?WX`-style) makes the language
   more useful; the grammar and validator already pin the contract.
5. **A phone app / PWA** around `/voice` — the page already degrades honestly
   without a backend.
6. **Production deployment** — a small VPS, `zeno voice --production`, your
   key offline, grants issued per device, the watchtower feed shipped to you.

*એક વાત યાદ રાખો: આ પ્રોજેક્ટ ક્યારેય કહેતો નથી કે એ "unbreakable" છે — એની તમામ ગેરેન્ટી ગણિતની છે, ટેસ્ટેડ છે, અને એની મર્યાદા દરેક ફાઇલમાં લખેલી છે. એ જ એની સૌથી મોટી મજબૂતી છે.*
