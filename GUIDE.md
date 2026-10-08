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
| `zeno pages --write` / `--check` | Re-render / verify the generated static pages |
| `python -m pytest tests/` | The whole suite (590 tests) |

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
- **Surfaces — rendered, not hand-written** (`zeno/pages/`): every page
  (dashboard, settings, admin, voice, playground, the site doorway, the 404)
  is *assembled by the page engine* at request time — one generated layout
  (sidebar, header, theme, kit) shared by all surfaces, plus a body fragment
  and the page's own script. The live server bakes the request-time truth
  into the HTML: the settings page ships with your provider table and the
  store's sealed/plaintext state already in it, the voice page with its
  status pills. The `*.html` files at the repository root are **generated
  artefacts** for the static Pages site (`zeno pages --write` re-renders
  them; a test fails if they drift), so
  [qevorasoftware.github.io/zeno-lang](https://qevorasoftware.github.io/zeno-lang/)
  and the local `zeno voice` server show the same pages from one source. On
  the static site every page opens, but it is a read-only copy: live figures
  and the talking agent need your own server.  URLs: the live server links
  clean routes (`/settings`, `/voice` — no `.html` in the address bar); the
  Pages mirror links file names, because that host resolves files. Both
  dialects come from the one generator.

## 4. Is it working? (verified 2026-10-08, commit `df33660`)

| Check | Result |
|---|---|
| Full test suite | **590 passed, 1 skipped** |
| AEGIS selftest | **7/7** |
| Language end to end (encode → run → decode) | **works** |
| Owner CLI lifecycle (init → issue → verify → revoke → rotate) | **works** |
| Voice turn (any language, sealed memory, chain verify) | **works** |
| Pages rendered live by the engine (settings SSR = the real store) | **works** |
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
6. **Production deployment** — Render works today (see §6); the next step
   beyond it is a small VPS with a persistent disk, `zeno voice --production`,
   your key offline, grants issued per device, the watchtower feed shipped to
   you.

## 6. Render પર live કરો (deployment)

**ઝડપી રીત (Gujarati):**

1. **Render માં:** New → Blueprint → આ repo પસંદ કરો → `render.yaml` બધું જ રાખી લેશે
   (build: `pip install -e .[aegis]`, start: `zeno serve --production`, health: `/api/health`).
2. **તમારા કમ્પ્યુટર પર** (એક જ વાર):
   `python -m aegis owner init` → `python -m aegis owner export-public --out owner-public.json`
3. **Render ના env માં** `ZENO_OWNER_PUBLIC` = એ file નું JSON પેસ્ટ કરો.
   (આ public key છે — એમાં કોઈ secret નથી.)
4. **Token બનાવો:**
   `python -m aegis owner issue --subject me --capability "read:*" --capability "settings:*" --capability "execute:*" --capability "agent:*" --ttl 86400`
5. તમારા browser માં Render ની site ખોલો → કોઈ પણ page પર 🔑 (grant) બટન → token પેસ્ટ કરો.
   હવે settings, voice agent, admin — બધું ચાલશે.

**શું ચાલે છે (verified):** બધા pages live render થાય (SSR સાથે), grant વગર દરેક
gated કામ machine-code refusal મળે, grant સાથે settings save/switch/test, voice turn,
run/ask — બધું ચાલે છે (`tests/test_deploy.py` + live 24/24).

**Production ના બે પ્રોફાઇલ — ઇમાનદારીથી:**
- `ZENO_PRODUCTION_PROFILE=browser` (render.yaml નું default): grant + nonce +
  audited ledger + sentinel + PQC backend + opaque refusals — **ફરજિયાત**. પણ
  browser ભૌતિકરીતે જે 4 સ્તર ક્યારેય પૂરા કરી શકે નહીં (biometric, ZKP proof,
  polymorphic, device-lock) એ **જરૂરી નથી** — અને `/api/health` દરેક request પર એમ જ કહે છે.
- `strict` (default નહીં આપો તો): આઠેય સ્તર ફરજિયાત — એ machine clients માટે છે
  (biometric vault + ZKP prover + device fingerprint ધરાવતા). Web page સાથે
  strict રાખશો તો દરેક કામ refuse થશે — એ bug નથી, design છે.

**મર્યાદા (છુપાવવાની નહીં):**
- **Free plan નું filesystem deploy પર ભૂંસાઈ જાય છે** — API keys અને memory નવા deploy
  પછી રહેશે નહીં. કાયમ માટે જોઈએ તો persistent disk (paid) જોડો.
- Token ની TTL હોય છે (ઉપરના ઉદાહરણમાં 24 કલાક) — પછી નવો બનાવવો પડે.
- `revoke`/`rotate-epoch` પછી `export-public` **ફરી ચલાવીને** Render ના env માં
  અપડેટ કરવું પડે (revocation list export માં હોય છે).
- Memory/providers ને seal કરવી હોય તો `zeno memory init-key` નું JSON
  `ZENO_MEMORY_KEY_DATA` env માં (private env છે — Render secrets).
- Public URL એ ખરેખર public છે: pages કોઈ પણ ખોલી શકે; કામ કરવા માટ્ર grant જોઈએ.
- **જો દરેક જવાબ ખોટો જણાય** (`frame: !RET[ok=true, nonce=…]` જેવું, `decoy: true`
  સાથે): તમારા browser ના source ને guardian એ flag કર્યો છે — 3 refused પ્રયત્નો પછી
  દરેક refusal ની જગ્યાએ 200 + બનાવટી જવાબ મળે છે (anti-attacker design). એ ભૂલ નથી;
  નીચેનું કારણ સુધારો (મોટે ભાગે grant નથી કે expire થયો), પછી **એક જ** પ્રયત્ન કરો —
  સફળ request ને ક્યારેય decoy નથી મળતી. વધુ રેપિડ ક્લિક કરવાથી flag વધુ ઊંડો જાય છે.
- **`ZN-SEC-0x9A01` (grant નથી પહોંચ્યો)**: કારણો — grant paste જ નહીં કર્યો, કે terminal
  એ token ને wrap કરીને દેખાડ્યો અને copy માં line-breaks ભળ્યા, કે અધૂરો copy થયો. Server
  હવે wrapped grant પણ વાંચે છે અને pages paste કરતાં જ whitespace સાફ કરે છે; તો પણ
  ન ચાલે તો `--out file` થી પૂરો token ફાઇલમાં લખાવીને એની આખી content એક સાથે copy કરો.
- **`ZN-SEC-0x9A09` (grant માં એ કામનો અધિકાર નથી)**: grant સાચો છે પણ એ scope નથી
  ધરાવતો. દરેક કામ માટે પોતાનો scope જોઈએ — Run/Ask માટે `execute:*`, settings બદલવા
  માટે `settings:*`, panels વાંચવા માટે `read:*`, voice માટે `agent:*`. Grant આમ બનાવો:
  `python -m aegis owner issue --capability "execute:*" --capability "settings:*"
  --capability "read:*" --capability "agent:*" --ttl 3600` (ડિફોલ્ટ TTL ફક્ત 15 મિનિટ છે —
  લાંબુ જોઈએ તો `--ttl` વધારો). Playground પેજ પર પણ હવે 🔑 grant બટન છે; settings માં
  paste કરેલો grant એ જ browser ના બધા pages માં ચાલે છે.
- **`ZN-SEC-0x9A02` (grant ની signature ન મળી)**: grant બીજા owner key થી બન્યો છે અને
  deployment પાસે બીજી public key છે. જે root થી grant બનાવો છો એ જ root ની public key
  deployment ના `ZENO_OWNER_PUBLIC` માં હોવી જોઈએ (`python -m aegis owner
  export-public --out …` થી ફરી export કરો).

 આ પ્રોજેક્ટ ક્યારેય કહેતો નથી કે એ "unbreakable" છે — એની તમામ ગેરેન્ટી ગણિતની છે, ટેસ્ટેડ છે, અને એની મર્યાદા દરેક ફાઇલમાં લખેલી છે. એ જ એની સૌથી મોટી મજબૂતી છે.*
