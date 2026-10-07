# AEGIS — security specification

**Status:** implemented · **Version:** 2.1.0 · **Code:** `aegis/` · **Tests:**
`tests/test_aegis.py`, `tests/test_boundary.py` · **Hardening plan:** P0 complete
(see §9), P1–P2 open

AEGIS is the gateway in front of Zeno: eight layers, applied in a fixed order, all
of which a request must pass. This document is the threat model, the exact
guarantees, and — the part that matters most — **what AEGIS does not do**.

---

## 1. The claim this specification refuses to make

The brief AEGIS was built from states an acceptance criterion: a payload stays
secret until the year 2126 against "any human, AI, quantum computer or agency".
That cannot be implemented. Not "is difficult" — cannot:

- Every cryptographic guarantee is **computational and time-bounded**. ML-KEM-768
  and X25519 are believed hard; "believed" is the operative word, and the belief
  can be falsified by a paper.
- Guarantees cover **mathematics, not endpoints**. A stolen device, a coerced
  operator, a keylogger, a malicious update, or a subpoena all bypass every layer
  at once. Eight layers of mathematics do not stop the ninth attack: asking a
  person with access.
- "AI cannot break it" is not a property of ciphertext. Ciphertext that is strong
  against a machine is strong against all machines; the AI framing adds nothing.

So AEGIS makes a different, checkable claim:

> AEGIS composes standard, standardised primitives correctly; detects
> misconfiguration by failing closed; records every decision; and reports its own
> limits in code — unless the reader prefers to re-run
> `python -m aegis selftest` and check for themselves.

`aegis.HONESTY` carries this at runtime, and `Gateway.describe()` repeats it in
every serialised description.

---

## 2. Layer-by-layer: guarantee, mechanism, limit

| # | Layer | Mechanism (real) | The limit, plainly |
|---|---|---|---|
| 1 | PQC engine | X25519 **+** ML-KEM-768 hybrid (HKDF-SHA256), Ed25519 **+** ML-DSA-65 dual signatures, ChaCha20-Poly1305 (RFC 8439) with nonce-reuse refusal | Depends on `cryptography` (used, audited) and `pqcrypto` (a young implementation: FIPS 203/204 are new, and side-channel history says assume nothing). Without `pqcrypto` the layer runs **classical-only** and says `quantum_resistant: false` |
| 2 | Biometric auth | Fuzzy commitment (Juels–Wattenberg) over quantised features, scrypt verifier, no stored templates, entropy budget reported | Biometrics are low-entropy and unrotatable. A 32-dimension template yields ~20 bits and the code says so. Sensors and DNA are **not** implemented: `features_from_text` is a stand-in for a real extractor |
| 3 | ZKP validator | Schnorr proofs over a library-validated 2048-bit prime-order group (Fiat–Shamir/SHA-256), Pedersen commitments, single-use nullifiers | **No SNARK/STARK.** No trusted setup, no pairings, no constraint system: proofs of *knowledge*, not statements about committed values. Group is generated locally (~45 s) once and cached, not from a published RFC constant |
| 4 | Ledger | SHA-256 hash chain, Ed25519-signed blocks, Merkle roots + inclusion proofs, anchors | **Tamper-evident, not immutable.** An attacker with write access *and* the node key can rewrite and re-sign. A verified copy proves internal consistency, nothing more |
| 5 | Guardian AI | Deterministic EWMA behavioural profiles; weighted deviations (failure ratio, rate, impossible travel, new device/location, off-hours, novel action, replay attempts); explainable verdicts | **Not a trained model and not an LLM.** Weights are hand-set starting points. A patient attacker shifts the baseline. An auxiliary scorer may only *raise* the score |
| 6 | Polymorphic engine | HMAC-derived per-epoch aliases (`?WX` → `?KHKP` …), 6-hour default window with one epoch of grace, table re-derived from the key and rejected on mismatch | A **keyed rename, not a cipher**. It defeats stale copies and leaked scripts; it does not stop a receiver, who holds the key. Rotation breaks long sessions at epoch boundaries — an availability trade-off |
| 7 | Geo/hardware lock | HKDF key from a 0600 keystore secret salted with a device fingerprint; optional expiry; TPM detected and reported | **Geofencing is advisory**: coordinates are declared, never proven (`spoofable: true` everywhere). Without a TPM, binding rests on a file a root attacker can steal. Fingerprints are identifiers, which are not authenticators |
| 8 | VAJRA | Devanagari encoding, Piṅgala combinatorics, prosody analysis, spectral voiceprint, bīja-salted scrypt | **An encoding, not a cipher.** No key is involved and a keyless decode succeeds by construction. See `specs/vajra_sanskrit.md` |

---

## 3. Cryptographic inventory

| Purpose | Primitive | Source | Verification |
|---|---|---|---|
| Key agreement | X25519 | `cryptography` | round-trip, wrong-key rejection |
| Key agreement (PQ) | ML-KEM-768 (FIPS 203) | `pqcrypto` | 1088-byte ciphertext, 32-byte secret, hybrid key differs per session |
| Key derivation | HKDF-SHA256 (RFC 5869) | in-repo (`aegis/_kdf.py`) | **RFC 5869 test cases 1 and 3** |
| Signatures | Ed25519 | `cryptography` | tamper rejection |
| Signatures (PQ) | ML-DSA-65 (FIPS 204) | `pqcrypto` | 3309-byte signature; valid verify returns falsy, tamper raises — wrapped accordingly |
| AEAD | ChaCha20-Poly1305 (RFC 8439) | `cryptography`, with a pure-Python fallback | **RFC 8439 §2.8.2 vector**, plus 300 randomised vectors byte-identical to the library |
| Password/template KDF | scrypt | `cryptography` | cost parameters recorded per record |
| Proofs | Schnorr + Pedersen over a validated safe-prime subgroup | in-repo (`aegis/zkp_validator.py`) | replay, wrong-context, forged-response, wrong-commitment attacks all rejected |
| Integrity | SHA-256 Merkle tree | in-repo | forged-leaf and edited-entry detection |
| Voiceprint | radix-2 FFT | in-repo | verified against a direct DFT (< 1e-14) |

The pure-Python AEAD fallback exists so the package is never unusable without
wheels. It is **not constant-time** and is labelled as such in the module: it is
for tests and demos, not for protecting traffic.

---

## 4. Adversary model

**In scope.** A network attacker (record, replay, modify, reorder, re-address);
an attacker who steals a sealed payload; an attacker who copies a payload to a
different device; a replay attacker against proofs and sessions; an insider
editing the audit log after the fact; a misconfigured deployment (missing wheel,
absent device lock), which the gateway makes **fail closed** rather than degrade
to allow.

**Out of scope.** A compromised endpoint (root, keylogger, screen capture); a
compelled or coerced operator; the user's own key handling; supply-chain
compromise of `cryptography`/`pqcrypto` themselves; a future cryptanalytic break;
traffic analysis (AEGIS does not hide message timing, size or participants);
denial of service below layer 5 — a freeze trigger is itself a DoS primitive,
which is why every freeze records **who asked** and lifting one needs **two
distinct approvers**.

---

## 5. Key management

- **Storage.** Long-term secrets live in memory in `Identity` objects. The device
  keystore is `~/.aegis/device.json` (mode `0600`, parent `0700`); the ZK group
  cache is validated on every load, so editing it is detected, not trusted.
- **Derivation.** No passphrase is used as a key directly: everything goes through
  HKDF or scrypt with a stated salt and info string.
- **Rotation.** `rotate_secret()` re-issues the device secret and invalidates every
  sealed blob. The ledger's node key is derived from supplied material — in
  production it belongs in a KMS or TPM, not in a process.
- **Destruction.** Python cannot promise zeroisation; `Identity.to_dict()` redacts
  secrets by default and only reveals them under an explicit flag.

---

## 6. Operating AEGIS

```bash
python -m aegis report         # layers, capabilities, limits
python -m aegis capabilities   # which backends exist on THIS machine
python -m aegis selftest       # 7 in-process checks, each a real attack
python -m aegis demo           # one request through all eight layers
python -m aegis vajra "TEXT"   # wrap + measure what the wrap is worth
```

Everything accepts `--json`. `selftest` exits non-zero if any check fails, which
makes it usable as a deployment gate: a host without `pqcrypto` will report the
classical-only downgrade rather than silently proceeding.

---

## 7. Deliberate divergences from the brief

| Asked for | Delivered | Why |
|---|---|---|
| "SHA-512 of fingerprint + retina + voice + DNA" | Fuzzy extractor + scrypt, no raw hashes | Hashing a biometric is a permanent identity leak: low entropy, no rotation |
| Kyber/Dilithium via `pqcrypto.kem.kyber512` | ML-KEM-768 / ML-DSA-65 | Those module names do not exist in the installed `pqcrypto`; ML-KEM/ML-DSA are the standardised names for the same algorithms |
| "zk-SNARKs" | Schnorr + Pedersen | No pairing library or trusted setup is available; a Schnorr proof is real, a mislabelled wrapper is not |
| "Immutable blockchain" | Tamper-evident ledger with anchors | Single-node chains are not immutable. Anchoring in a second trust domain is what makes rewrites provable |
| "Guardian AI learns and evolves" | Deterministic statistics + escalate-only LLM hook | An unauditable evolving component must never be the thing that unlocks a system |
| "6-hour rotation, mandatory" | Configurable, 6 h default with grace | Rotation that cannot complete a session is an outage, not a defence |
| "Unbreakable for 100 years" | No such claim | Section 1 |

---

## 8. Enforcement modes, and what "authorized" means

The gateway has two postures, and both are readable off the object, the server
banner, and `GET /api/health`. Nothing about the posture is implicit.

| | `development` (default) | `production` (`Policy.strict_policy()`) |
|---|---|---|
| Mandatory layers | 1, 4, 5 (3 when the HTTP surface drops the device lock) | all 8, in the brief's order |
| Proof binding | optional | required: key registered to the actor, plus a fresh nonce |
| Ledger signatures | hash chain only | re-verified on every request |
| Refusal text | readable (`code` + sentence) | machine code only (`ZN-SEC-0x…`) |
| Without the crypto wheels | effectful HTTP runs, labelled `enforcement: development` | server refuses to start (exit 3) |

The effectful HTTP routes (`POST /api/run`, `POST /api/ask`) never call the kernel
themselves. They call `aegis.boundary.AuthorizationBoundary.authorize`, and only a
permit unlocks execution; the permit is attached to the response, and the payload
the kernel receives is the *canonical* one that layer 6 restored from the epoch's
rotated vocabulary, never the bytes the caller sent. `tests/test_boundary.py`
asserts this by spying on the kernel: on a refusal it must not have been called.

A refusal in production is a code and nothing else. The sentence behind the code
stays in-process (`Result.human_reason`) and in the owner's ledger, so the owner
can always answer "why was this refused?" without telling the caller anything.

### What the ZKP binding actually establishes

An accepted production request proves three things, and only three: the caller
holds the private key registered to the claimed actor; that key was used over a
context this server derived (`aegis:<actor>:<nonce>`) rather than one the caller
chose; and that nonce had not been spent. It does **not** establish that the
actor is a human, that the actor is trustworthy, or that the request is
well-intentioned — those are the sentinel's and the policy's business, and the
sentinel can only escalate, never authorize.

Nonces are spent on acceptance and remembered in a bounded, per-process buffer.
Durable, multi-node replay state is Phase P1 and is explicitly not claimed.

## 9. Hardening plan: audit findings and their status

The hardened plan (v1.0) lists findings from an audit of this code. Each one was
checked against the code rather than assumed; this table is the result.

| ID | Finding | Status |
|---|---|---|
| C1 | HTTP reached the kernel without AEGIS | **Fixed (P0):** `AuthorizationBoundary` is the only path; spied-kernel test proves no execution on refusal |
| C2 | Eight-layer enforcement not mandatory | **Fixed (P0):** `Policy.strict_policy()` makes all 8 mandatory and is reported; development mode is labelled in every response, banner and `/api/health` |
| C3 | ZKP not bound to identity/context | **Partly fixed (P0):** registry binding (`require_identity_binding`) + nonce-bound context (`require_nonce`); binding to capability/audience/policy/semantic hashes needs capability tokens (P1) |
| H1 | PQC layer does not authenticate the caller | **Open (P1):** layer 1 checks the backend, not the sender; registry binding lands in layer 3 |
| H2 | Hybrid signature downgrade | **Open (P1):** the suite identifier is not yet inside the signed envelope |
| H3 | Receiver-side replay incomplete | **Partly fixed (P0):** nonce single-use per process; durable cross-node state is P1 |
| H4 | Ledger signatures not verified in the gateway | **Fixed (P0):** `verify_ledger_signatures` is on in production |
| H5 | Ledger failure swallowed | **Partly fixed (P0):** a boundary that cannot write the ledger refuses in production; per-layer audit failure inside `Result` remains best-effort |
| M1–M3 | Public endpoints, no quotas, DoS | **Open (P2)** |
| M4 | Guardian metadata attacker-controlled | **Open (P2):** claimed vs verified metadata is not yet separated |
| M5–M6 | Device binding, geofencing | **Documented limits**, unchanged: risk signals, never proof |
| G1 | No disclosure policy | **Fixed (P0):** `SECURITY.md`, including explicit non-scope and known-limitation lists |

What P0 explicitly did **not** do: capability tokens rooted in an owner key,
owner-controlled revocation/epoch rotation, independent ledger anchoring,
per-caller quotas, TPM attestation, layer-order permutation, and sealed
knowledge modules. None of them are claimed anywhere in this repository.

## 10. Verification checklist

- [x] RFC 8439 §2.8.2 and RFC 5869 test vectors pass.
- [x] Pure-Python AEAD is byte-identical to `cryptography` over 300 random cases.
- [x] Re-addressing, tampering, and wrong-recipient opens all raise.
- [x] ZK replay, wrong context, forged response, and wrong commitment are all refused.
- [x] Merkle inclusion proofs verify, and edited entries are detected.
- [x] Impossible travel and novel-device behaviour escalate; a negative auxiliary score cannot de-escalate.
- [x] The device lock refuses a foreign fingerprint and an expired blob.
- [x] The gateway fails closed when a required layer raises.
- [x] **The VAJRA wrap is decoded with no key, in a test, so the claim cannot quietly return.**
- [x] Unauthorized HTTP execution is refused, and the kernel is proven not to have run.
- [x] A fully authorized production request *does* execute (deny-by-default is not deny-always).
- [x] Removing any single piece of mandatory material turns an ALLOW into a DENY.
- [x] A proof for a key not registered to the actor, and a proof replayed under a new nonce, are both refused.
- [x] A refusal in production contains a code and no prose.
- [x] A production server refuses to start without a crypto backend.
- [ ] External audit. Not performed, and no amount of internal testing substitutes for it.
