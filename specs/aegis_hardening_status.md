# AEGIS — hardening plan: status against the audit

**Plan:** AEGIS Hardened Security Plan v1.0 · **Code:** `aegis/` · **Last reviewed:**
2026-10-08 · **Companion documents:** `specs/aegis_security.md` (threat model and
guarantees), `SECURITY.md` (disclosure policy).

This file exists because a hardening plan that is only claimed to be implemented is
worth nothing. Every row below was checked against the code and the test suite on
the date above — including the rows that say **open**. Where a claim could not be
substantiated it is marked open rather than described generously.

How to re-check any of it:

```bash
python -m pytest tests/test_capability.py tests/test_boundary.py tests/test_watchtower.py -q
python -m pytest tests/test_aegis.py tests/test_vajra.py -q
python -m aegis owner init --key /tmp/o.json && python -m aegis selftest
python -m aegis report            # what this machine can actually do
```

---

## 1. Audit findings

| ID | Finding | Status | Evidence / where |
|---|---|---|---|
| C1 | HTTP reached the kernel without AEGIS | **Fixed** | `zeno/server.py` routes every effectful call through `AuthorizationBoundary.authorize`; `tests/test_boundary.py` spies on the kernel and asserts it is never entered on a refusal |
| C2 | The eight-layer chain was not mandatory | **Fixed** | `Policy.strict_policy()` makes all eight mandatory; `boundary.mandatory_layers` is asserted equal to `LAYER_ORDER`; `/api/health` reports the live policy, so a permissive deployment is never silent |
| C3 | ZKP not bound to identity or context | **Fixed** | `require_identity_binding` (the proof key must be the key registered to the actor) + `require_nonce` (fresh context per attempt) + capability tokens that bind audience, epoch, policy hash and semantic scope (`aegis/capability.py`) |
| H1 | The PQC layer does not authenticate the caller | **Partly fixed** | Caller authentication now happens in two places that do exist: the hybrid-signed capability token verified against the owner's root, and the identity-bound proof at layer 3. A signature over the request envelope itself is implemented in `pqc_engine` (`sign` / `verify` / `SealedBox` with `_signed_material`) but the HTTP boundary does not *require* one yet — that is P2 |
| H2 | Hybrid signature downgrade | **Fixed** | The suite identifier is inside the signed material (`_signed_material` covers `box.suite`); the sealer now refuses an envelope claiming any other suite at all (`Sealer.open`, tested); the capability layer enforces a suite floor and requires the signed `required_algorithms` set to equal what actually verified |
| H3 | Declared replay protection was incomplete | **Partly fixed** | Nonces are single-use per process, bounded, spent only on acceptance, and now required for owner reads as well. State is still in-process: two nodes do not share it, and a restart forgets it. Durable, distributed replay state is P2 and is not claimed |
| H4 | Ledger signatures were not verified | **Fixed** | `verify_ledger_signatures` is on in the strict policy; layer 4 verifies the chain *and* the signatures of every block |
| H5 | Ledger failure was swallowed | **Fixed** | `Gateway._record` returns the outcome; when an audited operation cannot be written and the policy requires the ledger, `Gateway.decide` returns **DENY** (`refused_by="4-ledger"`, `audit_failures` counted and reported in `describe()`). Tested |
| M1 | Public endpoints were not hardened | **Open (P2)** | The playground is a deliberate public demo surface. Rate limits, quotas and per-caller budgets are not implemented |
| M2 | No quotas / DoS protection | **Partly mitigated, not fixed** | `MAX_BODY` caps request bodies; the watchtower's concurrency budget stops the tarpit being used against us. Real quotas are P2 |
| M3 | Abuse of the model endpoint | **Open (P2)** | Provider calls are not budgeted or metered |
| M4 | Guardian metadata is attacker-controlled | **Partly fixed** | The sentinel is advisory by design (its verdict enters as a scored signal, and it cannot unlock anything), and `Request.observer_view` separates declared fields from derived ones. Claimed-vs-verified separation for the remaining metadata is P2 |
| M5 | Device binding / geofencing are proofs | **Documented limits** | Unchanged and correct: device binding needs a 0600 keystore file, geolocation is a *claim* and is reported as spoofable. Neither is described as proof anywhere |
| M6 | Long-lived secrets in the process | **Documented limits** | The owner root is designed to live offline; the device secret is a file. TPM/HSM attestation is P2 |
| G1 | No disclosure policy | **Fixed** | `SECURITY.md`: supported versions, private reporting channel, response times, scope, out-of-scope, and an explicit prohibition on posting secrets or working exploits publicly |

---

## 2. The plan's invariants, restated and checked

Numbers are deliberately omitted: a wrong invariant number is worse than none. Each
line states the invariant, what enforces it, and what tests it.

| Invariant | Enforced by | Checked by |
|---|---|---|
| All eight layers are mandatory in strict mode; a silent downgrade is impossible | `Policy.strict_policy()`; `mandatory_layers`; `/api/health` | `tests/test_boundary.py` (mandatory-layer assertion), production refusal shape verified from outside the process in CI |
| A required hybrid signature is never satisfied by its classical half alone | `CapabilityVerifier` suite floor + `required_algorithms` equality | `tests/test_capability.py` (stripped PQ half, relabelled suite) |
| The suite identifier is itself signed | `_signed_material` covers `box.suite`; `Sealer.open` refuses foreign suites | `tests/test_aegis.py::test_a_relabelled_suite_is_refused_by_the_sealer` |
| An accepted effectful message cannot be replayed | single-use nonces, spent on acceptance | `tests/test_boundary.py` (replayed proof is refused) |
| Expired, revoked or old-epoch authority cannot execute | `CapabilityVerifier` (epoch equality, revocation list, TTL) | `tests/test_capability.py` |
| Ledger authenticity *and* integrity are required; a failure is DENY, never silent | `verify_ledger_signatures`; `_record` outcome gating `decide` | `tests/test_aegis.py::test_an_unwritable_ledger_refuses_instead_of_acting_unaudited` |
| The Guardian is advisory; deterministic policy decides | sentinel verdict is a scored signal inside the chain | `tests/test_aegis.py` sentinel tests |
| Geolocation is a risk signal unless independently proven | `DeviceBinding` / `GeoFence` report `spoofable` and are advisory | `tests/test_aegis.py` |
| Development bypasses cannot silently reach production | `Policy.mode` reported in every response, the banner and `/api/health`; production refuses to start without the crypto backend | `tests/test_boundary.py`, CI posture job |
| Internal kernel/tool endpoints are never public without an authorization boundary | the server has no effectful route outside `AuthorizationBoundary` | `tests/test_boundary.py` (bypass test) |
| Security decisions emit opaque machine codes only | `opaque_reasons`; `ZN-SEC-0x…` codes; refusals carry no prose | `tests/test_boundary.py`, CI posture job |
| An unauthorized view shows ciphertext and codes, never plaintext | refusals return a code and no body; the watchtower feed stores digests, not content | `tests/test_watchtower.py` |
| The owner's authority is the only root; agents cannot widen it | `OwnerRoot` (0600, public half only on the server), bounded delegation | `tests/test_capability.py` |

---

## 3. What the plan asks for that is not done

Stated plainly, because this is the list a reader needs:

1. **Durable, distributed replay state** (§ H3). In-process, bounded, forgotten on
   restart. Multi-node deployments can accept the same nonce on two nodes.
2. **Quotas, rate limits and per-caller budgets** (M1–M3). The demo surface has a
   body-size cap and nothing else.
3. **A signed request envelope at the HTTP layer** (H1). The machinery exists;
   requiring it is not wired into the boundary.
4. **Claimed-versus-verified metadata separation** for everything the guardian
   scores (M4).
5. **TPM/HSM attestation** for the device secret and the ledger node key (M6).
6. **Independent ledger anchoring.** The ledger is tamper-evident; its operator can
   still truncate it. Publishing `ledger.anchor()` to a second trust domain is the
   fix, and it is not implemented.
7. **Durable, restart-surviving watchtower strike counters.** Strikes and the
   tarpit state are in memory; the feed is on disk, so the evidence survives while
   the escalation state does not.
8. **External audit.** Nothing in this repository substitutes for one.

---

## 4. Statements this project continues to refuse to make

- No claim that VAJRA is a cipher, or that anything is unbreakable, uncrackable or
  impenetrable. `tools/no_overclaim.py` fails the build if such a claim appears
  without a denial, an attribution or a quotation around it, and the docstrings are
  allowed to say the words precisely in order to deny them.
- No claim that an attacker cannot escape, leave, or stop. The tarpit delays and
  the decoy misleads; both are bounded on purpose, and both are described in their
  own limits in `watchtower.summary()`.
- No claim of confidentiality against an adversary who holds the device, the
  owner key, or a legal instrument. Every cryptographic guarantee here is
  computational, time-bounded, and about the mathematics rather than the endpoint.
