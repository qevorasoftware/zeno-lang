# Security policy

This document is the disclosure policy for **zeno-lang** and for **AEGIS**, the
authorization gateway it ships with. It also states, plainly, what the security
story does and does not cover — because a policy that only lists phone numbers
without saying what is in scope is not much of a policy.

## Supported versions

| Version | Status |
| --- | --- |
| `0.1.x` (current `main`) | receives security fixes |
| anything older | not supported |

There are no long-term support branches. Fixes land on `main` and are released as
patch versions.

## Reporting a vulnerability

**Use GitHub's private vulnerability reporting:** repository → **Security** tab →
**Report a vulnerability**. That channel is private, threads the report against
this repository, and lets us collaborate on a fix before anything is public.

If that channel is unavailable to you, open a normal issue that says only
*"I have a security report and need a private channel"* — with no details, no
proof-of-concept, no exploit steps.

> **Do not post secrets, keys, credentials, private payloads, or working exploits
> in public issues, pull requests, discussions or commit messages.** If you
> believe a secret of yours has already been exposed, rotate it first, then tell
> us. A committed secret is a burned secret: assume it is public the moment it
> touches a public repository.

There is no security email address and no published PGP key. If one is added
later, it will appear here and nowhere else.

## What to expect from us

| Stage | Target |
| --- | --- |
| Acknowledgement of your report | 3 business days |
| Initial assessment (severity, affected versions, whether it is in scope) | 10 business days |
| Fix or documented mitigation for confirmed, in-scope issues | best effort, patch release on `main` |
| Credit | on request, in the release notes — never without your consent |

This is a small project: responses are best effort, not contractual, and there is
no bug bounty. We would rather tell you that plainly than imply an SLA we cannot
meet. Please give us a reasonable window (90 days is a common default) before
publishing details.

## Scope

**In scope — report these:**

- Bypassing AEGIS: anything that reaches effectful Zeno execution over HTTP
  without passing through `AuthorizationBoundary.authorize` (in production mode,
  without a valid authorization).
- Layer bypass or order manipulation that lets a request be *accepted* while a
  mandatory layer did not actually pass.
- Cryptographic misuse in `aegis/`: wrong key derivation, key/nonce reuse,
  predictable randomness, signature or MAC verification that can be skipped,
  encryption that is really encoding (or vice versa).
- Ledger integrity: an edit to an accepted ledger entry that `Ledger.verify`
  does not detect, or a way to make audit recording fail while execution
  proceeds in production mode.
- Information leakage in production mode: a refusal that reveals which layer
  failed, whether an actor exists, or any prose where only a code is promised.
- Claiming a property the code does not have — in the docs, the reports, or the
  API. Honesty bugs are security bugs in this project; see the documentation
  claims in `specs/aegis_security.md`.
- The dashboard: CORS or authorization behaviour that lets a web page drive a
  reader's local Zeno server without that server granting it.

**Out of scope — already documented limitations, not vulnerabilities:**

- **VAJRA is an encoding, not a cipher.** It provides no confidentiality. That is
  stated in `specs/vajra_sanskrit.md`, `aegis/vajra/__init__.py`,
  `VAJRA_IS_A_CIPHER = False`, and in every report the package emits. "I decoded
  a VAJRA-wrapped payload without a key" is expected behaviour, not a finding.
- **Geolocation is spoofable**, and device binding is not attestation unless the
  hardware provides it. Both are treated as risk signals, never as proof.
- **Replay state is per-process** and bounded. Multi-node, durable replay
  protection is planned (Phase P1 of the hardened plan) and not claimed yet.
- **Development mode is not a production posture.** It allows effectful
  execution with fewer than eight mandatory layers, and it says so in every
  response, the server banner, and `/api/health`. A deployment that runs in
  development mode has chosen that; it is not a bypass.
- **The Python library is not the enforcement boundary.** `import zeno` executes
  payloads in *your* process, with *your* privileges. AEGIS guards the HTTP
  surface of `zeno serve`; it cannot guard a caller who already has code
  execution in the host process, and it does not pretend to.
- Denial of service by a caller who is permitted to call, resource exhaustion
  inside a payload the operator chose to run, and anything that requires the
  attacker to already hold the owner's keys.

**Not yet implemented** (do not report as a hole — they are open items in the
plan, and the code says so): capability tokens with owner-rooted issuance,
independent ledger anchoring, cross-process replay state, per-caller quotas,
TPM/secure-enclave attestation, and layer-order permutation. See
`specs/aegis_security.md` for the current status of each.

## Operating this safely

```bash
zeno serve --production     # all eight layers mandatory, opaque refusals,
                            # ledger signatures verified, nonce-bound proofs
```

- Production mode **refuses to start** if the crypto backend
  (`python -m pip install -e .[aegis]`) is unavailable, rather than running with
  an authorization layer it cannot enforce.
- Keep `~/.aegis/` private. It holds the device secret and the cached ZKP group
  parameters.
- Read `aegis report` on the host you deploy to: it lists which layers are real
  cryptography, which are policy, and which are encoding, on *that* machine.
- Treat the ledger as evidence, not as immutable truth: it is append-only and
  tamper-evident, and its own operator can still truncate it. Independent
  anchoring is planned, not shipped.
