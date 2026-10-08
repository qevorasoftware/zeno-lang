"""AEGIS — Autonomous Encrypted Gateway for Intelligent Systems.

AEGIS sits in front of Zeno and decides whether a request may proceed. It is
eight layers, and this package implements all eight in the order the brief
specifies:

1. :mod:`aegis.pqc_engine` — hybrid X25519 + ML-KEM-768 key agreement, dual
   Ed25519 + ML-DSA-65 signatures, ChaCha20-Poly1305 sealing.
2. :mod:`aegis.biometric_auth` — fuzzy-extractor biometrics (no stored templates,
   no raw hashes) with a reported entropy budget.
3. :mod:`aegis.zkp_validator` — Schnorr proofs over a validated 2048-bit group,
   Pedersen commitments, single-use nullifiers.
4. :mod:`aegis.blockchain_ledger` — hash-chained, signed, Merkle-committed audit
   log. Tamper-evident, and explicitly *not* immutable.
5. :mod:`aegis.guardian_ai` — deterministic behavioural sentinel. Statistics, not
   a trained model; an LLM may be attached as an escalate-only advisor.
6. :mod:`aegis.polymorphic_engine` — six-hour vocabulary rotation. Keyed, and
   honestly labelled: it defeats stale copies, not a key-holding receiver.
7. :mod:`aegis.geo_hardware_lock` — device binding (real) plus geofencing
   (administrative, spoofable, always reported as such).
8. :mod:`aegis.vajra` — the Sanskrit layer. Encoding and mnemonic, never a cipher.

:mod:`aegis.gate` chains them. The chain is mandatory in the sense that every
request passes every layer in order and a refusal at any layer stops the request —
but "mandatory" is a code path, not a proof: read :func:`aegis.gate.Gateway.decide`
and see for yourself.

The one thing this package will not do
--------------------------------------
The brief's acceptance criterion is that a payload stays secret until the year
2126 against "any human, AI, quantum computer or agency". No implementation can
meet that, and any implementation that claims it is lying. What is here instead:

* genuine, standard cryptography (FIPS 203/204, RFC 8439, RFC 5869, RFC 3526),
* capability detection everywhere, so a missing wheel degrades the *claims*
  rather than silently faking them,
* every layer reporting its own limits in ``describe()``/``report()`` and in
  ``specs/aegis_security.md``.

Run ``python -m aegis report`` for the full picture, including which backends are
actually present on this machine.
"""

from __future__ import annotations

from typing import Any, Dict

from .capabilities import Capabilities, backend_report, capabilities, fingerprint

__all__ = [
    "capabilities",
    "backend_report",
    "fingerprint",
    "Capabilities",
    "__version__",
    "HONESTY",
    "report",
    "layers",
]

__version__ = "2.0.0"

#: Stated once, imported everywhere, so no docstring has to do the job alone.
HONESTY = {
    "claim_not_made": "unbreakable / unbreakable-for-100-years / uncrackable by any agency",
    "why": (
        "all cryptographic guarantees are computational and time-bounded, and they cover the "
        "mathematics, not the endpoint: a compromised device, a stolen key or a coerced operator "
        "defeats every layer at once"
    ),
    "what_is_claimed": "standard, verifiable primitives, correct composition, and recorded limits",
    "vajra_is_a_cipher": False,
}


def layers() -> Dict[int, Dict[str, str]]:
    """The eight layers, in the fixed order the gateway applies them."""
    return {
        1: {"module": "aegis.pqc_engine", "name": "post-quantum hybrid crypto", "class": "Sealer"},
        2: {"module": "aegis.biometric_auth", "name": "biometric verification", "class": "BiometricVault"},
        3: {"module": "aegis.zkp_validator", "name": "zero-knowledge proofs", "class": "Verifier"},
        4: {"module": "aegis.blockchain_ledger", "name": "access ledger", "class": "Ledger"},
        5: {"module": "aegis.guardian_ai", "name": "guardian sentinel", "class": "Sentinel"},
        6: {"module": "aegis.polymorphic_engine", "name": "polymorphic syntax", "class": "PolymorphicEngine"},
        7: {"module": "aegis.geo_hardware_lock", "name": "geo + hardware lock", "class": "HardwareLock"},
        8: {"module": "aegis.vajra", "name": "VAJRA Sanskrit layer", "class": "vajra_report"},
    }


def report() -> Dict[str, Any]:
    """The whole system's self-description: capabilities, layers, honest limits."""
    return {
        "version": __version__,
        "name": "AEGIS",
        "expansion": "Autonomous Encrypted Gateway for Intelligent Systems",
        "layers": layers(),
        "capabilities": backend_report(),
        "honesty": dict(HONESTY),
        "surfaces": [
            "python -m aegis report",
            "python -m aegis demo",
            "specs/aegis_security.md",
            "specs/vajra_sanskrit.md",
        ],
    }
