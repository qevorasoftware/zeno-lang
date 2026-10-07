"""Runtime capability detection for AEGIS.

AEGIS never claims a primitive it cannot actually run. Every layer asks this
module what is available and reports the answer in its output, so a payload
sealed with a pure-Python fallback is never mistaken for one sealed by an
audited backend.

Run ``python -m aegis capabilities`` to see the table for the current machine.
"""

from __future__ import annotations

import hashlib
import platform
import sys
from dataclasses import dataclass, field
from typing import Dict, Optional

__all__ = ["capabilities", "Capabilities", "backend_report", "MissingBackend", "require_classical"]


class MissingBackend(RuntimeError):
    """Raised when a layer is asked to do something no installed wheel can do.

    AEGIS raises this instead of substituting a weaker mechanism: an
    unauthenticated fallback for key exchange or signatures is worse than a
    refusal, because the caller would go on believing the stronger claim.
    """


def require_classical(feature: str) -> None:
    """Refuse, with an actionable message, when ``cryptography`` is absent."""
    if not capabilities().classical:
        raise MissingBackend(
            f"{feature} needs the 'cryptography' package (X25519 / Ed25519 / scrypt / "
            "constant-time ChaCha20-Poly1305). Install it with "
            "`python -m pip install -e .[aegis]` or `pip install cryptography`. "
            "AEGIS refuses rather than substituting an unauthenticated fallback."
        )


def _try(importer) -> Optional[str]:
    try:
        return importer()
    except Exception:  # pragma: no cover - depends on the host
        return None


@dataclass(frozen=True)
class Capabilities:
    """What this installation of AEGIS can really do."""

    #: AEAD backend: ``cryptography`` (audited, constant-time) or ``pure-python``.
    aead: str
    #: Post-quantum KEM: ``ml-kem-768`` etc. when ``pqcrypto`` is installed.
    pqc_kem: Optional[str]
    #: Post-quantum signature: ``ml-dsa-65`` etc. when ``pqcrypto`` is installed.
    pqc_sign: Optional[str]
    #: Classical primitives from ``cryptography`` (X25519 / Ed25519).
    classical: bool
    tpm_present: bool
    python: str = field(default_factory=platform.python_version)
    platform: str = field(default_factory=platform.platform)

    @property
    def post_quantum(self) -> bool:
        return bool(self.pqc_kem and self.pqc_sign)

    @property
    def hybrid_ready(self) -> bool:
        """A hybrid (classical + post-quantum) handshake needs both halves."""
        return self.post_quantum and self.classical

    def to_dict(self) -> Dict[str, object]:
        return {
            "aead": self.aead,
            "post_quantum_kem": self.pqc_kem,
            "post_quantum_signature": self.pqc_sign,
            "classical": self.classical,
            "tpm_present": self.tpm_present,
            "hybrid_ready": self.hybrid_ready,
            "python": self.python,
            "platform": self.platform,
        }


def _tpm_present() -> bool:
    import os

    for path in ("/dev/tpm0", "/dev/tpmrm0", "/sys/class/tpm/tpm0"):
        if os.path.exists(path):
            return True
    return False


def capabilities() -> Capabilities:
    """Detect the available backends once per call (cheap, cached by callers)."""

    def aead() -> str:
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305  # noqa: F401

        return "cryptography-chacha20poly1305"

    def pqc_kem() -> str:
        from pqcrypto.kem import ml_kem_768  # noqa: F401

        return "ml-kem-768"

    def pqc_sign() -> str:
        from pqcrypto.sign import ml_dsa_65  # noqa: F401

        return "ml-dsa-65"

    def classical() -> bool:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: F401
            Ed25519PrivateKey,
        )

        return True

    return Capabilities(
        aead=_try(aead) or "pure-python-chacha20poly1305",
        pqc_kem=_try(pqc_kem),
        pqc_sign=_try(pqc_sign),
        classical=_try(classical) is True,
        tpm_present=_tpm_present(),
    )


def backend_report() -> str:
    """Human-readable capability table used by the CLI and the docs."""
    caps = capabilities()
    lines = [
        "AEGIS capability report",
        "=" * 46,
        f"  AEAD                 : {caps.aead}",
        f"  Post-quantum KEM     : {caps.pqc_kem or 'not installed (pip install pqcrypto)'}",
        f"  Post-quantum signing : {caps.pqc_sign or 'not installed (pip install pqcrypto)'}",
        f"  Classical (X25519/Ed25519) : {'yes' if caps.classical else 'no'}",
        f"  TPM device present   : {'yes' if caps.tpm_present else 'no'}",
        "-" * 46,
        f"  hybrid (PQ + classical) handshake : {'available' if caps.hybrid_ready else 'unavailable'}",
        "",
        "  Layer 8 (VAJRA) is an *encoding* layer, not a cipher: it is reported",
        "  as such because claiming otherwise would be a security lie.",
        "=" * 46,
    ]
    return "\n".join(lines)


def fingerprint() -> str:
    """A stable short id for this runtime (used in the capability table)."""
    material = f"{sys.version_info[:3]}:{platform.platform()}:{hashlib.sha256(b'aegis').hexdigest()[:8]}"
    return hashlib.sha256(material.encode()).hexdigest()[:16]
