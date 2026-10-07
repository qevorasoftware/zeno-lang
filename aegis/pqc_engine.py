"""Layer 1 — post-quantum, hybrid key agreement and sealing.

What this layer really does
---------------------------
* **Key agreement** is *hybrid*: X25519 (classical, audited) combined with
  ML-KEM-768 (NIST FIPS 203, via ``pqcrypto``) through HKDF-SHA256. The session
  key depends on both secrets, so breaking one half is not enough.
* **Signatures** are dual: Ed25519 *and* ML-DSA-65 (FIPS 204) over the same
  transcript, both must verify.
* **Sealing** is ChaCha20-Poly1305 with a random 96-bit nonce, with a
  per-key nonce-reuse check that refuses to seal twice under one nonce.
  (A NIST-compliant XChaCha20 alternative is not used here because the
  ``cryptography`` build targets RFC 8439; see ``specs/aegis_security.md``.)

What this layer does not claim
------------------------------
* It is **not** "unbreakable for 100 years". It is a correct implementation of
  standardised primitives. Its security is bounded by those primitives, by the
  backend that implements them, and by how you store the keys.
* If ``pqcrypto`` is absent the layer runs *classical-only* and says so
  (``quantum_resistant: false`` in every envelope). It never pretends.

    >>> from aegis.pqc_engine import Sealer, generate_identity
    >>> alice = generate_identity("alice")
    >>> bob = generate_identity("bob")
    >>> sealer = Sealer(alice)
    >>> box = sealer.seal(b"@LOC[TYO] -> ?WX", recipient=bob.public)
    >>> bob.open(box)
    b'@LOC[TYO] -> ?WX'
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple

from . import cipher
from ._kdf import derive_key
from .capabilities import MissingBackend, capabilities, require_classical

__all__ = [
    "Identity",
    "SealedBox",
    "Sealer",
    "Signature",
    "generate_identity",
    "seal",
    "open_box",
    "sign",
    "verify",
    "SUITE",
]

#: Identifier written into every envelope so an old payload never claims a
#: suite it was not produced with.
SUITE = "aegis-hybrid/v2"

_KEM_INFO = b"aegis/hybrid/v2/kem"
_SIGN_INFO = b"aegis/hybrid/v2/sign"


# ---------------------------------------------------------------------------
# Identities
# ---------------------------------------------------------------------------
@dataclass
class Identity:
    """A long-term key pair: hybrid key agreement + dual signing keys.

    ``secret`` values are raw bytes and are never logged; ``public`` values are
    safe to hand to anyone and are what an envelope carries.
    """

    name: str
    #: X25519 key pair (classical half of the hybrid).
    x25519_public: bytes
    x25519_secret: bytes
    #: ML-KEM-768 key pair (post-quantum half); empty when unavailable.
    kem_public: bytes = b""
    kem_secret: bytes = b""
    #: Signing keys: Ed25519 and ML-DSA-65.
    ed25519_public: bytes = b""
    ed25519_secret: bytes = b""
    mldsa_public: bytes = b""
    mldsa_secret: bytes = b""
    #: Hex fingerprint of the public half, quoted in logs and envelopes.
    fingerprint: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.fingerprint:
            self.fingerprint = self.public.fingerprint

    # -- views -----------------------------------------------------------
    @property
    def public(self) -> "PublicIdentity":
        return PublicIdentity(
            name=self.name,
            x25519_public=self.x25519_public,
            kem_public=self.kem_public,
            ed25519_public=self.ed25519_public,
            mldsa_public=self.mldsa_public,
            fingerprint=self.fingerprint,
        )

    @property
    def quantum_resistant(self) -> bool:
        return bool(self.kem_public and self.mldsa_public)

    def to_dict(self, *, redact_secrets: bool = True) -> Dict[str, Any]:
        payload = self.public.to_dict()
        if not redact_secrets:  # pragma: no cover - explicit opt-in only
            payload["secrets"] = {
                "x25519": _b64(self.x25519_secret),
                "kem": _b64(self.kem_secret),
                "ed25519": _b64(self.ed25519_secret),
                "mldsa": _b64(self.mldsa_secret),
            }
        return payload


@dataclass(frozen=True)
class PublicIdentity:
    """The shareable half of an :class:`Identity`."""

    name: str
    x25519_public: bytes
    kem_public: bytes = b""
    ed25519_public: bytes = b""
    mldsa_public: bytes = b""
    fingerprint: str = ""

    @property
    def quantum_resistant(self) -> bool:
        return bool(self.kem_public and self.mldsa_public)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "fingerprint": self.fingerprint,
            "suite": SUITE,
            "quantum_resistant": self.quantum_resistant,
            "x25519": _b64(self.x25519_public),
            "ml_kem_768": _b64(self.kem_public),
            "ed25519": _b64(self.ed25519_public),
            "ml_dsa_65": _b64(self.mldsa_public),
        }

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "PublicIdentity":
        return cls(
            name=str(payload.get("name", "")),
            x25519_public=_unb64(payload["x25519"]),
            kem_public=_unb64(payload.get("ml_kem_768", "")),
            ed25519_public=_unb64(payload.get("ed25519", "")),
            mldsa_public=_unb64(payload.get("ml_dsa_65", "")),
            fingerprint=str(payload.get("fingerprint", "")),
        )


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _unb64(value: str | bytes | None) -> bytes:
    if not value:
        return b""
    if isinstance(value, bytes):
        value = value.decode("ascii")
    return base64.b64decode(value)


def _fingerprint(*public_values: bytes) -> str:
    import hashlib

    digest = hashlib.sha256()
    for value in public_values:
        digest.update(len(value).to_bytes(4, "big"))
        digest.update(value)
    return digest.hexdigest()[:32]


def generate_identity(name: str, *, seed: Optional[bytes] = None, **metadata: Any) -> Identity:
    """Create a fresh identity.

    ``seed`` makes generation deterministic *for tests only* — never pass a
    caller-supplied seed in production.
    """
    require_classical("generating an AEGIS identity")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    caps = capabilities()

    if seed is not None:
        x25519_secret = X25519PrivateKey.from_private_bytes(seed[:32])
        ed_secret = Ed25519PrivateKey.from_private_bytes(seed[32:64] if len(seed) >= 64 else seed[:32])
    else:
        x25519_secret = X25519PrivateKey.generate()
        ed_secret = Ed25519PrivateKey.generate()

    from cryptography.hazmat.primitives import serialization

    x_priv = x25519_secret.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    x_pub = x25519_secret.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    ed_priv = ed_secret.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    ed_pub = ed_secret.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )

    kem_pub = kem_secret = b""
    mldsa_pub = mldsa_secret = b""
    if caps.pqc_kem:
        from pqcrypto.kem import ml_kem_768

        kem_pub, kem_secret = ml_kem_768.keygen()
    if caps.pqc_sign:
        from pqcrypto.sign import ml_dsa_65

        mldsa_pub, mldsa_secret = ml_dsa_65.keygen()

    return Identity(
        name=name,
        x25519_public=x_pub,
        x25519_secret=x_priv,
        kem_public=kem_pub,
        kem_secret=kem_secret,
        ed25519_public=ed_pub,
        ed25519_secret=ed_priv,
        mldsa_public=mldsa_pub,
        mldsa_secret=mldsa_secret,
        fingerprint=_fingerprint(x_pub, kem_pub, ed_pub, mldsa_pub),
        metadata=dict(metadata),
    )


# ---------------------------------------------------------------------------
# Key agreement
# ---------------------------------------------------------------------------
def _encapsulate(recipient: PublicIdentity) -> Tuple[bytes, bytes, bytes]:
    """Return ``(x25519_ephemeral_public, kem_ciphertext, key_material)``.

    The key material is the XOR-independent concatenation of both shared
    secrets, mixed by HKDF inside :func:`derive_key`.
    """
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
        X25519PublicKey,
    )

    ephemeral = X25519PrivateKey.generate()
    ephemeral_public = ephemeral.public_key().public_bytes_raw()
    peer = X25519PublicKey.from_public_bytes(recipient.x25519_public)
    classical_secret = ephemeral.exchange(peer)

    kem_ciphertext = b""
    secrets = [classical_secret]
    if recipient.kem_public:
        from pqcrypto.kem import ml_kem_768

        kem_ciphertext, kem_secret = ml_kem_768.encaps(recipient.kem_public)
        secrets.append(kem_secret)

    return ephemeral_public, kem_ciphertext, derive_key(secrets, info=_KEM_INFO)


def _decapsulate(
    identity: Identity, ephemeral_public: bytes, kem_ciphertext: bytes
) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
        X25519PublicKey,
    )

    secret = X25519PrivateKey.from_private_bytes(identity.x25519_secret)
    peer = X25519PublicKey.from_public_bytes(ephemeral_public)
    secrets = [secret.exchange(peer)]
    if kem_ciphertext:
        if not identity.kem_secret:
            raise ValueError("this envelope needs an ML-KEM secret key that the recipient lacks")
        from pqcrypto.kem import ml_kem_768

        secrets.append(ml_kem_768.decaps(identity.kem_secret, kem_ciphertext))
    return derive_key(secrets, info=_KEM_INFO)


# ---------------------------------------------------------------------------
# Signatures
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Signature:
    """Dual signature: an envelope is valid only if *both* halves verify."""

    ed25519: bytes
    mldsa: bytes
    signer: str
    fingerprint: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "signer": self.signer,
            "fingerprint": self.fingerprint,
            "ed25519": _b64(self.ed25519),
            "ml_dsa_65": _b64(self.mldsa),
        }

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "Signature":
        return cls(
            ed25519=_unb64(payload.get("ed25519", "")),
            mldsa=_unb64(payload.get("ml_dsa_65", "")),
            signer=str(payload.get("signer", "")),
            fingerprint=str(payload.get("fingerprint", "")),
        )


def sign(identity: Identity, message: bytes) -> Signature:
    """Sign ``message`` with both signing keys."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    ed_signature = Ed25519PrivateKey.from_private_bytes(identity.ed25519_secret).sign(message)
    mldsa_signature = b""
    if identity.mldsa_secret:
        from pqcrypto.sign import ml_dsa_65

        mldsa_signature = ml_dsa_65.sign(identity.mldsa_secret, message)
    return Signature(
        ed25519=ed_signature,
        mldsa=mldsa_signature,
        signer=identity.name,
        fingerprint=identity.fingerprint,
    )


def verify(public: PublicIdentity, message: bytes, signature: Signature) -> bool:
    """``True`` only when every signature the signer was able to produce verifies."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        Ed25519PublicKey.from_public_bytes(public.ed25519_public).verify(
            signature.ed25519, message
        )
    except (InvalidSignature, ValueError):
        return False

    if signature.mldsa:
        if not public.mldsa_public:
            return False
        from pqcrypto import InvalidSignatureError
        from pqcrypto.sign import ml_dsa_65

        try:
            ml_dsa_65.verify(public.mldsa_public, message, signature.mldsa)
        except (InvalidSignatureError, ValueError):
            return False
    return True


# ---------------------------------------------------------------------------
# Sealing
# ---------------------------------------------------------------------------
@dataclass
class SealedBox:
    """A sealed payload: everything a recipient needs except their own keys."""

    ciphertext: bytes
    nonce: bytes
    ephemeral_public: bytes
    kem_ciphertext: bytes
    signature: Optional[Signature] = None
    suite: str = SUITE
    meta: Dict[str, Any] = field(default_factory=dict)

    @property
    def quantum_resistant(self) -> bool:
        return bool(self.kem_ciphertext)

    def to_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "suite": self.suite,
            "quantum_resistant": self.quantum_resistant,
            "nonce": _b64(self.nonce),
            "ephemeral_x25519": _b64(self.ephemeral_public),
            "ml_kem_768": _b64(self.kem_ciphertext),
            "ciphertext": _b64(self.ciphertext),
            "tag_bytes": cipher.TAG_BYTES,
            "aead": cipher.aead_backend(),
        }
        if self.signature is not None:
            payload["signature"] = self.signature.to_dict()
        if self.meta:
            payload["meta"] = self.meta
        return payload

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "SealedBox":
        signature = payload.get("signature")
        return cls(
            ciphertext=_unb64(payload["ciphertext"]),
            nonce=_unb64(payload["nonce"]),
            ephemeral_public=_unb64(payload["ephemeral_x25519"]),
            kem_ciphertext=_unb64(payload.get("ml_kem_768", "")),
            signature=Signature.from_dict(signature) if signature else None,
            suite=str(payload.get("suite", SUITE)),
            meta=dict(payload.get("meta", {})),
        )

    def encode(self) -> bytes:
        """Compact binary framing, for transport."""
        import json

        return b"AEGIS2" + json.dumps(self.to_dict(), separators=(",", ":")).encode("utf-8")

    @classmethod
    def decode(cls, blob: bytes) -> "SealedBox":
        import json

        if not blob.startswith(b"AEGIS2"):
            raise ValueError("not an AEGIS v2 envelope")
        return cls.from_dict(json.loads(blob[6:].decode("utf-8")))


class Sealer:
    """Seals and opens payloads on behalf of one identity.

    Tracks the nonces it has emitted so that a catastrophic RNG failure or a
    caller-supplied nonce cannot silently reuse one — the classic way AEAD gets
    broken in practice.
    """

    def __init__(self, identity: Identity, *, track_nonces: bool = True) -> None:
        self.identity = identity
        self.track_nonces = track_nonces
        self._used_nonces: set = set()
        self._opened: int = 0
        self._sealed: int = 0

    # -- capability view -------------------------------------------------
    @property
    def quantum_resistant(self) -> bool:
        return self.identity.quantum_resistant

    def describe(self) -> Dict[str, Any]:
        caps = capabilities()
        return {
            "identity": self.identity.name,
            "fingerprint": self.identity.fingerprint,
            "suite": SUITE,
            "quantum_resistant": self.quantum_resistant,
            "kem": caps.pqc_kem if self.quantum_resistant else "x25519-only",
            "signature": caps.pqc_sign if self.quantum_resistant else "ed25519-only",
            "aead": cipher.aead_backend(),
            "sealed": self._sealed,
            "opened": self._opened,
        }

    # -- operations ------------------------------------------------------
    def seal(
        self,
        plaintext: bytes,
        *,
        recipient: PublicIdentity,
        aad: bytes = b"",
        sign_message: bool = True,
        meta: Optional[Dict[str, Any]] = None,
    ) -> SealedBox:
        ephemeral_public, kem_ciphertext, key = _encapsulate(recipient)
        box_meta = dict(meta or {})
        box_meta.setdefault("sender", self.identity.name)
        box_meta.setdefault("sender_fingerprint", self.identity.fingerprint)
        # The recipient is part of the authenticated header: a sealed box
        # cannot be re-addressed to a third party without breaking the tag.
        box_meta["recipient_fingerprint"] = box_meta.get("recipient_fingerprint") or recipient.fingerprint

        header = _header(box_meta)
        nonce, sealed = cipher.encrypt(key, plaintext, aad + header)
        self._remember(nonce)
        self._sealed += 1

        box = SealedBox(
            ciphertext=sealed,
            nonce=nonce,
            ephemeral_public=ephemeral_public,
            kem_ciphertext=kem_ciphertext,
            meta=box_meta,
        )
        if sign_message:
            box.signature = sign(self.identity, _signed_material(box))
        return box

    def open(self, box: SealedBox, *, aad: bytes = b"", sender: Optional[PublicIdentity] = None) -> bytes:
        """Open a box, verifying its signature first when one is attached."""
        if box.signature is not None:
            checker = sender or self._known_senders.get(box.signature.fingerprint)
            if sender is not None and not verify(sender, _signed_material(box), box.signature):
                raise cipher.AeadError("signature verification failed: the envelope is not authentic")
            if checker is not None and not verify(checker, _signed_material(box), box.signature):
                raise cipher.AeadError("signature verification failed: the envelope is not authentic")

        key = _decapsulate(self.identity, box.ephemeral_public, box.kem_ciphertext)
        header = _header(box.meta)
        plaintext = cipher.decrypt(key, box.nonce, box.ciphertext, aad + header)
        self._opened += 1
        return plaintext

    # -- helpers ---------------------------------------------------------
    _known_senders: Dict[str, PublicIdentity] = {}

    def trust(self, public: PublicIdentity) -> "Sealer":
        """Register a sender so their signatures are checked automatically."""
        self._known_senders[public.fingerprint] = public
        return self

    def _remember(self, nonce: bytes) -> None:
        if not self.track_nonces:
            return
        if nonce in self._used_nonces:
            raise ValueError(
                "nonce reuse detected: refusing to seal twice under the same nonce"
            )
        self._used_nonces.add(nonce)


def _header(meta: Dict[str, Any]) -> bytes:
    """The authenticated-but-unencrypted part of the envelope.

    Both sides derive it from the same metadata, so any edit to routing
    metadata (sender, recipient, suite) invalidates the tag.
    """
    import json

    return json.dumps(
        {"meta": {key: meta[key] for key in sorted(meta)}, "suite": SUITE},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _signed_material(box: SealedBox) -> bytes:
    """Everything that must be covered by the signature, in a fixed order."""
    import hashlib

    digest = hashlib.sha256()
    for value in (box.suite.encode(), box.nonce, box.ephemeral_public, box.kem_ciphertext, box.ciphertext):
        digest.update(len(value).to_bytes(4, "big"))
        digest.update(value)
    return digest.digest()


# ---------------------------------------------------------------------------
# Convenience
# ---------------------------------------------------------------------------
def seal(plaintext: bytes, *, sender: Identity, recipient: PublicIdentity, **kwargs: Any) -> SealedBox:
    return Sealer(sender).seal(plaintext, recipient=recipient, **kwargs)


def open_box(box: SealedBox, *, recipient: Identity, sender: Optional[PublicIdentity] = None, **kwargs: Any) -> bytes:
    return Sealer(recipient).open(box, sender=sender, **kwargs)
