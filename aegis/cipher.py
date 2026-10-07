"""AEAD for AEGIS: ChaCha20-Poly1305 (RFC 8439).

Two backends, one API:

* ``cryptography`` (preferred) — audited, constant-time, hardware accelerated.
* a reference implementation in :mod:`aegis._chacha` — no dependencies at all,
  validated against the RFC 8439 test vectors and, when ``cryptography`` is
  present, cross-checked against it in the test-suite.

The reference backend is deliberately *not* described as hardened: it is pure
Python, so it is not constant-time. It exists so that a sealed payload is never
unopenable just because a wheel would not build, and every sealed envelope
records which backend produced it.
"""

from __future__ import annotations

import hmac as _hmac
import os
import secrets
from typing import Optional, Tuple

from . import _chacha

__all__ = ["KEY_BYTES", "NONCE_BYTES", "TAG_BYTES", "aead_backend", "encrypt", "decrypt", "AeadError"]

#: 32-byte keys, 96-bit nonces, 128-bit tags: the RFC 8439 parameters.
KEY_BYTES = 32
NONCE_BYTES = 12
TAG_BYTES = 16


class AeadError(Exception):
    """Raised when a ciphertext fails authentication. Never leaks why."""


def aead_backend() -> str:
    """Return the backend name that :func:`encrypt` will use."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305  # noqa: F401

        return "cryptography-chacha20poly1305"
    except Exception:  # pragma: no cover - depends on the host
        return "pure-python-chacha20poly1305"


def _cryptography():
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    return ChaCha20Poly1305


def new_nonce() -> bytes:
    return secrets.token_bytes(NONCE_BYTES)


def encrypt(key: bytes, plaintext: bytes, aad: bytes = b"", nonce: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """Seal ``plaintext``. Returns ``(nonce, ciphertext_with_tag)``.

    ``aad`` is authenticated but not encrypted — AEGIS puts the envelope header
    there, so tampering with routing metadata breaks decryption.
    """
    if len(key) != KEY_BYTES:
        raise ValueError(f"key must be {KEY_BYTES} bytes, got {len(key)}")
    nonce = nonce or new_nonce()
    if len(nonce) != NONCE_BYTES:
        raise ValueError(f"nonce must be {NONCE_BYTES} bytes")

    backend = aead_backend()
    if backend == "cryptography-chacha20poly1305":
        sealed = _cryptography()(key).encrypt(nonce, plaintext, aad)
    else:  # pragma: no cover - exercised on hosts without the wheel
        sealed = _chacha.aead_encrypt(key, nonce, plaintext, aad)
    return nonce, sealed


def decrypt(key: bytes, nonce: bytes, sealed: bytes, aad: bytes = b"") -> bytes:
    """Open a sealed value. Raises :class:`AeadError` if it was tampered with."""
    if len(key) != KEY_BYTES:
        raise ValueError(f"key must be {KEY_BYTES} bytes, got {len(key)}")
    if len(nonce) != NONCE_BYTES:
        raise ValueError(f"nonce must be {NONCE_BYTES} bytes")

    backend = aead_backend()
    try:
        if backend == "cryptography-chacha20poly1305":
            return _cryptography()(key).decrypt(nonce, sealed, aad)
        return _chacha.aead_decrypt(key, nonce, sealed, aad)  # pragma: no cover
    except AeadError:
        raise
    except Exception as exc:  # cryptography raises InvalidTag
        raise AeadError("authentication failed: the payload was modified or the key is wrong") from exc


def constant_time_equal(left: bytes, right: bytes) -> bool:
    return _hmac.compare_digest(left, right)


def random_bytes(length: int) -> bytes:
    return os.urandom(length)
