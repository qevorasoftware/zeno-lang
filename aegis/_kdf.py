"""HKDF-SHA256 (RFC 5869) and a few key-derivation helpers.

Standard library only, and verified against the RFC 5869 test vectors in
``tests/test_aegis.py``. AEGIS derives every symmetric key through this module:
the KEM shared secrets are never used directly as an encryption key.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Optional

__all__ = ["hkdf_extract", "hkdf_expand", "hkdf", "derive_key", "HASH_BYTES"]

HASH_BYTES = 32
_MAX_BLOCKS = 255


def hkdf_extract(salt: Optional[bytes], ikm: bytes) -> bytes:
    """RFC 5869 §2.2. ``salt`` may be empty, in which case a zero salt is used."""
    if salt is None:
        salt = b"\x00" * HASH_BYTES
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 §2.3."""
    if length > _MAX_BLOCKS * HASH_BYTES:
        raise ValueError("requested key material is too long")
    output = bytearray()
    previous = b""
    counter = 1
    while len(output) < length:
        previous = hmac.new(prk, previous + info + bytes([counter]), hashlib.sha256).digest()
        output.extend(previous)
        counter += 1
    return bytes(output[:length])


def hkdf(ikm: bytes, length: int = 32, *, salt: bytes = b"", info: bytes = b"") -> bytes:
    """Extract-then-expand in one call."""
    return hkdf_expand(hkdf_extract(salt, ikm), info, length)


def derive_key(
    secrets: list,
    length: int = 32,
    *,
    salt: bytes = b"",
    info: bytes = b"aegis/hybrid/v2",
) -> bytes:
    """Mix several shared secrets into one key.

    This is how the hybrid handshake stays hybrid even if one half is later
    broken: the key depends on *every* input, so an attacker who breaks X25519
    still needs the KEM secret, and vice versa.
    """
    if not secrets:
        raise ValueError("at least one secret is required")
    material = b"".join(len(secret).to_bytes(4, "big") + secret for secret in secrets)
    return hkdf(material, length, salt=salt, info=info)
