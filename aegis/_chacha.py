"""ChaCha20-Poly1305 (RFC 8439) reference implementation, standard library only.

This exists so AEGIS has a working AEAD when the ``cryptography`` wheel cannot
be installed. It is written to the RFC and is verified two ways in the
test-suite:

1. against the RFC 8439 §2.3.2 / §2.4.2 / §2.8.2 test vectors, and
2. against ``cryptography``'s ChaCha20Poly1305 on random inputs, when available.

It is pure Python and therefore **not constant-time**. Documented as such
everywhere it is exposed: use the ``cryptography`` backend for anything real.
"""

from __future__ import annotations

import struct
from typing import List

__all__ = ["chacha20_block", "chacha20_xor", "poly1305_mac", "aead_encrypt", "aead_decrypt"]

_CONSTANTS = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)
_MASK32 = 0xFFFFFFFF
_P255 = (1 << 130) - 5
_CLAMP = 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF


def _rotl(value: int, count: int) -> int:
    return ((value << count) & _MASK32) | (value >> (32 - count))


def _quarter_round(state: List[int], a: int, b: int, c: int, d: int) -> None:
    state[a] = (state[a] + state[b]) & _MASK32
    state[d] = _rotl(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & _MASK32
    state[b] = _rotl(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & _MASK32
    state[d] = _rotl(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & _MASK32
    state[b] = _rotl(state[b] ^ state[c], 7)


def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """One 64-byte ChaCha20 block (RFC 8439 §2.3)."""
    if len(key) != 32:
        raise ValueError("ChaCha20 needs a 32-byte key")
    if len(nonce) != 12:
        raise ValueError("ChaCha20 with a 96-bit nonce needs a 12-byte nonce")

    state = list(_CONSTANTS)
    state += list(struct.unpack("<8I", key))
    state.append(counter & _MASK32)
    state += list(struct.unpack("<3I", nonce))

    working = list(state)
    for _ in range(10):  # 20 rounds = 10 double rounds
        _quarter_round(working, 0, 4, 8, 12)
        _quarter_round(working, 1, 5, 9, 13)
        _quarter_round(working, 2, 6, 10, 14)
        _quarter_round(working, 3, 7, 11, 15)
        _quarter_round(working, 0, 5, 10, 15)
        _quarter_round(working, 1, 6, 11, 12)
        _quarter_round(working, 2, 7, 8, 13)
        _quarter_round(working, 3, 4, 9, 14)

    out = [(working[i] + state[i]) & _MASK32 for i in range(16)]
    return struct.pack("<16I", *out)


def chacha20_xor(key: bytes, counter: int, nonce: bytes, data: bytes) -> bytes:
    """Encrypt/decrypt ``data`` (the operation is its own inverse)."""
    result = bytearray(len(data))
    for offset in range(0, len(data), 64):
        keystream = chacha20_block(key, counter + offset // 64, nonce)
        chunk = data[offset : offset + 64]
        for index, byte in enumerate(chunk):
            result[offset + index] = byte ^ keystream[index]
    return bytes(result)


def poly1305_mac(one_time_key: bytes, message: bytes) -> bytes:
    """Poly1305 MAC (RFC 8439 §2.5)."""
    if len(one_time_key) != 32:
        raise ValueError("Poly1305 needs a 32-byte one-time key")
    r = int.from_bytes(one_time_key[:16], "little") & _CLAMP
    s = int.from_bytes(one_time_key[16:], "little")

    accumulator = 0
    for offset in range(0, len(message), 16):
        block = message[offset : offset + 16]
        chunk = int.from_bytes(block + b"\x01", "little")
        accumulator = ((accumulator + chunk) * r) % _P255
    tag = (accumulator + s) % (1 << 128)
    return tag.to_bytes(16, "little")


def _pad16(data: bytes) -> bytes:
    remainder = len(data) % 16
    return b"\x00" * (16 - remainder) if remainder else b""


def _mac_data(aad: bytes, ciphertext: bytes) -> bytes:
    return (
        aad
        + _pad16(aad)
        + ciphertext
        + _pad16(ciphertext)
        + struct.pack("<Q", len(aad))
        + struct.pack("<Q", len(ciphertext))
    )


def aead_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """RFC 8439 AEAD: returns ``ciphertext || tag``."""
    one_time_key = chacha20_block(key, 0, nonce)[:32]
    ciphertext = chacha20_xor(key, 1, nonce, plaintext)
    tag = poly1305_mac(one_time_key, _mac_data(aad, ciphertext))
    return ciphertext + tag


def aead_decrypt(key: bytes, nonce: bytes, sealed: bytes, aad: bytes = b"") -> bytes:
    """Verify then decrypt. Raises ``AeadError`` on any mismatch."""
    from .cipher import AeadError, constant_time_equal

    if len(sealed) < 16:
        raise AeadError("ciphertext is too short to carry a tag")
    ciphertext, tag = sealed[:-16], sealed[-16:]
    one_time_key = chacha20_block(key, 0, nonce)[:32]
    expected = poly1305_mac(one_time_key, _mac_data(aad, ciphertext))
    if not constant_time_equal(expected, tag):
        raise AeadError("authentication failed: the payload was modified or the key is wrong")
    return chacha20_xor(key, 1, nonce, ciphertext)
