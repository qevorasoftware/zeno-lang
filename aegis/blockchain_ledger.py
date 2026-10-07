"""Layer 4 — the access ledger.

A real hash-chained, Ed25519-signed, Merkle-committed append-only log. Every
access decision, every refused proof and every key rotation is written here, and
the ledger tells you — verifiably — whether it has been rewritten since.

Be precise about the guarantee
------------------------------
This is **tamper-evident**, not immutable. An attacker who can write the file
*and* steal the node's signing key can rewrite history and re-sign it; a copy of
the file on another machine cannot be trusted just because it verifies. Two
mechanisms make that expensive and detectable:

* :meth:`Ledger.anchor` returns the current head hash — publish it anywhere in a
  different trust domain (a timestamping service, a git commit, a colleague's
  mailbox) and any later rewrite is provable.
* Blocks are Merkle-committed, so :meth:`Ledger.inclusion_proof` lets you show a
  single access record without handing over the whole log.

The brief asked for "unauthorized entry = automatic network-wide lockdown". That
policy lives in :mod:`aegis.gate`; the honesty note is here: a lockdown trigger
that any unauthenticated actor can pull is a denial-of-service primitive. This
module therefore records *who* requested the freeze and leaves the decision
auditable, rather than hiding it behind "the blockchain did it".

    >>> from aegis.blockchain_ledger import Ledger, LedgerEntry
    >>> ledger = Ledger(node="gateway-1")
    >>> ledger.append(LedgerEntry(actor="amara", action="access", subject="zeno", decision="allow"))
    >>> ledger.verify().ok
    True
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from . import cipher
from ._kdf import hkdf

__all__ = [
    "Ledger",
    "LedgerEntry",
    "Block",
    "ChainStatus",
    "GENESIS",
    "merkle_root",
    "merkle_proof",
    "verify_merkle_proof",
]

GENESIS = "0" * 64
_NODE_INFO = b"aegis/ledger/v2"


def _canonical(payload: Dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _hash_bytes(*parts: bytes) -> str:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(len(part).to_bytes(4, "big"))
        digest.update(part)
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# Merkle tree
# ---------------------------------------------------------------------------
def merkle_root(leaves: Sequence[bytes]) -> str:
    """Root of a SHA-256 Merkle tree. Odd nodes are paired with themselves."""
    if not leaves:
        return GENESIS
    level = [hashlib.sha256(leaf).digest() for leaf in leaves]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [
            hashlib.sha256(level[index] + level[index + 1]).digest()
            for index in range(0, len(level), 2)
        ]
    return level[0].hex()


def merkle_proof(leaves: Sequence[bytes], index: int) -> List[Tuple[str, str]]:
    """Inclusion proof for ``index``: a list of ``(side, hash)`` steps."""
    if not 0 <= index < len(leaves):
        raise IndexError("leaf index out of range")
    level = [hashlib.sha256(leaf).digest() for leaf in leaves]
    path: List[Tuple[str, str]] = []
    position = index
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        sibling = position ^ 1
        path.append(("right" if sibling > position else "left", level[sibling].hex()))
        level = [
            hashlib.sha256(level[i] + level[i + 1]).digest() for i in range(0, len(level), 2)
        ]
        position //= 2
    return path


def verify_merkle_proof(leaf: bytes, path: Sequence[Tuple[str, str]], root: str) -> bool:
    current = hashlib.sha256(leaf).digest()
    for side, sibling_hex in path:
        sibling = bytes.fromhex(sibling_hex)
        current = (
            hashlib.sha256(sibling + current).digest()
            if side == "left"
            else hashlib.sha256(current + sibling).digest()
        )
    return current.hex() == root


# ---------------------------------------------------------------------------
# Entries and blocks
# ---------------------------------------------------------------------------
@dataclass
class LedgerEntry:
    """One audited event. ``subject`` is usually a payload hash, never a payload."""

    actor: str
    action: str
    subject: str = ""
    decision: str = "allow"
    seq: int = 0
    timestamp: float = field(default_factory=time.time)
    layer: str = ""
    reason: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def digest(self) -> str:
        return _hash_bytes(_canonical(asdict(self)))

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "LedgerEntry":
        known = {key: payload[key] for key in cls.__dataclass_fields__ if key in payload}
        return cls(**known)


@dataclass
class Block:
    """A sealed group of entries."""

    index: int
    entries: List[Dict[str, Any]]
    previous_hash: str
    merkle_root: str
    timestamp: float = field(default_factory=time.time)
    node: str = ""
    signature: str = ""
    hash: str = ""

    def compute_hash(self) -> str:
        return _hash_bytes(
            str(self.index).encode(),
            _canonical({"prev": self.previous_hash, "root": self.merkle_root, "node": self.node}),
            _canonical(self.entries),
            f"{self.timestamp:.6f}".encode(),
        )

    def seal(self, signer=None) -> "Block":
        self.hash = self.compute_hash()
        if signer is not None:
            self.signature = signer.sign_bytes(self.hash.encode())
        return self

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "Block":
        known = {key: payload[key] for key in cls.__dataclass_fields__ if key in payload}
        return cls(**known)


@dataclass
class ChainStatus:
    """The result of verifying the whole chain."""

    ok: bool
    blocks: int
    entries: int
    broken_at: Optional[int] = None
    reason: str = ""
    head: str = ""
    anchored: Optional[str] = None
    #: ``False`` when no node public key was recorded, so block signatures could
    #: not be checked at all. Reported rather than silently ignored.
    signatures_checked: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def render(self) -> str:
        state = "intact" if self.ok else f"BROKEN at block {self.broken_at}"
        lines = [
            f"ledger        : {state}",
            f"  blocks      : {self.blocks}",
            f"  entries     : {self.entries}",
            f"  head hash   : {self.head[:32]}",
        ]
        if self.anchored:
            lines.append(f"  last anchor : {self.anchored[:32]} (compare before trusting a copy)")
        if not self.ok:
            lines.append(f"  reason      : {self.reason}")
        if not self.signatures_checked:
            lines.append("  signatures  : NOT checked (no node public key recorded)")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------
class Ledger:
    """Append-only, signed, hash-chained log with Merkle commitments."""

    def __init__(
        self,
        node: str = "gateway",
        *,
        key_material: Optional[bytes] = None,
        block_size: int = 32,
        path: Optional[Path] = None,
    ) -> None:
        self.node = node
        self.block_size = block_size
        self.path = Path(path) if path else None
        self.blocks: List[Block] = []
        self._pending: List[LedgerEntry] = []
        self._seq = 0
        self._anchors: Dict[int, str] = {}
        self._signer = _NodeSigner(key_material or hkdf(f"aegis:{node}".encode(), 32, info=_NODE_INFO))
        self._public = self._signer.public
        self._fingerprint = self._signer.fingerprint

    # -- writing ---------------------------------------------------------
    def append(self, entry: LedgerEntry, *, seal: bool = False) -> LedgerEntry:
        entry.seq = entry.seq or (self._seq + 1)
        self._seq = entry.seq
        self._pending.append(entry)
        if seal or len(self._pending) >= self.block_size:
            self.seal_block()
        return entry

    def record(self, **fields: Any) -> LedgerEntry:
        """Convenience: ``ledger.record(actor="x", action="access")``."""
        return self.append(LedgerEntry(**fields))

    def seal_block(self) -> Optional[Block]:
        if not self._pending:
            return None
        entries = [entry.to_dict() for entry in self._pending]
        leaves = [_canonical(entry) for entry in entries]
        block = Block(
            index=len(self.blocks),
            entries=entries,
            previous_hash=self.blocks[-1].hash if self.blocks else GENESIS,
            merkle_root=merkle_root(leaves),
            node=self.node,
        ).seal(self._signer)
        self.blocks.append(block)
        self._pending = []
        self._persist()
        return block

    def anchor(self, *, label: str = "") -> str:
        """Record the head hash; publish it somewhere you do not control."""
        head = self.head_hash
        self._anchors[int(time.time())] = head
        self._persist()
        return head

    def anchor_history(self) -> List[Dict[str, Any]]:
        return [{"at": at, "head": head} for at, head in sorted(self._anchors.items())]

    # -- reading ---------------------------------------------------------
    @property
    def head_hash(self) -> str:
        if self.blocks:
            return self.blocks[-1].hash
        if self._pending:
            return _hash_bytes(_canonical([entry.to_dict() for entry in self._pending]))
        return GENESIS

    @property
    def entries(self) -> List[Dict[str, Any]]:
        return [entry for block in self.blocks for entry in block.entries] + [
            entry.to_dict() for entry in self._pending
        ]

    def by_actor(self, actor: str) -> List[Dict[str, Any]]:
        return [entry for entry in self.entries if entry.get("actor") == actor]

    def inclusion_proof(self, block_index: int, entry_index: int) -> List[Tuple[str, str]]:
        block = self.blocks[block_index]
        leaves = [_canonical(entry) for entry in block.entries]
        return merkle_proof(leaves, entry_index)

    def verify_inclusion(self, block_index: int, entry_index: int) -> bool:
        block = self.blocks[block_index]
        leaves = [_canonical(entry) for entry in block.entries]
        return verify_merkle_proof(
            leaves[entry_index], self.inclusion_proof(block_index, entry_index), block.merkle_root
        )

    # -- verification ----------------------------------------------------
    def verify(self, *, check_signatures: bool = True) -> ChainStatus:
        """Recompute every hash, root and signature. Never trusts the file."""
        entries = 0
        previous = GENESIS
        for block in self.blocks:
            entries += len(block.entries)
            if block.previous_hash != previous:
                return ChainStatus(False, len(self.blocks), entries, block.index, "previous_hash mismatch", self.head_hash)
            leaves = [_canonical(entry) for entry in block.entries]
            if merkle_root(leaves) != block.merkle_root:
                return ChainStatus(False, len(self.blocks), entries, block.index, "merkle root mismatch (an entry was edited)", self.head_hash)
            if block.compute_hash() != block.hash:
                return ChainStatus(False, len(self.blocks), entries, block.index, "block hash mismatch", self.head_hash)
            if check_signatures and self._public is not None:
                if not self._verify_signature(block):
                    return ChainStatus(
                        False, len(self.blocks), entries, block.index, "block signature invalid", self.head_hash
                    )
            previous = block.hash

        anchored = self._anchors[max(self._anchors)] if self._anchors else None
        return ChainStatus(
            ok=True,
            blocks=len(self.blocks),
            entries=entries,
            head=self.head_hash,
            anchored=anchored,
            signatures_checked=bool(check_signatures and self._public is not None),
        )

    def _verify_signature(self, block: Block) -> bool:
        from cryptography.exceptions import InvalidSignature

        if not block.signature:
            return False
        try:
            self._public.verify(bytes.fromhex(block.signature), block.hash.encode())
            return True
        except (InvalidSignature, ValueError):
            return False

    # -- persistence -----------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": 2,
            "node": self.node,
            "node_fingerprint": self._fingerprint,
            "block_size": self.block_size,
            "blocks": [block.to_dict() for block in self.blocks],
            "anchors": self.anchor_history(),
            "node_public_key": self._signer.public_hex,
            "note": "tamper-evident, not immutable: an attacker holding the node key can rewrite it",
        }

    def _persist(self) -> None:
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: Path, *, node: Optional[str] = None) -> "Ledger":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        ledger = cls(node=node or payload.get("node", "gateway"), path=Path(path))
        ledger.blocks = [Block.from_dict(block) for block in payload.get("blocks", [])]
        public = payload.get("node_public_key")
        if public:
            ledger._public = _NodeSigner.public_from_hex(public)
        else:
            ledger._public = None  # verification will report signatures_checked=False
        ledger._anchors = {int(item["at"]): item["head"] for item in payload.get("anchors", [])}
        return ledger

    # -- policy hooks ----------------------------------------------------
    def lockdown_requests(self) -> List[Dict[str, Any]]:
        """Every freeze ever requested, with the actor that asked for it."""
        return [entry for entry in self.entries if entry.get("action") in {"freeze", "lockdown"}]

    def security_notes(self) -> List[str]:
        return [
            "tamper-evident, not immutable: verification proves the file is internally consistent",
            "an adversary with write access AND the node signing key can rewrite the chain and re-sign it",
            "anchor the head hash in a second trust domain to make rewrites provable",
            "a lockdown any actor can trigger is a denial-of-service primitive; who asked is always recorded",
        ]


# ---------------------------------------------------------------------------
# Node signing
# ---------------------------------------------------------------------------
class _NodeSigner:
    """Ed25519 node key, derived deterministically from key material.

    Production note: this key protects the *ledger*, so it should live in a KMS
    or a TPM, not in a Python process. Derivation from a passphrase is a
    demonstration convenience, not a recommendation.
    """

    def __init__(self, material: bytes) -> None:
        from .capabilities import require_classical

        require_classical("signing ledger blocks (Ed25519)")
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        seed = hkdf(material, 32, info=_NODE_INFO + b"|sign")
        self._private = Ed25519PrivateKey.from_private_bytes(seed)
        self.public = self._private.public_key()
        self.public_hex = self.public.public_bytes_raw().hex()
        self.fingerprint = hashlib.sha256(self.public.public_bytes_raw()).hexdigest()[:16]

    def sign_bytes(self, message: bytes) -> str:
        return self._private.sign(message).hex()

    @staticmethod
    def public_from_hex(public_hex: str):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        return Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex))
