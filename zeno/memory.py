"""Conversation memory: everything the agent hears is kept, and kept sealed.

What this module is for: an agent that talks to you should remember what was
said, and *you* should be the only one who can read it. So every record is sealed
with the AEGIS hybrid sealer (X25519 + ML-KEM-768, ChaCha20-Poly1305) to the
owner's public identity, and written to an append-only log whose lines are chained
by digest.

Honest limits, stated here rather than in a footnote:

* **Tamper-evident, not immutable.** Each line carries the digest of the previous
  one, so an edit, a reorder or a deletion is detectable by ``verify()``. Anyone
  who can rewrite the whole file can also rewrite the chain — the same caveat the
  audit ledger carries, and for the same reason.
* **Sealed to the owner, not to the session.** One key opens everything the owner
  has stored. Per-session keys are not implemented.
* **Without an owner identity, records are plaintext.** That is the development
  mode, the file says ``"encrypted": false`` on every line, and the API reports
  it: the fallback is visible, never silent.
* **The seal has no forward secrecy.** A record sealed today can be opened by
  anyone who later obtains the owner's private key. Rotating that key does not
  re-protect history.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from aegis.capabilities import capabilities

DEFAULT_ROOT = "~/.zeno/memory"
#: A single memory line is capped so a runaway turn cannot fill the disk. Records
#: are text and small metadata; audio goes to its own file, not into this log.
MAX_RECORD_BYTES = 256 * 1024


def _now() -> float:
    return time.time()


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class Session:
    """One conversation thread."""

    id: str
    started_at: float = field(default_factory=_now)
    last_at: float = field(default_factory=_now)
    turns: int = 0
    languages: List[str] = field(default_factory=list)
    title: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "started_at": self.started_at,
            "last_at": self.last_at,
            "turns": self.turns,
            "languages": list(self.languages),
            "title": self.title,
        }


class MemoryStore:
    """An append-only, sealed log of what was said, per session.

    Layout: ``<root>/<session>.jsonl`` for text turns and
    ``<root>/<session>/audio/<record-id>.bin`` for audio, which is sealed whole
    (it is already opaque bytes, so a JSON envelope would only add base64 bloat).
    """

    def __init__(
        self,
        root: Optional[str] = None,
        *,
        owner: Any = None,
        sealer: Any = None,
        seal: bool = True,
    ) -> None:
        """``owner`` is the private AEGIS :class:`Identity` of whoever may read this.

        It is the *private* half on purpose: memory is sealed to the owner, so the
        owner is also the only party able to open it. ``OwnerRoot.identity`` can be
        passed directly, which is what the CLI does, so the same key that issues
        capability grants opens your own records."""
        self.root = Path(os.path.expanduser(root or os.environ.get("ZENO_MEMORY_ROOT") or DEFAULT_ROOT))
        # The directory is created on first write, not on construction: starting a
        # server (or importing a module in a test) must not leave a new folder in
        # the user's home.
        self.owner = owner
        self._sealer = sealer
        self.seal = bool(seal)

    @property
    def owner_public(self) -> Any:
        """The public half of the owner identity, or ``None`` when unconfigured."""
        return getattr(self.owner, "public", None)

    # -- keys --------------------------------------------------------------
    @classmethod
    def create_owner(cls, path: str) -> "Path":
        """Mint a standalone identity file to seal memory with, mode ``0600``."""
        from aegis.pqc_engine import generate_identity

        target = Path(os.path.expanduser(path))
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            raise FileExistsError(f"{target} already exists; refusing to overwrite a key")
        identity = generate_identity("zeno-memory-owner")
        target.write_text(json.dumps(identity.to_dict(redact_secrets=False), sort_keys=True), encoding="utf-8")
        os.chmod(target, 0o600)
        return target

    @classmethod
    def load_owner(cls, path: str) -> Any:
        """Load the owner's private identity from a key file or an owner-root file."""
        from aegis.capability import CapabilityError, OwnerRoot
        from aegis.pqc_engine import Identity

        target = Path(os.path.expanduser(path))
        if not target.is_file():
            raise FileNotFoundError(f"no memory key at {target}")
        mode = target.stat().st_mode & 0o777
        if mode & 0o077:
            raise PermissionError(
                f"{target} is mode {mode:o}: a key that seals everything you say must not be "
                "readable by anyone else (chmod 600 it, or mint a new one)"
            )
        payload = json.loads(target.read_text(encoding="utf-8"))
        if "identity" in payload:  # an owner-root file from `python -m aegis owner init`
            return OwnerRoot.load(target).identity
        if "secrets" not in payload:
            raise ValueError(f"{target} has no private half: it cannot open sealed memory")
        return Identity.from_dict(payload)

    # -- configuration -----------------------------------------------------
    @property
    def encrypting(self) -> bool:
        """Whether records are actually sealed, as opposed to merely claimed."""
        return bool(self.seal and self.owner_public is not None and self._can_seal())

    def _can_seal(self) -> bool:
        caps = capabilities()
        return bool(caps.aead and (caps.classical or caps.pqc_kem))

    def _sealer_for(self) -> Any:
        """The sealer is the owner's own identity: sealed to them, opened by them."""
        if self._sealer is None:
            from aegis.pqc_engine import Sealer

            self._sealer = Sealer(self.owner)
        return self._sealer

    def describe(self) -> Dict[str, Any]:
        return {
            "root": str(self.root),
            "encrypted": self.encrypting,
            "scheme": "aegis-hybrid-ed25519-ml-dsa-65 + x25519+ml-kem-768 / chacha20-poly1305"
            if self.encrypting
            else None,
            "owner_fingerprint": getattr(self.owner_public, "fingerprint", None),
            "owner_key": "loaded" if self.owner is not None else "absent",
            "limits": [
                "tamper-evident, not immutable: a full rewrite of the file rewrites the chain too",
                "one owner key opens every session; per-session keys are not implemented",
                "no forward secrecy: a later key compromise opens earlier records",
                "without an owner identity, records are stored as plaintext and say so",
            ],
        }

    # -- writing -----------------------------------------------------------
    def _ensure_root(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.root, 0o700)
        except OSError:  # pragma: no cover - a filesystem that will not allow it
            pass

    def record(
        self,
        session: str,
        *,
        kind: str,
        role: str = "user",
        text: str = "",
        lang: str = "",
        meta: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Append one record and return its envelope (the part that is stored)."""
        self._ensure_root()
        path = self._session_path(session)
        previous = self._last_envelope(path)
        record_id = uuid.uuid4().hex
        body: Dict[str, Any] = {
            "id": record_id,
            "session": session,
            "kind": kind,
            "role": role,
            "text": text,
            "lang": lang,
            "at": _now(),
            "meta": dict(meta or {}),
        }
        raw = json.dumps(body, ensure_ascii=False, sort_keys=True).encode("utf-8")
        if len(raw) > MAX_RECORD_BYTES:
            raise ValueError(
                f"record of {len(raw)} bytes exceeds MAX_RECORD_BYTES ({MAX_RECORD_BYTES}); "
                "audio belongs in the audio store, not in a text record"
            )

        envelope: Dict[str, Any] = {
            "id": record_id,
            "session": session,
            "kind": kind,
            "role": role,
            "lang": lang,
            "at": body["at"],
            "encrypted": self.encrypting,
            "prev": previous.get("digest", "") if previous else "",
            "bytes": len(raw),
        }
        if self.encrypting:
            envelope["sealed"] = self._sealer_for().seal(raw, recipient=self.owner_public).to_dict()
        else:
            envelope["plaintext"] = body
        envelope["digest"] = self._envelope_digest(envelope)

        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(envelope, ensure_ascii=False, sort_keys=True) + "\n")
        return envelope

    def open_record(self, envelope: Dict[str, Any]) -> Dict[str, Any]:
        """Decrypt one envelope back into its body. Raises on a broken seal."""
        if "plaintext" in envelope:
            return dict(envelope["plaintext"])
        from aegis.pqc_engine import SealedBox

        box = SealedBox.from_dict(envelope["sealed"])
        raw = self._sealer_for().open(box)
        return json.loads(raw.decode("utf-8"))

    def _envelope_digest(self, envelope: Dict[str, Any]) -> str:
        content = {key: value for key, value in envelope.items() if key != "digest"}
        return digest(json.dumps(content, ensure_ascii=False, sort_keys=True).encode("utf-8"))

    def _session_path(self, session: str) -> Path:
        safe = "".join(character for character in session if character.isalnum() or character in "-_.")[:80]
        if not safe:
            raise ValueError("session id must contain at least one safe character")
        return self.root / f"{safe}.jsonl"

    def _last_envelope(self, path: Path) -> Optional[Dict[str, Any]]:
        if not path.is_file():
            return None
        last: Optional[Dict[str, Any]] = None
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    last = json.loads(line)
        return last

    # -- reading -----------------------------------------------------------
    def envelopes(self, session: str) -> List[Dict[str, Any]]:
        path = self._session_path(session)
        if not path.is_file():
            return []
        out: List[Dict[str, Any]] = []
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
        return out

    def read(self, session: str, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Decrypt a session's records, oldest first (``limit`` keeps the newest)."""
        envelopes = self.envelopes(session)
        if limit is not None:
            envelopes = envelopes[-int(limit):]
        return [self.open_record(envelope) for envelope in envelopes]

    def sessions(self) -> List[Dict[str, Any]]:
        found: List[Dict[str, Any]] = []
        for path in sorted(self.root.glob("*.jsonl")):
            envelopes = self.envelopes(path.stem)
            if not envelopes:
                continue
            languages = sorted({str(item.get("lang") or "") for item in envelopes} - {""})
            found.append(
                Session(
                    id=path.stem,
                    started_at=float(envelopes[0].get("at") or 0.0),
                    last_at=float(envelopes[-1].get("at") or 0.0),
                    turns=len(envelopes),
                    languages=languages,
                    title=str((envelopes[0].get("session") or ""))[:60],
                ).to_dict()
            )
        return found

    def search(self, query: str, *, limit: int = 50, sessions: Optional[Iterable[str]] = None) -> List[Dict[str, Any]]:
        """Substring search over decrypted records.

        Bounded and linear on purpose: the honest description of this is "grep
        over your own memory", not a semantic index. Every session's ciphertext
        must be decrypted to search it, which is why the limit exists.
        """
        needle = (query or "").strip().lower()
        if not needle:
            return []
        hits: List[Dict[str, Any]] = []
        names = list(sessions) if sessions is not None else [item["id"] for item in self.sessions()]
        for name in names:
            for body in self.read(name):
                if needle in str(body.get("text", "")).lower():
                    hits.append(body)
                    if len(hits) >= limit:
                        return hits
        return hits

    # -- audio -------------------------------------------------------------
    def audio_path(self, session: str, record_id: str) -> Path:
        safe_session = self._session_path(session).stem
        folder = self.root / safe_session / "audio"
        folder.mkdir(parents=True, exist_ok=True)
        safe_id = "".join(character for character in record_id if character.isalnum())[:64]
        return folder / f"{safe_id}.bin"

    def store_audio(self, session: str, record_id: str, data: bytes) -> Dict[str, Any]:
        """Seal a blob of audio and write it next to the session's log."""
        envelope: Dict[str, Any] = {
            "record": record_id,
            "session": session,
            "bytes": len(data),
            "digest": digest(data),
            "encrypted": self.encrypting,
            "at": _now(),
        }
        if self.encrypting:
            envelope["sealed"] = self._sealer_for().seal(data, recipient=self.owner_public).to_dict()
        else:
            envelope["plaintext_b64"] = __import__("base64").b64encode(data).decode("ascii")
        path = self.audio_path(session, record_id)
        path.write_text(json.dumps(envelope, sort_keys=True), encoding="utf-8")
        try:
            os.chmod(path, 0o600)
        except OSError:  # pragma: no cover
            pass
        return {key: value for key, value in envelope.items() if key not in ("sealed", "plaintext_b64")}

    def load_audio(self, session: str, record_id: str) -> bytes:
        path = self.audio_path(session, record_id)
        envelope = json.loads(path.read_text(encoding="utf-8"))
        if "plaintext_b64" in envelope:
            import base64

            data = base64.b64decode(envelope["plaintext_b64"])
        else:
            from aegis.pqc_engine import SealedBox

            data = self._sealer_for().open(SealedBox.from_dict(envelope["sealed"]))
        if digest(data) != envelope.get("digest"):
            raise ValueError("stored audio does not match its recorded digest")
        return data

    # -- integrity ---------------------------------------------------------
    def verify(self, session: Optional[str] = None) -> Dict[str, Any]:
        """Check the chain and (when sealed) that every record still decrypts."""
        names = [session] if session else [item["id"] for item in self.sessions()]
        report: Dict[str, Any] = {
            "sessions": {},
            "ok": True,
            "encrypted": self.encrypting,
            "checked": 0,
            "problems": [],
        }
        for name in names:
            previous = ""
            problems: List[str] = []
            envelopes = self.envelopes(name)
            for index, envelope in enumerate(envelopes):
                if envelope.get("prev", "") != previous:
                    problems.append(f"line {index + 1}: chain broken (prev does not match)")
                if self._envelope_digest(envelope) != envelope.get("digest"):
                    problems.append(f"line {index + 1}: digest does not match the content")
                try:
                    self.open_record(envelope)
                except Exception as error:  # noqa: BLE001 - any failure here is the finding
                    problems.append(f"line {index + 1}: cannot be opened ({type(error).__name__})")
                previous = envelope.get("digest", "")
                report["checked"] += 1
            report["sessions"][name] = {"records": len(envelopes), "problems": problems}
            if problems:
                report["ok"] = False
                report["problems"].extend(f"{name}: {item}" for item in problems)
        return report

    def forget(self, session: str) -> int:
        """Delete one session. The rest of the store is untouched.

        This is the honest counterpart of "everything is saved": there has to be a
        way to unsave it, and it is destructive by design.
        """
        path = self._session_path(session)
        removed = len(self.envelopes(session))
        if path.is_file():
            path.unlink()
        folder = self.root / path.stem
        if folder.is_dir():
            for child in folder.rglob("*"):
                if child.is_file():
                    child.unlink()
            for child in sorted(folder.rglob("*"), reverse=True):
                if child.is_dir():
                    child.rmdir()
            folder.rmdir()
        return removed
