"""``python -m aegis`` — the operator's view of the gateway.

Subcommands
-----------
``report``        the whole system's self-description as JSON (default: pretty text)
``capabilities``  which cryptographic backends are actually present on this machine
``layers``        the eight layers in order, with what each one really provides
``demo``          runs one request through all eight layers and prints every verdict
``vajra TEXT``    wraps text in the Sanskrit encoding and measures what that is worth
``selftest``      exercises each layer in-process and prints pass/fail
"""

from __future__ import annotations

import argparse
import os
import pathlib
import sys
import time
import json
import sys
from typing import Any, Dict, List, Optional

from . import HONESTY, __version__, layers, report
from .capabilities import backend_report, capabilities


def _print_json(payload: Any) -> None:
    print(json.dumps(payload, indent=2, ensure_ascii=False, default=str))


def cmd_report(args: argparse.Namespace) -> int:
    payload = report()
    if args.json:
        _print_json(payload)
        return 0

    print(f"AEGIS v{payload['version']} — {payload['expansion']}")
    print("=" * 66)
    print(backend_report())
    print()
    print(f"{'#':<3}{'layer':<28}{'module':<28}{'what it really is'}")
    print("-" * 92)
    notes = {
        1: "hybrid PQ + classical encryption",
        2: "fuzzy extractor, no stored templates",
        3: "Schnorr proofs, no SNARK",
        4: "tamper-evident log (not immutable)",
        5: "statistics, not a trained model",
        6: "keyed rotation, not a cipher",
        7: "device binding real, geofence advisory",
        8: "encoding only — NOT a cipher",
    }
    for index, layer in layers().items():
        print(f"{index:<3}{layer['name']:<28}{layer['module']:<28}{notes[index]}")
    print()
    print("Claim NOT made:", HONESTY["claim_not_made"])
    print("Why:", HONESTY["why"])
    return 0


def cmd_capabilities(args: argparse.Namespace) -> int:
    if args.json:
        _print_json(capabilities().to_dict())
        return 0
    print(backend_report())
    caps = capabilities()
    print()
    print("  Honest consequence of the above:")
    if caps.pqc_kem and caps.pqc_sign:
        print("    - Layer 1 runs hybrid (X25519 + ML-KEM-768, Ed25519 + ML-DSA-65).")
    else:
        print("    - Layer 1 runs CLASSICAL ONLY and reports quantum_resistant=false.")
        print("    - pip install pqcrypto restores the post-quantum half.")
    print(f"    - AEAD backend: {caps.aead}")
    print(f"    - TPM: {'present' if caps.tpm_present else 'absent — device binding uses a file secret'}")
    return 0


def cmd_layers(args: argparse.Namespace) -> int:
    payload = {"layers": layers(), "order_is_load_bearing": True}
    if args.json:
        _print_json(payload)
        return 0
    for index, layer in layers().items():
        print(f"{index}. {layer['name']}  ({layer['module']})")
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    from .gate import Gateway, Policy, Request
    from .geo_hardware_lock import GeoFence, HardwareLock
    from .polymorphic_engine import PolymorphicEngine
    from .pqc_engine import generate_identity
    from .zkp_validator import Prover, SchnorrGroup, Verifier

    print("AEGIS end-to-end demo (all eight layers, real primitives)")
    print("=" * 66)

    group = SchnorrGroup.generate(args.group_bits, quiet=True)
    prover = Prover.from_secret(b"amara-identity", group=group, label="amara")
    gateway = Gateway(
        Policy(require_zkp=True, require_device_lock=False),
        verifier=Verifier(group),
        polymorphic=PolymorphicEngine(b"demo-rotation-key-32-bytes-padding"),
    )
    context = b"session-demo"
    proof = prover.prove(context=context)

    print("\n[1] request WITH a valid zero-knowledge proof")
    allowed = gateway.decide(
        Request(actor="amara", payload=b"@LOC[TYO] -> ?WX", context=context, proof=proof, statement=prover.public)
    )
    print(allowed.render())

    print("\n[2] the same proof replayed (nullifier already spent)")
    replayed = gateway.decide(
        Request(actor="amara", payload=b"@LOC[TYO] -> ?WX", context=context, proof=proof, statement=prover.public)
    )
    print(replayed.render())

    print("\n[3] outbound payload: rotated, wrapped, sealed to the gateway's own key")
    protection = gateway.protect(b"@LOC[TYO] -> ?WX", recipient=gateway.identity.public)
    print(protection.box.to_dict()["aead"], "| quantum_resistant:", protection.box.quantum_resistant)
    print("rotated payload:", protection.rotated)
    print("vajra wrap     :", (protection.wrapped or "")[:60], "…")
    restored = gateway.unprotect(protection, sender=gateway.identity.public)
    print("unprotected    :", restored.decode())

    print("\n[4] the VAJRA claim, measured rather than asserted")
    from .vajra.devanagari_wrapper import confidentiality_report

    measurement = confidentiality_report(b"@LOC[TYO] -> ?WX")
    print(f"    is_encryption       : {measurement['is_encryption']}")
    print(f"    requires_a_key      : {measurement['requires_a_key']}")
    print(f"    recovered_without_key: {measurement['recovered_without_key']}")

    print("\n[5] what is NOT claimed")
    print("   ", HONESTY["claim_not_made"])
    print("   ", HONESTY["why"])
    if args.json:
        _print_json({"allowed": allowed.to_dict(), "replayed": replayed.to_dict()})
    return 0


def cmd_vajra(args: argparse.Namespace) -> int:
    from .vajra import vajra_report
    from .vajra.devanagari_wrapper import decode, encode, unwrap, wrap
    from .vajra.paninian_grammar import to_devanagari

    text = args.text
    payload = text.encode("utf-8")
    wrapped = wrap(payload)
    if args.json:
        _print_json(
            {
                "input": text,
                "devanagari": to_devanagari(text),
                "wrapped": wrapped,
                "unwrapped": unwrap(wrapped).decode("utf-8", "replace"),
                "is_cipher": False,
                "report": vajra_report(),
            }
        )
        return 0

    print(f"input        : {text}")
    print(f"devanagari   : {to_devanagari(text)}")
    print(f"vajra wrap   : {wrapped[:90]}{'…' if len(wrapped) > 90 else ''}")
    print(f"unwrap       : {unwrap(wrapped).decode('utf-8', 'replace')}")
    print(f"raw decode   : {decode(encode(payload)).decode('utf-8', 'replace')} "
          f"(decode() takes the bare body; unwrap() strips the invocation)")
    report_payload = vajra_report()
    print(f"is a cipher  : {report_payload['is_a_cipher']}  (provides confidentiality: {report_payload['provides_confidentiality']})")
    return 0


def cmd_selftest(args: argparse.Namespace) -> int:
    checks: List[Dict[str, Any]] = []

    def check(name: str, function) -> None:
        try:
            outcome = function()
            checks.append({"check": name, "ok": bool(outcome), "detail": "" if outcome else "returned false"})
        except Exception as exc:  # noqa: BLE001 - a report, not a crash
            checks.append({"check": name, "ok": False, "detail": f"{type(exc).__name__}: {exc}"})

    def pqc_roundtrip() -> bool:
        from .pqc_engine import generate_identity, open_box, seal

        sender, recipient = generate_identity("s"), generate_identity("r")
        box = seal(b"payload", sender=sender, recipient=recipient.public)
        return open_box(box, recipient=recipient, sender=sender.public) == b"payload"

    def aead_tamper() -> bool:
        from . import cipher

        key = b"k" * 32
        nonce, sealed = cipher.encrypt(key, b"data")
        if cipher.decrypt(key, nonce, sealed) != b"data":
            return False
        try:
            cipher.decrypt(key, nonce, sealed[:-1] + bytes([sealed[-1] ^ 1]))
            return False  # a modified tag must never decrypt
        except cipher.AeadError:
            return True

    def zkp_replay() -> bool:
        from .zkp_validator import Prover, SchnorrGroup, Verifier

        group = SchnorrGroup.generate(1024, quiet=True)
        prover = Prover.from_secret(b"selftest", group=group)
        verifier = Verifier(group)
        proof = prover.prove(context=b"c")
        first = verifier.verify(prover.public, proof, context=b"c")
        return first and not verifier.verify(prover.public, proof, context=b"c")

    def ledger_tamper() -> bool:
        import json
        import tempfile
        from pathlib import Path

        from .blockchain_ledger import Ledger, LedgerEntry

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ledger.json"
            ledger = Ledger(node="selftest", block_size=2, path=path)
            ledger.append(LedgerEntry(actor="a", action="access", decision="allow"))
            ledger.append(LedgerEntry(actor="b", action="access", decision="deny"))
            ledger.seal_block()
            if not ledger.verify().ok:
                return False
            data = json.loads(path.read_text())
            data["blocks"][0]["entries"][0]["decision"] = "deny"
            path.write_text(json.dumps(data))
            return not Ledger.load(path).verify().ok

    def biometric_noise() -> bool:
        from .biometric_auth import BiometricVault, features_from_text

        vault = BiometricVault()
        template = features_from_text("selftest", dimensions=256)
        vault.enrol("s", template)
        noisy = [value + 0.02 for value in template]
        return vault.verify("s", noisy) and not vault.verify("s", features_from_text("other", dimensions=256))

    def sentinel_travel() -> bool:
        from .guardian_ai import Sentinel

        sentinel = Sentinel()
        for index in range(8):
            sentinel.observe(
                {
                    "actor": "a",
                    "action": "access",
                    "decision": "allow",
                    "timestamp": 1000.0 + index * 60,
                    "metadata": {"device": "d1", "latitude": 21.17, "longitude": 72.83, "hour": 10},
                }
            )
        decision = sentinel.observe(
            {
                "actor": "a",
                "action": "access",
                "decision": "allow",
                "timestamp": 2000.0,
                "metadata": {"device": "d1", "latitude": 51.5, "longitude": -0.12, "hour": 10},
            }
        )
        return decision.decision == "FREEZE"

    def vajra_roundtrip() -> bool:
        from .vajra import unwrap, wrap

        return unwrap(wrap(b"selftest")) == b"selftest"

    check("1 pqc hybrid seal/open", pqc_roundtrip)
    check("1 aead rejects tampering", aead_tamper)
    check("3 zkp accepts once, refuses replay", zkp_replay)
    check("4 ledger detects an edit", ledger_tamper)
    check("2 biometric tolerates noise", biometric_noise)
    check("5 sentinel flags impossible travel", sentinel_travel)
    check("8 vajra round trip", vajra_roundtrip)

    if args.json:
        _print_json({"checks": checks, "passed": sum(1 for c in checks if c["ok"]), "total": len(checks)})
    else:
        for item in checks:
            print(f"  [{'ok  ' if item['ok'] else 'FAIL'}] {item['check']}" + (f"  ({item['detail']})" if item["detail"] else ""))
        print(f"\n{sum(1 for c in checks if c['ok'])}/{len(checks)} checks passed")
    return 0 if all(item["ok"] for item in checks) else 1


# ---------------------------------------------------------------------------
# Owner: the root of trust (plan §3-4)
# ---------------------------------------------------------------------------
DEFAULT_OWNER_KEY = "~/.aegis/owner_root.json"


def cmd_owner(args: argparse.Namespace) -> int:
    """Issue, revoke and rotate the capability tokens the gateway accepts.

    Everything here has to be run by the owner, because everything here needs the
    owner's private key. The serving side only ever sees the public half.
    """
    from .capability import Capability, CapabilityError, CapabilityVerifier, OwnerRoot

    action = args.owner_action
    path = args.key

    if action == "init":
        if os.path.exists(os.path.expanduser(path)) and not args.force:
            print(f"{path} already exists (use --force to replace it)", file=sys.stderr)
            return 1
        root = OwnerRoot.create(
            name=args.issuer, audience=args.audience or "zeno-local", epoch=args.epoch
        )
        saved = root.save(path)
        payload = {
            "created": str(saved),
            "issuer": root.public.name,
            "fingerprint": root.fingerprint,
            "audience": root.audience,
            "epoch": root.epoch,
            "quantum_resistant": root.public.quantum_resistant,
            "file_mode": "0600",
            "warning": "keep this file offline; anyone holding it can mint authority",
        }
        if args.json:
            _print_json(payload)
        else:
            print(f"owner root created: {saved}")
            print(f"  issuer      : {root.public.name}")
            print(f"  fingerprint : {root.fingerprint}")
            print(f"  audience    : {root.audience}   epoch {root.epoch}")
            print(f"  hybrid      : {root.public.quantum_resistant}")
            print("  warning     : keep this file offline — anyone holding it can mint authority")
        return 0

    try:
        root = OwnerRoot.load(path)
    except FileNotFoundError:
        print(f"no owner key at {path}: run `python -m aegis owner init` first", file=sys.stderr)
        return 1
    except (ValueError, KeyError, CapabilityError) as error:
        print(f"cannot use the owner key: {error}", file=sys.stderr)
        return 1

    if action == "show":
        payload = root.to_dict() | {"path": os.path.expanduser(path)}
        if args.json:
            _print_json(payload)
        else:
            for key, value in payload.items():
                print(f"{key:16}: {value}")
        return 0

    if action == "issue":
        try:
            token = root.issue(
                args.subject,
                args.capability,
                audience=args.audience or None,
                ttl=args.ttl,
                semantic_scope_hash=args.semantic_scope or "",
            )
        except CapabilityError as error:
            print(f"refused: {error}", file=sys.stderr)
            return 1
        encoded = token.encode()
        if args.out:
            target = pathlib.Path(args.out).expanduser()
            target.write_text(encoded + "\n", encoding="utf-8")
            os.chmod(target, 0o600)
        payload = token.to_dict() | {"encoded": encoded, "verify_with": root.fingerprint}
        if args.json:
            _print_json(payload)
        else:
            print(f"token {token.token_id} for {token.subject}")
            print(f"  capabilities: {', '.join(token.capabilities)}")
            print(f"  audience    : {token.audience}   epoch {token.epoch}")
            print(f"  expires at  : {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(token.expires_at))}")
            print(f"  suite       : {token.crypto_suite} ({', '.join(token.required_algorithms)})")
            if args.out:
                print(f"  written to  : {os.path.expanduser(args.out)}")
            else:
                print(f"  token       : {encoded}")
        return 0

    if action == "revoke":
        try:
            token = Capability.decode(_read_token(args.token))
        except CapabilityError as error:
            print(f"cannot read the token: {error}", file=sys.stderr)
            return 1
        token_id = root.revoke(token)
        root.save(path)
        payload = {"revoked": token_id, "total": len(root.revocations)}
        if args.json:
            _print_json(payload)
        else:
            print(f"revoked {token_id} ({len(root.revocations)} total)")
        return 0

    if action == "rotate-epoch":
        epoch = root.rotate_epoch()
        root.save(path)
        payload = {"epoch": epoch, "effect": "every token from the previous epoch is now refused"}
        if args.json:
            _print_json(payload)
        else:
            print(f"owner epoch is now {epoch}: every token from the previous epoch is refused")
        return 0

    if action == "verify":
        try:
            token = Capability.decode(_read_token(args.token))
        except CapabilityError as error:
            print(f"cannot read the token: {error}", file=sys.stderr)
            return 1
        verifier = CapabilityVerifier(root.public, audience=args.audience, epoch=root.epoch,
                                      revocations=root.revocations)
        check = verifier.verify(token, action=args.action or "")
        payload = check.to_dict() | {"reason": check.reason}
        if args.json:
            _print_json(payload)
        else:
            print(f"{'ACCEPT' if check.ok else 'REFUSE'}: {check.reason or 'all checks passed'}")
            if check.ok:
                print(f"  subject     : {check.subject}")
                print(f"  capabilities: {', '.join(check.capabilities)}")
        return 0 if check.ok else 1

    print(f"unknown owner action {action!r}", file=sys.stderr)
    return 2


def _read_token(value: str) -> str:
    """Accept a token as the string itself, or a path to a file containing it."""
    expanded = os.path.expanduser(value)
    if os.path.exists(expanded):
        return pathlib.Path(expanded).read_text(encoding="utf-8").strip()
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegis",
        description="AEGIS — the eight-layer gateway in front of Zeno (honest edition).",
    )
    parser.add_argument("--version", action="version", version=f"aegis {__version__}")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    subparsers = parser.add_subparsers(dest="command")

    for name, handler, help_text in (
        ("report", cmd_report, "self-description: layers, capabilities, limits"),
        ("capabilities", cmd_capabilities, "which crypto backends are present"),
        ("layers", cmd_layers, "the eight layers, in order"),
        ("selftest", cmd_selftest, "exercise each layer in-process"),
    ):
        sub = subparsers.add_parser(name, help=help_text)
        # SUPPRESS keeps a global --json (given before the subcommand) from being
        # overwritten by the subparser default.
        sub.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
        sub.set_defaults(func=handler)

    demo = subparsers.add_parser("demo", help="run a request through all eight layers")
    demo.add_argument("--group-bits", type=int, default=1024, help="ZK group size (1024 is fast, 2048 is the default elsewhere)")
    demo.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
    demo.set_defaults(func=cmd_demo)

    owner = subparsers.add_parser(
        "owner", help="issue, revoke and rotate the owner-issued capability tokens"
    )
    owner.add_argument(
        "owner_action",
        choices=["init", "show", "issue", "revoke", "rotate-epoch", "verify"],
        help="what to do with the root of trust",
    )
    owner.add_argument(
        "--key",
        default=os.environ.get("ZENO_OWNER_KEY") or DEFAULT_OWNER_KEY,
        help="owner root key file (or set ZENO_OWNER_KEY)",
    )
    owner.add_argument("--issuer", default="owner_root", help="issuer name (init)")
    owner.add_argument(
        "--audience",
        default="",
        help="audience this root issues for (init: defaults to zeno-local; "
        "issue: defaults to the root's own audience)",
    )
    owner.add_argument("--epoch", type=int, default=1, help="starting epoch (init)")
    owner.add_argument("--force", action="store_true", help="replace an existing key file (init)")
    owner.add_argument("--subject", default="", help="who the token is for (issue)")
    owner.add_argument(
        "--capability", action="append", default=[], metavar="GRANT",
        help="a grant such as run:weather or execute:* (repeatable)",
    )
    owner.add_argument("--ttl", type=float, default=900.0, help="seconds until the token expires")
    owner.add_argument("--semantic-scope", default="", help="bind the token to a semantic hash")
    owner.add_argument("--out", default="", help="write the token to this file instead of stdout")
    owner.add_argument("--token", default="", help="token string or the file holding it")
    owner.add_argument("--action", default="", help="action to check, for `owner verify`")
    owner.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
    owner.set_defaults(func=cmd_owner)

    vajra = subparsers.add_parser("vajra", help="wrap text in the Sanskrit encoding and measure it")
    vajra.add_argument("text", help="text to wrap")
    vajra.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
    vajra.set_defaults(func=cmd_vajra)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.json = getattr(args, "json", False) or "--json" in (argv or sys.argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
