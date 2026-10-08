"""The deployment story: production mode on a platform such as Render.

``zeno serve --production`` behind a platform URL is a different animal from
the local playground: the filesystem is ephemeral, the only private channel
is an environment variable, and every effectful request needs an owner grant
the server must be able to verify. These tests pin that whole path — the
public-owner export, the env plumbing, and a real production server refusing
and honouring real grants — because a deployment that silently refuses
everything is worse than one that does not start.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from aegis.capabilities import capabilities

requires_crypto = pytest.mark.skipif(
    not capabilities().classical, reason="owner grants need the cryptography wheel"
)

#: The browser-profile e2e also needs the post-quantum wheel: layer 1 refuses
#: to run a production surface without it (refuse rather than downgrade).
requires_pqc = pytest.mark.skipif(
    not (capabilities().classical and capabilities().pqc_kem),
    reason="the production surface needs the pqcrypto wheel",
)


def _run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", *args], capture_output=True, text=True, timeout=120
    )


@pytest.fixture()
def owner(tmp_path: Path):
    """A real owner root + its public export, minted through the real CLI."""
    root = tmp_path / "owner-root.json"
    public = tmp_path / "owner-public.json"
    made = _run("aegis", "owner", "init", "--key", str(root), "--audience", "zeno-local")
    assert made.returncode == 0, made.stderr
    exported = _run(
        "aegis", "owner", "export-public", "--key", str(root), "--out", str(public)
    )
    assert exported.returncode == 0, exported.stderr
    return root, public


def _serve(playground):
    from zeno.server import _Handler

    handler = type("DeployHandler", (_Handler,), {"playground": playground})
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"http://{httpd.server_address[0]}:{httpd.server_address[1]}"


def _call(base: str, method: str, path: str, body: dict | None = None, token: str = ""):
    """One request the way the pages send them: nonce + X-Zeno-Capability."""
    from urllib.parse import quote

    nonce = f"n{time.monotonic_ns()}"
    if method == "GET":
        path = f"{path}{'&' if '?' in path else '?'}nonce={quote(nonce)}"
    request = urllib.request.Request(
        base + path,
        method=method,
        data=json.dumps({"nonce": nonce, **(body or {})}).encode() if body is not None else None,
        headers={"Content-Type": "application/json"},
    )
    if token:
        request.add_header("X-Zeno-Capability", token)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        raw = error.read().decode("utf-8", errors="replace")
        try:
            return error.code, json.loads(raw)
        except ValueError:
            return error.code, raw


import time  # noqa: E402 - used by _call


# ---------------------------------------------------------------------------
# The public-owner export
# ---------------------------------------------------------------------------
@requires_crypto
def test_export_public_is_public_only_and_server_loadable(owner, monkeypatch):
    """The export carries no secret, and the server's env parser accepts it —
    as a file path and as the JSON itself, because a platform env var is not
    a file."""
    from aegis.capability import OwnerRoot

    root_path, public_path = owner
    blob = public_path.read_text(encoding="utf-8")
    # nothing private may ship in an export meant for an env var
    assert "secret" not in blob
    root_file = root_path.read_text(encoding="utf-8")
    root_identity = json.loads(root_file)["identity"]
    for secret in root_identity.get("secrets", {}).values():
        assert secret not in blob, "a private key material appeared in the public export"

    from zeno.server import _owner_grant_verifier

    # as a path
    monkeypatch.setenv("ZENO_OWNER_PUBLIC", str(public_path))
    verifier = _owner_grant_verifier()
    assert verifier is not None
    assert verifier.owner_public.fingerprint == OwnerRoot.load(str(root_path)).fingerprint
    # as the JSON itself (the Render form)
    monkeypatch.setenv("ZENO_OWNER_PUBLIC", blob)
    inline = _owner_grant_verifier()
    assert inline is not None and inline.epoch == 1

    # a grant minted by this root verifies through the server's verifier
    root = OwnerRoot.load(str(root_path))
    token = root.issue("owner", ["read:settings"], ttl=300)
    assert verifier.verify(token, action="read:settings").ok

    # and revocations ship in the export, so revoked tokens stop working
    root.revoke(token)
    root.save(str(root_path))
    _run("aegis", "owner", "export-public", "--key", str(root_path), "--out", str(public_path))
    monkeypatch.setenv("ZENO_OWNER_PUBLIC", str(public_path))
    reloaded = _owner_grant_verifier()
    assert reloaded is not None
    assert not reloaded.verify(token, action="read:settings").ok


@requires_crypto
def test_a_broken_owner_export_is_a_loud_absence(monkeypatch, capsys):
    """A typo in the env var must not silently become 'grants work'."""
    from zeno.server import _owner_grant_verifier

    monkeypatch.setenv("ZENO_OWNER_PUBLIC", "{not json at all")
    assert _owner_grant_verifier() is None
    assert "ZENO_OWNER_PUBLIC" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Production, end to end, through the real boundary
# ---------------------------------------------------------------------------
@requires_pqc
def test_production_honours_real_grants_end_to_end(owner, monkeypatch, tmp_path):
    """The Render shape: production mode, the owner key in an env var, and a
    grant pasted into the page. Reads, settings writes and agent turns all
    pass with the grant — and refuse without it."""
    from aegis.capability import OwnerRoot
    from zeno.server import Playground

    root_path, public_path = owner
    monkeypatch.setenv("ZENO_OWNER_PUBLIC", str(public_path))
    # the Render shape: a browser-driven surface, where people talk
    monkeypatch.setenv("ZENO_PRODUCTION_PROFILE", "browser")
    monkeypatch.setenv("ZENO_SENTINEL_RATE_WEIGHT", "0")
    monkeypatch.setenv("ZENO_PROVIDERS_FILE", str(tmp_path / "providers.json"))
    playground = Playground(mode="production")
    assert playground.enforcement == "production"
    assert playground.boundary.capability_verifier is not None
    assert playground.boundary.gateway.sentinel.weights["rate"] == 0.0
    # the profile says what it is not: the four page-impossible layers, off
    policy = playground.boundary.policy.to_dict()["required"]
    assert policy["biometric"] is False and policy["zkp"] is False
    assert policy["device_lock"] is False and policy["polymorphic"] is False
    # and what it keeps: grants, nonces, the audited ledger, the sentinel
    report = playground.boundary.policy.to_dict()
    assert report["require_capability"] is True and report["require_nonce"] is True
    assert report["required"]["ledger"] is True and report["required"]["sentinel"] is True
    assert report["opaque_reasons"] is True and report["verify_ledger_signatures"] is True

    root = OwnerRoot.load(str(root_path))
    # the grant a page-driven deployment actually needs: reads, settings,
    # execution and the agent's own namespace (agent:turn)
    token = root.issue(
        "owner", ["read:*", "settings:*", "execute:*", "agent:*"], ttl=600
    ).encode()

    httpd, base = _serve(playground)
    try:
        # pages render for anyone; the APIs are what the grant gates
        status, health = _call(base, "GET", "/api/health")
        assert status == 200 and health["enforcement"] == "production"
        assert health["owner_grants"]["honored"] is True

        # without a grant: a machine code, no prose, no data
        status, refusal = _call(base, "GET", "/api/settings")
        assert status == 403
        assert refusal["error"]["code"].startswith("ZN-SEC-")

        # with the grant: the settings page's own flows work
        status, view = _call(base, "GET", "/api/settings", token=token)
        assert status == 200 and view["live"] is True
        status, saved = _call(
            base,
            "POST",
            "/api/settings/providers",
            body={
                "name": "render-openai",
                "provider": "openai",
                "model": "gpt-4o-mini",
                "api_key": "sk-not-a-real-key",
            },
            token=token,
        )
        assert status == 200, saved
        status, health = _call(base, "GET", "/api/health", token=token)
        assert status == 200 and health["provider"] == "openai"

        # and the agent answers with the grant — the whole point of the page
        status, turn = _call(
            base,
            "POST",
            "/api/voice/turn",
            body={"text": "hello", "language": "en"},
            token=token,
        )
        assert status == 200, turn
        assert turn.get("reply") or turn.get("answer") or turn.get("text")
    finally:
        httpd.shutdown()
        httpd.server_close()


@requires_crypto
def test_production_without_an_owner_key_refuses_everything(monkeypatch, tmp_path):
    """The unconfigured posture, said honestly: nothing effectful passes, and
    the refusal names the missing piece by its machine code."""
    from zeno.server import Playground

    monkeypatch.delenv("ZENO_OWNER_PUBLIC", raising=False)
    monkeypatch.setenv("ZENO_PROVIDERS_FILE", str(tmp_path / "providers.json"))
    playground = Playground(mode="production")
    assert playground.enforcement == "production"
    assert playground.boundary.capability_verifier is None

    httpd, base = _serve(playground)
    try:
        status, health = _call(base, "GET", "/api/health")
        assert status == 200 and health["owner_grants"]["honored"] is False
        status, refusal = _call(
            base,
            "POST",
            "/api/settings/providers",
            body={"name": "x", "provider": "mock"},
        )
        assert status == 403
        assert refusal["error"]["code"] == "ZN-SEC-0x9A0D"  # unconfigured
    finally:
        httpd.shutdown()
        httpd.server_close()


# ---------------------------------------------------------------------------
# Sealing on a platform: the key as an env var
# ---------------------------------------------------------------------------
@requires_crypto
def test_inline_key_data_seals_memory_and_providers(monkeypatch, tmp_path):
    """ZENO_MEMORY_KEY_DATA is the key file's JSON inline — the only private
    channel most platforms offer. Memory and provider keys seal with it."""
    from zeno.memory import MemoryStore
    from zeno.server import Playground

    key_file = tmp_path / "seal.json"
    MemoryStore.create_owner(str(key_file))
    monkeypatch.setenv("ZENO_MEMORY_KEY_DATA", key_file.read_text(encoding="utf-8"))
    monkeypatch.delenv("ZENO_MEMORY_KEY", raising=False)
    monkeypatch.setenv("ZENO_PROVIDERS_FILE", str(tmp_path / "providers.json"))

    playground = Playground()
    assert playground.memory.describe()["encrypted"] is True
    assert playground.provider_store.describe()["encrypted"] is True


def test_the_render_blueprint_matches_the_real_commands():
    """render.yaml is deployment configuration; if it drifts from what the
    server actually accepts, the blueprint silently breaks deploys."""
    yaml_text = (Path(__file__).resolve().parent.parent / "render.yaml").read_text(
        encoding="utf-8"
    )
    assert "python -m pip install -e .[aegis]" in yaml_text
    assert "python -m zeno serve --host 0.0.0.0 --port $PORT --production" in yaml_text
    assert "ZENO_OWNER_PUBLIC" in yaml_text
    assert "sync: false" in yaml_text  # secrets are pasted, never committed
    # the browser profile is the documented posture for a page-driven service
    assert "ZENO_PRODUCTION_PROFILE" in yaml_text and "browser" in yaml_text
    # and the blueprint stays key-material-free itself
    for banned in ("BEGIN ", "sk-", "gsk_"):
        assert banned not in yaml_text, f"render.yaml must never carry {banned!r}"


@requires_pqc
def test_a_terminal_wrapped_grant_still_authorizes(owner, monkeypatch, tmp_path):
    """`aegis owner issue` prints one very long line; terminals wrap it.

    An owner who copies the wrapped display used to paste a token the server
    could not read — reported, misleadingly, as 'no capability token
    supplied'. Decode now strips transport whitespace, and this proves it on a
    live production server: the same grant, newline-wrapped, still authorizes.
    """
    from aegis.capability import OwnerRoot
    from zeno.server import Playground

    root_path, public_path = owner
    monkeypatch.setenv("ZENO_OWNER_PUBLIC", str(public_path))
    monkeypatch.setenv("ZENO_PRODUCTION_PROFILE", "browser")
    monkeypatch.setenv("ZENO_SENTINEL_RATE_WEIGHT", "0")
    monkeypatch.setenv("ZENO_PROVIDERS_FILE", str(tmp_path / "providers.json"))
    monkeypatch.delenv("ZENO_MEMORY_KEY", raising=False)
    monkeypatch.delenv("ZENO_MEMORY_KEY_DATA", raising=False)
    playground = Playground(mode="production")

    root = OwnerRoot.load(str(root_path))
    encoded = root.issue("owner", ["read:*", "settings:*"], ttl=300).encode()
    wrapped = "\n".join(encoded[i : i + 48] for i in range(0, len(encoded), 48))
    assert "\n" in wrapped, "the test needs a wrapped token"

    httpd, base = _serve(playground)
    try:
        # the grant travels in the aegis block, wrapped exactly as pasted
        status, saved = _call(
            base,
            "POST",
            "/api/settings/providers",
            body={
                "name": "wrapped-grant-check",
                "provider": "openai",
                "nonce": "w1",
                "aegis": {"token": wrapped, "nonce": "w1"},
            },
        )
        assert status == 200, saved
        assert saved["profile"]["name"] == "wrapped-grant-check"
        assert "wrapped-grant-check" in playground.provider_store.profiles
    finally:
        httpd.shutdown()
        httpd.server_close()


@requires_pqc
def test_the_playground_runs_with_a_header_grant_and_names_a_scope_gap(owner, monkeypatch, tmp_path):
    """The playground page sends its grant as a header, not a body block.

    A production run must honour that header (the page could not run at all
    otherwise), and a grant without the execute scope must refuse with the
    scope code the page glossary explains — never as a silent no-token 0x9A01.
    """
    from aegis.capability import OwnerRoot
    from zeno.server import Playground

    root_path, public_path = owner
    monkeypatch.setenv("ZENO_OWNER_PUBLIC", str(public_path))
    monkeypatch.setenv("ZENO_PRODUCTION_PROFILE", "browser")
    monkeypatch.setenv("ZENO_SENTINEL_RATE_WEIGHT", "0")
    monkeypatch.setenv("ZENO_PROVIDERS_FILE", str(tmp_path / "providers.json"))
    monkeypatch.delenv("ZENO_MEMORY_KEY", raising=False)
    monkeypatch.delenv("ZENO_MEMORY_KEY_DATA", raising=False)
    playground = Playground(mode="production")

    root = OwnerRoot.load(str(root_path))
    runner = root.issue("owner", ["execute:*"], ttl=300).encode()
    reader = root.issue("owner", ["read:*"], ttl=300).encode()

    httpd, base = _serve(playground)
    try:
        status, ran = _call(
            base, "POST", "/api/run", body={"payload": "@LOC[TYO] -> ?WX"}, token=runner
        )
        assert status == 200, ran
        assert ran.get("decoy") is not True, "a permitted request is never a decoy"
        assert "frame" in ran

        status, refused = _call(
            base, "POST", "/api/run", body={"payload": "@LOC[TYO] -> ?WX"}, token=reader
        )
        assert status == 403, refused
        assert refused["error"]["code"] == "ZN-SEC-0x9A09", refused
    finally:
        httpd.shutdown()
        httpd.server_close()
