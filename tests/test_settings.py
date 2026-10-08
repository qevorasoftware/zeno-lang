"""The settings page: several AI providers, their keys, one active.

What is under test, in order of how much it matters:

* **A key, once saved, never comes back.** No endpoint, no page and no error
  path in this repository echoes stored key material; the only things anyone
  may see are ``has_key`` and the last four characters. The tests assert this
  against the raw HTTP body, not the parsed view.
* **Keys are sealed at rest when an owner key is configured** — ciphertext on
  disk, the same sealer and the same key file as conversation memory. Without
  one the file is plaintext mode 0600 and every view says so.
* **The active provider actually switches** — the server rebuilds its provider
  from the stored profile, and ``/api/health`` reports the new one.
* **Production gates every part of it**: reads need ``read:settings``, writes
  need ``settings:write``, and the test button's outbound call needs
  ``settings:test``.
"""

from __future__ import annotations

import json
import stat
import urllib.error
import urllib.request

import pytest

from aegis.capabilities import capabilities

HAVE_CRYPTO = capabilities().classical
requires_crypto = pytest.mark.skipif(not HAVE_CRYPTO, reason="cryptography wheel not installed")


def _serve(playground):
    from zeno.server import _Handler
    from http.server import ThreadingHTTPServer
    import threading

    handler = type("SettingsHandler", (_Handler,), {"playground": playground})
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"http://{httpd.server_address[0]}:{httpd.server_address[1]}"


def _post(base: str, path: str, body: dict) -> tuple[int, dict]:
    request = urllib.request.Request(
        base + path,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


def _calm(playground) -> None:
    """Switch off the guardian's rate feature for this test only.

    The EWMA profile starts with a low baseline, so a test's three quick
    requests read as a burst and the guardian freezes the actor -- the layer
    working as designed, with its own tests elsewhere. Settings tests are not
    about the rate feature, so it is turned off here; every other weight,
    including the freeze on genuine anomalies, stays on.
    """
    if playground.boundary is not None:
        playground.boundary.gateway.sentinel.weights["rate"] = 0.0


def _get(base: str, path: str) -> tuple[int, dict]:
    try:
        with urllib.request.urlopen(base + path, timeout=30) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


# ---------------------------------------------------------------------------
# The store
# ---------------------------------------------------------------------------
def test_the_store_round_trips_and_never_shows_the_key(tmp_path):
    from zeno.settings import ProviderStore

    store = ProviderStore(str(tmp_path / "providers.json"))
    store.add("groq-fast", "groq", api_key="gsk-DO-NOT-ECHO-987654")
    stored = json.loads((tmp_path / "providers.json").read_text(encoding="utf-8"))

    # plaintext mode (no owner key): the key IS in the file, the file is 0600,
    # and the view still never says it
    assert stat.S_IMODE((tmp_path / "providers.json").stat().st_mode) == 0o600
    view = store.view("groq-fast")
    assert view["has_key"] is True
    assert view["key_hint"] == "…7654"
    assert "gsk-DO-NOT-ECHO" not in json.dumps(store.describe())


def test_the_store_validates_what_it_is_asked_to_keep(tmp_path):
    from zeno.settings import ProviderStore

    store = ProviderStore(str(tmp_path / "providers.json"))
    with pytest.raises(Exception, match="unknown provider"):
        store.add("bad", "not-a-provider")
    with pytest.raises(Exception, match="testing backend"):
        store.add("sneaky", "mock")


def test_updating_keeps_the_key_and_empty_clears_it(tmp_path):
    from zeno.settings import ProviderStore

    store = ProviderStore(str(tmp_path / "providers.json"))
    store.add("one", "openai", api_key="sk-keep-me-1234")
    # no api_key argument: the stored key survives a model edit
    store.add("one", "openai", model="gpt-4o")
    assert store.view("one")["has_key"] is True
    assert store.view("one")["model"] == "gpt-4o"
    # an explicit empty string clears it on purpose
    store.add("one", "openai", api_key="")
    assert store.view("one")["has_key"] is False


@requires_crypto
def test_keys_are_sealed_at_rest_and_locked_without_the_key(tmp_path):
    from zeno.memory import MemoryStore
    from zeno.settings import ProviderStore, SettingsError

    key = MemoryStore.create_owner(str(tmp_path / "owner.key"))
    owner = MemoryStore.load_owner(str(key))
    store = ProviderStore(str(tmp_path / "providers.json"), owner=owner)
    store.add("groq-fast", "groq", api_key="gsk-SECRET-987654")

    raw = (tmp_path / "providers.json").read_text(encoding="utf-8")
    assert "gsk-SECRET" not in raw, "the key must be ciphertext on disk"
    assert "sealed" in json.loads(raw)

    # the owner can open it again
    reopened = ProviderStore(str(tmp_path / "providers.json"), owner=owner)
    assert reopened.view("groq-fast")["has_key"] is True

    # nobody else can, and the store refuses to clobber what it cannot read
    with pytest.raises(SettingsError, match="sealed"):
        ProviderStore(str(tmp_path / "providers.json"))
    locked = ProviderStore.locked_store("sealed")
    with pytest.raises(SettingsError, match="sealed"):
        locked.add("x", "openai", api_key="sk-anything")


# ---------------------------------------------------------------------------
# The routes (development)
# ---------------------------------------------------------------------------
def test_add_activate_and_the_health_endpoint_agrees(tmp_path, monkeypatch):
    from zeno.server import Playground

    monkeypatch.setenv("ZENO_PROVIDERS_FILE", str(tmp_path / "providers.json"))
    playground = Playground()
    httpd, base = _serve(playground)
    try:
        status, body = _post(
            base,
            "/api/settings/providers",
            {"name": "local-llama", "provider": "ollama", "model": "llama3.1"},
        )
        assert status == 200, body
        assert body["profile"]["provider"] == "ollama"
        assert body["profile"]["ready"] is True  # local endpoints need no key

        status, health = _get(base, "/api/health")
        assert status == 200
        assert health["provider"] == "ollama"
        assert health["model"] == "llama3.1"
        # availability for local endpoints is key-based (no key needed), not a
        # connection probe — the honest test button is the one that really calls
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_a_saved_key_never_crosses_the_wire(tmp_path, monkeypatch):
    from zeno.server import Playground

    monkeypatch.setenv("ZENO_PROVIDERS_FILE", str(tmp_path / "providers.json"))
    playground = Playground()
    httpd, base = _serve(playground)
    try:
        status, _ = _post(
            base,
            "/api/settings/providers",
            {"name": "cloud", "provider": "openai", "api_key": "sk-WIRE-SECRET-4242"},
        )
        assert status == 200

        request = urllib.request.Request(base + "/api/settings")
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read().decode("utf-8")
        assert "sk-WIRE-SECRET" not in raw, "the key must not appear in any response"
        _, view = _get(base, "/api/settings")
        profile = next(item for item in view["profiles"] if item["name"] == "cloud")
        assert profile["key_hint"].endswith("4242")  # the hint, and only the hint
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_remove_and_switch(tmp_path, monkeypatch):
    from zeno.server import Playground

    monkeypatch.setenv("ZENO_PROVIDERS_FILE", str(tmp_path / "providers.json"))
    playground = Playground()
    _calm(playground)
    httpd, base = _serve(playground)
    try:
        _post(base, "/api/settings/providers", {"name": "a", "provider": "ollama"})
        _post(base, "/api/settings/providers", {"name": "b", "provider": "vllm"})
        status, body = _post(base, "/api/settings/activate", {"name": "a"})
        assert status == 200 and body["provider"]["provider"] == "ollama"
        status, body = _post(base, "/api/settings/remove", {"name": "b"})
        assert status == 200 and body["removed"] is True
        with pytest.raises(Exception):
            playground.provider_store.provider_for("b")
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_the_test_endpoint_reports_failure_gracefully(tmp_path, monkeypatch):
    from zeno.server import Playground

    monkeypatch.setenv("ZENO_PROVIDERS_FILE", str(tmp_path / "providers.json"))
    playground = Playground()
    httpd, base = _serve(playground)
    try:
        _post(base, "/api/settings/providers", {"name": "local", "provider": "ollama"})
        status, body = _post(base, "/api/settings/test", {"name": "local"})
        # nothing listens on localhost:11434 in the test environment: the honest
        # answer is ok:false with the reason, never a 500
        assert status == 200
        assert body["ok"] is False
        assert body.get("error")
    finally:
        httpd.shutdown()
        httpd.server_close()


# ---------------------------------------------------------------------------
# Production: settings are the owner's
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def settings_world(tmp_path_factory):
    from aegis.boundary import AuthorizationBoundary
    from aegis.capability import CapabilityVerifier, OwnerRoot
    from aegis.gate import Gateway, Policy
    from aegis.guardian_ai import Sentinel

    root = tmp_path_factory.mktemp("settings")
    owner = OwnerRoot.create(name="owner_root", audience="zeno-local", epoch=1)
    grant = owner.issue("owner", ["read:*", "settings:*", "execute:*"], ttl=600)
    gateway = Gateway(
        Policy.strict_policy(),
        sentinel=Sentinel(max_events_per_minute=6000.0),
    )
    return {
        "grant": grant,
        "boundary": AuthorizationBoundary(
            gateway=gateway,
            capability_verifier=CapabilityVerifier(owner.public, audience="zeno-local", epoch=1),
        ),
    }


@requires_crypto
def test_production_refuses_settings_without_a_grant(settings_world, tmp_path, monkeypatch):
    from zeno.server import Playground

    monkeypatch.setenv("ZENO_PROVIDERS_FILE", str(tmp_path / "providers.json"))
    playground = Playground(boundary=settings_world["boundary"])
    if playground.watchtower is not None:
        playground.watchtower.tarpit_base_ms = 1
        playground.watchtower.tarpit_max_ms = 2
    httpd, base = _serve(playground)
    try:
        status, body = _get(base, "/api/settings")
        assert status == 403
        assert body["error"]["code"].startswith("ZN-SEC-")

        status, body = _post(
            base, "/api/settings/providers", {"name": "x", "provider": "openai", "api_key": "sk-nope"}
        )
        assert status == 403
        assert body["error"]["code"].startswith("ZN-SEC-")
        # and the refusal meant it: nothing was stored
        assert playground.provider_store.profiles == {}
    finally:
        httpd.shutdown()
        httpd.server_close()
