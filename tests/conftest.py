"""Shared fixtures for the Zeno test-suite."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from zeno import Kernel  # noqa: E402
from zeno.providers import MockProvider  # noqa: E402

#: The canonical example from the project brief §1.
CANONICAL = (
    "@LOC[TYO] -> ?WX : { $WX.state == RAIN => !GEN[INDOOR, 3] | !GEN[OUTDOOR, 3] }"
)


@pytest.fixture
def canonical_payload() -> str:
    return CANONICAL


@pytest.fixture
def weather_kernel() -> Kernel:
    """A kernel whose ``?WX`` returns rainy Tokyo."""
    kernel = Kernel(generator=lambda topic, count, kwargs, env: [f"{topic}-{i}" for i in range(count)])
    kernel.register_query("WX", lambda args, kwargs, env, call: {"state": "RAIN", "temp": 18})
    return kernel


@pytest.fixture
def mock_provider() -> MockProvider:
    return MockProvider(CANONICAL)
