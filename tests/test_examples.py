"""The examples and the agents are part of the product: keep them running.

These tests execute the shipped example scripts as subprocesses, which catches
the failure mode unit tests miss — code that works when imported but not when
run from a clean interpreter.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def run_script(relative: str, *arguments: str, timeout: int = 120):
    return subprocess.run(
        [sys.executable, relative, *arguments],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


@pytest.mark.parametrize(
    "script",
    ["examples/01_basic_math.py", "examples/02_agent_chat.py", "examples/tools.py"],
)
def test_example_runs_clean(script):
    completed = run_script(script)
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip()


def test_basic_math_example_reports_the_answer():
    completed = run_script("examples/01_basic_math.py")
    assert "answer: 480.97" in completed.stdout
    assert "!RET[" in completed.stdout


def test_agent_chat_example_reports_a_comparison():
    completed = run_script("examples/02_agent_chat.py")
    assert "NL tokens →" in completed.stdout
    assert "Zeno tokens" in completed.stdout


def test_agent_chat_example_is_honest_about_its_limits():
    """If the payloads are not smaller, the example must say so."""
    completed = run_script("examples/02_agent_chat.py")
    if "saved" not in completed.stdout:
        assert "not smaller here" in completed.stdout


def test_tools_example_exposes_its_registry():
    completed = subprocess.run(
        [sys.executable, "-c", "from examples.tools import tools; print(sorted(tools()))"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert completed.returncode == 0, completed.stderr
    assert "?WX" in completed.stdout
    assert "?REPO" in completed.stdout


# ---------------------------------------------------------------------------
# Agents as programs
# ---------------------------------------------------------------------------
def test_tester_agent_passes():
    completed = run_script("agents/tester.py")
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "0 failed" in completed.stdout


def test_tester_agent_json():
    import json

    completed = run_script("agents/tester.py", "--json")
    payload = json.loads(completed.stdout)
    assert payload["ok"] is True
    assert payload["failed"] == 0
    assert payload["total"] >= 100


def test_tester_agent_can_include_the_intent_check():
    completed = run_script("agents/tester.py", "--intent-check")
    assert completed.returncode == 0, completed.stdout
    assert "intent" in completed.stdout


def test_linguist_agent_explains_a_payload():
    completed = run_script(
        "agents/linguist.py",
        "explain",
        "@LOC[TYO] -> ?WX : { $WX.state == RAIN => !GEN[INDOOR, 3] | !GEN[OUTDOOR, 3] }",
    )
    assert completed.returncode == 0, completed.stderr
    assert "scope LOC of TYO" in completed.stdout
    assert "otherwise generate OUTDOOR, 3" in completed.stdout


def test_linguist_agent_normalises_a_payload():
    completed = run_script("agents/linguist.py", "normalise", "@SYS[x]  ->   ?A:{$A==1=>!B|!C}")
    assert completed.stdout.strip() == "@SYS[x] -> ?A : { $A == 1 => !B | !C }"


def test_linguist_agent_check_exits_nonzero_for_bad_input():
    completed = run_script("agents/linguist.py", "check", "@LOC[TYO] -> ?WX : { $X = 1 }")
    assert completed.returncode == 1


def test_linguist_agent_encodes_offline():
    completed = run_script("agents/linguist.py", "encode", "check the weather in Tokyo")
    assert completed.returncode == 0
    assert completed.stdout.strip().startswith("@LOC[TYO]")
