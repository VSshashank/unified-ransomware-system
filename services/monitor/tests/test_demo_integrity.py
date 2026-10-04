"""The demonstrations report what the system did, and nothing they made up.

Ported from fix/evidence-integrity's 58ce021 (docs/CORRECTIONS.md): until the
port, `scripts/attack_chain_demo.py` spawned `time.sleep(60)` and asked the
Response service to kill it, recording a TC-07 kill time from a process that
never wrote, was never detected and was never attributed; its exit code counted
a skipped check as a pass; and `scripts/si_demo.py` and a recovery test the
claim matrix cites wrote an invented PID into the ledger. Each test here fails
on the code before the port.
"""

from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / "scripts"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(f"urds_{name}", SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


demo = _load("attack_chain_demo")
si_demo = _load("si_demo")


# ---------------------------------------------------------------- the PID literal


def test_the_invented_pid_appears_nowhere_in_scripts_or_services():
    """The acceptance grep, as a test: no exception list to remember.

    The one occurrence that was not a PID - a synthetic shadow-copy GUID in
    test_vss_manager.py - is re-lettered so the gate stays literal.
    """
    needle = "66" * 2  # not written out, or this file would match itself
    hits = []
    for top in ("scripts", "services"):
        for path in (ROOT / top).rglob("*"):
            if not path.is_file() or "__pycache__" in path.parts or ".pytest_cache" in path.parts:
                continue
            if path.suffix not in {".py", ".ps1", ".md", ".json", ".txt", ".yml", ".yaml", ".ini"}:
                continue
            for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                if needle in line:
                    hits.append(f"{path.relative_to(ROOT)}:{number}")
    assert hits == []


@pytest.mark.parametrize("script", ["attack_chain_demo.py", "si_demo.py"])
def test_no_demo_writes_a_literal_pid_into_an_event(script):
    """A `"process_id": <int literal>` in a demo is a PID nobody attributed."""
    tree = ast.parse((SCRIPTS / script).read_text(encoding="utf-8"))
    literal = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if (
                    isinstance(key, ast.Constant) and key.value == "process_id"
                    and isinstance(value, ast.Constant) and isinstance(value.value, int)
                    and not isinstance(value.value, bool)
                ):
                    literal.append(f"line {node.lineno}: process_id {value.value}")
    assert literal == []


# ------------------------------------------------------------------- TC-07


def test_the_attack_demo_never_asks_for_a_termination_or_kills_anything():
    """TC-07 is read off the system; the demo itself terminates nothing."""
    tree = ast.parse((SCRIPTS / "attack_chain_demo.py").read_text(encoding="utf-8"))
    offences = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and "/response/terminate" in node.value:
            offences.append(f"line {node.lineno}: asks /response/terminate")
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in {"kill", "terminate"}:
            offences.append(f"line {node.lineno}: .{node.func.attr}()")
    assert offences == []


WRITER = 4242
OTHER = 1717


def _event(confidence, pid, result=None, **extra):
    event = {"attribution_confidence": confidence, "process_id": pid,
             "attribution_reason": "test", "attribution_source": "test"}
    if result is not None:
        event["attribution_escalation"] = {"result": result}
    event.update(extra)
    return event


def test_tc07_with_nothing_certain_is_a_skip_and_says_why():
    verdicts, lines = demo.judge_tc07([_event("unknown", None)], WRITER, writer_ended_early=False)
    assert verdicts == {"tc07_attributed_pid_is_the_writer": None, "tc07_process_terminated": None}
    assert any("only a CERTAIN attribution" in line for line in lines)


def test_tc07_a_probable_pid_is_not_enough():
    verdicts, _ = demo.judge_tc07([_event("probable", WRITER, "not_escalated")], WRITER, writer_ended_early=False)
    assert verdicts["tc07_process_terminated"] is None


def test_tc07_passes_only_when_the_system_killed_the_writer_it_named():
    events = [_event("certain", WRITER, "terminated"), _event("probable", WRITER, "not_escalated")]
    verdicts, _ = demo.judge_tc07(events, WRITER, writer_ended_early=True)
    assert verdicts == {"tc07_attributed_pid_is_the_writer": True, "tc07_process_terminated": True}


def test_tc07_a_certain_answer_naming_another_process_fails():
    verdicts, lines = demo.judge_tc07([_event("certain", OTHER, "terminated")], WRITER, writer_ended_early=True)
    assert verdicts == {"tc07_attributed_pid_is_the_writer": False, "tc07_process_terminated": False}
    assert any("WRONG PROCESS" in line for line in lines)


def test_tc07_a_refused_termination_is_a_failure_not_a_pass():
    verdicts, _ = demo.judge_tc07(
        [_event("certain", WRITER, "termination_refused_or_unreachable")], WRITER, writer_ended_early=False
    )
    assert verdicts["tc07_attributed_pid_is_the_writer"] is True
    assert verdicts["tc07_process_terminated"] is False


# --------------------------------------------------------------- exit codes


@pytest.mark.parametrize(
    "outcomes, expected",
    [
        ({"a": True, "b": True}, 0),
        ({"a": True, "b": None}, 1),
        ({"a": True, "b": False}, 1),
        ({"a": None, "b": False}, 1),
        ({}, 1),
    ],
    ids=["all-pass", "one-skip", "one-fail", "skip-and-fail", "nothing-ran"],
)
def test_the_attack_demo_exits_0_only_when_every_check_passed(monkeypatch, tmp_path, outcomes, expected):
    """Through `finish`, the function that produces the exit status."""
    monkeypatch.setattr(demo, "EVIDENCE_PATH", tmp_path / "attack_chain_evidence.txt")
    monkeypatch.setattr(demo, "results", dict(outcomes))
    monkeypatch.setattr(demo, "transcript", [])
    assert demo.finish(None, None, None) == expected


@pytest.mark.parametrize(
    "tc04, chain_ok, tc05, expected",
    [(True, True, True, 0), (True, True, None, 1), (True, True, False, 1), (False, True, True, 1)],
    ids=["all-pass", "tc05-skipped", "tc05-failed", "tc04-failed"],
)
def test_the_si_demo_exits_0_only_when_every_check_passed(tc04, chain_ok, tc05, expected):
    assert si_demo.exit_code(tc04, chain_ok, tc05) == expected
