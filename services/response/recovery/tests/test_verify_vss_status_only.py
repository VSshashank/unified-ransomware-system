"""Defect 6 of the Windows integration test: `--status-only` created a snapshot when elevated.

The help text says the mode "creates nothing". Unelevated that held, because
the create attempt was refused - and the refusal is what the mode records.
Run elevated on the VM, the attempt succeeded and left a shadow copy behind.

scripts/verify_vss.py is loaded by file: it is a script, not a module, and it
puts services/response on the path itself, as it does when run.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[4] / "scripts" / "verify_vss.py"


@pytest.fixture(scope="module")
def verify_vss():
    spec = importlib.util.spec_from_file_location("urds_verify_vss", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeManager:
    def __init__(self, elevated: bool) -> None:
        self.elevated = elevated
        self.created: list[str] = []

    def platform_status(self) -> dict:
        return {"supported": True, "elevated": self.elevated, "reason": None}

    def list_snapshots(self) -> list:
        return []

    def create_snapshot(self, volume: str) -> str:
        self.created.append(volume)
        if not self.elevated:
            raise PermissionError("VSS needs an elevated process")
        return "{shadow-copy-that-should-not-exist}"


@pytest.fixture
def run(verify_vss, monkeypatch, capsys):
    monkeypatch.delenv("URDS_WRITE_REPORTS", raising=False)
    monkeypatch.setattr(verify_vss, "git", lambda *args: "test")

    def go(manager):
        code = verify_vss.status_only(manager, "C:\\")
        return code, capsys.readouterr().out

    return go


def test_elevated_status_only_never_calls_create_snapshot(run):
    manager = FakeManager(elevated=True)

    code, out = run(manager)

    assert code == 0
    assert manager.created == []
    assert "not attempted: --status-only creates nothing" in out


def test_elevated_status_only_records_why_it_did_not_attempt(verify_vss, monkeypatch, tmp_path):
    """The report written with URDS_WRITE_REPORTS carries the reason, not a refusal."""
    import json

    monkeypatch.setenv("URDS_WRITE_REPORTS", "1")
    monkeypatch.setattr(verify_vss, "REPORTS", tmp_path)
    monkeypatch.setattr(verify_vss, "git", lambda *args: "test")
    manager = FakeManager(elevated=True)

    assert verify_vss.status_only(manager, "C:\\") == 0

    report = json.loads((tmp_path / "vss_status.json").read_text(encoding="utf-8"))
    (create,) = [a for a in report["attempts"] if a["operation"] == "create_snapshot"]
    assert create == {
        "operation": "create_snapshot",
        "succeeded": False,
        "attempted": False,
        "reason": "not attempted: --status-only creates nothing",
    }
    assert manager.created == []


def test_unelevated_status_only_still_records_the_refusal(run):
    manager = FakeManager(elevated=False)

    code, out = run(manager)

    assert code == 0
    assert manager.created == ["C:\\"]  # attempted, and refused
    assert "PermissionError: VSS needs an elevated process" in out
