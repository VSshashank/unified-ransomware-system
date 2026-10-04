"""The demos leave reports/ alone unless URDS_WRITE_REPORTS=1 (F7).

reports/VM_TEST_REPORT_2026-10-04.md, F7: `scripts/attack_chain_demo.py`
(reports/attack_chain_evidence.txt and attack_chain_results.json) and
`scripts/si_demo.py` (reports/si_demo_evidence.txt) wrote tracked evidence on
every run, while every other measurement script writes reports/ only under
URDS_WRITE_REPORTS=1. Running either to check something changed the evidence.

The evidence paths are pointed at a temporary directory here, so a regression
would not touch the real reports/ either.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
SCRIPTS = ROOT / "scripts"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(f"urds_gate_{name}", SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


demo = _load("attack_chain_demo")
si_demo = _load("si_demo")


# --------------------------------------------------------------- attack chain


@pytest.fixture
def attack(monkeypatch, tmp_path):
    reports = tmp_path / "reports"
    monkeypatch.setattr(demo, "EVIDENCE_PATH", reports / "attack_chain_evidence.txt")
    monkeypatch.setattr(demo, "results", {"tc01_detected": True})
    monkeypatch.setattr(demo, "transcript", ["a transcript line"])
    return reports


def test_the_attack_demo_writes_nothing_to_reports_by_default(monkeypatch, attack):
    monkeypatch.delenv("URDS_WRITE_REPORTS", raising=False)
    demo.finish(None, None, None)
    assert not attack.exists() or list(attack.iterdir()) == []


def test_the_attack_demo_writes_reports_when_asked(monkeypatch, attack):
    monkeypatch.setenv("URDS_WRITE_REPORTS", "1")
    demo.finish(None, None, None)
    assert (attack / "attack_chain_evidence.txt").read_text().startswith("a transcript line")
    assert (attack / "attack_chain_results.json").is_file()


def test_the_attack_demo_writes_to_out_and_not_to_reports(monkeypatch, attack, tmp_path):
    monkeypatch.delenv("URDS_WRITE_REPORTS", raising=False)
    out = tmp_path / "run" / "chain.txt"
    demo.finish(None, type("Args", (), {"out": str(out)})(), None)
    assert out.is_file() and (out.parent / "chain_results.json").is_file()
    assert not attack.exists() or list(attack.iterdir()) == []


# -------------------------------------------------------------------- si demo


class _Response:
    def __init__(self, body: dict, status_code: int = 200) -> None:
        self._body = body
        self.status_code = status_code

    def json(self) -> dict:
        return self._body


class _FakeClient:
    """Answers si_demo's calls well enough for it to reach the end."""

    def __init__(self, *args, **kwargs) -> None:
        self.blocks = 0

    def get(self, url, **kwargs):
        if url.endswith("/ledger/verify"):
            return _Response({"valid": True, "verification_time_ms": 1.0, "blocks_checked": self.blocks})
        return _Response({"status": "healthy"})

    def post(self, url, json=None, **kwargs):
        if url.endswith("/ledger/log"):
            self.blocks += 1
            return _Response({"block_id": self.blocks, "current_hash": "ab" * 32})
        return _Response({"status": "failed", "integrity_verified": False})


@pytest.fixture
def si(monkeypatch, tmp_path):
    reports = tmp_path / "reports"
    monkeypatch.setattr(si_demo, "EVIDENCE_PATH", reports / "si_demo_evidence.txt")
    monkeypatch.setattr(si_demo, "transcript", [])
    monkeypatch.setattr(si_demo.httpx, "Client", _FakeClient)
    argv = ["si_demo.py", "--db", str(tmp_path / "no-such.db"),
            "--snapshot-root", str(tmp_path / "snapshots"), "--workspace", str(tmp_path / "workspace")]
    monkeypatch.setattr(sys, "argv", argv)
    return reports, argv


def test_the_si_demo_writes_nothing_to_reports_by_default(monkeypatch, si):
    reports, _ = si
    monkeypatch.delenv("URDS_WRITE_REPORTS", raising=False)
    si_demo.main()
    assert not reports.exists() or list(reports.iterdir()) == []


def test_the_si_demo_writes_reports_when_asked(monkeypatch, si):
    reports, _ = si
    monkeypatch.setenv("URDS_WRITE_REPORTS", "1")
    si_demo.main()
    assert (reports / "si_demo_evidence.txt").is_file()


def test_the_si_demo_writes_to_out_and_not_to_reports(monkeypatch, si, tmp_path):
    reports, argv = si
    monkeypatch.delenv("URDS_WRITE_REPORTS", raising=False)
    out = tmp_path / "run" / "si.txt"
    monkeypatch.setattr(sys, "argv", argv + ["--out", str(out)])
    si_demo.main()
    assert out.is_file()
    assert not reports.exists() or list(reports.iterdir()) == []
