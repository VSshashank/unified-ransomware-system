"""The Exhibition Story page draws the demo from gateway data and the state file.

Same approach as test_render.py: the real page under Streamlit's AppTest, the
gateway stubbed at `requests.get`.
"""

import json
from pathlib import Path

import pytest
import requests
from streamlit.testing.v1 import AppTest

PAGE = Path(__file__).resolve().parents[1] / "pages" / "1_Exhibition_Story.py"

FORGED = {
    "event_id": "evt_2", "timestamp": "2026-11-06T10:00:02Z", "event_type": "created",
    "file_path": r"C:\urds\watched_files\exhibition\invoice_march.zip", "file_size": 200004,
    "entropy": 8.0, "suspicious": True, "verdict": "suspected_encryption", "container_valid": False,
    "prediction": "ransomware", "threat_level": "critical", "block_id": 7,
    "pipeline": {"stages": ["ml_predicted", "ledger_logged", "response_triggered"]},
    "attribution_confidence": "certain", "process_id": 4242, "process_image": r"C:\Python313\python.exe",
    "attribution_escalation": {"result": "terminated"},
}
BENIGN = {
    "event_id": "evt_1", "timestamp": "2026-11-06T10:00:01Z", "event_type": "created",
    "file_path": r"C:\urds\watched_files\exhibition\quarterly_report.zip", "file_size": 200061,
    "entropy": 8.0, "suspicious": False, "verdict": "benign_compressed", "container_valid": True,
}
MANIFEST = dict(BENIGN, event_id="evt_3", file_path=r"C:\urds\watched_files\exhibition\office_documents\.simulator_manifest.json",
                verdict="benign", entropy=4.7)
BLOCKS = [{"block_id": i, "event_type": "file_event", "previous_hash": f"{i - 1:064d}", "current_hash": f"{i:064d}"}
          for i in range(7, 1, -1)]


class FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


def stub(monkeypatch, events, verify):
    answers = {
        "/monitor/events": {"events": events},
        "/monitor/status": {"status": "active", "files_monitored": 12, "attribution_available": True},
        "/ledger/verify": verify,
        "/ledger/blocks": {"blocks": BLOCKS},
    }

    def answer(url, **_):
        return FakeResponse(answers["/" + url.split("://", 1)[-1].split("/", 1)[-1]])

    monkeypatch.setattr(requests, "get", answer)


@pytest.fixture
def state_file(tmp_path, monkeypatch):
    path = tmp_path / "exhibition_state.json"
    monkeypatch.setenv("URDS_EXHIBITION_STATE", str(path))
    return path


def render() -> str:
    app = AppTest.from_file(str(PAGE), default_timeout=60)
    app.run()
    assert not app.exception, [e.value for e in app.exception]
    return "\n".join(block.value for block in app.markdown)


def test_a_caught_attack_lights_every_stage(monkeypatch, state_file):
    state_file.write_text(json.dumps({
        "current": 2, "title": "A disguised encrypted file is caught", "story": "s", "watch": "w",
        "focus_file": FORGED["file_path"], "steps": [{"n": 1, "status": "done"}, {"n": 2, "status": "running"}],
    }))
    stub(monkeypatch, [BENIGN, FORGED], {"valid": True, "blocks_checked": 7})
    page = render()
    assert "THREAT DETECTED" in page
    assert "Step 2 of 8" in page
    assert "Looks encrypted" in page and "structure FORGED" in page
    assert "Sealed in block #7" in page
    assert "Attacker STOPPED" in page and "PID 4242" in page


def test_a_real_archive_stops_at_the_monitor(monkeypatch, state_file):
    stub(monkeypatch, [BENIGN], {"valid": True, "blocks_checked": 3})
    page = render()
    assert "SYSTEM SECURE" in page
    assert "Real compressed file - safe" in page
    assert "Not needed" in page and "Nothing to record" in page


def test_bookkeeping_files_never_take_the_spotlight(monkeypatch, state_file):
    stub(monkeypatch, [MANIFEST, BENIGN], {"valid": True, "blocks_checked": 3})
    page = render()
    assert "quarterly_report.zip" in page
    assert ".simulator_manifest.json" not in page


def test_a_tampered_ledger_is_named(monkeypatch, state_file):
    state_file.write_text(json.dumps({"current": 6, "tamper": {"state": "tampered", "block": 5}}))
    stub(monkeypatch, [BENIGN], {"valid": False, "invalid_block_id": 5, "blocks_checked": 7})
    page = render()
    assert "LEDGER TAMPERED" in page
    assert "Tampering detected at block #5" in page
    assert "TAMPERED" in page and "link broken" in page


def test_no_state_file_and_no_gateway_says_so(monkeypatch, state_file):
    def refuse(url, **_):
        raise requests.ConnectionError("refused")

    monkeypatch.setattr(requests, "get", refuse)
    app = AppTest.from_file(str(PAGE), default_timeout=60)
    app.run()
    assert not app.exception
    assert "not reachable" in app.error[0].value
