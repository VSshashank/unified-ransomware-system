"""No ledger event names a process the evidence does not support (claim C-16).

Ported from fix/evidence-integrity's 58ce021. `scripts/ledger_coverage.py`
already measured whether every mitigation decision reaches the chain, and
whether the blocks that arrive carry all five required fields. Both count
*presence*, and neither can tell an attributed PID from an invented one: an
invented `process_id` sat in the tamper-evident chain while the row meant to
police it stayed green (docs/CORRECTIONS.md). So the scan asserts a *value*: a
ledger event may name a process only when attribution resolved to CERTAIN.
`None` is not an offence - "no process was identified" has to stay expressible.

On this branch the rule met a chain that broke it by design: a PROBABLE answer
put its PID in `process_id` on the `file_event`, the Response service's trigger
block and the escalation block, and an unattributed trigger recorded the number
0. The 2026-10-04 elevated run's chain named a process in 703 blocks, 649 of
them unsupported (`ledger_coverage.py --ledger-db`). The chain was changed to
fit the rule (`pipeline.chained_pid`), not the rule to fit the chain, and the
second half of this file drives the real pipeline, with a lagging kernel-grade
source, through the cases that used to break it.

The scan's own report is vacuous where no audit source runs - every answer is
UNKNOWN, so nothing names a process - which is why the first half feeds it
PIDs that must be flagged.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sqlite3
import sys
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
MONITOR_DIR = ROOT / "services" / "monitor"
sys.path.insert(0, str(MONITOR_DIR))

import app as monitor_app  # noqa: E402
import attribution  # noqa: E402
import pipeline  # noqa: E402
from attribution import CERTAIN, PROBABLE, UNKNOWN, AttributionSource, Attributor, ProcessFacts, WriteLog  # noqa: E402


def _load():
    spec = importlib.util.spec_from_file_location("urds_ledger_coverage", ROOT / "scripts" / "ledger_coverage.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["urds_ledger_coverage"] = module
    spec.loader.exec_module(module)
    return module


ledger_coverage = _load()


def scan(*event_data: dict) -> dict:
    """Run the scan over ledger writes carrying the given event_data."""
    stub = ledger_coverage.LedgerStub()
    stub.ledger_writes = [{"event_type": "file_encrypted", "event_data": data} for data in event_data]
    return stub.unsupported_pids()


# ------------------------------------------------------------- the rule itself


def test_a_pid_named_without_any_confidence_is_flagged():
    """The shape the invented PID had: a bare number, nothing behind it."""
    result = scan({"file_path": "/x", "process_id": 4242})
    assert result["unsupported"] == 1
    assert result["events_naming_a_process"] == 1
    assert "only 'certain'" in result["detail"][0]["why"]


def test_a_pid_named_with_unknown_attribution_is_flagged():
    result = scan({"file_path": "/x", "process_id": 4242, "attribution_confidence": "unknown"})
    assert result["unsupported"] == 1


def test_a_pid_named_with_probable_attribution_is_flagged():
    """PROBABLE is explicitly not kill-authorising, so it cannot name one either."""
    result = scan({"file_path": "/x", "process_id": 4242, "attribution_confidence": "probable"})
    assert result["unsupported"] == 1


def test_a_pid_named_with_certain_attribution_is_accepted():
    result = scan({"file_path": "/x", "process_id": 22716, "attribution_confidence": "certain"})
    assert result["unsupported"] == 0
    assert result["events_naming_a_process"] == 1


def test_a_null_pid_is_not_an_offence():
    """"No process was identified" must stay expressible and must stay free."""
    result = scan({"file_path": "/x", "process_id": None, "attribution_confidence": "unknown"})
    assert result["unsupported"] == 0
    assert result["events_naming_a_process"] == 0


def test_candidates_are_evidence_and_are_not_read():
    result = scan({"file_path": "/x", "process_id": None, "attribution_confidence": "probable",
                   "attribution_candidates": [1717, 4242]})
    assert result["unsupported"] == 0


def test_an_event_that_never_mentions_a_process_is_ignored():
    result = scan({"file_path": "/x", "file_hash": "ab" * 32})
    assert result["unsupported"] == 0
    assert result["events_examined"] == 1


@pytest.mark.parametrize("pid", ["4242", 0, -1, 3.5, True, [4242]])
def test_a_pid_that_is_not_a_positive_integer_is_flagged(pid):
    """Including True, which is an int in Python and would otherwise pass as 1,
    and 0, which an unattributed trigger block used to record."""
    result = scan({"file_path": "/x", "process_id": pid, "attribution_confidence": "certain"})
    assert result["unsupported"] == 1, f"{pid!r} should not be accepted as a PID"
    assert "positive integer" in result["detail"][0]["why"]


def test_offences_are_reported_individually_not_just_counted():
    """An auditor needs to know which block, not how many."""
    result = scan(
        {"file_path": "/clean", "process_id": None},
        {"file_path": "/bad", "process_id": 4242},
        {"file_path": "/good", "process_id": 22716, "attribution_confidence": "certain"},
    )
    assert result["events_examined"] == 3
    assert result["events_naming_a_process"] == 2
    assert result["unsupported"] == 1
    assert result["detail"][0]["file_path"] == "/bad"


def test_a_real_ledger_file_is_scanned_read_only(tmp_path):
    """`--ledger-db`: the same rule over a run's chain, without writing to it."""
    db = tmp_path / "ledger.db"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE blocks (id INTEGER PRIMARY KEY, timestamp TEXT, event_type TEXT, "
                 "event_data TEXT, previous_hash TEXT, current_hash TEXT)")
    rows = [
        ("response_action", {"action": "trigger", "process_id": 0, "attribution_confidence": "unknown"}),
        ("attribution_escalation", {"process_id": 4242, "attribution_confidence": "probable"}),
        ("attribution_escalation", {"process_id": 4242, "attribution_confidence": "certain"}),
        ("file_event", {"process_id": None, "attribution_candidates": [4242]}),
    ]
    for event_type, data in rows:
        conn.execute("INSERT INTO blocks (timestamp, event_type, event_data, previous_hash, current_hash) "
                     "VALUES ('t', ?, ?, 'p', 'c')", (event_type, json.dumps(data)))
    conn.commit()
    conn.close()
    before = db.read_bytes()

    result = ledger_coverage.scan_ledger_db(str(db))

    assert result["events_examined"] == 4
    assert result["events_naming_a_process"] == 3
    assert [d["block_id"] for d in result["detail"]] == [1, 2]
    assert db.read_bytes() == before


def test_the_committed_report_carries_the_scan_and_it_is_zero():
    """The figure claim C-16 quotes, in the artefact it quotes it from."""
    report = json.loads((ROOT / "reports" / "ledger_coverage.json").read_text(encoding="utf-8"))
    integrity = report["process_attribution_integrity"]
    assert integrity["unsupported"] == 0, integrity["detail"]
    assert integrity["meets_target"] is True
    assert integrity["events_examined"] > 0, "a scan over no events is not evidence of anything"


# ------------------------------------- this branch's chain, with a live source

HORIZON_MS = 1500.0
ATTACKER = 4242
BENIGN = 1717
LOCKER = r"C:\Temp\locker.exe"
NOTEPAD = r"C:\Windows\System32\notepad.exe"


class LaggingKernelSource(AttributionSource):
    """Kernel-grade and late, like the Security channel's 4663."""

    name = "fake-lagging-4663"
    kernel_grade = True
    delivery_horizon_ms = HORIZON_MS

    def __init__(self, log: WriteLog) -> None:
        super().__init__(log)
        self._timers: list[threading.Timer] = []

    def start(self) -> bool:
        self.available = True
        return True

    def deliver(self, path: str, pid: int, image: str, written_at: float, lag_ms: float) -> None:
        timer = threading.Timer(lag_ms / 1000.0, lambda: self.log.record(path, pid, image, written_at=written_at))
        timer.daemon = True
        timer.start()
        self._timers.append(timer)

    def cancel(self) -> None:
        for timer in self._timers:
            timer.cancel()


class Capture:
    """Stands in for the ML engine, the ledger and the Response service.

    Ledger writes are kept as the ledger would store them. The Response
    service's own blocks are rebuilt from the real Response code's rules
    elsewhere (services/response/tests/test_chain_pid_fields.py); here the
    Monitor's writes and the payloads it sends are what is checked.
    """

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []
        self.lock = threading.Lock()

    def __call__(self, client, base_url, path, payload, *args, **kwargs):
        with self.lock:
            self.calls.append((path, payload))
        if path == "/predict":
            return {"prediction": "ransomware", "confidence": 0.97, "threat_level": "critical"}
        if path == "/ledger/log":
            return {"block_id": len(self.calls)}
        if path == "/response/trigger":
            return {"status": "success", "actions_taken": ["network_isolation_planned", "admin_notified"]}
        if path == "/response/terminate":
            return {"status": "terminated", "process_id": payload["process_id"], "incident_id": payload["incident_id"]}
        return {}

    def posts(self, path: str) -> list[dict]:
        with self.lock:
            return [payload for p, payload in self.calls if p == path]


@pytest.fixture
def live(monkeypatch):
    log = WriteLog()
    source = LaggingKernelSource(log)
    source.start()
    at = Attributor(log=log, source=source,
                    probe=lambda pid: ProcessFacts(pid=pid, image=LOCKER if pid == ATTACKER else NOTEPAD,
                                                   created_at=time.time() - 60))
    capture = Capture()
    monkeypatch.setattr(pipeline, "_post", capture)
    monkeypatch.setattr(monitor_app, "attributor", at)
    monkeypatch.setattr(monitor_app, "PIPELINE_ENABLED", True)
    monkeypatch.setattr(monitor_app, "BASELINE_LOGGING_ENABLED", False)
    monitor_app.ENTROPY_HISTORY.clear()
    monitor_app._ensure_worker()
    yield source, capture
    source.cancel()
    if monitor_app._pending is not None:
        monitor_app._pending.stop(timeout=2.0)
        monitor_app._pending = None
    monitor_app._work.join()
    monitor_app._escalations.join()
    with monitor_app._ANCHORS_LOCK:
        monitor_app._ANCHORS.clear()
    monitor_app.EVENTS.clear()
    monitor_app._SEEN_FILES.clear()
    monitor_app.ENTROPY_HISTORY.clear()


def _wait_for(predicate, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return predicate()


def test_the_monitors_chain_names_a_process_only_on_certain(live, tmp_path):
    """One sole writer (escalates to CERTAIN) and one shared file (PROBABLE).

    Before the change, the PROBABLE answer's PID went into `process_id` on the
    file_event and the escalation block, and the trigger asked the Response
    service to record it there too.
    """
    source, capture = live
    sole = tmp_path / "board_minutes.docx"
    shared = tmp_path / "payroll.xlsx"

    for target, writers in ((sole, [ATTACKER]), (shared, [BENIGN, ATTACKER])):
        written_at = time.time()
        target.write_bytes(os.urandom(64 * 1024))
        for offset, pid in enumerate(writers):
            source.deliver(str(target), pid, LOCKER if pid == ATTACKER else NOTEPAD,
                           written_at=written_at - 0.01 * (len(writers) - offset), lag_ms=300)
        event = monitor_app.handle_event(str(target), "modified")
        assert event["suspicious"] is True

    assert _wait_for(lambda: len([w for w in capture.posts("/ledger/log")
                                  if w["event_type"] == "attribution_escalation"]) == 2, timeout=5.0)
    monitor_app._work.join()

    writes = capture.posts("/ledger/log")
    result = ledger_coverage.scan_writes(writes)
    assert result["unsupported"] == 0, result["detail"]

    escalations = {w["event_data"]["file_path"]: w["event_data"] for w in writes
                   if w["event_type"] == "attribution_escalation"}
    killed = escalations[str(sole)]
    assert killed["attribution_confidence"] == CERTAIN and killed["process_id"] == ATTACKER
    ambiguous = escalations[str(shared)]
    assert ambiguous["attribution_confidence"] == PROBABLE
    assert ambiguous["process_id"] is None
    assert set(ambiguous["attribution_candidates"]) == {BENIGN, ATTACKER}

    for block in (w["event_data"] for w in writes if w["event_type"] == "file_event"):
        assert block["process_id"] is None, "a first answer from a lagging source is never CERTAIN"

    # The trigger still tells the Response service who it probably was
    # (test_tc26_attribution.py's design); the candidates travel beside it.
    for trigger in capture.posts("/response/trigger"):
        assert trigger["action_required"] == "isolate_and_log"
        assert "attribution_candidates" in trigger

    (terminate,) = capture.posts("/response/terminate")
    assert terminate["process_id"] == ATTACKER
    assert terminate["attribution_confidence"] == CERTAIN
    assert terminate["attribution_source"] == source.name


def test_chained_pid_keeps_only_a_certain_answers_pid():
    assert pipeline.chained_pid(ATTACKER, CERTAIN) == ATTACKER
    assert pipeline.chained_pid(ATTACKER, PROBABLE) is None
    assert pipeline.chained_pid(ATTACKER, UNKNOWN) is None
    assert pipeline.chained_pid(0, CERTAIN) is None
    assert pipeline.chained_pid(None, CERTAIN) is None
