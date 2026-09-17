"""The self-test's own moving parts, tested where they can run anywhere.

`scripts/selftest.py` is the thing `install.ps1` believes when it says an
installation works. Two properties matter more than the rest and neither can be
checked by running it on a healthy machine:

  * it must be able to report FAIL. A self-test that cannot go red is a
    decoration. The chain check is exercised here against a deliberately
    corrupted ledger, and the report object against a run that measured nothing.
  * it must not fabricate the verdict. It reads what the service wrote; these
    tests build a ledger with the ledger service's own writer and then read it
    back through the self-test's reader, so the two halves are held to the same
    format.

The live half - spawn a child, watch the agent suspend it, restore from a
shadow copy - needs Windows, elevation and a running service, and is not
simulated here. Simulating it would produce a green test on a machine where the
real thing cannot work, which is the failure this file exists to prevent.
"""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
for extra in (ROOT / "scripts", ROOT / "services" / "ledger"):
    if str(extra) not in sys.path:
        sys.path.insert(0, str(extra))

import selftest  # noqa: E402


@pytest.fixture()
def ledger(tmp_path: Path) -> Path:
    """A real ledger, written by the ledger service's own append path."""
    from hash_chain import HashChainLedger  # noqa: PLC0415

    db = tmp_path / "ledger.db"
    chain = HashChainLedger(str(db))
    chain.add_block("agent_started", {"host": "test"})
    chain.add_block("file_event", {"file_path": r"C:\protected\a.txt",
                                   "verdict": "benign"})
    chain.add_block("response_escalation", {"process_id": 4321,
                                            "process_image": "python.exe",
                                            "decision": "resume",
                                            "snapshot": {"taken": True,
                                                         "snapshot_id": "{abc}"}})
    chain.close()
    return db


# ------------------------------------------------------------- reading blocks


def test_tip_id_is_the_last_block(ledger: Path):
    assert selftest.tip_id(ledger) == 3


def test_blocks_since_filters_by_type_and_id(ledger: Path):
    everything = selftest.blocks_since(ledger, 0)
    assert [b["event_type"] for b in everything] == [
        "agent_started", "file_event", "response_escalation"]

    escalations = selftest.blocks_since(ledger, 1, "response_escalation")
    assert len(escalations) == 1
    assert escalations[0]["data"]["process_id"] == 4321

    assert selftest.blocks_since(ledger, 3) == []


def test_the_reader_never_opens_the_ledger_for_writing(ledger: Path):
    """The agent owns the only writer. A second one contends with the thing
    under test, and the first symptom would be the agent failing to record the
    incident the self-test is waiting for."""
    conn = selftest.read_only_connection(ledger)
    try:
        with pytest.raises(sqlite3.OperationalError):
            conn.execute("INSERT INTO blocks (timestamp, event_type) VALUES ('x','y')")
    finally:
        conn.close()


# --------------------------------------------------------- verifying the chain


def test_a_clean_chain_verifies(ledger: Path):
    result = selftest.verify_chain(ledger)
    assert result == {"valid": True, "blocks_checked": 3, "invalid_block_id": None}


def test_an_edited_block_is_caught_and_named(ledger: Path):
    """The check has to be able to go red, and say where."""
    conn = sqlite3.connect(ledger)
    conn.execute("UPDATE blocks SET event_data = ? WHERE id = 2",
                 (json.dumps({"file_path": "nothing happened"}),))
    conn.commit()
    conn.close()

    result = selftest.verify_chain(ledger)
    assert result["valid"] is False
    assert result["invalid_block_id"] == 2


def test_a_forked_chain_is_caught(ledger: Path):
    """Two appends with the same previous_hash - what two writers produce.

    This is the shape `scripts/start_stack.ps1` exists to avoid: pointing a
    second process's ledger service at the agent's database produced 300 blocks
    and a chain that failed verification at block 116.
    """
    conn = sqlite3.connect(ledger)
    row = conn.execute("SELECT previous_hash, current_hash FROM blocks WHERE id = 3").fetchone()
    conn.execute(
        "INSERT INTO blocks (timestamp, event_type, event_data, previous_hash,"
        " current_hash) VALUES ('2026-01-01T00:00:00Z', 'file_event', '{}', ?, ?)",
        (row[0], row[1]))
    conn.commit()
    conn.close()

    assert selftest.verify_chain(ledger)["valid"] is False


# ------------------------------------------------------------------ the report


def test_a_report_that_measured_nothing_is_not_a_pass():
    """Zero checks and zero failures is not green.

    It is the shape of every false green this project has shipped: the suite
    runner that printed `0 passed, 0 failed` under five green groups and exited
    0, and before that an audit script that printed FAIL and exited 0.
    """
    report = selftest.Report()
    assert report.as_dict()["result"] == "FAIL"


def test_a_failed_check_makes_the_report_fail(capsys):
    report = selftest.Report()
    assert report.record("something true", True, "detail") is True
    assert report.record("something false", False, "detail",
                         remediation="run this") is False

    printed = capsys.readouterr().out
    assert "[ PASS ] something true" in printed
    assert "[ FAIL ] something false" in printed
    assert "run this" in printed, "a failure must print its own remediation"

    payload = report.as_dict()
    assert payload["result"] == "FAIL"
    assert payload["passed"] == 1
    assert payload["failed"] == 1


def test_every_check_carries_its_remediation_into_the_report():
    report = selftest.Report()
    report.record("a", False, "d", remediation="do the thing", child_pid=7)
    check = report.as_dict()["checks"][0]
    assert check["remediation"] == "do the thing"
    assert check["observed"] == {"child_pid": 7}


# ----------------------------------------------------------- the service state


@pytest.mark.parametrize("raw, expected", [
    ("SERVICE_NAME: URDSAgent\n        STATE              : 4  RUNNING\n", "RUNNING"),
    ("        STATE              : 1  STOPPED\n", "STOPPED"),
    ("        STATE              : 3  STOP_PENDING\n", "STOP_PENDING"),
    ("[SC] EnumQueryServicesStatus:OpenService FAILED 1060:\n\n"
     "The specified service does not exist as an installed service.\n", "absent"),
    ("nothing useful here\n", "unknown"),
])
def test_service_state_is_read_as_a_word(raw: str, expected: str):
    assert selftest.parse_service_state(raw) == expected


# ------------------------------------------------------------------- waiting


def test_wait_for_returns_the_first_truthy_answer():
    answers = iter([None, None, "found"])
    assert selftest.wait_for(lambda: next(answers), timeout_s=5, interval_s=0) == "found"


def test_wait_for_gives_up_and_says_so():
    assert selftest.wait_for(lambda: None, timeout_s=0.05, interval_s=0.01) is None


def test_wait_for_checks_once_even_with_no_time_left():
    """A zero timeout must still ask. Otherwise a condition that is already
    true reads as a timeout."""
    assert selftest.wait_for(lambda: "already true", timeout_s=0) == "already true"
