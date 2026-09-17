"""No ledger event names a process the evidence does not support.

`scripts/ledger_coverage.py` already measured whether every mitigation decision
reaches the chain, and whether the blocks that arrive carry all five required
fields. Both are counts of *presence*. Neither can tell an attributed PID from
an invented one, and for a period neither did: a fabricated `process_id` sat in
the tamper-evident chain, written there by the demo, while the claim-matrix row
that was supposed to police the chain stayed green - because the row counted
fields, and the field was there. docs/CORRECTIONS.md has the history.

So the scan asserts a *value* relationship instead: a ledger event may name a
process only when attribution resolved to CERTAIN. `None` is not an offence.
"No process was identified" is the honest answer for an unattributed write and
has to stay expressible, or the pressure to invent one comes straight back.

These tests exist because of what the scan currently returns. On a host with no
Windows Security-log audit source, attribution resolves to UNKNOWN for every
write, so no event names a process at all and "0 unsupported" is *vacuously*
true. A scan that never looked would report exactly the same number. The cases
below feed it PIDs that must be flagged, so the zero in the report is known to
be a measurement rather than an absence of measurement.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]


def _load():
    spec = importlib.util.spec_from_file_location(
        "urds_ledger_coverage", ROOT / "scripts" / "ledger_coverage.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["urds_ledger_coverage"] = module
    spec.loader.exec_module(module)
    return module


ledger_coverage = _load()


def scan(*event_data: dict) -> dict:
    """Run the scan over ledger writes carrying the given event_data."""
    stub = ledger_coverage.LedgerStub()
    stub.ledger_writes = [
        {"event_type": "file_encrypted", "event_data": data} for data in event_data
    ]
    return stub.unsupported_pids()


def test_a_pid_named_without_any_confidence_is_flagged():
    """The shape the fabricated PID had: a bare number, nothing behind it."""
    result = scan({"file_path": "/x", "process_id": 6666})
    assert result["unsupported"] == 1
    assert result["events_naming_a_process"] == 1
    assert "only 'certain'" in result["detail"][0]["why"]


def test_a_pid_named_with_unknown_attribution_is_flagged():
    result = scan({"file_path": "/x", "process_id": 4242,
                   "attribution_confidence": "unknown"})
    assert result["unsupported"] == 1


def test_a_pid_named_with_probable_attribution_is_flagged():
    """PROBABLE is explicitly not kill-authorising, so it cannot name one either."""
    result = scan({"file_path": "/x", "process_id": 4242,
                   "attribution_confidence": "probable"})
    assert result["unsupported"] == 1


def test_a_pid_named_with_certain_attribution_is_accepted():
    """The one case that may name a process. 22716 is the live run's writer."""
    result = scan({"file_path": "/x", "process_id": 22716,
                   "attribution_confidence": "certain"})
    assert result["unsupported"] == 0
    assert result["events_naming_a_process"] == 1


def test_a_null_pid_is_not_an_offence():
    """"No process was identified" must stay expressible and must stay free."""
    result = scan({"file_path": "/x", "process_id": None,
                   "attribution_confidence": "unknown"})
    assert result["unsupported"] == 0
    assert result["events_naming_a_process"] == 0


def test_an_event_that_never_mentions_a_process_is_ignored():
    result = scan({"file_path": "/x", "file_hash": "ab" * 32})
    assert result["unsupported"] == 0
    assert result["events_examined"] == 1


@pytest.mark.parametrize("pid", ["6666", 0, -1, 3.5, True, [6666]])
def test_a_pid_that_is_not_a_positive_integer_is_flagged(pid):
    """Including True, which is an int in Python and would otherwise pass as 1."""
    result = scan({"file_path": "/x", "process_id": pid,
                   "attribution_confidence": "certain"})
    assert result["unsupported"] == 1, f"{pid!r} should not be accepted as a PID"
    assert "positive integer" in result["detail"][0]["why"]


def test_offences_are_reported_individually_not_just_counted():
    """An auditor needs to know which block, not how many."""
    result = scan(
        {"file_path": "/clean", "process_id": None},
        {"file_path": "/bad", "process_id": 6666},
        {"file_path": "/good", "process_id": 22716,
         "attribution_confidence": "certain"},
    )
    assert result["events_examined"] == 3
    assert result["events_naming_a_process"] == 2
    assert result["unsupported"] == 1
    assert result["detail"][0]["file_path"] == "/bad"


def test_the_committed_report_carries_the_scan_and_it_is_zero():
    """The figure claim C-16 quotes, in the artefact it quotes it from."""
    report = json.loads(
        (ROOT / "reports" / "ledger_coverage.json").read_text(encoding="utf-8"))
    integrity = report["process_attribution_integrity"]
    assert integrity["unsupported"] == 0, integrity["detail"]
    assert integrity["meets_target"] is True
    assert integrity["events_examined"] > 0, (
        "a scan over no events is not evidence of anything")
