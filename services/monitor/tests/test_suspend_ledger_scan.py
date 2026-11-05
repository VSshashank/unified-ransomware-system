"""C-16 and the blocks freeze-first adds to the chain.

`process_suspended` and `process_resumed` are written by the Response service,
and they name the process they froze or released. Claim C-16 says an event
names a process only when attribution resolved to CERTAIN - and a suspension is
taken on an answer that is, by design, not CERTAIN yet. So these two block
types are the one exception, and a narrow one: they MAY name a PID only
together with the gate that allowed it (`gate` present and equal to
"suspend_authorised"). A block that names a PID without it is an offence, as
any other block naming one without CERTAIN attribution is. Every other rule
stays: a PID that is not a positive integer, or any other event type naming a
process short of CERTAIN, is still flagged.

What the gate field is: the *caller's claim* (`gate_verified: false`) - the
Response service does not evaluate the gate, the Monitor does. The scan checks
that the claim is present and is the right one, which is what an operator
auditing a chain can check; it does not make the claim true.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]


def _load():
    spec = importlib.util.spec_from_file_location("urds_ledger_coverage_suspend", ROOT / "scripts" / "ledger_coverage.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["urds_ledger_coverage_suspend"] = module
    spec.loader.exec_module(module)
    return module


ledger_coverage = _load()

GATE = "suspend_authorised"


def suspended(**overrides) -> dict:
    data = {
        "action": "suspend", "incident_id": "inc_1", "process_id": 4242, "lease_id": "lease_1",
        "attribution_confidence": "probable", "attribution_source": "windows-security-4663",
        "attribution_reason": "one writer so far", "attribution_supplied_by": "caller",
        "gate": GATE, "gate_verified": False, "outcome": "suspended", "suspended": True,
    }
    data.update(overrides)
    return data


def scan(event_type: str, data: dict) -> dict:
    return ledger_coverage.scan_writes([{"block_id": 1, "event_type": event_type, "event_data": data}])


@pytest.mark.parametrize("event_type", ["process_suspended", "process_resumed"])
def test_a_suspend_block_naming_a_pid_without_the_gate_is_rejected(event_type):
    data = suspended()
    data["gate"] = None
    report = scan(event_type, data)
    assert report["unsupported"] == 1, report
    assert report["events_naming_a_process"] == 1
    assert "gate" in report["detail"][0]["why"]


@pytest.mark.parametrize("event_type", ["process_suspended", "process_resumed"])
def test_a_suspend_block_with_no_gate_field_at_all_is_rejected(event_type):
    data = suspended()
    del data["gate"]
    assert scan(event_type, data)["unsupported"] == 1


@pytest.mark.parametrize("event_type", ["process_suspended", "process_resumed"])
def test_a_suspend_block_naming_a_pid_with_the_gate_is_accepted(event_type):
    report = scan(event_type, suspended())
    assert report["unsupported"] == 0, report
    assert report["events_naming_a_process"] == 1


@pytest.mark.parametrize("event_type", ["process_suspended", "process_resumed"])
def test_the_gate_must_be_the_right_one(event_type):
    assert scan(event_type, suspended(gate="kill_authorised"))["unsupported"] == 1
    assert scan(event_type, suspended(gate=""))["unsupported"] == 1
    assert scan(event_type, suspended(gate="Suspend_Authorised"))["unsupported"] == 1


def test_the_gate_excuses_the_confidence_and_nothing_else():
    """Short of CERTAIN is fine for these two blocks, with the gate; a bad PID is not."""
    assert scan("process_suspended", suspended(attribution_confidence="probable"))["unsupported"] == 0
    assert scan("process_suspended", suspended(attribution_confidence=None))["unsupported"] == 0
    for bad in (0, -5, True, "4242", 4242.0):
        assert scan("process_suspended", suspended(process_id=bad))["unsupported"] == 1, bad


@pytest.mark.parametrize("event_type", ["process_suspended", "process_resumed"])
def test_a_block_that_names_no_process_is_never_an_offence(event_type):
    data = suspended(process_id=None, gate=None)
    assert scan(event_type, data)["unsupported"] == 0
    data.pop("process_id")
    assert scan(event_type, data)["unsupported"] == 0


@pytest.mark.parametrize("event_type", ["file_event", "response_action", "attribution_escalation",
                                        "suppression_decision", None])
def test_the_gate_does_not_excuse_any_other_block(event_type):
    """Only the two suspend block types have the exception; the rest keep the old rule."""
    offending = {"process_id": 4242, "attribution_confidence": "probable", "gate": GATE}
    report = scan(event_type, offending)
    assert report["unsupported"] == 1, report
    assert "certain" in report["detail"][0]["why"]
    assert scan(event_type, {**offending, "attribution_confidence": "certain"})["unsupported"] == 0


def test_the_existing_rules_are_unchanged_for_a_call_with_no_event_type():
    assert ledger_coverage.unsupported_pid({"process_id": 7, "attribution_confidence": "probable"})
    assert ledger_coverage.unsupported_pid({"process_id": 7, "attribution_confidence": "certain"}) is None
    assert ledger_coverage.unsupported_pid({"process_id": None}) is None
    assert ledger_coverage.unsupported_pid({"attribution_confidence": "probable"}) is None


def test_a_chain_mixing_all_of_it_is_judged_block_by_block():
    writes = [
        {"block_id": 1, "event_type": "process_suspended", "event_data": suspended()},
        {"block_id": 2, "event_type": "process_resumed", "event_data": suspended(action="resume")},
        {"block_id": 3, "event_type": "process_suspended", "event_data": suspended(gate=None)},
        {"block_id": 4, "event_type": "attribution_escalation",
         "event_data": {"process_id": None, "attribution_confidence": "probable", "lease_id": "lease_1"}},
        {"block_id": 5, "event_type": "attribution_escalation",
         "event_data": {"process_id": 4242, "attribution_confidence": "certain", "lease_id": "lease_1"}},
    ]
    report = ledger_coverage.scan_writes(writes)
    assert report["events_examined"] == 5
    assert report["events_naming_a_process"] == 4
    assert [d["block_id"] for d in report["detail"]] == [3]
