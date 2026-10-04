"""The Response service's blocks name a process only as the target of a kill.

Claim C-16 (scripts/ledger_coverage.py, docs/CORRECTIONS.md): an event in the
chain names a process only when attribution resolved to CERTAIN. The
2026-10-04 elevated run's chain broke it in this service's blocks two ways:
every unattributed trigger recorded `process_id: 0` (299 blocks), and a
PROBABLE answer's PID sent along with an isolate-and-log trigger was recorded as
`process_id` (18). A terminate block named its target with no word of what
authorised the kill (54).

Now a trigger block carries `process_id` only when a kill was asked for, and the
caller's PIDs otherwise go in `attribution_candidates`; a terminate block says
what authorised it when the caller does.
"""

import pytest
from fastapi.testclient import TestClient

import actions
import app as response_app


@pytest.fixture
def blocks(monkeypatch):
    recorded: list[tuple[str, dict]] = []
    monkeypatch.setattr(actions, "ISOLATION_ENABLED", False)
    monkeypatch.setattr(response_app, "log_action",
                        lambda event_type, event_data: recorded.append((event_type, event_data)) or {"block_id": 1})
    return recorded


@pytest.fixture
def client(blocks):
    with TestClient(response_app.app) as test_client:
        yield test_client


def test_an_unattributed_trigger_records_no_process_not_the_number_zero(client, blocks):
    client.post("/response/trigger", json={
        "incident_id": "inc-a", "process_id": 0, "threat_level": "critical",
        "action_required": "isolate_and_log", "attribution_confidence": "unknown",
    })
    ((_, block),) = blocks
    assert block["process_id"] is None
    assert block["attribution_candidates"] == []


def test_a_probable_pid_is_a_candidate_not_the_named_process(client, blocks):
    client.post("/response/trigger", json={
        "incident_id": "inc-b", "process_id": 4242, "threat_level": "critical",
        "action_required": "isolate_and_log", "attribution_confidence": "probable",
        "attribution_candidates": [1717, 4242],
    })
    ((_, block),) = blocks
    assert block["process_id"] is None
    assert block["attribution_candidates"] == [1717, 4242]
    assert block["attribution_confidence"] == "probable"


def test_a_probable_pid_from_an_older_caller_still_lands_in_the_candidates(client, blocks):
    client.post("/response/trigger", json={
        "incident_id": "inc-c", "process_id": 4242, "threat_level": "critical",
        "action_required": "isolate_and_log", "attribution_confidence": "probable",
    })
    ((_, block),) = blocks
    assert block["process_id"] is None
    assert block["attribution_candidates"] == [4242]


def test_a_kill_names_its_target_whatever_the_outcome(client, blocks):
    """PID 1 is refused by the guard; the block still says what was asked."""
    client.post("/response/trigger", json={
        "incident_id": "inc-d", "process_id": 1, "threat_level": "critical",
        "action_required": "terminate_process", "attribution_confidence": "certain",
    })
    ((_, block),) = blocks
    assert block["process_id"] == 1
    assert block["attribution_confidence"] == "certain"


def test_a_terminate_block_records_what_authorised_it(client, blocks):
    client.post("/response/terminate", json={
        "process_id": 1, "incident_id": "inc-e", "reason": "test", "force": True,
        "attribution_confidence": "certain", "attribution_source": "windows-security-4663",
    })
    ((_, block),) = blocks
    assert block["outcome"] == "refused"
    assert block["attribution_confidence"] == "certain"
    assert block["attribution_source"] == "windows-security-4663"


def test_an_operator_kill_is_recorded_without_attribution(client, blocks):
    """Nothing is invented for it: the scan reports such a block, by design."""
    client.post("/response/terminate", json={
        "process_id": 1, "incident_id": "inc-f", "reason": "operator", "force": True,
    })
    ((_, block),) = blocks
    assert block["process_id"] == 1
    assert block["attribution_confidence"] is None
