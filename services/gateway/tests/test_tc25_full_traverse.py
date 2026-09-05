"""TC-25 (SH): one event, five hops, the policy record intact at each.

Table 9.7 row: *one suspicious event traverses Monitor → ML → Ledger → Response →
Recovery with the policy record intact at every hop.*

This is the row that decides whether the word *unified* is carried by
measurement. §9.7 D6 says that if any pipeline gate fails, the final claim is
reduced to "URDS Monitor" scope and the reduction is written down. So the test is
not "does the pipeline run" - it is "does the **adjudication** survive the
journey, byte for byte, or does each service hold a slightly different account of
why the alert exists".

Five hops, and what each has to carry:

    Monitor    the event carries the adjudication, the validation state and the
               policy version
    ML         receives features and returns a score. It does **not** receive the
               adjudication, by design - the model scores bytes, not policy - and
               that is asserted rather than skipped, so the absence is a recorded
               decision and not a hole
    Ledger     the `file_event` block carries the adjudication unchanged
    Response   `/response/trigger` receives it, and the `response_action` block
               chains it again
    Recovery   the real `RecoveryManager` carries it into `file_recovered`,
               alongside the incident it answers

"Intact" is asserted as equality with the record the Monitor produced, not as
"the field is present". A hop that carried a truncated or re-derived copy would
satisfy presence and defeat the purpose: an auditor joining two chains has to
find the same decision on both, not two decisions that look similar.

The row is SH's, and the test lives in the gateway suite for that reason. It
imports the Monitor and Response modules by path, which is what
`scripts/pipeline_governance.py` does; the gateway itself is a proxy and holds
none of this state.
"""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT / "services" / "monitor"))
sys.path.insert(0, str(REPO_ROOT / "services" / "response"))

import detection  # noqa: E402
import pipeline as monitor_pipeline  # noqa: E402
from admissibility import adjudicate  # noqa: E402
from recovery.recovery import RecoveryManager  # noqa: E402

PAYLOAD_BYTES = 120_000


def payload(tag: str, size: int = PAYLOAD_BYTES) -> bytes:
    return hashlib.shake_256(tag.encode()).digest(size)


class Hops:
    """Stands in for `pipeline._post` and keeps every body, per endpoint."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    def __call__(self, client, base_url, path, body):
        self.calls.append((path, body))
        if path == "/predict":
            return {"prediction": "ransomware", "confidence": 0.97, "threat_level": "critical"}
        if path == "/ledger/log":
            return {"block_id": len(self.calls), "current_hash": "a" * 64}
        if path == "/response/trigger":
            return {"status": "success", "actions_taken": ["admin_notified", "host_isolated"]}
        return {}

    def bodies(self, path: str) -> list[dict]:
        return [body for called, body in self.calls if called == path]

    def blocks(self, event_type: str) -> list[dict]:
        return [
            body["event_data"]
            for called, body in self.calls
            if called == "/ledger/log" and body.get("event_type") == event_type
        ]


@pytest.fixture(scope="module")
def traverse(tmp_path_factory) -> dict:
    """Drive one attenuated event through the Monitor pipeline, recording each hop.

    Attenuated rather than clean: an operator rule matched and was outranked, so
    the adjudication is a real record with a rule name, both costs and a reason -
    the hardest thing to carry and the thing that is worth carrying.
    """
    tmp = tmp_path_factory.mktemp("tc25")
    target = tmp / "quarterly_report.zip"
    target.write_bytes(b"PK\x03\x04" + payload("tc25"))

    size = target.stat().st_size
    head, tail = detection.sample_file(str(target), size)
    entropy, statistics = detection.measure(head)
    magic = detection.read_magic(str(target))
    fmt = detection.identify_container(magic)

    import containers

    validation_state = containers.container_status(head, tail, fmt, size)
    verdict = detection.classify(
        str(target),
        entropy,
        magic,
        readable=True,
        container_valid=containers.tristate(validation_state),
        statistics=statistics,
        container_status=validation_state,
    )
    assert verdict["suspicious"] and verdict["signal"] == "structural_mismatch"

    # A path whitelist: LOW to forge, against a MODERATE signal. Outranked, so
    # the alert stands and the decision is attenuated.
    decision = adjudicate(verdict, {"rule": "path", "value": str(tmp / "*")})
    assert decision["outcome"] == "attenuated"

    event = {
        "event_id": "evt_tc25",
        "file_path": str(target),
        "file_hash": detection.sha256_file(str(target)),
        "event_type": "modified",
        "detection_latency_ms": 2.5,
        "process_id": None,
        "admissibility": decision,
        "validation_state": verdict["validation_state"],
        "policy_version": verdict["policy"],
    }
    features = {"shannon_entropy": entropy, "file_size": size, **statistics}

    hops = Hops()
    original = monitor_pipeline._post
    monitor_pipeline._post = hops
    try:
        result = monitor_pipeline.run(event, features, verdict, client=object())
    finally:
        monitor_pipeline._post = original

    return {
        "decision": decision,
        "verdict": verdict,
        "event": event,
        "hops": hops,
        "result": result,
    }


# ------------------------------------------------------------------ the hops


def test_tc25_the_monitor_hop_carries_the_record(traverse):
    event = traverse["event"]
    assert event["admissibility"] == traverse["decision"]
    assert event["validation_state"] == "forged"
    assert event["policy_version"] == detection.DEFAULT_CONTAINER_POLICY


def test_tc25_the_ml_hop_happens_and_deliberately_does_not_receive_the_record(traverse):
    """A recorded decision, not an omission.

    The model scores bytes. Handing it the adjudication would let an operator's
    rule move a score, which is the coupling the governance layer exists to
    prevent - and there is nothing in `features_to_vector` that could use it.
    Asserted so that if it ever *starts* arriving, someone has to explain why.
    """
    predicts = traverse["hops"].bodies("/predict")
    assert len(predicts) == 1
    assert "ml_predicted" in traverse["result"]["stages"]
    assert "admissibility" not in json.dumps(predicts[0])


def test_tc25_the_ledger_hop_carries_the_record_unchanged(traverse):
    blocks = traverse["hops"].blocks("file_event")
    assert len(blocks) == 1
    block = blocks[0]

    assert block["admissibility"] == traverse["decision"], "the record was altered in transit"
    assert block["validation_state"] == traverse["event"]["validation_state"]
    assert block["policy_version"] == traverse["event"]["policy_version"]
    assert block["signal"] == traverse["verdict"]["signal"]
    assert "ledger_logged" in traverse["result"]["stages"]


def test_tc25_the_response_hop_receives_the_record(traverse):
    triggers = traverse["hops"].bodies("/response/trigger")
    assert len(triggers) == 1
    assert triggers[0]["admissibility"] == traverse["decision"]
    assert triggers[0]["threat_level"] in monitor_pipeline.ACTIONABLE_THREAT_LEVELS
    assert triggers[0]["incident_id"]
    assert "response_triggered" in traverse["result"]["stages"]


def test_tc25_the_response_action_is_chained_with_the_record(traverse):
    blocks = traverse["hops"].blocks("response_action")
    assert len(blocks) == 1
    block = blocks[0]

    assert block["admissibility"] == traverse["decision"]
    assert block["validation_state"] == traverse["event"]["validation_state"]
    assert block["policy_version"] == traverse["event"]["policy_version"]
    assert block["actions_taken"]
    assert block["incident_id"] == traverse["hops"].bodies("/response/trigger")[0][
        "incident_id"
    ]


def test_tc25_the_recovery_hop_carries_the_record_and_the_incident(traverse):
    """The fifth hop, against the real `RecoveryManager`.

    Only the ledger transport is replaced. What is asserted is that a restore
    authorised by a decision chains that decision - so "this file was put back"
    and "this is why we were allowed to" live on one block rather than two chains
    joined on a timestamp.
    """
    captured: list[dict] = []

    class Recorder:
        base_url = "recorded://ledger"

        def try_log_event(self, event_type, event_data):
            captured.append({"event_type": event_type, "event_data": event_data})
            return None

        def last_known_hash(self, file_path):
            return None

    with tempfile.TemporaryDirectory(prefix="tc25_recovery_") as tmp:
        root = Path(tmp)
        snapshot = root / "snap"
        snapshot.mkdir()
        target = root / "document.docx"
        original = payload("tc25-original", 4096)
        target.write_bytes(original)
        mirrored = snapshot / target.relative_to(target.anchor)
        mirrored.parent.mkdir(parents=True, exist_ok=True)
        mirrored.write_bytes(original)
        target.write_bytes(payload("tc25-encrypted", 4096))

        manager = RecoveryManager(ledger_client=Recorder())
        manager.resolve_snapshot_root = lambda snapshot_id: str(snapshot)
        result = manager.recover(
            snapshot_id="snap",
            files=[str(target)],
            verify_integrity=False,
            incident_id="inc_tc25",
            admissibility=traverse["decision"],
        )

        assert result["files"][0]["restored"] is True
        assert target.read_bytes() == original, "the file did not actually come back"

    recovered = [c["event_data"] for c in captured if c["event_type"] == "file_recovered"]
    assert len(recovered) == 1
    assert recovered[0]["admissibility"] == traverse["decision"]
    assert recovered[0]["incident_id"] == "inc_tc25"


def test_tc25_every_hop_holds_the_same_decision_and_not_a_lookalike(traverse):
    """The row, in one assertion.

    Equality, not presence. Four copies of the record travel by three different
    routes, and any hop that re-derived its own would satisfy a presence check
    and leave an auditor with two accounts of one decision.
    """
    decision = traverse["decision"]
    hops = traverse["hops"]

    carried = [
        traverse["event"]["admissibility"],
        hops.blocks("file_event")[0]["admissibility"],
        hops.bodies("/response/trigger")[0]["admissibility"],
        hops.blocks("response_action")[0]["admissibility"],
    ]
    assert all(record == decision for record in carried)
    assert {json.dumps(record, sort_keys=True) for record in carried} == {
        json.dumps(decision, sort_keys=True)
    }


def test_tc25_the_recorded_run_agrees_with_this_one():
    """Cross-check against `scripts/pipeline_governance.py`'s artefact.

    That script measures the same hops over three populations and evaluates D6.
    If it and this test ever disagree, one of the two was not re-run.
    """
    report = REPO_ROOT / "reports" / "pipeline_governance.json"
    if not report.exists():
        pytest.skip("reports/pipeline_governance.json is absent")

    recorded = json.loads(report.read_text(encoding="utf-8"))
    gates = recorded["gates"]
    for name, gate in gates.items():
        assert gate is True or gate.get("passes") is True, (name, gate)
