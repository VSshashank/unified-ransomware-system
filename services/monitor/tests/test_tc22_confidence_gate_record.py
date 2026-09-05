"""TC-22 (NI): a sub-threshold confidence withholds nothing, and says so.

Table 9.7 row: *a case suppressed by sub-threshold confidence still produces an
adjudication record - the withheld action is visible, not silent.*

Chapter 9 §9.3 finding 3 states that the ML confidence gate silently withholds a
response. `scripts/capability_calibration.py` measured the claim instead of
restating it, and the measurement narrows it in one direction and widens it in
another. Both are asserted here.

**Narrowed.** On the only live caller the gate cannot withhold anything.
`app.handle_event` fans out to the pipeline only for a verdict that is already
suspicious, and `pipeline.effective_threat_level` floors a suspicious event at
`high`, which is actionable. A model that scores the file `benign` at 0.2
confidence therefore changes nothing about whether the response fires. The
calibration recorded this as `monitor_floor_makes_gate_unreachable: true`, and
these tests drive the real pipeline to check it still holds.

**Widened.** What the gate costs is not the action, it is the *distinction*. A
case the model scored 0.2 and a case it scored 0.95 both reach the ledger as
`threat_level: high`. That is only not-silent because `model_threat_level` is
recorded beside the effective one - so the entry reads as a deliberate override
with both inputs visible, rather than as two fields contradicting each other. If
that field ever stops being written, the override becomes invisible and finding 3
becomes true as written.

The tests live in the Monitor because that is where the gate is - the threshold
is in `ml-engine/app.py` and the decision it feeds is `pipeline.run`'s. The row
is NI's.

The sizes are the ones that produced the original defect: real ciphertext at 4KB,
8KB and 32KB scores below the behavioural model's own confidence threshold, and
every test in the suite used 64KB or more, so nothing caught it.
"""

from __future__ import annotations

import hashlib
import json

import httpx
import pytest

import detection
import pipeline

UNDER_CONFIDENT_SIZES = [4 * 1024, 8 * 1024, 32 * 1024]


def stub_client(ml_threat_level: str, ml_prediction: str, confidence: float):
    """Real pipeline, stubbed hops. Records every body the ledger was sent."""
    calls: list[str] = []
    ledger: list[dict] = []
    responses: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        body = json.loads(request.content) if request.content else {}
        if request.url.path == "/predict":
            return httpx.Response(
                200,
                json={
                    "prediction": ml_prediction,
                    "confidence": confidence,
                    "threat_level": ml_threat_level,
                    "model_version": "test",
                },
            )
        if request.url.path == "/ledger/log":
            ledger.append(body)
            return httpx.Response(200, json={"block_id": len(ledger), "current_hash": "a" * 64})
        if request.url.path == "/response/trigger":
            responses.append(body)
            return httpx.Response(
                200, json={"status": "success", "actions_taken": ["admin_notified"]}
            )
        return httpx.Response(404, json={})

    return httpx.Client(transport=httpx.MockTransport(handler)), calls, ledger, responses


def encrypted(tmp_path, size: int):
    """Encrypted in place: original name, original extension, ciphertext."""
    path = tmp_path / "quarterly_report.docx"
    path.write_bytes(hashlib.shake_256(f"tc22:{size}".encode()).digest(size))
    return path


def detect(path):
    size = path.stat().st_size
    head, tail = detection.sample_file(str(path), size)
    entropy, statistics = detection.measure(head)
    magic = detection.read_magic(str(path))
    verdict = detection.classify(
        str(path), entropy, magic, readable=True, statistics=statistics
    )
    event = {
        "event_id": "evt_tc22",
        "file_path": str(path),
        "file_hash": detection.sha256_file(str(path)),
        "event_type": "modified",
        "detection_latency_ms": 1.0,
        "process_id": None,
        "admissibility": None,
        "validation_state": "unvalidated",
        "policy_version": detection.DEFAULT_CONTAINER_POLICY,
    }
    features = {"shannon_entropy": entropy, "file_size": size, **statistics}
    return event, features, verdict


@pytest.mark.parametrize("size", UNDER_CONFIDENT_SIZES)
def test_tc22_the_monitor_floor_makes_the_gate_unreachable(size, tmp_path):
    """The model says benign at a level that would withhold. Nothing is withheld."""
    path = encrypted(tmp_path, size)
    event, features, verdict = detect(path)
    assert verdict["suspicious"] is True, "the fixture must be one the Monitor flags"

    client, calls, _ledger, responses = stub_client("low", "benign", 0.21)
    result = pipeline.run(event, features, verdict, client=client)

    assert "/response/trigger" in calls, "the response was withheld"
    assert "response_triggered" in result["stages"]
    assert len(responses) == 1
    assert responses[0]["threat_level"] == "high"


@pytest.mark.parametrize("model_level", ["low", "medium"])
def test_tc22_effective_threat_level_floors_a_suspicious_verdict(model_level):
    """The mechanism, stated directly. `high` is in ACTIONABLE_THREAT_LEVELS."""
    assert pipeline.effective_threat_level(model_level, suspicious=True) == "high"
    assert "high" in pipeline.ACTIONABLE_THREAT_LEVELS
    # And the floor is a floor, not an override: a model that scores *higher*
    # than the Monitor is not pulled down to it.
    assert pipeline.effective_threat_level("critical", suspicious=True) == "critical"
    # With no Monitor verdict to floor against, the model's answer stands.
    assert pipeline.effective_threat_level(model_level, suspicious=False) == model_level


@pytest.mark.parametrize("size", UNDER_CONFIDENT_SIZES)
def test_tc22_the_ledger_entry_shows_both_the_model_and_the_effective_level(size, tmp_path):
    """The row itself: the override is visible, not silent.

    Without `model_threat_level` the entry would read `prediction: benign,
    threat_level: high` and look like two fields disagreeing. With it, an auditor
    can see the model's own answer, the Monitor's floor, and which one decided.
    """
    path = encrypted(tmp_path, size)
    event, features, verdict = detect(path)

    client, _calls, ledger, _responses = stub_client("low", "benign", 0.21)
    pipeline.run(event, features, verdict, client=client)

    file_events = [b for b in ledger if b.get("event_type") == "file_event"]
    assert len(file_events) == 1
    data = file_events[0]["event_data"]

    assert data["model_threat_level"] == "low", "the model's own answer is gone"
    assert data["threat_level"] == "high", "the effective level is gone"
    assert data["prediction"] == "benign"
    assert data["confidence"] == 0.21
    # And the Monitor's own reasoning, so the floor is explicable from the entry.
    assert data["verdict"] == verdict["verdict"]
    assert data["signal"] == verdict["signal"]
    assert data["reason"]


def test_tc22_a_confident_and_an_unconfident_case_are_distinguishable(tmp_path):
    """Both reach the ledger as `high`; only `model_threat_level` tells them apart.

    This is the finding, asserted. The gate does not cost the action - it costs
    the distinction, and the distinction survives only because that one field is
    written.
    """
    path = encrypted(tmp_path, 8 * 1024)
    entries = {}
    for label, (level, prediction, confidence) in {
        "unconfident": ("low", "benign", 0.21),
        "confident": ("critical", "ransomware", 0.98),
    }.items():
        event, features, verdict = detect(path)
        client, _calls, ledger, _responses = stub_client(level, prediction, confidence)
        pipeline.run(event, features, verdict, client=client)
        entries[label] = [b for b in ledger if b["event_type"] == "file_event"][0][
            "event_data"
        ]

    assert entries["unconfident"]["model_threat_level"] == "low"
    assert entries["confident"]["model_threat_level"] == "critical"
    assert entries["unconfident"]["model_threat_level"] != entries["confident"][
        "model_threat_level"
    ]
    # Both act. The threat levels differ only because the model's own answer was
    # already above the floor in one case.
    assert entries["unconfident"]["threat_level"] == "high"
    assert entries["confident"]["threat_level"] == "critical"


def test_tc22_the_calibration_recorded_the_same_conclusion():
    """Cross-check against the artefact that measured it, if it is present."""
    from pathlib import Path

    report = Path(__file__).resolve().parents[3] / "reports" / "capability_calibration.json"
    if not report.exists():
        pytest.skip("reports/capability_calibration.json is absent")

    levels = json.loads(report.read_text(encoding="utf-8"))["levels"]
    gate = [e for e in levels if "ml_confidence_gate" in e["strategy"]]
    assert gate, "the ML gate strategy is no longer measured"

    measurement = gate[0]["measurement"]
    assert measurement["monitor_floor_makes_gate_unreachable"] is True
    assert measurement["finding_3_status"] == "restated"
