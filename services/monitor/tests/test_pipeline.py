"""Downstream fan-out decisions - which detections actually produce a response.

The regression these cover (finding F-1) is that the response gate used to read
only the ML engine's `threat_level`. The behavioural classifier needs Shannon
entropy of roughly 7.995 before it is confident, and ciphertext under about 40KB
does not reach that through sampling noise alone, so a small file encrypted in
place was detected by the Monitor, written to the ledger, and then acted on by
nobody. Every test in the suite used files of 64KB or more, so nothing caught it.

The sizes below (4KB, 8KB, 32KB) sit in that dead band deliberately. They keep
their original filename and carry no ransomware extension, because both of those
are separate signals that would otherwise mask the gap.
"""

import json
import os

import httpx
import pytest

import detection
import pipeline
from pipeline import effective_threat_level

# Inside the band where the behavioural model scores real ciphertext below its
# own confidence threshold. Above ~40KB it is confident and the gap closes.
UNDER_CONFIDENT_SIZES = [4 * 1024, 8 * 1024, 32 * 1024]


def build_client(ml_threat_level: str, ml_prediction: str = "benign", record: list | None = None):
    """An httpx client wired to stub ML, ledger and response endpoints.

    `record` collects the paths that were called, which is what the assertions
    below are actually about - not the response bodies.
    """
    record = record if record is not None else []

    def handler(request: httpx.Request) -> httpx.Response:
        record.append(request.url.path)
        if request.url.path == "/predict":
            return httpx.Response(
                200,
                json={
                    "prediction": ml_prediction,
                    "confidence": 0.83,
                    "threat_level": ml_threat_level,
                    "model_version": "test",
                },
            )
        if request.url.path == "/ledger/log":
            return httpx.Response(200, json={"block_id": 1, "current_hash": "a" * 64})
        if request.url.path == "/response/trigger":
            return httpx.Response(200, json={"status": "success", "actions_taken": ["admin_notified"]})
        return httpx.Response(404, json={})

    return httpx.Client(transport=httpx.MockTransport(handler)), record


def encrypted_file(tmp_path, size: int):
    """A file encrypted in place: original name, original extension, random bytes."""
    target = tmp_path / f"quarterly_report_{size}.docx"
    target.write_bytes(os.urandom(size))
    return target


def detect(path) -> tuple[dict, dict]:
    """Run the real Monitor detection path over one file."""
    magic = detection.read_magic(str(path))
    entropy = detection.calculate_entropy(str(path))
    verdict = detection.classify(str(path), entropy, magic)
    event = {
        "event_id": "evt_test",
        "file_path": str(path),
        "event_type": "modified",
        "file_hash": "f" * 64,
        "process_id": None,
    }
    features = {"shannon_entropy": entropy, "file_size": os.path.getsize(path)}
    return event, {"verdict": verdict, "features": features}


# ------------------------------------------------------ the threat-level floor


@pytest.mark.parametrize(
    "model_level,suspicious,expected",
    [
        # The Monitor's verdict is a floor, so a low model score cannot cancel it.
        ("low", True, "high"),
        ("medium", True, "high"),
        # A confident model still escalates above the floor.
        ("critical", True, "critical"),
        # An unsuspicious file is left where the model put it.
        ("low", False, "low"),
        ("critical", False, "critical"),
        # ML unreachable: the Monitor's own view stands, as it always did.
        (None, True, "high"),
        (None, False, "low"),
        # An unrecognised level ranks lowest rather than raising.
        ("bogus", True, "high"),
    ],
)
def test_effective_threat_level_takes_the_higher_of_both_detectors(model_level, suspicious, expected):
    assert effective_threat_level(model_level, suspicious) == expected


# ------------------------------------------------------------- F-1 regression


@pytest.mark.parametrize("size", UNDER_CONFIDENT_SIZES)
def test_small_in_place_encryption_is_flagged_by_the_monitor(tmp_path, size):
    """Precondition for the regression below: the Monitor does detect these."""
    target = encrypted_file(tmp_path, size)
    _, detected = detect(target)

    assert detected["verdict"]["suspicious"] is True
    assert detected["verdict"]["verdict"] == "suspected_encryption"
    # No secondary signal is doing the work here.
    assert detected["verdict"]["ransom_extension"] is False
    assert detected["verdict"]["container_format"] is None


@pytest.mark.parametrize("size", UNDER_CONFIDENT_SIZES)
def test_small_encrypted_file_triggers_a_response_despite_a_low_model_score(tmp_path, size):
    """F-1: this fired no response at all before the threat level became a floor."""
    target = encrypted_file(tmp_path, size)
    event, detected = detect(target)
    client, calls = build_client(ml_threat_level="low", ml_prediction="benign")

    with client:
        result = pipeline.run(event, detected["features"], detected["verdict"], client=client)

    assert "/response/trigger" in calls, f"{size}B encrypted file produced no response"
    assert "response_triggered" in result["stages"]


@pytest.mark.parametrize("size", UNDER_CONFIDENT_SIZES)
def test_the_response_is_told_a_level_that_makes_it_isolate(tmp_path, size):
    """The Response service only isolates on high/critical, so the floor has to
    reach it - forwarding "low" would trigger a response that then declined to
    do most of its job."""
    target = encrypted_file(tmp_path, size)
    event, detected = detect(target)
    sent = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/response/trigger":
            sent.append(json.loads(request.content))
            return httpx.Response(200, json={"status": "success", "actions_taken": []})
        if request.url.path == "/predict":
            return httpx.Response(200, json={"prediction": "benign", "threat_level": "low"})
        return httpx.Response(200, json={"block_id": 1})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        pipeline.run(event, detected["features"], detected["verdict"], client=client)

    assert sent, "no response was triggered"
    assert sent[0]["threat_level"] in pipeline.ACTIONABLE_THREAT_LEVELS


def test_the_ledger_records_both_the_model_score_and_the_escalated_level(tmp_path):
    """An escalated entry must show its own working, or "benign" next to "high"
    reads as two fields contradicting each other."""
    target = encrypted_file(tmp_path, 4 * 1024)
    event, detected = detect(target)
    logged = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/ledger/log":
            logged.append(json.loads(request.content))
            return httpx.Response(200, json={"block_id": 1})
        if request.url.path == "/predict":
            return httpx.Response(200, json={"prediction": "benign", "threat_level": "low"})
        return httpx.Response(200, json={"status": "success", "actions_taken": []})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        pipeline.run(event, detected["features"], detected["verdict"], client=client)

    file_event = logged[0]["event_data"]
    assert file_event["threat_level"] == "high"
    assert file_event["model_threat_level"] == "low"


# ------------------------------------------- the gate must not have been widened


def test_a_benign_low_entropy_file_still_triggers_nothing(tmp_path):
    target = tmp_path / "notes.txt"
    target.write_text("the quick brown fox jumps over the lazy dog. " * 200)
    event, detected = detect(target)
    client, calls = build_client(ml_threat_level="low")

    with client:
        pipeline.run(event, detected["features"], detected["verdict"], client=client)

    assert detected["verdict"]["suspicious"] is False
    assert "/response/trigger" not in calls


def test_a_legitimate_archive_still_triggers_nothing(tmp_path):
    """TC-03: high entropy explained by a container header is not an attack.

    This is the false-positive guard that has to survive the wider gate - the
    Monitor's verdict is magic-byte aware, so raising it to a floor does not
    reintroduce archives as threats.
    """
    import zipfile

    target = tmp_path / "photos.zip"
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
        for index in range(8):
            archive.writestr(f"photo_{index}.bin", os.urandom(16 * 1024))

    event, detected = detect(target)
    client, calls = build_client(ml_threat_level="low")

    with client:
        pipeline.run(event, detected["features"], detected["verdict"], client=client)

    assert detected["verdict"]["verdict"] == "benign_compressed"
    assert "/response/trigger" not in calls


def test_a_confident_model_still_drives_the_response_on_its_own(tmp_path):
    """The floor is additive - it must not have replaced the model's own path."""
    target = tmp_path / "invoice.pdf"
    target.write_text("plain text, nothing alarming here")
    event, detected = detect(target)
    client, calls = build_client(ml_threat_level="critical", ml_prediction="ransomware")

    with client:
        pipeline.run(event, detected["features"], detected["verdict"], client=client)

    assert detected["verdict"]["suspicious"] is False
    assert "/response/trigger" in calls
