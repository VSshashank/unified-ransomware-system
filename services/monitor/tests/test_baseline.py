"""Known-good hashes: what makes recovery's integrity check able to verify anything.

services/response/recovery/ledger_client.py will only accept a hash from an
event type that records a file in a state worth restoring *to* -
`file_baseline`, `file_recovered`, `snapshot_created`. That allowlist is
correct, and until this existed nothing in the running system ever wrote the
first of them: `pipeline.run` reaches the ledger only for suspicious events, so
the only hash recorded on an attacked path was the one the attacker's write
produced. Checking a restored file against that hash inverts the test - it
passes only if recovery hands back the ciphertext.

So the integrity check was honest and inert. It reported "integrity could not be
verified" for every real recovery, because there was genuinely nothing
trustworthy to compare against.

What is asserted here is the shape of the fix and its bounds. A baseline write is
worth something only if it is (a) written for benign content, (b) written once,
and (c) not on the detection path.
"""

import os
import queue

import httpx
import pytest

import app as monitor_app
import pipeline
import synthetic_corpus


@pytest.fixture(autouse=True)
def isolated_work_queue(monkeypatch):
    """Capture what the detection path enqueues instead of letting it fan out.

    The worker thread is only started by /monitor/start, so in most of the suite
    these items simply accumulate. Swapping the queue makes that explicit and
    keeps one test's enqueues out of the next one's assertions.
    """
    monkeypatch.setattr(monitor_app, "_work", queue.Queue())
    monkeypatch.setattr(monitor_app, "PIPELINE_ENABLED", True)
    monkeypatch.setattr(monitor_app, "BASELINE_LOGGING_ENABLED", True)
    monitor_app.EVENTS.clear()
    monitor_app._SEEN_FILES.clear()
    monitor_app.ENTROPY_HISTORY.clear()
    monitor_app.WHITELIST.replace([], [])
    monitor_app.TRAINING_MODE.reset()
    yield
    monitor_app.EVENTS.clear()
    monitor_app._SEEN_FILES.clear()
    monitor_app.ENTROPY_HISTORY.clear()


def queued() -> list[tuple]:
    items = []
    while not monitor_app._work.empty():
        items.append(monitor_app._work.get_nowait())
    return items


def kinds() -> list[str]:
    return [item[0] for item in queued()]


# ------------------------------------------------------------- what is written


def test_a_first_benign_sighting_records_one_baseline(tmp_path):
    target = tmp_path / "report.docx"
    target.write_bytes(synthetic_corpus.build_docx(40000))

    event = monitor_app.handle_event(str(target), "created")
    assert event["suspicious"] is False

    items = queued()
    assert [item[0] for item in items] == ["baseline"]
    assert items[0][1] is event


def test_a_second_sighting_of_the_same_path_records_nothing(tmp_path):
    """One write per path per monitor run. A document saved every thirty seconds
    must not produce a ledger block every thirty seconds."""
    target = tmp_path / "report.docx"
    target.write_bytes(synthetic_corpus.build_docx(40000))

    monitor_app.handle_event(str(target), "created")
    queued()

    target.write_bytes(synthetic_corpus.build_docx(41000))
    monitor_app.handle_event(str(target), "modified")

    assert kinds() == []


def test_a_suspicious_first_sighting_records_no_baseline(tmp_path):
    """A file that is already ciphertext the first time it is seen has no
    known-good state to record, and recording one would certify the attacker's
    output as the thing recovery should restore to."""
    target = tmp_path / "victim.docx"
    target.write_bytes(os.urandom(40000))

    event = monitor_app.handle_event(str(target), "created")
    assert event["suspicious"] is True

    assert kinds() == ["detection"], "a suspicious file must fan out, not baseline"


def test_a_whitelisted_file_still_records_no_baseline(tmp_path):
    """Suppression changes whether an alert fires, not what the detector thought.

    An operator silencing a path has not certified its contents as a recovery
    target, so the *raw* verdict is what gates the baseline write.
    """
    target = tmp_path / "vault.bin"
    target.write_bytes(os.urandom(40000))
    monitor_app.WHITELIST.replace([str(tmp_path / "*.bin")], [])

    event = monitor_app.handle_event(str(target), "created")
    assert event["suspicious"] is False
    assert event["suppressed_by"]["rule"] == "path"

    assert kinds() == []


def test_a_deleted_file_records_no_baseline(tmp_path):
    target = tmp_path / "gone.docx"
    target.write_bytes(synthetic_corpus.build_docx(40000))
    target.unlink()

    monitor_app.handle_event(str(target), "deleted")

    assert kinds() == []


def test_baseline_logging_can_be_switched_off(monkeypatch, tmp_path):
    """Deviation V-5: the extra ledger traffic is a cost, so it is switchable."""
    monkeypatch.setattr(monitor_app, "BASELINE_LOGGING_ENABLED", False)
    target = tmp_path / "report.docx"
    target.write_bytes(synthetic_corpus.build_docx(40000))

    monitor_app.handle_event(str(target), "created")

    assert kinds() == []


def test_the_baseline_write_is_not_on_the_detection_path(tmp_path):
    """It is queued, not called. The detection budget is measured over
    `handle_event`, and an HTTP round trip to another container does not fit in
    it - the queue is what keeps the sub-100ms target true."""
    target = tmp_path / "report.docx"
    target.write_bytes(synthetic_corpus.build_docx(40000))

    event = monitor_app.handle_event(str(target), "created")

    assert event["detection_latency_ms"] < 100
    assert "baseline_block_id" not in event, "the ledger was called inline"
    assert kinds() == ["baseline"]


# --------------------------------------------------------- what reaches the ledger


def test_log_baseline_writes_the_event_type_recovery_will_accept():
    """The allowlist in ledger_client.GOOD_STATE_EVENT_TYPES is the contract."""
    sent = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request.read())
        return httpx.Response(200, json={"block_id": 7, "current_hash": "a" * 64})

    event = {
        "file_path": "/watch/report.docx",
        "file_hash": "b" * 64,
        "file_size": 40000,
        "entropy": 4.6,
        "verdict": "benign",
        "event_type": "created",
        "timestamp": "2026-01-01T00:00:00Z",
    }

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        block = pipeline.log_baseline(client, event)

    assert block == {"block_id": 7, "current_hash": "a" * 64}
    import json

    body = json.loads(sent[0])
    assert body["event_type"] == "file_baseline"
    assert body["event_data"]["file_path"] == "/watch/report.docx"
    assert body["event_data"]["file_hash"] == "b" * 64


def test_the_worker_dispatches_baseline_and_detection_items_differently(monkeypatch, tmp_path):
    """`_drain` used to unpack a three-tuple unconditionally.

    Two shapes now go through one queue, so the tag is what keeps a baseline
    item from being handed to the ML engine as though it were a detection.
    """
    seen = []
    monkeypatch.setattr(monitor_app, "_run_baseline", lambda client, event: seen.append(("baseline", event)))
    monkeypatch.setattr(
        monitor_app,
        "_run_detection",
        lambda client, event, features, verdict: seen.append(("detection", event)),
    )

    benign = tmp_path / "report.docx"
    benign.write_bytes(synthetic_corpus.build_docx(40000))
    monitor_app.handle_event(str(benign), "created")

    encrypted = tmp_path / "victim.docx"
    encrypted.write_bytes(os.urandom(40000))
    monitor_app.handle_event(str(encrypted), "created")

    monitor_app._work.put(None)
    monitor_app._drain()

    assert [kind for kind, _ in seen] == ["baseline", "detection"]
