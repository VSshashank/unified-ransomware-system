"""TC-11 - multiple simultaneous attacks (detection half).

Table 5.8: "Multiple simultaneous attacks -> All processes detected and
terminated, system remains stable."

Detection is this service's half of that: when several files are encrypted at
the same moment, every one of them must be flagged, and the shared state the
Monitor keeps - the bounded event buffer and the seen-file set - must survive
concurrent writers intact. The termination half is in
services/response/tests/test_tc11_concurrent.py.

The concurrency here is real threads against the real `handle_event`, not a
simulated queue: `_record` takes a lock, and a test that never contends it
would not be testing anything.
"""

import os
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import app as monitor_app

SIMULTANEOUS_ATTACKS = 12


def _encrypted_file(root: Path, index: int) -> Path:
    """A document-named file whose contents are indistinguishable from ciphertext."""
    path = root / f"victim_{index}.docx"
    path.write_bytes(os.urandom(96 * 1024))
    return path


@pytest.fixture(autouse=True)
def clean_event_state():
    monitor_app.EVENTS.clear()
    monitor_app._SEEN_FILES.clear()
    yield
    monitor_app.EVENTS.clear()
    monitor_app._SEEN_FILES.clear()


def test_tc11_every_simultaneous_attack_is_detected(tmp_path):
    """All twelve are flagged. One missed file is one unrecoverable document."""
    paths = [_encrypted_file(tmp_path, i) for i in range(SIMULTANEOUS_ATTACKS)]

    barrier = threading.Barrier(SIMULTANEOUS_ATTACKS)

    def attack(path: Path) -> dict | None:
        barrier.wait()  # release all threads at the same instant
        return monitor_app.handle_event(str(path), "created")

    with ThreadPoolExecutor(max_workers=SIMULTANEOUS_ATTACKS) as pool:
        events = list(pool.map(attack, paths))

    assert all(event is not None for event in events), "an event was dropped under concurrency"

    suspicious = [event for event in events if event["suspicious"]]
    assert len(suspicious) == SIMULTANEOUS_ATTACKS, (
        f"only {len(suspicious)}/{SIMULTANEOUS_ATTACKS} simultaneous attacks were flagged: "
        f"{[e['file_path'] for e in events if not e['suspicious']]}"
    )


def test_tc11_shared_state_stays_consistent_under_concurrent_writers(tmp_path):
    """The buffer and the seen-file set are shared mutable state. Twelve threads
    appending at once must not lose, duplicate, or corrupt an entry."""
    paths = [_encrypted_file(tmp_path, i) for i in range(SIMULTANEOUS_ATTACKS)]

    with ThreadPoolExecutor(max_workers=SIMULTANEOUS_ATTACKS) as pool:
        list(pool.map(lambda p: monitor_app.handle_event(str(p), "created"), paths))

    assert len(monitor_app.EVENTS) == SIMULTANEOUS_ATTACKS, (
        f"event buffer holds {len(monitor_app.EVENTS)}, expected {SIMULTANEOUS_ATTACKS}"
    )

    recorded = {event["file_path"] for event in monitor_app.EVENTS}
    assert recorded == {str(p) for p in paths}, "buffer contents do not match the files written"

    event_ids = [event["event_id"] for event in monitor_app.EVENTS]
    assert len(set(event_ids)) == len(event_ids), "duplicate event_id generated under concurrency"

    assert monitor_app._SEEN_FILES == {str(p) for p in paths}


def test_tc11_detection_stays_within_budget_under_load(tmp_path):
    """Concurrency must not push detection past the 100ms target - a storm is
    exactly when latency matters most."""
    paths = [_encrypted_file(tmp_path, i) for i in range(SIMULTANEOUS_ATTACKS)]

    with ThreadPoolExecutor(max_workers=SIMULTANEOUS_ATTACKS) as pool:
        events = list(pool.map(lambda p: monitor_app.handle_event(str(p), "created"), paths))

    latencies = sorted(event["detection_latency_ms"] for event in events)
    p95 = latencies[int(len(latencies) * 0.95) - 1]
    print(f"\nTC-11: {SIMULTANEOUS_ATTACKS} concurrent detections, p95 {p95:.2f}ms (target <100ms)")

    assert p95 < 100.0, f"p95 detection latency under concurrent load was {p95:.2f}ms"


def test_tc11_benign_files_in_the_storm_are_still_not_flagged(tmp_path):
    """A storm must not become an excuse for false positives: legitimate
    compressed files mixed into the same burst stay benign."""
    import io
    import zipfile

    attacks = [_encrypted_file(tmp_path, i) for i in range(6)]

    benign = []
    for index in range(6):
        path = tmp_path / f"archive_{index}.zip"
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("data.bin", os.urandom(90000))
        path.write_bytes(buffer.getvalue())
        benign.append(path)

    everything = attacks + benign
    with ThreadPoolExecutor(max_workers=len(everything)) as pool:
        events = list(pool.map(lambda p: monitor_app.handle_event(str(p), "created"), everything))

    by_path = {event["file_path"]: event for event in events}
    assert all(by_path[str(p)]["suspicious"] for p in attacks), "missed an attack in the mixed burst"
    assert not any(by_path[str(p)]["suspicious"] for p in benign), (
        f"false positive under load: {[str(p) for p in benign if by_path[str(p)]['suspicious']]}"
    )
