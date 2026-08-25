"""End-to-end: recovery against a real ledger service.

TC-04  file recovery from backup - restored to pre-attack state, integrity verified
TC-05  audit log tampering attempt - chain validation fails, tampering detected

The ledger here is the actual FastAPI app from services/ledger, reached over
HTTP through an in-process ASGI transport. Nothing about the ledger is mocked:
real SQLite file, real hash chain, real endpoints.
"""

import hashlib
import math
import os
import queue
import sqlite3
import sys
from collections import Counter
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

# The ledger is a sibling service, imported here the way the running system
# reaches it - as a separate application.
LEDGER_DIR = Path(__file__).resolve().parents[3] / "ledger"
sys.path.insert(0, str(LEDGER_DIR))

from recovery.ledger_client import LedgerClient  # noqa: E402
from recovery.recovery import RecoveryManager, to_relative  # noqa: E402


def shannon_entropy(data: bytes) -> float:
    """Same measure the monitor service uses to spot encrypted files."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


@pytest.fixture
def ledger_app(tmp_path, monkeypatch):
    """A real ledger service backed by its own SQLite file."""
    db_path = tmp_path / "ledger.db"
    monkeypatch.setenv("LEDGER_DB_PATH", str(db_path))

    for module in ("main", "hash_chain", "database", "models"):
        sys.modules.pop(module, None)

    import main as ledger_main

    ledger_main._ledger = None  # fresh chain per test
    yield ledger_main, db_path

    if ledger_main._ledger is not None:
        ledger_main._ledger.close()
    sys.modules.pop("main", None)


@pytest.fixture
def ledger_client(ledger_app):
    """A LedgerClient whose HTTP calls land on the real ledger app."""
    ledger_main, _ = ledger_app
    return LedgerClient(
        base_url="http://ledger:8003",
        client_factory=lambda: TestClient(ledger_main.app),
    )


@pytest.fixture
def manager(ledger_client, tmp_path):
    snapshot_root = tmp_path / "snapshots"
    snapshot_root.mkdir()
    return RecoveryManager(ledger_client=ledger_client, snapshot_root=str(snapshot_root))


def take_snapshot(snapshot_root: Path, snapshot_id: str, file_path: Path) -> Path:
    """Copy a file into a snapshot directory, re-rooted like VSS would."""
    target = snapshot_root / snapshot_id / to_relative(str(file_path))
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(file_path.read_bytes())
    return target


def test_tc04_file_recovered_to_pre_attack_state(manager, ledger_client, tmp_path):
    """TC-04, the full path: baseline -> snapshot -> encryption -> recovery."""
    snapshot_root = Path(manager.snapshot_root)
    document = tmp_path / "documents" / "thesis.doc"
    document.parent.mkdir(parents=True)

    # 1. A known-good file, hashed and recorded in the ledger before anything happens.
    original_content = b"Chapter 1. The original, uncorrupted thesis.\n" * 64
    document.write_bytes(original_content)
    original_hash = hashlib.sha256(original_content).hexdigest()

    ledger_client.log_event(
        "file_baseline",
        {
            "file_path": str(document),
            "file_hash": original_hash,
            "entropy": round(shannon_entropy(original_content), 3),
        },
    )

    # 2. Scheduled snapshot captures it while it is still clean.
    take_snapshot(snapshot_root, "snap_pre_attack", document)
    ledger_client.log_event(
        "snapshot_created", {"snapshot_id": "snap_pre_attack", "volume": str(tmp_path)}
    )

    # 3. Ransomware encrypts it: high-entropy bytes replace the contents.
    encrypted_content = os.urandom(4096)
    document.write_bytes(encrypted_content)
    encrypted_entropy = shannon_entropy(encrypted_content)
    assert encrypted_entropy > 7.5, "test fixture should look encrypted to the monitor"

    ledger_client.log_event(
        "file_encrypted",
        {
            "file_path": str(document),
            "process_id": 4321,
            "user": "admin",
            "entropy": round(encrypted_entropy, 3),
        },
    )
    assert document.read_bytes() != original_content

    # 4. Recover.
    result = manager.recover("snap_pre_attack", [str(document)], verify_integrity=True)

    # 5. The file is byte-identical to its pre-attack state and says so.
    assert result["status"] == "success"
    assert result["files_recovered"] == 1
    assert result["integrity_verified"] is True
    assert document.read_bytes() == original_content
    assert result["files"][0]["restored_hash"] == original_hash
    assert shannon_entropy(document.read_bytes()) < 6.0

    # 6. The recovery itself is in the audit trail.
    with TestClient(sys.modules["main"].app) as ledger_http:
        blocks = ledger_http.get("/ledger/blocks", params={"limit": 100}).json()["blocks"]
    event_types = [b["event_type"] for b in blocks]
    assert "file_baseline" in event_types
    assert "file_encrypted" in event_types
    assert "file_recovered" in event_types
    assert "recovery_completed" in event_types

    # 7. And the chain is still intact afterwards.
    verification = ledger_client.verify_chain()
    assert verification["valid"] is True
    assert verification["verification_time_ms"] < 50


def test_tc04_integrity_check_catches_a_bad_snapshot(manager, ledger_client, tmp_path):
    """A snapshot taken *after* encryption must not be reported as verified."""
    snapshot_root = Path(manager.snapshot_root)
    document = tmp_path / "report.doc"

    good_content = b"clean report contents\n" * 32
    document.write_bytes(good_content)
    ledger_client.log_event(
        "file_baseline",
        {"file_path": str(document), "file_hash": hashlib.sha256(good_content).hexdigest()},
    )

    document.write_bytes(os.urandom(2048))  # encrypted before the snapshot ran
    take_snapshot(snapshot_root, "snap_too_late", document)

    result = manager.recover("snap_too_late", [str(document)], verify_integrity=True)

    assert result["files_recovered"] == 1
    assert result["integrity_verified"] is False
    assert result["status"] == "partial"


def test_monitor_pipeline_hash_is_not_used_as_the_recovery_reference(manager, ledger_client, tmp_path):
    """Regression: the Monitor records the *encrypted* file's hash.

    services/monitor/pipeline.py fans out only for events it has already judged
    suspicious, and writes `file_hash` - the hash of the file as the attacker
    left it - into a `file_event` block, then again into `response_action`.
    Those are the newest blocks on the path, so a lookup that took "the most
    recent hash" checked the restored file against the ciphertext and reported
    every successful recovery as unverified. It would have passed only if
    recovery had handed back the encrypted file.

    The rest of the suite could not catch this: its encryption events carry no
    file_hash at all, which is a shape the running system never produces.
    """
    snapshot_root = Path(manager.snapshot_root)
    document = tmp_path / "documents" / "thesis.doc"
    document.parent.mkdir(parents=True)

    clean = b"Chapter 1. The original, uncorrupted thesis. " * 64
    clean_hash = hashlib.sha256(clean).hexdigest()
    document.write_bytes(clean)
    ledger_client.log_event(
        "file_baseline", {"file_path": str(document), "file_hash": clean_hash}
    )
    take_snapshot(snapshot_root, "snap_pre_attack", document)

    ciphertext = os.urandom(4096)
    document.write_bytes(ciphertext)
    cipher_hash = hashlib.sha256(ciphertext).hexdigest()

    # Exactly the two blocks services/monitor/pipeline.py appends on detection.
    for event_type in ("file_event", "response_action"):
        ledger_client.log_event(
            event_type,
            {
                "file_path": str(document),
                "file_hash": cipher_hash,
                "verdict": "suspected_encryption",
                "prediction": "ransomware",
                "threat_level": "critical",
            },
        )

    result = manager.recover("snap_pre_attack", [str(document)], verify_integrity=True)
    restored = result["files"][0]

    assert document.read_bytes() == clean, "the restore itself works"
    assert restored["expected_hash"] != cipher_hash, "must not verify against the attacker's hash"
    assert restored["expected_hash"] == clean_hash
    assert restored["integrity_verified"] is True
    assert result["status"] == "success"


def test_tc05_tampered_ledger_row_is_detected(manager, ledger_client, ledger_app, tmp_path):
    """TC-05: someone edits the audit log to hide the attack."""
    _, db_path = ledger_app
    snapshot_root = Path(manager.snapshot_root)
    document = tmp_path / "report.doc"

    content = b"original contents\n" * 32
    document.write_bytes(content)
    ledger_client.log_event(
        "file_baseline", {"file_path": str(document), "file_hash": hashlib.sha256(content).hexdigest()}
    )
    take_snapshot(snapshot_root, "snap1", document)

    document.write_bytes(os.urandom(1024))
    incriminating_block = ledger_client.log_event(
        "file_encrypted", {"file_path": str(document), "process_id": 6666, "entropy": 7.99}
    )

    manager.recover("snap1", [str(document)], verify_integrity=True)
    assert ledger_client.verify_chain()["valid"] is True

    # The attacker rewrites the block that records the encryption.
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "UPDATE blocks SET event_data = ? WHERE id = ?",
        ('{"entropy":1.2,"file_path":"/harmless.txt","process_id":1}', incriminating_block),
    )
    conn.commit()
    conn.close()

    verification = ledger_client.verify_chain()
    assert verification["valid"] is False
    assert verification["invalid_block_id"] == incriminating_block
    assert verification["verification_time_ms"] < 50


def test_recovery_works_when_the_baseline_hash_came_from_a_snapshot_event(manager, ledger_client, tmp_path):
    """A snapshot event carrying file_hash serves as the integrity reference.

    Not *any* event carrying one: see GOOD_STATE_EVENT_TYPES in
    recovery/ledger_client.py. The Monitor writes the attacker's hash.
    """
    snapshot_root = Path(manager.snapshot_root)
    document = tmp_path / "notes.txt"
    content = b"meeting notes"
    document.write_bytes(content)

    ledger_client.log_event(
        "snapshot_created",
        {"snapshot_id": "snap1", "file_path": str(document), "file_hash": hashlib.sha256(content).hexdigest()},
    )
    take_snapshot(snapshot_root, "snap1", document)
    document.write_bytes(b"ENCRYPTED")

    result = manager.recover("snap1", [str(document)], verify_integrity=True)

    assert result["integrity_verified"] is True
    assert document.read_bytes() == content


def test_multiple_files_recover_in_one_call(manager, ledger_client, tmp_path):
    snapshot_root = Path(manager.snapshot_root)
    documents = {}
    for name in ("a.doc", "b.doc", "c.doc"):
        path = tmp_path / "docs" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        content = f"contents of {name}".encode()
        path.write_bytes(content)
        documents[path] = content
        ledger_client.log_event(
            "file_baseline", {"file_path": str(path), "file_hash": hashlib.sha256(content).hexdigest()}
        )
        take_snapshot(snapshot_root, "snap1", path)
        path.write_bytes(os.urandom(512))

    result = manager.recover("snap1", [str(p) for p in documents], verify_integrity=True)

    assert result["status"] == "success"
    assert result["files_recovered"] == 3
    assert result["integrity_verified"] is True
    for path, content in documents.items():
        assert path.read_bytes() == content

    assert ledger_client.verify_chain()["valid"] is True


# ----------------------------------------- the Monitor writing its own baseline


def load_monitor():
    """The Monitor service, loaded by file rather than by name.

    `services/monitor/app.py`, `services/response/app.py` and
    `services/ledger/app.py` are three different modules all called `app`, so a
    plain `import app` here would resolve to whichever service happens to be
    earlier on the path - and the Response suite runs in this same process.
    Loading by location sidesteps that entirely; the monitor's directory is
    *appended* to sys.path, not prepended, so its siblings (`detection`,
    `pipeline`, `containers`) resolve while `import app` still means what it
    meant before.
    """
    import importlib.util

    monitor_dir = Path(__file__).resolve().parents[3] / "monitor"
    if str(monitor_dir) not in sys.path:
        sys.path.append(str(monitor_dir))
    spec = importlib.util.spec_from_file_location("urds_monitor_app", monitor_dir / "app.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["urds_monitor_app"] = module
    spec.loader.exec_module(module)
    return module


def monitor_downstream(ledger_main):
    """An httpx client that puts the real ledger behind the Monitor's fan-out.

    The ML engine and the Response service are stubbed - neither is what this
    test is about - but every /ledger call lands on the actual ledger app, so
    the blocks the Monitor writes are the blocks recovery then reads.
    """
    ledger_http = TestClient(ledger_main.app)

    def handler(request):
        if request.url.path.startswith("/ledger/"):
            response = ledger_http.request(
                request.method,
                request.url.path,
                content=request.read(),
                headers={"content-type": "application/json"},
            )
            return httpx.Response(
                response.status_code,
                content=response.content,
                headers={"content-type": "application/json"},
            )
        if request.url.path == "/predict":
            return httpx.Response(
                200,
                json={
                    "prediction": "ransomware",
                    "confidence": 0.91,
                    "threat_level": "high",
                    "model_version": "test",
                },
            )
        return httpx.Response(200, json={"status": "success", "actions_taken": ["admin_notified"]})

    return httpx.Client(transport=httpx.MockTransport(handler))


def drain(monitor, client):
    """Run the Monitor's queued work, the way its worker thread would.

    `_drain` builds its own client and blocks, so the dispatch it performs is
    reproduced here instead. That dispatch is itself covered by
    services/monitor/tests/test_baseline.py.
    """
    while not monitor._work.empty():
        kind, *payload = monitor._work.get_nowait()
        if kind == "baseline":
            monitor._run_baseline(client, *payload)
        else:
            monitor._run_detection(client, *payload)


def test_tc04_a_real_detect_encrypt_recover_cycle_verifies(manager, ledger_client, ledger_app, tmp_path):
    """The whole loop with nothing hand-written into the ledger.

    Every other TC-04 test above logs `file_baseline` itself, which proves the
    integrity check works *given* a known-good hash. It could not prove the
    running system ever produces one, and it did not: the Monitor reached the
    ledger only for suspicious events, so the sole hash on an attacked path was
    the ciphertext's. Recovery correctly refused to verify against it and every
    real recovery reported "integrity could not be verified" - honest, and
    useless.

    Here the Monitor writes the baseline itself, on the first benign sighting,
    and it is the only thing that makes the last assertion possible.
    """
    monitor = load_monitor()
    ledger_main, _ = ledger_app
    snapshot_root = Path(manager.snapshot_root)

    monitor.EVENTS.clear()
    monitor._SEEN_FILES.clear()
    monitor.ENTROPY_HISTORY.clear()
    monitor.WHITELIST.replace([], [])
    monitor.TRAINING_MODE.reset()
    monitor.PIPELINE_ENABLED = True
    monitor.BASELINE_LOGGING_ENABLED = True
    monitor._work = queue.Queue()

    document = tmp_path / "documents" / "thesis.doc"
    document.parent.mkdir(parents=True)
    clean = b"Chapter 1. The original, uncorrupted thesis. " * 64
    clean_hash = hashlib.sha256(clean).hexdigest()

    with monitor_downstream(ledger_main) as client:
        # 1. The file appears and the Monitor finds it benign. This is the only
        #    step that is new, and the whole test turns on it.
        document.write_bytes(clean)
        first = monitor.handle_event(str(document), "created")
        assert first["suspicious"] is False
        assert first["file_hash"] == clean_hash
        drain(monitor, client)

        # 2. A snapshot captures it while it is still clean.
        take_snapshot(snapshot_root, "snap_pre_attack", document)

        # 3. It is encrypted in place. The Monitor detects that and fans out,
        #    which writes the *ciphertext's* hash as the newest one on the path.
        document.write_bytes(os.urandom(4096))
        attacked = monitor.handle_event(str(document), "modified")
        assert attacked["suspicious"] is True
        drain(monitor, client)

    with TestClient(ledger_main.app) as ledger_http:
        blocks = ledger_http.get(
            "/ledger/blocks", params={"file_path": str(document), "newest_first": True, "limit": 50}
        ).json()["blocks"]

    types = [block["event_type"] for block in blocks]
    assert "file_baseline" in types, "the Monitor recorded no known-good hash"
    assert types.count("file_baseline") == 1, "one baseline per path per run"
    # The newest hash on this path belongs to the attacker, which is exactly why
    # last_known_hash cannot simply take the most recent one.
    assert (blocks[0]["event_data"] or {}).get("file_hash") != clean_hash

    reference = ledger_client.last_known_hash(str(document))
    assert reference["event_type"] == "file_baseline"
    assert reference["file_hash"] == clean_hash

    # 4. Recover, and verify against a hash the system produced by itself.
    result = manager.recover("snap_pre_attack", [str(document)], verify_integrity=True)

    assert result["status"] == "success"
    assert result["integrity_verified"] is True
    assert result["files"][0]["expected_hash"] == clean_hash
    assert document.read_bytes() == clean
    assert ledger_client.verify_chain()["valid"] is True
