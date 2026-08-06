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
import sqlite3
import sys
from collections import Counter
from pathlib import Path

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
    """Any event carrying file_hash serves as the integrity reference."""
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
