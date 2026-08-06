"""Recovery module tests.

The directory-backed snapshot source is used throughout so these run anywhere,
independent of VSS.
"""

import hashlib
import os

import pytest
from fastapi.testclient import TestClient

from recovery.recovery import (
    RecoveryError,
    RecoveryManager,
    sha256_file,
    to_relative,
)


class FakeLedger:
    """Records events and serves back hashes, like the real ledger would."""

    base_url = "http://ledger:8003"

    def __init__(self):
        self.events = []
        self.hashes = {}

    def try_log_event(self, event_type, event_data):
        self.events.append((event_type, event_data))
        return len(self.events)

    def log_event(self, event_type, event_data):
        return self.try_log_event(event_type, event_data)

    def last_known_hash(self, file_path):
        if file_path not in self.hashes:
            return None
        return {
            "file_hash": self.hashes[file_path],
            "block_id": 1,
            "event_type": "file_baseline",
            "timestamp": "2026-08-06T10:00:00Z",
        }

    def events_of(self, event_type):
        return [data for name, data in self.events if name == event_type]


@pytest.fixture
def ledger():
    return FakeLedger()


@pytest.fixture
def snapshot_root(tmp_path):
    root = tmp_path / "snapshots"
    root.mkdir()
    return root


@pytest.fixture
def manager(ledger, snapshot_root):
    return RecoveryManager(ledger_client=ledger, snapshot_root=str(snapshot_root))


def make_snapshot(snapshot_root, snapshot_id, files: dict):
    """Build a snapshot directory holding `files` at re-rooted paths."""
    snapshot_dir = snapshot_root / snapshot_id
    for original_path, content in files.items():
        target = snapshot_dir / to_relative(str(original_path))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    return snapshot_dir


# ------------------------------------------------------------------- path logic


@pytest.mark.parametrize(
    "path,expected",
    [
        ("C:\\data\\report.doc", "data\\report.doc"),
        ("/data/report.doc", "data/report.doc"),
        ("data/report.doc", "data/report.doc"),
        ("D:\\a\\b\\c.txt", "a\\b\\c.txt"),
    ],
)
def test_paths_are_re_rooted_without_their_volume(path, expected):
    assert to_relative(path) == expected


def test_sha256_matches_hashlib(tmp_path):
    target = tmp_path / "f.bin"
    target.write_bytes(b"hello ransomware")
    assert sha256_file(str(target)) == hashlib.sha256(b"hello ransomware").hexdigest()


# ------------------------------------------------------------------- restoring


def test_restore_overwrites_the_damaged_file(manager, snapshot_root, tmp_path):
    original = tmp_path / "docs" / "report.doc"
    original.parent.mkdir(parents=True)
    original.write_bytes(b"ENCRYPTED-GARBAGE")
    make_snapshot(snapshot_root, "snap1", {original: b"the real contents"})

    result = manager.recover("snap1", [str(original)], verify_integrity=False)

    assert result["files_recovered"] == 1
    assert original.read_bytes() == b"the real contents"


def test_restore_recreates_a_deleted_file(manager, snapshot_root, tmp_path):
    """Ransomware often deletes the original after writing its encrypted copy."""
    original = tmp_path / "docs" / "gone.doc"
    make_snapshot(snapshot_root, "snap1", {original: b"recovered"})

    result = manager.recover("snap1", [str(original)], verify_integrity=False)

    assert result["files_recovered"] == 1
    assert original.read_bytes() == b"recovered"


def test_file_absent_from_the_snapshot_is_reported(manager, snapshot_root, tmp_path):
    make_snapshot(snapshot_root, "snap1", {tmp_path / "a.doc": b"a"})
    missing = tmp_path / "b.doc"

    result = manager.recover("snap1", [str(missing)], verify_integrity=False)

    assert result["status"] == "failed"
    assert result["files_recovered"] == 0
    assert "not present in the snapshot" in result["files"][0]["reason"]


def test_unknown_snapshot_raises(manager):
    with pytest.raises(RecoveryError, match="not found"):
        manager.recover("no-such-snapshot", ["/tmp/a.doc"])


def test_unknown_snapshot_says_where_it_looked(manager, snapshot_root):
    """The message has to be actionable on any host, VSS or not."""
    with pytest.raises(RecoveryError) as exc:
        manager.recover("no-such-snapshot", ["/tmp/a.doc"])

    message = str(exc.value)
    assert "Searched:" in message
    assert str(snapshot_root) in message


def test_an_operational_vss_failure_is_distinct_from_not_found(manager, monkeypatch):
    """VSS present but erroring is a different problem from a missing snapshot."""
    from recovery.vss_manager import VSSError as _VSSError

    def broken_list(self):
        raise _VSSError("vssadmin list shadows failed (exit 1); it requires an elevated shell")

    monkeypatch.setattr(type(manager.vss), "list_snapshots", broken_list)

    with pytest.raises(RecoveryError, match="Cannot access snapshot"):
        manager.recover("snap1", ["/tmp/a.doc"])


def test_damaged_copy_can_be_preserved(manager, snapshot_root, tmp_path):
    original = tmp_path / "report.doc"
    original.write_bytes(b"ENCRYPTED")
    make_snapshot(snapshot_root, "snap1", {original: b"clean"})

    manager.recover("snap1", [str(original)], verify_integrity=False, preserve_damaged_copy=True)

    assert original.read_bytes() == b"clean"
    preserved = [p for p in os.listdir(tmp_path) if ".damaged-" in p]
    assert len(preserved) == 1
    assert (tmp_path / preserved[0]).read_bytes() == b"ENCRYPTED"


# ------------------------------------------------------- integrity verification


def test_integrity_verified_against_the_ledger_hash(manager, ledger, snapshot_root, tmp_path):
    original = tmp_path / "report.doc"
    content = b"the original document"
    original.write_bytes(b"ENCRYPTED")
    make_snapshot(snapshot_root, "snap1", {original: content})
    ledger.hashes[str(original)] = hashlib.sha256(content).hexdigest()

    result = manager.recover("snap1", [str(original)], verify_integrity=True)

    assert result["status"] == "success"
    assert result["integrity_verified"] is True
    assert result["files"][0]["restored_hash"] == result["files"][0]["expected_hash"]


def test_integrity_fails_when_the_snapshot_copy_does_not_match(manager, ledger, snapshot_root, tmp_path):
    """A snapshot taken after the encryption started must not pass as clean."""
    original = tmp_path / "report.doc"
    make_snapshot(snapshot_root, "snap1", {original: b"already encrypted"})
    ledger.hashes[str(original)] = hashlib.sha256(b"the original document").hexdigest()

    result = manager.recover("snap1", [str(original)], verify_integrity=True)

    assert result["files_recovered"] == 1  # the file was restored...
    assert result["integrity_verified"] is False  # ...but it is not the right file
    assert result["status"] == "partial"
    assert "does not match ledger block" in result["files"][0]["reason"]


def test_no_prior_hash_reports_unverified_rather_than_claiming_success(manager, snapshot_root, tmp_path):
    original = tmp_path / "report.doc"
    make_snapshot(snapshot_root, "snap1", {original: b"contents"})

    result = manager.recover("snap1", [str(original)], verify_integrity=True)

    assert result["files_recovered"] == 1
    assert result["integrity_verified"] is False
    assert "No prior hash" in result["files"][0]["reason"]


def test_verification_skipped_makes_no_claim(manager, snapshot_root, tmp_path):
    original = tmp_path / "report.doc"
    make_snapshot(snapshot_root, "snap1", {original: b"contents"})

    result = manager.recover("snap1", [str(original)], verify_integrity=False)

    assert result["status"] == "success"
    assert result["integrity_verified"] is False


def test_mixed_batch_reports_partial(manager, ledger, snapshot_root, tmp_path):
    good = tmp_path / "good.doc"
    missing = tmp_path / "missing.doc"
    make_snapshot(snapshot_root, "snap1", {good: b"good contents"})
    ledger.hashes[str(good)] = hashlib.sha256(b"good contents").hexdigest()

    result = manager.recover("snap1", [str(good), str(missing)], verify_integrity=True)

    assert result["status"] == "partial"
    assert result["files_recovered"] == 1
    assert result["integrity_verified"] is False


# ------------------------------------------------------------------ audit trail


def test_every_restore_is_logged(manager, ledger, snapshot_root, tmp_path):
    original = tmp_path / "report.doc"
    make_snapshot(snapshot_root, "snap1", {original: b"contents"})

    manager.recover("snap1", [str(original)], verify_integrity=False)

    recorded = ledger.events_of("file_recovered")
    assert len(recorded) == 1
    assert recorded[0]["file_path"] == str(original)
    assert recorded[0]["snapshot_id"] == "snap1"
    assert len(recorded[0]["file_hash"]) == 64

    summary = ledger.events_of("recovery_completed")
    assert summary[0]["files_recovered"] == 1


def test_failed_restores_are_logged_too(manager, ledger, snapshot_root, tmp_path):
    make_snapshot(snapshot_root, "snap1", {tmp_path / "other.doc": b"x"})

    manager.recover("snap1", [str(tmp_path / "missing.doc")], verify_integrity=False)

    assert len(ledger.events_of("recovery_failed")) == 1


def test_recovery_survives_the_ledger_being_down(manager, snapshot_root, tmp_path, monkeypatch):
    """Losing the audit write must not lose the restored file."""
    original = tmp_path / "report.doc"
    make_snapshot(snapshot_root, "snap1", {original: b"contents"})
    monkeypatch.setattr(manager.ledger, "try_log_event", lambda *a, **k: None)
    monkeypatch.setattr(
        manager.ledger, "last_known_hash", lambda p: (_ for _ in ()).throw(RuntimeError("ledger down"))
    )

    result = manager.recover("snap1", [str(original)], verify_integrity=True)

    assert result["files_recovered"] == 1
    assert original.read_bytes() == b"contents"


# ------------------------------------------------------------------- API layer


@pytest.fixture
def client(manager):
    import app as response_app
    from recovery import recovery as recovery_module

    response_app.app.dependency_overrides[recovery_module.get_recovery_manager] = lambda: manager
    with TestClient(response_app.app) as test_client:
        yield test_client
    response_app.app.dependency_overrides.clear()


def test_recover_endpoint_returns_the_contract_shape(client, manager, ledger, snapshot_root, tmp_path):
    original = tmp_path / "report.doc"
    content = b"the original document"
    make_snapshot(snapshot_root, "snap1", {original: content})
    ledger.hashes[str(original)] = hashlib.sha256(content).hexdigest()

    response = client.post(
        "/response/recover",
        json={"snapshot_id": "snap1", "files": [str(original)], "verify_integrity": True},
    )

    assert response.status_code == 200
    body = response.json()
    for field in ("status", "files_recovered", "integrity_verified", "timestamp"):
        assert field in body
    assert body["status"] == "success"
    assert body["files_recovered"] == 1
    assert body["integrity_verified"] is True


def test_recover_endpoint_404s_on_an_unknown_snapshot(client, tmp_path):
    response = client.post(
        "/response/recover",
        json={"snapshot_id": "nope", "files": [str(tmp_path / "a.doc")], "verify_integrity": False},
    )

    assert response.status_code == 404
    body = response.json()
    assert body["error"]["code"] == "SNAPSHOT_UNAVAILABLE"
    assert set(body["error"]) == {"code", "message", "timestamp", "request_id"}


def test_recover_endpoint_rejects_an_empty_file_list(client):
    response = client.post(
        "/response/recover", json={"snapshot_id": "snap1", "files": [], "verify_integrity": True}
    )
    # Was 422 with FastAPI's raw {"detail": [...]} body. The response service now
    # has the same validation handler as the gateway and ledger, so this is a 400
    # carrying the project's error envelope.
    assert response.status_code == 400
    body = response.json()
    assert body["error"]["code"] == "BAD_REQUEST"
    assert set(body["error"]) == {"code", "message", "timestamp", "request_id"}


def test_status_endpoint_explains_the_platform(client):
    body = client.get("/response/recover/status").json()
    assert "vss" in body
    assert "supported" in body["vss"]
    assert "ledger_url" in body


def test_teammate_endpoints_are_untouched(client):
    """terminate/isolate belong to AS and must keep working.

    These were placeholders returning a fixed 200 when this test was written, so
    it used an arbitrary PID. They are real now: a PID that does not exist is
    refused rather than reported as terminated. The point of the test is that
    SI's router still mounts alongside AS's endpoints, so it checks they are
    routed and answering in-contract, not that any PID can be killed.
    """
    terminate = client.post(
        "/response/terminate",
        json={"process_id": 1234, "incident_id": "i-1", "reason": "test", "force": True},
    )
    assert terminate.status_code in {200, 409}
    if terminate.status_code == 409:
        assert terminate.json()["error"]["code"] == "TERMINATION_REFUSED"

    isolate = client.post(
        "/response/isolate",
        json={"isolation_level": "full", "duration_seconds": 60, "allow_localhost": True},
    )
    assert isolate.status_code == 200
    assert "enforced" in isolate.json()
