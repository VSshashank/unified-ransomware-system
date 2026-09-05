"""TC-24 (SI): three broken restores, three distinct outcomes, none verified.

Table 9.7 row: *missing baseline, mismatched hash and corrupted snapshot produce
three distinct outcomes; none is reported as verified.*

The failure mode this rules out is the one that makes a recovery claim worthless:
a restore path that answers "restored" whatever happened, so "100% verified
restoration" means "the code ran". Each injection below breaks a different thing
and the result has to say *which* - a caller who cannot tell "there was nothing
to compare against" from "the bytes did not match" cannot act on either.

Driven against the real `RecoveryManager`. Only the ledger transport is stood in
for, and it records rather than answers; what is restored, what is compared and
what is reported is the shipped code.

`scripts/failure_injection.py` runs the same three plus ledger tampering and
response isolation and writes `reports/failure_injection.json`. This is the
regression form of the first three, so the property is checked on every run
rather than only when someone re-runs the script.

The row is SI's.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from recovery.recovery import RecoveryManager  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[3]


def sha256_bytes(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


class RecordingLedger:
    """Answers a controlled prior hash and keeps what it was told."""

    base_url = "recorded://ledger"

    def __init__(self, known: dict | None = None) -> None:
        self.known = known
        self.events: list[dict] = []

    def try_log_event(self, event_type, event_data):
        self.events.append({"event_type": event_type, "event_data": event_data})
        return None

    def last_known_hash(self, file_path):
        return self.known

    def types(self) -> list[str]:
        return [e["event_type"] for e in self.events]


def manager(ledger: RecordingLedger, snapshot: Path) -> RecoveryManager:
    instance = RecoveryManager(ledger_client=ledger)
    instance.resolve_snapshot_root = lambda snapshot_id: str(snapshot)
    return instance


def workspace(tmp_path: Path, name: str) -> tuple[Path, Path]:
    root = tmp_path / name
    snapshot = root / "snap"
    snapshot.mkdir(parents=True)
    return snapshot, root / "quarterly.docx"


def mirror(snapshot: Path, target: Path, blob: bytes) -> None:
    mirrored = snapshot / target.relative_to(target.anchor)
    mirrored.parent.mkdir(parents=True, exist_ok=True)
    mirrored.write_bytes(blob)


# ----------------------------------------------------------------- injections


def run_missing_baseline(tmp_path) -> tuple[dict, RecordingLedger]:
    """Nothing in the ledger has ever recorded this path.

    The file restores. What must not happen is a claim that it restored
    *correctly*: there is nothing to compare it against.
    """
    snapshot, target = workspace(tmp_path, "missing_baseline")
    good = b"quarterly figures, unencrypted\n" * 200
    mirror(snapshot, target, good)
    target.write_bytes(b"\x00" * len(good))

    ledger = RecordingLedger(known=None)
    result = manager(ledger, snapshot).recover("snap", [str(target)], verify_integrity=True)
    return result, ledger


def run_mismatched_hash(tmp_path) -> tuple[dict, RecordingLedger]:
    """The ledger's hash and the snapshot's bytes disagree.

    Either the snapshot is not the file the ledger saw, or the ledger entry is
    not this file's. The system cannot tell which and must not pick one.
    """
    snapshot, target = workspace(tmp_path, "mismatched_hash")
    mirror(snapshot, target, b"a different revision of the same document\n" * 200)
    target.write_bytes(b"\x00" * 4096)

    ledger = RecordingLedger(
        known={"file_hash": sha256_bytes(b"the hash of some other content"), "block_id": 41}
    )
    result = manager(ledger, snapshot).recover("snap", [str(target)], verify_integrity=True)
    return result, ledger


def run_corrupted_snapshot(tmp_path) -> tuple[dict, RecordingLedger]:
    """The snapshot root exists and holds no copy of this path.

    What a truncated or pruned shadow copy looks like. Nothing is restored, and
    the difference from the two above is that here there is no file to verify.
    """
    snapshot, target = workspace(tmp_path, "corrupted_snapshot")
    target.write_bytes(b"\x00" * 4096)

    ledger = RecordingLedger(known={"file_hash": sha256_bytes(b"anything"), "block_id": 7})
    result = manager(ledger, snapshot).recover("snap", [str(target)], verify_integrity=True)
    return result, ledger


INJECTIONS = {
    "missing_baseline": run_missing_baseline,
    "mismatched_restore_hash": run_mismatched_hash,
    "corrupted_snapshot": run_corrupted_snapshot,
}


@pytest.fixture(scope="function")
def outcomes(tmp_path):
    return {name: run(tmp_path) for name, run in INJECTIONS.items()}


# --------------------------------------------------------------------- the row


@pytest.mark.parametrize("name", sorted(INJECTIONS))
def test_tc24_no_injection_is_reported_as_verified(name, tmp_path):
    """The half of the row that a recovery claim depends on."""
    result, _ledger = INJECTIONS[name](tmp_path)
    file_result = result["files"][0]

    assert file_result["integrity_verified"] is not True, file_result
    assert result["status"] != "success", result["status"]
    assert file_result["reason"], "an unverified restore with no reason is unactionable"


def test_tc24_the_three_outcomes_are_distinct(outcomes):
    """The other half. Same shape for all three would be no answer at all."""
    signatures = {}
    for name, (result, _ledger) in outcomes.items():
        file_result = result["files"][0]
        signatures[name] = (
            file_result["restored"],
            file_result["integrity_verified"],
            result["status"],
            file_result["reason"],
        )

    assert len(set(signatures.values())) == 3, signatures


def test_tc24_a_missing_baseline_restores_but_does_not_verify(tmp_path):
    """Restored true, verified false. The two are not the same claim.

    Collapsing them is the defect: a caller told "not restored" would go looking
    for a backup that is in fact already on disk.
    """
    result, ledger = run_missing_baseline(tmp_path)
    file_result = result["files"][0]

    assert file_result["restored"] is True
    assert file_result["integrity_verified"] is False
    assert file_result["expected_hash"] is None, "there was no baseline to expect"
    assert result["status"] == "partial"
    assert "no prior hash" in file_result["reason"].lower()
    assert "recovery_completed" in ledger.types()


def test_tc24_a_mismatched_hash_names_both_sides(tmp_path):
    """Restored, not verified, and the record says what disagreed with what."""
    result, ledger = run_mismatched_hash(tmp_path)
    file_result = result["files"][0]

    assert file_result["restored"] is True
    assert file_result["integrity_verified"] is False
    assert file_result["expected_hash"], "the ledger's hash is gone from the record"
    assert file_result["restored_hash"], "the restored hash is gone from the record"
    assert file_result["expected_hash"] != file_result["restored_hash"]
    assert result["status"] == "partial"
    assert "does not match" in file_result["reason"]
    assert "recovery_completed" in ledger.types()


def test_tc24_a_corrupted_snapshot_restores_nothing_and_says_so(tmp_path):
    """The third outcome: not restored at all, which is not "partial"."""
    result, ledger = run_corrupted_snapshot(tmp_path)
    file_result = result["files"][0]

    assert file_result["restored"] is False
    assert file_result["integrity_verified"] is False
    assert file_result["restored_hash"] is None
    assert result["status"] == "failed"
    assert "not present in the snapshot" in file_result["reason"]
    assert "recovery_failed" in ledger.types()


def test_tc24_a_good_restore_still_verifies(tmp_path):
    """The control, without which the three rows above are met by never verifying.

    A snapshot whose bytes match the ledger's recorded hash must come back
    verified, or the recovery path is not a recovery path.
    """
    snapshot, target = workspace(tmp_path, "good")
    good = b"quarterly figures, unencrypted\n" * 200
    mirror(snapshot, target, good)
    target.write_bytes(b"\x00" * len(good))

    ledger = RecordingLedger(known={"file_hash": sha256_bytes(good), "block_id": 12})
    result = manager(ledger, snapshot).recover("snap", [str(target)], verify_integrity=True)
    file_result = result["files"][0]

    assert file_result["restored"] is True
    assert file_result["integrity_verified"] is True
    assert result["status"] == "success"
    assert target.read_bytes() == good


def test_tc24_the_recorded_run_agrees_with_this_one():
    """Cross-check against the artefact, if it is present.

    `scripts/failure_injection.py` runs these three plus ledger tampering and
    response isolation, and records that all five signatures are distinct and
    none claims verification. If that file ever disagrees with these tests, one
    of the two was not re-run.
    """
    report = REPO_ROOT / "reports" / "failure_injection.json"
    if not report.exists():
        pytest.skip("reports/failure_injection.json is absent")

    checks = json.loads(report.read_text(encoding="utf-8"))["checks"]
    assert checks["all_five_ran"] is True
    assert checks["outcomes_are_distinct"] is True
    assert checks["none_reported_as_verified"] is True
    assert checks["every_outcome_is_explained"] is True
    assert checks["meets_section_9_4_2"] is True
