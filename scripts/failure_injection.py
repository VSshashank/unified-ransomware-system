"""Five injected failures, five distinct recorded outcomes - SI.

Item P6.5, Chapter 9 §9.4.2 and the artefact register §9.8. Writes
reports/failure_injection.json.

§9.4.2 names the five: *missing baseline, mismatched restore hash, corrupted
snapshot, ledger tampering, response isolation - each producing a distinct,
recorded outcome; none reported as verified.*

The last clause is the whole point. A recovery system that answers "restored"
to every request is worse than one that fails loudly, because the operator
stops checking. Each injection below is run against the real component - the
real `RecoveryManager`, the real `HashChainLedger`, the real `isolate_host` -
and the harness records what came back rather than what should have.

Three properties are then checked over the five results:

  distinct       no two injections produce the same recorded outcome. If two do,
                 an operator cannot tell them apart from the record, which is
                 the same as not recording them.
  not verified   no injection comes back claiming integrity was verified or
                 isolation enforced.
  explained      every one carries a reason naming what went wrong.

    .venv\\Scripts\\python.exe scripts/failure_injection.py

Writes the report only when URDS_WRITE_REPORTS=1.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
REPORTS = REPO_ROOT / "reports"

sys.path.insert(0, str(REPO_ROOT / "services" / "ledger"))
sys.path.insert(0, str(REPO_ROOT / "services" / "response"))


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=REPO_ROOT, capture_output=True, text=True, check=False
    ).stdout.strip()


def sha256_bytes(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


class RecordingLedger:
    """A ledger client that answers a controlled hash and records what it is told.

    Only the transport is stood in for. `RecoveryManager`'s own logic - what it
    restores, what it compares, what it writes - is the real thing.
    """

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


def _scenario_root(tmp: Path, name: str) -> tuple[Path, Path, Path]:
    """A workspace, a snapshot directory, and the file to be restored."""
    root = tmp / name
    snapshot = root / "snap"
    snapshot.mkdir(parents=True)
    target = root / "quarterly.docx"
    return root, snapshot, target


def _manager(ledger: RecordingLedger, snapshot: Path):
    from recovery.recovery import RecoveryManager

    manager = RecoveryManager(ledger_client=ledger)
    manager.resolve_snapshot_root = lambda snapshot_id: str(snapshot)
    return manager


def _mirror(snapshot: Path, target: Path, blob: bytes) -> Path:
    """Put `blob` where the manager will look for `target`'s snapshot copy."""
    mirrored = snapshot / target.relative_to(target.anchor)
    mirrored.parent.mkdir(parents=True, exist_ok=True)
    mirrored.write_bytes(blob)
    return mirrored


# ------------------------------------------------------------------ injections


def inject_missing_baseline(tmp: Path) -> dict:
    """Nothing in the ledger has ever recorded this path.

    The file restores. What cannot happen is a claim that it restored
    *correctly*, because there is nothing to compare it against.
    """
    _root, snapshot, target = _scenario_root(tmp, "missing_baseline")
    good = b"quarterly figures, unencrypted\n" * 200
    _mirror(snapshot, target, good)
    target.write_bytes(b"\x00" * len(good))

    ledger = RecordingLedger(known=None)
    result = _manager(ledger, snapshot).recover("snap", [str(target)], verify_integrity=True)
    file_result = result["files"][0]
    return {
        "injection": "missing_baseline",
        "what_was_broken": "the ledger holds no prior hash for this path",
        "restored": file_result["restored"],
        "integrity_verified": file_result["integrity_verified"],
        "expected_hash": file_result["expected_hash"],
        "reason": file_result["reason"],
        "overall_status": result["status"],
        "ledger_events": ledger.types(),
    }


def inject_mismatched_restore_hash(tmp: Path) -> dict:
    """The ledger's hash and the snapshot's bytes disagree.

    Either the snapshot is not the file the ledger saw or the ledger entry is
    not this file's. The system cannot tell which, and must not pick one.
    """
    _root, snapshot, target = _scenario_root(tmp, "mismatched_hash")
    snapshot_bytes = b"a different revision of the same document\n" * 200
    _mirror(snapshot, target, snapshot_bytes)
    target.write_bytes(b"\x00" * 4096)

    ledger = RecordingLedger(
        known={"file_hash": sha256_bytes(b"the hash of some other content"), "block_id": 41}
    )
    result = _manager(ledger, snapshot).recover("snap", [str(target)], verify_integrity=True)
    file_result = result["files"][0]
    return {
        "injection": "mismatched_restore_hash",
        "what_was_broken": "the ledger's recorded hash does not match the restored bytes",
        "restored": file_result["restored"],
        "integrity_verified": file_result["integrity_verified"],
        "expected_hash": file_result["expected_hash"],
        "restored_hash": file_result["restored_hash"],
        "reason": file_result["reason"],
        "overall_status": result["status"],
        "ledger_events": ledger.types(),
    }


def inject_corrupted_snapshot(tmp: Path) -> dict:
    """The snapshot copy is not there to restore from."""
    _root, snapshot, target = _scenario_root(tmp, "corrupted_snapshot")
    target.write_bytes(b"\x00" * 4096)
    # Deliberately no mirrored copy: the snapshot root exists and the file in it
    # does not, which is what a truncated or pruned shadow copy looks like.

    ledger = RecordingLedger(known={"file_hash": sha256_bytes(b"anything"), "block_id": 7})
    result = _manager(ledger, snapshot).recover("snap", [str(target)], verify_integrity=True)
    file_result = result["files"][0]
    return {
        "injection": "corrupted_snapshot",
        "what_was_broken": "the snapshot holds no copy of this path",
        "restored": file_result["restored"],
        "integrity_verified": file_result["integrity_verified"],
        "restored_hash": file_result["restored_hash"],
        "reason": file_result["reason"],
        "overall_status": result["status"],
        "ledger_events": ledger.types(),
    }


def inject_ledger_tampering(tmp: Path) -> dict:  # noqa: C901
    """A block is rewritten in the database, behind the ledger's back.

    Written through SQL rather than through the API, because the API is what a
    tamper-detection claim has to hold up against someone who has stopped using
    it. The read-back uses a *fresh* connection, so the verdict cannot come from
    a cached row the writer still holds.
    """
    from hash_chain import HashChainLedger

    db = tmp / "tamper.db"
    ledger = HashChainLedger(db_path=str(db))
    ledger.create_tables()
    for index in range(6):
        ledger.add_block("file_event", {"file_path": f"/data/file_{index}.docx", "entropy": 3.1})
    before = ledger.verify_chain()
    ledger.close()

    connection = sqlite3.connect(str(db))
    connection.execute(
        "UPDATE blocks SET event_data = ? WHERE id = ?",
        (json.dumps({"file_path": "/data/file_3.docx", "entropy": 0.0}), 4),
    )
    connection.commit()
    connection.close()

    reopened = HashChainLedger(db_path=str(db))
    after = reopened.verify_chain()
    reopened.close()

    return {
        "injection": "ledger_tampering",
        "what_was_broken": "block 4's event_data rewritten directly in sqlite",
        "blocks": 6,
        "valid_before": before.get("valid"),
        "valid_after": after.get("valid"),
        "detected": bool(before.get("valid")) and not after.get("valid"),
        "verification_before": before,
        "verification_after": after,
        "invalid_block_id": after.get("invalid_block_id"),
        "blocks_checked": after.get("blocks_checked"),
        # The reason names the block the walk stopped at. "verification failed"
        # on its own tells an operator nothing they can act on; the block id is
        # what they take to the audit.
        "reason": (
            f"hash chain broken at block {after.get('invalid_block_id')}: the "
            "recomputed hash does not match the stored one. The walk stopped "
            f"there, having checked {after.get('blocks_checked')} of 6 blocks - "
            "verify_chain reports how far it got rather than certifying a short "
            "walk (inventory row D-01)"
            if after.get("invalid_block_id") is not None
            else "chain verified as intact, which is the wrong answer here"
        ),
        "read_with_a_fresh_connection": True,
    }


def inject_response_isolation(_tmp: Path) -> dict:
    """Ask for isolation on a host where it is not switched on.

    RESPONSE_ISOLATION_ENABLED is unset here, which is the default. The only
    acceptable answer is that nothing was enforced, with the rules that *would*
    have been applied attached - reporting a block that did not happen is the
    failure this injection exists to catch.
    """
    from actions import isolate_host

    outcome = isolate_host(level="full", duration_seconds=300, allow_localhost=True)
    return {
        "injection": "response_isolation",
        "what_was_broken": "isolation requested on a host where it is not enabled",
        "status": outcome.get("status"),
        "enforced": outcome.get("enforced"),
        "backend": outcome.get("backend"),
        "backend_supported": outcome.get("backend_supported"),
        "reason": outcome.get("reason"),
        "planned_rules": outcome.get("planned_rules"),
        "rules_actually_applied": outcome.get("applied_rules", []),
    }


INJECTIONS = (
    inject_missing_baseline,
    inject_mismatched_restore_hash,
    inject_corrupted_snapshot,
    inject_ledger_tampering,
    inject_response_isolation,
)


# --------------------------------------------------------------------- checks


def claims_verified(result: dict) -> bool:
    """Did anything come back asserting a guarantee it cannot support?"""
    if result.get("integrity_verified"):
        return True
    if result.get("enforced"):
        return True
    # The tamper injection is the one where a *true* here is the honest answer -
    # it is reporting that verification failed, not that anything was verified.
    if result["injection"] == "ledger_tampering" and result.get("valid_after"):
        return True
    return False


def signature(result: dict) -> str:
    """What an operator reading the record would take away from it.

    Two injections with the same signature are two failures an operator cannot
    tell apart, which is what "distinct" in §9.4.2 is asking about.
    """
    return "|".join(
        str(result.get(field))
        for field in (
            "restored",
            "integrity_verified",
            "overall_status",
            "status",
            "enforced",
            "detected",
            "reason",
        )
    )


def main() -> int:
    # ignore_cleanup_errors: sqlite on Windows can hold the database file a
    # moment past close(), and a cleanup failure must not discard five
    # measurements that already succeeded.
    with tempfile.TemporaryDirectory(
        prefix="failure_injection_", ignore_cleanup_errors=True
    ) as tmp:
        results = [injection(Path(tmp)) for injection in INJECTIONS]

    signatures = {r["injection"]: signature(r) for r in results}
    duplicates = [
        (a, b)
        for i, a in enumerate(signatures)
        for b in list(signatures)[i + 1 :]
        if signatures[a] == signatures[b]
    ]
    verified = [r["injection"] for r in results if claims_verified(r)]
    unexplained = [r["injection"] for r in results if not r.get("reason")]

    checks = {
        "all_five_ran": len(results) == 5,
        "outcomes_are_distinct": not duplicates,
        "duplicate_pairs": duplicates,
        "none_reported_as_verified": not verified,
        "wrongly_reported_as_verified": verified,
        "every_outcome_is_explained": not unexplained,
        "unexplained": unexplained,
    }
    checks["meets_section_9_4_2"] = (
        checks["all_five_ran"]
        and checks["outcomes_are_distinct"]
        and checks["none_reported_as_verified"]
        and checks["every_outcome_is_explained"]
    )

    report = {
        "schema": "urds.failure_injection/1",
        "generated_at": utc_now(),
        "commit": git("rev-parse", "HEAD"),
        "branch": git("rev-parse", "--abbrev-ref", "HEAD"),
        "requirement": (
            "Chapter 9 §9.4.2: missing baseline, mismatched restore hash, "
            "corrupted snapshot, ledger tampering, response isolation - each "
            "producing a distinct, recorded outcome; none reported as verified."
        ),
        "method": (
            "Each injection is run against the real component: the real "
            "RecoveryManager, the real HashChainLedger, the real isolate_host. "
            "Only the ledger transport is stood in for, and it records rather "
            "than answers. The tamper is written through SQL, not the API."
        ),
        "injections": results,
        "signatures": signatures,
        "checks": checks,
    }

    for result in results:
        print(f"\n{result['injection']}")
        print(f"  broke   : {result['what_was_broken']}")
        for field in (
            "restored", "integrity_verified", "overall_status",
            "status", "enforced", "detected", "valid_before", "valid_after",
        ):
            if field in result:
                print(f"  {field:16}: {result[field]}")
        print(f"  reason  : {str(result.get('reason'))[:110]}")

    print("\nCHECKS")
    for name in (
        "all_five_ran",
        "outcomes_are_distinct",
        "none_reported_as_verified",
        "every_outcome_is_explained",
        "meets_section_9_4_2",
    ):
        print(f"  {'PASS' if checks[name] else 'FAIL'}  {name}")
    if duplicates:
        print(f"  duplicate pairs: {duplicates}")
    if verified:
        print(f"  wrongly verified: {verified}")

    if os.getenv("URDS_WRITE_REPORTS", "").lower() not in {"1", "true", "yes"}:
        print("\nURDS_WRITE_REPORTS is not set: report not written")
        return 0

    REPORTS.mkdir(exist_ok=True)
    path = REPORTS / "failure_injection.json"
    path.write_text(json.dumps(report, indent=2, default=str))
    print(f"\nwrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
