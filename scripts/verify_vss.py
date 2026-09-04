"""Phase 3 acceptance check - real Windows VSS snapshot.

This one cannot run in CI or in the container: it needs Windows, pywin32, and an
elevated shell, and it creates an actual shadow copy on the machine.

    # from an Administrator PowerShell, with the ledger running:
    pip install pywin32
    python scripts/verify_vss.py --volume C:\\

Checks:
  1. the host reports VSS as supported
  2. a snapshot is created in under 30 seconds (Table 5.9)
  3. the new snapshot shows up in list_snapshots()
  4. a snapshot_created block reaches the ledger

Nothing here deletes shadow copies. Remove the snapshot yourself afterwards if
you want to (Disk Cleanup, or `vssadmin delete shadows /shadow=<id>` elevated).

`--status-only` runs without elevation and records what the host actually says:
the platform status, and the exact refusal each operation returns. It does not
pass the acceptance check and does not pretend to. It exists so
`NOVELTY_PROOF_PLAN.md` §9 row 12 can cite a measured blocker rather than the
sentence "not measured", which does not distinguish "we could not" from "we did
not try".

    .venv\\Scripts\\python.exe scripts/verify_vss.py --status-only

Writes reports/vss_status.json only when URDS_WRITE_REPORTS=1.
"""

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
REPORTS = REPO_ROOT / "reports"
sys.path.insert(0, str(REPO_ROOT / "services" / "response"))

from recovery.ledger_client import LedgerClient  # noqa: E402
from recovery.vss_manager import VSSError, VSSManager  # noqa: E402

SNAPSHOT_TARGET_SECONDS = 30


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=REPO_ROOT, capture_output=True, text=True, check=False
    ).stdout.strip()


def attempt(label: str, call) -> dict:
    """Run one VSS operation and record what came back, success or refusal."""
    started = time.perf_counter()
    try:
        value = call()
        return {
            "operation": label,
            "succeeded": True,
            "elapsed_s": round(time.perf_counter() - started, 3),
            "result": value if isinstance(value, (str, int)) else len(value),
        }
    except Exception as exc:  # the refusal is the measurement
        return {
            "operation": label,
            "succeeded": False,
            "elapsed_s": round(time.perf_counter() - started, 3),
            "error_type": type(exc).__name__,
            "error": str(exc),
        }


def status_only(manager: VSSManager, volume: str) -> int:
    status = manager.platform_status()
    attempts = [
        attempt("list_snapshots", manager.list_snapshots),
        attempt("create_snapshot", lambda: manager.create_snapshot(volume)),
    ]

    report = {
        "schema": "urds.vss_status/1",
        "generated_at": utc_now(),
        "commit": git("rev-parse", "HEAD"),
        "branch": git("rev-parse", "--abbrev-ref", "HEAD"),
        "acceptance_row": (
            "NOVELTY_PROOF_PLAN.md §9 row 12 - recovery preservation, "
            "snapshot-backed restoration"
        ),
        "platform_status": status,
        "attempts": attempts,
        "acceptance_check_run": False,
        "blocker": (
            "elevation"
            if status.get("supported") and not status.get("elevated")
            else ("unsupported platform" if not status.get("supported") else None)
        ),
        "what_this_does_not_show": (
            "Whether a VSS-backed restore verifies. Nothing here creates a "
            "snapshot or restores from one. What it records is that the host "
            "reports VSS as supported and that both operations refuse for one "
            "stated reason, so the gap in row 12 is a shell privilege and not an "
            "unmeasured capability."
        ),
    }

    print("=" * 68)
    print("VSS status only - this is NOT the acceptance check")
    print("=" * 68)
    for key, value in status.items():
        print(f"  {key:12} {value}")
    print()
    for record in attempts:
        if record["succeeded"]:
            print(f"  {record['operation']:18} ok ({record['result']})")
        else:
            print(f"  {record['operation']:18} {record['error_type']}: {record['error']}")
    print()
    print(f"blocker: {report['blocker']}")

    if os.getenv("URDS_WRITE_REPORTS", "").lower() not in {"1", "true", "yes"}:
        print("\nURDS_WRITE_REPORTS is not set: report not written")
        return 0
    REPORTS.mkdir(exist_ok=True)
    (REPORTS / "vss_status.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nwrote {REPORTS / 'vss_status.json'}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--volume", default="C:\\")
    parser.add_argument("--ledger", default="http://localhost:8003")
    parser.add_argument(
        "--status-only",
        action="store_true",
        help="record the host's VSS status and each operation's refusal; creates nothing",
    )
    args = parser.parse_args()

    ledger = LedgerClient(base_url=args.ledger)
    manager = VSSManager(ledger_client=ledger, default_volume=args.volume)

    if args.status_only:
        return status_only(manager, args.volume)

    print("=" * 68)
    print("Phase 3 acceptance - Windows VSS")
    print("=" * 68)

    status = manager.platform_status()
    for key, value in status.items():
        print(f"  {key:12} {value}")

    if not status["supported"]:
        print("\nFAIL: VSS is not available here.")
        print(f"      {status['reason']}")
        return 1
    if not status.get("elevated"):
        print("\nFAIL: not elevated. Re-run from an Administrator shell.")
        return 1

    print(f"\nCreating a shadow copy of {args.volume} ...")
    started = time.perf_counter()
    try:
        snapshot_id = manager.create_snapshot(args.volume)
    except VSSError as exc:
        print(f"FAIL: {exc}")
        return 1
    elapsed = time.perf_counter() - started

    print(f"  snapshot id     {snapshot_id}")
    print(f"  creation time   {elapsed:.1f}s (target <{SNAPSHOT_TARGET_SECONDS}s)")
    creation_ok = elapsed < SNAPSHOT_TARGET_SECONDS

    snapshots = manager.list_snapshots()
    listed = any(s["snapshot_id"].upper() == snapshot_id.upper() for s in snapshots)
    print(f"  total snapshots {len(snapshots)}")
    print(f"  new one listed  {listed}")

    logged = False
    try:
        blocks = ledger._request(
            "GET", "/ledger/blocks", params={"event_type": "snapshot_created", "newest_first": True, "limit": 10}
        )["blocks"]
        logged = any(b["event_data"].get("snapshot_id", "").upper() == snapshot_id.upper() for b in blocks)
        print(f"  in the ledger   {logged}")
    except Exception as exc:
        print(f"  in the ledger   could not check ({exc})")

    print("\n" + "=" * 68)
    for label, passed in (
        (f"creation under {SNAPSHOT_TARGET_SECONDS}s", creation_ok),
        ("snapshot listed", listed),
        ("logged to ledger", logged),
    ):
        print(f"{label:32} {'PASS' if passed else 'FAIL'}")
    print("=" * 68)

    return 0 if (creation_ok and listed and logged) else 1


if __name__ == "__main__":
    sys.exit(main())
