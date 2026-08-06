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
"""

import argparse
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "services" / "response"))

from recovery.ledger_client import LedgerClient  # noqa: E402
from recovery.vss_manager import VSSError, VSSManager  # noqa: E402

SNAPSHOT_TARGET_SECONDS = 30


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--volume", default="C:\\")
    parser.add_argument("--ledger", default="http://localhost:8003")
    args = parser.parse_args()

    ledger = LedgerClient(base_url=args.ledger)
    manager = VSSManager(ledger_client=ledger, default_volume=args.volume)

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
