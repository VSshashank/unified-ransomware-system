"""TC-04 / TC-05 demo against running services.

Drives the real ledger (8003) and response (8004) services over HTTP and writes
a before/after transcript to reports/si_demo_evidence.txt for the demo chapter.

    python scripts/si_demo.py --db data/ledger/ledger.db

Start the services first - see README-SI.md. The --db path is only needed for
the TC-05 step, which edits the SQLite file directly to simulate an attacker
with disk access.
"""

import argparse
import hashlib
import json
import math
import os
import shutil
import sqlite3
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import httpx

REPO_ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_PATH = REPO_ROOT / "reports" / "si_demo_evidence.txt"

transcript = []


def say(line: str = "") -> None:
    print(line)
    transcript.append(line)


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    return -sum((c / len(data)) * math.log2(c / len(data)) for c in counts.values())


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ledger", default="http://localhost:8003")
    parser.add_argument("--response", default="http://localhost:8004")
    parser.add_argument("--db", default=str(REPO_ROOT / "data" / "ledger" / "ledger.db"))
    parser.add_argument("--snapshot-root", default=str(REPO_ROOT / "data" / "snapshots"))
    parser.add_argument("--workspace", default=str(REPO_ROOT / "data" / "si_demo"))
    args = parser.parse_args()

    client = httpx.Client(timeout=10.0)
    snapshot_id = "snap_demo"
    workspace = Path(args.workspace)
    snapshot_dir = Path(args.snapshot_root) / snapshot_id

    if workspace.exists():
        shutil.rmtree(workspace)
    if snapshot_dir.exists():
        shutil.rmtree(snapshot_dir)
    workspace.mkdir(parents=True)

    document = workspace / "thesis.doc"

    say("=" * 72)
    say(f"SI demo - TC-04 file recovery, TC-05 tamper detection")
    say(f"run at {datetime.now(timezone.utc).isoformat()}")
    say("=" * 72)

    for name, url in (("ledger", args.ledger), ("response", args.response)):
        health = client.get(f"{url}/health").json()
        say(f"[health] {name:9} {health.get('status')}")
    say()

    # --- 1. clean file, hashed into the ledger --------------------------------
    original = b"Chapter 1. The original, uncorrupted thesis.\n" * 128
    document.write_bytes(original)
    clean_hash = sha256_file(document)
    clean_entropy = shannon_entropy(original)

    say("--- BEFORE THE ATTACK " + "-" * 50)
    say(f"  path            {document}")
    say(f"  size            {document.stat().st_size} bytes")
    say(f"  sha256          {clean_hash}")
    say(f"  entropy         {clean_entropy:.3f}  (low - readable text)")
    say(f"  first 48 bytes  {original[:48]!r}")

    baseline = client.post(
        f"{args.ledger}/ledger/log",
        json={
            "event_type": "file_baseline",
            "event_data": {
                "file_path": str(document),
                "file_hash": clean_hash,
                "entropy": round(clean_entropy, 3),
            },
        },
    ).json()
    say(f"  ledger block    #{baseline['block_id']} file_baseline  hash={baseline['current_hash'][:16]}...")

    # --- 2. snapshot ----------------------------------------------------------
    snapshot_target = snapshot_dir / Path(os.path.splitdrive(str(document))[1].lstrip("\\/"))
    snapshot_target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(document, snapshot_target)
    snap_block = client.post(
        f"{args.ledger}/ledger/log",
        json={
            "event_type": "snapshot_created",
            "event_data": {"snapshot_id": snapshot_id, "volume": str(workspace)},
        },
    ).json()
    say(f"  snapshot        {snapshot_id} taken (ledger block #{snap_block['block_id']})")
    say()

    # --- 3. the attack --------------------------------------------------------
    encrypted = os.urandom(5760)
    document.write_bytes(encrypted)
    encrypted_entropy = shannon_entropy(encrypted)

    say("--- AFTER THE ATTACK " + "-" * 51)
    say(f"  sha256          {sha256_file(document)}")
    say(f"  entropy         {encrypted_entropy:.3f}  (high - encrypted)")
    say(f"  first 48 bytes  {document.read_bytes()[:48]!r}")

    attack_block = client.post(
        f"{args.ledger}/ledger/log",
        json={
            "event_type": "file_encrypted",
            "event_data": {
                "file_path": str(document),
                "process_id": 6666,
                "user": "admin",
                "entropy": round(encrypted_entropy, 3),
            },
        },
    ).json()
    say(f"  ledger block    #{attack_block['block_id']} file_encrypted")
    say()

    # --- 4. TC-04 recovery ----------------------------------------------------
    say("--- TC-04 RECOVERY " + "-" * 53)
    recover = client.post(
        f"{args.response}/response/recover",
        json={"snapshot_id": snapshot_id, "files": [str(document)], "verify_integrity": True},
    )
    result = recover.json()
    say(f"  POST /response/recover -> HTTP {recover.status_code}")
    say(json.dumps(result, indent=2))

    restored_hash = sha256_file(document)
    restored_entropy = shannon_entropy(document.read_bytes())
    say(f"  sha256          {restored_hash}")
    say(f"  entropy         {restored_entropy:.3f}")
    say(f"  first 48 bytes  {document.read_bytes()[:48]!r}")

    tc04 = (
        result.get("status") == "success"
        and result.get("integrity_verified") is True
        and restored_hash == clean_hash
    )
    say(f"  matches pre-attack hash: {restored_hash == clean_hash}")
    say(f"  TC-04: {'PASS' if tc04 else 'FAIL'}")
    say()

    # --- 5. chain still intact ------------------------------------------------
    verify = client.get(f"{args.ledger}/ledger/verify").json()
    say("--- CHAIN AFTER RECOVERY " + "-" * 47)
    say(f"  {json.dumps(verify)}")
    chain_ok = verify["valid"] is True and verify["verification_time_ms"] < 50
    say(f"  valid and under 50ms: {'PASS' if chain_ok else 'FAIL'}")
    say()

    # --- 6. TC-05 tampering ---------------------------------------------------
    say("--- TC-05 TAMPERING " + "-" * 52)
    db_path = Path(args.db)
    if not db_path.exists():
        say(f"  SKIPPED - ledger database not found at {db_path}")
        say("  (pass --db pointing at the running service's SQLite file)")
        tc05 = None
    else:
        say(f"  attacker edits block #{attack_block['block_id']} to hide the encryption")
        conn = sqlite3.connect(str(db_path))

        # Keep the real row so the edit can be undone. Without this the demo
        # leaves the chain permanently broken: the next run trips over *this*
        # run's tamper before reaching its own, and reports a false failure for
        # every check downstream of it.
        original = conn.execute(
            "SELECT event_data FROM blocks WHERE id = ?", (attack_block["block_id"],)
        ).fetchone()[0]

        try:
            conn.execute(
                "UPDATE blocks SET event_data = ? WHERE id = ?",
                (
                    json.dumps(
                        {"entropy": 1.1, "file_path": str(document), "process_id": 4, "user": "admin"},
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                    attack_block["block_id"],
                ),
            )
            conn.commit()

            tampered = client.get(f"{args.ledger}/ledger/verify").json()
            say(f"  {json.dumps(tampered)}")
            tc05 = tampered["valid"] is False and tampered["invalid_block_id"] == attack_block["block_id"]
            say(f"  detected at the right block: {tc05}")
            say(f"  TC-05: {'PASS' if tc05 else 'FAIL'}")
        finally:
            # Restore even if the assertion above raised - a half-finished demo
            # must not be the thing that corrupts the audit log.
            conn.execute(
                "UPDATE blocks SET event_data = ? WHERE id = ?", (original, attack_block["block_id"])
            )
            conn.commit()
            conn.close()

        restored_chain = client.get(f"{args.ledger}/ledger/verify").json()
        say(f"  chain restored after the test: {restored_chain['valid']}")
    say()

    say("=" * 72)
    say(f"TC-04 file recovery + integrity : {'PASS' if tc04 else 'FAIL'}")
    say(f"TC-05 tamper detection          : {'PASS' if tc05 else ('SKIPPED' if tc05 is None else 'FAIL')}")
    say("=" * 72)

    EVIDENCE_PATH.parent.mkdir(parents=True, exist_ok=True)
    EVIDENCE_PATH.write_text("\n".join(transcript), encoding="utf-8")
    print(f"\nEvidence written to {EVIDENCE_PATH}")

    return 0 if (tc04 and chain_ok and tc05 is not False) else 1


if __name__ == "__main__":
    sys.exit(main())
