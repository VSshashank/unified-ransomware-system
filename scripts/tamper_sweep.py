"""Every tamper shape, at every position, against the real chain - SI + SH.

Item P7.3, Chapter 9 §9.4.2 and the Phase 7 exit gate:

    injected ledger-tamper cases must fail verification 100% of the time

`scripts/failure_injection.py` injects one tamper and detects it. One case does
not support a claim with "100%" in it, and it does not distinguish the tampers a
hash chain catches from the ones it cannot - which is the part of this that
matters, because the answer is not "all of them".

The sweep is every shape crossed with every position:

    shapes      the five columns a row has, deleted rows, swapped rows, an
                appended forgery, a truncated tail, and a re-chained suffix
    positions   first block, a middle block, last block

Each case gets a freshly built chain, is tampered **through SQL** rather than
through the API - the API is what a tamper claim has to hold up against someone
who has stopped using it - and is then verified by a new `HashChainLedger`
opened on the file, so no cached connection can answer from a snapshot taken
before the edit.

Two classes of result, and they are reported separately because collapsing them
would be the dishonest part:

    in_place    an edit that leaves the chain's shape alone. Every one of these
                must be detected, and this is the population the 100% claim is
                about.
    structural  an edit that rebuilds the chain to be self-consistent - an
                appended block, a truncated tail, a re-chained suffix. An
                unkeyed SHA-256 chain with no external anchor **cannot** detect
                these, because the attacker can recompute every hash the
                verifier will recompute. Measured rather than argued, and
                reported as the limit it is. Anchoring is what closes it, and
                Chapter 9 §9.13 places anchoring outside this project's scope.

    .venv\\Scripts\\python.exe scripts/tamper_sweep.py

Writes reports/tamper_sweep.json only when URDS_WRITE_REPORTS=1.
"""

from __future__ import annotations

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

from hash_chain import HashChainLedger  # noqa: E402

CHAIN_LENGTH = 40


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=REPO_ROOT, capture_output=True, text=True, check=False
    ).stdout.strip()


def build_chain(db_path: Path, length: int = CHAIN_LENGTH) -> dict:
    """A chain of realistic blocks, closed before anything touches the file."""
    ledger = HashChainLedger(db_path=str(db_path))
    try:
        for index in range(length):
            ledger.add_block(
                "file_event",
                {
                    "file_path": f"C:/data/report_{index}.docx",
                    "verdict": "suspected_encryption" if index % 3 == 0 else "benign",
                    "entropy": 7.99 if index % 3 == 0 else 4.2,
                    "signal": "static_entropy" if index % 3 == 0 else None,
                },
            )
        before = ledger.verify_chain()
    finally:
        ledger.close()
    return before


def verify(db_path: Path) -> dict:
    """Verify from a fresh instance, so nothing answers from its own cache."""
    ledger = HashChainLedger(db_path=str(db_path))
    try:
        return ledger.verify_chain()
    finally:
        ledger.close()


def sql(db_path: Path, statement: str, params: tuple = ()) -> None:
    connection = sqlite3.connect(str(db_path))
    try:
        connection.execute(statement, params)
        connection.commit()
    finally:
        connection.close()


def rows(db_path: Path) -> list[sqlite3.Row]:
    connection = sqlite3.connect(str(db_path))
    connection.row_factory = sqlite3.Row
    try:
        return connection.execute("SELECT * FROM blocks ORDER BY id ASC").fetchall()
    finally:
        connection.close()


# --------------------------------------------------------------------- shapes
#
# Each takes the database and the id of the block to attack, and returns a short
# description of what it did. Every one writes through SQL.


def edit_event_data(db_path: Path, block_id: int) -> str:
    sql(
        db_path,
        "UPDATE blocks SET event_data = ? WHERE id = ?",
        ('{"file_path": "C:/data/nothing_happened.docx", "verdict": "benign"}', block_id),
    )
    return "event_data rewritten to a benign-looking payload"


def edit_event_type(db_path: Path, block_id: int) -> str:
    sql(db_path, "UPDATE blocks SET event_type = ? WHERE id = ?", ("file_baseline", block_id))
    return "event_type changed to file_baseline"


def edit_timestamp(db_path: Path, block_id: int) -> str:
    sql(
        db_path,
        "UPDATE blocks SET timestamp = ? WHERE id = ?",
        ("2020-01-01T00:00:00Z", block_id),
    )
    return "timestamp backdated"


def edit_current_hash(db_path: Path, block_id: int) -> str:
    sql(db_path, "UPDATE blocks SET current_hash = ? WHERE id = ?", ("f" * 64, block_id))
    return "current_hash overwritten"


def edit_previous_hash(db_path: Path, block_id: int) -> str:
    # Not "0" * 64. That is GENESIS_HASH (services/ledger/database.py:20), which
    # is what block 1's previous_hash already holds - so writing it there is a
    # no-op and the case reads as an undetected tamper when nothing was tampered.
    # The first run of this sweep did exactly that.
    sql(db_path, "UPDATE blocks SET previous_hash = ? WHERE id = ?", ("d" * 64, block_id))
    return "previous_hash overwritten with a hash of no block"


def delete_block(db_path: Path, block_id: int) -> str:
    sql(db_path, "DELETE FROM blocks WHERE id = ?", (block_id,))
    return "row deleted, leaving a gap in the back-pointers"


def swap_payloads(db_path: Path, block_id: int) -> str:
    """Two blocks trade their event_data. Both hashes now disagree with content."""
    all_rows = rows(db_path)
    other = all_rows[0] if all_rows[0]["id"] != block_id else all_rows[-1]
    target = [r for r in all_rows if r["id"] == block_id][0]
    sql(db_path, "UPDATE blocks SET event_data = ? WHERE id = ?", (other["event_data"], block_id))
    sql(
        db_path,
        "UPDATE blocks SET event_data = ? WHERE id = ?",
        (target["event_data"], other["id"]),
    )
    return f"event_data swapped between blocks {block_id} and {other['id']}"


# ------------------------------------------------------ the structural shapes


def append_forged_block(db_path: Path, _block_id: int) -> str:
    """Append a block the attacker computed the hash for themselves.

    The hash is unkeyed SHA-256 over public inputs, so anyone who can write the
    file can also produce a correct-looking hash. There is no secret in the
    scheme for them not to have.
    """
    tip = rows(db_path)[-1]
    timestamp = "2026-09-05T00:00:00Z"
    event_type = "file_event"
    event_json = '{"file_path": "C:/data/planted.docx", "verdict": "benign"}'
    current = HashChainLedger.compute_hash(
        timestamp, event_type, event_json, tip["current_hash"]
    )
    sql(
        db_path,
        "INSERT INTO blocks (timestamp, event_type, event_data, previous_hash, current_hash)"
        " VALUES (?,?,?,?,?)",
        (timestamp, event_type, event_json, tip["current_hash"], current),
    )
    return "a block appended with a correctly computed hash"


def truncate_tail(db_path: Path, block_id: int) -> str:
    """Delete every block from `block_id` on. What remains is a valid prefix."""
    sql(db_path, "DELETE FROM blocks WHERE id >= ?", (block_id,))
    return f"every block from {block_id} onward deleted"


def rechain_suffix(db_path: Path, block_id: int) -> str:
    """Rewrite one block and recompute every hash after it.

    The strongest tamper available to someone with file access, and the one that
    says what the chain is actually worth: they change what they came to change,
    then walk forward recomputing exactly what the verifier will recompute.
    """
    all_rows = rows(db_path)
    previous = None
    for row in all_rows:
        event_json = row["event_data"]
        if row["id"] == block_id:
            event_json = '{"file_path": "C:/data/nothing_happened.docx", "verdict": "benign"}'
        previous_hash = previous if previous is not None else row["previous_hash"]
        current = HashChainLedger.compute_hash(
            row["timestamp"], row["event_type"], event_json, previous_hash
        )
        sql(
            db_path,
            "UPDATE blocks SET event_data = ?, previous_hash = ?, current_hash = ? WHERE id = ?",
            (event_json, previous_hash, current, row["id"]),
        )
        previous = current
    return f"block {block_id} rewritten and every hash after it recomputed"


IN_PLACE_SHAPES = {
    "edit_event_data": edit_event_data,
    "edit_event_type": edit_event_type,
    "edit_timestamp": edit_timestamp,
    "edit_current_hash": edit_current_hash,
    "edit_previous_hash": edit_previous_hash,
    "delete_block": delete_block,
    "swap_payloads": swap_payloads,
}

STRUCTURAL_SHAPES = {
    "append_forged_block": append_forged_block,
    "truncate_tail": truncate_tail,
    "rechain_suffix": rechain_suffix,
}


def positions(length: int) -> dict[str, int]:
    return {"first": 1, "middle": length // 2, "last": length}


# Deleting a row is two different attacks depending on where the row is, and the
# distinction is a property of the operation rather than of how it turned out.
# Removing an interior row leaves the next block pointing at a hash no row now
# holds, which is a gap the walk finds. Removing the tip leaves a shorter chain
# that is internally perfect - it *is* a truncation, and it belongs with the
# structural cases for the same reason `truncate_tail` does. Classified here,
# before the sweep runs, so the split is not fitted to the result.
STRUCTURAL_BY_POSITION = {("delete_block", "last")}


def classify(shape_name: str, position: str, default: str) -> str:
    if (shape_name, position) in STRUCTURAL_BY_POSITION:
        return "structural"
    return default


# ----------------------------------------------------------------------- sweep


def run_case(tmp: Path, name: str, shape, block_id: int, klass: str, index: int) -> dict:
    db_path = tmp / f"case_{index:03d}.db"
    before = build_chain(db_path)
    assert before["valid"], "the chain was already broken before the tamper"

    what = shape(db_path, block_id)
    after = verify(db_path)

    return {
        "shape": name,
        "class": klass,
        "block_id": block_id,
        "what_was_done": what,
        "valid_before": before["valid"],
        "valid_after": after["valid"],
        "detected": not after["valid"],
        "invalid_block_id": after["invalid_block_id"],
        "blocks_checked": after["blocks_checked"],
        "verification_time_ms": after["verification_time_ms"],
    }


def main() -> int:
    cases: list[dict] = []
    index = 0

    with tempfile.TemporaryDirectory(prefix="tamper_sweep_") as tmp_name:
        tmp = Path(tmp_name)
        where = positions(CHAIN_LENGTH)

        for klass, shapes in (("in_place", IN_PLACE_SHAPES), ("structural", STRUCTURAL_SHAPES)):
            for name, shape in shapes.items():
                for label, block_id in where.items():
                    # Appending has one position by construction: the tip.
                    if name == "append_forged_block" and label != "last":
                        continue
                    index += 1
                    case = run_case(
                        tmp, name, shape, block_id, classify(name, label, klass), index
                    )
                    case["position"] = label
                    cases.append(case)

    in_place = [c for c in cases if c["class"] == "in_place"]
    structural = [c for c in cases if c["class"] == "structural"]
    detected_in_place = [c for c in in_place if c["detected"]]
    detected_structural = [c for c in structural if c["detected"]]

    rate = len(detected_in_place) / len(in_place) if in_place else 0.0

    report = {
        "schema": "urds.tamper_sweep/1",
        "generated_at": utc_now(),
        "commit": git("rev-parse", "HEAD"),
        "branch": git("rev-parse", "--abbrev-ref", "HEAD"),
        "requirement": (
            "Phase 7 P7.3 and Chapter 9 §9.4.2: injected ledger-tamper cases must "
            "fail verification 100% of the time."
        ),
        "method": (
            "Every shape at every position, each against its own freshly built "
            f"{CHAIN_LENGTH}-block chain. Tampering is done through SQL, not the API, "
            "because the API is what a tamper claim has to hold up against someone who "
            "has stopped using it. Verification uses a new HashChainLedger opened on "
            "the file, so no cached connection can answer from a snapshot taken before "
            "the edit."
        ),
        "chain_length": CHAIN_LENGTH,
        "cases": len(cases),
        "in_place": {
            "cases": len(in_place),
            "detected": len(detected_in_place),
            "rate": round(rate, 4),
            "meets_target": len(in_place) > 0 and len(detected_in_place) == len(in_place),
            "missed": [
                {"shape": c["shape"], "position": c["position"]}
                for c in in_place
                if not c["detected"]
            ],
        },
        "structural": {
            "cases": len(structural),
            "detected": len(detected_structural),
            "undetected": [
                {"shape": c["shape"], "position": c["position"], "what": c["what_was_done"]}
                for c in structural
                if not c["detected"]
            ],
        },
        "what_the_chain_cannot_detect": (
            "An unkeyed SHA-256 chain verifies internal consistency and nothing "
            "else. Its inputs are all public, so an attacker who can write the "
            "database file can recompute every hash the verifier will recompute. "
            "Appending a block, truncating the tail - including by deleting the "
            "single newest block - and rewriting a block and re-chaining "
            "everything after it all produce a chain that verifies. "
            "This is a property of the scheme, not a defect in the implementation, "
            "and it is the reason the tamper claim is stated over in-place edits. "
            "Closing it needs something the attacker cannot recompute - a signing "
            "key they do not hold, or an external anchor recording what the tip "
            "was at a time before they arrived. Chapter 9 §9.13 places anchoring "
            "outside this project's scope, so the limit stands and is reported "
            "rather than worked around."
        ),
        "detail": cases,
    }

    print(f"tamper sweep - {len(cases)} cases over {CHAIN_LENGTH}-block chains")
    print(
        f"  in-place    {len(detected_in_place)}/{len(in_place)} detected "
        f"({rate:.1%})  meets_target={report['in_place']['meets_target']}"
    )
    print(f"  structural  {len(detected_structural)}/{len(structural)} detected")
    for case in structural:
        mark = "detected" if case["detected"] else "NOT DETECTED"
        print(f"    {case['shape']:<22} {case['position']:<7} {mark}")
    if report["in_place"]["missed"]:
        print("\n  MISSED in-place cases:")
        for missed in report["in_place"]["missed"]:
            print(f"    {missed['shape']} at {missed['position']}")

    if os.getenv("URDS_WRITE_REPORTS", "").lower() not in {"1", "true", "yes"}:
        print("\nURDS_WRITE_REPORTS is not set: report not written")
        return 0

    REPORTS.mkdir(exist_ok=True)
    (REPORTS / "tamper_sweep.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nwrote {REPORTS / 'tamper_sweep.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
