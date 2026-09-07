"""P7.3: every in-place tamper is detected, and the ones that are not are named.

Phase 7 P7.3 and Chapter 9 §9.4.2 require that *injected ledger-tamper cases
fail verification 100% of the time*. `scripts/tamper_sweep.py` measures that over
28 cases - every shape at every position - and writes
`reports/tamper_sweep.json`. This is the regression form, so the property is
checked on every run rather than only when someone remembers the script.

The sweep splits its cases in two and this file keeps the split, because
collapsing them would turn an honest limit into a false claim:

  **in-place** - an edit that leaves the chain's shape alone: any of the five
  columns rewritten, an interior row deleted, two payloads swapped. Every one of
  these must be detected. That is the 100% claim.

  **structural** - an edit that leaves a chain which is internally perfect:
  appending a block, deleting the newest one, truncating the tail, or rewriting a
  block and recomputing every hash after it. **None of these is detected, and
  none can be.** The hash is unkeyed SHA-256 over public inputs, so an attacker
  who can write the database can recompute exactly what the verifier will
  recompute. It is a property of the scheme, not a defect in this implementation.
  Closing it needs something the attacker cannot reproduce - a signing key, or an
  external anchor recording what the tip was before they arrived - and Chapter 9
  §9.13 places anchoring outside this project's scope.

Asserting the undetected cases is deliberate. They are the boundary of the tamper
claim, and a boundary nobody tests is a boundary nobody notices moving.

Tampering goes through SQL rather than the API, because the API is what a tamper
claim has to hold up against someone who has stopped using it. Verification uses
a fresh `HashChainLedger` on the file, so no cached connection can answer from a
snapshot taken before the edit.
"""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from database import GENESIS_HASH  # noqa: E402
from hash_chain import HashChainLedger  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[3]
CHAIN_LENGTH = 12


@pytest.fixture
def chain(tmp_path) -> Path:
    """A closed chain on disk, verified good before anything touches it."""
    db_path = tmp_path / "ledger.db"
    ledger = HashChainLedger(db_path=str(db_path))
    try:
        for index in range(CHAIN_LENGTH):
            ledger.add_block(
                "file_event",
                {"file_path": f"C:/data/report_{index}.docx", "verdict": "benign"},
            )
        assert ledger.verify_chain()["valid"] is True
    finally:
        ledger.close()
    return db_path


def verify(db_path: Path) -> dict:
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


POSITIONS = {"first": 1, "middle": CHAIN_LENGTH // 2, "last": CHAIN_LENGTH}

# Column edits. `previous_hash` is deliberately not overwritten with "0" * 64:
# that is GENESIS_HASH, which block 1 already holds, so writing it there tampers
# with nothing and reads as an undetected case. The first run of the sweep script
# did exactly that and reported 19/21.
COLUMN_EDITS = {
    "event_data": '{"file_path": "C:/data/nothing_happened.docx", "verdict": "benign"}',
    "event_type": "file_baseline",
    "timestamp": "2020-01-01T00:00:00Z",
    "current_hash": "f" * 64,
    "previous_hash": "d" * 64,
}


# ------------------------------------------------------------------- in-place


@pytest.mark.parametrize("column,value", sorted(COLUMN_EDITS.items()))
@pytest.mark.parametrize("position", sorted(POSITIONS))
def test_every_column_edit_is_detected(column, value, position, chain):
    block_id = POSITIONS[position]
    sql(chain, f"UPDATE blocks SET {column} = ? WHERE id = ?", (value, block_id))

    result = verify(chain)

    assert result["valid"] is False, f"{column} at {position} went undetected"
    assert result["invalid_block_id"] is not None


@pytest.mark.parametrize("position", ["first", "middle"])
def test_deleting_an_interior_row_is_detected(position, chain):
    """An interior deletion leaves the next block pointing at a hash no row holds."""
    sql(chain, "DELETE FROM blocks WHERE id = ?", (POSITIONS[position],))

    result = verify(chain)

    assert result["valid"] is False
    assert result["invalid_block_id"] is not None


def test_swapping_two_payloads_is_detected(chain):
    """Both rows now hash to something other than their stored hash."""
    all_rows = rows(chain)
    first, last = all_rows[0], all_rows[-1]
    sql(chain, "UPDATE blocks SET event_data = ? WHERE id = ?", (last["event_data"], first["id"]))
    sql(chain, "UPDATE blocks SET event_data = ? WHERE id = ?", (first["event_data"], last["id"]))

    assert verify(chain)["valid"] is False


def test_the_first_broken_block_is_named_and_the_walk_stops_there(chain):
    """`blocks_checked` says how far verification got, which is where to look."""
    target = POSITIONS["middle"]
    sql(
        chain,
        "UPDATE blocks SET event_data = ? WHERE id = ?",
        ('{"verdict": "benign"}', target),
    )

    result = verify(chain)

    assert result["invalid_block_id"] == target
    assert result["blocks_checked"] == target, "the walk did not stop at the break"


def test_the_genesis_hash_is_what_the_first_block_points_at(chain):
    """The fixture assumption behind the `previous_hash` value above.

    If this ever changes, `"d" * 64` might become the genesis value and the
    column-edit case for `previous_hash` at `first` would silently stop testing
    anything.
    """
    assert rows(chain)[0]["previous_hash"] == GENESIS_HASH
    assert GENESIS_HASH != COLUMN_EDITS["previous_hash"]


# ----------------------------------------------------------------- structural


def test_an_appended_block_is_not_detected(chain):
    """The attacker computes the hash themselves. There is no secret to lack."""
    tip = rows(chain)[-1]
    timestamp = "2026-09-05T00:00:00Z"
    event_json = '{"file_path": "C:/data/planted.docx", "verdict": "benign"}'
    current = HashChainLedger.compute_hash(
        timestamp, "file_event", event_json, tip["current_hash"]
    )
    sql(
        chain,
        "INSERT INTO blocks (timestamp, event_type, event_data, previous_hash, current_hash)"
        " VALUES (?,?,?,?,?)",
        (timestamp, "file_event", event_json, tip["current_hash"], current),
    )

    result = verify(chain)

    assert result["valid"] is True, (
        "an appended block is now detected - if a signing key or an external "
        "anchor was added, the tamper claim widens and every document stating "
        "this limit needs updating"
    )
    assert result["blocks_checked"] == CHAIN_LENGTH + 1


def test_deleting_the_newest_block_is_not_detected(chain):
    """Truncation by one. What remains is a perfect prefix."""
    sql(chain, "DELETE FROM blocks WHERE id = ?", (POSITIONS["last"],))

    result = verify(chain)

    assert result["valid"] is True
    assert result["blocks_checked"] == CHAIN_LENGTH - 1, (
        "the chain got shorter and nothing said so"
    )


def test_truncating_the_tail_is_not_detected(chain):
    """Everything from the middle on, gone. The verifier sees a shorter chain."""
    sql(chain, "DELETE FROM blocks WHERE id >= ?", (POSITIONS["middle"],))

    result = verify(chain)

    assert result["valid"] is True
    assert result["blocks_checked"] == POSITIONS["middle"] - 1


def test_a_rechained_suffix_is_not_detected(chain):
    """The strongest tamper: change one block, recompute everything after it.

    This is what the chain is actually worth against someone with file access. It
    is the case the write-up has to state, because it is the one that makes
    "tamper-evident" mean "tamper-evident against an attacker who does not
    recompute", which is a much smaller claim than it sounds.
    """
    target = POSITIONS["middle"]
    previous = None
    for row in rows(chain):
        event_json = row["event_data"]
        if row["id"] == target:
            event_json = '{"file_path": "C:/data/nothing_happened.docx", "verdict": "benign"}'
        previous_hash = previous if previous is not None else row["previous_hash"]
        current = HashChainLedger.compute_hash(
            row["timestamp"], row["event_type"], event_json, previous_hash
        )
        sql(
            chain,
            "UPDATE blocks SET event_data = ?, previous_hash = ?, current_hash = ? WHERE id = ?",
            (event_json, previous_hash, current, row["id"]),
        )
        previous = current

    result = verify(chain)

    assert result["valid"] is True
    assert result["blocks_checked"] == CHAIN_LENGTH
    # The evidence really is gone: the rewritten payload is what a reader sees.
    rewritten = [r for r in rows(chain) if r["id"] == target][0]
    assert "nothing_happened" in rewritten["event_data"]


# ------------------------------------------------------------- the artefact


def test_the_recorded_sweep_agrees_with_this_one():
    """Cross-check against `scripts/tamper_sweep.py`, if it has been run."""
    report = REPO_ROOT / "reports" / "tamper_sweep.json"
    if not report.exists():
        pytest.skip("reports/tamper_sweep.json is absent; run scripts/tamper_sweep.py")

    recorded = json.loads(report.read_text(encoding="utf-8"))
    assert recorded["in_place"]["meets_target"] is True
    assert recorded["in_place"]["rate"] == 1.0
    assert recorded["in_place"]["missed"] == []
    assert recorded["structural"]["detected"] == 0, (
        "a structural tamper is now detected; the scheme changed and the limit "
        "stated across the write-up needs revisiting"
    )
