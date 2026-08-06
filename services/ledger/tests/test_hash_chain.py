"""Hash chain tests: growth, tamper detection (TC-05), and the <50ms target."""

import hashlib
import sqlite3

import pytest

from database import GENESIS_HASH, canonical_json
from hash_chain import HashChainLedger


@pytest.fixture
def ledger(tmp_path):
    chain = HashChainLedger(str(tmp_path / "ledger.db"))
    yield chain
    chain.close()


def tamper(db_path: str, sql: str, params: tuple = ()) -> None:
    """Edit the SQLite file directly, the way an attacker with disk access would."""
    conn = sqlite3.connect(db_path)
    conn.execute(sql, params)
    conn.commit()
    conn.close()


# ------------------------------------------------------------------- edge cases


def test_empty_chain_is_valid(ledger):
    result = ledger.verify_chain()
    assert result["valid"] is True
    assert result["blocks_checked"] == 0
    assert result["invalid_block_id"] is None


def test_empty_chain_reads_return_nothing(ledger):
    page = ledger.get_blocks()
    assert page["blocks"] == []
    assert page["total"] == 0


# ----------------------------------------------------------------- chain growth


def test_first_block_points_at_genesis(ledger):
    block = ledger.add_block("file_encrypted", {"file_path": "/a.doc"})
    assert block["previous_hash"] == GENESIS_HASH
    assert block["block_id"] == 1


def test_blocks_link_to_their_predecessor(ledger):
    first = ledger.add_block("analysis", {"file_path": "/a.doc"})
    second = ledger.add_block("analysis", {"file_path": "/b.doc"})
    third = ledger.add_block("analysis", {"file_path": "/c.doc"})

    assert second["previous_hash"] == first["current_hash"]
    assert third["previous_hash"] == second["current_hash"]
    assert ledger.verify_chain()["valid"] is True
    assert ledger.count_blocks() == 3


def test_hashes_are_full_width_sha256(ledger):
    block = ledger.add_block("file_encrypted", {"file_path": "/a.doc"})
    assert len(block["current_hash"]) == 64
    assert len(block["previous_hash"]) == 64
    int(block["current_hash"], 16)  # raises if not hex


def test_hash_is_recomputable_from_the_response(ledger):
    """A caller can verify our arithmetic without trusting us."""
    block = ledger.add_block("file_encrypted", {"file_path": "/a.doc", "entropy": 7.9})
    preimage = (
        block["timestamp"]
        + block["event_type"]
        + canonical_json(block["event_data"])
        + block["previous_hash"]
    )
    assert hashlib.sha256(preimage.encode("utf-8")).hexdigest() == block["current_hash"]


def test_key_order_does_not_affect_the_hash(ledger):
    """Canonical JSON means logically identical payloads hash identically."""
    a = ledger.add_block("analysis", {"file_path": "/a.doc", "entropy": 7.9, "pid": 1234})
    b = ledger.add_block("analysis", {"pid": 1234, "entropy": 7.9, "file_path": "/a.doc"})
    assert canonical_json(a["event_data"]) == canonical_json(b["event_data"])
    assert ledger.verify_chain()["valid"] is True


def test_nested_event_data_survives_round_trip(ledger):
    """The gateway's /analyze sends nested objects."""
    payload = {"file_path": "/a.doc", "features": {"entropy": 7.9}, "result": {"prediction": "ransomware"}}
    ledger.add_block("analysis", payload)
    assert ledger.get_blocks()["blocks"][0]["event_data"] == payload
    assert ledger.verify_chain()["valid"] is True


# -------------------------------------------------------------- TC-05 tampering


def test_edited_event_data_is_detected(ledger):
    ledger.add_block("file_encrypted", {"file_path": "/a.doc", "entropy": 7.9})
    ledger.add_block("file_encrypted", {"file_path": "/b.doc", "entropy": 7.5})
    ledger.add_block("file_encrypted", {"file_path": "/c.doc", "entropy": 7.2})

    tamper(ledger.db_path, "UPDATE blocks SET event_data = ? WHERE id = 2", ('{"file_path":"/harmless.txt"}',))

    result = ledger.verify_chain()
    assert result["valid"] is False
    assert result["invalid_block_id"] == 2


def test_journal_mode_is_not_wal(ledger):
    """WAL must stay off, and this is not a style preference.

    WAL coordinates connections through a shared-memory index (-shm), which does
    not survive Docker Desktop's bind mount from a macOS/Windows host into its
    Linux VM. The observed consequence was the running service answering
    /ledger/verify from a snapshot taken before a row was rewritten underneath
    it - a tamper reported as a valid chain, which is precisely the failure
    TC-05 exists to catch. The rollback journal uses POSIX file locks, which do
    cross that boundary.
    """
    mode = ledger.conn.execute("PRAGMA journal_mode").fetchone()[0]
    assert mode.lower() != "wal", (
        "journal_mode is WAL; external tampering can go undetected on a "
        "bind-mounted volume"
    )


def test_tamper_by_a_live_external_connection_is_detected(ledger):
    """The TC-05 threat model: the ledger is up and serving when the file is edited."""
    ledger.add_block("file_encrypted", {"file_path": "/a.doc", "entropy": 7.9})
    ledger.add_block("file_encrypted", {"file_path": "/b.doc", "entropy": 7.5})

    # Read through the service's own connection first, so any cached view of the
    # table is populated before the edit lands.
    assert ledger.verify_chain()["valid"] is True

    tamper(
        ledger.db_path,
        "UPDATE blocks SET event_data = ? WHERE id = 2",
        ('{"file_path":"/harmless.txt"}',),
    )

    result = ledger.verify_chain()
    assert result["valid"] is False, "tamper went undetected by a live ledger"
    assert result["invalid_block_id"] == 2


def test_verification_still_meets_the_50ms_target_with_a_fresh_connection(ledger):
    """Re-opening the database per verify must not cost the Table 5.9 target."""
    for index in range(1000):
        ledger.add_block("file_event", {"file_path": f"/f{index}.doc", "entropy": 7.9})

    result = ledger.verify_chain()
    assert result["valid"] is True
    assert result["blocks_checked"] == 1000
    assert result["verification_time_ms"] < 50, result["verification_time_ms"]


def test_relabelled_event_type_is_detected(ledger):
    """event_type is inside the preimage, so it can't be rewritten silently."""
    ledger.add_block("file_encrypted", {"file_path": "/a.doc"})
    tamper(ledger.db_path, "UPDATE blocks SET event_type = 'benign_write' WHERE id = 1")

    result = ledger.verify_chain()
    assert result["valid"] is False
    assert result["invalid_block_id"] == 1


def test_edited_timestamp_is_detected(ledger):
    ledger.add_block("file_encrypted", {"file_path": "/a.doc"})
    ledger.add_block("file_encrypted", {"file_path": "/b.doc"})
    tamper(ledger.db_path, "UPDATE blocks SET timestamp = '1999-01-01T00:00:00Z' WHERE id = 1")

    assert ledger.verify_chain()["invalid_block_id"] == 1


def test_deleted_block_is_detected(ledger):
    """Removing a row breaks the next block's back-pointer."""
    ledger.add_block("analysis", {"n": 1})
    ledger.add_block("analysis", {"n": 2})
    ledger.add_block("analysis", {"n": 3})

    tamper(ledger.db_path, "DELETE FROM blocks WHERE id = 2")

    result = ledger.verify_chain()
    assert result["valid"] is False
    assert result["invalid_block_id"] == 3


def test_rewriting_a_block_with_a_valid_hash_still_breaks_the_chain(ledger):
    """The strong case: an attacker who recomputes the edited block's own hash.

    Block 2 is internally consistent afterwards, but block 3 still points at the
    old hash, so the chain catches it one block later.
    """
    ledger.add_block("analysis", {"n": 1})
    ledger.add_block("analysis", {"n": 2})
    ledger.add_block("analysis", {"n": 3})

    row = sqlite3.connect(ledger.db_path).execute(
        "SELECT timestamp, previous_hash FROM blocks WHERE id = 2"
    ).fetchone()
    forged_data = '{"n":99}'
    forged_hash = HashChainLedger.compute_hash(row[0], "analysis", forged_data, row[1])
    tamper(
        ledger.db_path,
        "UPDATE blocks SET event_data = ?, current_hash = ? WHERE id = 2",
        (forged_data, forged_hash),
    )

    result = ledger.verify_chain()
    assert result["valid"] is False
    assert result["invalid_block_id"] == 3


def test_tampering_does_not_crash_on_invalid_json(ledger):
    """Verification must still name the block even if event_data stops being JSON."""
    ledger.add_block("analysis", {"n": 1})
    tamper(ledger.db_path, "UPDATE blocks SET event_data = 'not-json{' WHERE id = 1")

    result = ledger.verify_chain()
    assert result["valid"] is False
    assert result["invalid_block_id"] == 1


def test_verify_reports_the_first_break_only(ledger):
    for n in range(5):
        ledger.add_block("analysis", {"n": n})
    tamper(ledger.db_path, "UPDATE blocks SET event_data = '{}' WHERE id = 2")
    tamper(ledger.db_path, "UPDATE blocks SET event_data = '{}' WHERE id = 4")

    result = ledger.verify_chain()
    assert result["invalid_block_id"] == 2
    assert result["blocks_checked"] == 2


# ------------------------------------------------------------------- performance


@pytest.mark.benchmark
def test_verify_1000_blocks_under_50ms(ledger):
    """Table 5.9 target: full-chain verification under 50ms."""
    for n in range(1000):
        ledger.add_block("file_encrypted", {"file_path": f"/file_{n}.doc", "entropy": 7.5, "process_id": n})

    # First call can pay page-cache costs; measure a warm run, report both.
    cold = ledger.verify_chain()
    warm = ledger.verify_chain()

    assert warm["valid"] is True
    assert warm["blocks_checked"] == 1000
    assert warm["verification_time_ms"] < 50, (
        f"verification took {warm['verification_time_ms']}ms "
        f"(cold run {cold['verification_time_ms']}ms), target <50ms"
    )


# ------------------------------------------------------------------ paginated read


def test_pagination_returns_a_window_of_the_chain(ledger):
    for n in range(10):
        ledger.add_block("analysis", {"n": n})

    page = ledger.get_blocks(offset=3, limit=4)
    assert page["total"] == 10
    assert [b["block_id"] for b in page["blocks"]] == [4, 5, 6, 7]


def test_newest_first_read(ledger):
    for n in range(3):
        ledger.add_block("analysis", {"n": n})
    page = ledger.get_blocks(newest_first=True)
    assert [b["block_id"] for b in page["blocks"]] == [3, 2, 1]


def test_filter_by_event_type(ledger):
    ledger.add_block("analysis", {"n": 1})
    ledger.add_block("snapshot_created", {"snapshot_id": "vss_1"})
    ledger.add_block("analysis", {"n": 2})

    page = ledger.get_blocks(event_type="snapshot_created")
    assert page["total"] == 1
    assert page["blocks"][0]["event_data"]["snapshot_id"] == "vss_1"


def test_filter_by_file_path_is_exact(ledger):
    ledger.add_block("file_encrypted", {"file_path": "/data/report.doc", "file_hash": "a" * 64})
    ledger.add_block("file_encrypted", {"file_path": "/data/report.doc.backup", "file_hash": "b" * 64})

    page = ledger.get_blocks(file_path="/data/report.doc")
    assert [b["event_data"]["file_path"] for b in page["blocks"]] == ["/data/report.doc"]


def test_filter_by_windows_path(ledger):
    """Regression: JSON escapes backslashes, so the filter must too.

    Caught by the integration test - POSIX-path unit tests passed while every
    real Windows lookup silently returned nothing, which made recovery report
    "no prior hash" for files the ledger actually knew about.
    """
    windows_path = "C:\\Users\\demo\\Documents\\thesis.doc"
    ledger.add_block("file_baseline", {"file_path": windows_path, "file_hash": "c" * 64})
    ledger.add_block("file_baseline", {"file_path": "C:\\Users\\demo\\other.doc", "file_hash": "d" * 64})

    page = ledger.get_blocks(file_path=windows_path)
    assert page["total"] == 1
    assert page["blocks"][0]["event_data"]["file_hash"] == "c" * 64


def test_filter_by_path_with_unicode(ledger):
    path = "/data/rapport-\u00e9t\u00e9.doc"
    ledger.add_block("file_baseline", {"file_path": path, "file_hash": "e" * 64})
    assert ledger.get_blocks(file_path=path)["total"] == 1


def test_filter_by_file_path_ignores_like_wildcards(ledger):
    """A path containing % or _ must not turn into a wildcard match."""
    ledger.add_block("file_encrypted", {"file_path": "/data/real.doc"})
    page = ledger.get_blocks(file_path="/data/%.doc")
    assert page["blocks"] == []


def test_blocks_expose_null_blockchain_anchor(ledger):
    ledger.add_block("analysis", {"n": 1})
    assert ledger.get_blocks()["blocks"][0]["blockchain_anchor"] is None
