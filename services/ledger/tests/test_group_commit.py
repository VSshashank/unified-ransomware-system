"""Group commit: appends that overlap share a commit; nothing else about the chain changes.

The Monitor writes ~4 blocks per suspicious event, from its drain thread, its
escalation writer and (through the Response service) several request threads. Each
used to take the connection lock and pay for its own commit - several disk flushes
with `synchronous=FULL` and a rollback journal - so on a slow disk a 20-file burst's
blocks landed 4-8 s behind the events. Appends that arrive while a commit is in
flight now ride in the next one.

What must not change, and is pinned here: a caller returns only after its block is
durable, ids are contiguous, every block links to the one before it, the order is
the order the appends were taken, and a batch that fails to commit leaves nothing
in the chain.
"""

import sqlite3
import threading
import time

import pytest

import hash_chain
from database import GENESIS_HASH
from hash_chain import HashChainLedger


@pytest.fixture
def ledger(tmp_path):
    chain = HashChainLedger(str(tmp_path / "ledger.db"))
    yield chain
    chain.close()


def commits_of(ledger) -> list:
    seen: list = []
    ledger.conn.set_trace_callback(lambda statement: seen.append(statement) if statement == "COMMIT" else None)
    return seen


def slow_commits(ledger, monkeypatch, seconds=0.02):
    real = ledger._commit

    def slow(batch):
        time.sleep(seconds)  # the disk flush; lets the other writers queue behind it
        return real(batch)

    monkeypatch.setattr(ledger, "_commit", slow)


def hammer(ledger, threads: int, each: int) -> dict:
    """`threads` writers, `each` appends apiece; the block ids each was given, in call order."""
    got = {n: [] for n in range(threads)}
    errors: list = []
    gate = threading.Barrier(threads)

    def work(n: int) -> None:
        try:
            gate.wait()
            for i in range(each):
                got[n].append(ledger.add_block("file_event", {"writer": n, "i": i})["block_id"])
        except BaseException as exc:  # reported below, not swallowed by the thread
            errors.append(exc)

    pool = [threading.Thread(target=work, args=(n,)) for n in range(threads)]
    for t in pool:
        t.start()
    for t in pool:
        t.join(timeout=60)
    assert not errors, errors
    assert not [t for t in pool if t.is_alive()], "a writer never came back"
    return got


def test_a_lone_writer_is_unchanged(ledger):
    seen = commits_of(ledger)
    blocks = [ledger.add_block("file_event", {"i": i}) for i in range(5)]
    assert [b["block_id"] for b in blocks] == [1, 2, 3, 4, 5]
    assert blocks[0]["previous_hash"] == GENESIS_HASH
    assert all(blocks[i + 1]["previous_hash"] == blocks[i]["current_hash"] for i in range(4))
    assert len(seen) == 5, "one writer, one commit each, as before"
    result = ledger.verify_chain()
    assert result["valid"] is True and result["blocks_checked"] == 5


def test_overlapping_writers_share_commits_and_the_chain_is_intact(ledger, monkeypatch):
    slow_commits(ledger, monkeypatch)
    seen = commits_of(ledger)
    got = hammer(ledger, threads=8, each=10)

    assert ledger.count_blocks() == 80
    assert len(seen) < 80 / 2, f"{len(seen)} commits for 80 appends: the writers did not share"
    ids = sorted(i for ids in got.values() for i in ids)
    assert ids == list(range(1, 81)), "ids are not contiguous, or one was given twice"
    for n, mine in got.items():
        assert mine == sorted(mine), f"writer {n}'s own appends were chained out of order"
    result = ledger.verify_chain()
    assert result["valid"] is True and result["blocks_checked"] == 80


def test_each_block_is_durable_when_its_caller_returns(ledger, tmp_path, monkeypatch):
    slow_commits(ledger, monkeypatch)
    outcomes: list = []

    def work(n: int) -> None:
        block = ledger.add_block("file_event", {"writer": n})
        reader = sqlite3.connect(str(tmp_path / "ledger.db"))
        try:
            row = reader.execute("SELECT current_hash FROM blocks WHERE id=?", (block["block_id"],)).fetchone()
        finally:
            reader.close()
        outcomes.append((n, row is not None and row[0] == block["current_hash"]))

    pool = [threading.Thread(target=work, args=(n,)) for n in range(6)]
    for t in pool:
        t.start()
    for t in pool:
        t.join(timeout=60)
    assert len(outcomes) == 6 and all(ok for _, ok in outcomes), outcomes


def test_a_backlog_longer_than_one_batch_still_completes(ledger, monkeypatch):
    monkeypatch.setattr(hash_chain, "MAX_BATCH", 3)
    slow_commits(ledger, monkeypatch, seconds=0.01)
    seen = commits_of(ledger)
    hammer(ledger, threads=12, each=4)
    assert ledger.count_blocks() == 48
    assert len(seen) >= 48 / 3
    assert ledger.verify_chain()["valid"] is True


def test_a_batch_that_fails_leaves_nothing_behind_and_the_next_append_chains_cleanly(ledger, monkeypatch):
    first = ledger.add_block("file_event", {"i": 0})
    real = HashChainLedger.compute_hash

    def flaky(timestamp, event_type, event_json, previous_hash):
        if event_type == "boom":
            raise OSError("disk went away")
        return real(timestamp, event_type, event_json, previous_hash)

    monkeypatch.setattr(HashChainLedger, "compute_hash", staticmethod(flaky))
    with pytest.raises(OSError):
        ledger.add_block("boom", {"i": 1})
    monkeypatch.setattr(HashChainLedger, "compute_hash", staticmethod(real))

    assert ledger.count_blocks() == 1, "the failed append is in the chain"
    after = ledger.add_block("file_event", {"i": 2})
    assert after["block_id"] == 2 and after["previous_hash"] == first["current_hash"]
    assert ledger.verify_chain()["valid"] is True


def test_a_failure_inside_a_shared_batch_rolls_the_whole_batch_back(ledger, monkeypatch):
    """No half-committed batch: the appends that shared the failing commit are all out of the chain."""
    ledger.add_block("file_event", {"i": 0})
    real = HashChainLedger.compute_hash

    def flaky(timestamp, event_type, event_json, previous_hash):
        if event_type == "boom":
            raise OSError("disk went away")
        return real(timestamp, event_type, event_json, previous_hash)

    # Hold the first commit open until two more writers are queued, so they share the next batch.
    release = threading.Event()
    held_once = threading.Event()
    real_commit = ledger._commit

    def held(batch):
        if not held_once.is_set():
            held_once.set()
            release.wait(5)
        return real_commit(batch)

    monkeypatch.setattr(ledger, "_commit", held)
    monkeypatch.setattr(HashChainLedger, "compute_hash", staticmethod(flaky))
    results: dict = {}

    def run(name: str, event_type: str) -> None:
        try:
            results[name] = ledger.add_block(event_type, {"who": name})
        except BaseException as exc:
            results[name] = exc

    leader = threading.Thread(target=run, args=("leader", "file_event"))
    leader.start()
    held_once.wait(5)
    others = [
        threading.Thread(target=run, args=("good", "file_event")),
        threading.Thread(target=run, args=("bad", "boom")),
    ]
    for t in others:
        t.start()
    deadline = time.monotonic() + 5
    while len(ledger._waiting) < 2 and time.monotonic() < deadline:
        time.sleep(0.005)
    release.set()
    for t in [leader, *others]:
        t.join(timeout=30)
    monkeypatch.setattr(HashChainLedger, "compute_hash", staticmethod(real))

    assert not isinstance(results["leader"], BaseException), "the first batch had no bad append"
    assert isinstance(results["bad"], OSError)
    assert isinstance(results["good"], OSError), "it shared the failing commit, so it failed with it"
    assert ledger.count_blocks() == 2, "the failed batch left something in the chain"
    assert ledger.verify_chain()["valid"] is True
