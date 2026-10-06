"""Append-only SHA-256 hash chain over SQLite.

    current_hash = SHA256(timestamp + event_type + event_data + previous_hash)

where `event_data` is the canonical JSON text actually stored in the row. Each
block commits to the one before it, so editing any historical row invalidates
that block and every block after it.

There is no update or delete path here on purpose: the only write is an append.
"""

import hashlib
import sqlite3
import threading
import time
from datetime import datetime, timezone
from typing import Any, Optional

from database import (
    DEFAULT_DB_PATH,
    GENESIS_HASH,
    canonical_json,
    connect,
    create_tables,
    decode_event_data,
)
from path_keys import path_key, prefilter, same_file

_BLOCK_COLUMNS = "id, timestamp, event_type, event_data, previous_hash, current_hash"

# The most appends one commit may carry. A bound, so that one caller is never
# made to wait on an unbounded backlog; far above the handful of writers (the
# Monitor's two threads, the Response service's workers) that can queue at once.
MAX_BATCH = 64


class _Append:
    """One caller's append, waiting to be committed by whichever caller leads."""

    __slots__ = ("event_type", "event_json", "done", "block", "error")

    def __init__(self, event_type: str, event_json: str) -> None:
        self.event_type = event_type
        self.event_json = event_json
        self.done = False
        self.block: Optional[dict] = None
        self.error: Optional[BaseException] = None


def utc_now() -> str:
    """UTC timestamp, ISO-8601 with a Z suffix (matches the other services)."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class HashChainLedger:
    def __init__(self, db_path: str = DEFAULT_DB_PATH) -> None:
        self.db_path = db_path
        self.conn = connect(db_path)
        # Appends read the tip and then insert. FastAPI runs sync endpoints in a
        # threadpool, so without this lock two concurrent logs could read the
        # same tip and fork the chain.
        self._lock = threading.Lock()
        # Group commit. Each append is made durable before its caller returns, as
        # it always was, but appends that arrive while a commit is in flight are
        # carried by the next one instead of each paying for its own: with
        # `synchronous=FULL` and a rollback journal a commit is several disk
        # flushes, and on a slow disk a burst's blocks fell seconds behind the
        # events they describe. `_waiting` and `_leading` are guarded by `_turn`;
        # `_lock` still guards the connection.
        self._turn = threading.Condition()
        self._waiting: list[_Append] = []
        self._leading = False
        self.create_tables()

    def create_tables(self) -> None:
        create_tables(self.conn)

    def close(self) -> None:
        self.conn.close()

    # ------------------------------------------------------------------ hashing

    @staticmethod
    def compute_hash(timestamp: str, event_type: str, event_json: str, previous_hash: str) -> str:
        """Hash one block. `event_json` must be the exact stored text."""
        block_content = f"{timestamp}{event_type}{event_json}{previous_hash}"
        return hashlib.sha256(block_content.encode("utf-8")).hexdigest()

    # ------------------------------------------------------------------- writes

    def add_block(self, event_type: str, event_data: Any) -> dict:
        """Append a block and return it. The only write path in the service.

        Returns once the block is committed. Blocks are chained in the order the
        calls arrived; callers that overlap share one commit.
        """
        append = _Append(event_type, canonical_json(event_data))

        with self._turn:
            self._waiting.append(append)
        while True:
            with self._turn:
                while self._leading and not append.done:
                    self._turn.wait()
                if append.done:
                    return self._outcome(append)
                # Nobody is committing and this append is not yet committed:
                # lead. The batch is the oldest appends, this one among them
                # unless more than MAX_BATCH are ahead of it, in which case the
                # next pass of this loop leads again.
                self._leading = True
                batch = self._waiting[:MAX_BATCH]
                del self._waiting[:MAX_BATCH]
            try:
                self._commit(batch)
            finally:
                with self._turn:
                    self._leading = False
                    self._turn.notify_all()

    @staticmethod
    def _outcome(append: _Append) -> dict:
        if append.error is not None:
            raise append.error
        assert append.block is not None
        return append.block

    def _commit(self, batch: list[_Append]) -> None:
        """Chain `batch` in order and commit it once. Every entry is settled, win or lose."""
        try:
            with self._lock:
                tip = self.conn.execute(
                    "SELECT current_hash FROM blocks ORDER BY id DESC LIMIT 1"
                ).fetchone()
                previous_hash = tip["current_hash"] if tip else GENESIS_HASH
                blocks = []
                try:
                    for append in batch:
                        timestamp = utc_now()
                        current_hash = self.compute_hash(
                            timestamp, append.event_type, append.event_json, previous_hash
                        )
                        cursor = self.conn.execute(
                            "INSERT INTO blocks (timestamp, event_type, event_data, previous_hash, current_hash)"
                            " VALUES (?,?,?,?,?)",
                            (timestamp, append.event_type, append.event_json, previous_hash, current_hash),
                        )
                        blocks.append(
                            {
                                "block_id": cursor.lastrowid,
                                "timestamp": timestamp,
                                "event_type": append.event_type,
                                "event_data": decode_event_data(append.event_json),
                                "previous_hash": previous_hash,
                                "current_hash": current_hash,
                            }
                        )
                        previous_hash = current_hash
                    self.conn.commit()
                except BaseException:
                    # Nothing from a batch that did not commit may stay in the
                    # open transaction to ride into the next one.
                    self.conn.rollback()
                    raise
        except BaseException as exc:
            for append in batch:
                append.error = exc
        else:
            for append, block in zip(batch, blocks):
                append.block = block
        finally:
            with self._turn:
                for append in batch:
                    append.done = True
                self._turn.notify_all()

    # -------------------------------------------------------------- verification

    def verify_chain(self) -> dict:
        """Walk the whole chain, recomputing every hash.

        Stops at the first broken block and reports its id. `blocks_checked` is
        how many were examined, so on a valid chain it equals the chain length
        and on a broken one it tells you how far verification got.

        Single query plus an in-memory walk - the sub-50ms target (Table 5.9)
        does not survive a query per block.

        The read goes through a *fresh* connection, not `self.conn`. The threat
        TC-05 models is an attacker editing the SQLite file directly, and a
        long-lived connection can answer from a snapshot taken before that edit
        - which was observed in Docker, where the service kept certifying a
        chain as valid after a row had been rewritten underneath it. An
        integrity check that trusts its own cache cannot detect the one thing it
        exists to detect, so this one always re-reads from disk.
        """
        started = time.perf_counter()

        if self.db_path == ":memory:":
            # No file to re-open; an in-memory database has no external writer.
            rows = self.conn.execute(
                f"SELECT {_BLOCK_COLUMNS} FROM blocks ORDER BY id ASC"
            ).fetchall()
        else:
            reader = connect(self.db_path)
            try:
                rows = reader.execute(
                    f"SELECT {_BLOCK_COLUMNS} FROM blocks ORDER BY id ASC"
                ).fetchall()
            finally:
                reader.close()

        expected_previous = GENESIS_HASH
        invalid_block_id: Optional[int] = None
        blocks_checked = 0

        for row in rows:
            blocks_checked += 1
            recomputed = self.compute_hash(
                row["timestamp"], row["event_type"], row["event_data"], row["previous_hash"]
            )
            # Two independent failures: the row's own contents no longer hash to
            # its stored hash, or its back-pointer doesn't match the real prior
            # block (a deleted or reordered row).
            if recomputed != row["current_hash"] or row["previous_hash"] != expected_previous:
                invalid_block_id = row["id"]
                break
            expected_previous = row["current_hash"]

        elapsed_ms = (time.perf_counter() - started) * 1000.0

        return {
            "valid": invalid_block_id is None,
            "blocks_checked": blocks_checked,
            "invalid_block_id": invalid_block_id,
            "verification_time_ms": round(elapsed_ms, 3),
        }

    # -------------------------------------------------------------------- reads

    def count_blocks(self) -> int:
        return self.conn.execute("SELECT COUNT(*) AS n FROM blocks").fetchone()["n"]

    def get_blocks(
        self,
        offset: int = 0,
        limit: int = 50,
        event_type: Optional[str] = None,
        file_path: Optional[str] = None,
        newest_first: bool = False,
    ) -> dict:
        """Paginated read of the audit trail.

        Defaults are the plain paginated read the dashboard needs. The optional
        filters exist so recovery can find "the last block about this path"
        in one call instead of paging the whole chain over HTTP.

        `file_path` matches the file in any spelling - separators, case on a
        Windows path, `.` and `..` - including rows stored before the Monitor
        normalised paths. path_keys.py has the policy, and why the match is
        computed from the hashed `event_data` rather than kept in a column.
        """
        clauses: list[str] = []
        params: list[Any] = []

        if event_type:
            clauses.append("event_type = ?")
            params.append(event_type)

        if file_path:
            # A prefilter on the file's name, the one part every spelling
            # shares; `same_file` below decides. JSON-encoded, then escaped for
            # LIKE, so a name containing % or _ cannot widen it.
            clauses.append("event_data LIKE ? ESCAPE '\\'")
            params.append(prefilter(file_path))

        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        order = "DESC" if newest_first else "ASC"

        if not file_path:
            total = self.conn.execute(
                f"SELECT COUNT(*) AS n FROM blocks{where}", params
            ).fetchone()["n"]

            rows = self.conn.execute(
                f"SELECT {_BLOCK_COLUMNS} FROM blocks{where} ORDER BY id {order} LIMIT ? OFFSET ?",
                (*params, limit, offset),
            ).fetchall()

            blocks = [self._row_to_block(row) for row in rows]
            return {"blocks": blocks, "total": total, "offset": offset, "limit": limit}

        # The page is cut *after* matching, and `total` counts matches. This used
        # to apply LIMIT/OFFSET to the prefilter and then the exact comparison,
        # so a page could come back short and `total` counted rows the
        # comparison then dropped - rare while the prefilter was the exact
        # spelling, routine now that it is only the name.
        key = path_key(file_path)
        rows = self.conn.execute(
            f"SELECT {_BLOCK_COLUMNS} FROM blocks{where} ORDER BY id {order}", params
        ).fetchall()

        blocks: list[dict] = []
        total = 0
        for row in rows:
            event_data = decode_event_data(row["event_data"])
            if not same_file(event_data.get("file_path"), key):
                continue
            if offset <= total < offset + limit:
                blocks.append(self._row_to_block(row, event_data))
            total += 1

        return {"blocks": blocks, "total": total, "offset": offset, "limit": limit}

    @staticmethod
    def _row_to_block(row: sqlite3.Row, event_data: Optional[dict] = None) -> dict:
        return {
            "block_id": row["id"],
            "timestamp": row["timestamp"],
            "event_type": row["event_type"],
            "event_data": decode_event_data(row["event_data"]) if event_data is None else event_data,
            "previous_hash": row["previous_hash"],
            "current_hash": row["current_hash"],
            "blockchain_anchor": None,  # Phase 5
        }
