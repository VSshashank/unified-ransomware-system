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
    json_fragment,
)

_BLOCK_COLUMNS = "id, timestamp, event_type, event_data, previous_hash, current_hash"


def utc_now() -> str:
    """UTC timestamp, ISO-8601 with a Z suffix (matches the other services)."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _like_escape(value: str) -> str:
    """Escape LIKE wildcards so a path containing % or _ can't widen the match."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


class HashChainLedger:
    def __init__(self, db_path: str = DEFAULT_DB_PATH) -> None:
        self.db_path = db_path
        self.conn = connect(db_path)
        # Appends read the tip and then insert. FastAPI runs sync endpoints in a
        # threadpool, so without this lock two concurrent logs could read the
        # same tip and fork the chain.
        self._lock = threading.Lock()
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
        """Append a block and return it. The only write path in the service."""
        event_json = canonical_json(event_data)

        with self._lock:
            tip = self.conn.execute(
                "SELECT current_hash FROM blocks ORDER BY id DESC LIMIT 1"
            ).fetchone()
            previous_hash = tip["current_hash"] if tip else GENESIS_HASH

            timestamp = utc_now()
            current_hash = self.compute_hash(timestamp, event_type, event_json, previous_hash)

            cursor = self.conn.execute(
                "INSERT INTO blocks (timestamp, event_type, event_data, previous_hash, current_hash)"
                " VALUES (?,?,?,?,?)",
                (timestamp, event_type, event_json, previous_hash, current_hash),
            )
            self.conn.commit()
            block_id = cursor.lastrowid

        return {
            "block_id": block_id,
            "timestamp": timestamp,
            "event_type": event_type,
            "event_data": decode_event_data(event_json),
            "previous_hash": previous_hash,
            "current_hash": current_hash,
        }

    # -------------------------------------------------------------- verification

    def verify_chain(self) -> dict:
        """Walk the whole chain, recomputing every hash.

        Stops at the first broken block and reports its id. `blocks_checked` is
        how many were examined, so on a valid chain it equals the chain length
        and on a broken one it tells you how far verification got.

        Single query plus an in-memory walk - the sub-50ms target (Table 5.9)
        does not survive a query per block.
        """
        started = time.perf_counter()

        rows = self.conn.execute(
            f"SELECT {_BLOCK_COLUMNS} FROM blocks ORDER BY id ASC"
        ).fetchall()

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
        """
        clauses: list[str] = []
        params: list[Any] = []

        if event_type:
            clauses.append("event_type = ?")
            params.append(event_type)

        if file_path:
            # Canonical JSON has no spaces, so this substring is a tight
            # prefilter. Exact matching still happens in Python below.
            # JSON-encode first (backslashes get doubled), then escape for LIKE.
            clauses.append("event_data LIKE ? ESCAPE '\\'")
            params.append(f'%"file_path":"{_like_escape(json_fragment(file_path))}"%')

        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        order = "DESC" if newest_first else "ASC"

        total = self.conn.execute(
            f"SELECT COUNT(*) AS n FROM blocks{where}", params
        ).fetchone()["n"]

        rows = self.conn.execute(
            f"SELECT {_BLOCK_COLUMNS} FROM blocks{where} ORDER BY id {order} LIMIT ? OFFSET ?",
            (*params, limit, offset),
        ).fetchall()

        blocks = [self._row_to_block(row) for row in rows]
        if file_path:
            blocks = [b for b in blocks if b["event_data"].get("file_path") == file_path]

        return {"blocks": blocks, "total": total, "offset": offset, "limit": limit}

    @staticmethod
    def _row_to_block(row: sqlite3.Row) -> dict:
        return {
            "block_id": row["id"],
            "timestamp": row["timestamp"],
            "event_type": row["event_type"],
            "event_data": decode_event_data(row["event_data"]),
            "previous_hash": row["previous_hash"],
            "current_hash": row["current_hash"],
            "blockchain_anchor": None,  # Phase 5
        }
