"""SQLite storage layer for the ledger.

Two things here matter for chain integrity:

1. `canonical_json` is the single definition of how a dict becomes the bytes we
   hash. Blocks are stored as that exact text, so verification re-hashes the
   stored string rather than a re-serialised dict. Without this, key ordering or
   whitespace differences would break the chain on read-back.
2. The connection is opened with `check_same_thread=False` because FastAPI runs
   sync endpoints in a worker threadpool. `HashChainLedger` serialises writes
   with a lock - see hash_chain.py.
"""

import json
import os
import sqlite3
from typing import Any

# previous_hash of the first block. 64 zeros = the width of a SHA-256 hexdigest.
GENESIS_HASH = "0" * 64

DEFAULT_DB_PATH = os.getenv("LEDGER_DB_PATH", "./data/ledger.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS blocks (
    id INTEGER PRIMARY KEY,
    timestamp TEXT,
    event_type TEXT,
    event_data TEXT,
    previous_hash TEXT,
    current_hash TEXT
)
"""

# Recovery looks up "the last block that mentions this file path", which is a
# reverse scan filtered by event_type. Cheap index, big help at demo sizes.
INDEXES = (
    "CREATE INDEX IF NOT EXISTS idx_blocks_event_type ON blocks(event_type)",
)


def canonical_json(event_data: Any) -> str:
    """Serialise event_data deterministically.

    Sorted keys and no incidental whitespace, so the same logical payload always
    produces the same bytes - and therefore the same hash.
    """
    if isinstance(event_data, str):
        # Already serialised (or a plain string payload); hash it as-is.
        return event_data
    return json.dumps(event_data, sort_keys=True, separators=(",", ":"), default=str)


def json_fragment(value: str) -> str:
    """How `value` appears inside canonical JSON, without the surrounding quotes.

    Windows paths pick up escaped backslashes when serialised - C:\\data becomes
    C:\\\\data in the stored text - so any substring search over event_data has
    to look for the escaped form, not the raw path.
    """
    return json.dumps(value)[1:-1]


def decode_event_data(raw: str) -> dict:
    """Parse stored event_data back to a dict.

    A tampered row may no longer be valid JSON. Verification must still be able
    to report *which* block broke, so decoding failure degrades to a wrapper
    dict instead of raising.
    """
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        return {"_raw": raw}
    return parsed if isinstance(parsed, dict) else {"_value": parsed}


def connect(db_path: str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """Open the ledger database, creating the parent directory if needed."""
    if db_path != ":memory:":
        parent = os.path.dirname(os.path.abspath(db_path))
        os.makedirs(parent, exist_ok=True)

    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    if db_path != ":memory:":
        # Deliberately NOT WAL. WAL coordinates readers and writers through a
        # shared-memory index (the -shm file), and that coordination does not
        # survive a bind mount from a macOS/Windows host into the Linux VM that
        # Docker Desktop runs. Observed consequence: the service kept answering
        # /ledger/verify from a snapshot taken before a row was rewritten in the
        # file underneath it, so a tamper went undetected - the exact failure
        # TC-05 exists to catch.
        #
        # The rollback journal uses only POSIX locks on the database file, which
        # do cross that boundary. The ledger appends small audit rows and is read
        # by one dashboard, so WAL's concurrency advantage was never load-bearing
        # and is not worth a hole in the integrity guarantee.
        conn.execute("PRAGMA journal_mode=DELETE")
        # Readers and writers can now briefly block each other; wait rather than
        # returning "database is locked".
        conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA synchronous=FULL")
    return conn


def create_tables(conn: sqlite3.Connection) -> None:
    conn.execute(SCHEMA)
    for statement in INDEXES:
        conn.execute(statement)
    conn.commit()
