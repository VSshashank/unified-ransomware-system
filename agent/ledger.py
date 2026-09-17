"""The ledger, written directly to SQLite instead of over HTTP.

`recovery/ledger_client.py` talks to the ledger service on port 8003, and its
docstring gives the reason: two containers writing the same chain file would
race and fork it. That reason is about containers. The agent is one process on
one host, it is the only writer, and a localhost round trip inside a 100 ms
budget is budget spent on the wrong thing.

What is *not* duplicated is the part that matters. `LedgerClient` carries real
domain logic - `GOOD_STATE_EVENT_TYPES`, the `HASH_KEYS` priority, and the rule
that "the last hash on this path" is the attacker's hash during an attack and
must never be the integrity reference. Reimplementing that here would be two
copies of a rule whose subtlety is the whole point of it, and the copies would
drift.

So this subclasses `LedgerClient` and replaces exactly one method: the
transport. Every caller-facing method above it - `log_event`, `try_log_event`,
`last_known_hash`, `verify_chain` - runs the service's code unchanged, against
`HashChainLedger` rather than against httpx.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from agent import imports

_recovery_client = imports.load("recovery.ledger_client")
_hash_chain = imports.load("hash_chain")

LedgerClient = _recovery_client.LedgerClient
LedgerUnavailableError = _recovery_client.LedgerUnavailableError
GOOD_STATE_EVENT_TYPES = _recovery_client.GOOD_STATE_EVENT_TYPES
HashChainLedger = _hash_chain.HashChainLedger

logger = logging.getLogger(__name__)


class DirectLedger(LedgerClient):
    """`LedgerClient`'s logic over `HashChainLedger`'s storage.

    Thread-safe for appends because `HashChainLedger.add_block` holds a lock
    across read-tip-then-insert, which is the operation that would otherwise
    fork the chain under concurrency.
    """

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = str(db_path)
        # base_url is never dialled; it is carried so that error messages and
        # anything logging the client still say where the chain actually is.
        super().__init__(base_url=f"sqlite:///{self.db_path}")
        self.chain = HashChainLedger(self.db_path)

    # -- the only thing that changes ---------------------------------------

    def _request(self, method: str, path: str, **kwargs: Any) -> dict:
        try:
            if method == "POST" and path == "/ledger/log":
                body = kwargs.get("json") or {}
                return self.chain.add_block(body["event_type"], body["event_data"])

            if method == "GET" and path == "/ledger/blocks":
                params = kwargs.get("params") or {}
                return self.chain.get_blocks(
                    offset=int(params.get("offset", 0)),
                    limit=int(params.get("limit", 50)),
                    event_type=params.get("event_type"),
                    file_path=params.get("file_path"),
                    newest_first=bool(params.get("newest_first", False)),
                )

            if method == "GET" and path == "/ledger/verify":
                return self.chain.verify_chain()
        except Exception as exc:  # noqa: BLE001 - re-raised in the shape callers expect
            raise LedgerUnavailableError(
                f"direct ledger at {self.db_path} failed on {method} {path}: {exc}"
            ) from exc

        raise LedgerUnavailableError(
            f"{method} {path} is not implemented by the direct ledger. It "
            f"mirrors only the three routes recovery uses; a new call site "
            f"should be added here deliberately rather than falling back to "
            f"HTTP."
        )

    # -- convenience --------------------------------------------------------

    def block_count(self) -> int:
        return self.chain.count_blocks()

    def close(self) -> None:
        self.chain.close()

    def __enter__(self) -> "DirectLedger":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()
