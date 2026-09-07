"""HTTP client for the ledger service.

Recovery runs in the Response service (port 8004) and the ledger runs in its own
container (port 8003), so this talks over HTTP rather than touching the SQLite
file. Two containers writing the same chain file would race and fork it.
"""

import logging
import os
from typing import Any, Callable, Optional

import httpx

logger = logging.getLogger(__name__)

# Keys we accept as "the hash of this file" in event_data, in priority order.
# Monitor/Response teammates are asked to send `file_hash`; the others are
# tolerated so an integrity check never fails purely on naming.
HASH_KEYS = ("file_hash", "sha256", "hash")

# Event types whose `file_hash` records the file in a state worth restoring *to*.
#
# An allowlist, and it has to be one. The Monitor only reaches the ledger for
# events it has already judged suspicious - services/monitor/pipeline.py fans out
# only when `verdict["suspicious"]` - and the hash it writes is the hash of the
# file *as the attacker left it*. `response_action` then carries that same hash a
# second time. So on a path that is under attack the newest hash is the
# ciphertext's, and checking a restored file against it inverts the test: it
# passes only when recovery hands back the encrypted file.
#
# A denylist would be one new event type away from reintroducing exactly that, so
# an unrecognised event type is not trusted here. Being wrong in this direction
# costs "integrity could not be verified", which is honest; being wrong in the
# other direction certifies the attacker's output as the recovered file.
# `snapshot_created` is included because it is written by the snapshot process
# about content the defender captured, never in response to an attacker's
# write. Note the residual limit: it attests to what the snapshot holds, so a
# snapshot taken after encryption would attest to ciphertext. `file_baseline`
# is what catches that, and test_tc04_integrity_check_catches_a_bad_snapshot
# covers it.
GOOD_STATE_EVENT_TYPES = frozenset({"file_baseline", "file_recovered", "snapshot_created"})


class LedgerUnavailableError(RuntimeError):
    """The ledger service could not be reached or returned an error."""


class LedgerClient:
    def __init__(
        self,
        base_url: Optional[str] = None,
        timeout: float = 5.0,
        client_factory: Optional[Callable[[], httpx.Client]] = None,
    ) -> None:
        self.base_url = (base_url or os.getenv("LEDGER_URL", "http://localhost:8003")).rstrip("/")
        self.timeout = timeout
        # Integration tests pass a factory returning a TestClient, so they reach
        # a real ledger app in-process. In production this is a plain HTTP call.
        self._client_factory = client_factory or (lambda: httpx.Client(timeout=timeout))

    # ------------------------------------------------------------------ helpers

    def _request(self, method: str, path: str, **kwargs: Any) -> dict:
        try:
            with self._client_factory() as client:
                response = client.request(method, f"{self.base_url}{path}", **kwargs)
        except httpx.HTTPError as exc:
            raise LedgerUnavailableError(f"Ledger unreachable at {self.base_url}: {exc}") from exc

        if response.status_code >= 400:
            raise LedgerUnavailableError(
                f"Ledger returned HTTP {response.status_code} for {path}: {response.text[:200]}"
            )
        return response.json()

    # -------------------------------------------------------------------- writes

    def log_event(self, event_type: str, event_data: dict) -> int:
        """Append an event and return its block id."""
        body = self._request("POST", "/ledger/log", json={"event_type": event_type, "event_data": event_data})
        return body["block_id"]

    def try_log_event(self, event_type: str, event_data: dict) -> Optional[int]:
        """Best-effort append.

        Used where the action has already happened (a snapshot exists, a file is
        restored) and losing the audit line is bad but discarding the work is
        worse. Returns None and warns loudly if the ledger is down.
        """
        try:
            return self.log_event(event_type, event_data)
        except LedgerUnavailableError as exc:
            logger.warning("Failed to log %s to ledger: %s", event_type, exc)
            return None

    # --------------------------------------------------------------------- reads

    def last_known_hash(self, file_path: str) -> Optional[dict]:
        """Most recent hash recording this path in a state worth restoring *to*.

        This is the reference value for recovery's integrity check. Returns None
        when no event ever carried a good-state hash for the path - in which case
        recovery can still restore the file, but cannot claim it verified it.

        Deliberately not "the most recent hash on this path": that one belongs to
        whoever wrote the file last, which during an attack is the attacker. See
        GOOD_STATE_EVENT_TYPES.
        """
        body = self._request(
            "GET",
            "/ledger/blocks",
            params={"file_path": file_path, "newest_first": True, "limit": 100},
        )
        for block in body.get("blocks", []):
            if block.get("event_type") not in GOOD_STATE_EVENT_TYPES:
                continue
            event_data = block.get("event_data") or {}
            for key in HASH_KEYS:
                value = event_data.get(key)
                if isinstance(value, str) and value:
                    return {
                        "file_hash": value,
                        "block_id": block["block_id"],
                        "event_type": block["event_type"],
                        "timestamp": block["timestamp"],
                    }
        return None

    def verify_chain(self) -> dict:
        return self._request("GET", "/ledger/verify")
