"""Recovery module - SI's slice of the Response service (port 8004).

Owns POST /response/recover and everything behind it: VSS snapshots,
restoration, and integrity verification against the ledger.

Terminate/isolate belong to AS and are untouched by this package.
"""

from recovery.ledger_client import LedgerClient
from recovery.vss_manager import (
    Snapshot,
    SnapshotCreationError,
    VSSError,
    VSSManager,
    VSSUnavailableError,
)

__all__ = [
    "LedgerClient",
    "Snapshot",
    "SnapshotCreationError",
    "VSSError",
    "VSSManager",
    "VSSUnavailableError",
]
