"""Pydantic models for the URDS ledger service.

The ledger stores metadata only - file paths, hashes, entropy, process IDs.
Raw file content never enters a block (project privacy principle, spec 1.5).
"""

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


class LedgerBlock(BaseModel):
    """One block of the hash chain, as stored in the `blocks` table."""

    block_id: int
    timestamp: datetime
    event_type: str
    event_data: dict
    previous_hash: str
    current_hash: str
    blockchain_anchor: Optional[str] = None  # Phase 5 (Polygon anchoring) - null until then


class LedgerLogRequest(BaseModel):
    """Body of POST /ledger/log."""

    event_type: str = Field(min_length=1, max_length=64)
    event_data: dict


class LedgerLogResponse(BaseModel):
    """Result of appending a block.

    `timestamp` is returned as the exact string that was hashed and stored, so a
    caller can recompute current_hash from this response alone.
    """

    block_id: int
    current_hash: str
    previous_hash: str
    timestamp: str
    tamper_proof: bool = True


class VerifyResponse(BaseModel):
    """Result of GET /ledger/verify. Target: under 50ms (spec Table 5.9)."""

    valid: bool
    blocks_checked: int
    invalid_block_id: Optional[int] = None
    verification_time_ms: float


class BlocksResponse(BaseModel):
    """Paginated read of the audit trail, oldest first (GET /ledger/blocks)."""

    blocks: list[LedgerBlock]
    total: int
    offset: int
    limit: int


class ErrorBody(BaseModel):
    code: str
    message: str
    timestamp: str
    request_id: str


class ErrorResponse(BaseModel):
    """Project-wide error envelope (spec 3.4)."""

    error: ErrorBody
    details: dict[str, Any] = {}
