from datetime import datetime, timezone
from hashlib import sha256
from json import dumps

from fastapi import FastAPI
from pydantic import BaseModel


# PLACEHOLDER STUB: SI owns the real Ledger/blockchain logic.
# This in-memory hash chain is only for SH integration testing.

app = FastAPI(title="URDS Ledger Stub", version="0.1.0")
ENTRIES = []
GENESIS_HASH = "1f2e3d4c5b6a7988c0d2e4f6a8b0c2d4"


class LedgerLogRequest(BaseModel):
    event_type: str
    event_data: dict


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def create_block(event_type: str, event_data: dict) -> dict:
    previous_hash = ENTRIES[-1]["current_hash"] if ENTRIES else GENESIS_HASH
    block_id = len(ENTRIES) + 1
    timestamp = utc_now()
    digest_source = dumps(
        {"block_id": block_id, "event_type": event_type, "event_data": event_data, "previous_hash": previous_hash, "timestamp": timestamp},
        sort_keys=True,
    )
    block = {
        "block_id": block_id,
        "current_hash": sha256(digest_source.encode()).hexdigest()[:32],
        "previous_hash": previous_hash,
        "timestamp": timestamp,
        "tamper_proof": True,
        "event_type": event_type,
        "event_data": event_data,
    }
    ENTRIES.append(block)
    del ENTRIES[:-50]
    return block


@app.get("/health")
def health() -> dict:
    return {"status": "healthy", "service": "ledger", "placeholder": True}


@app.post("/ledger/log")
def log_event(payload: LedgerLogRequest) -> dict:
    block = create_block(payload.event_type, payload.event_data)
    return {
        "block_id": block["block_id"],
        "current_hash": block["current_hash"],
        "previous_hash": block["previous_hash"],
        "timestamp": block["timestamp"],
        "tamper_proof": block["tamper_proof"],
    }


@app.get("/ledger/entries")
def ledger_entries(limit: int = 20) -> dict:
    if not ENTRIES:
        create_block("system_started", {"message": "placeholder ledger initialized"})
    return {"entries": list(reversed(ENTRIES[-limit:]))}
