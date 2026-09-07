"""URDS Ledger service (port 8003).

Endpoints
    POST /ledger/log      append an event to the hash chain
    GET  /ledger/verify   walk the chain and report the first broken block
    GET  /ledger/blocks   paginated read of the audit trail
    GET  /ledger/entries  newest-first view kept for the existing dashboard
    GET  /health          liveness for docker-compose and the gateway
"""

import os
from typing import Optional
from uuid import uuid4

from fastapi import Depends, FastAPI, Query, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from database import DEFAULT_DB_PATH
from hash_chain import HashChainLedger, utc_now
from models import BlocksResponse, LedgerLogRequest, LedgerLogResponse, VerifyResponse

app = FastAPI(title="URDS Ledger", version="1.0.0")

_ledger: Optional[HashChainLedger] = None


def get_ledger() -> HashChainLedger:
    """Process-wide ledger handle. Tests override this via dependency_overrides."""
    global _ledger
    if _ledger is None:
        _ledger = HashChainLedger(os.getenv("LEDGER_DB_PATH", DEFAULT_DB_PATH))
    return _ledger


# --------------------------------------------------------------- error handling
# Same envelope as the gateway: {"error": {...}, "details": {...}}


def build_error(request: Request, code: str, message: str, details: Optional[dict] = None) -> dict:
    request_id = request.headers.get("X-Request-ID") or f"req_{uuid4().hex[:12]}"
    return {
        "error": {
            "code": code,
            "message": message,
            "timestamp": utc_now(),
            "request_id": request_id,
        },
        "details": details or {},
    }


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content=build_error(request, "BAD_REQUEST", "Request validation failed", {"errors": exc.errors()}),
    )


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    code = {
        404: "NOT_FOUND",
        405: "METHOD_NOT_ALLOWED",
        500: "INTERNAL_SERVER_ERROR",
    }.get(exc.status_code, "REQUEST_FAILED")
    return JSONResponse(
        status_code=exc.status_code,
        content=build_error(request, code, str(exc.detail)),
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=build_error(request, "LEDGER_ERROR", "Unexpected ledger error", {"error": str(exc)}),
    )


# -------------------------------------------------------------------- endpoints


@app.get("/health")
def health(ledger: HashChainLedger = Depends(get_ledger)) -> JSONResponse:
    try:
        blocks = ledger.count_blocks()
    except Exception as exc:  # a ledger that can't read its chain is not healthy
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"status": "unhealthy", "service": "ledger", "error": str(exc)},
        )
    return JSONResponse(content={"status": "healthy", "service": "ledger", "blocks": blocks})


# 201, not 200: Table 3.2 names a ledger entry as its example of Created, and
# gateway.yaml already declared it. An append is a new resource on an append-only
# chain, so the status code may as well say so.
@app.post("/ledger/log", response_model=LedgerLogResponse, status_code=status.HTTP_201_CREATED)
def log_event(payload: LedgerLogRequest, ledger: HashChainLedger = Depends(get_ledger)) -> LedgerLogResponse:
    block = ledger.add_block(payload.event_type, payload.event_data)
    return LedgerLogResponse(
        block_id=block["block_id"],
        current_hash=block["current_hash"],
        previous_hash=block["previous_hash"],
        timestamp=block["timestamp"],
        tamper_proof=True,
    )


@app.get("/ledger/verify", response_model=VerifyResponse)
def verify_chain(ledger: HashChainLedger = Depends(get_ledger)) -> VerifyResponse:
    """Full-chain integrity check. Target: under 50ms for 1,000+ blocks."""
    return VerifyResponse(**ledger.verify_chain())


@app.get("/ledger/blocks", response_model=BlocksResponse)
def get_blocks(
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    file_path: Optional[str] = Query(None, description="Filter to events about one file"),
    newest_first: bool = Query(False, description="Reverse order; used by recovery lookups"),
    ledger: HashChainLedger = Depends(get_ledger),
) -> BlocksResponse:
    return BlocksResponse(
        **ledger.get_blocks(
            offset=offset,
            limit=limit,
            event_type=event_type,
            file_path=file_path,
            newest_first=newest_first,
        )
    )


@app.get("/ledger/entries")
def ledger_entries(
    limit: int = Query(20, ge=1, le=500),
    ledger: HashChainLedger = Depends(get_ledger),
) -> dict:
    """Newest-first view of the chain.

    Kept because the gateway and Streamlit dashboard already consume this shape.
    /ledger/blocks is the spec'd read endpoint; this is the compatibility one.
    """
    page = ledger.get_blocks(offset=0, limit=limit, newest_first=True)
    entries = [{**block, "tamper_proof": True} for block in page["blocks"]]
    return {"entries": entries, "total": page["total"]}
