from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from auth import get_current_user, require_role
from models import LedgerLogRequest
from rate_limit import enforce_rate_limit
from routers.proxy import LEDGER_URL, proxy_request


# Reading the audit trail is open to any authenticated role; appending to it is
# not. An append is permanent - the chain is append-only by design.
router = APIRouter(prefix="/ledger", tags=["ledger"], dependencies=[Depends(get_current_user), Depends(enforce_rate_limit)])


@router.post("/log", dependencies=[Depends(require_role("admin", "enterprise"))])
async def log_event(payload: LedgerLogRequest, request: Request) -> JSONResponse:
    return await proxy_request(request, "POST", LEDGER_URL, "/ledger/log", payload.model_dump())


@router.get("/entries")
async def ledger_entries(request: Request) -> JSONResponse:
    return await proxy_request(request, "GET", LEDGER_URL, "/ledger/entries")


@router.get("/verify")
async def verify_chain(request: Request) -> JSONResponse:
    return await proxy_request(request, "GET", LEDGER_URL, "/ledger/verify")


@router.get("/blocks")
async def ledger_blocks(request: Request) -> JSONResponse:
    # proxy_request forwards the query string, so offset/limit/event_type/
    # file_path/newest_first all reach the ledger unchanged.
    return await proxy_request(request, "GET", LEDGER_URL, "/ledger/blocks")
