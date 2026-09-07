from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from auth import get_current_user, require_role
from models import PredictRequest
from rate_limit import enforce_rate_limit
from routers.proxy import ML_URL, proxy_request


router = APIRouter(tags=["ml"], dependencies=[Depends(get_current_user), Depends(enforce_rate_limit)])


# Grouped with /analyze rather than with the GET reads: it is a POST that spends
# real inference budget, and /analyze - which is admin-or-enterprise - is just
# this call with feature extraction and a ledger write around it. Leaving
# /predict open to free would make that gate bypassable for the ML half.
@router.post("/predict", dependencies=[Depends(require_role("admin", "enterprise"))])
async def predict(payload: PredictRequest, request: Request) -> JSONResponse:
    return await proxy_request(request, "POST", ML_URL, "/predict", payload.model_dump())


@router.get("/model/metrics")
async def model_metrics(request: Request) -> JSONResponse:
    return await proxy_request(request, "GET", ML_URL, "/model/metrics")
