from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from auth import get_current_user
from models import PredictRequest
from rate_limit import enforce_rate_limit
from routers.proxy import ML_URL, proxy_request


router = APIRouter(tags=["ml"], dependencies=[Depends(get_current_user), Depends(enforce_rate_limit)])


@router.post("/predict")
async def predict(payload: PredictRequest, request: Request) -> JSONResponse:
    return await proxy_request(request, "POST", ML_URL, "/predict", payload.model_dump())


@router.get("/model/metrics")
async def model_metrics(request: Request) -> JSONResponse:
    return await proxy_request(request, "GET", ML_URL, "/model/metrics")
