from datetime import datetime, timezone
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from auth import create_access_token, get_current_user
from models import AnalyzeRequest, TokenRequest, TokenResponse
from rate_limit import enforce_rate_limit
from routers import ledger, ml, monitor, response
from routers.proxy import LEDGER_URL, ML_URL, MONITOR_URL, SERVICE_URLS, call_downstream


app = FastAPI(title="URDS API Gateway", version="1.0.0")
app.include_router(monitor.router)
app.include_router(ml.router)
app.include_router(ledger.router)
app.include_router(response.router)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def build_error(request: Request, code: str, message: str, details: dict | None = None) -> dict:
    return {
        "error": {
            "code": code,
            "message": message,
            "timestamp": utc_now(),
            "request_id": getattr(request.state, "request_id", f"req_{uuid4().hex[:12]}"),
        },
        "details": details or {},
    }


@app.middleware("http")
async def request_context(request: Request, call_next):
    request.state.request_id = request.headers.get("X-Request-ID", f"req_{uuid4().hex[:12]}")
    response = await call_next(request)
    response.headers["X-Request-ID"] = request.state.request_id
    return response


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content=build_error(
            request,
            "BAD_REQUEST",
            "Request validation failed",
            {"errors": exc.errors()},
        ),
    )


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    detail = exc.detail if isinstance(exc.detail, dict) else {}
    code = detail.get("code") or {
        401: "UNAUTHORIZED",
        403: "FORBIDDEN",
        404: "NOT_FOUND",
        429: "RATE_LIMIT_EXCEEDED",
        500: "INTERNAL_SERVER_ERROR",
        503: "SERVICE_UNAVAILABLE",
    }.get(exc.status_code, "REQUEST_FAILED")
    message = detail.get("message") if isinstance(detail, dict) else str(exc.detail)
    details = detail.get("details", {}) if isinstance(detail, dict) else {}
    return JSONResponse(status_code=exc.status_code, content=build_error(request, code, message, details))


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=build_error(request, "INTERNAL_SERVER_ERROR", "Unexpected gateway error", {"error": str(exc)}),
    )


@app.get("/health")
async def health() -> JSONResponse:
    services = {"gateway": {"status": "healthy"}}
    degraded = False
    for name, base_url in SERVICE_URLS.items():
        try:
            downstream = await call_downstream("GET", base_url, "/health")
            services[name] = downstream.json() if downstream.status_code < 400 else {"status": "unhealthy", "http_status": downstream.status_code}
            degraded = degraded or downstream.status_code >= 400
        except HTTPException as exc:
            services[name] = {"status": "unhealthy", "details": exc.detail}
            degraded = True
    status_code = status.HTTP_503_SERVICE_UNAVAILABLE if degraded else status.HTTP_200_OK
    return JSONResponse(status_code=status_code, content={"status": "degraded" if degraded else "healthy", "services": services})


@app.post("/auth/token", response_model=TokenResponse)
async def issue_dev_token(payload: TokenRequest | None = None) -> TokenResponse:
    # Phase 4 placeholder only. Replace with real identity management before production.
    payload = payload or TokenRequest()
    return TokenResponse(access_token=create_access_token(payload.sub, payload.role, payload.tier))


@app.post("/analyze", dependencies=[Depends(get_current_user), Depends(enforce_rate_limit)])
async def analyze_file(payload: AnalyzeRequest, request: Request) -> JSONResponse:
    monitor_resp = await call_downstream("POST", MONITOR_URL, "/features", json_body={"path": payload.file_path})
    if monitor_resp.status_code >= 400:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "FEATURE_EXTRACTION_FAILED", "message": "Monitor service failed to extract features", "details": monitor_resp.json()},
        )
    features = monitor_resp.json()

    ml_resp = await call_downstream("POST", ML_URL, "/predict", json_body={"features": features})
    if ml_resp.status_code >= 400:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "PREDICTION_FAILED", "message": "ML service failed to classify file", "details": ml_resp.json()},
        )
    prediction = ml_resp.json()

    ledger_payload = {
        "event_type": "analysis",
        "event_data": {
            "file_path": payload.file_path,
            "features": features,
            "result": prediction,
            "request_id": request.state.request_id,
        },
    }
    ledger_resp = await call_downstream("POST", LEDGER_URL, "/ledger/log", json_body=ledger_payload)
    if ledger_resp.status_code >= 400:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "LEDGER_LOG_FAILED", "message": "Ledger service failed to log analysis", "details": ledger_resp.json()},
        )
    return JSONResponse(status_code=status.HTTP_200_OK, content=prediction)
