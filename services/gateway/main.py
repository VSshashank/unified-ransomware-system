from contextlib import asynccontextmanager
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from auth import (
    BOOTSTRAP_SECRET_HEADER,
    bootstrap_secret_matches,
    create_access_token,
    dev_tokens_allowed,
    get_current_user,
    require_role,
    requires_bootstrap_secret,
    verify_jwt_secret_configuration,
)
from models import AnalyzeRequest, TokenRequest, TokenResponse
from rate_limit import enforce_rate_limit
from routers import ledger, ml, monitor, response
from routers.proxy import LEDGER_URL, ML_URL, MONITOR_URL, SERVICE_URLS, call_downstream


@asynccontextmanager
async def lifespan(_: FastAPI):
    # Refuses to boot on a committed secret outside development, warns inside it.
    verify_jwt_secret_configuration()
    yield


app = FastAPI(title="URDS API Gateway", version="1.0.0", lifespan=lifespan)
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
async def issue_dev_token(request: Request, payload: TokenRequest | None = None) -> TokenResponse:
    # =====================================================================
    # PHASE 4 PLACEHOLDER - THIS IS NOT AUTHENTICATION.
    #
    # This endpoint verifies no identity whatsoever. It exists so local
    # development and the demo scripts can obtain a token without an
    # identity provider standing behind them. It must be replaced with real
    # identity management before this gateway is exposed to anyone.
    #
    # Two guards keep the blast radius small in the meantime:
    #   * ALLOW_DEV_TOKENS=false switches the endpoint off entirely.
    #   * Anything above the "free" floor requires the shared bootstrap
    #     secret in the X-Bootstrap-Secret header. An empty POST yields a
    #     free token, which can read but cannot act.
    # =====================================================================
    if not dev_tokens_allowed():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "code": "DEV_TOKENS_DISABLED",
                "message": "The development token endpoint is disabled on this deployment",
                "details": {"env": "ALLOW_DEV_TOKENS"},
            },
        )

    payload = payload or TokenRequest()

    if requires_bootstrap_secret(payload.role, payload.tier):
        if not bootstrap_secret_matches(request.headers.get(BOOTSTRAP_SECRET_HEADER)):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "code": "FORBIDDEN",
                    "message": f"A valid {BOOTSTRAP_SECRET_HEADER} header is required to issue a token above 'free'",
                    "details": {"requested_role": payload.role, "requested_tier": payload.tier},
                },
            )

    return TokenResponse(access_token=create_access_token(payload.sub, payload.role, payload.tier))


@app.post(
    "/analyze",
    dependencies=[Depends(get_current_user), Depends(require_role("admin", "enterprise")), Depends(enforce_rate_limit)],
)
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
