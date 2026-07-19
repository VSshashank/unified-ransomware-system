import os
from typing import Any

import httpx
from fastapi import HTTPException, Request, status
from fastapi.responses import JSONResponse


MONITOR_URL = os.getenv("MONITOR_URL", "http://localhost:8001")
ML_URL = os.getenv("ML_URL", "http://localhost:8002")
LEDGER_URL = os.getenv("LEDGER_URL", "http://localhost:8003")
RESPONSE_URL = os.getenv("RESPONSE_URL", "http://localhost:8004")

SERVICE_URLS = {
    "monitor": MONITOR_URL,
    "ml_engine": ML_URL,
    "ledger": LEDGER_URL,
    "response": RESPONSE_URL,
}


async def call_downstream(method: str, base_url: str, path: str, json_body: Any | None = None, params: dict[str, Any] | None = None) -> httpx.Response:
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            return await client.request(method, f"{base_url}{path}", json=json_body, params=params)
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "DOWNSTREAM_UNAVAILABLE", "message": f"Downstream service unavailable: {base_url}", "details": {"error": str(exc)}},
        ) from exc


async def proxy_request(request: Request, method: str, base_url: str, path: str, json_body: Any | None = None) -> JSONResponse:
    params = dict(request.query_params)
    response = await call_downstream(method, base_url, path, json_body=json_body, params=params)
    try:
        payload = response.json()
    except ValueError:
        payload = {"message": response.text}
    if response.status_code >= 400:
        raise HTTPException(
            status_code=response.status_code,
            detail={
                "code": "DOWNSTREAM_ERROR",
                "message": f"Downstream service returned HTTP {response.status_code}",
                "details": payload if isinstance(payload, dict) else {"response": payload},
            },
        )
    return JSONResponse(status_code=response.status_code, content=payload)
