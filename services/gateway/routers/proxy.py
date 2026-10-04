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


DOWNSTREAM_TIMEOUT = 5.0

# One client for the life of the gateway: built at startup by
# `open_downstream_client` (main.lifespan), reused by every downstream call,
# closed at shutdown.
#
# call_downstream used to build a new httpx.AsyncClient per call. Building one
# loads certifi's CA bundle into a new SSL context - synchronous work on the
# event loop, so every request the gateway was serving waited behind it. On the
# Windows test VM that took 267-376 ms a time; /health paid it four times over,
# and the dashboard's six calls a second kept the gateway permanently busy:
# proxied GETs went from about 0.2 s to 2.4-2.7 s, /health to 5.5-10.3 s
# (FIXES.md, defect 13). Shared, it is paid once, and the connections to the
# services stay open between calls.
_client: httpx.AsyncClient | None = None


def _new_client() -> httpx.AsyncClient:
    # Idle connections are dropped after 4 s, before uvicorn's default 5 s
    # keep-alive closes them from the service's end, so the gateway never sends
    # a request down a connection the service is in the middle of closing.
    return httpx.AsyncClient(timeout=DOWNSTREAM_TIMEOUT, limits=httpx.Limits(keepalive_expiry=4.0))


def downstream_client() -> httpx.AsyncClient:
    """The shared client, built now if startup did not build it."""
    global _client
    if _client is None or _client.is_closed:
        _client = _new_client()
    return _client


def open_downstream_client() -> None:
    """Build the shared client before the first request, so no request pays for it."""
    downstream_client()


async def close_downstream_client() -> None:
    global _client
    client, _client = _client, None
    if client is not None:
        await client.aclose()


async def call_downstream(method: str, base_url: str, path: str, json_body: Any | None = None, params: dict[str, Any] | None = None) -> httpx.Response:
    try:
        return await downstream_client().request(method, f"{base_url}{path}", json=json_body, params=params)
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
