"""Defect 13: the gateway builds its downstream client once, and asks the
services' /health at once.

The shared `client` fixture replaces call_downstream outright, so nothing in the
rest of this suite ever built an httpx client - which is how a gateway that
built one per call (267-376 ms each on the Windows test VM, on the event loop)
passed every test here. These tests leave call_downstream real and stub one
level down instead: every httpx.AsyncClient the gateway builds is counted and
given a transport that answers for the four services in-process.
"""

import asyncio

import httpx
import pytest
from fastapi.testclient import TestClient

import main
import routers.proxy as proxy
from auth import create_access_token


ADMIN = {"Authorization": f"Bearer {create_access_token('defect13', role='admin', tier='enterprise')}"}


@pytest.fixture
def services(monkeypatch):
    state = {"built": 0, "in_flight": 0, "max_in_flight": 0, "down": set()}
    real_async_client = httpx.AsyncClient

    async def answer(request: httpx.Request) -> httpx.Response:
        state["in_flight"] += 1
        state["max_in_flight"] = max(state["max_in_flight"], state["in_flight"])
        try:
            # Long enough that checks made in turn could never overlap.
            await asyncio.sleep(0.05)
            base_url = f"{request.url.scheme}://{request.url.netloc.decode()}"
            if base_url in state["down"]:
                raise httpx.ConnectError("connection refused", request=request)
            if request.url.path == "/monitor/status":
                return httpx.Response(200, json={"status": "active", "files_monitored": 1})
            return httpx.Response(200, json={"status": "healthy", "service": base_url})
        finally:
            state["in_flight"] -= 1

    class CountedClient(real_async_client):
        def __init__(self, *args, **kwargs):
            state["built"] += 1
            kwargs["transport"] = httpx.MockTransport(answer)
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", CountedClient)
    # A client left over from another test would have the real transport.
    monkeypatch.setattr(proxy, "_client", None, raising=False)
    return state


def test_the_client_is_built_once_at_startup_and_reused(services):
    with TestClient(main.app) as client:
        assert services["built"] == 1, "startup did not build the downstream client"
        for _ in range(10):
            assert client.get("/monitor/status", headers=ADMIN).status_code == 200
        for _ in range(3):
            assert client.get("/health").status_code == 200
    # Old code: 10 + 3 * 4 = 22 clients, every one built while a request waited.
    assert services["built"] == 1


def test_the_client_is_closed_at_shutdown(services):
    with TestClient(main.app):
        shared = proxy.downstream_client()
        assert not shared.is_closed
    assert shared.is_closed
    assert proxy._client is None


def test_a_closed_client_is_replaced_rather_than_used(services):
    """A call after shutdown (or before a startup that never ran) still works."""
    with TestClient(main.app):
        pass
    replacement = proxy.downstream_client()
    assert not replacement.is_closed
    assert services["built"] == 2
    asyncio.run(proxy.close_downstream_client())


def test_health_asks_the_four_services_at_once(services):
    with TestClient(main.app) as client:
        response = client.get("/health")
    assert response.status_code == 200
    assert set(response.json()["services"]) == {"gateway", *proxy.SERVICE_URLS}
    # Old code: 1, one service after another.
    assert services["max_in_flight"] == len(proxy.SERVICE_URLS)


def test_one_service_down_is_reported_and_does_not_hide_the_others(services):
    services["down"].add(proxy.LEDGER_URL)
    with TestClient(main.app) as client:
        response = client.get("/health")
    assert response.status_code == 503
    body = response.json()
    assert body["status"] == "degraded"
    assert body["services"]["ledger"]["status"] == "unhealthy"
    assert body["services"]["ledger"]["details"]["code"] == "DOWNSTREAM_UNAVAILABLE"
    for name in ("monitor", "ml_engine", "response"):
        assert body["services"][name]["status"] == "healthy"
