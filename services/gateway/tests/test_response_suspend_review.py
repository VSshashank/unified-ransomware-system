"""Defect 26 review follow-ups, gateway side.

- A non-finite `lease_seconds` (`NaN`, `Infinity`) is a 400 at the gateway and
  never reaches the Response service. Before, the validation error echoed the
  NaN back and serialising it failed: a 500.
- The caller's `gate` claim is forwarded as given, and is optional: Response
  records it as the caller's, unverified.
"""

import json

import httpx
import pytest
from fastapi.testclient import TestClient

import main
import routers.proxy as proxy
from auth import create_access_token

SUSPEND_BODY = {
    "process_id": 4512,
    "incident_id": "inc_1",
    "lease_seconds": 2.0,
    "reason": "sole writer",
    "attribution_confidence": "probable",
    "attribution_source": "windows-security-4663",
    "attribution_reason": "one writer so far (pending)",
    "image": "C:\\work\\locker.exe",
    "started_at": 1790000000.25,
}
ADMIN = {"Authorization": f"Bearer {create_access_token('test_user', role='admin', tier='enterprise')}"}


@pytest.fixture
def stub(monkeypatch):
    calls = []

    async def fake_call_downstream(method, base_url, path, json_body=None, params=None):
        calls.append({"method": method, "path": path, "json": json_body})
        if path == "/response/suspend":
            return httpx.Response(200, json={"lease_id": "lease_abc", "process_id": 4512, "suspended": True,
                                             "expires_at": "2026-10-06T10:00:02Z", "already_held": False})
        return httpx.Response(201, json={"block_id": 1})

    monkeypatch.setattr(proxy, "call_downstream", fake_call_downstream)
    monkeypatch.setattr(main, "call_downstream", fake_call_downstream)
    client = TestClient(main.app, raise_server_exceptions=False)
    client.calls = calls
    return client


@pytest.mark.parametrize("bad", ["NaN", "Infinity", "-Infinity"])
def test_non_finite_lease_seconds_is_a_400_and_is_not_forwarded(stub, bad):
    raw = json.dumps(SUSPEND_BODY).replace('"lease_seconds": 2.0', f'"lease_seconds": {bad}')
    response = stub.post("/response/suspend", content=raw,
                         headers={**ADMIN, "content-type": "application/json"})
    assert response.status_code == 400, response.text
    assert not [c for c in stub.calls if c["path"].startswith("/response/")]


def test_a_gate_claim_is_forwarded_as_given(stub):
    stub.post("/response/suspend", json={**SUSPEND_BODY, "gate": "suspend_authorised"}, headers=ADMIN)
    (call,) = [c for c in stub.calls if c["path"] == "/response/suspend"]
    assert call["json"]["gate"] == "suspend_authorised"


def test_the_gate_is_optional(stub):
    response = stub.post("/response/suspend", json=SUSPEND_BODY, headers=ADMIN)
    assert response.status_code == 200
    (call,) = [c for c in stub.calls if c["path"] == "/response/suspend"]
    assert call["json"].get("gate") is None
