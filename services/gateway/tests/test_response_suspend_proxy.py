"""The gateway proxies suspend, resume and leases, admin-only (defect 26, F2b).

Before this, the gateway had no route for any of them, and documented none.
The downstream is stubbed as in conftest.py; what is checked is that each
route exists, forwards the body unchanged to the Response service, refuses a
non-admin token, and that terminate forwards a lease id only when one is given.
"""

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
RESUME_BODY = {"lease_id": "lease_abc", "incident_id": "inc_1", "reason": "a second writer appeared"}
TERMINATE_BODY = {"process_id": 4512, "incident_id": "inc_1", "reason": "ransomware_detected", "force": True}

LEASE = {"lease_id": "lease_abc", "process_id": 4512, "incident_id": "inc_1",
         "expires_at": "2026-10-06T10:00:02Z", "state": "held"}


def response_calls(stub):
    return [call for call in stub.calls if call["path"].startswith("/response/")]


def headers_for(role, tier=None):
    return {"Authorization": f"Bearer {create_access_token('test_user', role=role, tier=tier or role)}"}


@pytest.fixture
def stub(monkeypatch):
    calls = []

    async def fake_call_downstream(method, base_url, path, json_body=None, params=None):
        calls.append({"method": method, "base_url": base_url, "path": path, "json": json_body})
        if path == "/response/suspend":
            return httpx.Response(200, json={"lease_id": "lease_abc", "process_id": 4512, "suspended": True,
                                             "expires_at": "2026-10-06T10:00:02Z", "already_held": False})
        if path == "/response/resume":
            return httpx.Response(200, json={"lease_id": "lease_abc", "resumed": True, "reason": "r"})
        if path == "/response/leases":
            return httpx.Response(200, json=[LEASE])
        if path == "/response/terminate":
            return httpx.Response(200, json={"status": "terminated", "process_id": 4512,
                                             "timestamp": "2026-10-06T10:00:01Z", "exit_code": 0})
        return httpx.Response(404, json={"message": path})

    monkeypatch.setattr(proxy, "call_downstream", fake_call_downstream)
    monkeypatch.setattr(main, "call_downstream", fake_call_downstream)
    client = TestClient(main.app)
    client.calls = calls
    return client


def test_suspend_is_proxied_unchanged(stub):
    response = stub.post("/response/suspend", json=SUSPEND_BODY, headers=headers_for("admin", "enterprise"))
    assert response.status_code == 200, response.text
    assert response.json()["lease_id"] == "lease_abc"
    (call,) = stub.calls
    assert (call["method"], call["path"]) == ("POST", "/response/suspend")
    assert call["json"] == SUSPEND_BODY


def test_resume_is_proxied(stub):
    response = stub.post("/response/resume", json=RESUME_BODY, headers=headers_for("admin", "enterprise"))
    assert response.status_code == 200
    (call,) = stub.calls
    assert call["path"] == "/response/resume"
    assert call["json"]["lease_id"] == "lease_abc"


def test_leases_are_listed(stub):
    response = stub.get("/response/leases", headers=headers_for("admin", "enterprise"))
    assert response.status_code == 200
    assert response.json() == [LEASE]
    assert stub.calls[0]["method"] == "GET"


def test_terminate_forwards_a_lease_id_when_given(stub):
    stub.post("/response/terminate", json={**TERMINATE_BODY, "lease_id": "lease_abc"},
              headers=headers_for("admin", "enterprise"))
    assert stub.calls[0]["json"]["lease_id"] == "lease_abc"


def test_terminate_without_a_lease_forwards_the_same_body_as_before(stub):
    stub.post("/response/terminate", json=TERMINATE_BODY, headers=headers_for("admin", "enterprise"))
    assert stub.calls[0]["json"] == TERMINATE_BODY


@pytest.mark.parametrize("method,path,body", [
    ("post", "/response/suspend", SUSPEND_BODY),
    ("post", "/response/resume", RESUME_BODY),
    ("get", "/response/leases", None),
])
@pytest.mark.parametrize("role", ["free", "enterprise"])
def test_only_an_admin_can_suspend_resume_or_list(stub, method, path, body, role):
    kwargs = {"headers": headers_for(role)}
    if body is not None:
        kwargs["json"] = body
    assert getattr(stub, method)(path, **kwargs).status_code == 403
    # The refusal is audited to the ledger (TC-10); nothing reaches Response.
    assert response_calls(stub) == []


def test_a_suspend_without_the_gate_is_rejected_at_the_gateway(stub):
    body = {k: v for k, v in SUSPEND_BODY.items() if k != "attribution_source"}
    response = stub.post("/response/suspend", json=body, headers=headers_for("admin", "enterprise"))
    assert response.status_code in (400, 422)
    assert response_calls(stub) == []
