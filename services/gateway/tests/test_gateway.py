import sys
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import main
import rate_limit
import routers.proxy as proxy
from auth import create_access_token


@pytest.fixture(autouse=True)
def reset_limits():
    rate_limit.reset_rate_limits()
    yield
    rate_limit.reset_rate_limits()


@pytest.fixture
def client(monkeypatch):
    calls = []

    async def fake_call_downstream(method, base_url, path, json_body=None, params=None):
        calls.append({"method": method, "base_url": base_url, "path": path, "json": json_body, "params": params})
        if path == "/health":
            return httpx.Response(200, json={"status": "healthy", "service": base_url.rsplit("/", 1)[-1] or "stub"})
        if path == "/monitor/status":
            return httpx.Response(200, json={"status": "active", "files_monitored": 1523, "events_captured": 45, "uptime_seconds": 3600})
        if path == "/monitor/start":
            return httpx.Response(200, json={"status": "monitoring", "monitor_id": "mon_123abc", "start_time": "2026-01-31T10:00:00Z"})
        if path == "/monitor/events":
            return httpx.Response(200, json={"events": [{"event_id": "evt_1", "file_path": "/watch/file.doc", "event_type": "modified", "entropy": 7.89, "timestamp": "2026-01-31T10:00:00Z"}]})
        if path == "/features":
            return httpx.Response(
                200,
                json={
                    "shannon_entropy": 7.89,
                    "file_size": 1048576,
                    "magic_bytes": "4D5A",
                    "modification_rate": 0.85,
                    "pe_imports_count": 45,
                    "api_calls": ["CreateFile", "WriteFile", "CryptEncrypt"],
                },
            )
        if path == "/predict":
            return httpx.Response(
                200,
                json={
                    "prediction": "ransomware",
                    "confidence": 0.94,
                    "model_version": "1.0.0",
                    "timestamp": "2026-01-31T10:01:05Z",
                    "threat_level": "high",
                    "features_importance": {"shannon_entropy": 0.35, "modification_rate": 0.28, "api_calls": 0.22},
                },
            )
        if path == "/model/metrics":
            return httpx.Response(200, json={"accuracy": 0.92, "precision": 0.91, "recall": 0.93, "f1_score": 0.92, "roc_auc": 0.95, "last_trained": "2026-01-30T14:00:00Z"})
        if path == "/ledger/log":
            return httpx.Response(200, json={"block_id": 42, "current_hash": "abc123", "previous_hash": "def456", "timestamp": "2026-01-31T10:01:10Z", "tamper_proof": True})
        if path == "/ledger/entries":
            return httpx.Response(200, json={"entries": [{"block_id": 42, "current_hash": "abc123", "previous_hash": "def456", "timestamp": "2026-01-31T10:01:10Z", "tamper_proof": True}]})
        if path == "/response/trigger":
            return httpx.Response(200, json={"status": "success", "actions_taken": ["process_terminated", "network_isolated", "admin_notified"], "timestamp": "2026-01-31T10:02:45Z"})
        return httpx.Response(404, json={"message": f"Unhandled test path: {path}"})

    monkeypatch.setattr(proxy, "call_downstream", fake_call_downstream)
    monkeypatch.setattr(main, "call_downstream", fake_call_downstream)
    test_client = TestClient(main.app)
    test_client.calls = calls
    return test_client


def auth_headers(role="admin", tier="enterprise"):
    token = create_access_token("test_user", role=role, tier=tier)
    return {"Authorization": f"Bearer {token}"}


def test_health_is_unauthenticated(client):
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "healthy"
    assert "gateway" in body["services"]
    assert "monitor" in body["services"]


def test_protected_route_rejects_missing_token(client):
    response = client.get("/monitor/status")
    assert response.status_code == 401
    body = response.json()
    assert body["error"]["code"] == "UNAUTHORIZED"
    assert body["error"]["request_id"].startswith("req_")


def test_dev_token_can_access_monitor_status(client):
    token_response = client.post("/auth/token", json={"sub": "user_id_123", "role": "admin", "tier": "enterprise"})
    assert token_response.status_code == 200
    token = token_response.json()["access_token"]
    response = client.get("/monitor/status", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json()["files_monitored"] == 1523


def test_predict_contract_shape(client):
    payload = {
        "features": {
            "shannon_entropy": 7.89,
            "file_size": 1048576,
            "magic_bytes": "4D5A",
            "modification_rate": 0.85,
            "pe_imports_count": 45,
            "api_calls": ["CreateFile", "WriteFile", "CryptEncrypt"],
        }
    }
    response = client.post("/predict", json=payload, headers=auth_headers())
    assert response.status_code == 200
    body = response.json()
    assert body["prediction"] == "ransomware"
    assert body["threat_level"] == "high"
    assert "features_importance" in body


def test_analyze_calls_monitor_ml_and_ledger_in_order(client):
    response = client.post("/analyze", json={"file_path": "/watch/file.doc"}, headers=auth_headers())
    assert response.status_code == 200
    assert response.json()["prediction"] == "ransomware"
    paths = [call["path"] for call in client.calls]
    assert paths[-3:] == ["/features", "/predict", "/ledger/log"]
    assert client.calls[-1]["json"]["event_type"] == "analysis"


def test_response_trigger_proxy_supports_full_flow(client):
    payload = {
        "incident_id": "inc_998877",
        "process_id": 4512,
        "threat_level": "critical",
        "action_required": "terminate_process",
    }
    response = client.post("/response/trigger", json=payload, headers=auth_headers())
    assert response.status_code == 200
    assert "process_terminated" in response.json()["actions_taken"]


def test_rate_limit_returns_standard_429(client, monkeypatch):
    monkeypatch.setitem(rate_limit.RATE_LIMITS, "free", {"requests_per_minute": 1, "burst": 1})
    headers = auth_headers(role="free", tier="free")
    assert client.get("/monitor/status", headers=headers).status_code == 200
    response = client.get("/monitor/status", headers=headers)
    assert response.status_code == 429
    body = response.json()
    assert body["error"]["code"] == "RATE_LIMIT_EXCEEDED"
    assert body["details"]["tier"] == "free"
